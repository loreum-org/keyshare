//! Hyperliquid testnet trading (design §8). The bot's wallet key is the master account; a
//! separate agent key, approved by the master with `keyshare-mcp hl-approve-agent`, signs orders.
//! The agent can't withdraw or transfer, so funds only leave through the master.
//!
//! Every action goes through the kill switch, this bot's [`HlPolicy`] and the audit log before
//! the agent key signs it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, B256};
use keyshare_core::audit::AuditEvent;
use keyshare_core::hyperliquid::{
    self as hl, CancelWire, HlPolicy, L1Action, LimitWire, ModifyWire, OrderCheck, OrderTypeWire, OrderWire, Tif, Tpsl,
    TriggerWire,
};
use keyshare_core::killswitch::KillSwitch;
use keyshare_core::{LocalSigner, Refusal, RefusalCode, Signer};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::config::Config;
use crate::exec::{Executor, Outcome};

pub const TESTNET_API: &str = "https://api.hyperliquid-testnet.xyz";
/// Phase 0 is testnet only: every signature says so.
const MAINNET: bool = false;
/// An agent this close to expiry is treated as expired, so an order never races the cutoff.
const EXPIRY_MARGIN_MS: u64 = 60_000;

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HlConfig {
    /// Default: Hyperliquid testnet.
    pub api_url: Option<String>,
}

/// The agent key file `hl-approve-agent` writes (mode 0600). A new key every time: an agent
/// address is never reused (design §8).
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentFile {
    pub address: Address,
    pub key: String,
    pub name: String,
    pub valid_until_ms: u64,
}

/// Phase 0 signs for testnet only, so refuse any other API host up front. Loopback is allowed
/// for local mocks.
pub fn check_api_url(config: Option<&HlConfig>) -> Result<(), String> {
    let Some(url) = config.and_then(|c| c.api_url.as_deref()) else { return Ok(()) };
    let host = url.split("://").nth(1).unwrap_or("").split(['/', ':']).next().unwrap_or("");
    if matches!(host, "api.hyperliquid-testnet.xyz" | "127.0.0.1" | "localhost") {
        Ok(())
    } else {
        Err(format!("hyperliquid api_url {url:?} is not testnet; Phase 0 is testnet only"))
    }
}

pub fn agent_path(state_dir: &Path, bot: &str) -> PathBuf {
    state_dir.join("hyperliquid").join(format!("{bot}.agent.json"))
}

fn day_path(state_dir: &Path, bot: &str) -> PathBuf {
    state_dir.join("hyperliquid").join(format!("{bot}.day.json"))
}

/// Account value at the first order of the UTC day, for the daily loss stop.
#[derive(Debug, Serialize, Deserialize)]
struct DayStart {
    day: u64,
    account_value: String,
}

fn venue(why: impl std::fmt::Display) -> Refusal {
    Refusal::new(RefusalCode::VenueUnavailable, format!("hyperliquid: {why}"))
}

fn bad(why: impl Into<String>) -> Refusal {
    Refusal::new(RefusalCode::Internal, why)
}

fn bad_args(why: impl Into<String>) -> Refusal {
    Refusal::new(RefusalCode::BadArgs, why)
}

#[derive(Debug, Clone, Copy)]
struct Asset {
    index: u32,
    sz_decimals: u32,
}

/// An order as a bot asks for it. Sizes and prices are decimal strings, never floats.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct OrderSpec {
    /// Perp coin, e.g. "ETH".
    pub coin: String,
    pub is_buy: bool,
    /// Size in coin units, e.g. "0.05".
    pub sz: String,
    /// Limit price in USD. For a trigger order, the worst price it may fill at.
    pub limit_px: String,
    /// "Gtc", "Ioc" or "Alo". Ignored when `trigger_px` is set. Default "Gtc".
    #[schemars(with = "Option<String>")]
    pub tif: Option<Tif>,
    /// Makes this a stop-loss or take-profit order that fires at this price.
    pub trigger_px: Option<String>,
    /// "tp" or "sl". Needed with `trigger_px`.
    #[schemars(with = "Option<String>")]
    pub tpsl: Option<Tpsl>,
    /// With `trigger_px`: fill at market once triggered. Default true.
    pub trigger_is_market: Option<bool>,
    #[serde(default)]
    pub reduce_only: bool,
    /// Client order id, 0x + 32 hex chars.
    pub cloid: Option<String>,
}

pub struct Hyperliquid {
    api_url: String,
    http: reqwest::Client,
    state_dir: PathBuf,
    policies: HashMap<String, HlPolicy>,
    /// Nonces are millisecond timestamps, unique per agent (design §8).
    last_nonce: Mutex<u64>,
    meta: tokio::sync::Mutex<Option<HashMap<String, Asset>>>,
}

impl Hyperliquid {
    pub fn new(config: Option<&HlConfig>, state_dir: PathBuf, policies: HashMap<String, HlPolicy>) -> Self {
        let api_url = config.and_then(|c| c.api_url.clone()).unwrap_or_else(|| TESTNET_API.to_string());
        Self {
            api_url: api_url.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
            state_dir,
            policies,
            last_nonce: Mutex::new(0),
            meta: tokio::sync::Mutex::new(None),
        }
    }

    fn policy(&self, bot: &str) -> Result<&HlPolicy, Refusal> {
        self.policies
            .get(bot)
            .ok_or_else(|| Refusal::new(RefusalCode::MarketNotAllowed, "Hyperliquid is not enabled for this bot"))
    }

    fn nonce(&self) -> u64 {
        let mut last = self.last_nonce.lock().unwrap_or_else(|e| e.into_inner());
        *last = now_ms().max(*last + 1);
        *last
    }

    async fn post(&self, path: &str, body: &Value) -> Result<Value, Refusal> {
        let resp = self.http.post(format!("{}{path}", self.api_url)).json(body).send().await.map_err(venue)?;
        let status = resp.status();
        let text = resp.text().await.map_err(venue)?;
        if !status.is_success() {
            return Err(venue(format!("{status}: {text}")));
        }
        serde_json::from_str(&text).map_err(|_| venue(format!("unreadable reply: {text}")))
    }

    pub async fn info(&self, body: Value) -> Result<Value, Refusal> {
        self.post("/info", &body).await
    }

    async fn asset(&self, coin: &str) -> Result<Asset, Refusal> {
        let mut meta = self.meta.lock().await;
        if meta.is_none() {
            let v = self.info(json!({"type": "meta"})).await?;
            let universe = v["universe"].as_array().ok_or_else(|| venue("meta has no universe"))?;
            let map = universe
                .iter()
                .enumerate()
                .filter_map(|(i, a)| {
                    let name = a["name"].as_str()?.to_string();
                    let sz_decimals = a["szDecimals"].as_u64()? as u32;
                    Some((name, Asset { index: i as u32, sz_decimals }))
                })
                .collect();
            *meta = Some(map);
        }
        meta.as_ref()
            .and_then(|m| m.get(coin).copied())
            .ok_or_else(|| Refusal::new(RefusalCode::MarketNotAllowed, format!("{coin} is not a Hyperliquid perp")))
    }

    fn agent(&self, bot: &str) -> Result<LocalSigner, Refusal> {
        let none = |why: &str| {
            Refusal::new(
                RefusalCode::NoAgentKey,
                format!("{why}; the owner runs `keyshare-mcp hl-approve-agent <config> {bot}`"),
            )
        };
        let text = std::fs::read_to_string(agent_path(&self.state_dir, bot)).map_err(|_| none("no agent key"))?;
        let file: AgentFile = serde_json::from_str(&text).map_err(|_| none("agent key file is unreadable"))?;
        if file.valid_until_ms <= now_ms() + EXPIRY_MARGIN_MS {
            return Err(none("agent key has expired"));
        }
        let signer = LocalSigner::from_hex(&file.key).map_err(|_| none("agent key file is unreadable"))?;
        if signer.address() != file.address {
            return Err(none("agent key does not match its address"));
        }
        Ok(signer)
    }

    /// Master address (queries use it, not the agent's) after the kill switch.
    async fn master(&self, exec: &Executor, bot: &str) -> Result<Address, Refusal> {
        let b = bot.to_string();
        exec.with_wallet(move |w| {
            let a = w.address(&b)?;
            w.kill_switch().check(&b)?;
            Ok(a)
        })
        .await
        .map_err(bad)?
    }

    /// Account value and this coin's signed position size, both `E8`.
    async fn account(&self, master: Address, coin: &str) -> Result<(i128, i128), Refusal> {
        let state = self.info(json!({"type": "clearinghouseState", "user": master})).await?;
        let value = state["marginSummary"]["accountValue"].as_str().ok_or_else(|| venue("no account value"))?;
        let value = hl::parse_e8(value).map_err(venue)?;
        let mut szi = 0;
        for p in state["assetPositions"].as_array().into_iter().flatten() {
            if p["position"]["coin"] == coin {
                szi = hl::parse_e8(p["position"]["szi"].as_str().unwrap_or("0")).map_err(venue)?;
            }
        }
        Ok((value, szi))
    }

    /// The coin's mark price (oracle price if no mark), `E8`. Orders are valued at least at this.
    async fn mark(&self, coin: &str) -> Result<i128, Refusal> {
        let v = self.info(json!({"type": "metaAndAssetCtxs"})).await?;
        let universe = v[0]["universe"].as_array().ok_or_else(|| venue("no universe in metaAndAssetCtxs"))?;
        let i = universe.iter().position(|a| a["name"] == coin).ok_or_else(|| venue(format!("no {coin} context")))?;
        let ctx = &v[1][i];
        let px =
            ctx["markPx"].as_str().or(ctx["oraclePx"].as_str()).ok_or_else(|| venue(format!("no {coin} price")))?;
        hl::parse_e8(px).map_err(venue)
    }

    /// The account's current leverage on this coin.
    async fn leverage(&self, master: Address, coin: &str) -> Result<u32, Refusal> {
        let v = self.info(json!({"type": "activeAssetData", "user": master, "coin": coin})).await?;
        v["leverage"]["value"]
            .as_u64()
            .and_then(|l| u32::try_from(l).ok())
            .ok_or_else(|| venue(format!("no {coin} leverage")))
    }

    /// Total size of resting orders on this coin and side, `E8`. Counted as if they all fill.
    async fn resting(&self, master: Address, coin: &str, is_buy: bool) -> Result<i128, Refusal> {
        let v = self.info(json!({"type": "openOrders", "user": master})).await?;
        let side = if is_buy { "B" } else { "A" };
        let mut total: i128 = 0;
        for o in v.as_array().into_iter().flatten().filter(|o| o["coin"] == coin && o["side"] == side) {
            let sz = hl::parse_e8(o["sz"].as_str().unwrap_or("0")).map_err(venue)?;
            total = total.checked_add(sz).ok_or_else(|| venue("open order sizes overflow"))?;
        }
        Ok(total)
    }

    /// Loss since the first check of the UTC day, `E8`. Records today's starting value if new.
    fn loss_today(&self, bot: &str, value: i128) -> Result<i128, Refusal> {
        let day = now_ms() / 86_400_000;
        let path = day_path(&self.state_dir, bot);
        let start = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str::<DayStart>(&t).ok())
            .filter(|d| d.day == day)
            .and_then(|d| hl::parse_e8(&d.account_value).ok());
        let start = match start {
            Some(s) => s,
            None => {
                let rec = DayStart { day, account_value: hl::wire_e8(value) };
                let text = serde_json::to_vec(&rec).map_err(|e| bad(e.to_string()))?;
                if let Some(dir) = path.parent() {
                    std::fs::create_dir_all(dir).map_err(|e| bad(e.to_string()))?;
                }
                keyshare_core::spend::write_atomic(&path, &text).map_err(|e| bad(e.to_string()))?;
                value
            }
        };
        Ok(start - value)
    }

    /// Builds the wire order after every guardrail passes.
    async fn checked_order(&self, bot: &str, master: Address, o: &OrderSpec) -> Result<OrderWire, Refusal> {
        let policy = self.policy(bot)?;
        policy.check_market(&o.coin)?;
        let asset = self.asset(&o.coin).await?;
        let arg = |what: &str, s: &str| hl::parse_e8(s).map_err(|e| bad_args(format!("{what}: {e}")));
        let sz = arg("sz", &o.sz)?;
        let px = arg("limit_px", &o.limit_px)?;
        if sz <= 0 || px <= 0 {
            return Err(bad_args("sz and limit_px must be above zero"));
        }
        let s = hl::wire_e8(sz);
        if hl::decimals(&s) > asset.sz_decimals {
            return Err(bad_args(format!("{} sizes have at most {} decimals", o.coin, asset.sz_decimals)));
        }
        // Reading the account also sets the day's loss baseline, reduce-only orders included.
        let (value, szi) = self.account(master, &o.coin).await?;
        let loss = self.loss_today(bot, value)?;
        let (value_px, position_after, leverage) = if o.reduce_only {
            (px, 0, 0)
        } else {
            let mark = self.mark(&o.coin).await?;
            let resting = self.resting(master, &o.coin, o.is_buy).await?;
            let overflow = || bad_args("size overflows");
            let added = sz.checked_add(resting).ok_or_else(overflow)?;
            let after = if o.is_buy { szi.checked_add(added) } else { szi.checked_sub(added) }.ok_or_else(overflow)?;
            (px.max(mark), after, self.leverage(master, &o.coin).await?)
        };
        policy.check_order(&OrderCheck {
            coin: &o.coin,
            reduce_only: o.reduce_only,
            sz_e8: sz,
            px_e8: value_px,
            position_after_e8: position_after,
            leverage,
            loss_today_e8: loss,
        })?;
        let t = match &o.trigger_px {
            Some(tp) => OrderTypeWire {
                limit: None,
                trigger: Some(TriggerWire {
                    is_market: o.trigger_is_market.unwrap_or(true),
                    trigger_px: hl::wire_e8(arg("trigger_px", tp)?),
                    tpsl: o.tpsl.clone().ok_or_else(|| bad_args("trigger_px needs tpsl: \"tp\" or \"sl\""))?,
                }),
            },
            None => OrderTypeWire { limit: Some(LimitWire { tif: o.tif.clone().unwrap_or(Tif::Gtc) }), trigger: None },
        };
        if let Some(c) = &o.cloid
            && !(c.len() == 34 && c.starts_with("0x") && c[2..].bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(bad_args("cloid must be 0x followed by 32 hex characters"));
        }
        Ok(OrderWire { a: asset.index, b: o.is_buy, p: hl::wire_e8(px), s, r: o.reduce_only, t, c: o.cloid.clone() })
    }

    /// Audits, signs with the agent key and posts one L1 action.
    async fn send(&self, exec: &Executor, bot: &str, id: &str, action: L1Action) -> Result<Outcome, String> {
        let detail = json!({ "venue": "hyperliquid", "action": action });
        let signed = (|| {
            let agent = self.agent(bot)?;
            let nonce = self.nonce();
            let hash = hl::action_hash(&action, None, nonce, None).map_err(bad)?;
            let sig = agent.sign_typed_data(&hl::l1_typed_data(hash, MAINNET)).map_err(|e| bad(e.to_string()))?;
            Ok::<_, Refusal>((nonce, hl::signature_json(&sig)))
        })();
        let (nonce, signature) = match signed {
            Ok(s) => s,
            Err(r) => return self.refuse(exec, bot, id, detail, r).await,
        };
        let (b, i, d) = (bot.to_string(), id.to_string(), detail.clone());
        exec.with_wallet(move |w| {
            let now = crate::exec::now();
            w.log_event(&b, &i, AuditEvent::Requested, d, now);
            w.log_event(&b, &i, AuditEvent::Signed, json!({ "nonce": nonce }), now);
        })
        .await?;
        let body = json!({
            "action": action,
            "nonce": nonce,
            "signature": signature,
            "vaultAddress": Value::Null,
            "expiresAfter": Value::Null,
        });
        Ok(match self.post("/exchange", &body).await {
            Ok(resp) if resp["status"] == "ok" => Ok(json!({ "request_id": id, "response": resp["response"] })),
            Ok(resp) => Err(json!({
                "refused": true, "code": "VENUE_REJECTED", "reason": resp["response"], "request_id": id
            })),
            Err(r) => Err(refusal_json(id, &r)),
        })
    }

    async fn refuse(&self, exec: &Executor, bot: &str, id: &str, detail: Value, r: Refusal) -> Result<Outcome, String> {
        let (b, i, rr) = (bot.to_string(), id.to_string(), r.clone());
        exec.with_wallet(move |w| w.log_refusal(&b, &i, detail, &rr, crate::exec::now())).await?;
        Ok(Err(refusal_json(id, &r)))
    }

    pub async fn place_order(&self, exec: &Executor, bot: &str, id: &str, o: OrderSpec) -> Result<Outcome, String> {
        let wire = match self.prepare(exec, bot, &o).await {
            Ok(w) => w,
            Err(r) => {
                return self.refuse(exec, bot, id, json!({ "venue": "hyperliquid", "order": o_json(&o) }), r).await;
            }
        };
        self.send(exec, bot, id, L1Action::order(vec![wire])).await
    }

    pub async fn modify(
        &self,
        exec: &Executor,
        bot: &str,
        id: &str,
        oid: u64,
        o: OrderSpec,
    ) -> Result<Outcome, String> {
        let wire = match self.prepare(exec, bot, &o).await {
            Ok(w) => w,
            Err(r) => {
                let detail = json!({ "venue": "hyperliquid", "modify": oid, "order": o_json(&o) });
                return self.refuse(exec, bot, id, detail, r).await;
            }
        };
        self.send(exec, bot, id, L1Action::modify(vec![ModifyWire { oid, order: wire }])).await
    }

    async fn prepare(&self, exec: &Executor, bot: &str, o: &OrderSpec) -> Result<OrderWire, Refusal> {
        let master = self.master(exec, bot).await?;
        self.checked_order(bot, master, o).await
    }

    pub async fn cancel(&self, exec: &Executor, bot: &str, id: &str, coin: &str, oid: u64) -> Result<Outcome, String> {
        let checked = async {
            self.master(exec, bot).await?;
            self.policy(bot)?.check_market(coin)?;
            self.asset(coin).await
        };
        match checked.await {
            Ok(a) => self.send(exec, bot, id, L1Action::cancel(vec![CancelWire { a: a.index, o: oid }])).await,
            Err(r) => {
                self.refuse(exec, bot, id, json!({ "venue": "hyperliquid", "cancel": oid, "coin": coin }), r).await
            }
        }
    }

    pub async fn set_leverage(
        &self,
        exec: &Executor,
        bot: &str,
        id: &str,
        coin: &str,
        leverage: u32,
        is_cross: bool,
    ) -> Result<Outcome, String> {
        let checked = async {
            self.master(exec, bot).await?;
            self.policy(bot)?.check_leverage(coin, leverage)?;
            self.asset(coin).await
        };
        match checked.await {
            Ok(a) => self.send(exec, bot, id, L1Action::update_leverage(a.index, is_cross, leverage)).await,
            Err(r) => {
                let detail = json!({ "venue": "hyperliquid", "leverage": leverage, "coin": coin });
                self.refuse(exec, bot, id, detail, r).await
            }
        }
    }

    /// Positions, margin and open orders of this bot's master account.
    pub async fn positions(&self, exec: &Executor, bot: &str) -> Outcome {
        let run = async {
            let b = bot.to_string();
            let master = exec.with_wallet(move |w| w.address(&b)).await.map_err(bad)??;
            self.policy(bot)?;
            let state = self.info(json!({"type": "clearinghouseState", "user": master})).await?;
            // A read sets the day's loss baseline too, so overnight losses count from the first look.
            if let Some(v) = state["marginSummary"]["accountValue"].as_str().and_then(|v| hl::parse_e8(v).ok()) {
                self.loss_today(bot, v)?;
            }
            let orders = self.info(json!({"type": "openOrders", "user": master})).await?;
            Ok::<_, Refusal>(json!({ "master": master, "state": state, "open_orders": orders }))
        };
        run.await.map_err(|r| refusal_json("", &r))
    }
}

fn o_json(o: &OrderSpec) -> Value {
    json!({ "coin": o.coin, "is_buy": o.is_buy, "sz": o.sz, "limit_px": o.limit_px, "reduce_only": o.reduce_only })
}

fn refusal_json(id: &str, r: &Refusal) -> Value {
    let mut v = json!(r);
    v["request_id"] = json!(id);
    v
}

/// Generates a brand-new agent key, has the bot's wallet key (the master) approve it on
/// Hyperliquid testnet, and saves it where the server reads it. Run by the owner, not a bot.
/// An agent address is never reused (design §8).
pub async fn approve_agent(
    config: &Config,
    bot: &str,
    hours: u64,
    env: impl Fn(&str) -> Option<String>,
) -> Result<AgentFile, String> {
    let cfg = config.bots.get(bot).ok_or_else(|| format!("no bot {bot} in the config"))?;
    if cfg.hyperliquid.is_none() {
        return Err(format!("bot {bot} has no [bots.{bot}.hyperliquid] table"));
    }
    KillSwitch::new(config.state_paths().kill_switch).check(bot).map_err(|r| r.reason)?;
    let key = env(&cfg.key_env).ok_or_else(|| format!("{} is not set", cfg.key_env))?;
    let master = LocalSigner::from_hex(&key).map_err(|e| e.to_string())?;
    let agent_key = B256::random().to_string();
    let agent = LocalSigner::from_hex(&agent_key).map_err(|e| e.to_string())?;
    let nonce = now_ms();
    let valid_until_ms = nonce + hours * 3_600_000;
    // Hyperliquid reads an agent's expiry from this suffix on its name.
    let name = format!("keyshare-{bot} valid_until {valid_until_ms}");
    let (action, data) = hl::approve_agent(agent.address(), &name, nonce, MAINNET);
    let sig = master.sign_typed_data(&data).map_err(|e| e.to_string())?;
    let body = json!({
        "action": action,
        "nonce": nonce,
        "signature": hl::signature_json(&sig),
        "vaultAddress": Value::Null,
        "expiresAfter": Value::Null,
    });
    let venue = config.hyperliquid().map_err(|e| e.to_string())?;
    let resp = venue.post("/exchange", &body).await.map_err(|r| r.reason)?;
    if resp["status"] != "ok" {
        return Err(format!("Hyperliquid refused the agent: {resp}"));
    }
    let file = AgentFile { address: agent.address(), key: agent_key, name, valid_until_ms };
    let text = serde_json::to_vec_pretty(&file).map_err(|e| e.to_string())?;
    write_private(&agent_path(&config.server.state_dir, bot), &text).map_err(|e| e.to_string())?;
    Ok(file)
}

/// Writes a file only its owner can read, replacing any old one.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    // A stale tmp file could carry looser permissions; start fresh so mode 0600 applies.
    match std::fs::remove_file(&tmp) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}
