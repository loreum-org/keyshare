//! Hyperliquid testnet trading (design §8). The bot's wallet key is the master account; a
//! separate agent key, approved by the master with `keyshare-mcp hl-approve-agent`, signs orders.
//! The agent can't withdraw or transfer, so funds only leave through the master.
//!
//! Every action goes through the kill switch, this bot's [`HlPolicy`] and the audit log before
//! the agent key signs it.

use std::collections::{HashMap, HashSet};
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
/// for local mocks. The host is the authority after the scheme, not the text before the first
/// colon: `http://127.0.0.1:x@api.hyperliquid.xyz` is userinfo plus the mainnet host.
pub fn check_api_url(config: Option<&HlConfig>) -> Result<(), String> {
    let Some(raw) = config.and_then(|c| c.api_url.as_deref()) else { return Ok(()) };
    let bad = || format!("hyperliquid api_url {raw:?} is not testnet; Phase 0 is testnet only");
    let (https, rest) = if let Some(rest) = raw.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = raw.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(bad());
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') || authority.contains('\\') {
        return Err(bad());
    }
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => authority,
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let loopback = matches!(host.as_str(), "127.0.0.1" | "localhost");
    if host == "api.hyperliquid-testnet.xyz" && https || loopback { Ok(()) } else { Err(bad()) }
}

pub fn agent_path(state_dir: &Path, bot: &str) -> PathBuf {
    state_dir.join("hyperliquid").join(format!("{bot}.agent.json"))
}

fn day_path(state_dir: &Path, bot: &str) -> PathBuf {
    state_dir.join("hyperliquid").join(format!("{bot}.day.json"))
}

/// Account value at the first check of the UTC day, for the daily loss stop.
/// `basis` records which figure was stored. Files written before unified accounts
/// have no basis; a value of zero in those files is the perp `accountValue`, which
/// is not the equity of a unified account.
#[derive(Debug, Serialize, Deserialize)]
struct DayStart {
    day: u64,
    account_value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    basis: Option<String>,
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

/// USDC is token 0. Unified accounts collateralize validator-operated perps with it.
const USDC_TOKEN: u64 = 0;
const BASIS_PERP: &str = "perp_account_value";
const BASIS_UNIFIED: &str = "spot_usdc_total_plus_unrealized_pnl";

/// Equity used for reporting and the daily loss stop. Built only from fields the
/// venue documents for that account mode. A missing figure is an error, not zero.
#[derive(Debug)]
struct Equity {
    /// Raw `userAbstraction` mode.
    mode: String,
    equity: i128,
    /// Venue string when it is a single field, otherwise the canonical wire form.
    equity_wire: String,
    equity_source: &'static str,
    /// Spot USDC `total` as the venue sent it. Unified accounts only.
    usdc_total: Option<String>,
    /// Sum of default-dex unrealized PnL. Unified accounts only.
    unrealized_pnl: Option<i128>,
    available_wire: Option<String>,
    available_source: Option<&'static str>,
    positions: HashMap<String, i128>,
    /// A legacy baseline of exactly 0 may be replaced with `equity`.
    repair_legacy_zero: bool,
    /// A legacy baseline of exactly 0 must not be used.
    reject_legacy_zero: bool,
}

impl Equity {
    fn szi(&self, coin: &str) -> i128 {
        self.positions.get(coin).copied().unwrap_or(0)
    }

    fn report(&self) -> Value {
        let mut v = json!({
            "abstraction": self.mode,
            "equity": self.equity_wire,
            "equity_source": self.equity_source,
        });
        if let Some(total) = &self.usdc_total {
            v["usdc_total"] = json!(total);
        }
        if let Some(pnl) = self.unrealized_pnl {
            v["unrealized_pnl"] = json!(hl::wire_e8(pnl));
        }
        if let (Some(margin), Some(source)) = (&self.available_wire, self.available_source) {
            v["available_margin"] = json!(margin);
            v["available_source"] = json!(source);
        }
        v
    }
}

fn decimal_field<'a>(v: &'a Value, what: &str) -> Result<(&'a str, i128), Refusal> {
    let s = v.as_str().ok_or_else(|| venue(format!("{what} is not a string")))?;
    let n = hl::parse_e8(s).map_err(|_| venue(format!("{what} is not a decimal")))?;
    Ok((s, n))
}

/// `true` for modes whose perp `accountValue` is the equity. Unified and portfolio
/// margin keep balances in the spot clearinghouse; their perp account value is not.
fn standard_mode(mode: &str) -> bool {
    matches!(mode, "default" | "disabled" | "dexAbstraction")
}

fn positions_of(state: &Value, unified: bool) -> Result<(HashMap<String, i128>, i128, bool), Refusal> {
    let rows = state["assetPositions"].as_array().ok_or_else(|| venue("asset positions missing"))?;
    let mut positions = HashMap::new();
    let mut pnl = 0i128;
    let mut flat = true;
    for row in rows {
        let pos = &row["position"];
        let coin = pos["coin"].as_str().ok_or_else(|| venue("position has no coin"))?.to_string();
        let (_, szi) = decimal_field(&pos["szi"], &format!("{coin} position size"))?;
        if szi != 0 {
            flat = false;
        }
        // Last row for a coin wins, as the previous scan did. Flatness still sees every row.
        positions.insert(coin.clone(), szi);
        if !unified {
            continue;
        }
        match pos.get("unrealizedPnl") {
            None | Some(Value::Null) if szi == 0 => {}
            None | Some(Value::Null) => {
                return Err(venue(format!("{coin} unrealized PnL is missing")));
            }
            Some(raw) => {
                let (_, p) = decimal_field(raw, &format!("{coin} unrealized PnL"))?;
                if szi == 0 && p != 0 {
                    return Err(venue(format!("{coin} is flat but has unrealized PnL")));
                }
                pnl = pnl.checked_add(p).ok_or_else(|| venue("unrealized PnL overflow"))?;
            }
        }
    }
    Ok((positions, pnl, flat))
}

fn perp_equity(mode: &str, state: &Value) -> Result<Equity, Refusal> {
    let (wire, equity) = decimal_field(&state["marginSummary"]["accountValue"], "account value")?;
    let (positions, _, _) = positions_of(state, false)?;
    let (available_wire, available_source) = match state.get("withdrawable") {
        None | Some(Value::Null) => (None, None),
        Some(raw) => {
            let (wire, _) = decimal_field(raw, "withdrawable")?;
            (Some(wire.to_string()), Some("withdrawable"))
        }
    };
    Ok(Equity {
        mode: mode.to_string(),
        equity,
        equity_wire: wire.to_string(),
        equity_source: BASIS_PERP,
        usdc_total: None,
        unrealized_pnl: None,
        available_wire,
        available_source,
        positions,
        repair_legacy_zero: false,
        reject_legacy_zero: false,
    })
}

fn unified_equity(mode: &str, state: &Value, spot: &Value) -> Result<Equity, Refusal> {
    let balances = spot["balances"].as_array().ok_or_else(|| venue("spot balances missing"))?;
    let mut usdc: Option<(String, i128, i128)> = None;
    for row in balances {
        if row.get("borrow").is_some() || row.get("debt").is_some() {
            return Err(venue("spot borrow or debt is not priced"));
        }
        let token = row["token"].as_u64().ok_or_else(|| venue("spot balance token is not an index"))?;
        let (wire, total) = decimal_field(&row["total"], "spot balance total")?;
        let (_, hold) = decimal_field(&row["hold"], "spot balance hold")?;
        let coin = row["coin"].as_str().unwrap_or("");
        if token == USDC_TOKEN {
            if coin != "USDC" {
                return Err(venue("token 0 is not USDC"));
            }
            if usdc.is_some() {
                return Err(venue("more than one USDC balance"));
            }
            usdc = Some((wire.to_string(), total, hold));
        } else if total != 0 || hold != 0 {
            return Err(venue(format!("non-USDC spot balance {coin} (token {token}) is not perp equity")));
        }
    }
    let (usdc_wire, usdc_total, hold) = usdc.ok_or_else(|| venue("no USDC balance in the spot clearinghouse"))?;
    let rows = spot["tokenToAvailableAfterMaintenance"]
        .as_array()
        .ok_or_else(|| venue("tokenToAvailableAfterMaintenance is missing"))?;
    let mut available: Option<(String, i128)> = None;
    for row in rows {
        let pair =
            row.as_array().filter(|p| p.len() == 2).ok_or_else(|| venue("available margin entry is not a pair"))?;
        let token = pair[0].as_u64().ok_or_else(|| venue("available margin token is not an index"))?;
        let (wire, amount) = decimal_field(&pair[1], "available margin")?;
        if token == USDC_TOKEN {
            if available.is_some() {
                return Err(venue("more than one USDC available margin"));
            }
            available = Some((wire.to_string(), amount));
        } else if amount != 0 {
            return Err(venue(format!("non-USDC available margin for token {token} is not priced")));
        }
    }
    let (available_wire, available) = available.ok_or_else(|| venue("no USDC available margin"))?;
    if available > usdc_total {
        return Err(venue("USDC available margin exceeds the USDC balance"));
    }
    let (positions, pnl, flat) = positions_of(state, true)?;
    let equity = usdc_total.checked_add(pnl).ok_or_else(|| venue("unified equity overflow"))?;
    // Cash is the spot USDC total. Unrealized PnL is not inside that total and is not
    // the perp account value, which is not the balance on a unified account.
    let equity_wire = if pnl == 0 { usdc_wire.clone() } else { hl::wire_e8(equity) };
    Ok(Equity {
        mode: mode.to_string(),
        equity,
        equity_wire,
        equity_source: BASIS_UNIFIED,
        usdc_total: Some(usdc_wire),
        unrealized_pnl: Some(pnl),
        available_wire: Some(available_wire),
        available_source: Some("token_to_available_after_maintenance"),
        positions,
        repair_legacy_zero: flat && hold == 0 && equity > 0,
        reject_legacy_zero: (!flat || hold != 0) && equity > 0,
    })
}

fn equity_of(abstraction: &Value, state: &Value, spot: Option<&Value>) -> Result<Equity, Refusal> {
    let mode = abstraction.as_str().ok_or_else(|| venue("userAbstraction is not a mode"))?;
    if standard_mode(mode) {
        return perp_equity(mode, state);
    }
    if mode == "unifiedAccount" {
        let spot = spot.ok_or_else(|| venue("spot clearinghouse state is missing"))?;
        return unified_equity(mode, state, spot);
    }
    if mode == "portfolioMargin" {
        return Err(venue("portfolio margin equity is not priced here"));
    }
    Err(venue(format!("unsupported account abstraction {mode}")))
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
    /// Caller-scoped request ids that have reached signing. In memory, like EVM request ids: a
    /// restart forgets them. A second use is refused before the agent signs again.
    used_requests: Mutex<HashSet<String>>,
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
            used_requests: Mutex::new(HashSet::new()),
            meta: tokio::sync::Mutex::new(None),
        }
    }

    /// `true` when this caller is the first to use `key`.
    fn claim_request(&self, key: &str) -> bool {
        let mut used = self.used_requests.lock().unwrap_or_else(|e| e.into_inner());
        used.insert(key.to_string())
    }

    fn release_request(&self, key: &str) {
        let mut used = self.used_requests.lock().unwrap_or_else(|e| e.into_inner());
        used.remove(key);
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

    /// Equity for this master. Standard modes use the perp account value. A unified
    /// account uses spot USDC plus unrealized PnL, and does not add the perp value.
    async fn equity(&self, master: Address) -> Result<(Value, Equity), Refusal> {
        let abstraction = self.info(json!({"type": "userAbstraction", "user": master})).await?;
        let state = self.info(json!({"type": "clearinghouseState", "user": master})).await?;
        let mode = abstraction.as_str().ok_or_else(|| venue("userAbstraction is not a mode"))?;
        let spot = if mode == "unifiedAccount" {
            Some(self.info(json!({"type": "spotClearinghouseState", "user": master})).await?)
        } else {
            None
        };
        let equity = equity_of(&abstraction, &state, spot.as_ref())?;
        Ok((state, equity))
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

    /// Today's saved equity, if the file is for this UTC day. A missing file is `None`.
    /// An unreadable file is an error and is left in place.
    fn load_day(&self, path: &Path, day: u64) -> Result<Option<DayStart>, Refusal> {
        match std::fs::read_to_string(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(bad(e.to_string())),
            Ok(text) if text.trim().is_empty() => Err(bad("daily loss baseline is empty")),
            Ok(text) => {
                let rec: DayStart =
                    serde_json::from_str(&text).map_err(|_| bad("daily loss baseline is unreadable"))?;
                if rec.day != day {
                    return Ok(None);
                }
                hl::parse_e8(&rec.account_value).map_err(|_| bad("daily loss baseline is unreadable"))?;
                Ok(Some(rec))
            }
        }
    }

    fn store_day(&self, path: &Path, day: u64, eq: &Equity) -> Result<(), Refusal> {
        let rec = DayStart { day, account_value: hl::wire_e8(eq.equity), basis: Some(eq.equity_source.to_string()) };
        let text = serde_json::to_vec(&rec).map_err(|e| bad(e.to_string()))?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| bad(e.to_string()))?;
        }
        keyshare_core::spend::write_atomic(path, &text).map_err(|e| bad(e.to_string()))
    }

    /// Loss since the first check of the UTC day, `E8`. Records today's equity if new.
    /// A legacy baseline of exactly 0 is the old perp reading: it is replaced only for a
    /// flat unified account, and otherwise refuses new risk instead of counting as a gain.
    fn loss_today(&self, bot: &str, eq: &Equity) -> Result<i128, Refusal> {
        let day = now_ms() / 86_400_000;
        let path = day_path(&self.state_dir, bot);
        let start = match self.load_day(&path, day)? {
            Some(rec) => {
                let saved = hl::parse_e8(&rec.account_value).map_err(|_| bad("daily loss baseline is unreadable"))?;
                if saved == 0 && rec.basis.is_none() {
                    if eq.repair_legacy_zero {
                        self.store_day(&path, day, eq)?;
                        eq.equity
                    } else if eq.reject_legacy_zero {
                        return Err(venue("untrusted zero daily-loss baseline was not replaced"));
                    } else {
                        saved
                    }
                } else {
                    saved
                }
            }
            None => {
                self.store_day(&path, day, eq)?;
                eq.equity
            }
        };
        Ok(start - eq.equity)
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
        // Reading equity also sets the day's loss baseline. A reduce-only order only shrinks
        // risk, so a failed read or baseline write never blocks it.
        let read = async {
            let (_, eq) = self.equity(master).await?;
            let szi = eq.szi(&o.coin);
            Ok::<_, Refusal>((szi, self.loss_today(bot, &eq)?))
        };
        let (szi, loss) = if o.reduce_only { read.await.unwrap_or((0, 0)) } else { read.await? };
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
        let key = crate::exec::scoped(bot, id);
        if !self.claim_request(&key) {
            let r = Refusal::new(RefusalCode::NonceReused, format!("request {id} was already used"));
            return self.refuse(exec, bot, id, detail, r).await;
        }
        // Recheck immediately before signing. `prepare` already checked, then waited on the venue.
        let b = bot.to_string();
        match exec.with_wallet(move |w| w.kill_switch().check(&b)).await {
            Ok(Ok(())) => {}
            Ok(Err(r)) => {
                self.release_request(&key);
                return self.refuse(exec, bot, id, detail, r).await;
            }
            Err(e) => {
                self.release_request(&key);
                return Err(e);
            }
        }
        let (b, i, d) = (bot.to_string(), id.to_string(), detail.clone());
        if let Err(e) =
            exec.with_wallet(move |w| w.log_event(&b, &i, AuditEvent::Requested, d, crate::exec::now())).await
        {
            self.release_request(&key);
            return Err(e);
        }
        let signed = (|| {
            let agent = self.agent(bot)?;
            let nonce = self.nonce();
            let hash = hl::action_hash(&action, None, nonce, None).map_err(bad)?;
            let sig = agent.sign_typed_data(&hl::l1_typed_data(hash, MAINNET)).map_err(|e| bad(e.to_string()))?;
            Ok::<_, Refusal>((nonce, hl::signature_json(&sig)))
        })();
        let (nonce, signature) = match signed {
            Ok(s) => s,
            Err(r) => {
                self.release_request(&key);
                return self.refuse(exec, bot, id, detail, r).await;
            }
        };
        // Signed from here, whether or not the post lands. The id stays used.
        let (b, i) = (bot.to_string(), id.to_string());
        exec.with_wallet(move |w| {
            w.log_event(&b, &i, AuditEvent::Signed, json!({ "nonce": nonce }), crate::exec::now())
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
            let (state, eq) = self.equity(master).await?;
            // A read sets the day's loss baseline too, so overnight losses count from the first look.
            self.loss_today(bot, &eq)?;
            let orders = self.info(json!({"type": "openOrders", "user": master})).await?;
            Ok::<_, Refusal>(json!({
                "master": master,
                "state": state,
                "open_orders": orders,
                "account": eq.report(),
            }))
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

#[cfg(test)]
mod equity_tests {
    use super::*;

    fn spot_usdc(total: &str, hold: &str, available: &str, extra: Value) -> Value {
        let mut balances = vec![json!({"coin":"USDC","token":0,"total": total, "hold": hold, "entryNtl":"0.0"})];
        if !extra.is_null() {
            balances.push(extra);
        }
        json!({
            "balances": balances,
            "tokenToAvailableAfterMaintenance": [[0, available]],
        })
    }

    fn state(account_value: &str, positions: Value) -> Value {
        json!({"marginSummary": {"accountValue": account_value}, "assetPositions": positions})
    }

    fn unified(total: &str, positions: Value) -> Equity {
        equity_of(
            &json!("unifiedAccount"),
            &state("0.0", positions),
            Some(&spot_usdc(total, "0.0", total, Value::Null)),
        )
        .unwrap()
    }

    fn reason(abstraction: Value, state: Value, spot: Option<Value>) -> String {
        equity_of(&abstraction, &state, spot.as_ref()).unwrap_err().reason
    }

    #[test]
    fn unified_flat_usdc_is_not_the_perp_account_value() {
        let eq = unified("999.0", json!([]));
        let report = eq.report();
        assert_eq!(report["abstraction"], "unifiedAccount");
        assert_eq!(report["equity"], "999.0");
        assert_eq!(report["equity_source"], BASIS_UNIFIED);
        assert_eq!(report["usdc_total"], "999.0");
        assert_eq!(report["unrealized_pnl"], "0");
        assert_eq!(report["available_margin"], "999.0");
        assert_eq!(report["available_source"], "token_to_available_after_maintenance");
        assert!(eq.repair_legacy_zero);
        assert!(!eq.reject_legacy_zero);
        // A non-zero perp account value is not added on top of the USDC balance.
        let spot = spot_usdc("999.0", "0.0", "999.0", Value::Null);
        let eq = equity_of(&json!("unifiedAccount"), &state("50.0", json!([])), Some(&spot)).unwrap();
        assert_eq!(eq.equity_wire, "999.0");
    }

    #[test]
    fn unified_equity_adds_unrealized_pnl_once() {
        let positions = json!([{"position": {"coin": "ETH", "szi": "0.1", "unrealizedPnl": "-10.5"}}]);
        let spot = spot_usdc("999.0", "0.0", "999.0", Value::Null);
        // Perp account value echoes the same PnL. Adding it again would make equity 978.
        let eq = equity_of(&json!("unifiedAccount"), &state("-10.5", positions), Some(&spot)).unwrap();
        assert_eq!(eq.equity_wire, "988.5");
        assert_eq!(eq.report()["unrealized_pnl"], "-10.5");
        assert_eq!(eq.szi("ETH"), hl::parse_e8("0.1").unwrap());
        assert!(!eq.repair_legacy_zero);
        assert!(eq.reject_legacy_zero);
    }

    #[test]
    fn standard_equity_ignores_spot_and_position_pnl() {
        let positions = json!([{"position": {"coin": "ETH", "szi": "1", "unrealizedPnl": "50"}}]);
        let state = json!({
            "marginSummary": {"accountValue": "10000.0"},
            "withdrawable": "8000",
            "assetPositions": positions,
        });
        let spot = spot_usdc("999.0", "0.0", "999.0", Value::Null);
        let eq = equity_of(&json!("default"), &state, Some(&spot)).unwrap();
        assert_eq!(eq.equity_wire, "10000.0");
        assert_eq!(eq.report()["available_margin"], "8000");
        assert_eq!(eq.report()["available_source"], "withdrawable");
        assert!(eq.report().get("usdc_total").is_none());
        assert!(!eq.repair_legacy_zero);
        let disabled = equity_of(&json!("disabled"), &state, None).unwrap();
        assert_eq!(disabled.equity_wire, "10000.0");
        let dex = equity_of(&json!("dexAbstraction"), &state, None).unwrap();
        assert_eq!(dex.equity_wire, "10000.0");
        assert!(dex.report().get("available_margin").is_some());
    }

    #[test]
    fn failed_or_unsupported_reads_are_not_zero() {
        let flat = state("0.0", json!([]));
        let spot = spot_usdc("999.0", "0.0", "999.0", Value::Null);
        let cases = [
            (json!(null), flat.clone(), Some(spot.clone()), "not a mode"),
            (json!("portfolioMargin"), flat.clone(), Some(spot.clone()), "portfolio margin"),
            (json!("somethingElse"), flat.clone(), None, "unsupported account abstraction"),
            (json!("unifiedAccount"), flat.clone(), None, "spot clearinghouse"),
            (
                json!("unifiedAccount"),
                json!({"marginSummary": {"accountValue": "0.0"}}),
                Some(spot.clone()),
                "asset positions",
            ),
            (json!("default"), json!({"marginSummary": {}}), None, "account value"),
            (json!("default"), json!({"marginSummary": {"accountValue": "1"}}), None, "asset positions"),
        ];
        for (mode, state, spot, needle) in cases {
            let why = reason(mode, state, spot);
            assert!(why.contains(needle), "{why} does not mention {needle}");
        }
        let open = json!([{"position": {"coin": "ETH", "szi": "0.1"}}]);
        let why = reason(json!("unifiedAccount"), state("0.0", open), Some(spot.clone()));
        assert!(why.contains("unrealized PnL is missing"), "{why}");
        let weird = json!([{"position": {"coin": "ETH", "szi": "0", "unrealizedPnl": "1"}}]);
        let why = reason(json!("unifiedAccount"), state("0.0", weird), Some(spot.clone()));
        assert!(why.contains("flat but has unrealized PnL"), "{why}");
        let purr = spot_usdc("999.0", "0.0", "999.0", json!({"coin":"PURR","token":1,"total":"2","hold":"0.0"}));
        let why = reason(json!("unifiedAccount"), flat.clone(), Some(purr));
        assert!(why.contains("non-USDC"), "{why}");
        let dust = spot_usdc(
            "999.0",
            "0.0",
            "999.0",
            json!({"coin":"PURR","token":1,"total":"0.0","hold":"0.0","entryNtl":"12.5"}),
        );
        let eq = equity_of(&json!("unifiedAccount"), &flat, Some(&dust)).unwrap();
        assert_eq!(eq.equity_wire, "999.0");
        let borrowed = json!({
            "balances": [{"coin":"USDC","token":0,"total":"999.0","hold":"0.0","borrow":"1"}],
            "tokenToAvailableAfterMaintenance": [[0, "999.0"]],
        });
        let why = reason(json!("unifiedAccount"), flat.clone(), Some(borrowed));
        assert!(why.contains("borrow"), "{why}");
        let mut over = spot.clone();
        over["tokenToAvailableAfterMaintenance"] = json!([[0, "1000.0"]]);
        let why = reason(json!("unifiedAccount"), flat.clone(), Some(over));
        assert!(why.contains("exceeds"), "{why}");
        let mut missing = spot.clone();
        missing.as_object_mut().unwrap().remove("tokenToAvailableAfterMaintenance");
        let why = reason(json!("unifiedAccount"), flat, Some(missing));
        assert!(why.contains("tokenToAvailableAfterMaintenance"), "{why}");
        // A hold is not subtracted by hand, and it blocks replacing a legacy zero.
        let held = spot_usdc("999.0", "100.0", "850.0", Value::Null);
        let eq = equity_of(&json!("unifiedAccount"), &state("0.0", json!([])), Some(&held)).unwrap();
        assert_eq!(eq.equity_wire, "999.0");
        assert_eq!(eq.report()["available_margin"], "850.0");
        assert!(!eq.repair_legacy_zero);
        assert!(eq.reject_legacy_zero);
        // Negative USDC is debt, not a missing read.
        let eq = unified("-10.0", json!([]));
        assert_eq!(eq.equity, hl::parse_e8("-10.0").unwrap());
        assert!(!eq.repair_legacy_zero);
    }
}
