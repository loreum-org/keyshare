//! Runs state-changing requests (design §4): policy pre-check → simulate → sign → broadcast.
//! A refusal the owner can waive (allowlist miss, cap, co-sign threshold) is held for the owner's
//! admin approval instead (§13.2). Shared by the MCP tools and the admin endpoints.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::consensus::TxEip1559;
use alloy::primitives::{Address, B256, Signature};
use keyshare_core::approval::{self, Decision};
use keyshare_core::audit::AuditEvent;
use keyshare_core::policy::{TypedDataRule, Verdict};
use keyshare_core::price::{MICROS_PER_USD, PriceEntry, UsdMicros};
use keyshare_core::{Action, Refusal, RefusalCode, Signer, Wallet};
use keyshare_module::{Grant, ModuleView, authorize_typed};
use serde::Serialize;
use serde_json::{Value, json};

use crate::chain::{self, Chains};
use crate::config::Config;
use crate::hl::Hyperliquid;
use crate::policy::{self, LoadedPolicy, ModuleToggles};
use keyshare_core::PlainPolicy;
use keyshare_core::policy::PolicyEngine;
use keyshare_core::policy_file::{PolicyRef, VersionGate};

/// How long a held request waits for the owner (design §13.2 step 5, estimate).
pub const DEFAULT_HOLD_SECS: u64 = 15 * 60;

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn usd(micros: u128) -> String {
    format!("{}.{:06}", micros / MICROS_PER_USD, micros % MICROS_PER_USD)
}

fn tx_detail(tx: &TxEip1559) -> Value {
    json!({ "chain_id": tx.chain_id, "to": tx.to.to(), "value": tx.value, "data": tx.input })
}

/// Result of a request: `Ok` is a normal tool result, `Err` a refusal (`{refused, code, reason}`).
pub type Outcome = Result<Value, Value>;

fn refusal(id: &str, r: &Refusal) -> Value {
    let mut v = json!(r);
    v["request_id"] = json!(id);
    v
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RequestState {
    PendingUserApproval {
        reason: Refusal,
        expires_at: u64,
    },
    /// The owner approved and the request is being signed and sent.
    Executing,
    Broadcast {
        tx_hash: B256,
        approved_by_owner: bool,
    },
    Refused {
        refusal: Refusal,
    },
}

#[derive(Debug, Clone)]
struct Request {
    caller: String,
    id: String,
    /// As submitted, before nonce and gas are filled. Approvals bind to this.
    tx: TxEip1559,
    state: RequestState,
}

pub struct Executor {
    wallet: Arc<Mutex<Wallet>>,
    pub chains: Arc<Chains>,
    /// Priced tokens, for `balances`. Replaced with the policy's price list on reload.
    tokens: RwLock<Arc<Vec<PriceEntry>>>,
    pub hl: Option<Arc<Hyperliquid>>,
    /// Per-bot module switches. A bot with no entry is offered every module.
    modules: RwLock<HashMap<String, ModuleToggles>>,
    /// The signed policy in force.
    active: RwLock<Option<ActivePolicy>>,
    /// Last rejected policy (hash and reason), so a bad file is logged once, not every poll.
    last_rejected: Mutex<Option<String>>,
    /// Held from nonce lookup to broadcast so two sends never get the same nonce.
    send_lock: tokio::sync::Mutex<()>,
    /// Keyed by the caller-scoped request id. In memory: a restart drops held requests, which
    /// then never sign.
    requests: Mutex<HashMap<String, Request>>,
    hold_secs: u64,
}

/// The signed policy in force, as the `policy` tool reports it.
#[derive(Debug, Clone)]
pub struct ActivePolicy {
    pub reference: PolicyRef,
    pub signer: Address,
    pub loaded_at: u64,
    pub set: Arc<policy::PolicySet>,
}

/// What a reload attempt did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reload {
    Unchanged,
    Loaded(PolicyRef),
    /// The file was refused; the previous policy stays in force.
    Rejected(String),
}

/// Held requests one bot may have waiting for the owner at once.
const MAX_PENDING_PER_BOT: usize = 16;

enum Claim {
    Ready(Box<Request>),
    Expired,
    Unavailable,
}

fn releases_request_id(state: &RequestState, t: u64) -> bool {
    match state {
        RequestState::PendingUserApproval { expires_at, .. } => *expires_at <= t,
        RequestState::Refused { refusal } => refusal.code == RefusalCode::Expired,
        RequestState::Executing | RequestState::Broadcast { .. } => false,
    }
}

/// Request ids are namespaced per caller so one bot can't burn another's ids.
pub fn scoped(caller: &str, id: &str) -> String {
    format!("{caller}:{id}")
}

impl Executor {
    pub fn new(wallet: Arc<Mutex<Wallet>>, chains: Arc<Chains>, tokens: Arc<Vec<PriceEntry>>, hold_secs: u64) -> Self {
        Self {
            wallet,
            chains,
            tokens: RwLock::new(tokens),
            hl: None,
            modules: RwLock::new(HashMap::new()),
            active: RwLock::new(None),
            last_rejected: Mutex::new(None),
            send_lock: tokio::sync::Mutex::new(()),
            requests: Mutex::new(HashMap::new()),
            hold_secs,
        }
    }

    pub fn with_hyperliquid(mut self, hl: Hyperliquid) -> Self {
        self.hl = Some(Arc::new(hl));
        self
    }

    pub fn with_modules(self, modules: HashMap<String, ModuleToggles>) -> Self {
        *self.modules.write().unwrap_or_else(|e| e.into_inner()) = modules;
        self
    }

    pub fn wallet(&self) -> Arc<Mutex<Wallet>> {
        self.wallet.clone()
    }

    pub fn tokens(&self) -> Arc<Vec<PriceEntry>> {
        self.tokens.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn modules_for(&self, bot: &str) -> Option<ModuleToggles> {
        self.modules.read().unwrap_or_else(|e| e.into_inner()).get(bot).cloned()
    }

    pub fn active_policy(&self) -> Option<ActivePolicy> {
        self.active.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Puts a signed policy in force: version check, then the wallet's core rules and prices,
    /// the Hyperliquid limits, the module switches and the token list, then the version record.
    /// Refuses an older version, or the same version with other contents.
    pub async fn apply_policy(&self, loaded: LoadedPolicy, gate: &VersionGate) -> Result<PolicyRef, String> {
        gate.check(&loaded.reference).map_err(|e| e.to_string())?;
        let set = Arc::new(loaded.set);
        let hl_policies = set.hyperliquid()?;
        let reference = loaded.reference;
        let signer = loaded.signer;
        let for_wallet = set.clone();
        self.with_wallet(move |w| {
            let mut engines: HashMap<String, Box<dyn PolicyEngine>> = HashMap::new();
            for (bot, rules) in &for_wallet.bots {
                let own = w.address(bot).ok();
                engines.insert(bot.clone(), Box::new(PlainPolicy { own_address: own, ..rules.core.clone() }));
            }
            let prices = for_wallet.price_table()?;
            let detail = json!({ "version": reference.version, "hash": reference.hash, "signed_by": signer });
            w.apply_policy(reference, engines, Box::new(prices), detail, now())
        })
        .await??;
        if let Some(hl) = &self.hl {
            hl.set_policies(hl_policies);
        }
        *self.modules.write().unwrap_or_else(|e| e.into_inner()) = set.modules();
        *self.tokens.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(set.prices.clone());
        gate.record(&reference).map_err(|e| e.to_string())?;
        *self.active.write().unwrap_or_else(|e| e.into_inner()) =
            Some(ActivePolicy { reference, signer, loaded_at: now(), set });
        *self.last_rejected.lock().unwrap_or_else(|e| e.into_inner()) = None;
        Ok(reference)
    }

    /// Looks at the policy file and loads it if its contents changed. A refused file is logged to
    /// the audit log once and the policy in force stays.
    pub async fn reload_policy(&self, config: &Config) -> Reload {
        let current = self.active_policy().map(|a| a.reference.hash);
        let on_disk = policy::read_doc(&config.server.policy).map(|d| d.reference.hash);
        if let (Some(cur), Ok(disk)) = (current, &on_disk)
            && cur == *disk
        {
            return Reload::Unchanged;
        }
        let result = match policy::load(config) {
            Ok(loaded) => self.apply_policy(loaded, &VersionGate::new(config.policy_state_path())).await,
            Err(e) => Err(e.to_string()),
        };
        match result {
            Ok(reference) => Reload::Loaded(reference),
            Err(reason) => {
                let key = format!("{:?}|{reason}", on_disk.as_ref().ok());
                let first_time = {
                    let mut last = self.last_rejected.lock().unwrap_or_else(|e| e.into_inner());
                    let new = last.as_deref() != Some(key.as_str());
                    *last = Some(key);
                    new
                };
                if first_time {
                    let hash = on_disk.ok();
                    let detail = json!({ "hash": hash, "reason": reason });
                    let _ = self
                        .with_wallet(move |w| w.log_event("", "policy", AuditEvent::PolicyRejected, detail, now()))
                        .await;
                }
                Reload::Rejected(reason)
            }
        }
    }

    /// Tool names this bot should not see. An unknown bot, or a bot with no switches, hides nothing.
    pub fn hidden_tools(&self, bot: &str) -> Vec<&'static str> {
        let Some(toggles) = self.modules_for(bot) else { return Vec::new() };
        let mut hidden = Vec::new();
        if !toggles.hyperliquid {
            hidden.extend(keyshare_hyperliquid::client::HYPERLIQUID_TOOLS);
        }
        if !toggles.uniswap {
            hidden.extend(keyshare_uniswap::UNISWAP_TOOLS);
        }
        hidden
    }

    /// Runs `f` on the wallet off the async runtime (it does fsyncs).
    pub async fn with_wallet<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Wallet) -> T + Send + 'static,
    ) -> Result<T, String> {
        let wallet = self.wallet.clone();
        tokio::task::spawn_blocking(move || {
            wallet.lock().map(|mut w| f(&mut w)).map_err(|_| "wallet lock poisoned".to_string())
        })
        .await
        .map_err(|e| e.to_string())?
    }

    /// A broadcast request keeps its tx hash: nothing later overwrites it, so `tx_status` never
    /// tells a bot that a transaction on chain was refused.
    fn set_state(&self, key: &str, req: Request) {
        if let Ok(mut map) = self.requests.lock()
            && !matches!(map.get(key).map(|r| &r.state), Some(RequestState::Broadcast { .. }))
        {
            map.insert(key.to_string(), req);
        }
    }

    /// An expired hold, and a refusal that only records that expiry, can never sign. Dropping
    /// them lets the bot retry the id. Which one is stored depends on whether `decide` or
    /// `submit` observed the deadline first.
    fn release_expired(&self, key: &str) -> Result<bool, String> {
        let mut map = self.requests.lock().map_err(|e| e.to_string())?;
        let Some(req) = map.get(key) else { return Ok(false) };
        if releases_request_id(&req.state, now()) {
            map.remove(key);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Claims the hold identified by `expires_at`. A newer hold for the same id is left alone, so
    /// a late decision on an expired hold can't overwrite a retry. Expiry is rechecked under the
    /// same lock as the claim.
    fn claim(&self, key: &str, expires_at: u64) -> Result<Claim, String> {
        let mut map = self.requests.lock().map_err(|e| e.to_string())?;
        let Some(req) = map.get_mut(key) else { return Ok(Claim::Unavailable) };
        match &req.state {
            RequestState::PendingUserApproval { expires_at: exp, .. } if *exp == expires_at && now() < *exp => {
                let held = Box::new(req.clone());
                req.state = RequestState::Executing;
                Ok(Claim::Ready(held))
            }
            RequestState::PendingUserApproval { expires_at: exp, .. } if *exp == expires_at => {
                let r = Refusal::new(RefusalCode::Expired, format!("request {} expired", req.id));
                req.state = RequestState::Refused { refusal: r };
                Ok(Claim::Expired)
            }
            RequestState::PendingUserApproval { .. }
            | RequestState::Executing
            | RequestState::Broadcast { .. }
            | RequestState::Refused { .. } => Ok(Claim::Unavailable),
        }
    }

    pub fn request_state(&self, caller: &str, id: &str) -> Option<RequestState> {
        self.requests.lock().ok()?.get(&scoped(caller, id)).map(|r| r.state.clone())
    }

    /// `send` and `call_contract`.
    pub async fn submit(&self, caller: &str, id: &str, tx: TxEip1559, dry_run: bool) -> Result<Outcome, String> {
        let key = scoped(caller, id);
        if let Err(r) = self.chains.get(tx.chain_id) {
            return Ok(Err(refusal(id, &r)));
        }
        if !dry_run {
            // An expired hold can never be signed. Drop it so the same request id can be retried
            // instead of staying burned until some other hold happens to sweep the map.
            let held = self.requests.lock().map_err(|e| e.to_string())?.contains_key(&key);
            if held && !self.release_expired(&key)? {
                let r = Refusal::new(RefusalCode::NonceReused, format!("request {id} was already used"));
                return Ok(Err(refusal(id, &r)));
            }
        }

        // Policy first: a bad recipient fails fast with a readable reason, before any RPC.
        let (c, t) = (caller.to_string(), tx.clone());
        let (preview, has_admins) =
            self.with_wallet(move |w| (w.preview(&c, Action::Transaction(&t), now()), w.has_admins(&c))).await?;
        let outflow = match preview {
            Ok(v) => v.outflow_usd,
            Err(r) if dry_run => return Ok(Err(refusal(id, &r))),
            Err(r) if r.code.is_owner_approvable() && has_admins => return self.hold(caller, id, tx, r).await,
            Err(r) => {
                let (c, k, d, r2) = (caller.to_string(), key.clone(), tx_detail(&tx), r.clone());
                self.with_wallet(move |w| w.log_refusal(&c, &k, d, &r2, now())).await?;
                return Ok(Err(refusal(id, &r)));
            }
        };
        let mut out = self.execute(caller, id, tx.clone(), None, dry_run).await?;
        if let Ok(v) = &mut out {
            v["outflow_usd"] = json!(usd(outflow));
        }
        Ok(out)
    }

    async fn hold(&self, caller: &str, id: &str, tx: TxEip1559, reason: Refusal) -> Result<Outcome, String> {
        let t = now();
        let expires_at = t + self.hold_secs;
        let key = scoped(caller, id);
        {
            // Expired holds can never sign, so drop them; then cap what one bot can keep waiting.
            let mut map = self.requests.lock().map_err(|e| e.to_string())?;
            map.retain(
                |_, r| !matches!(r.state, RequestState::PendingUserApproval { expires_at, .. } if expires_at <= t),
            );
            let waiting = map
                .values()
                .filter(|r| r.caller == caller && matches!(r.state, RequestState::PendingUserApproval { .. }))
                .count();
            if waiting >= MAX_PENDING_PER_BOT {
                let r = Refusal::new(
                    RefusalCode::TooManyPending,
                    format!("{waiting} requests already wait for the owner; {reason}"),
                );
                return Ok(Err(refusal(id, &r)));
            }
        }
        let (c, k, d) = (caller.to_string(), key.clone(), json!({ "tx": tx_detail(&tx), "reason": reason }));
        self.with_wallet(move |w| {
            w.log_event(&c, &k, AuditEvent::Requested, d.clone(), now());
            w.log_event(&c, &k, AuditEvent::Held, d, now());
        })
        .await?;
        let state = RequestState::PendingUserApproval { reason: reason.clone(), expires_at };
        self.set_state(&key, Request { caller: caller.to_string(), id: id.to_string(), tx, state });
        Ok(Ok(json!({
            "request_id": id,
            "state": "pending_user_approval",
            "reason": reason,
            "expires_at": expires_at,
        })))
    }

    /// Fill, simulate, sign (with the owner's approval if given) and broadcast.
    async fn execute(
        &self,
        caller: &str,
        id: &str,
        submitted: TxEip1559,
        approval: Option<Signature>,
        dry_run: bool,
    ) -> Result<Outcome, String> {
        let key = scoped(caller, id);
        let provider = match self.chains.get(submitted.chain_id) {
            Ok(p) => p,
            Err(r) => return Ok(Err(refusal(id, &r))),
        };
        let c = caller.to_string();
        let from = match self.with_wallet(move |w| w.address(&c)).await? {
            Ok(a) => a,
            Err(r) => return Ok(Err(refusal(id, &r))),
        };
        let refuse = |r: Refusal| {
            let state = RequestState::Refused { refusal: r.clone() };
            let req = Request { caller: caller.to_string(), id: id.to_string(), tx: submitted.clone(), state };
            (req, refusal(id, &r))
        };

        let _guard = if dry_run { None } else { Some(self.send_lock.lock().await) };
        let mut tx = submitted.clone();
        let sim = match chain::fill_and_simulate(provider, from, &mut tx).await {
            Ok(sim) => sim,
            Err(r) => return Ok(Err(refusal(id, &r))),
        };
        if !sim.ok {
            let r = Refusal::new(RefusalCode::SimRevert, sim.revert.clone().unwrap_or_default());
            let mut out = refusal(id, &r);
            out["simulation"] = json!(sim);
            if !dry_run {
                let (c, k, d, r2) = (caller.to_string(), key.clone(), tx_detail(&tx), r.clone());
                self.with_wallet(move |w| w.log_refusal(&c, &k, d, &r2, now())).await?;
                self.set_state(&key, refuse(r).0);
            }
            return Ok(Err(out));
        }
        if dry_run {
            return Ok(Ok(json!({
                "request_id": id,
                "dry_run": true,
                "policy_verdict": "allowed",
                "simulation": sim,
                "tx": { "nonce": tx.nonce, "gas_limit": tx.gas_limit, "max_fee_per_gas": tx.max_fee_per_gas },
            })));
        }

        let (c, k, approved) = (caller.to_string(), key.clone(), approval.is_some());
        let signed = self
            .with_wallet(move |w| match approval {
                Some(sig) => w.sign_transaction_approved(&c, &k, tx, &sig, now()),
                None => w.sign_transaction(&c, &k, tx, now()),
            })
            .await?;
        let signed = match signed {
            Ok(s) => s,
            Err(r) => {
                let (req, out) = refuse(r);
                self.set_state(&key, req);
                return Ok(Err(out));
            }
        };
        // Signed and counted from here, whether or not the broadcast lands.
        let state = RequestState::Broadcast { tx_hash: signed.hash, approved_by_owner: approved };
        self.set_state(&key, Request { caller: caller.to_string(), id: id.to_string(), tx: submitted, state });
        match chain::broadcast(provider, &signed.raw).await {
            Ok(_) => Ok(Ok(json!({ "request_id": id, "tx_hash": signed.hash, "simulation": sim }))),
            Err(r) => {
                let mut out = refusal(id, &r);
                out["tx_hash"] = json!(signed.hash);
                Ok(Err(out))
            }
        }
    }

    /// Held requests that are still waiting, with the exact messages the owner signs.
    pub fn pending(&self) -> Vec<Value> {
        let t = now();
        let Ok(map) = self.requests.lock() else { return Vec::new() };
        let mut out: Vec<Value> = map
            .values()
            .filter_map(|r| match &r.state {
                RequestState::PendingUserApproval { reason, expires_at } if *expires_at > t => {
                    let intent = approval::intent_hash(&r.tx);
                    Some(json!({
                        "bot": r.caller,
                        "request_id": r.id,
                        "reason": reason,
                        "tx": tx_detail(&r.tx),
                        "expires_at": expires_at,
                        "approve_message": approval::message(Decision::Approve, &r.caller, &scoped(&r.caller, &r.id), intent),
                        "deny_message": approval::message(Decision::Deny, &r.caller, &scoped(&r.caller, &r.id), intent),
                    }))
                }
                _ => None,
            })
            .collect();
        out.sort_by_key(|v| v["expires_at"].as_u64());
        out
    }

    /// Records that `expires_at`'s hold expired, unless a newer hold has already replaced it.
    async fn expire(&self, bot: &str, id: &str, key: &str, expires_at: u64) -> Result<Outcome, String> {
        let r = Refusal::new(RefusalCode::Expired, format!("request {id} expired"));
        let log = {
            let mut map = self.requests.lock().map_err(|e| e.to_string())?;
            match map.get_mut(key) {
                Some(req)
                    if matches!(
                        &req.state,
                        RequestState::PendingUserApproval { expires_at: exp, .. } if *exp == expires_at
                    ) =>
                {
                    req.state = RequestState::Refused { refusal: r.clone() };
                    true
                }
                // `claim` already stored the expiry under the lock. Log that one, and nothing else.
                Some(req) if matches!(&req.state, RequestState::Refused { refusal } if refusal.code == RefusalCode::Expired) => {
                    true
                }
                _ => false,
            }
        };
        if log {
            let (b, k, r2) = (bot.to_string(), key.to_string(), r.clone());
            self.with_wallet(move |w| w.log_event(&b, &k, AuditEvent::Refused, json!(r2), now())).await?;
        }
        Ok(Err(refusal(id, &r)))
    }

    /// The owner's approve or deny on a held request.
    pub async fn decide(
        &self,
        bot: &str,
        id: &str,
        decision: Decision,
        signature: Signature,
    ) -> Result<Outcome, String> {
        let key = scoped(bot, id);
        let held = self.requests.lock().map_err(|e| e.to_string())?.get(&key).cloned();
        let Some(held) = held else {
            let r = Refusal::new(RefusalCode::BadApproval, format!("no held request {id} for {bot}"));
            return Ok(Err(refusal(id, &r)));
        };
        let RequestState::PendingUserApproval { expires_at, .. } = held.state else {
            let r = Refusal::new(RefusalCode::BadApproval, format!("request {id} is not waiting for approval"));
            return Ok(Err(refusal(id, &r)));
        };
        if now() >= expires_at {
            return self.expire(bot, id, &key, expires_at).await;
        }

        let (b, k, t) = (bot.to_string(), key.clone(), held.tx.clone());
        let verified = self.with_wallet(move |w| w.verify_decision(&b, &k, &t, decision, &signature)).await?;
        let admin = match verified {
            Ok(a) => a,
            Err(r) => return Ok(Err(refusal(id, &r))),
        };
        // Two decisions posted at once both pass the check above; only one may act. The deadline
        // is checked again here, and only this hold (same `expires_at`) can be claimed.
        let held = match self.claim(&key, expires_at)? {
            Claim::Ready(held) => *held,
            Claim::Expired => return self.expire(bot, id, &key, expires_at).await,
            Claim::Unavailable => {
                let r = Refusal::new(RefusalCode::BadApproval, format!("request {id} was already decided"));
                return Ok(Err(refusal(id, &r)));
            }
        };
        match decision {
            Decision::Deny => {
                let r = Refusal::new(RefusalCode::UserDenied, format!("denied by owner key {admin}"));
                let (b, k, r2) = (bot.to_string(), key.clone(), r.clone());
                self.with_wallet(move |w| w.log_event(&b, &k, AuditEvent::Refused, json!(r2), now())).await?;
                self.set_state(&key, Request { state: RequestState::Refused { refusal: r.clone() }, ..held });
                Ok(Err(refusal(id, &r)))
            }
            Decision::Approve => {
                let out = self.execute(bot, id, held.tx.clone(), Some(signature), false).await;
                // If it stopped before signing (e.g. an RPC failure), the request waits again so the
                // owner can retry.
                if let Ok(mut map) = self.requests.lock()
                    && let Some(r) = map.get_mut(&key)
                    && matches!(r.state, RequestState::Executing)
                {
                    r.state = held.state;
                }
                let mut out = out?;
                if let Ok(v) = &mut out {
                    v["approved_by"] = json!(admin);
                }
                Ok(out)
            }
        }
    }
}

fn hyperliquid_grant() -> Grant {
    Grant {
        id: "hyperliquid",
        calls: vec![],
        approve_spenders: vec![],
        typed_data: vec![TypedDataRule {
            primary_type: "Agent".into(),
            verifying_contract: Some(Address::ZERO),
            name: Some("Exchange".into()),
            chain_id: Some(1337),
            chainless: false,
        }],
    }
}

fn host_err(e: String) -> Refusal {
    Refusal::new(RefusalCode::Internal, e)
}

impl ModuleView for Executor {
    async fn address(&self, caller: &str) -> Result<Address, Refusal> {
        let caller = caller.to_string();
        self.with_wallet(move |w| w.address(&caller)).await.map_err(host_err)?
    }

    async fn limits(&self, caller: &str) -> Result<keyshare_core::policy::Limits, Refusal> {
        let caller = caller.to_string();
        self.with_wallet(move |w| w.limits(&caller)).await.map_err(host_err)?
    }

    async fn spent_24h(&self, caller: &str, now: u64) -> Result<UsdMicros, Refusal> {
        let caller = caller.to_string();
        self.with_wallet(move |w| w.spent_24h(&caller, now)).await.map_err(host_err)
    }

    async fn check_kill_switch(&self, caller: &str) -> Result<(), Refusal> {
        let caller = caller.to_string();
        self.with_wallet(move |w| w.kill_switch().check(&caller)).await.map_err(host_err)?
    }

    async fn preview_tx(&self, caller: &str, tx: TxEip1559, now: u64) -> Result<Verdict, Refusal> {
        let caller = caller.to_string();
        self.with_wallet(move |w| w.preview(&caller, Action::Transaction(&tx), now)).await.map_err(host_err)?
    }

    async fn log_event(
        &self,
        caller: &str,
        request_id: &str,
        event: AuditEvent,
        detail: Value,
        now: u64,
    ) -> Result<(), String> {
        let caller = caller.to_string();
        let request_id = request_id.to_string();
        self.with_wallet(move |w| w.log_event(&caller, &request_id, event, detail, now)).await
    }

    async fn log_refusal(
        &self,
        caller: &str,
        request_id: &str,
        detail: Value,
        refusal: &Refusal,
        now: u64,
    ) -> Result<(), String> {
        let caller = caller.to_string();
        let request_id = request_id.to_string();
        let refusal = refusal.clone();
        self.with_wallet(move |w| w.log_refusal(&caller, &request_id, detail, &refusal, now)).await
    }
}

impl keyshare_hyperliquid::HlHost for Executor {
    async fn sign_l1(
        &self,
        bot: &str,
        coin: &str,
        action: &keyshare_hyperliquid::L1Action,
        nonce: u64,
    ) -> Result<Signature, Refusal> {
        let hl = self
            .hl
            .as_deref()
            .ok_or_else(|| Refusal::new(RefusalCode::MarketNotAllowed, "Hyperliquid is not configured"))?;
        let policy = hl.policy(bot)?;
        let indexes = keyshare_hyperliquid::action_assets(action);
        if indexes.is_empty() {
            return Err(Refusal::new(RefusalCode::BadArgs, "action names no asset"));
        }
        for index in indexes {
            let Some(name) = hl.coin_for_index(index).await else {
                return Err(Refusal::new(
                    RefusalCode::MarketNotAllowed,
                    format!("asset index {index} is not in the loaded market list"),
                ));
            };
            if name != coin {
                return Err(Refusal::new(
                    RefusalCode::MarketNotAllowed,
                    format!("asset index {index} is {name}, not {coin}"),
                ));
            }
        }
        policy.vet_action(action, coin)?;
        let hash = keyshare_hyperliquid::action_hash(action, None, nonce, None)
            .map_err(|e| Refusal::new(RefusalCode::BadArgs, e))?;
        // Phase 0 signs for testnet only, matching the module's posted actions.
        let typed = keyshare_hyperliquid::l1_typed_data(hash, false);
        authorize_typed(&hyperliquid_grant(), &typed)?;
        let agent = crate::hl::open_agent(hl, bot)?;
        agent.sign_typed_data(&typed).map_err(|e| Refusal::new(RefusalCode::ThresholdUnavailable, e.to_string()))
    }
}

impl keyshare_uniswap::SwapHost for Executor {
    fn provider(&self, chain_id: u64) -> Result<&alloy::providers::RootProvider, Refusal> {
        self.chains.get(chain_id)
    }

    fn uniswap(&self, chain_id: u64) -> Result<&keyshare_uniswap::UniswapV3, Refusal> {
        self.chains.uniswap(chain_id)
    }

    async fn token_decimals(&self, chain_id: u64, token: alloy::primitives::Address) -> Result<u8, Refusal> {
        let provider = self.chains.get(chain_id)?;
        chain::token_decimals(provider, token).await
    }

    async fn tx_state(&self, chain_id: u64, hash: B256) -> Result<String, Refusal> {
        let provider = self.chains.get(chain_id)?;
        Ok(chain::tx_status(provider, hash).await?.state.to_string())
    }

    async fn submit(&self, caller: &str, id: &str, tx: TxEip1559, dry_run: bool) -> Result<Outcome, String> {
        let router = match self.chains.uniswap(tx.chain_id) {
            Ok(dex) => dex.router,
            Err(r) => return Ok(Err(refusal(id, &r))),
        };
        if let Err(r) = keyshare_uniswap::grant(router).covers_tx(&tx) {
            return Ok(Err(refusal(id, &r)));
        }
        Executor::submit(self, caller, id, tx, dry_run).await
    }
}
