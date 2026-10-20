//! Runs state-changing requests (design §4): policy pre-check → simulate → sign → broadcast.
//! A refusal the owner can waive (allowlist miss, cap, co-sign threshold) is held for the owner's
//! admin approval instead (§13.2). Shared by the MCP tools and the admin endpoints.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::consensus::TxEip1559;
use alloy::primitives::{B256, Signature};
use keyshare_core::approval::{self, Decision};
use keyshare_core::audit::AuditEvent;
use keyshare_core::price::{MICROS_PER_USD, PriceEntry};
use keyshare_core::{Action, Refusal, RefusalCode, Wallet};
use serde::Serialize;
use serde_json::{Value, json};

use crate::chain::{self, Chains};
use crate::hl::Hyperliquid;

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
    pub tokens: Arc<Vec<PriceEntry>>,
    pub hl: Option<Arc<Hyperliquid>>,
    /// Held from nonce lookup to broadcast so two sends never get the same nonce.
    send_lock: tokio::sync::Mutex<()>,
    /// Keyed by the caller-scoped request id. In memory: a restart drops held requests, which
    /// then never sign.
    requests: Mutex<HashMap<String, Request>>,
    hold_secs: u64,
}

/// Held requests one bot may have waiting for the owner at once.
const MAX_PENDING_PER_BOT: usize = 16;

/// Request ids are namespaced per caller so one bot can't burn another's ids.
pub fn scoped(caller: &str, id: &str) -> String {
    format!("{caller}:{id}")
}

impl Executor {
    pub fn new(wallet: Arc<Mutex<Wallet>>, chains: Arc<Chains>, tokens: Arc<Vec<PriceEntry>>, hold_secs: u64) -> Self {
        Self {
            wallet,
            chains,
            tokens,
            hl: None,
            send_lock: tokio::sync::Mutex::new(()),
            requests: Mutex::new(HashMap::new()),
            hold_secs,
        }
    }

    pub fn with_hyperliquid(mut self, hl: Hyperliquid) -> Self {
        self.hl = Some(Arc::new(hl));
        self
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

    /// Moves a held request to `Executing`, or returns `None` if another decision got there first.
    fn claim(&self, key: &str) -> Result<Option<Request>, String> {
        let mut map = self.requests.lock().map_err(|e| e.to_string())?;
        let Some(req) = map.get_mut(key) else { return Ok(None) };
        if !matches!(req.state, RequestState::PendingUserApproval { .. }) {
            return Ok(None);
        }
        let held = req.clone();
        req.state = RequestState::Executing;
        Ok(Some(held))
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
            let mut map = self.requests.lock().map_err(|e| e.to_string())?;
            let expired = map.get(&key).is_some_and(
                |r| matches!(r.state, RequestState::PendingUserApproval { expires_at, .. } if expires_at <= now()),
            );
            if expired {
                map.remove(&key);
            } else if map.contains_key(&key) {
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
            let r = Refusal::new(RefusalCode::Expired, format!("request {id} expired"));
            let (b, k, r2) = (bot.to_string(), key.clone(), r.clone());
            self.with_wallet(move |w| w.log_event(&b, &k, AuditEvent::Refused, json!(r2), now())).await?;
            self.set_state(&key, Request { state: RequestState::Refused { refusal: r.clone() }, ..held });
            return Ok(Err(refusal(id, &r)));
        }

        let (b, k, t) = (bot.to_string(), key.clone(), held.tx.clone());
        let verified = self.with_wallet(move |w| w.verify_decision(&b, &k, &t, decision, &signature)).await?;
        let admin = match verified {
            Ok(a) => a,
            Err(r) => return Ok(Err(refusal(id, &r))),
        };
        // Two decisions posted at once both pass the check above; only one may act.
        let Some(held) = self.claim(&key)? else {
            let r = Refusal::new(RefusalCode::BadApproval, format!("request {id} was already decided"));
            return Ok(Err(refusal(id, &r)));
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
