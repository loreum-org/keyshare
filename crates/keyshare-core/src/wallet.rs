//! The signing path every state-changing tool goes through:
//! audit → caller → kill switch → counter anchor → request id → policy → record spend → sign → audit.

use std::collections::HashMap;
use std::path::PathBuf;

use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy::dyn_abi::TypedData;
use alloy::eips::Encodable2718;
use alloy::primitives::{Address, B256, Bytes, Signature};
use serde::Serialize;
use serde_json::json;

use crate::approval::{self, Decision};
use crate::audit::{AuditEntry, AuditEvent, AuditLog};
use crate::chainlog::LogError;
use crate::killswitch::KillSwitch;
use crate::policy::{Action, PolicyEngine, Verdict};
use crate::price::{PriceSource, UsdMicros};
use crate::refusal::{Refusal, RefusalCode};
use crate::signer::Signer;
use crate::spend::{SpendEntry, SpendLog};

/// One caller's wallet: its key and its rules. Design §11 Q1: one EOA per bot.
pub struct Account {
    pub signer: Box<dyn Signer>,
    pub policy: Box<dyn PolicyEngine>,
    /// Owner admin keys (not shares). They approve held requests (design §15.2).
    pub admins: Vec<Address>,
}

#[derive(Debug, Clone)]
pub struct StatePaths {
    pub spend_log: PathBuf,
    /// Put this on a different disk or mount from `spend_log`.
    pub spend_anchor: Option<PathBuf>,
    pub audit_log: PathBuf,
    pub kill_switch: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignedTx {
    pub hash: B256,
    /// EIP-2718 bytes, ready for `eth_sendRawTransaction`.
    pub raw: Bytes,
}

pub struct Wallet {
    accounts: HashMap<String, Account>,
    prices: Box<dyn PriceSource>,
    spend: SpendLog,
    audit: AuditLog,
    kill: KillSwitch,
}

fn internal(e: impl std::fmt::Display) -> Refusal {
    Refusal::new(RefusalCode::Internal, e.to_string())
}

impl Wallet {
    pub fn open(
        accounts: HashMap<String, Account>,
        prices: Box<dyn PriceSource>,
        paths: &StatePaths,
    ) -> Result<Self, LogError> {
        Ok(Self {
            accounts,
            prices,
            spend: SpendLog::open(&paths.spend_log, paths.spend_anchor.clone())?,
            audit: AuditLog::open(&paths.audit_log)?,
            kill: KillSwitch::new(&paths.kill_switch),
        })
    }

    pub fn kill_switch(&self) -> &KillSwitch {
        &self.kill
    }

    pub fn address(&self, caller: &str) -> Result<Address, Refusal> {
        Ok(self.account(caller)?.signer.address())
    }

    pub fn limits(&self, caller: &str) -> Result<crate::policy::Limits, Refusal> {
        Ok(self.account(caller)?.policy.limits())
    }

    pub fn spent_24h(&self, caller: &str, now: u64) -> UsdMicros {
        self.spend.spent_24h(caller, now)
    }

    fn account(&self, caller: &str) -> Result<&Account, Refusal> {
        self.accounts
            .get(caller)
            .ok_or_else(|| Refusal::new(RefusalCode::UnknownCaller, format!("no wallet for caller {caller:?}")))
    }

    pub fn sign_transaction(
        &mut self,
        caller: &str,
        request_id: &str,
        tx: TxEip1559,
        now: u64,
    ) -> Result<SignedTx, Refusal> {
        self.sign_tx_inner(caller, request_id, tx, None, now)
    }

    /// Whether `caller`'s owner has admin keys, so a waivable refusal can be held for approval.
    pub fn has_admins(&self, caller: &str) -> bool {
        self.account(caller).is_ok_and(|a| !a.admins.is_empty())
    }

    /// Checks an owner's decision on a held request and returns the admin key that signed it.
    pub fn verify_decision(
        &self,
        caller: &str,
        request_id: &str,
        tx: &TxEip1559,
        decision: Decision,
        signature: &Signature,
    ) -> Result<Address, Refusal> {
        let msg = approval::message(decision, caller, request_id, approval::intent_hash(tx));
        approval::verify(&self.account(caller)?.admins, &msg, signature)
    }

    /// Signs a held request the owner approved. The approval must match this exact request and
    /// transaction intent. Kill switch, counter anchor, request id and hard policy rules still
    /// apply, and the spend still counts toward the daily cap.
    pub fn sign_transaction_approved(
        &mut self,
        caller: &str,
        request_id: &str,
        tx: TxEip1559,
        approval: &Signature,
        now: u64,
    ) -> Result<SignedTx, Refusal> {
        let admin = self.verify_decision(caller, request_id, &tx, Decision::Approve, approval)?;
        self.sign_tx_inner(caller, request_id, tx, Some(admin), now)
    }

    fn sign_tx_inner(
        &mut self,
        caller: &str,
        request_id: &str,
        tx: TxEip1559,
        approved_by: Option<Address>,
        now: u64,
    ) -> Result<SignedTx, Refusal> {
        let detail = json!({
            "approved_by": approved_by,
            "kind": "transaction",
            "chain_id": tx.chain_id,
            "nonce": tx.nonce,
            "to": tx.to.to(),
            "value": tx.value,
            "input": tx.input,
            "digest": tx.signature_hash(),
        });
        let sig =
            self.authorize_and_sign(caller, request_id, Action::Transaction(&tx), approved_by, detail, now, |s| {
                s.sign_transaction(&tx)
            })?;
        let envelope = TxEnvelope::from(tx.into_signed(sig));
        Ok(SignedTx { hash: *envelope.tx_hash(), raw: envelope.encoded_2718().into() })
    }

    pub fn sign_message(
        &mut self,
        caller: &str,
        request_id: &str,
        message: &[u8],
        now: u64,
    ) -> Result<Signature, Refusal> {
        let detail = json!({ "kind": "message", "message": String::from_utf8_lossy(message) });
        self.authorize_and_sign(caller, request_id, Action::Message(message), None, detail, now, |s| {
            s.sign_message(message)
        })
    }

    pub fn sign_typed_data(
        &mut self,
        caller: &str,
        request_id: &str,
        data: &TypedData,
        now: u64,
    ) -> Result<Signature, Refusal> {
        let detail = json!({ "kind": "typed_data", "primary_type": data.primary_type, "typed_data": data });
        self.authorize_and_sign(caller, request_id, Action::TypedData(data), None, detail, now, |s| {
            s.sign_typed_data(data)
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn authorize_and_sign(
        &mut self,
        caller: &str,
        request_id: &str,
        action: Action<'_>,
        approved_by: Option<Address>,
        detail: serde_json::Value,
        now: u64,
        sign: impl FnOnce(&dyn Signer) -> Result<Signature, crate::signer::SignerError>,
    ) -> Result<Signature, Refusal> {
        let entry = |event, detail| AuditEntry {
            at: now,
            request_id: request_id.to_string(),
            caller: caller.to_string(),
            event,
            detail,
        };
        // No audit entry, no signature.
        self.audit.append(&entry(AuditEvent::Requested, detail)).map_err(internal)?;

        match self.authorize(caller, request_id, action, approved_by.is_some(), now) {
            Ok(()) => {}
            Err(refusal) => {
                // The refusal stands even if this write fails.
                let _ = self.audit.append(&entry(AuditEvent::Refused, json!(refusal)));
                return Err(refusal);
            }
        }

        let account = self.account(caller)?;
        match sign(account.signer.as_ref()) {
            Ok(sig) => {
                self.audit.append(&entry(AuditEvent::Signed, json!({ "signature": sig }))).map_err(internal)?;
                Ok(sig)
            }
            Err(e) => {
                let refusal = Refusal::new(RefusalCode::ThresholdUnavailable, e.to_string());
                let _ = self.audit.append(&entry(AuditEvent::Refused, json!(refusal)));
                Err(refusal)
            }
        }
    }

    /// The same checks as signing, with nothing recorded, logged or signed. For `dry_run` and
    /// to fail fast before simulating (design §4 step 3).
    pub fn preview(&self, caller: &str, action: Action<'_>, now: u64) -> Result<Verdict, Refusal> {
        let account = self.account(caller)?;
        self.kill.check(caller)?;
        self.spend.check_anchor()?;
        account.policy.check(action, self.spend.spent_24h(caller, now), self.prices.as_ref())
    }

    /// Appends one audit entry for something outside the signing path (a hold, a denial).
    pub fn log_event(
        &mut self,
        caller: &str,
        request_id: &str,
        event: AuditEvent,
        detail: serde_json::Value,
        now: u64,
    ) {
        let entry = AuditEntry { at: now, request_id: request_id.into(), caller: caller.into(), event, detail };
        let _ = self.audit.append(&entry);
    }

    /// Logs a refusal that happened outside the signing path (e.g. a simulation revert).
    pub fn log_refusal(
        &mut self,
        caller: &str,
        request_id: &str,
        detail: serde_json::Value,
        refusal: &Refusal,
        now: u64,
    ) {
        for (event, detail) in [(AuditEvent::Requested, detail), (AuditEvent::Refused, json!(refusal))] {
            let entry = AuditEntry { at: now, request_id: request_id.into(), caller: caller.into(), event, detail };
            let _ = self.audit.append(&entry);
        }
    }

    pub fn prices(&self) -> &dyn PriceSource {
        self.prices.as_ref()
    }

    /// Every check that can refuse, then the spend record. Nothing here signs.
    fn authorize(
        &mut self,
        caller: &str,
        request_id: &str,
        action: Action<'_>,
        owner_approved: bool,
        now: u64,
    ) -> Result<(), Refusal> {
        self.spend.check_request_id(request_id)?;
        let verdict = if owner_approved {
            let account = self.account(caller)?;
            self.kill.check(caller)?;
            self.spend.check_anchor()?;
            account.policy.check_owner_approved(action, self.prices.as_ref())?
        } else {
            self.preview(caller, action, now)?
        };
        // Recorded on approval, before signing (design §6.4). This also burns the request id.
        self.spend
            .record(SpendEntry {
                caller: caller.to_string(),
                request_id: request_id.to_string(),
                usd_micros: verdict.outflow_usd,
                at: now,
            })
            .map_err(internal)?;
        Ok(())
    }
}
