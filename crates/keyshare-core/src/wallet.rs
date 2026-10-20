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

use crate::audit::{AuditEntry, AuditEvent, AuditLog};
use crate::chainlog::LogError;
use crate::killswitch::KillSwitch;
use crate::policy::{Action, PolicyEngine};
use crate::price::{PriceSource, UsdMicros};
use crate::refusal::{Refusal, RefusalCode};
use crate::signer::Signer;
use crate::spend::{SpendEntry, SpendLog};

/// One caller's wallet: its key and its rules. Design §11 Q1: one EOA per bot.
pub struct Account {
    pub signer: Box<dyn Signer>,
    pub policy: Box<dyn PolicyEngine>,
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
        let detail = json!({
            "kind": "transaction",
            "chain_id": tx.chain_id,
            "nonce": tx.nonce,
            "to": tx.to.to(),
            "value": tx.value,
            "input": tx.input,
            "digest": tx.signature_hash(),
        });
        let sig = self.authorize_and_sign(caller, request_id, Action::Transaction(&tx), detail, now, |s| {
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
        self.authorize_and_sign(caller, request_id, Action::Message(message), detail, now, |s| s.sign_message(message))
    }

    pub fn sign_typed_data(
        &mut self,
        caller: &str,
        request_id: &str,
        data: &TypedData,
        now: u64,
    ) -> Result<Signature, Refusal> {
        let detail = json!({ "kind": "typed_data", "primary_type": data.primary_type, "typed_data": data });
        self.authorize_and_sign(caller, request_id, Action::TypedData(data), detail, now, |s| s.sign_typed_data(data))
    }

    fn authorize_and_sign(
        &mut self,
        caller: &str,
        request_id: &str,
        action: Action<'_>,
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

        match self.authorize(caller, request_id, action, now) {
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

    /// Every check that can refuse, then the spend record. Nothing here signs.
    fn authorize(&mut self, caller: &str, request_id: &str, action: Action<'_>, now: u64) -> Result<(), Refusal> {
        let account = self.account(caller)?;
        self.kill.check(caller)?;
        self.spend.check_anchor()?;
        self.spend.check_request_id(request_id)?;
        let spent = self.spend.spent_24h(caller, now);
        let verdict = account.policy.check(action, spent, self.prices.as_ref())?;
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
