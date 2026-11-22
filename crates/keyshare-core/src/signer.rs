//! The signing backend trait. This crate has no way to load a key or build a signer: Phase 0's
//! `LocalSigner` lives in `keyshare-signer`, which only the connector depends on. A threshold
//! signer implements the same trait. Every method takes the full payload, never a bare hash, so a
//! backend always rebuilds the digest itself (design §3, T6).

use alloy::consensus::TxEip1559;
use alloy::dyn_abi::TypedData;
use alloy::primitives::{Address, Signature};

use crate::policy::Action;
use crate::policy_file::PolicyRef;
use crate::refusal::Refusal;

#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error("bad key: {0}")]
    BadKey(String),
    #[error("signing failed: {0}")]
    Failed(String),
    /// Another signing party (a threshold co-signer) checked the request and refused it.
    #[error("co-signer refused: {0}")]
    Refused(Refusal),
}

/// Who is asking, for which request, under which policy. The wallet passes this with every
/// signature. A single-key signer ignores it. A threshold signer hands it to the co-signer,
/// which re-checks the request against its own copy of that policy before it helps sign.
#[derive(Debug, Clone, Default)]
pub struct SignContext {
    pub caller: String,
    pub request_id: String,
    pub policy: Option<PolicyRef>,
    /// The owner's signed approval of a held transaction, when the request is one.
    pub owner_approval: Option<Signature>,
}

pub trait Signer: Send + Sync {
    fn address(&self) -> Address;
    fn sign_transaction(&self, tx: &TxEip1559) -> Result<Signature, SignerError>;
    /// EIP-191 personal message.
    fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError>;
    fn sign_typed_data(&self, data: &TypedData) -> Result<Signature, SignerError>;

    /// The wallet's signing call. The default ignores `ctx`; a backend that involves another
    /// party overrides it.
    fn sign_with(&self, _ctx: &SignContext, action: Action<'_>) -> Result<Signature, SignerError> {
        match action {
            Action::Transaction(tx) => self.sign_transaction(tx),
            Action::Message(m) => self.sign_message(m),
            Action::TypedData(d) => self.sign_typed_data(d),
        }
    }
}
