//! The signing backend trait. This crate has no way to load a key or build a signer: Phase 0's
//! `LocalSigner` lives in `keyshare-signer`, which only the connector depends on. A threshold
//! signer implements the same trait. Every method takes the full payload, never a bare hash, so a
//! backend always rebuilds the digest itself (design §3, T6).

use alloy::consensus::TxEip1559;
use alloy::dyn_abi::TypedData;
use alloy::primitives::{Address, Signature};

#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error("bad key: {0}")]
    BadKey(String),
    #[error("signing failed: {0}")]
    Failed(String),
}

pub trait Signer: Send + Sync {
    fn address(&self) -> Address;
    fn sign_transaction(&self, tx: &TxEip1559) -> Result<Signature, SignerError>;
    /// EIP-191 personal message.
    fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError>;
    fn sign_typed_data(&self, data: &TypedData) -> Result<Signature, SignerError>;
}
