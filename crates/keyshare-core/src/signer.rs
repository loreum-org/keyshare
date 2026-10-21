//! The signing backend. Phase 0 uses [`LocalSigner`], a single testnet key. The 2-of-3 DKLs23
//! signer (Phase 2) implements the same trait. Every method takes the full payload, never a
//! bare hash, so a backend always rebuilds the digest itself (design §3, T6).

use alloy::consensus::{SignableTransaction, TxEip1559};
use alloy::dyn_abi::TypedData;
use alloy::primitives::{Address, B256, Signature};
use alloy::signers::SignerSync;
use alloy::signers::local::PrivateKeySigner;

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

/// One plain private key in memory. Testnet only (design §5, Phase 0).
pub struct LocalSigner(PrivateKeySigner);

impl LocalSigner {
    pub fn from_hex(key: &str) -> Result<Self, SignerError> {
        key.trim().parse::<PrivateKeySigner>().map(Self).map_err(|e| SignerError::BadKey(e.to_string()))
    }

    pub fn random() -> Self {
        Self(PrivateKeySigner::random())
    }

    fn sign_hash(&self, hash: &B256) -> Result<Signature, SignerError> {
        self.0.sign_hash_sync(hash).map_err(|e| SignerError::Failed(e.to_string()))
    }
}

impl Signer for LocalSigner {
    fn address(&self) -> Address {
        self.0.address()
    }

    fn sign_transaction(&self, tx: &TxEip1559) -> Result<Signature, SignerError> {
        self.sign_hash(&tx.signature_hash())
    }

    fn sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        self.0.sign_message_sync(message).map_err(|e| SignerError::Failed(e.to_string()))
    }

    fn sign_typed_data(&self, data: &TypedData) -> Result<Signature, SignerError> {
        let hash = data.eip712_signing_hash().map_err(|e| SignerError::Failed(e.to_string()))?;
        self.sign_hash(&hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{TxKind, U256, address};

    #[test]
    fn transaction_signature_recovers_to_signer() {
        let signer = LocalSigner::random();
        let tx = TxEip1559 {
            chain_id: 11155111,
            nonce: 0,
            gas_limit: 21_000,
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            to: TxKind::Call(address!("0x000000000000000000000000000000000000dEaD")),
            value: U256::from(1),
            ..Default::default()
        };
        let sig = signer.sign_transaction(&tx).expect("sign");
        let recovered = sig.recover_address_from_prehash(&tx.signature_hash()).expect("recover");
        assert_eq!(recovered, signer.address());
    }

    #[test]
    fn message_signature_recovers_to_signer() {
        let signer = LocalSigner::random();
        let sig = signer.sign_message(b"hello").expect("sign");
        assert_eq!(sig.recover_address_from_msg(b"hello").expect("recover"), signer.address());
    }
}
