//! Owner approval of held requests (design §13.2, §15.2). The owner signs a plain EIP-191 message
//! with an admin key; any wallet can produce it. The message binds the decision, the caller, the
//! request id and the transaction's intent (chain, recipient, value, calldata), so one approval
//! can't be reused for a different request or a different transaction. Nonce and gas are left out
//! because they are filled after approval.

use alloy::consensus::TxEip1559;
use alloy::primitives::{Address, B256, Signature, keccak256};
use serde::{Deserialize, Serialize};

use crate::refusal::{Refusal, RefusalCode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Approve,
    Deny,
}

pub fn intent_hash(tx: &TxEip1559) -> B256 {
    let mut buf = Vec::with_capacity(8 + 20 + 32 + 32);
    buf.extend_from_slice(&tx.chain_id.to_be_bytes());
    buf.extend_from_slice(tx.to.to().copied().unwrap_or_default().as_slice());
    buf.extend_from_slice(&tx.value.to_be_bytes::<32>());
    buf.extend_from_slice(keccak256(&tx.input).as_slice());
    keccak256(buf)
}

/// The exact text the owner signs.
pub fn message(decision: Decision, caller: &str, request_id: &str, intent: B256) -> String {
    let verb = match decision {
        Decision::Approve => "approve",
        Decision::Deny => "deny",
    };
    format!("keyshare: {verb} request {request_id} for {caller}\nintent: {intent}")
}

/// Returns the admin key that signed, or refuses if it isn't one of `admins`.
pub fn verify(admins: &[Address], message: &str, signature: &Signature) -> Result<Address, Refusal> {
    let bad = |why: String| Refusal::new(RefusalCode::BadApproval, why);
    let signer = signature.recover_address_from_msg(message).map_err(|e| bad(format!("bad signature: {e}")))?;
    if admins.contains(&signer) {
        Ok(signer)
    } else {
        Err(bad(format!("{signer} is not an admin key for this wallet")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::{LocalSigner, Signer};
    use alloy::primitives::{TxKind, U256};

    #[test]
    fn approval_is_bound_to_request_and_intent() {
        let admin = LocalSigner::random();
        let tx = TxEip1559 { chain_id: 1, to: TxKind::Call(Address::ZERO), value: U256::from(5), ..Default::default() };
        let msg = message(Decision::Approve, "filltape", "r1", intent_hash(&tx));
        let sig = admin.sign_message(msg.as_bytes()).unwrap();
        assert_eq!(verify(&[admin.address()], &msg, &sig).unwrap(), admin.address());

        // Same signature, different request, decision or tx: refused.
        let other_tx = TxEip1559 { value: U256::from(6), ..tx.clone() };
        for m in [
            message(Decision::Approve, "filltape", "r2", intent_hash(&tx)),
            message(Decision::Deny, "filltape", "r1", intent_hash(&tx)),
            message(Decision::Approve, "loreum", "r1", intent_hash(&tx)),
            message(Decision::Approve, "filltape", "r1", intent_hash(&other_tx)),
        ] {
            assert!(verify(&[admin.address()], &m, &sig).is_err());
        }
        assert!(verify(&[LocalSigner::random().address()], &msg, &sig).is_err());
    }
}
