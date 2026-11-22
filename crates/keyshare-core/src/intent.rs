//! An unsigned request a protocol module hands to the core.
//!
//! Modules build these. They do not sign them. [`Intent::check`] is the core's
//! re-check: the payload must match the allowlist the module declared when it
//! was registered. A module that emits something outside that list is refused
//! here, before any key is used.

use alloy::consensus::TxEip1559;
use alloy::dyn_abi::TypedData;
use alloy::primitives::{Address, TxKind, U256};
use alloy::sol;
use alloy::sol_types::SolCall;

use crate::refusal::{Refusal, RefusalCode};

sol! {
    function approve(address spender, uint256 amount);
}

/// What a module is asking the core to sign. None of these carry a signature.
#[derive(Debug, Clone)]
pub enum Intent {
    Transaction(TxEip1559),
    TypedData(TypedData),
}

/// Contracts and EIP-712 domains one module is allowed to ask the core to sign.
/// Built once from the module's declaration and the operator's config, then
/// stored by the host. A later call cannot swap in a wider list.
#[derive(Debug, Clone, Default)]
pub struct ModuleAllowlist {
    pub contracts: Vec<ContractAllow>,
    pub typed: Vec<TypedAllow>,
}

/// One contract call the module may produce.
#[derive(Debug, Clone)]
pub enum ContractAllow {
    /// `to` and the 4-byte selector must both match, on this chain.
    Call { chain_id: u64, to: Address, selector: [u8; 4] },
    /// `approve(spender, amount)` to any token, and only this spender, on this chain.
    Approve { chain_id: u64, spender: Address },
}

/// One EIP-712 shape the module may produce. Every field that is set must match.
/// `message_equals` pins string fields inside the message (Hyperliquid's `source`
/// is pinned to testnet here).
#[derive(Debug, Clone)]
pub struct TypedAllow {
    pub primary_type: String,
    pub name: Option<String>,
    pub version: Option<String>,
    pub chain_id: Option<u64>,
    pub verifying_contract: Option<Address>,
    pub message_equals: Vec<(String, String)>,
}

impl Intent {
    /// Refuse the intent unless it matches `allow`. This does not sign.
    pub fn check(&self, allow: &ModuleAllowlist) -> Result<(), Refusal> {
        match self {
            Self::Transaction(tx) => permits_tx(allow, tx),
            Self::TypedData(data) => permits_typed(allow, data),
        }
    }
}

fn refuse(code: RefusalCode, reason: impl Into<String>) -> Refusal {
    Refusal::new(code, reason)
}

fn permits_tx(allow: &ModuleAllowlist, tx: &TxEip1559) -> Result<(), Refusal> {
    let TxKind::Call(to) = tx.to else {
        return Err(refuse(RefusalCode::ContractNotAllowed, "contract creation is not allowed"));
    };
    let data = tx.input.as_ref();
    let Some(bytes) = data.get(..4) else {
        return Err(refuse(RefusalCode::ContractNotAllowed, "module intent has no function selector"));
    };
    let selector: [u8; 4] = bytes.try_into().unwrap_or([0, 0, 0, 0]);
    let ok = allow.contracts.iter().any(|pattern| match pattern {
        ContractAllow::Call { chain_id, to: want, selector: want_sel } => {
            tx.chain_id == *chain_id && to == *want && selector == *want_sel
        }
        ContractAllow::Approve { chain_id, spender } => {
            tx.chain_id == *chain_id && selector == approveCall::SELECTOR && approve_spender(data) == Some(*spender)
        }
    });
    if ok {
        Ok(())
    } else {
        Err(refuse(
            RefusalCode::ContractNotAllowed,
            format!("call {selector:?} on {to} is outside the module allowlist on chain {}", tx.chain_id),
        ))
    }
}

fn approve_spender(data: &[u8]) -> Option<Address> {
    approveCall::abi_decode(data).ok().map(|call| call.spender)
}

fn permits_typed(allow: &ModuleAllowlist, data: &TypedData) -> Result<(), Refusal> {
    if allow.typed.iter().any(|rule| rule.matches(data)) {
        Ok(())
    } else {
        Err(refuse(
            RefusalCode::TypedDataNotAllowed,
            format!("typed data {:?} with this domain is outside the module allowlist", data.primary_type),
        ))
    }
}

impl TypedAllow {
    fn matches(&self, data: &TypedData) -> bool {
        if self.primary_type != data.primary_type {
            return false;
        }
        let domain = &data.domain;
        if self.name.as_deref().is_some_and(|name| domain.name.as_deref() != Some(name)) {
            return false;
        }
        if self.version.as_deref().is_some_and(|version| domain.version.as_deref() != Some(version)) {
            return false;
        }
        if let Some(chain) = self.chain_id
            && domain.chain_id != Some(U256::from(chain))
        {
            return false;
        }
        if let Some(contract) = self.verifying_contract
            && domain.verifying_contract != Some(contract)
        {
            return false;
        }
        self.message_equals.iter().all(|(field, want)| data.message.get(field).and_then(|v| v.as_str()) == Some(want))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Bytes, TxKind, U256, address};

    const CHAIN: u64 = 11155111;
    const ROUTER: Address = address!("0x3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48E");
    const TOKEN: Address = address!("0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238");
    const OTHER: Address = address!("0x2222222222222222222222222222222222222222");
    const EXACT_INPUT_SINGLE: [u8; 4] = [0x04, 0xe4, 0x5a, 0xaf];

    fn swap_allow() -> ModuleAllowlist {
        ModuleAllowlist {
            contracts: vec![
                ContractAllow::Call { chain_id: CHAIN, to: ROUTER, selector: EXACT_INPUT_SINGLE },
                ContractAllow::Approve { chain_id: CHAIN, spender: ROUTER },
            ],
            typed: vec![],
        }
    }

    fn tx(to: Address, input: impl Into<Bytes>) -> TxEip1559 {
        TxEip1559 { chain_id: CHAIN, to: TxKind::Call(to), input: input.into(), ..Default::default() }
    }

    #[test]
    fn transaction_outside_the_module_allowlist_is_refused() {
        let allow = swap_allow();
        let inside = tx(ROUTER, EXACT_INPUT_SINGLE);
        assert!(Intent::Transaction(inside).check(&allow).is_ok());

        let approve = approveCall { spender: ROUTER, amount: U256::from(1u8) };
        assert!(Intent::Transaction(tx(TOKEN, approve.abi_encode())).check(&allow).is_ok());

        let elsewhere = tx(OTHER, EXACT_INPUT_SINGLE);
        let err = Intent::Transaction(elsewhere).check(&allow).unwrap_err();
        assert_eq!(err.code, RefusalCode::ContractNotAllowed);

        let wrong_spender = approveCall { spender: OTHER, amount: U256::from(1u8) };
        let err = Intent::Transaction(tx(TOKEN, wrong_spender.abi_encode())).check(&allow).unwrap_err();
        assert_eq!(err.code, RefusalCode::ContractNotAllowed);
    }

    fn agent(source: &str) -> TypedData {
        serde_json::from_value(serde_json::json!({
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}
                ],
                "Agent": [
                    {"name": "source", "type": "string"},
                    {"name": "connectionId", "type": "bytes32"}
                ]
            },
            "primaryType": "Agent",
            "domain": {
                "name": "Exchange",
                "version": "1",
                "chainId": 1337,
                "verifyingContract": Address::ZERO
            },
            "message": {"source": source, "connectionId": alloy::primitives::B256::ZERO}
        }))
        .unwrap()
    }

    fn hl_allow() -> ModuleAllowlist {
        ModuleAllowlist {
            contracts: vec![],
            typed: vec![TypedAllow {
                primary_type: "Agent".into(),
                name: Some("Exchange".into()),
                version: Some("1".into()),
                chain_id: Some(1337),
                verifying_contract: Some(Address::ZERO),
                message_equals: vec![("source".into(), "b".into())],
            }],
        }
    }

    #[test]
    fn typed_data_outside_the_module_allowlist_is_refused() {
        let allow = hl_allow();
        assert!(Intent::TypedData(agent("b")).check(&allow).is_ok());
        // Phase 0: source "a" is Hyperliquid mainnet. The module allowlist does not include it.
        let err = Intent::TypedData(agent("a")).check(&allow).unwrap_err();
        assert_eq!(err.code, RefusalCode::TypedDataNotAllowed);

        let mut other = agent("b");
        other.primary_type = "UsdSend".into();
        let err = Intent::TypedData(other).check(&allow).unwrap_err();
        assert_eq!(err.code, RefusalCode::TypedDataNotAllowed);
    }
}
