//! The seam between a protocol module and the keyshare core.
//!
//! A module turns a tool call into an [`Intent`]: an unsigned transaction or an EIP-712 payload.
//! It does not receive a signer. [`authorize_tx`] and [`authorize_typed`] run in the core, on the
//! bytes about to be signed, and they refuse anything the module's [`Grant`] does not name even
//! when the bot's own allowlist would have permitted it.
//!
//! [`ModuleView`] is the only wallet surface a host trait should expose: reads and audit writes.
//! It has no `sign_*` method.

use std::future::Future;

use alloy::consensus::TxEip1559;
use alloy::dyn_abi::TypedData;
use alloy::primitives::{Address, Selector, TxKind};
use keyshare_core::audit::AuditEvent;
use keyshare_core::policy::{Action, Limits, PlainPolicy, PolicyEngine, TypedDataRule, Verdict};
use keyshare_core::price::{PriceSource, UsdMicros};
use keyshare_core::{Refusal, RefusalCode};
use serde_json::Value;

/// What the module asks the core to sign. There is no path here that carries a signature back
/// from the module; the core produces the signature after [`authorize_tx`] or [`authorize_typed`].
#[derive(Debug, Clone)]
pub enum Intent {
    Transaction(TxEip1559),
    TypedData(TypedData),
}

/// The contracts and EIP-712 domains a module is allowed to ask the core to sign.
/// Built by the module, enforced by the core.
#[derive(Debug, Clone)]
pub struct Grant {
    pub id: &'static str,
    /// `(contract, selector)` calls. The bot policy must allow them too.
    pub calls: Vec<(Address, [u8; 4])>,
    /// ERC-20 `approve` whose spender is one of these. The token address may vary.
    pub approve_spenders: Vec<Address>,
    pub typed_data: Vec<TypedDataRule>,
}

const APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];

fn refuse(code: RefusalCode, reason: impl Into<String>) -> Refusal {
    Refusal::new(code, reason)
}

impl Grant {
    /// `true` when this transaction is one of the shapes the module declared.
    pub fn covers_tx(&self, tx: &TxEip1559) -> Result<(), Refusal> {
        let TxKind::Call(to) = tx.to else {
            return Err(refuse(RefusalCode::ContractNotAllowed, format!("{} cannot deploy contracts", self.id)));
        };
        let data = tx.input.as_ref();
        let selector = data.get(..4).ok_or_else(|| {
            refuse(RefusalCode::ContractNotAllowed, format!("{} sent a transaction with no selector", self.id))
        })?;
        if selector == APPROVE {
            let spender = approve_spender(data).ok_or_else(|| {
                refuse(RefusalCode::ContractNotAllowed, format!("{} sent an approve the core cannot read", self.id))
            })?;
            if self.approve_spenders.contains(&spender) {
                return Ok(());
            }
            return Err(refuse(RefusalCode::ContractNotAllowed, format!("{} may not approve {spender}", self.id)));
        }
        let mut selector_bytes = [0u8; 4];
        selector_bytes.copy_from_slice(selector);
        if self.calls.iter().any(|(addr, sel)| *addr == to && *sel == selector_bytes) {
            return Ok(());
        }
        Err(refuse(
            RefusalCode::ContractNotAllowed,
            format!("{} may not call {} on {to}", self.id, Selector::from(selector_bytes)),
        ))
    }

    pub fn covers_typed(&self, data: &TypedData) -> Result<(), Refusal> {
        if self.typed_data.iter().any(|rule| rule.matches(data)) {
            Ok(())
        } else {
            Err(refuse(RefusalCode::TypedDataNotAllowed, format!("{} may not sign {:?}", self.id, data.primary_type)))
        }
    }
}

fn approve_spender(data: &[u8]) -> Option<Address> {
    // selector + abi word (address right-aligned) + amount word
    if data.len() < 4 + 32 || data[..4] != APPROVE {
        return None;
    }
    Some(Address::from_slice(&data[4 + 12..4 + 32]))
}

/// Core check for a transaction a module built. The grant is applied first, so a module cannot
/// aim at a contract just because the bot allowlisted it for `call_contract`. The bot policy
/// then runs unchanged: caps, chains, recipients, decoded calls.
pub fn authorize_tx(
    policy: &PlainPolicy,
    grant: &Grant,
    tx: &TxEip1559,
    spent_24h: UsdMicros,
    prices: &dyn PriceSource,
) -> Result<Verdict, Refusal> {
    grant.covers_tx(tx)?;
    policy.check(Action::Transaction(tx), spent_24h, prices)
}

/// Core check for EIP-712 a module built. Fund-moving types stay refused. Anything the grant
/// does not name is refused before a signer is invoked.
pub fn authorize_typed(grant: &Grant, data: &TypedData) -> Result<(), Refusal> {
    if keyshare_core::policy::refuses_raw_typed_data(&data.primary_type) {
        return Err(refuse(
            RefusalCode::DeniedPrimitive,
            format!("{:?} moves funds outside the module grant", data.primary_type),
        ));
    }
    grant.covers_typed(data)
}

/// What a module may ask the connector about a bot. Reads and audit writes only: there is no
/// signer, and no way to reach `Wallet::sign_transaction`, `sign_message`, or `sign_typed_data`.
pub trait ModuleView: Send + Sync {
    fn address(&self, caller: &str) -> impl Future<Output = Result<Address, Refusal>> + Send;
    fn limits(&self, caller: &str) -> impl Future<Output = Result<Limits, Refusal>> + Send;
    fn spent_24h(&self, caller: &str, now: u64) -> impl Future<Output = Result<UsdMicros, Refusal>> + Send;
    fn check_kill_switch(&self, caller: &str) -> impl Future<Output = Result<(), Refusal>> + Send;
    fn preview_tx(
        &self,
        caller: &str,
        tx: TxEip1559,
        now: u64,
    ) -> impl Future<Output = Result<Verdict, Refusal>> + Send;
    fn log_event(
        &self,
        caller: &str,
        request_id: &str,
        event: AuditEvent,
        detail: Value,
        now: u64,
    ) -> impl Future<Output = Result<(), String>> + Send;
    fn log_refusal(
        &self,
        caller: &str,
        request_id: &str,
        detail: Value,
        refusal: &Refusal,
        now: u64,
    ) -> impl Future<Output = Result<(), String>> + Send;
}

/// Runs the matching authorizer. There is no signer argument: the caller signs only after `Ok`.
pub fn authorize(
    policy: &PlainPolicy,
    grant: &Grant,
    intent: &Intent,
    spent_24h: UsdMicros,
    prices: &dyn PriceSource,
) -> Result<Option<Verdict>, Refusal> {
    match intent {
        Intent::Transaction(tx) => authorize_tx(policy, grant, tx, spent_24h, prices).map(Some),
        Intent::TypedData(data) => authorize_typed(grant, data).map(|()| None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Bytes, FixedBytes, U256, address};
    use alloy::sol;
    use alloy::sol_types::SolCall;
    use keyshare_core::policy::{ContractRule, RecipientRule};
    use keyshare_core::price::{PriceEntry, PriceTable};

    sol! {
        function transfer(address to, uint256 amount);
        function approve(address spender, uint256 amount);
    }

    /// Allowlisted on the bot, absent from the module grant.
    const BOT_ONLY: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
    /// Named by both the grant and the bot policy, and not a decoded special case.
    const MODULE_CALL: [u8; 4] = [0x01, 0x02, 0x03, 0x04];

    const CHAIN: u64 = 11_155_111;
    const ROUTER: Address = address!("0x3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48E");
    const USDC: Address = address!("0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238");
    const ATTACKER: Address = address!("0x2222222222222222222222222222222222222222");

    fn policy() -> PlainPolicy {
        PlainPolicy {
            chains: vec![CHAIN],
            per_tx_cap_usd: 1000,
            daily_cap_usd: 1000,
            recipients_allow: vec![RecipientRule::Any(ATTACKER)],
            contracts_allow: vec![
                ContractRule {
                    addr: USDC,
                    selectors: vec![transferCall::SELECTOR.into(), approveCall::SELECTOR.into()],
                    chains: vec![],
                },
                ContractRule {
                    addr: ROUTER,
                    selectors: vec![FixedBytes(BOT_ONLY), FixedBytes(MODULE_CALL)],
                    chains: vec![],
                },
                ContractRule { addr: ATTACKER, selectors: vec![transferCall::SELECTOR.into()], chains: vec![] },
            ],
            typed_data_allow: vec![],
            require_admin_cosign_above_usd: None,
            max_slippage_bps: 100,
            max_price_deviation_bps: 500,
            own_address: None,
        }
    }

    fn prices() -> PriceTable {
        PriceTable::from_entries(&[
            PriceEntry { chain_id: CHAIN, token: None, decimals: 18, usd: "2500".into() },
            PriceEntry { chain_id: CHAIN, token: Some(USDC), decimals: 6, usd: "1".into() },
        ])
        .unwrap()
    }

    fn grant() -> Grant {
        Grant {
            id: "uniswap",
            calls: vec![(ROUTER, MODULE_CALL)],
            approve_spenders: vec![ROUTER],
            typed_data: vec![TypedDataRule {
                primary_type: "Agent".into(),
                verifying_contract: Some(Address::ZERO),
                name: Some("Exchange".into()),
                chain_id: Some(1337),
                chainless: false,
            }],
        }
    }

    fn tx(to: Address, input: Vec<u8>) -> TxEip1559 {
        TxEip1559 { chain_id: CHAIN, to: TxKind::Call(to), input: Bytes::from(input), ..Default::default() }
    }

    #[test]
    fn module_intent_outside_the_grant_is_refused_before_signing() {
        // The bot policy allows a USDC transfer to the attacker. The module grant does not,
        // so the core refuses it even though the module produced the transaction. `authorize`
        // has no signer argument: a module cannot reach the key through this interface.
        let stolen = tx(USDC, transferCall { to: ATTACKER, amount: U256::from(1u64) }.abi_encode());
        let err = authorize(&policy(), &grant(), &Intent::Transaction(stolen), 0, &prices()).unwrap_err();
        assert_eq!(err.code, RefusalCode::ContractNotAllowed);

        let sneaky = tx(ROUTER, BOT_ONLY.to_vec());
        let err = authorize(&policy(), &grant(), &Intent::Transaction(sneaky), 0, &prices()).unwrap_err();
        assert_eq!(err.code, RefusalCode::ContractNotAllowed);

        let ok = tx(ROUTER, MODULE_CALL.to_vec());
        assert!(authorize(&policy(), &grant(), &Intent::Transaction(ok), 0, &prices()).is_ok());

        let approve = tx(USDC, approveCall { spender: ROUTER, amount: U256::from(1u64) }.abi_encode());
        assert!(authorize(&policy(), &grant(), &Intent::Transaction(approve), 0, &prices()).is_ok());
        let approve_stranger = tx(USDC, approveCall { spender: ATTACKER, amount: U256::from(1u64) }.abi_encode());
        assert_eq!(
            authorize(&policy(), &grant(), &Intent::Transaction(approve_stranger), 0, &prices()).unwrap_err().code,
            RefusalCode::ContractNotAllowed
        );
    }

    #[test]
    fn typed_data_outside_the_grant_is_refused_and_fund_moves_stay_refused() {
        let agent = serde_json::json!({
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}
                ],
                "Agent": [{"name": "source", "type": "string"}, {"name": "connectionId", "type": "bytes32"}]
            },
            "primaryType": "Agent",
            "domain": {"name": "Exchange", "version": "1", "chainId": 1337, "verifyingContract": Address::ZERO},
            "message": {"source": "b", "connectionId": "0x0000000000000000000000000000000000000000000000000000000000000001"}
        });
        let data: TypedData = serde_json::from_value(agent).unwrap();
        assert!(authorize(&policy(), &grant(), &Intent::TypedData(data), 0, &prices()).is_ok());

        let other = serde_json::json!({
            "types": {
                "EIP712Domain": [{"name": "name", "type": "string"}, {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}],
                "Agent": [{"name": "source", "type": "string"}]
            },
            "primaryType": "Agent",
            "domain": {"name": "NotExchange", "chainId": 1337, "verifyingContract": Address::ZERO},
            "message": {"source": "b"}
        });
        let data: TypedData = serde_json::from_value(other).unwrap();
        let err = authorize(&policy(), &grant(), &Intent::TypedData(data), 0, &prices()).unwrap_err();
        assert_eq!(err.code, RefusalCode::TypedDataNotAllowed);

        let withdraw = serde_json::json!({
            "types": {
                "EIP712Domain": [{"name": "name", "type": "string"}, {"name": "verifyingContract", "type": "address"}],
                "HyperliquidTransaction:UsdSend": [{"name": "amount", "type": "string"}]
            },
            "primaryType": "HyperliquidTransaction:UsdSend",
            "domain": {"name": "HyperliquidSignTransaction", "verifyingContract": Address::ZERO},
            "message": {"amount": "1"}
        });
        let data: TypedData = serde_json::from_value(withdraw).unwrap();
        // Even if a module grant named this type, the core still refuses fund-moving typed data.
        let mut wide = grant();
        wide.typed_data.push(TypedDataRule {
            primary_type: "HyperliquidTransaction:UsdSend".into(),
            verifying_contract: Some(Address::ZERO),
            name: Some("HyperliquidSignTransaction".into()),
            chain_id: None,
            chainless: true,
        });
        let err = authorize(&policy(), &wide, &Intent::TypedData(data), 0, &prices()).unwrap_err();
        assert_eq!(err.code, RefusalCode::DeniedPrimitive);
    }
}
