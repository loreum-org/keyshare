//! Hyperliquid testnet module.
//!
//! Encoding and venue calls live here. Signing does not: [`client::Hyperliquid`]
//! asks the host [`keyshare_module::Core`] to sign an intent the core has checked
//! against [`hyperliquid_allowlist`].

mod client;
pub mod protocol;

use std::sync::Arc;

use alloy::primitives::Address;
use keyshare_core::{ContractAllow, ModuleAllowlist, TypedAllow};
use keyshare_module::{ProtocolModule, ToolDecl};

pub use client::{
    AgentFile, EXPIRY_MARGIN_MS, HlConfig, Hyperliquid, OrderSpec, TESTNET_API, agent_path, check_api_url, now_ms,
};
pub use protocol::{
    CancelWire, E8, HlPolicy, L1Action, LimitWire, ModifyWire, OrderCheck, OrderTypeWire, OrderWire, Tif, Tpsl,
    TriggerWire, USER_SIGNATURE_CHAIN_ID, action_hash, approve_agent, chain_name, decimals, l1_typed_data,
    notional_usd, parse_e8, signature_json, user_signed_typed_data, wire_e8,
};

pub const MODULE_ID: &str = "hyperliquid";

pub const TOOLS: &[ToolDecl] = &[
    ToolDecl {
        name: "hl_positions",
        description: "Hyperliquid testnet: positions, margin and open orders of this bot's account. account.equity is the figure the daily loss stop uses.",
    },
    ToolDecl {
        name: "hl_place_order",
        description: "Hyperliquid testnet: place a limit or trigger (tp/sl) order. Checked against this bot's markets, size caps and daily loss stop. Sizes and prices are decimal strings.",
    },
    ToolDecl {
        name: "hl_modify",
        description: "Hyperliquid testnet: replace a resting order. The new order gets the same checks as a new one.",
    },
    ToolDecl { name: "hl_cancel", description: "Hyperliquid testnet: cancel a resting order by coin and order id." },
    ToolDecl {
        name: "hl_set_leverage",
        description: "Hyperliquid testnet: set leverage for a coin, up to this bot's maximum.",
    },
];

/// EIP-712 shapes this module may ask the core to sign.
///
/// L1 actions are the `Agent` type on the Exchange domain, chain 1337, and the
/// message `source` is testnet (`b`). Mainnet (`a`) is not on the list, so the
/// core refuses it even if this module built it. Phase 0 does not sign mainnet.
pub fn hyperliquid_allowlist() -> ModuleAllowlist {
    ModuleAllowlist {
        contracts: Vec::<ContractAllow>::new(),
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

/// Adapter so the registry can snapshot tools, the allowlist, and policy checks.
pub struct HyperliquidModule {
    inner: Arc<Hyperliquid>,
}

impl HyperliquidModule {
    pub fn new(inner: Arc<Hyperliquid>) -> Self {
        Self { inner }
    }

    pub fn inner(&self) -> &Arc<Hyperliquid> {
        &self.inner
    }
}

impl ProtocolModule for HyperliquidModule {
    fn id(&self) -> &'static str {
        MODULE_ID
    }

    fn tools(&self) -> &'static [ToolDecl] {
        TOOLS
    }

    fn allowlist(&self) -> ModuleAllowlist {
        hyperliquid_allowlist()
    }

    fn validate_policy(&self, value: &toml::Value) -> Result<(), String> {
        let policy: HlPolicy = value.clone().try_into().map_err(|e: toml::de::Error| e.to_string())?;
        policy.validate()
    }

    fn limits_key(&self) -> &'static str {
        "hyperliquid"
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn trading_client_cannot_sign_directly() {
        let src = include_str!("client.rs");
        assert!(!src.contains("LocalSigner"), "client.rs must not name the signer");
        assert!(!src.contains("sign_typed_data"), "client.rs must not sign typed data");
        assert!(!src.contains("sign_message"), "client.rs must not sign messages");
        assert!(!src.contains("PrivateKeySigner"), "client.rs must not name a private key type");
    }
}
