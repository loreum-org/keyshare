//! The seam between protocol modules and the keyshare core.
//!
//! A module declares tools, an allowlist, and its own policy checks. It turns a
//! tool call into an [`Intent`](keyshare_core::Intent) and asks the [`Core`] to
//! accept it. The [`Core`] trait has no key and no raw sign method: the only
//! signature a module can receive is one the core already checked against the
//! module's registered allowlist.

use std::sync::Arc;

use alloy::consensus::TxEip1559;
use alloy::dyn_abi::TypedData;
use alloy::primitives::{Address, B256, Bytes, Signature};
use async_trait::async_trait;
use keyshare_core::audit::AuditEvent;
use keyshare_core::{ModuleAllowlist, Refusal, UsdMicros};
use serde_json::Value;

/// One MCP tool a module contributes. The host registers these and hides them
/// when the module is disabled for the calling bot.
#[derive(Debug, Clone, Copy)]
pub struct ToolDecl {
    pub name: &'static str,
    pub description: &'static str,
}

/// What the core will tell a module about a chain transaction it watched.
#[derive(Debug, Clone, Copy)]
pub struct ChainTxStatus {
    pub state: &'static str,
}

/// Uniswap v3 contracts a module may target on one chain. The host fills this
/// from the operator's chain config; the module does not choose new addresses.
#[derive(Debug, Clone)]
pub struct UniswapDeployment {
    pub chain_id: u64,
    pub router: Address,
    pub quoter: Address,
    pub weth: Address,
    pub fee_tiers: Vec<u32>,
}

/// Result of a tool that goes through the core's transaction path.
pub type Outcome = Result<Value, Value>;

/// The host a module is allowed to talk to.
///
/// There is no `sign` method that takes a private key. [`Core::sign_venue`]
/// asks the core to check `data` against the allowlist registered for
/// `module_id` and, only if that passes, sign with the venue key the host
/// holds. [`Core::submit_module_tx`] does the same check for an unsigned
/// transaction, then runs core policy, simulation, and signing.
#[async_trait]
pub trait Core: Send + Sync {
    /// Outer error is a host failure (lock poison). Inner error is a policy refusal.
    async fn address(&self, caller: &str) -> Result<Result<Address, Refusal>, String>;
    async fn max_slippage_bps(&self, caller: &str) -> Result<u32, Refusal>;
    async fn kill_check(&self, caller: &str) -> Result<Result<(), Refusal>, String>;
    async fn log_event(
        &self,
        caller: &str,
        request_id: &str,
        event: AuditEvent,
        detail: Value,
        now: u64,
    ) -> Result<(), String>;
    async fn log_refusal(
        &self,
        caller: &str,
        request_id: &str,
        detail: Value,
        refusal: &Refusal,
        now: u64,
    ) -> Result<(), String>;
    /// Outer error is a host failure. Inner error is the allowlist or policy refusal.
    async fn preview_module_tx(
        &self,
        module_id: &str,
        caller: &str,
        tx: &TxEip1559,
        now: u64,
    ) -> Result<Result<(), Refusal>, String>;
    async fn submit_module_tx(
        &self,
        module_id: &str,
        caller: &str,
        id: &str,
        tx: TxEip1559,
        dry_run: bool,
    ) -> Result<Outcome, String>;
    /// The venue key for `module_id` is present and unexpired. Does not return the key.
    async fn venue_key_ready(&self, module_id: &str, bot: &str) -> Result<(), Refusal>;
    async fn sign_venue(&self, module_id: &str, bot: &str, data: &TypedData) -> Result<Signature, Refusal>;
    async fn eth_call(&self, chain_id: u64, to: Address, data: Bytes) -> Result<Bytes, Refusal>;
    async fn token_decimals(&self, chain_id: u64, token: Address) -> Result<u8, Refusal>;
    async fn tx_status(&self, chain_id: u64, hash: B256) -> Result<ChainTxStatus, Refusal>;
    fn uniswap(&self, chain_id: u64) -> Result<UniswapDeployment, Refusal>;
}

/// A protocol module. Implementing this does not grant access to a signer.
pub trait ProtocolModule: Send + Sync {
    fn id(&self) -> &'static str;
    fn tools(&self) -> &'static [ToolDecl];
    /// Allowlist snapshotted when the module is registered. The core checks
    /// every intent against this value, not against a list the module passes
    /// later.
    fn allowlist(&self) -> ModuleAllowlist;
    /// Parse and validate this module's own policy fields. Core caps, chain
    /// allowlists, and the approval flow are not this method's job.
    fn validate_policy(&self, value: &toml::Value) -> Result<(), String>;
    /// Usage the `limits` tool should merge in. `None` when this bot has nothing to report.
    fn limits_key(&self) -> &'static str;
}

/// Modules registered with the host, plus the allowlists frozen at startup.
#[derive(Clone, Default)]
pub struct Registry {
    modules: Vec<Arc<dyn ProtocolModule>>,
    allowlists: Vec<(&'static str, ModuleAllowlist)>,
    /// Tool name → module id. Declared even when that module's client is not built,
    /// so a disabled module can be hidden before it has any state.
    tools: Vec<(&'static str, &'static [ToolDecl])>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, module: Arc<dyn ProtocolModule>) {
        let id = module.id();
        let tools = module.tools();
        let allow = module.allowlist();
        self.claim_tools(id, tools);
        if let Some(slot) = self.allowlists.iter_mut().find(|(name, _)| *name == id) {
            *slot = (id, allow);
        } else {
            self.allowlists.push((id, allow));
        }
        if let Some(slot) = self.modules.iter_mut().find(|m| m.id() == id) {
            *slot = module;
        } else {
            self.modules.push(module);
        }
    }

    /// Remember which tools belong to `id` before a live client exists.
    pub fn claim_tools(&mut self, id: &'static str, tools: &'static [ToolDecl]) {
        if let Some(slot) = self.tools.iter_mut().find(|(name, _)| *name == id) {
            *slot = (id, tools);
        } else {
            self.tools.push((id, tools));
        }
    }

    pub fn allowlist(&self, id: &str) -> Option<&ModuleAllowlist> {
        self.allowlists.iter().find(|(name, _)| *name == id).map(|(_, allow)| allow)
    }

    /// The module that declared `tool`, if it is one of ours.
    pub fn module_for_tool(&self, tool: &str) -> Option<&'static str> {
        self.tools
            .iter()
            .find(|(_, tools)| tools.iter().any(|decl| decl.name == tool))
            .map(|(id, _)| *id)
            .or_else(|| self.modules.iter().find(|m| m.tools().iter().any(|t| t.name == tool)).map(|m| m.id()))
    }

    pub fn module(&self, id: &str) -> Option<&dyn ProtocolModule> {
        self.modules.iter().find(|m| m.id() == id).map(|m| m.as_ref())
    }
}

/// Unix seconds. The host and the modules share this clock for audit entries.
pub fn unix_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Whole-dollar micros, for modules that report usage next to the core caps.
pub fn usd(micros: UsdMicros) -> String {
    format!("{}.{:06}", micros / 1_000_000, micros % 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use alloy::primitives::{TxKind, U256, address};
    use keyshare_core::{ContractAllow, Intent, RefusalCode, TypedAllow};

    const CHAIN: u64 = 11155111;
    const ROUTER: Address = address!("0x3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48E");

    struct Toy {
        allow: ModuleAllowlist,
    }

    impl ProtocolModule for Toy {
        fn id(&self) -> &'static str {
            "toy"
        }
        fn tools(&self) -> &'static [ToolDecl] {
            &[ToolDecl { name: "toy_do", description: "toy" }]
        }
        fn allowlist(&self) -> ModuleAllowlist {
            self.allow.clone()
        }
        fn validate_policy(&self, _value: &toml::Value) -> Result<(), String> {
            Ok(())
        }
        fn limits_key(&self) -> &'static str {
            "toy"
        }
    }

    struct Recording {
        allow: ModuleAllowlist,
        signed: Mutex<u32>,
    }

    #[async_trait]
    impl Core for Recording {
        async fn address(&self, _: &str) -> Result<Result<Address, Refusal>, String> {
            Ok(Ok(Address::ZERO))
        }
        async fn max_slippage_bps(&self, _: &str) -> Result<u32, Refusal> {
            Ok(100)
        }
        async fn kill_check(&self, _: &str) -> Result<Result<(), Refusal>, String> {
            Ok(Ok(()))
        }
        async fn log_event(&self, _: &str, _: &str, _: AuditEvent, _: Value, _: u64) -> Result<(), String> {
            Ok(())
        }
        async fn log_refusal(&self, _: &str, _: &str, _: Value, _: &Refusal, _: u64) -> Result<(), String> {
            Ok(())
        }
        async fn preview_module_tx(
            &self,
            _: &str,
            _: &str,
            _: &TxEip1559,
            _: u64,
        ) -> Result<Result<(), Refusal>, String> {
            Ok(Ok(()))
        }
        async fn submit_module_tx(
            &self,
            module_id: &str,
            _: &str,
            _: &str,
            tx: TxEip1559,
            _: bool,
        ) -> Result<Outcome, String> {
            // The core re-check uses the registered allowlist, even though the
            // module is the one that built the transaction.
            if let Err(r) = Intent::Transaction(tx).check(self.allowlist_of(module_id)) {
                return Ok(Err(refusal_value(&r)));
            }
            Ok(Ok(serde_json::json!({ "signed": false })))
        }
        async fn venue_key_ready(&self, _: &str, _: &str) -> Result<(), Refusal> {
            Ok(())
        }
        async fn sign_venue(&self, module_id: &str, _: &str, data: &TypedData) -> Result<Signature, Refusal> {
            Intent::TypedData(data.clone()).check(self.allowlist_of(module_id))?;
            *self.signed.lock().unwrap() += 1;
            // A real host would sign here. This stub refuses to invent a signature
            // and only counts a check that passed. The test below never gets here
            // for an out-of-allowlist payload.
            Err(Refusal::new(RefusalCode::Internal, "stub does not hold a key"))
        }
        async fn eth_call(&self, _: u64, _: Address, _: Bytes) -> Result<Bytes, Refusal> {
            Ok(Bytes::new())
        }
        async fn token_decimals(&self, _: u64, _: Address) -> Result<u8, Refusal> {
            Ok(18)
        }
        async fn tx_status(&self, _: u64, _: B256) -> Result<ChainTxStatus, Refusal> {
            Ok(ChainTxStatus { state: "unknown" })
        }
        fn uniswap(&self, chain_id: u64) -> Result<UniswapDeployment, Refusal> {
            Ok(UniswapDeployment {
                chain_id,
                router: ROUTER,
                quoter: Address::ZERO,
                weth: Address::ZERO,
                fee_tiers: vec![500],
            })
        }
    }

    impl Recording {
        fn allowlist_of(&self, id: &str) -> &ModuleAllowlist {
            assert_eq!(id, "toy");
            &self.allow
        }
    }

    fn refusal_value(r: &Refusal) -> Value {
        serde_json::json!(r)
    }

    #[test]
    fn registry_freezes_the_allowlist_a_module_declared() {
        let mut registry = Registry::new();
        let module = Arc::new(Toy {
            allow: ModuleAllowlist {
                contracts: vec![ContractAllow::Call {
                    chain_id: CHAIN,
                    to: ROUTER,
                    selector: [0x04, 0xe4, 0x5a, 0xaf],
                }],
                typed: vec![TypedAllow {
                    primary_type: "Agent".into(),
                    name: Some("Exchange".into()),
                    version: Some("1".into()),
                    chain_id: Some(1337),
                    verifying_contract: Some(Address::ZERO),
                    message_equals: vec![("source".into(), "b".into())],
                }],
            },
        });
        registry.register(module);
        assert_eq!(registry.module_for_tool("toy_do"), Some("toy"));
        assert!(registry.module_for_tool("send").is_none());
        assert_eq!(registry.allowlist("toy").unwrap().contracts.len(), 1);
    }

    #[tokio::test]
    async fn core_refuses_an_intent_the_module_produced_outside_its_allowlist() {
        let allow = ModuleAllowlist {
            contracts: vec![ContractAllow::Call { chain_id: CHAIN, to: ROUTER, selector: [0x04, 0xe4, 0x5a, 0xaf] }],
            typed: vec![],
        };
        let host = Recording { allow, signed: Mutex::new(0) };
        // A module bug: the declared router is ROUTER, the intent goes elsewhere.
        let tx = TxEip1559 {
            chain_id: CHAIN,
            to: TxKind::Call(address!("0x2222222222222222222222222222222222222222")),
            input: Bytes::from_static(&[0x04, 0xe4, 0x5a, 0xaf]),
            value: U256::ZERO,
            ..Default::default()
        };
        let out = host.submit_module_tx("toy", "bot", "req", tx, false).await.unwrap();
        let err = out.unwrap_err();
        assert_eq!(err["code"], "CONTRACT_NOT_ALLOWED");
        assert_eq!(*host.signed.lock().unwrap(), 0);
    }
}
