//! Uniswap v3 swap module. Builds unsigned transactions. The core checks them
//! against [`uniswap_allowlist`] and the bot's policy, then signs.

mod swap;

use std::sync::Arc;

use keyshare_core::{ContractAllow, ModuleAllowlist};
use keyshare_module::{ProtocolModule, ToolDecl, UniswapDeployment};

pub use swap::{SwapRequest, swap};

pub const MODULE_ID: &str = "uniswap";

/// `exactInputSingle` on SwapRouter02.
pub const EXACT_INPUT_SINGLE: [u8; 4] = [0x04, 0xe4, 0x5a, 0xaf];

pub const TOOLS: &[ToolDecl] = &[ToolDecl {
    name: "swap",
    description: "Swap an exact amount on Uniswap v3. Quotes first; the output always comes back to this wallet with at most max_slippage_bps below the quote. Approves the router for exactly the amount if needed.",
}];

/// Router calls and exact approves this module may ask the core to sign.
/// Built from the operator's chain config, not from the tool arguments.
pub fn uniswap_allowlist(deployments: &[UniswapDeployment]) -> ModuleAllowlist {
    let mut contracts = Vec::with_capacity(deployments.len() * 2);
    for deployment in deployments {
        contracts.push(ContractAllow::Call {
            chain_id: deployment.chain_id,
            to: deployment.router,
            selector: EXACT_INPUT_SINGLE,
        });
        contracts.push(ContractAllow::Approve { chain_id: deployment.chain_id, spender: deployment.router });
    }
    ModuleAllowlist { contracts, typed: Vec::new() }
}

pub struct UniswapModule {
    deployments: Vec<UniswapDeployment>,
}

impl UniswapModule {
    pub fn new(deployments: Vec<UniswapDeployment>) -> Self {
        Self { deployments }
    }

    pub fn deployments(&self) -> &[UniswapDeployment] {
        &self.deployments
    }
}

impl ProtocolModule for UniswapModule {
    fn id(&self) -> &'static str {
        MODULE_ID
    }

    fn tools(&self) -> &'static [ToolDecl] {
        TOOLS
    }

    fn allowlist(&self) -> ModuleAllowlist {
        uniswap_allowlist(&self.deployments)
    }

    /// Slippage and price deviation stay on the bot's core policy. There is no
    /// separate uniswap table, so an empty value is the only valid module policy.
    fn validate_policy(&self, value: &toml::Value) -> Result<(), String> {
        match value {
            toml::Value::Table(table) if table.is_empty() => Ok(()),
            _ => Err(
                "uniswap has no module config table; max_slippage_bps and max_price_deviation_bps are policy fields"
                    .into(),
            ),
        }
    }

    fn limits_key(&self) -> &'static str {
        "uniswap"
    }
}

pub fn module(deployments: Vec<UniswapDeployment>) -> Arc<UniswapModule> {
    Arc::new(UniswapModule::new(deployments))
}

#[cfg(test)]
mod tests {
    #[test]
    fn swap_source_does_not_sign() {
        let src = include_str!("swap.rs");
        assert!(!src.contains("LocalSigner"));
        assert!(!src.contains("sign_typed_data"));
        assert!(!src.contains("sign_transaction"));
    }
}
