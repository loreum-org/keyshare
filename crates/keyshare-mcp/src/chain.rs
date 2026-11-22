//! Chain RPC: nonce, gas, fees, simulation and broadcast. Phase 0 simulates with `eth_estimateGas`
//! (a revert there is `SIM_REVERT`). Full asset-delta tracing comes later.

use std::collections::HashMap;

use alloy::consensus::TxEip1559;
use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, B256, Bytes, TxKind, U256};
use alloy::providers::{Provider, RootProvider};
use alloy::rpc::types::TransactionRequest;
use alloy::sol;
use alloy::sol_types::SolCall;
use alloy::transports::TransportError;
use keyshare_core::{Refusal, RefusalCode};
use serde::{Deserialize, Serialize};

sol! {
    function decimals() returns (uint8);
    function balanceOf(address owner) returns (uint256);
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainConfig {
    pub id: u64,
    pub rpc_url: String,
    /// Uniswap v3 contracts for the `swap` tool. Without them `swap` refuses this chain.
    pub uniswap_v3: Option<UniswapV3>,
}

/// SwapRouter02, QuoterV2 and the wrapped native token on one chain.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UniswapV3 {
    pub router: Address,
    pub quoter: Address,
    pub weth: Address,
    /// Pool fee tiers to quote, in hundredths of a bip. Default 500, 3000, 10000.
    #[serde(default = "default_fee_tiers")]
    pub fee_tiers: Vec<u32>,
}

fn default_fee_tiers() -> Vec<u32> {
    vec![500, 3000, 10000]
}

pub struct Chains {
    providers: HashMap<u64, RootProvider>,
    uniswap: HashMap<u64, UniswapV3>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Simulation {
    pub ok: bool,
    pub gas: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revert: Option<String>,
}

/// A failed RPC call. The node's own error message is passed on to the bot, but a transport error
/// is not: its text carries the RPC URL, which may hold the operator's API key. That detail goes
/// to the server log only.
pub fn rpc_err(e: TransportError) -> Refusal {
    match e.as_error_resp() {
        Some(resp) => Refusal::new(RefusalCode::RpcUnavailable, format!("rpc: {}", resp.message)),
        None => {
            eprintln!("rpc transport error: {e}");
            Refusal::new(RefusalCode::RpcUnavailable, "rpc unavailable")
        }
    }
}

/// A bad answer from the RPC (no secrets in it).
pub fn rpc_bad(why: impl std::fmt::Display) -> Refusal {
    Refusal::new(RefusalCode::RpcUnavailable, format!("rpc: {why}"))
}

impl Chains {
    pub fn new(configs: &[ChainConfig]) -> Result<Self, String> {
        let (mut providers, mut uniswap) = (HashMap::new(), HashMap::new());
        for c in configs {
            let url = c.rpc_url.parse().map_err(|e| format!("chain {}: bad rpc_url: {e}", c.id))?;
            providers.insert(c.id, RootProvider::new_http(url));
            if let Some(u) = &c.uniswap_v3 {
                uniswap.insert(c.id, u.clone());
            }
        }
        Ok(Self { providers, uniswap })
    }

    pub fn ids(&self) -> Vec<u64> {
        let mut ids: Vec<u64> = self.providers.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    pub fn get(&self, chain_id: u64) -> Result<&RootProvider, Refusal> {
        self.providers.get(&chain_id).ok_or_else(|| {
            Refusal::new(RefusalCode::ChainNotAllowed, format!("no RPC configured for chain {chain_id}"))
        })
    }

    pub fn uniswap_all(&self) -> Vec<(u64, UniswapV3)> {
        let mut out: Vec<_> = self.uniswap.iter().map(|(id, u)| (*id, u.clone())).collect();
        out.sort_by_key(|(id, _)| *id);
        out
    }

    pub fn uniswap(&self, chain_id: u64) -> Result<&UniswapV3, Refusal> {
        self.uniswap.get(&chain_id).ok_or_else(|| {
            Refusal::new(RefusalCode::NoRoute, format!("no swap router configured for chain {chain_id}"))
        })
    }
}

pub async fn token_decimals(p: &RootProvider, token: Address) -> Result<u8, Refusal> {
    let req = TransactionRequest::default().with_to(token).with_input(decimalsCall {}.abi_encode());
    let out = p.call(req).await.map_err(rpc_err)?;
    decimalsCall::abi_decode_returns(&out).map_err(|e| rpc_bad(format!("decimals() on {token}: {e}")))
}

pub async fn balance(p: &RootProvider, owner: Address, token: Option<Address>) -> Result<U256, Refusal> {
    match token {
        None => p.get_balance(owner).await.map_err(rpc_err),
        Some(t) => {
            let req = TransactionRequest::default().with_to(t).with_input(balanceOfCall { owner }.abi_encode());
            let out = p.call(req).await.map_err(rpc_err)?;
            balanceOfCall::abi_decode_returns(&out).map_err(|e| rpc_bad(format!("balanceOf on {t}: {e}")))
        }
    }
}

/// Fills nonce, gas and fees, simulating the call on the way. A revert returns `ok: false`.
pub async fn fill_and_simulate(p: &RootProvider, from: Address, tx: &mut TxEip1559) -> Result<Simulation, Refusal> {
    let TxKind::Call(to) = tx.to else {
        return Err(Refusal::new(RefusalCode::ContractNotAllowed, "contract creation is not allowed"));
    };
    let req = TransactionRequest::default()
        .with_from(from)
        .with_to(to)
        .with_value(tx.value)
        .with_input(tx.input.clone())
        .with_chain_id(tx.chain_id);

    let chain = p.get_chain_id().await.map_err(rpc_err)?;
    if chain != tx.chain_id {
        return Err(rpc_bad(format!("RPC for chain {} reports chain {chain}", tx.chain_id)));
    }

    let gas = match p.estimate_gas(req).await {
        Ok(gas) => gas,
        // An error response from the node (not a transport failure) means the call reverts.
        Err(e) if e.as_error_resp().is_some() => {
            return Ok(Simulation { ok: false, gas: 0, revert: Some(e.to_string()) });
        }
        Err(e) => return Err(rpc_err(e)),
    };
    let nonce = p.get_transaction_count(from).pending().await.map_err(rpc_err)?;
    let gas_price = p.get_gas_price().await.map_err(rpc_err)?;
    let priority = p.get_max_priority_fee_per_gas().await.map_err(rpc_err)?;

    tx.nonce = nonce;
    tx.gas_limit = gas.saturating_mul(12) / 10; // 20% headroom
    tx.max_fee_per_gas = gas_price.saturating_mul(2).max(priority);
    tx.max_priority_fee_per_gas = priority.min(tx.max_fee_per_gas);
    Ok(Simulation { ok: true, gas, revert: None })
}

pub async fn broadcast(p: &RootProvider, raw: &Bytes) -> Result<B256, Refusal> {
    Ok(*p.send_raw_transaction(raw).await.map_err(rpc_err)?.tx_hash())
}

#[derive(Debug, Clone, Serialize)]
pub struct TxStatus {
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_number: Option<u64>,
}

pub async fn tx_status(p: &RootProvider, hash: B256) -> Result<TxStatus, Refusal> {
    // Raw JSON keeps this tolerant of chain-specific receipt fields.
    let receipt: Option<serde_json::Value> =
        p.raw_request("eth_getTransactionReceipt".into(), (hash,)).await.map_err(rpc_err)?;
    if let Some(r) = receipt {
        let block_number =
            r["blockNumber"].as_str().and_then(|b| u64::from_str_radix(b.trim_start_matches("0x"), 16).ok());
        let state = if r["status"] == "0x1" { "confirmed" } else { "failed" };
        return Ok(TxStatus { state, block_number });
    }
    let pending: Option<serde_json::Value> =
        p.raw_request("eth_getTransactionByHash".into(), (hash,)).await.map_err(rpc_err)?;
    Ok(TxStatus { state: if pending.is_some() { "pending" } else { "unknown" }, block_number: None })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rpc_url_never_reaches_the_bot() {
        // Nothing listens on port 9, so every call is a transport error.
        let chains = Chains::new(&[ChainConfig {
            id: 1,
            rpc_url: "http://127.0.0.1:9/v2/SECRET_API_KEY".into(),
            uniswap_v3: None,
        }])
        .expect("chains");
        let p = chains.get(1).expect("provider");
        let refusals = [
            balance(p, Address::ZERO, None).await.unwrap_err(),
            balance(p, Address::ZERO, Some(Address::ZERO)).await.unwrap_err(),
            token_decimals(p, Address::ZERO).await.unwrap_err(),
            broadcast(p, &Bytes::from_static(&[1])).await.unwrap_err(),
            tx_status(p, B256::ZERO).await.unwrap_err(),
        ];
        for r in refusals {
            assert_eq!(r.code, RefusalCode::RpcUnavailable);
            let text = serde_json::to_string(&r).expect("json");
            assert!(!text.contains("SECRET") && !text.contains("127.0.0.1"), "{text}");
        }
    }
}
