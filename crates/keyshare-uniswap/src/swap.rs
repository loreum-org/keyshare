//! The `swap` tool (design §7): exact-input swaps through Uniswap v3's SwapRouter02.
//!
//! The quote comes from QuoterV2 on the same RPC, the minimum out is that quote less the
//! slippage, and the output always goes back to the bot's own wallet. Both transactions (the
//! exact-amount approve, then the swap) are intents the core re-checks against this module's
//! allowlist and then against the bot's policy. This module does not sign.

use std::time::Duration;

use alloy::consensus::TxEip1559;
use alloy::primitives::utils::{format_units, parse_units};
use alloy::primitives::{Address, TxKind, U256, aliases::U24};
use alloy::sol;
use alloy::sol_types::SolCall;
use keyshare_core::{Refusal, RefusalCode};
use keyshare_module::{Core, Outcome, UniswapDeployment, unix_now};
use serde_json::{Value, json};

use crate::MODULE_ID;

sol! {
    struct QuoteExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint256 amountIn;
        uint24 fee;
        uint160 sqrtPriceLimitX96;
    }
    function quoteExactInputSingle(QuoteExactInputSingleParams params)
        returns (uint256 amountOut, uint160 sqrtPriceX96After, uint32 initializedTicksCrossed, uint256 gasEstimate);

    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }
    function exactInputSingle(ExactInputSingleParams params) payable returns (uint256 amountOut);

    function allowance(address owner, address spender) returns (uint256);
    function approve(address spender, uint256 amount);
}

/// How long to wait for the approve to confirm before giving up on the swap.
const APPROVE_WAIT_SECS: u64 = 90;

pub struct SwapRequest {
    pub chain_id: u64,
    /// `None` sells the native token (wrapped by the router).
    pub sell_token: Option<Address>,
    pub buy_token: Address,
    /// Whole tokens, e.g. "0.05".
    pub amount: String,
    pub max_slippage_bps: Option<u32>,
    pub route_provider: Option<String>,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Copy)]
struct Quote {
    fee: u32,
    amount_out: U256,
}

fn refusal(id: &str, r: &Refusal) -> Value {
    let mut v = json!(r);
    v["request_id"] = json!(id);
    v
}

fn bad_args(why: impl Into<String>) -> Refusal {
    Refusal::new(RefusalCode::BadArgs, why)
}

fn rpc_bad(why: impl std::fmt::Display) -> Refusal {
    Refusal::new(RefusalCode::RpcUnavailable, format!("rpc: {why}"))
}

async fn best_quote(
    core: &dyn Core,
    chain_id: u64,
    u: &UniswapDeployment,
    sell: Address,
    buy: Address,
    amount: U256,
) -> Option<Quote> {
    let mut best: Option<Quote> = None;
    for &fee in &u.fee_tiers {
        let call = quoteExactInputSingleCall {
            params: QuoteExactInputSingleParams {
                tokenIn: sell,
                tokenOut: buy,
                amountIn: amount,
                fee: U24::from(fee),
                sqrtPriceLimitX96: Default::default(),
            },
        };
        // A missing pool reverts; that tier is simply skipped.
        let Ok(out) = core.eth_call(chain_id, u.quoter, call.abi_encode().into()).await else { continue };
        let Ok(q) = quoteExactInputSingleCall::abi_decode_returns(&out) else { continue };
        if q.amountOut > U256::ZERO && best.is_none_or(|b| q.amountOut > b.amount_out) {
            best = Some(Quote { fee, amount_out: q.amountOut });
        }
    }
    best
}

async fn allowance_of(
    core: &dyn Core,
    chain_id: u64,
    token: Address,
    owner: Address,
    spender: Address,
) -> Result<U256, Refusal> {
    let data = allowanceCall { owner, spender }.abi_encode().into();
    let out = core.eth_call(chain_id, token, data).await?;
    allowanceCall::abi_decode_returns(&out).map_err(|e| rpc_bad(format!("allowance on {token}: {e}")))
}

async fn wait_confirmed(core: &dyn Core, chain_id: u64, hash: alloy::primitives::B256) -> Result<(), Refusal> {
    for _ in 0..APPROVE_WAIT_SECS {
        match core.tx_status(chain_id, hash).await?.state {
            "confirmed" => return Ok(()),
            "failed" => return Err(Refusal::new(RefusalCode::SimRevert, format!("approve {hash} failed on chain"))),
            _ => tokio::time::sleep(Duration::from_secs(1)).await,
        }
    }
    Err(Refusal::new(
        RefusalCode::RpcUnavailable,
        format!("approve {hash} not confirmed after {APPROVE_WAIT_SECS}s; call swap again once it is"),
    ))
}

/// Quotes, then (unless `dry_run`) approves the router for exactly `amount` if needed and swaps.
pub async fn swap(core: &dyn Core, caller: &str, id: &str, req: SwapRequest) -> Result<Outcome, String> {
    let prepared = prepare(core, caller, &req).await;
    let (u, owner, plan) = match prepared {
        Ok(x) => x,
        Err(r) => return Ok(Err(refusal(id, &r))),
    };
    let quote_json = json!({
        "route_provider": "uniswap_v3",
        "fee": plan.quote.fee,
        "amount_in": req.amount,
        "amount_out": format_units(plan.quote.amount_out, plan.buy_decimals).unwrap_or_default(),
        "min_amount_out": format_units(plan.min_out, plan.buy_decimals).unwrap_or_default(),
        "slippage_bps": plan.slippage_bps,
    });
    let with_quote = |mut out: Outcome| {
        match &mut out {
            Ok(v) | Err(v) => v["quote"] = quote_json.clone(),
        }
        out
    };

    let call = exactInputSingleCall {
        params: ExactInputSingleParams {
            tokenIn: plan.token_in,
            tokenOut: req.buy_token,
            fee: U24::from(plan.quote.fee),
            recipient: owner,
            amountIn: plan.amount_in,
            amountOutMinimum: plan.min_out,
            sqrtPriceLimitX96: Default::default(),
        },
    };
    let tx = TxEip1559 {
        chain_id: req.chain_id,
        to: TxKind::Call(u.router),
        value: if req.sell_token.is_none() { plan.amount_in } else { U256::ZERO },
        input: call.abi_encode().into(),
        ..Default::default()
    };

    // Check the swap itself before approving anything, so a swap the policy refuses never
    // leaves an approve behind. The core also checks the module allowlist.
    if let Err(r) = core.preview_module_tx(MODULE_ID, caller, &tx, unix_now()).await? {
        if !req.dry_run {
            let d = json!({ "swap": quote_json.clone() });
            let scoped = format!("{caller}:{id}");
            core.log_refusal(caller, &scoped, d, &r, unix_now()).await?;
        }
        return Ok(with_quote(Err(refusal(id, &r))));
    }

    // Approve the router for exactly this amount when the current allowance is short.
    let mut approve_out = None;
    if let Some(token) = req.sell_token {
        let current = match allowance_of(core, req.chain_id, token, owner, u.router).await {
            Ok(a) => a,
            Err(r) => return Ok(with_quote(Err(refusal(id, &r)))),
        };
        if current < plan.amount_in {
            let tx = TxEip1559 {
                chain_id: req.chain_id,
                to: TxKind::Call(token),
                input: approveCall { spender: u.router, amount: plan.amount_in }.abi_encode().into(),
                ..Default::default()
            };
            let approve_id = format!("{id}-approve");
            let out = core.submit_module_tx(MODULE_ID, caller, &approve_id, tx, req.dry_run).await?;
            let v = match out {
                Ok(v) => v,
                Err(mut v) => {
                    v["step"] = json!("approve");
                    v["request_id"] = json!(id);
                    return Ok(with_quote(Err(v)));
                }
            };
            if req.dry_run {
                // The swap can't be simulated until the approve lands.
                return Ok(with_quote(Ok(json!({
                    "request_id": id, "dry_run": true, "approve": v, "swap": "simulated after the approve confirms"
                }))));
            }
            if v["state"] == "pending_user_approval" {
                return Ok(with_quote(Ok(json!({
                    "request_id": id,
                    "state": "pending_user_approval",
                    "step": "approve",
                    "approve": v,
                    "next": "call swap again with a new request_id once the owner approves",
                }))));
            }
            if let Some(hash) = v["tx_hash"].as_str().and_then(|h| h.parse().ok())
                && let Err(r) = wait_confirmed(core, req.chain_id, hash).await
            {
                let mut out = refusal(id, &r);
                out["approve"] = v;
                return Ok(with_quote(Err(out)));
            }
            approve_out = Some(v);
        }
    }

    let mut out = core.submit_module_tx(MODULE_ID, caller, id, tx, req.dry_run).await?;
    if let (Some(a), Ok(v) | Err(v)) = (approve_out, &mut out) {
        v["approve"] = a;
    }
    Ok(with_quote(out))
}

struct Plan {
    token_in: Address,
    amount_in: U256,
    buy_decimals: u8,
    quote: Quote,
    min_out: U256,
    slippage_bps: u32,
}

async fn prepare(
    core: &dyn Core,
    caller: &str,
    req: &SwapRequest,
) -> Result<(UniswapDeployment, Address, Plan), Refusal> {
    if let Some(r) = &req.route_provider
        && r != "uniswap_v3"
    {
        return Err(Refusal::new(
            RefusalCode::NoRoute,
            format!("route provider {r:?} is not supported; use uniswap_v3"),
        ));
    }
    let u = core.uniswap(req.chain_id)?;
    let owner = core.address(caller).await.map_err(|e| Refusal::new(RefusalCode::Internal, e))??;
    let cap = core.max_slippage_bps(caller).await?;
    let slippage_bps = req.max_slippage_bps.unwrap_or(cap);
    if slippage_bps > cap {
        return Err(Refusal::new(
            RefusalCode::SlippageTooHigh,
            format!("{slippage_bps} bps is over this bot's {cap} bps limit"),
        ));
    }
    let token_in = req.sell_token.unwrap_or(u.weth);
    if token_in == req.buy_token {
        return Err(bad_args("sell and buy token are the same"));
    }
    let sell_decimals = match req.sell_token {
        None => 18,
        Some(t) => core.token_decimals(req.chain_id, t).await?,
    };
    let buy_decimals = core.token_decimals(req.chain_id, req.buy_token).await?;
    let amount_in: U256 =
        parse_units(&req.amount, sell_decimals).map_err(|e| bad_args(format!("amount {:?}: {e}", req.amount)))?.into();
    if amount_in.is_zero() {
        return Err(bad_args("amount must be above zero"));
    }
    let quote = best_quote(core, req.chain_id, &u, token_in, req.buy_token, amount_in)
        .await
        .ok_or_else(|| Refusal::new(RefusalCode::NoRoute, "no Uniswap v3 pool quotes this pair"))?;
    let keep = U256::from(10_000u32 - slippage_bps.min(10_000));
    let min_out = quote
        .amount_out
        .checked_mul(keep)
        .and_then(|v| v.checked_div(U256::from(10_000u32)))
        .ok_or_else(|| Refusal::new(RefusalCode::Internal, "quote is too large to apply slippage"))?;
    Ok((u, owner, Plan { token_in, amount_in, buy_decimals, quote, min_out, slippage_bps }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_match_deployed_contracts() {
        assert_eq!(exactInputSingleCall::SELECTOR, [0x04, 0xe4, 0x5a, 0xaf]);
        assert_eq!(quoteExactInputSingleCall::SELECTOR, [0xc6, 0xa5, 0x02, 0x6a]);
    }
}
