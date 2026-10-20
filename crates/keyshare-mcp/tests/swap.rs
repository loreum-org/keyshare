#![allow(clippy::unwrap_used)]

//! The `swap` tool against a mock chain with a Uniswap v3 quoter and router.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use alloy::consensus::{Transaction, TxEnvelope};
use alloy::eips::Decodable2718;
use alloy::primitives::{Address, Bytes, U256, address, keccak256};
use alloy::sol;
use alloy::sol_types::SolCall;
use axum::body::Body;
use axum::{Json, Router};
use http::Request;
use keyshare_core::{LocalSigner, Signer};
use keyshare_mcp::auth::{Credentials, token_hash};
use keyshare_mcp::config::Config;
use keyshare_mcp::exec::{DEFAULT_HOLD_SECS, Executor};
use serde_json::{Value, json};
use tower::ServiceExt;

sol! {
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
    function approve(address spender, uint256 amount);
}

const TOKEN: &str = "filltape-test-token";
const KEY: &str = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const OTHER_TOKEN: &str = "other-test-token";
const OTHER_KEY: &str = "0x8da4ef21b864d2cc526dbdb2a120bd2874c36c9d0a1fb7f8c63d7f7a8b41de8f";
const USDC: Address = address!("0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238");
const WETH: Address = address!("0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14");
const NOPE: Address = address!("0x4444444444444444444444444444444444444444");
const ROUTER: Address = address!("0x3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48E");
const QUOTER: Address = address!("0xEd1f6473345F45b75F8179591dd5bA1888cf2FB3");

#[derive(Default)]
struct ChainState {
    allowance: U256,
    sent: Vec<TxEnvelope>,
}

fn word(v: U256) -> Value {
    json!(format!("0x{v:064x}"))
}

/// Mock Sepolia: USDC has 6 decimals, the 0.3% pool quotes 2× the input, the 1% pool 1×, the
/// 0.05% pool and anything involving NOPE revert.
async fn mock_rpc(state: Arc<Mutex<ChainState>>) -> String {
    let handler = move |Json(req): Json<Value>| {
        let state = state.clone();
        async move {
            let p = &req["params"];
            let to: Address = p[0]["to"].as_str().map(|s| s.parse().unwrap()).unwrap_or_default();
            let input: Bytes =
                p[0]["input"].as_str().or(p[0]["data"].as_str()).map(|s| s.parse().unwrap()).unwrap_or_default();
            let revert =
                || json!({"jsonrpc": "2.0", "id": req["id"], "error": {"code": 3, "message": "execution reverted"}});
            let result = match req["method"].as_str().unwrap() {
                "eth_chainId" => json!("0xaa36a7"),
                "eth_estimateGas" => json!("0x30d40"),
                "eth_getTransactionCount" => json!(format!("{:#x}", state.lock().unwrap().sent.len())),
                "eth_gasPrice" => json!("0x3b9aca00"),
                "eth_maxPriorityFeePerGas" => json!("0x5f5e100"),
                "eth_call" if input.starts_with(&[0x31, 0x3c, 0xe5, 0x67]) => {
                    word(U256::from(if to == USDC { 6 } else { 18 }))
                }
                "eth_call" if input.starts_with(&[0xdd, 0x62, 0xed, 0x3e]) => word(state.lock().unwrap().allowance),
                "eth_call" if to == QUOTER => {
                    // (tokenIn, tokenOut, amountIn, fee, sqrtPriceLimitX96)
                    let w = |i: usize| U256::from_be_slice(&input[4 + 32 * i..4 + 32 * (i + 1)]);
                    let (token_in, token_out) = (Address::from_word(w(0).into()), Address::from_word(w(1).into()));
                    let (amount, fee) = (w(2), w(3).to::<u32>());
                    let out = match fee {
                        3000 => amount * U256::from(2),
                        10000 => amount,
                        _ => return Json(revert()),
                    };
                    if token_in == NOPE || token_out == NOPE {
                        return Json(revert());
                    }
                    json!(format!("0x{out:064x}{:0>192}", ""))
                }
                "eth_sendRawTransaction" => {
                    let raw: Bytes = serde_json::from_value(p[0].clone()).unwrap();
                    let tx = TxEnvelope::decode_2718(&mut raw.as_ref()).unwrap();
                    let mut s = state.lock().unwrap();
                    if let Ok(call) = approveCall::abi_decode(tx.input()) {
                        s.allowance = call.amount;
                    }
                    s.sent.push(tx);
                    json!(keccak256(&raw))
                }
                "eth_getTransactionReceipt" => json!({"status": "0x1", "blockNumber": "0x10"}),
                m => panic!("mock rpc: unexpected {m}"),
            };
            Json(json!({"jsonrpc": "2.0", "id": req["id"], "result": result}))
        }
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, Router::new().route("/", axum::routing::post(handler))).await });
    format!("http://{addr}/")
}

struct Fixture {
    app: Router,
    state: Arc<Mutex<ChainState>>,
    _dir: tempfile::TempDir,
}

async fn fixture() -> Fixture {
    let state = Arc::new(Mutex::new(ChainState::default()));
    let rpc_url = mock_rpc(state.clone()).await;
    let dir = tempfile::tempdir().unwrap();
    let toml = format!(
        r#"
        [server]
        listen = "127.0.0.1:0"
        state_dir = "{state_dir}"

        [[chains]]
        id = 11155111
        rpc_url = "{rpc_url}"
        [chains.uniswap_v3]
        router = "{ROUTER}"
        quoter = "{QUOTER}"
        weth = "{WETH}"

        [[prices]]
        chain_id = 11155111
        decimals = 18
        usd = "2500"

        [[prices]]
        chain_id = 11155111
        token = "{USDC}"
        decimals = 6
        usd = "1"

        [bots.filltape]
        credential_sha256 = "{hash}"
        key_env = "FILLTAPE_KEY"
        [bots.filltape.policy]
        chains = [11155111]
        per_tx_cap_usd = 200
        daily_cap_usd = 500
        max_slippage_bps = 50
        [[bots.filltape.policy.contracts_allow]]
        addr = "{USDC}"
        selectors = ["0x095ea7b3"]
        [[bots.filltape.policy.contracts_allow]]
        addr = "{ROUTER}"
        selectors = ["0x04e45aaf"]

        [bots.other]
        credential_sha256 = "{other_hash}"
        key_env = "OTHER_KEY"
        [bots.other.policy]
        chains = [11155111]
        per_tx_cap_usd = 200
        daily_cap_usd = 500
        "#,
        state_dir = dir.path().join("state").display(),
        hash = token_hash(TOKEN),
        other_hash = token_hash(OTHER_TOKEN),
    );
    let path = dir.path().join("keyshare.toml");
    std::fs::write(&path, toml).unwrap();
    let config = Config::load(&path).unwrap();
    let env: HashMap<&str, &str> = [("FILLTAPE_KEY", KEY), ("OTHER_KEY", OTHER_KEY)].into();
    let wallet = Arc::new(Mutex::new(config.wallet(|v| env.get(v).map(|s| s.to_string())).unwrap()));
    let creds: Credentials = Arc::new(config.credentials().unwrap());
    let chains = Arc::new(keyshare_mcp::chain::Chains::new(&config.chains).unwrap());
    let exec = Executor::new(wallet, chains, Arc::new(config.prices.clone()), DEFAULT_HOLD_SECS);
    let app = keyshare_mcp::app(Arc::new(exec), creds, None, &[]);
    Fixture { app, state, _dir: dir }
}

async fn rpc(app: &Router, token: &str, session: Option<&str>, body: Value) -> (Option<String>, Value) {
    let mut req = Request::post("/mcp")
        .header("host", "localhost")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2025-06-18")
        .header("authorization", format!("Bearer {token}"));
    if let Some(s) = session {
        req = req.header("mcp-session-id", s);
    }
    let resp = app.clone().oneshot(req.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    assert!(resp.status().is_success(), "{}", resp.status());
    let session = resp.headers().get("mcp-session-id").map(|v| v.to_str().unwrap().to_string());
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let text = String::from_utf8_lossy(&bytes).to_string();
    let json = text
        .lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .map(str::trim)
        .find(|d| !d.is_empty())
        .map(|d| serde_json::from_str(d).unwrap())
        .or_else(|| serde_json::from_str(&text).ok())
        .unwrap_or(Value::Null);
    (session, json)
}

async fn swap_as(app: &Router, token: &str, args: Value) -> Value {
    let init = json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}
    });
    let (session, _) = rpc(app, token, None, init).await;
    rpc(app, token, session.as_deref(), json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).await;
    let body =
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "swap", "arguments": args}});
    rpc(app, token, session.as_deref(), body).await.1["result"].clone()
}

async fn swap(app: &Router, args: Value) -> Value {
    swap_as(app, TOKEN, args).await
}

fn code(result: &Value) -> &str {
    assert_eq!(result["isError"], true, "{result}");
    result["structuredContent"]["code"].as_str().unwrap()
}

fn me() -> Address {
    LocalSigner::from_hex(KEY).unwrap().address()
}

#[tokio::test]
async fn erc20_swap_approves_exact_amount_then_swaps_to_self() {
    let f = fixture().await;
    let args =
        json!({"chain_id": 11155111, "sell_token": USDC, "buy_token": WETH, "amount": "100", "request_id": "s1"});
    let r = swap(&f.app, args).await;
    assert_eq!(r["isError"], false, "{r}");
    let out = &r["structuredContent"];
    assert_eq!(out["quote"]["fee"], 3000, "best of the quoted pools");
    assert_eq!(out["quote"]["slippage_bps"], 50, "defaults to the policy limit");
    assert_eq!(out["approve"]["outflow_usd"], "100.000000", "the approve counts against the caps");

    let sent = std::mem::take(&mut f.state.lock().unwrap().sent);
    assert_eq!(sent.len(), 2);
    let approve = approveCall::abi_decode(sent[0].input()).unwrap();
    assert_eq!((sent[0].to(), approve.spender, approve.amount), (Some(USDC), ROUTER, U256::from(100_000_000u64)));
    let call = exactInputSingleCall::abi_decode(sent[1].input()).unwrap().params;
    assert_eq!(sent[1].to(), Some(ROUTER));
    assert_eq!(sent[1].value(), U256::ZERO);
    assert_eq!((call.tokenIn, call.tokenOut, call.recipient), (USDC, WETH, me()));
    assert_eq!(call.amountIn, U256::from(100_000_000u64));
    // Quote is 2× the raw input; 0.5% below that.
    assert_eq!(call.amountOutMinimum, U256::from(199_000_000u64));

    // The allowance now covers the next swap of the same size, so no second approve.
    let args = json!({"chain_id": 11155111, "sell_token": USDC, "buy_token": WETH, "amount": "100"});
    assert_eq!(swap(&f.app, args).await["isError"], false);
    assert_eq!(f.state.lock().unwrap().sent.len(), 1);
}

#[tokio::test]
async fn native_swap_sends_value_through_weth() {
    let f = fixture().await;
    let args = json!({"chain_id": 11155111, "buy_token": USDC, "amount": "0.01", "max_slippage_bps": 10});
    let r = swap(&f.app, args).await;
    assert_eq!(r["isError"], false, "{r}");
    assert_eq!(r["structuredContent"]["outflow_usd"], "25.000000");
    let sent = std::mem::take(&mut f.state.lock().unwrap().sent);
    assert_eq!(sent.len(), 1);
    let call = exactInputSingleCall::abi_decode(sent[0].input()).unwrap().params;
    assert_eq!(sent[0].value(), U256::from(10_000_000_000_000_000u64));
    assert_eq!((call.tokenIn, call.tokenOut, call.recipient), (WETH, USDC, me()));
}

#[tokio::test]
async fn refusals() {
    let f = fixture().await;
    let base = json!({"chain_id": 11155111, "sell_token": USDC, "buy_token": WETH, "amount": "10"});
    let with = |k: &str, v: Value| {
        let mut a = base.clone();
        a[k] = v;
        a
    };
    assert_eq!(code(&swap(&f.app, with("max_slippage_bps", json!(51))).await), "SLIPPAGE_TOO_HIGH");
    assert_eq!(code(&swap(&f.app, with("buy_token", json!(NOPE))).await), "NO_ROUTE");
    assert_eq!(code(&swap(&f.app, with("buy_token", json!(USDC))).await), "BAD_ARGS");
    assert_eq!(code(&swap(&f.app, with("route_provider", json!("1inch"))).await), "NO_ROUTE");
    assert_eq!(code(&swap(&f.app, with("chain_id", json!(1))).await), "CHAIN_NOT_ALLOWED");
    let r = swap(&f.app, with("amount", json!("300"))).await;
    assert_eq!(code(&r), "PER_TX_CAP_EXCEEDED");
    assert_eq!(r["structuredContent"]["step"], "approve");
    // Router not on this bot's allowlist.
    let native = json!({"chain_id": 11155111, "buy_token": USDC, "amount": "0.01"});
    assert_eq!(code(&swap_as(&f.app, OTHER_TOKEN, native).await), "CONTRACT_NOT_ALLOWED");
    assert!(f.state.lock().unwrap().sent.is_empty());
}

#[tokio::test]
async fn dry_run_quotes_without_signing() {
    let f = fixture().await;
    let args = json!({"chain_id": 11155111, "sell_token": USDC, "buy_token": WETH, "amount": "10", "dry_run": true});
    let r = swap(&f.app, args).await;
    assert_eq!(r["isError"], false, "{r}");
    assert_eq!(r["structuredContent"]["quote"]["amount_out"], "0.000000000020000000");
    assert_eq!(r["structuredContent"]["approve"]["dry_run"], true);
    assert!(f.state.lock().unwrap().sent.is_empty());
}
