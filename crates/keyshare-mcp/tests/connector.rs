#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use alloy::consensus::{SignableTransaction, TxEnvelope};
use alloy::eips::Decodable2718;
use alloy::primitives::{Address, Bytes, Signature, keccak256};
use axum::Router;
use axum::body::Body;
use http::{Request, StatusCode};
use keyshare_core::Wallet;
use keyshare_core::{LocalSigner, Signer};
use keyshare_mcp::auth::{Credentials, token_hash};
use keyshare_mcp::config::Config;
use keyshare_mcp::exec::{DEFAULT_HOLD_SECS, Executor};
use serde_json::{Value, json};
use tower::ServiceExt;

const TOKEN: &str = "filltape-test-token";
const KEY: &str = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
/// A second bot whose owner has an admin key, so waivable refusals are held.
const TRADER_TOKEN: &str = "trader-test-token";
const TRADER_KEY: &str = "0x8da4ef21b864d2cc526dbdb2a120bd2874c36c9d0a1fb7f8c63d7f7a8b41de8f";
const ADMIN_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const ADMIN_TOKEN: &str = "admin-test-token";
const USDC: &str = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";
const OWNER: &str = "0x1111111111111111111111111111111111111111";
const ATTACKER: &str = "0x2222222222222222222222222222222222222222";
const REVERTER: &str = "0x3333333333333333333333333333333333333333";

struct Fixture {
    app: Router,
    wallet: Arc<Mutex<Wallet>>,
    /// Raw transactions the mock chain received.
    sent: Arc<Mutex<Vec<Bytes>>>,
    _dir: tempfile::TempDir,
}

/// A minimal Sepolia JSON-RPC stand-in. Calls starting with 0xdeadbeef revert.
async fn mock_rpc(sent: Arc<Mutex<Vec<Bytes>>>) -> String {
    use axum::Json;
    let handler = move |Json(req): Json<Value>| {
        let sent = sent.clone();
        async move {
            let p = &req["params"];
            let input = p[0]["input"].as_str().or(p[0]["data"].as_str()).unwrap_or("0x").to_string();
            let word = |n: u64| format!("0x{n:064x}");
            let result = match req["method"].as_str().unwrap() {
                "eth_chainId" => json!("0xaa36a7"),
                "eth_estimateGas" if input.starts_with("0xdeadbeef") => {
                    return Json(
                        json!({"jsonrpc": "2.0", "id": req["id"], "error": {"code": 3, "message": "execution reverted: nope"}}),
                    );
                }
                "eth_estimateGas" => json!("0xea60"),
                "eth_getTransactionCount" => json!("0x7"),
                "eth_gasPrice" => json!("0x3b9aca00"),
                "eth_maxPriorityFeePerGas" => json!("0x5f5e100"),
                "eth_getBalance" => json!("0xde0b6b3a7640000"),
                "eth_call" if input.starts_with("0x313ce567") => json!(word(6)),
                "eth_call" if input.starts_with("0x70a08231") => json!(word(250_000_000)),
                "eth_sendRawTransaction" => {
                    let raw: Bytes = serde_json::from_value(p[0].clone()).unwrap();
                    let hash = keccak256(&raw);
                    sent.lock().unwrap().push(raw);
                    json!(hash)
                }
                "eth_getTransactionReceipt" => {
                    let known = sent.lock().unwrap().iter().any(|r| json!(keccak256(r)) == p[0]);
                    if known { json!({"status": "0x1", "blockNumber": "0x10"}) } else { Value::Null }
                }
                "eth_getTransactionByHash" => Value::Null,
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

async fn fixture() -> Fixture {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let rpc_url = mock_rpc(sent.clone()).await;
    let dir = tempfile::tempdir().unwrap();
    let toml = format!(
        r#"
        [server]
        listen = "127.0.0.1:0"
        state_dir = "{state}"
        admin_token_sha256 = "{admin_hash}"

        [[chains]]
        id = 11155111
        rpc_url = "{rpc_url}"

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
        recipients_allow = ["{OWNER}"]
        typed_data_allow = ["Order"]

        [[bots.filltape.policy.contracts_allow]]
        addr = "{USDC}"
        selectors = ["0xa9059cbb"]

        [[bots.filltape.policy.contracts_allow]]
        addr = "{REVERTER}"
        selectors = ["0xdeadbeef"]

        [bots.trader]
        credential_sha256 = "{trader_hash}"
        key_env = "TRADER_KEY"
        admin_keys = ["{admin}"]
        [bots.trader.policy]
        chains = [11155111]
        per_tx_cap_usd = 200
        daily_cap_usd = 500
        recipients_allow = ["{OWNER}"]
        "#,
        state = dir.path().join("state").display(),
        hash = token_hash(TOKEN),
        trader_hash = token_hash(TRADER_TOKEN),
        admin_hash = token_hash(ADMIN_TOKEN),
        admin = admin().address(),
    );
    let path = dir.path().join("keyshare.toml");
    std::fs::write(&path, toml).unwrap();
    let config = Config::load(&path).unwrap();
    let env: HashMap<&str, &str> = [("FILLTAPE_KEY", KEY), ("TRADER_KEY", TRADER_KEY)].into();
    let wallet = Arc::new(Mutex::new(config.wallet(|v| env.get(v).map(|s| s.to_string())).unwrap()));
    let creds: Credentials = Arc::new(config.credentials().unwrap());
    let chains = Arc::new(keyshare_mcp::chain::Chains::new(&config.chains).unwrap());
    let tokens = Arc::new(config.prices.clone());
    let exec = Arc::new(Executor::new(wallet.clone(), chains, tokens, DEFAULT_HOLD_SECS));
    let app = keyshare_mcp::app(exec, creds, Some(token_hash(ADMIN_TOKEN)), &[]);
    Fixture { app, wallet, sent, _dir: dir }
}

/// Sends one JSON-RPC request and returns the JSON-RPC response (SSE or plain JSON body).
async fn rpc(
    app: &Router,
    token: Option<&str>,
    session: Option<&str>,
    body: Value,
) -> (StatusCode, Option<String>, Value) {
    let mut req = Request::post("/mcp")
        .header("host", "localhost")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2025-06-18");
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    if let Some(s) = session {
        req = req.header("mcp-session-id", s);
    }
    let resp = app.clone().oneshot(req.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let status = resp.status();
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
    (status, session, json)
}

fn admin() -> LocalSigner {
    LocalSigner::from_hex(ADMIN_KEY).unwrap()
}

async fn session(app: &Router) -> Option<String> {
    session_as(app, TOKEN).await
}

async fn session_as(app: &Router, token: &str) -> Option<String> {
    let init = json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}
    });
    let (status, session, resp) = rpc(app, Some(token), None, init).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let note = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
    rpc(app, Some(token), session.as_deref(), note).await;
    session
}

async fn call(app: &Router, session: Option<&str>, tool: &str, args: Value) -> Value {
    call_as(app, TOKEN, session, tool, args).await
}

async fn call_as(app: &Router, token: &str, session: Option<&str>, tool: &str, args: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": tool, "arguments": args}});
    let (status, _, resp) = rpc(app, Some(token), session, body).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    resp["result"].clone()
}

#[tokio::test]
async fn rejects_missing_or_unknown_credentials() {
    let f = fixture().await;
    let ping = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});
    assert_eq!(rpc(&f.app, None, None, ping.clone()).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(rpc(&f.app, Some("wrong"), None, ping).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn lists_tools() {
    let f = fixture().await;
    let s = session(&f.app).await;
    let body = json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"});
    let (_, _, resp) = rpc(&f.app, Some(TOKEN), s.as_deref(), body).await;
    let mut names: Vec<&str> =
        resp["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    names.sort();
    assert_eq!(
        names,
        [
            "address",
            "balances",
            "call_contract",
            "hl_cancel",
            "hl_modify",
            "hl_place_order",
            "hl_positions",
            "hl_set_leverage",
            "limits",
            "send",
            "sign_message",
            "sign_typed_data",
            "simulate",
            "swap",
            "tx_status"
        ]
    );
}

#[tokio::test]
async fn signs_as_the_authenticated_bot() {
    let f = fixture().await;
    let s = session(&f.app).await;
    let addr: Address = serde_json::from_value(
        call(&f.app, s.as_deref(), "address", json!({})).await["structuredContent"]["address"].clone(),
    )
    .unwrap();
    assert_eq!(addr, f.wallet.lock().unwrap().address("filltape").unwrap());

    let out = call(&f.app, s.as_deref(), "sign_message", json!({"message": "hello keyshare"})).await;
    assert_ne!(out["isError"], json!(true), "{out}");
    let sig: Signature = serde_json::from_value(out["structuredContent"]["signature"].clone()).unwrap();
    assert_eq!(sig.recover_address_from_msg("hello keyshare").unwrap(), addr);
}

#[tokio::test]
async fn refusals_carry_a_code() {
    let f = fixture().await;
    let s = session(&f.app).await;
    let out = call(&f.app, s.as_deref(), "sign_message", json!({"message": "0xdeadbeef", "request_id": "r1"})).await;
    assert_eq!(out["isError"], json!(true));
    assert_eq!(out["structuredContent"]["code"], "MESSAGE_LOOKS_LIKE_TX");
    assert_eq!(out["structuredContent"]["request_id"], "r1");

    let permit = json!({
        "types": {"EIP712Domain": [], "Permit": [{"name": "value", "type": "uint256"}]},
        "primaryType": "Permit", "domain": {}, "message": {"value": "1"}
    });
    let out = call(&f.app, s.as_deref(), "sign_typed_data", json!({"typed_data": permit})).await;
    assert_eq!(out["structuredContent"]["code"], "TYPED_DATA_NOT_ALLOWED");
}

#[tokio::test]
async fn kill_switch_halts_signing() {
    let f = fixture().await;
    let s = session(&f.app).await;
    f.wallet.lock().unwrap().kill_switch().set(None, true).unwrap();
    let out = call(&f.app, s.as_deref(), "sign_message", json!({"message": "hi"})).await;
    assert_eq!(out["structuredContent"]["code"], "KILL_SWITCH");
    // Read tools still work.
    let out = call(&f.app, s.as_deref(), "limits", json!({})).await;
    assert_eq!(out["structuredContent"]["daily_cap_usd"], 500);
}

fn code(out: &Value) -> &str {
    out["structuredContent"]["code"].as_str().unwrap_or("")
}

#[tokio::test]
async fn sends_usdc_end_to_end() {
    let f = fixture().await;
    let s = session(&f.app).await;
    let args = json!({"chain_id": 11155111, "to": OWNER, "token": USDC, "amount": "150"});
    let out = call(&f.app, s.as_deref(), "send", args).await;
    assert_ne!(out["isError"], json!(true), "{out}");
    assert_eq!(out["structuredContent"]["outflow_usd"], "150.000000");

    let raw = f.sent.lock().unwrap()[0].clone();
    let envelope = TxEnvelope::decode_2718(&mut raw.as_ref()).unwrap();
    let signed = envelope.as_eip1559().unwrap();
    let tx = signed.tx();
    assert_eq!(tx.nonce, 7);
    assert_eq!(tx.chain_id, 11155111);
    assert_eq!(tx.gas_limit, 72_000);
    assert_eq!(tx.to.to().unwrap().to_string(), USDC);
    let bot = f.wallet.lock().unwrap().address("filltape").unwrap();
    assert_eq!(signed.signature().recover_address_from_prehash(&tx.signature_hash()).unwrap(), bot);

    let hash = out["structuredContent"]["tx_hash"].clone();
    let status = call(&f.app, s.as_deref(), "tx_status", json!({"chain_id": 11155111, "tx_hash": hash})).await;
    assert_eq!(status["structuredContent"]["state"], "confirmed");
}

#[tokio::test]
async fn prompt_injected_send_is_refused_before_any_rpc() {
    let f = fixture().await;
    let s = session(&f.app).await;
    let args = json!({"chain_id": 11155111, "to": ATTACKER, "amount": "0.01"});
    let out = call(&f.app, s.as_deref(), "send", args).await;
    assert_eq!(code(&out), "RECIPIENT_NOT_ALLOWED");
    assert!(f.sent.lock().unwrap().is_empty());
    // The refusal is in the audit log.
    let audit = std::fs::read_to_string(f._dir.path().join("state/audit.jsonl")).unwrap();
    assert!(audit.contains("RECIPIENT_NOT_ALLOWED"));
}

#[tokio::test]
async fn caps_hold_across_sends() {
    let f = fixture().await;
    let s = session(&f.app).await;
    let over = json!({"chain_id": 11155111, "to": OWNER, "token": USDC, "amount": "200.01"});
    assert_eq!(code(&call(&f.app, s.as_deref(), "send", over).await), "PER_TX_CAP_EXCEEDED");
    for _ in 0..2 {
        let ok = json!({"chain_id": 11155111, "to": OWNER, "token": USDC, "amount": "200"});
        assert_ne!(call(&f.app, s.as_deref(), "send", ok).await["isError"], json!(true));
    }
    let last = json!({"chain_id": 11155111, "to": OWNER, "token": USDC, "amount": "101"});
    assert_eq!(code(&call(&f.app, s.as_deref(), "send", last).await), "CAP_EXCEEDED");
    assert_eq!(f.sent.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn dry_run_signs_nothing() {
    let f = fixture().await;
    let s = session(&f.app).await;
    let args = json!({"chain_id": 11155111, "to": OWNER, "amount": "0.01", "dry_run": true});
    let out = call(&f.app, s.as_deref(), "send", args).await;
    assert_eq!(out["structuredContent"]["policy_verdict"], "allowed", "{out}");
    assert_eq!(out["structuredContent"]["simulation"]["ok"], true);
    assert!(f.sent.lock().unwrap().is_empty());
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    assert_eq!(f.wallet.lock().unwrap().spent_24h("filltape", now), 0);
}

#[tokio::test]
async fn reverting_call_is_refused() {
    let f = fixture().await;
    let s = session(&f.app).await;
    let args = json!({"chain_id": 11155111, "to": REVERTER, "data": "0xdeadbeef"});
    let out = call(&f.app, s.as_deref(), "call_contract", args).await;
    assert_eq!(code(&out), "SIM_REVERT", "{out}");
    assert!(f.sent.lock().unwrap().is_empty());
}

#[tokio::test]
async fn balances_include_priced_tokens() {
    let f = fixture().await;
    let s = session(&f.app).await;
    let out = call(&f.app, s.as_deref(), "balances", json!({})).await;
    let rows = out["structuredContent"]["balances"].as_array().unwrap().clone();
    assert_eq!(rows[0]["amount"], "1.000000000000000000");
    assert_eq!(rows[0]["usd"], "2500.000000");
    assert_eq!(rows[1]["amount"], "250.000000");
    assert_eq!(rows[1]["usd"], "250.000000");
}

#[tokio::test]
async fn unconfigured_chain_is_refused() {
    let f = fixture().await;
    let s = session(&f.app).await;
    let out = call(&f.app, s.as_deref(), "send", json!({"chain_id": 1, "to": OWNER, "amount": "1"})).await;
    assert_eq!(code(&out), "CHAIN_NOT_ALLOWED");
}

async fn admin_http(
    app: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(path).header("content-type", "application/json");
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let body = body.map_or(Body::empty(), |b| Body::from(b.to_string()));
    let resp = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// Holds an over-allowlist send from `trader` and returns its request id and the pending entry.
async fn hold_one(f: &Fixture, s: Option<&str>) -> (String, Value) {
    let args = json!({"chain_id": 11155111, "to": ATTACKER, "amount": "0.01", "request_id": "held-1"});
    let out = call_as(&f.app, TRADER_TOKEN, s, "send", args).await;
    assert_eq!(out["structuredContent"]["state"], "pending_user_approval", "{out}");
    assert_eq!(out["structuredContent"]["reason"]["code"], "RECIPIENT_NOT_ALLOWED");
    let (status, list) = admin_http(&f.app, "GET", "/admin/pending", Some(ADMIN_TOKEN), None).await;
    assert_eq!(status, StatusCode::OK);
    (out["structuredContent"]["request_id"].as_str().unwrap().to_string(), list["pending"][0].clone())
}

#[tokio::test]
async fn owner_approves_a_held_send() {
    let f = fixture().await;
    let s = session_as(&f.app, TRADER_TOKEN).await;
    let (id, pending) = hold_one(&f, s.as_deref()).await;
    assert!(f.sent.lock().unwrap().is_empty());
    let st =
        call_as(&f.app, TRADER_TOKEN, s.as_deref(), "tx_status", json!({"chain_id": 11155111, "request_id": id})).await;
    assert_eq!(st["structuredContent"]["state"], "pending_user_approval");

    let sig = admin().sign_message(pending["approve_message"].as_str().unwrap().as_bytes()).unwrap();
    let body = json!({"bot": "trader", "request_id": id, "decision": "approve", "signature": sig});
    let (status, out) = admin_http(&f.app, "POST", "/admin/decide", None, Some(body.clone())).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(out["approved_by"], json!(admin().address()));
    assert_eq!(f.sent.lock().unwrap().len(), 1);

    let st =
        call_as(&f.app, TRADER_TOKEN, s.as_deref(), "tx_status", json!({"chain_id": 11155111, "request_id": id})).await;
    assert_eq!(st["structuredContent"]["state"], "confirmed");
    // The approval can't be used twice.
    let (status, out) = admin_http(&f.app, "POST", "/admin/decide", None, Some(body)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(out["code"], "BAD_APPROVAL");
    assert_eq!(f.sent.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn owner_denies_a_held_send() {
    let f = fixture().await;
    let s = session_as(&f.app, TRADER_TOKEN).await;
    let (id, pending) = hold_one(&f, s.as_deref()).await;
    let sig = admin().sign_message(pending["deny_message"].as_str().unwrap().as_bytes()).unwrap();
    let body = json!({"bot": "trader", "request_id": id, "decision": "deny", "signature": sig});
    let (_, out) = admin_http(&f.app, "POST", "/admin/decide", None, Some(body)).await;
    assert_eq!(out["code"], "USER_DENIED");
    let st =
        call_as(&f.app, TRADER_TOKEN, s.as_deref(), "tx_status", json!({"chain_id": 11155111, "request_id": id})).await;
    assert_eq!(st["structuredContent"]["state"], "refused");
    assert!(f.sent.lock().unwrap().is_empty());
}

#[tokio::test]
async fn only_the_owner_can_decide() {
    let f = fixture().await;
    let s = session_as(&f.app, TRADER_TOKEN).await;
    let (id, pending) = hold_one(&f, s.as_deref()).await;
    let msg = pending["approve_message"].as_str().unwrap().as_bytes().to_vec();

    // A stranger's key, or the owner's signature on a deny used as an approve, is refused.
    let stranger = LocalSigner::random().sign_message(&msg).unwrap();
    let deny_sig = admin().sign_message(pending["deny_message"].as_str().unwrap().as_bytes()).unwrap();
    for sig in [stranger, deny_sig] {
        let body = json!({"bot": "trader", "request_id": id, "decision": "approve", "signature": sig});
        let (status, out) = admin_http(&f.app, "POST", "/admin/decide", None, Some(body)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(out["code"], "BAD_APPROVAL");
    }
    assert!(f.sent.lock().unwrap().is_empty());

    // Listing needs the admin token; bot tokens don't work.
    assert_eq!(admin_http(&f.app, "GET", "/admin/pending", None, None).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(admin_http(&f.app, "GET", "/admin/pending", Some(TRADER_TOKEN), None).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn hard_rules_are_never_held() {
    let f = fixture().await;
    let s = session_as(&f.app, TRADER_TOKEN).await;
    let out = call_as(
        &f.app,
        TRADER_TOKEN,
        s.as_deref(),
        "send",
        json!({"chain_id": 11155111, "to": OWNER, "amount": "1", "dry_run": false}),
    )
    .await;
    // 1 ETH = $2500 is over the cap: held, not refused.
    assert_eq!(out["structuredContent"]["state"], "pending_user_approval");
    f.wallet.lock().unwrap().kill_switch().set(None, true).unwrap();
    let out =
        call_as(&f.app, TRADER_TOKEN, s.as_deref(), "send", json!({"chain_id": 11155111, "to": OWNER, "amount": "1"}))
            .await;
    assert_eq!(code(&out), "KILL_SWITCH");
}
