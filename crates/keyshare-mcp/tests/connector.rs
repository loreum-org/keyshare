#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use alloy::primitives::{Address, Signature};
use axum::Router;
use axum::body::Body;
use http::{Request, StatusCode};
use keyshare_core::Wallet;
use keyshare_mcp::auth::{Credentials, token_hash};
use keyshare_mcp::config::Config;
use serde_json::{Value, json};
use tower::ServiceExt;

const TOKEN: &str = "filltape-test-token";
const KEY: &str = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";

struct Fixture {
    app: Router,
    wallet: Arc<Mutex<Wallet>>,
    _dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let toml = format!(
        r#"
        [server]
        listen = "127.0.0.1:0"
        state_dir = "{state}"

        [bots.filltape]
        credential_sha256 = "{hash}"
        key_env = "FILLTAPE_KEY"
        [bots.filltape.policy]
        chains = [11155111]
        per_tx_cap_usd = 200
        daily_cap_usd = 500
        typed_data_allow = ["Order"]
        "#,
        state = dir.path().join("state").display(),
        hash = token_hash(TOKEN),
    );
    let path = dir.path().join("keyshare.toml");
    std::fs::write(&path, toml).unwrap();
    let config = Config::load(&path).unwrap();
    let env: HashMap<&str, &str> = [("FILLTAPE_KEY", KEY)].into();
    let wallet = Arc::new(Mutex::new(config.wallet(|v| env.get(v).map(|s| s.to_string())).unwrap()));
    let creds: Credentials = Arc::new(config.credentials().unwrap());
    Fixture { app: keyshare_mcp::app(wallet.clone(), creds, &[]), wallet, _dir: dir }
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

async fn session(app: &Router) -> Option<String> {
    let init = json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}
    });
    let (status, session, resp) = rpc(app, Some(TOKEN), None, init).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    let note = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
    rpc(app, Some(TOKEN), session.as_deref(), note).await;
    session
}

async fn call(app: &Router, session: Option<&str>, tool: &str, args: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": tool, "arguments": args}});
    let (status, _, resp) = rpc(app, Some(TOKEN), session, body).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    resp["result"].clone()
}

#[tokio::test]
async fn rejects_missing_or_unknown_credentials() {
    let f = fixture();
    let ping = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});
    assert_eq!(rpc(&f.app, None, None, ping.clone()).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(rpc(&f.app, Some("wrong"), None, ping).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn lists_tools() {
    let f = fixture();
    let s = session(&f.app).await;
    let body = json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"});
    let (_, _, resp) = rpc(&f.app, Some(TOKEN), s.as_deref(), body).await;
    let mut names: Vec<&str> =
        resp["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    names.sort();
    assert_eq!(names, ["address", "limits", "sign_message", "sign_typed_data"]);
}

#[tokio::test]
async fn signs_as_the_authenticated_bot() {
    let f = fixture();
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
    let f = fixture();
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
    let f = fixture();
    let s = session(&f.app).await;
    f.wallet.lock().unwrap().kill_switch().set(None, true).unwrap();
    let out = call(&f.app, s.as_deref(), "sign_message", json!({"message": "hi"})).await;
    assert_eq!(out["structuredContent"]["code"], "KILL_SWITCH");
    // Read tools still work.
    let out = call(&f.app, s.as_deref(), "limits", json!({})).await;
    assert_eq!(out["structuredContent"]["daily_cap_usd"], 500);
}
