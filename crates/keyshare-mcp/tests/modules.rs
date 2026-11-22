//! A module that is switched off for a bot is not offered to that bot.

#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use http::Request;
use keyshare_mcp::auth::{Credentials, token_hash};
use keyshare_mcp::config::Config;
use keyshare_mcp::exec::{DEFAULT_HOLD_SECS, Executor};
use serde_json::{Value, json};
use tower::ServiceExt;

const TOKEN: &str = "module-test-token";
const KEY: &str = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";

async fn app() -> Router {
    let dir = tempfile::tempdir().unwrap();
    let toml = format!(
        r#"
        [server]
        listen = "127.0.0.1:0"
        state_dir = "{state}"

        [[chains]]
        id = 11155111
        rpc_url = "http://127.0.0.1:9"

        [bots.quiet]
        credential_sha256 = "{hash}"
        key_env = "QUIET_KEY"
        [bots.quiet.policy]
        chains = [11155111]
        per_tx_cap_usd = 1
        daily_cap_usd = 1

        [bots.quiet.modules]
        hyperliquid = false
        uniswap = false
        "#,
        state = dir.path().join("state").display(),
        hash = token_hash(TOKEN),
    );
    let path = dir.path().join("keyshare.toml");
    std::fs::write(&path, toml).unwrap();
    let config = Config::load(&path).unwrap();
    let env: HashMap<&str, &str> = [("QUIET_KEY", KEY)].into();
    let wallet = Arc::new(Mutex::new(config.wallet(|v| env.get(v).map(|s| (*s).to_string())).unwrap()));
    let creds: Credentials = Arc::new(config.credentials().unwrap());
    let chains = Arc::new(keyshare_mcp::chain::Chains::new(&config.chains).unwrap());
    let modules = config.bots.iter().map(|(bot, cfg)| (bot.clone(), cfg.modules.clone())).collect();
    let exec = Executor::new(wallet, chains, Arc::new(vec![]), DEFAULT_HOLD_SECS).with_modules(modules);
    // Leak the temp dir for the process: the app keeps paths into it.
    std::mem::forget(dir);
    keyshare_mcp::app(Arc::new(exec), creds, None, &[])
}

async fn rpc(app: &Router, token: &str, session: Option<&str>, body: Value) -> Value {
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
    let session_out = resp.headers().get("mcp-session-id").map(|v| v.to_str().unwrap().to_string());
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let text = String::from_utf8_lossy(&bytes).to_string();
    let mut json = text
        .lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .map(str::trim)
        .find(|d| !d.is_empty())
        .map(|d| serde_json::from_str(d).unwrap())
        .or_else(|| serde_json::from_str(&text).ok())
        .unwrap_or(Value::Null);
    if let Some(s) = session_out {
        json["_session"] = json!(s);
    }
    json
}

#[tokio::test]
async fn disabled_module_tools_are_not_offered() {
    let app = app().await;
    let init = json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}
    });
    let started = rpc(&app, TOKEN, None, init).await;
    let session = started["_session"].as_str().unwrap().to_string();
    let listed = rpc(&app, TOKEN, Some(&session), json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})).await;
    let names: Vec<&str> =
        listed["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    for hidden in ["hl_place_order", "hl_cancel", "hl_modify", "hl_positions", "hl_set_leverage", "swap"] {
        assert!(!names.contains(&hidden), "{hidden} is still listed: {names:?}");
    }
    for kept in ["address", "limits", "send", "sign_typed_data", "simulate"] {
        assert!(names.contains(&kept), "{kept} missing: {names:?}");
    }
    let call = rpc(
        &app,
        TOKEN,
        Some(&session),
        json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "hl_place_order", "arguments": {"coin": "ETH", "is_buy": true, "sz": "0.1", "limit_px": "1"}}
        }),
    )
    .await;
    let text = call.to_string();
    assert!(text.contains("tool not found"), "{call}");
}
