#![allow(clippy::unwrap_used)]

//! Hyperliquid tools against a mock Hyperliquid API.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use alloy::primitives::Address;
use axum::body::Body;
use axum::{Json, Router};
use http::Request;
use keyshare_core::hyperliquid as hl;
use keyshare_core::killswitch::KillSwitch;
use keyshare_core::{LocalSigner, Signer};
use keyshare_mcp::auth::{Credentials, token_hash};
use keyshare_mcp::config::Config;
use keyshare_mcp::exec::{DEFAULT_HOLD_SECS, Executor};
use serde_json::{Value, json};
use tower::ServiceExt;

const TOKEN: &str = "filltape-test-token";
const KEY: &str = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const PLAIN_TOKEN: &str = "plain-test-token";
const PLAIN_KEY: &str = "0x8da4ef21b864d2cc526dbdb2a120bd2874c36c9d0a1fb7f8c63d7f7a8b41de8f";

/// What the mock exchange holds and what it was sent.
#[derive(Default)]
struct Venue {
    account_value: String,
    eth_szi: String,
    /// ETH mark price; BTC is fixed at 60,000.
    eth_mark: String,
    /// Current ETH and BTC leverage on the account.
    leverage: u64,
    open_orders: Vec<Value>,
    posted: Vec<Value>,
}

async fn mock_hl(venue: Arc<Mutex<Venue>>) -> String {
    let info = {
        let venue = venue.clone();
        move |Json(req): Json<Value>| {
            let venue = venue.clone();
            async move {
                let v = venue.lock().unwrap();
                Json(match req["type"].as_str().unwrap() {
                    "meta" => json!({"universe": [
                        {"name": "BTC", "szDecimals": 5},
                        {"name": "ETH", "szDecimals": 4},
                        {"name": "SOL", "szDecimals": 2}
                    ]}),
                    "clearinghouseState" => json!({
                        "marginSummary": {"accountValue": v.account_value},
                        "assetPositions": [{"position": {"coin": "ETH", "szi": v.eth_szi}}]
                    }),
                    "metaAndAssetCtxs" => json!([
                        {"universe": [{"name": "BTC"}, {"name": "ETH"}, {"name": "SOL"}]},
                        [{"markPx": "60000.0"}, {"markPx": v.eth_mark, "oraclePx": "1.0"}, {"oraclePx": "150.0"}]
                    ]),
                    "activeAssetData" => json!({"leverage": {"type": "cross", "value": v.leverage}}),
                    "openOrders" => json!(v.open_orders),
                    t => panic!("mock hl: unexpected info {t}"),
                })
            }
        }
    };
    let exchange = move |Json(req): Json<Value>| {
        let venue = venue.clone();
        async move {
            venue.lock().unwrap().posted.push(req);
            Json(json!({"status": "ok", "response": {"type": "default"}}))
        }
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route("/info", axum::routing::post(info)).route("/exchange", axum::routing::post(exchange));
    tokio::spawn(async move { axum::serve(listener, app).await });
    format!("http://{addr}")
}

struct Fixture {
    app: Router,
    config: Config,
    venue: Arc<Mutex<Venue>>,
    _dir: tempfile::TempDir,
}

fn env(var: &str) -> Option<String> {
    let env: HashMap<&str, &str> = [("FILLTAPE_KEY", KEY), ("PLAIN_KEY", PLAIN_KEY)].into();
    env.get(var).map(|s| s.to_string())
}

async fn fixture() -> Fixture {
    let venue = Arc::new(Mutex::new(Venue {
        account_value: "10000.0".into(),
        eth_szi: "0.0".into(),
        eth_mark: "2500.0".into(),
        leverage: 3,
        ..Default::default()
    }));
    let api = mock_hl(venue.clone()).await;
    let dir = tempfile::tempdir().unwrap();
    let toml = format!(
        r#"
        [server]
        listen = "127.0.0.1:0"
        state_dir = "{state}"

        [hyperliquid]
        api_url = "{api}"

        [bots.filltape]
        credential_sha256 = "{hash}"
        key_env = "FILLTAPE_KEY"
        [bots.filltape.policy]
        chains = []
        per_tx_cap_usd = 0
        daily_cap_usd = 0
        [bots.filltape.hyperliquid]
        markets = ["ETH", "BTC"]
        max_order_usd = 1000
        max_position_usd = 2000
        max_leverage = 5
        daily_loss_stop_usd = 100

        [bots.plain]
        credential_sha256 = "{plain_hash}"
        key_env = "PLAIN_KEY"
        [bots.plain.policy]
        chains = []
        per_tx_cap_usd = 0
        daily_cap_usd = 0
        "#,
        state = dir.path().join("state").display(),
        hash = token_hash(TOKEN),
        plain_hash = token_hash(PLAIN_TOKEN),
    );
    let path = dir.path().join("keyshare.toml");
    std::fs::write(&path, toml).unwrap();
    let config = Config::load(&path).unwrap();
    let wallet = Arc::new(Mutex::new(config.wallet(env).unwrap()));
    let creds: Credentials = Arc::new(config.credentials().unwrap());
    let chains = Arc::new(keyshare_mcp::chain::Chains::new(&config.chains).unwrap());
    let exec = Executor::new(wallet, chains, Arc::new(vec![]), DEFAULT_HOLD_SECS)
        .with_hyperliquid(config.hyperliquid().unwrap());
    let app = keyshare_mcp::app(Arc::new(exec), creds, None, &[]);
    Fixture { app, config, venue, _dir: dir }
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

async fn call_as(app: &Router, token: &str, tool: &str, args: Value) -> Value {
    let init = json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}
    });
    let (session, _) = rpc(app, token, None, init).await;
    rpc(app, token, session.as_deref(), json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).await;
    let body = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": tool, "arguments": args}});
    rpc(app, token, session.as_deref(), body).await.1["result"].clone()
}

async fn call(app: &Router, tool: &str, args: Value) -> Value {
    call_as(app, TOKEN, tool, args).await
}

fn code(result: &Value) -> &str {
    assert_eq!(result["isError"], true, "{result}");
    result["structuredContent"]["code"].as_str().unwrap()
}

fn buy(sz: &str, px: &str) -> Value {
    json!({"coin": "ETH", "is_buy": true, "sz": sz, "limit_px": px})
}

/// Approves an agent through the mock exchange and checks the master signed it.
async fn approve(f: &Fixture) -> Address {
    let file = keyshare_mcp::hl::approve_agent(&f.config, "filltape", 48, env).await.unwrap();
    let posted = f.venue.lock().unwrap().posted.pop().unwrap();
    assert_eq!(posted["action"]["type"], "approveAgent");
    assert_eq!(posted["action"]["hyperliquidChain"], "Testnet");
    assert!(posted["action"]["agentName"].as_str().unwrap().starts_with("keyshare-filltape valid_until "));
    let (_, data) = hl::approve_agent(
        file.address,
        posted["action"]["agentName"].as_str().unwrap(),
        posted["nonce"].as_u64().unwrap(),
        false,
    );
    let signer = recover(&data, &posted["signature"]);
    assert_eq!(signer, LocalSigner::from_hex(KEY).unwrap().address(), "master signs approveAgent");
    file.address
}

fn recover(data: &alloy::dyn_abi::TypedData, sig: &Value) -> Address {
    let r: alloy::primitives::U256 = sig["r"].as_str().unwrap().parse().unwrap();
    let s: alloy::primitives::U256 = sig["s"].as_str().unwrap().parse().unwrap();
    let sig = alloy::primitives::Signature::new(r, s, sig["v"].as_u64().unwrap() == 28);
    sig.recover_address_from_prehash(&data.eip712_signing_hash().unwrap()).unwrap()
}

#[tokio::test]
async fn approved_agent_signs_orders_within_guardrails() {
    let f = fixture().await;
    let agent = approve(&f).await;
    let state = f.config.server.state_dir.join("hyperliquid/filltape.agent.json");
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&state).unwrap().permissions().mode() & 0o777, 0o600);
    }

    let mut order = buy("0.25", "2500.50");
    order["cloid"] = json!("0x00000000000000000000000000000001");
    let r = call(&f.app, "hl_place_order", order).await;
    assert_eq!(r["isError"], false, "{r}");
    let posted = f.venue.lock().unwrap().posted.pop().unwrap();
    assert_eq!(
        posted["action"],
        json!({"type": "order", "orders": [{
            "a": 1, "b": true, "p": "2500.5", "s": "0.25", "r": false,
            "t": {"limit": {"tif": "Gtc"}}, "c": "0x00000000000000000000000000000001"
        }], "grouping": "na"})
    );
    // The agent signed exactly what was posted, for testnet.
    let action: hl::L1Action = hl::L1Action::order(vec![hl::OrderWire {
        a: 1,
        b: true,
        p: "2500.5".into(),
        s: "0.25".into(),
        r: false,
        t: hl::OrderTypeWire { limit: Some(hl::LimitWire { tif: hl::Tif::Gtc }), trigger: None },
        c: Some("0x00000000000000000000000000000001".into()),
    }]);
    let hash = hl::action_hash(&action, None, posted["nonce"].as_u64().unwrap(), None).unwrap();
    assert_eq!(recover(&hl::l1_typed_data(hash, false), &posted["signature"]), agent);

    // Cancel and leverage go out as their own actions.
    let r = call(&f.app, "hl_cancel", json!({"coin": "BTC", "oid": 42})).await;
    assert_eq!(r["isError"], false, "{r}");
    let r = call(&f.app, "hl_set_leverage", json!({"coin": "ETH", "leverage": 3})).await;
    assert_eq!(r["isError"], false, "{r}");
    let posted = std::mem::take(&mut f.venue.lock().unwrap().posted);
    assert_eq!(posted[0]["action"], json!({"type": "cancel", "cancels": [{"a": 0, "o": 42}]}));
    assert_eq!(posted[1]["action"], json!({"type": "updateLeverage", "asset": 1, "isCross": true, "leverage": 3}));
    assert!(posted[1]["nonce"].as_u64() > posted[0]["nonce"].as_u64());

    let r = call(&f.app, "hl_positions", json!({})).await;
    assert_eq!(r["structuredContent"]["state"]["marginSummary"]["accountValue"], "10000.0");
}

#[tokio::test]
async fn guardrails_refuse_before_signing() {
    let f = fixture().await;
    approve(&f).await;
    let cases = [
        (json!({"coin": "SOL", "is_buy": true, "sz": "1", "limit_px": "150"}), "MARKET_NOT_ALLOWED"),
        (json!({"coin": "DOGE", "is_buy": true, "sz": "1", "limit_px": "1"}), "MARKET_NOT_ALLOWED"),
        (buy("0.5", "2500"), "ORDER_TOO_LARGE"),
        (buy("0.12345", "2500"), "BAD_ARGS"),
        (buy("0.1", "1e3"), "BAD_ARGS"),
        (json!({"coin": "ETH", "is_buy": true, "sz": "0.1", "limit_px": "2500", "trigger_px": "2400"}), "BAD_ARGS"),
    ];
    for (order, want) in cases {
        let r = call(&f.app, "hl_place_order", order.clone()).await;
        assert_eq!(code(&r), want, "{order}");
    }
    // Existing short of 0.6 ETH: selling 0.3 more at 2500 makes a $2,250 position.
    f.venue.lock().unwrap().eth_szi = "-0.6".into();
    let sell = json!({"coin": "ETH", "is_buy": false, "sz": "0.3", "limit_px": "2500"});
    assert_eq!(code(&call(&f.app, "hl_place_order", sell).await), "POSITION_TOO_LARGE");
    let r = call(&f.app, "hl_set_leverage", json!({"coin": "ETH", "leverage": 10})).await;
    assert_eq!(code(&r), "LEVERAGE_TOO_HIGH");

    // A sell with a token limit is valued at the mark, not the limit: 0.5 ETH is $1,250.
    f.venue.lock().unwrap().eth_szi = "0.0".into();
    let lowball = json!({"coin": "ETH", "is_buy": false, "sz": "0.5", "limit_px": "1"});
    assert_eq!(code(&call(&f.app, "hl_place_order", lowball).await), "ORDER_TOO_LARGE");
    // Resting same-side orders count toward the position: 0.5 resting + 0.35 new = $2,125.
    f.venue.lock().unwrap().open_orders = vec![json!({"coin": "ETH", "side": "A", "sz": "0.5", "limitPx": "2600"})];
    let sell = json!({"coin": "ETH", "is_buy": false, "sz": "0.35", "limit_px": "2500"});
    assert_eq!(code(&call(&f.app, "hl_place_order", sell.clone()).await), "POSITION_TOO_LARGE");
    // The account's current leverage binds orders, not only hl_set_leverage.
    {
        let mut v = f.venue.lock().unwrap();
        v.open_orders.clear();
        v.leverage = 20;
    }
    assert_eq!(code(&call(&f.app, "hl_place_order", sell).await), "LEVERAGE_TOO_HIGH");
    assert!(f.venue.lock().unwrap().posted.is_empty());
}

#[test]
fn api_url_must_be_testnet() {
    use keyshare_mcp::hl::{HlConfig, check_api_url};
    let cfg = |u: &str| HlConfig { api_url: Some(u.into()) };
    assert!(check_api_url(None).is_ok());
    assert!(check_api_url(Some(&cfg("https://api.hyperliquid-testnet.xyz"))).is_ok());
    assert!(check_api_url(Some(&cfg("https://api.hyperliquid-testnet.xyz/info"))).is_ok());
    assert!(check_api_url(Some(&cfg("http://127.0.0.1:9999"))).is_ok());
    assert!(check_api_url(Some(&cfg("https://api.hyperliquid.xyz"))).is_err());
    // Userinfo must not disguise the mainnet host as loopback or testnet.
    assert!(check_api_url(Some(&cfg("https://127.0.0.1:x@api.hyperliquid.xyz"))).is_err());
    assert!(check_api_url(Some(&cfg("https://api.hyperliquid-testnet.xyz:443@api.hyperliquid.xyz"))).is_err());
    assert!(check_api_url(Some(&cfg("http://api.hyperliquid-testnet.xyz"))).is_err());
}

#[tokio::test]
async fn daily_loss_stop_allows_only_reduce_only() {
    let f = fixture().await;
    approve(&f).await;
    // The first look of the day records $10,000 as the starting value.
    assert_eq!(call(&f.app, "hl_positions", json!({})).await["isError"], false);
    f.venue.lock().unwrap().account_value = "9950".into();
    assert_eq!(call(&f.app, "hl_place_order", buy("0.1", "2500")).await["isError"], false);
    f.venue.lock().unwrap().account_value = "9899.99".into();
    assert_eq!(code(&call(&f.app, "hl_place_order", buy("0.1", "2500")).await), "DAILY_LOSS_STOP");
    let mut close = json!({"coin": "ETH", "is_buy": false, "sz": "5", "limit_px": "2400", "reduce_only": true});
    assert_eq!(call(&f.app, "hl_place_order", close.clone()).await["isError"], false);
    close["coin"] = json!("SOL");
    assert_eq!(code(&call(&f.app, "hl_place_order", close).await), "MARKET_NOT_ALLOWED");
}

#[tokio::test]
async fn no_agent_kill_switch_and_unconfigured_bot() {
    let f = fixture().await;
    assert_eq!(code(&call(&f.app, "hl_place_order", buy("0.1", "2500")).await), "NO_AGENT_KEY");

    approve(&f).await;
    // An expired agent is never used.
    let path = keyshare_mcp::hl::agent_path(&f.config.server.state_dir, "filltape");
    let mut file: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    file["valid_until_ms"] = json!(keyshare_mcp::hl::now_ms() + 1_000);
    std::fs::write(&path, file.to_string()).unwrap();
    assert_eq!(code(&call(&f.app, "hl_place_order", buy("0.1", "2500")).await), "NO_AGENT_KEY");

    approve(&f).await;
    KillSwitch::new(f.config.state_paths().kill_switch).set(Some("filltape"), true).unwrap();
    assert_eq!(code(&call(&f.app, "hl_place_order", buy("0.1", "2500")).await), "KILL_SWITCH");
    assert_eq!(code(&call(&f.app, "hl_cancel", json!({"coin": "ETH", "oid": 1})).await), "KILL_SWITCH");
    assert!(keyshare_mcp::hl::approve_agent(&f.config, "filltape", 48, env).await.is_err());

    let r = call_as(&f.app, PLAIN_TOKEN, "hl_place_order", buy("0.1", "2500")).await;
    assert_eq!(code(&r), "MARKET_NOT_ALLOWED");
    assert!(f.venue.lock().unwrap().posted.is_empty());
}

#[test]
fn example_config_parses() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../keyshare.example.toml");
    let config = Config::load(&path).unwrap();
    assert!(config.bots["filltape"].hyperliquid.is_some());
}
