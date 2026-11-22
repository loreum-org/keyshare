#![allow(clippy::unwrap_used)]

//! Hyperliquid tools against a mock Hyperliquid API.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use alloy::primitives::Address;
use axum::body::Body;
use axum::{Json, Router};
use http::Request;
use keyshare_core::killswitch::KillSwitch;
use keyshare_core::{LocalSigner, Signer};
use keyshare_hyperliquid as hl;
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
    /// ETH unrealized PnL. `None` omits the field.
    eth_pnl: Option<String>,
    /// Perp `withdrawable`. `None` omits the field.
    withdrawable: Option<String>,
    /// Include `assetPositions`. A missing array is a failed read.
    include_positions: bool,
    /// `userAbstraction` response. A JSON string such as `"default"`.
    abstraction: Value,
    /// `spotClearinghouseState` response.
    spot: Value,
    /// Info request types, in order.
    seen: Vec<String>,
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
                let mut v = venue.lock().unwrap();
                let kind = req["type"].as_str().unwrap().to_string();
                v.seen.push(kind.clone());
                Json(match kind.as_str() {
                    "meta" => json!({"universe": [
                        {"name": "BTC", "szDecimals": 5},
                        {"name": "ETH", "szDecimals": 4},
                        {"name": "SOL", "szDecimals": 2}
                    ]}),
                    "clearinghouseState" => {
                        let mut position = json!({"coin": "ETH", "szi": v.eth_szi});
                        if let Some(pnl) = &v.eth_pnl {
                            position["unrealizedPnl"] = json!(pnl);
                        }
                        let mut state = json!({
                            "marginSummary": {"accountValue": v.account_value},
                            "crossMarginSummary": {"accountValue": v.account_value},
                            "withdrawable": "0.0",
                        });
                        if v.include_positions {
                            state["assetPositions"] = json!([{"position": position}]);
                        }
                        if let Some(w) = &v.withdrawable {
                            state["withdrawable"] = json!(w);
                        } else {
                            state.as_object_mut().unwrap().remove("withdrawable");
                        }
                        state
                    }
                    "userAbstraction" => v.abstraction.clone(),
                    "spotClearinghouseState" => v.spot.clone(),
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

fn write_config(dir: &std::path::Path, state: &std::path::Path, api: &str, hl_extra: &str) -> Config {
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
        {hl_extra}

        [bots.plain]
        credential_sha256 = "{plain_hash}"
        key_env = "PLAIN_KEY"
        [bots.plain.policy]
        chains = []
        per_tx_cap_usd = 0
        daily_cap_usd = 0
        "#,
        state = state.display(),
        hash = token_hash(TOKEN),
        plain_hash = token_hash(PLAIN_TOKEN),
    );
    let path = dir.join("keyshare.toml");
    std::fs::write(&path, toml).unwrap();
    Config::load(&path).unwrap()
}

fn serve(config: &Config) -> Router {
    let wallet = Arc::new(Mutex::new(config.wallet(env).unwrap()));
    let creds: Credentials = Arc::new(config.credentials().unwrap());
    let chains = Arc::new(keyshare_mcp::chain::Chains::new(&config.chains).unwrap());
    let exec = Executor::new(wallet, chains, Arc::new(vec![]), DEFAULT_HOLD_SECS)
        .with_hyperliquid(config.hyperliquid().unwrap());
    keyshare_mcp::app(Arc::new(exec), creds, None, &[])
}

async fn fixture() -> Fixture {
    fixture_with("").await
}

async fn fixture_with(hl_extra: &str) -> Fixture {
    let venue = Arc::new(Mutex::new(Venue {
        account_value: "10000.0".into(),
        eth_szi: "0.0".into(),
        include_positions: true,
        abstraction: json!("default"),
        eth_mark: "2500.0".into(),
        leverage: 3,
        ..Default::default()
    }));
    let api = mock_hl(venue.clone()).await;
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), &dir.path().join("state"), &api, hl_extra);
    let app = serve(&config);
    Fixture { app, config, venue, _dir: dir }
}

fn restart(f: &Fixture) -> Router {
    serve(&f.config)
}

/// A new process: same state directory and mock, with a different floor config.
fn reload(f: &Fixture, hl_extra: &str) -> Router {
    let api = f.config.hyperliquid.as_ref().unwrap().api_url.clone().unwrap();
    let config = write_config(f._dir.path(), &f.config.server.state_dir, &api, hl_extra);
    serve(&config)
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
    assert_eq!(r["structuredContent"]["account"]["equity"], "10000.0");
    assert_eq!(r["structuredContent"]["account"]["abstraction"], "default");
    assert_eq!(r["structuredContent"]["account"]["equity_source"], "perp_account_value");
    assert!(r["structuredContent"]["account"].get("available_margin").is_none());
    // No equity floor is configured, so the account is not latched and no mark is written.
    assert_eq!(r["structuredContent"]["account"]["breached"], false);
    assert!(r["structuredContent"]["account"]["floor"].is_null());
    assert!(r["structuredContent"]["account"]["peak_equity"].is_null());
    let limits = call(&f.app, "limits", json!({})).await;
    assert_eq!(limits["structuredContent"]["hyperliquid"]["breached"], false);
    assert!(limits["structuredContent"]["hyperliquid"]["floor"].is_null());
    assert!(limits["structuredContent"]["hyperliquid"]["equity"].is_null());

    // A request id is spent once the agent signs, so a retry cannot place a second order.
    let mut once = buy("0.1", "2500");
    once["request_id"] = json!("hl-once");
    assert_eq!(call(&f.app, "hl_place_order", once.clone()).await["isError"], false);
    let n = f.venue.lock().unwrap().posted.len();
    assert_eq!(code(&call(&f.app, "hl_place_order", once).await), "NONCE_REUSED");
    assert_eq!(f.venue.lock().unwrap().posted.len(), n);
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

fn today() -> u64 {
    keyshare_mcp::hl::now_ms() / 86_400_000
}

fn day_file(f: &Fixture) -> std::path::PathBuf {
    f.config.server.state_dir.join("hyperliquid/filltape.day.json")
}

fn write_day(f: &Fixture, value: &str) {
    let path = day_file(f);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, json!({"day": today(), "account_value": value}).to_string()).unwrap();
}

fn saved_day(f: &Fixture) -> Value {
    serde_json::from_slice(&std::fs::read(day_file(f)).unwrap()).unwrap()
}

/// Spot USDC only. Perp account value stays 0, which is what a unified account reports.
fn unified(v: &mut Venue, total: &str, hold: &str, available: &str) {
    v.abstraction = json!("unifiedAccount");
    v.account_value = "0.0".into();
    v.eth_szi = "0.0".into();
    v.eth_pnl = None;
    v.spot = json!({
        "balances": [{"coin": "USDC", "token": 0, "total": total, "hold": hold, "entryNtl": "0.0"}],
        "tokenToAvailableAfterMaintenance": [[0, available]],
    });
}

#[tokio::test]
async fn standard_account_does_not_treat_zero_equity_as_a_stop() {
    let f = fixture().await;
    approve(&f).await;
    // The old claim was that new risk is refused at zero equity. It is not:
    // size caps still apply, and a zero baseline makes the loss today zero.
    f.venue.lock().unwrap().account_value = "0".into();
    assert_eq!(call(&f.app, "hl_place_order", buy("0.1", "2500")).await["isError"], false);
    assert_eq!(saved_day(&f)["account_value"], "0");
    assert_eq!(saved_day(&f)["basis"], "perp_account_value");
    // A later deposit does not rewrite that real zero, and it does not trip the stop.
    f.venue.lock().unwrap().account_value = "10000.0".into();
    assert_eq!(call(&f.app, "hl_place_order", buy("0.1", "2500")).await["isError"], false);
    assert_eq!(saved_day(&f)["account_value"], "0");
    // Spot USDC on a standard account is not equity, and the spot endpoint is not read.
    {
        let mut v = f.venue.lock().unwrap();
        v.seen.clear();
        v.withdrawable = Some("8000".into());
        v.spot = json!({
            "balances": [{"coin": "USDC", "token": 0, "total": "999.0", "hold": "0.0", "entryNtl": "0.0"}],
            "tokenToAvailableAfterMaintenance": [[0, "999.0"]],
        });
    }
    let r = call(&f.app, "hl_positions", json!({})).await;
    assert_eq!(r["structuredContent"]["account"]["equity"], "10000.0");
    assert_eq!(r["structuredContent"]["account"]["available_margin"], "8000");
    assert_eq!(r["structuredContent"]["account"]["available_source"], "withdrawable");
    let seen = f.venue.lock().unwrap().seen.clone();
    assert!(seen.iter().any(|t| t == "userAbstraction"));
    assert!(seen.iter().all(|t| t != "spotClearinghouseState"), "{seen:?}");
}

#[tokio::test]
async fn unified_usdc_equity_and_loss_baseline() {
    let f = fixture().await;
    approve(&f).await;
    // A previous read stored the meaningless perp zero. The account is flat, so that
    // baseline is replaced with the USDC balance and is not left to mask later losses.
    write_day(&f, "0");
    {
        let mut v = f.venue.lock().unwrap();
        unified(&mut v, "999.0", "0.0", "999.0");
    }
    let r = call(&f.app, "hl_positions", json!({})).await;
    assert_eq!(r["isError"], false, "{r}");
    let account = &r["structuredContent"]["account"];
    assert_eq!(account["abstraction"], "unifiedAccount");
    assert_eq!(account["equity"], "999.0");
    assert_eq!(account["usdc_total"], "999.0");
    assert_eq!(account["unrealized_pnl"], "0");
    assert_eq!(account["available_margin"], "999.0");
    assert_eq!(account["available_source"], "token_to_available_after_maintenance");
    assert_eq!(r["structuredContent"]["state"]["marginSummary"]["accountValue"], "0.0");
    assert_eq!(saved_day(&f)["account_value"], "999");
    assert_eq!(saved_day(&f)["basis"], "spot_usdc_total_plus_unrealized_pnl");

    // A hold is not a loss, and it is not subtracted from the baseline by hand.
    {
        let mut v = f.venue.lock().unwrap();
        unified(&mut v, "999.0", "100.0", "850.0");
    }
    assert_eq!(call(&f.app, "hl_place_order", buy("0.1", "2500")).await["isError"], false);
    assert_eq!(saved_day(&f)["account_value"], "999");

    // Unrealized PnL counts once. The perp account value echoes it and is not added again.
    {
        let mut v = f.venue.lock().unwrap();
        unified(&mut v, "999.0", "0.0", "999.0");
        v.account_value = "-100.01".into();
        v.eth_szi = "0.1".into();
        v.eth_pnl = Some("-100.01".into());
    }
    assert_eq!(code(&call(&f.app, "hl_place_order", buy("0.1", "2500")).await), "DAILY_LOSS_STOP");
    assert_eq!(saved_day(&f)["account_value"], "999");
    let close = json!({"coin": "ETH", "is_buy": false, "sz": "0.1", "limit_px": "2400", "reduce_only": true});
    assert_eq!(call(&f.app, "hl_place_order", close).await["isError"], false);

    // A non-zero saved baseline is not replaced, even when it is above today's equity.
    write_day(&f, "5000");
    let before = std::fs::read(day_file(&f)).unwrap();
    {
        let mut v = f.venue.lock().unwrap();
        unified(&mut v, "999.0", "0.0", "999.0");
    }
    assert_eq!(code(&call(&f.app, "hl_place_order", buy("0.1", "2500")).await), "DAILY_LOSS_STOP");
    assert_eq!(std::fs::read(day_file(&f)).unwrap(), before);
}

#[tokio::test]
async fn unified_failures_refuse_new_risk_and_keep_reduce_only() {
    let f = fixture().await;
    approve(&f).await;
    let close = json!({"coin": "ETH", "is_buy": false, "sz": "0.1", "limit_px": "2400", "reduce_only": true});

    // Portfolio margin is not priced. The order is refused and no baseline is invented.
    f.venue.lock().unwrap().abstraction = json!("portfolioMargin");
    assert_eq!(code(&call(&f.app, "hl_place_order", buy("0.1", "2500")).await), "VENUE_UNAVAILABLE");
    assert_eq!(call(&f.app, "hl_place_order", close.clone()).await["isError"], false);
    assert!(!day_file(&f).exists());

    // Non-USDC collateral, a missing available figure, and a non-flat legacy zero.
    {
        let mut v = f.venue.lock().unwrap();
        unified(&mut v, "999.0", "0.0", "999.0");
        v.spot["balances"]
            .as_array_mut()
            .unwrap()
            .push(json!({"coin": "PURR", "token": 1, "total": "2", "hold": "0.0"}));
    }
    let r = call(&f.app, "hl_place_order", buy("0.1", "2500")).await;
    assert_eq!(code(&r), "VENUE_UNAVAILABLE");
    assert!(r["structuredContent"]["reason"].as_str().unwrap().contains("non-USDC"), "{r}");
    assert!(!day_file(&f).exists());
    assert_eq!(call(&f.app, "hl_place_order", close.clone()).await["isError"], false);

    {
        let mut v = f.venue.lock().unwrap();
        unified(&mut v, "999.0", "0.0", "999.0");
        v.spot.as_object_mut().unwrap().remove("tokenToAvailableAfterMaintenance");
    }
    assert_eq!(code(&call(&f.app, "hl_place_order", buy("0.1", "2500")).await), "VENUE_UNAVAILABLE");
    assert_eq!(call(&f.app, "hl_positions", json!({})).await["isError"], true);

    write_day(&f, "0");
    let before = std::fs::read(day_file(&f)).unwrap();
    {
        let mut v = f.venue.lock().unwrap();
        unified(&mut v, "999.0", "0.0", "999.0");
        v.eth_szi = "0.2".into();
        v.eth_pnl = Some("-1".into());
    }
    let r = call(&f.app, "hl_place_order", buy("0.1", "2500")).await;
    assert_eq!(code(&r), "VENUE_UNAVAILABLE");
    assert!(r["structuredContent"]["reason"].as_str().unwrap().contains("untrusted zero"), "{r}");
    assert_eq!(std::fs::read(day_file(&f)).unwrap(), before);
    assert_eq!(call(&f.app, "hl_place_order", close).await["isError"], false);
    assert_eq!(std::fs::read(day_file(&f)).unwrap(), before);
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

fn equity_file(f: &Fixture) -> std::path::PathBuf {
    f.config.server.state_dir.join("hyperliquid/filltape.equity.json")
}

fn saved_equity(f: &Fixture) -> Value {
    serde_json::from_slice(&std::fs::read(equity_file(f)).unwrap()).unwrap()
}

fn reason(result: &Value) -> &str {
    result["structuredContent"]["reason"].as_str().unwrap()
}

fn reduce_only(sz: &str) -> Value {
    json!({"coin": "ETH", "is_buy": false, "sz": sz, "limit_px": "2400", "reduce_only": true})
}

#[tokio::test]
async fn equity_floor_latches_until_an_explicit_reset() {
    let f = fixture_with("equity_floor_usd = 8000").await;
    approve(&f).await;
    let limits = call(&f.app, "limits", json!({})).await;
    let hl = &limits["structuredContent"]["hyperliquid"];
    assert_eq!(hl["equity_floor_usd"], 8000);
    assert!(hl["max_drawdown_from_peak_usd"].is_null());
    assert_eq!(hl["equity"], "10000.0");
    assert_eq!(hl["floor"], "8000");
    assert_eq!(hl["peak_equity"], "10000");
    assert_eq!(hl["headroom"], "2000");
    assert_eq!(hl["breached"], false);
    assert_eq!(call(&f.app, "hl_place_order", buy("0.1", "2500")).await["isError"], false);

    f.venue.lock().unwrap().account_value = "8000".into();
    let r = call(&f.app, "hl_place_order", buy("0.1", "2500")).await;
    assert_eq!(code(&r), "EQUITY_FLOOR_BREACHED");
    assert!(reason(&r).contains("equity 8000"), "{}", reason(&r));
    assert!(reason(&r).contains("floor 8000"), "{}", reason(&r));
    assert!(reason(&r).contains("does not flatten"), "{}", reason(&r));
    assert_eq!(saved_equity(&f)["breached"], true);
    assert_eq!(saved_equity(&f)["peak"], "10000");

    // Reduce-only orders, a reduce-only stop, and cancels still go out. A stop that can add
    // risk does not. Modify is checked like a new order.
    assert_eq!(call(&f.app, "hl_place_order", reduce_only("0.1")).await["isError"], false);
    let sl = json!({
        "coin": "ETH", "is_buy": false, "sz": "0.1", "limit_px": "2000",
        "trigger_px": "2100", "tpsl": "sl", "reduce_only": true
    });
    assert_eq!(call(&f.app, "hl_place_order", sl).await["isError"], false);
    let open_sl = json!({
        "coin": "ETH", "is_buy": false, "sz": "0.1", "limit_px": "2000",
        "trigger_px": "2100", "tpsl": "sl"
    });
    assert_eq!(code(&call(&f.app, "hl_place_order", open_sl).await), "EQUITY_FLOOR_BREACHED");
    assert_eq!(call(&f.app, "hl_cancel", json!({"coin": "ETH", "oid": 9})).await["isError"], false);
    let mut modify = buy("0.1", "2500");
    modify["oid"] = json!(7);
    assert_eq!(code(&call(&f.app, "hl_modify", modify).await), "EQUITY_FLOOR_BREACHED");

    // Leverage can go down, not up. The same value again is not an increase.
    assert_eq!(
        code(&call(&f.app, "hl_set_leverage", json!({"coin": "ETH", "leverage": 4})).await),
        "EQUITY_FLOOR_BREACHED"
    );
    assert_eq!(call(&f.app, "hl_set_leverage", json!({"coin": "ETH", "leverage": 3})).await["isError"], false);
    assert_eq!(call(&f.app, "hl_set_leverage", json!({"coin": "ETH", "leverage": 1})).await["isError"], false);
    let posted = std::mem::take(&mut f.venue.lock().unwrap().posted);
    assert_eq!(posted.last().unwrap()["action"]["leverage"], 1);

    // Recovery does not clear the latch, and neither does a new process.
    f.venue.lock().unwrap().account_value = "9500".into();
    let r = call(&f.app, "hl_place_order", buy("0.1", "2500")).await;
    assert_eq!(code(&r), "EQUITY_FLOOR_BREACHED");
    assert!(reason(&r).contains("latched"), "{}", reason(&r));
    assert!(reason(&r).contains("equity 9500"), "{}", reason(&r));
    assert!(reason(&r).contains("floor 8000"), "{}", reason(&r));
    let app = restart(&f);
    assert_eq!(code(&call(&app, "hl_place_order", buy("0.1", "2500")).await), "EQUITY_FLOOR_BREACHED");

    // Editing the floor number is not a reset.
    let app = reload(&f, "equity_floor_usd = 1000");
    assert_eq!(code(&call(&app, "hl_place_order", buy("0.1", "2500")).await), "EQUITY_FLOOR_BREACHED");
    assert_eq!(saved_equity(&f)["peak"], "10000");

    // The reset flag clears once. The high-water mark stays where it was.
    // The day's loss baseline is pinned so the daily stop is not what allows this order.
    write_day(&f, "9500");
    let app = reload(&f, "equity_floor_usd = 8000\nreset_equity_floor = true");
    assert_eq!(call(&app, "hl_place_order", buy("0.1", "2500")).await["isError"], false);
    assert_eq!(saved_equity(&f)["breached"], false);
    assert_eq!(saved_equity(&f)["reset_seen"], true);
    assert_eq!(saved_equity(&f)["peak"], "10000");

    // A new breach is not cleared by leaving the flag true across a restart.
    f.venue.lock().unwrap().account_value = "7000".into();
    assert_eq!(code(&call(&app, "hl_place_order", buy("0.1", "2500")).await), "EQUITY_FLOOR_BREACHED");
    f.venue.lock().unwrap().account_value = "9500".into();
    let app = reload(&f, "equity_floor_usd = 8000\nreset_equity_floor = true");
    assert_eq!(code(&call(&app, "hl_place_order", buy("0.1", "2500")).await), "EQUITY_FLOOR_BREACHED");

    // Toggle the flag off, then on, once equity is back above the floor.
    let app = reload(&f, "equity_floor_usd = 8000\nreset_equity_floor = false");
    assert_eq!(code(&call(&app, "hl_place_order", buy("0.1", "2500")).await), "EQUITY_FLOOR_BREACHED");
    assert_eq!(saved_equity(&f)["reset_seen"], false);
    write_day(&f, "9500");
    let app = reload(&f, "equity_floor_usd = 8000\nreset_equity_floor = true");
    assert_eq!(call(&app, "hl_place_order", buy("0.1", "2500")).await["isError"], false);
    assert_eq!(saved_equity(&f)["breached"], false);
    assert_eq!(saved_equity(&f)["peak"], "10000");
}

#[tokio::test]
async fn unified_equity_floor_uses_spot_usdc_plus_pnl() {
    let f = fixture_with("equity_floor_usd = 800").await;
    approve(&f).await;
    {
        let mut v = f.venue.lock().unwrap();
        unified(&mut v, "999.0", "0.0", "999.0");
        v.seen.clear();
    }
    let r = call(&f.app, "hl_positions", json!({})).await;
    assert_eq!(r["isError"], false, "{r}");
    let account = &r["structuredContent"]["account"];
    assert_eq!(account["equity"], "999.0");
    assert_eq!(account["floor"], "800");
    assert_eq!(account["peak_equity"], "999");
    assert_eq!(account["headroom"], "199");
    assert_eq!(account["breached"], false);
    // Perp account value is 0 on this account. Using it as equity would already be a breach.
    assert_eq!(r["structuredContent"]["state"]["marginSummary"]["accountValue"], "0.0");
    assert!(f.venue.lock().unwrap().seen.iter().any(|t| t == "spotClearinghouseState"));
    assert_eq!(call(&f.app, "hl_place_order", buy("0.1", "2500")).await["isError"], false);

    {
        let mut v = f.venue.lock().unwrap();
        unified(&mut v, "999.0", "0.0", "799.0");
        v.account_value = "-200".into();
        v.eth_szi = "0.1".into();
        v.eth_pnl = Some("-200".into());
    }
    let r = call(&f.app, "hl_place_order", buy("0.1", "2500")).await;
    assert_eq!(code(&r), "EQUITY_FLOOR_BREACHED");
    assert!(reason(&r).contains("equity 799"), "{}", reason(&r));
    assert!(reason(&r).contains("floor 800"), "{}", reason(&r));
    assert_eq!(saved_equity(&f)["peak"], "999");
    assert_eq!(call(&f.app, "hl_place_order", reduce_only("0.1")).await["isError"], false);
}

#[tokio::test]
async fn drawdown_peak_tracks_across_restarts() {
    let f = fixture_with("max_drawdown_from_peak_usd = 200").await;
    approve(&f).await;
    assert_eq!(call(&f.app, "hl_positions", json!({})).await["isError"], false);
    assert_eq!(saved_equity(&f)["peak"], "10000");
    assert_eq!(saved_equity(&f)["breached"], false);

    f.venue.lock().unwrap().account_value = "12000".into();
    let app = restart(&f);
    let r = call(&app, "hl_positions", json!({})).await;
    assert_eq!(r["structuredContent"]["account"]["peak_equity"], "12000");
    assert_eq!(r["structuredContent"]["account"]["floor"], "11800");
    assert_eq!(r["structuredContent"]["account"]["headroom"], "200");
    assert_eq!(r["structuredContent"]["account"]["breached"], false);
    assert_eq!(saved_equity(&f)["peak"], "12000");

    // One tick above the trailing floor is still allowed, and a restart keeps the higher peak.
    // Pin the daily baseline so the daily loss stop is not the check under test.
    write_day(&f, "11800.01");
    f.venue.lock().unwrap().account_value = "11800.01".into();
    let app = restart(&f);
    assert_eq!(call(&app, "hl_place_order", buy("0.1", "2500")).await["isError"], false);
    assert_eq!(saved_equity(&f)["peak"], "12000");
    assert_eq!(saved_equity(&f)["breached"], false);

    f.venue.lock().unwrap().account_value = "11800".into();
    let app = restart(&f);
    let r = call(&app, "hl_place_order", buy("0.1", "2500")).await;
    assert_eq!(code(&r), "EQUITY_FLOOR_BREACHED");
    assert!(reason(&r).contains("equity 11800"), "{}", reason(&r));
    assert!(reason(&r).contains("floor 11800"), "{}", reason(&r));
    assert_eq!(saved_equity(&f)["peak"], "12000");
    assert_eq!(saved_equity(&f)["breached"], true);
    assert_eq!(call(&app, "hl_place_order", reduce_only("1")).await["isError"], false);
}

#[tokio::test]
async fn unreadable_equity_fails_closed_for_new_risk() {
    let f = fixture_with("equity_floor_usd = 100\nmax_drawdown_from_peak_usd = 50").await;
    approve(&f).await;
    assert_eq!(call(&f.app, "hl_positions", json!({})).await["isError"], false);
    let before = std::fs::read(equity_file(&f)).unwrap();
    assert_eq!(saved_equity(&f)["peak"], "10000");

    f.venue.lock().unwrap().abstraction = json!("portfolioMargin");
    let r = call(&f.app, "hl_place_order", buy("0.1", "2500")).await;
    assert_eq!(code(&r), "VENUE_UNAVAILABLE");
    assert!(reason(&r).contains("portfolio margin"), "{}", reason(&r));
    assert_eq!(std::fs::read(equity_file(&f)).unwrap(), before);
    assert_eq!(call(&f.app, "hl_place_order", reduce_only("0.1")).await["isError"], false);
    assert_eq!(std::fs::read(equity_file(&f)).unwrap(), before);
    // An increase needs a readable equity. A decrease does not.
    assert_eq!(
        code(&call(&f.app, "hl_set_leverage", json!({"coin": "ETH", "leverage": 4})).await),
        "VENUE_UNAVAILABLE"
    );
    assert_eq!(call(&f.app, "hl_set_leverage", json!({"coin": "ETH", "leverage": 2})).await["isError"], false);
    assert_eq!(std::fs::read(equity_file(&f)).unwrap(), before);

    {
        let mut v = f.venue.lock().unwrap();
        unified(&mut v, "999.0", "0.0", "999.0");
        v.eth_szi = "0.2".into();
        v.eth_pnl = None;
    }
    let r = call(&f.app, "hl_place_order", buy("0.1", "2500")).await;
    assert_eq!(code(&r), "VENUE_UNAVAILABLE");
    assert!(reason(&r).contains("unrealized PnL"), "{}", reason(&r));
    assert_eq!(std::fs::read(equity_file(&f)).unwrap(), before);
    let limits = call(&f.app, "limits", json!({})).await;
    assert_eq!(limits["isError"], false, "{limits}");
    let hl = &limits["structuredContent"]["hyperliquid"];
    assert!(hl["equity"].is_null(), "{hl}");
    assert!(hl["equity_error"].as_str().unwrap().contains("unrealized PnL"), "{hl}");
    // The saved peak is still reported. The read is not treated as zero, so this is not a breach.
    assert_eq!(hl["peak_equity"], "10000");
    assert_eq!(hl["breached"], false);
    assert_eq!(std::fs::read(equity_file(&f)).unwrap(), before);

    {
        let mut v = f.venue.lock().unwrap();
        v.abstraction = json!("default");
        v.account_value = "nope".into();
    }
    assert_eq!(code(&call(&f.app, "hl_place_order", buy("0.1", "2500")).await), "VENUE_UNAVAILABLE");
    assert_eq!(std::fs::read(equity_file(&f)).unwrap(), before);
    assert_eq!(call(&f.app, "hl_cancel", json!({"coin": "ETH", "oid": 3})).await["isError"], false);
}

#[test]
fn example_config_parses() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../keyshare.example.toml");
    let config = Config::load(&path).unwrap();
    assert!(config.bots["filltape"].hyperliquid.is_some());
}
