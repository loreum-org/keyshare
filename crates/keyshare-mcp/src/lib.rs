//! keyshare MCP connector (design §7). Bots authenticate with a bearer token; every tool runs
//! against that bot's own wallet and policy.

pub mod admin;
pub mod auth;
pub mod chain;
pub mod config;
pub mod exec;
pub mod hl;
pub mod policy;
pub mod server;
pub mod swap;

use std::sync::Arc;

use alloy::primitives::B256;
use axum::Router;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};

use crate::auth::Credentials;
use crate::chain::Chains;
use crate::config::Config;
use crate::exec::{DEFAULT_HOLD_SECS, Executor, Reload};
use crate::server::KeyshareServer;
use keyshare_core::policy_file::VersionGate;

/// Builds the executor from the config and the signed policy, and puts the policy in force.
/// Fails if the policy is unsigned, signed by the wrong key, invalid, or older than the newest
/// one this state directory has accepted.
pub async fn build(config: &Config, env: impl Fn(&str) -> Option<String>) -> Result<Executor, String> {
    let loaded = policy::load(config).map_err(|e| format!("policy {}: {e}", config.server.policy.display()))?;
    let gate = VersionGate::new(config.policy_state_path());
    gate.check(&loaded.reference).map_err(|e| e.to_string())?;
    let wallet = config.wallet(env, &loaded.set).map_err(|e| e.to_string())?;
    let chains = Arc::new(Chains::new(&config.chains).map_err(|e| e.to_string())?);
    let tokens = Arc::new(loaded.set.prices.clone());
    let hold = config.server.hold_secs.unwrap_or(DEFAULT_HOLD_SECS);
    let hl = config.hyperliquid(&loaded.set).map_err(|e| e.to_string())?;
    let exec = Executor::new(Arc::new(std::sync::Mutex::new(wallet)), chains, tokens, hold)
        .with_hyperliquid(hl)
        .with_modules(loaded.set.modules());
    exec.apply_policy(loaded, &gate).await?;
    Ok(exec)
}

/// Polls the policy file every `server.policy_reload_secs` (default 5) and loads a newly signed
/// version without a restart. Returns `None` when reloading is off.
pub fn spawn_policy_reload(exec: Arc<Executor>, config: Arc<Config>) -> Option<tokio::task::JoinHandle<()>> {
    let secs = config.server.policy_reload_secs.unwrap_or(5);
    if secs == 0 {
        return None;
    }
    Some(tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(secs));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            match exec.reload_policy(&config).await {
                Reload::Unchanged => {}
                Reload::Loaded(p) => eprintln!("policy version {} loaded ({})", p.version, p.hash),
                Reload::Rejected(why) => eprintln!("policy file refused, keeping the current policy: {why}"),
            }
        }
    }))
}

/// The HTTP app: `/mcp` behind bot auth; `/admin/*` for the owner; `/health` open.
pub fn app(
    exec: Arc<Executor>,
    creds: Credentials,
    admin_token_sha256: Option<B256>,
    allowed_hosts: &[String],
) -> Router {
    let mut config = StreamableHttpServerConfig::default();
    // Empty must not be passed to with_allowed_hosts. rmcp treats an empty list as "allow every
    // host", which turns the DNS-rebinding guard off. Empty keeps the crate default: localhost,
    // 127.0.0.1 and ::1. A non-empty list replaces that default with exactly those hosts.
    if !allowed_hosts.is_empty() {
        config = config.with_allowed_hosts(allowed_hosts.iter().cloned());
    }
    let tools_exec = exec.clone();
    let mcp = StreamableHttpService::new(
        move || Ok(KeyshareServer::new(tools_exec.clone())),
        Arc::new(LocalSessionManager::default()),
        config,
    );
    let admin = Router::new()
        .route("/admin/pending", axum::routing::get(admin::pending))
        .route("/admin/decide", axum::routing::post(admin::decide))
        .with_state(admin::AdminState { exec, token_sha256: admin_token_sha256 });
    Router::new()
        .nest_service("/mcp", mcp)
        .layer(axum::middleware::from_fn_with_state(creds, auth::require_bot))
        .merge(admin)
        .route("/health", axum::routing::get(|| async { "ok" }))
}
