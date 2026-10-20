//! keyshare MCP connector (design §7). Bots authenticate with a bearer token; every tool runs
//! against that bot's own wallet and policy.

pub mod auth;
pub mod chain;
pub mod config;
pub mod server;

use std::sync::{Arc, Mutex};

use axum::Router;
use keyshare_core::Wallet;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};

use keyshare_core::price::PriceEntry;

use crate::auth::Credentials;
use crate::chain::Chains;
use crate::server::KeyshareServer;

/// The HTTP app: `/mcp` behind bot auth, `/health` open.
pub fn app(
    wallet: Arc<Mutex<Wallet>>,
    chains: Arc<Chains>,
    tokens: Arc<Vec<PriceEntry>>,
    creds: Credentials,
    allowed_hosts: &[String],
) -> Router {
    let mut config = StreamableHttpServerConfig::default();
    if !allowed_hosts.is_empty() {
        config = config.with_allowed_hosts(allowed_hosts.iter().cloned());
    }
    let mcp = StreamableHttpService::new(
        move || Ok(KeyshareServer::new(wallet.clone(), chains.clone(), tokens.clone())),
        Arc::new(LocalSessionManager::default()),
        config,
    );
    Router::new()
        .nest_service("/mcp", mcp)
        .layer(axum::middleware::from_fn_with_state(creds, auth::require_bot))
        .route("/health", axum::routing::get(|| async { "ok" }))
}
