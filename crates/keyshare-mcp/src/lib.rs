//! keyshare MCP connector (design §7). Bots authenticate with a bearer token; every tool runs
//! against that bot's own wallet and policy.

pub mod admin;
pub mod auth;
pub mod chain;
pub mod config;
pub mod exec;
pub mod hl;
pub mod server;
pub mod swap;

use std::sync::Arc;

use alloy::primitives::B256;
use axum::Router;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};

use crate::auth::Credentials;
use crate::exec::Executor;
use crate::server::KeyshareServer;

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
