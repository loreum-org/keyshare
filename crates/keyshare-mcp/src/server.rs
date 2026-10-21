//! The MCP tools. Phase 0 tools that need no chain RPC: `address`, `limits`, `sign_message`,
//! `sign_typed_data`. State-changing tools run through [`keyshare_core::Wallet`], so they get the
//! same kill switch, policy, spend counter and audit log as every other signature.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::dyn_abi::TypedData;
use alloy::primitives::B256;
use keyshare_core::price::MICROS_PER_USD;
use keyshare_core::{Refusal, RefusalCode, Wallet};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::Extension;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ServerCapabilities, ServerConfig};
use rmcp::{ErrorData, ServerHandler, schemars, tool, tool_handler, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::auth::Caller;

#[derive(Clone)]
pub struct KeyshareServer {
    wallet: Arc<Mutex<Wallet>>,
    tool_router: ToolRouter<Self>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SignMessageArgs {
    /// Plain text to sign with EIP-191. Hex strings and binary are refused.
    pub message: String,
    /// Optional idempotency key. A request id can only be used once.
    pub request_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SignTypedDataArgs {
    /// EIP-712 payload: `{types, primaryType, domain, message}`.
    pub typed_data: Value,
    /// Optional idempotency key. A request id can only be used once.
    pub request_id: Option<String>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn caller(parts: &http::request::Parts) -> Result<String, ErrorData> {
    parts
        .extensions
        .get::<Caller>()
        .map(|c| c.0.clone())
        .ok_or_else(|| ErrorData::invalid_request("no authenticated caller", None))
}

/// Request ids are namespaced per caller so one bot can't burn another's ids.
fn request_id(caller: &str, given: Option<String>) -> (String, String) {
    let id = given.unwrap_or_else(|| alloy::hex::encode(&B256::random()[..16]));
    (format!("{caller}:{id}"), id)
}

fn refused(request_id: &str, r: Refusal) -> CallToolResult {
    let mut v = json!(r);
    v["request_id"] = json!(request_id);
    CallToolResult::structured_error(v)
}

fn usd(micros: u128) -> String {
    format!("{}.{:06}", micros / MICROS_PER_USD, micros % MICROS_PER_USD)
}

impl KeyshareServer {
    pub fn new(wallet: Arc<Mutex<Wallet>>) -> Self {
        Self { wallet, tool_router: Self::tool_router() }
    }

    /// Runs `f` on the wallet off the async runtime (it does fsyncs).
    async fn with_wallet<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Wallet) -> T + Send + 'static,
    ) -> Result<T, ErrorData> {
        let wallet = self.wallet.clone();
        tokio::task::spawn_blocking(move || {
            let mut w = wallet.lock().map_err(|_| ErrorData::internal_error("wallet lock poisoned", None))?;
            Ok(f(&mut w))
        })
        .await
        .map_err(|e| ErrorData::internal_error(e.to_string(), None))?
    }
}

#[tool_router]
impl KeyshareServer {
    #[tool(description = "This bot's wallet address and the chains it may use.")]
    async fn address(&self, Extension(parts): Extension<http::request::Parts>) -> Result<CallToolResult, ErrorData> {
        let caller = caller(&parts)?;
        self.with_wallet(move |w| match (w.address(&caller), w.limits(&caller)) {
            (Ok(address), Ok(limits)) => {
                CallToolResult::structured(json!({ "address": address, "chain_ids": limits.chains }))
            }
            (Err(r), _) | (_, Err(r)) => refused("", r),
        })
        .await
    }

    #[tool(description = "This bot's caps and how much of today's cap it has used. Use it to self-limit.")]
    async fn limits(&self, Extension(parts): Extension<http::request::Parts>) -> Result<CallToolResult, ErrorData> {
        let caller = caller(&parts)?;
        self.with_wallet(move |w| match w.limits(&caller) {
            Ok(limits) => {
                let mut v = json!(limits);
                v["spent_24h_usd"] = json!(usd(w.spent_24h(&caller, now())));
                CallToolResult::structured(v)
            }
            Err(r) => refused("", r),
        })
        .await
    }

    #[tool(description = "Sign a plain-text message (EIP-191) with this bot's wallet.")]
    async fn sign_message(
        &self,
        Extension(parts): Extension<http::request::Parts>,
        Parameters(args): Parameters<SignMessageArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let caller = caller(&parts)?;
        let (scoped, id) = request_id(&caller, args.request_id);
        self.with_wallet(move |w| match w.sign_message(&caller, &scoped, args.message.as_bytes(), now()) {
            Ok(sig) => CallToolResult::structured(json!({ "request_id": id, "signature": sig })),
            Err(r) => refused(&id, r),
        })
        .await
    }

    #[tool(description = "Sign EIP-712 typed data with this bot's wallet. Only allowlisted types are signed.")]
    async fn sign_typed_data(
        &self,
        Extension(parts): Extension<http::request::Parts>,
        Parameters(args): Parameters<SignTypedDataArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let caller = caller(&parts)?;
        let (scoped, id) = request_id(&caller, args.request_id);
        let data: TypedData = match serde_json::from_value(args.typed_data) {
            Ok(d) => d,
            Err(e) => {
                let r = Refusal::new(RefusalCode::TypedDataNotAllowed, format!("not valid EIP-712: {e}"));
                return Ok(refused(&id, r));
            }
        };
        self.with_wallet(move |w| match w.sign_typed_data(&caller, &scoped, &data, now()) {
            Ok(sig) => CallToolResult::structured(json!({ "request_id": id, "signature": sig })),
            Err(r) => refused(&id, r),
        })
        .await
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for KeyshareServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "keyshare wallet. Every signature is checked against this bot's policy and logged. \
             Refusals return {refused, code, reason}; explain them to the owner instead of retrying.",
        )
    }
}
