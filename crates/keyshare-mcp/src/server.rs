//! The MCP tools (design §7). State-changing tools run through [`keyshare_core::Wallet`], so they
//! get the same kill switch, policy, spend counter and audit log as every other signature.
//! Transactions follow §4: build → policy pre-check → simulate → sign → broadcast.

use std::sync::Arc;

use alloy::consensus::TxEip1559;
use alloy::dyn_abi::TypedData;
use alloy::primitives::utils::{ParseUnits, parse_units};
use alloy::primitives::{Address, B256, Bytes, TxKind, U256};
use alloy::sol;
use alloy::sol_types::SolCall;
use keyshare_core::{Refusal, RefusalCode, Wallet};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::Extension;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ServerCapabilities, ServerConfig};
use rmcp::{ErrorData, ServerHandler, schemars, tool, tool_handler, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::auth::Caller;
use crate::chain;
use crate::exec::{Executor, Outcome, RequestState, now, scoped, usd};

sol! { function transfer(address to, uint256 amount); }

#[derive(Clone)]
pub struct KeyshareServer {
    exec: Arc<Executor>,
    tool_router: ToolRouter<Self>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct BalancesArgs {
    /// Only this chain. Default: every configured chain.
    pub chain_id: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SendArgs {
    pub chain_id: u64,
    #[schemars(with = "String")]
    pub to: Address,
    /// ERC-20 token address. Omit for the chain's native token.
    #[schemars(with = "Option<String>")]
    pub token: Option<Address>,
    /// Decimal amount in whole tokens, e.g. "12.5".
    pub amount: String,
    /// Build, check and simulate only. Nothing is signed.
    #[serde(default)]
    pub dry_run: bool,
    pub request_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CallArgs {
    pub chain_id: u64,
    #[schemars(with = "String")]
    pub to: Address,
    /// Calldata, 0x-prefixed hex.
    #[schemars(with = "String")]
    pub data: Bytes,
    /// Native value in wei, as a decimal string. Default 0.
    pub value_wei: Option<String>,
    #[serde(default)]
    pub dry_run: bool,
    pub request_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SimulateArgs {
    pub chain_id: u64,
    #[schemars(with = "String")]
    pub to: Address,
    /// Calldata, 0x-prefixed hex. Omit for a plain transfer.
    #[schemars(with = "Option<String>")]
    pub data: Option<Bytes>,
    /// Native value in wei, as a decimal string. Default 0.
    pub value_wei: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TxStatusArgs {
    pub chain_id: u64,
    /// Look up by transaction hash...
    #[schemars(with = "Option<String>")]
    pub tx_hash: Option<B256>,
    /// ...or by the request id a state-changing tool returned.
    pub request_id: Option<String>,
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

fn caller(parts: &http::request::Parts) -> Result<String, ErrorData> {
    parts
        .extensions
        .get::<Caller>()
        .map(|c| c.0.clone())
        .ok_or_else(|| ErrorData::invalid_request("no authenticated caller", None))
}

fn new_request_id(given: Option<String>) -> String {
    given.unwrap_or_else(|| alloy::hex::encode(&B256::random()[..16]))
}

fn refused(request_id: &str, r: Refusal) -> CallToolResult {
    let mut v = json!(r);
    v["request_id"] = json!(request_id);
    CallToolResult::structured_error(v)
}

fn bad_args(why: impl Into<String>) -> CallToolResult {
    CallToolResult::structured_error(json!({ "refused": true, "code": "BAD_ARGS", "reason": why.into() }))
}

fn parse_wei(v: Option<String>) -> Result<U256, CallToolResult> {
    match v {
        None => Ok(U256::ZERO),
        Some(s) => s.parse().map_err(|_| bad_args(format!("value_wei {s:?} is not a decimal integer"))),
    }
}

fn internal(e: String) -> ErrorData {
    ErrorData::internal_error(e, None)
}

fn to_result(outcome: Outcome) -> CallToolResult {
    match outcome {
        Ok(v) => CallToolResult::structured(v),
        Err(v) => CallToolResult::structured_error(v),
    }
}

impl KeyshareServer {
    pub fn new(exec: Arc<Executor>) -> Self {
        Self { exec, tool_router: Self::tool_router() }
    }

    async fn with_wallet<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Wallet) -> T + Send + 'static,
    ) -> Result<T, ErrorData> {
        self.exec.with_wallet(f).await.map_err(internal)
    }

    async fn submit(
        &self,
        caller: String,
        request_id: Option<String>,
        tx: TxEip1559,
        dry_run: bool,
    ) -> Result<CallToolResult, ErrorData> {
        let id = new_request_id(request_id);
        self.exec.submit(&caller, &id, tx, dry_run).await.map(to_result).map_err(internal)
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

    #[tool(description = "Native and priced-token balances of this bot's wallet.")]
    async fn balances(
        &self,
        Extension(parts): Extension<http::request::Parts>,
        Parameters(args): Parameters<BalancesArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let caller = caller(&parts)?;
        let c = caller.clone();
        let owner = match self.with_wallet(move |w| w.address(&c)).await? {
            Ok(a) => a,
            Err(r) => return Ok(refused("", r)),
        };
        let chains = match args.chain_id {
            Some(id) => vec![id],
            None => self.exec.chains.ids(),
        };
        let mut rows = Vec::new();
        for chain_id in chains {
            let provider = match self.exec.chains.get(chain_id) {
                Ok(p) => p,
                Err(r) => return Ok(refused("", r)),
            };
            let mut tokens: Vec<(Option<Address>, u8)> = vec![(None, 18)];
            tokens.extend(
                self.exec
                    .tokens
                    .iter()
                    .filter(|t| t.chain_id == chain_id && t.token.is_some())
                    .map(|t| (t.token, t.decimals)),
            );
            for (token, decimals) in tokens {
                let amount = match chain::balance(provider, owner, token).await {
                    Ok(a) => a,
                    Err(r) => return Ok(refused("", r)),
                };
                let usd_value = self.with_wallet(move |w| w.prices().value_usd(chain_id, token, amount)).await?;
                rows.push(json!({
                    "chain_id": chain_id,
                    "token": token.map_or("native".to_string(), |t| t.to_string()),
                    "amount": alloy::primitives::utils::format_units(amount, decimals).unwrap_or_default(),
                    "usd": usd_value.map(usd),
                }));
            }
        }
        Ok(CallToolResult::structured(json!({ "address": owner, "balances": rows })))
    }

    #[tool(
        description = "Dry-run a transaction from this bot's wallet: policy verdict, gas, and whether it reverts. Nothing is signed."
    )]
    async fn simulate(
        &self,
        Extension(parts): Extension<http::request::Parts>,
        Parameters(args): Parameters<SimulateArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let caller = caller(&parts)?;
        let value = match parse_wei(args.value_wei) {
            Ok(v) => v,
            Err(e) => return Ok(e),
        };
        let tx = TxEip1559 {
            chain_id: args.chain_id,
            to: TxKind::Call(args.to),
            value,
            input: args.data.unwrap_or_default(),
            ..Default::default()
        };
        self.submit(caller, None, tx, true).await
    }

    #[tool(
        description = "Send native tokens or an ERC-20 from this bot's wallet. Checked against policy and simulated before signing."
    )]
    async fn send(
        &self,
        Extension(parts): Extension<http::request::Parts>,
        Parameters(args): Parameters<SendArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let caller = caller(&parts)?;
        let decimals = match args.token {
            None => 18,
            Some(token) => {
                let provider = match self.exec.chains.get(args.chain_id) {
                    Ok(p) => p,
                    Err(r) => return Ok(refused("", r)),
                };
                match chain::token_decimals(provider, token).await {
                    Ok(d) => d,
                    Err(r) => return Ok(refused("", r)),
                }
            }
        };
        let amount: U256 = match parse_units(&args.amount, decimals) {
            Ok(ParseUnits::U256(a)) => a,
            _ => {
                return Ok(bad_args(format!(
                    "amount {:?} is not a positive decimal with at most {decimals} places",
                    args.amount
                )));
            }
        };
        let (to, value, input) = match args.token {
            None => (args.to, amount, Bytes::new()),
            Some(token) => (token, U256::ZERO, Bytes::from(transferCall { to: args.to, amount }.abi_encode())),
        };
        let tx = TxEip1559 { chain_id: args.chain_id, to: TxKind::Call(to), value, input, ..Default::default() };
        self.submit(caller, args.request_id, tx, args.dry_run).await
    }

    #[tool(
        description = "Call an allowlisted contract function from this bot's wallet. Checked against policy and simulated before signing."
    )]
    async fn call_contract(
        &self,
        Extension(parts): Extension<http::request::Parts>,
        Parameters(args): Parameters<CallArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let caller = caller(&parts)?;
        let value = match parse_wei(args.value_wei) {
            Ok(v) => v,
            Err(e) => return Ok(e),
        };
        let tx = TxEip1559 {
            chain_id: args.chain_id,
            to: TxKind::Call(args.to),
            value,
            input: args.data,
            ..Default::default()
        };
        self.submit(caller, args.request_id, tx, args.dry_run).await
    }

    #[tool(
        description = "Status of a request or transaction: pending_user_approval, refused, pending, confirmed, failed or unknown."
    )]
    async fn tx_status(
        &self,
        Extension(parts): Extension<http::request::Parts>,
        Parameters(args): Parameters<TxStatusArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let caller = caller(&parts)?;
        let hash = match (args.tx_hash, args.request_id) {
            (Some(h), _) => h,
            (None, Some(id)) => match self.exec.request_state(&caller, &id) {
                Some(RequestState::Broadcast { tx_hash, .. }) => tx_hash,
                Some(state) => return Ok(CallToolResult::structured(json!(state))),
                None => return Ok(CallToolResult::structured(json!({ "state": "unknown" }))),
            },
            (None, None) => return Ok(bad_args("give tx_hash or request_id")),
        };
        let provider = match self.exec.chains.get(args.chain_id) {
            Ok(p) => p,
            Err(r) => return Ok(refused("", r)),
        };
        match chain::tx_status(provider, hash).await {
            Ok(s) => Ok(CallToolResult::structured(
                json!({ "tx_hash": hash, "state": s.state, "block_number": s.block_number }),
            )),
            Err(r) => Ok(refused("", r)),
        }
    }

    #[tool(description = "Sign a plain-text message (EIP-191) with this bot's wallet.")]
    async fn sign_message(
        &self,
        Extension(parts): Extension<http::request::Parts>,
        Parameters(args): Parameters<SignMessageArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let caller = caller(&parts)?;
        let id = new_request_id(args.request_id);
        let scoped = scoped(&caller, &id);
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
        let id = new_request_id(args.request_id);
        let scoped = scoped(&caller, &id);
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
