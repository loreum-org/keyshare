//! Bot credentials. Each bot sends `Authorization: Bearer <token>`. The connector stores only the
//! token's SHA-256 and attaches the matching bot id to the request. Tools read the caller from
//! there, never from tool arguments (design §7).

use std::collections::HashMap;
use std::sync::Arc;

use alloy::primitives::B256;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};

/// The authenticated bot id, put in request extensions by [`require_bot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller(pub String);

pub type Credentials = Arc<HashMap<B256, String>>;

pub fn token_hash(token: &str) -> B256 {
    B256::from_slice(&Sha256::digest(token.as_bytes()))
}

/// A fresh 32-byte token, hex encoded, and its hash for the config file.
pub fn new_token() -> (String, B256) {
    let token = alloy::hex::encode(B256::random());
    let hash = token_hash(&token);
    (token, hash)
}

pub async fn require_bot(State(creds): State<Credentials>, mut req: Request, next: Next) -> Response {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim);
    let Some(bot) = token.and_then(|t| creds.get(&token_hash(t))) else {
        return (StatusCode::UNAUTHORIZED, "missing or unknown bot credential").into_response();
    };
    req.extensions_mut().insert(Caller(bot.clone()));
    next.run(req).await
}
