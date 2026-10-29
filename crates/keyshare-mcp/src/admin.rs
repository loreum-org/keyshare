//! Owner endpoints for held requests (design §13.2). They sit outside bot auth: a decision is
//! authenticated by the owner's admin-key signature, which binds the request and the transaction.
//! Listing pending requests needs the admin token from the config.
//!
//! The owner signs the `approve_message` (or `deny_message`) from `GET /admin/pending` with any
//! wallet, e.g. `cast wallet sign "<message>"`, and posts it to `POST /admin/decide`.

use std::sync::Arc;

use alloy::primitives::{B256, Signature};
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use keyshare_core::approval::Decision;
use serde::Deserialize;
use serde_json::json;

use crate::auth::token_hash;
use crate::exec::Executor;

#[derive(Clone)]
pub struct AdminState {
    pub exec: Arc<Executor>,
    pub token_sha256: Option<B256>,
}

#[derive(Debug, Deserialize)]
pub struct DecideBody {
    pub bot: String,
    pub request_id: String,
    pub decision: Decision,
    pub signature: Signature,
}

pub async fn pending(State(s): State<AdminState>, headers: HeaderMap) -> Response {
    let Some(expected) = s.token_sha256 else {
        return (StatusCode::NOT_FOUND, "admin listing is not configured").into_response();
    };
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim);
    if token.map(token_hash) != Some(expected) {
        return (StatusCode::UNAUTHORIZED, "missing or wrong admin token").into_response();
    }
    Json(json!({ "pending": s.exec.pending() })).into_response()
}

pub async fn decide(State(s): State<AdminState>, Json(body): Json<DecideBody>) -> Response {
    match s.exec.decide(&body.bot, &body.request_id, body.decision, body.signature).await {
        Ok(Ok(v)) => Json(v).into_response(),
        Ok(Err(v)) => (StatusCode::UNPROCESSABLE_ENTITY, Json(v)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}
