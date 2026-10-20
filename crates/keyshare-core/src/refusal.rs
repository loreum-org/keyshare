use serde::{Deserialize, Serialize};

/// Why a request was not signed. Codes follow the error contract in docs/design.md §7,
/// so a bot can explain the refusal to its owner instead of retrying blindly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RefusalCode {
    UnknownCaller,
    KillSwitch,
    ChainNotAllowed,
    RecipientNotAllowed,
    ContractNotAllowed,
    DeniedPrimitive,
    TypedDataNotAllowed,
    MessageLooksLikeTx,
    PriceUnavailable,
    PerTxCapExceeded,
    CapExceeded,
    NonceReused,
    CounterBehindAnchor,
    SimRevert,
    RpcUnavailable,
    ThresholdUnavailable,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{code:?}: {reason}")]
pub struct Refusal {
    pub refused: bool,
    pub code: RefusalCode,
    pub reason: String,
}

impl Refusal {
    pub fn new(code: RefusalCode, reason: impl Into<String>) -> Self {
        Self { refused: true, code, reason: reason.into() }
    }
}
