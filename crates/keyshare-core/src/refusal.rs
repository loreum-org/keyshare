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
    AdminApprovalRequired,
    BadApproval,
    UserDenied,
    TooManyPending,
    Expired,
    CounterBehindAnchor,
    SimRevert,
    RpcUnavailable,
    ThresholdUnavailable,
    /// Swap: asked for more slippage than the policy allows.
    SlippageTooHigh,
    /// Swap: no pool quotes this pair.
    NoRoute,
    /// Hyperliquid: coin not on the bot's market list.
    MarketNotAllowed,
    OrderTooLarge,
    PositionTooLarge,
    LeverageTooHigh,
    DailyLossStop,
    /// Hyperliquid: equity is at or below the account floor, or that breach is still latched.
    /// Not owner-approvable. The server does not flatten; the caller sends reduce-only orders.
    EquityFloorBreached,
    /// Hyperliquid: no approved, unexpired agent key for this bot.
    NoAgentKey,
    /// Hyperliquid API unreachable or returned something unreadable.
    VenueUnavailable,
    /// The request itself is malformed.
    BadArgs,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{code:?}: {reason}")]
pub struct Refusal {
    pub refused: bool,
    pub code: RefusalCode,
    pub reason: String,
}

impl RefusalCode {
    /// Refusals the wallet's owner can override with an admin approval (design §13.2).
    pub fn is_owner_approvable(self) -> bool {
        matches!(
            self,
            Self::RecipientNotAllowed
                | Self::ContractNotAllowed
                | Self::PerTxCapExceeded
                | Self::CapExceeded
                | Self::AdminApprovalRequired
        )
    }
}

impl Refusal {
    pub fn new(code: RefusalCode, reason: impl Into<String>) -> Self {
        Self { refused: true, code, reason: reason.into() }
    }
}
