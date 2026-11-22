//! Hyperliquid testnet module. It builds L1 actions and talks to the venue API.
//! [`client::HlHost::sign_l1`] is implemented by the connector, which re-checks the action and
//! signs with the agent key. This crate does not sign bot orders, and it cannot load a key: it does
//! not depend on `keyshare-signer`.

pub mod client;
pub mod protocol;

pub use client::{
    ApprovedAgent, HlConfig, HlHost, Hyperliquid, OrderSpec, Outcome, approve_agent, check_api_url, now_ms,
};
pub use protocol::*;
