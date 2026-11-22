//! keyshare core: the parts of the signing path that stay the same whether a wallet is backed by
//! one testnet key (Phase 0) or a threshold key. See docs/design.md.
//!
//! This crate exports the [`Signer`] trait but nothing that loads a key or builds a signer. That
//! lives in `keyshare-signer`, which only the connector depends on (docs/modules.md).

pub mod approval;
pub mod audit;
pub mod chainlog;
pub mod killswitch;
pub mod policy;
pub mod policy_file;
pub mod price;
pub mod refusal;
pub mod signer;
pub mod spend;
pub mod wallet;

pub use policy::{Action, Limits, PlainPolicy, PolicyEngine, TypedDataRule, Verdict};
pub use price::{PriceSource, PriceTable, UsdMicros};
pub use refusal::{Refusal, RefusalCode};
pub use signer::{SignContext, Signer, SignerError};
pub use wallet::{Account, SignedTx, StatePaths, Wallet};
