//! keyshare core: the parts of the signing path that stay the same whether a wallet is backed by
//! one testnet key (Phase 0) or a 2-of-3 threshold key (Phase 2). See docs/design.md.

pub mod approval;
pub mod audit;
pub mod chainlog;
pub mod killswitch;
pub mod policy;
pub mod price;
pub mod refusal;
pub mod signer;
pub mod spend;
pub mod wallet;

pub use policy::{Action, Limits, PlainPolicy, PolicyEngine, TypedDataRule, Verdict};
pub use price::{PriceSource, PriceTable, UsdMicros};
pub use refusal::{Refusal, RefusalCode};
pub use signer::{LocalSigner, Signer};
pub use wallet::{Account, SignedTx, StatePaths, Wallet};
