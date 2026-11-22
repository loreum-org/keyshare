//! Key material for keyshare: the Phase 0 [`LocalSigner`] and the Hyperliquid agent key file.
//!
//! Only `keyshare-mcp` (the connector) depends on this crate. `keyshare-core` exports the
//! [`keyshare_core::Signer`] trait but no way to build one, and protocol module crates must not
//! depend on this crate at all. `tests/boundary.rs` fails if one does. See docs/modules.md.

pub mod agent;
mod local;

pub use local::LocalSigner;
