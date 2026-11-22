//! Re-exports the Uniswap v3 module. The executor implements [`keyshare_uniswap::SwapHost`]
//! and re-checks every transaction against that module's grant before signing.

pub use keyshare_uniswap::{SwapRequest, swap};
