//! USD values for caps. Amounts are integer micro-dollars (1 USD = 1_000_000) so cap math never
//! touches floats. Phase 0 reads fixed prices from config. A signed oracle quote with a staleness
//! bound (design §6.4) replaces [`PriceTable`] behind the same [`PriceSource`] trait.

use std::collections::HashMap;

use alloy::primitives::{Address, U256};
use serde::Deserialize;

pub type UsdMicros = u128;
pub const MICROS_PER_USD: UsdMicros = 1_000_000;

/// `None` is the chain's native token.
pub type Token = Option<Address>;

pub trait PriceSource: Send + Sync {
    /// Micro-USD value of `amount` base units of `token`, or `None` if the token has no price.
    fn value_usd(&self, chain_id: u64, token: Token, amount: U256) -> Option<UsdMicros>;
}

#[derive(Debug, Clone, Deserialize)]
pub struct PriceEntry {
    pub chain_id: u64,
    /// Omit for the native token.
    pub token: Option<Address>,
    pub decimals: u8,
    /// Decimal string, e.g. "2500.00". Stablecoins are "1".
    pub usd: String,
}

#[derive(Debug, Default)]
pub struct PriceTable {
    /// (chain, token) -> (decimals, micro-USD per whole token)
    prices: HashMap<(u64, Token), (u8, UsdMicros)>,
}

#[derive(Debug, thiserror::Error)]
#[error("bad price {0:?}: expected a decimal like \"2500.50\"")]
pub struct BadPrice(String);

impl PriceTable {
    pub fn from_entries(entries: &[PriceEntry]) -> Result<Self, BadPrice> {
        let mut prices = HashMap::new();
        for e in entries {
            prices.insert((e.chain_id, e.token), (e.decimals, parse_usd(&e.usd)?));
        }
        Ok(Self { prices })
    }
}

impl PriceSource for PriceTable {
    fn value_usd(&self, chain_id: u64, token: Token, amount: U256) -> Option<UsdMicros> {
        let (decimals, per_token) = *self.prices.get(&(chain_id, token))?;
        // Round up so a cap can't be dodged by dust-sized rounding.
        let numerator = amount.checked_mul(U256::from(per_token))?;
        let denominator = U256::from(10u8).pow(U256::from(decimals));
        let value = numerator.div_ceil(denominator);
        u128::try_from(value).ok()
    }
}

/// Parses a non-negative decimal string into micro-USD.
pub fn parse_usd(s: &str) -> Result<UsdMicros, BadPrice> {
    let bad = || BadPrice(s.to_string());
    let (whole, frac) = s.trim().split_once('.').unwrap_or((s.trim(), ""));
    if whole.is_empty() || frac.len() > 6 || !(whole.chars().chain(frac.chars()).all(|c| c.is_ascii_digit())) {
        return Err(bad());
    }
    let whole: UsdMicros = whole.parse().map_err(|_| bad())?;
    let frac: UsdMicros = if frac.is_empty() { 0 } else { format!("{frac:0<6}").parse().map_err(|_| bad())? };
    whole.checked_mul(MICROS_PER_USD).and_then(|w| w.checked_add(frac)).ok_or_else(bad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_decimals() {
        assert_eq!(parse_usd("1").unwrap(), 1_000_000);
        assert_eq!(parse_usd("2500.5").unwrap(), 2_500_500_000);
        assert_eq!(parse_usd("0.000001").unwrap(), 1);
        assert!(parse_usd("-1").is_err());
        assert!(parse_usd("1.0000001").is_err());
        assert!(parse_usd("abc").is_err());
        assert!(parse_usd(".5").is_err());
    }

    #[test]
    fn values_native_and_tokens() {
        let usdc: Address = "0x036CbD53842c5426634e7929541eC2318f3dCF7e".parse().unwrap();
        let table = PriceTable::from_entries(&[
            PriceEntry { chain_id: 1, token: None, decimals: 18, usd: "2000".into() },
            PriceEntry { chain_id: 1, token: Some(usdc), decimals: 6, usd: "1".into() },
        ])
        .unwrap();
        // 0.5 ETH at $2000 = $1000
        let half_eth = U256::from(5u64) * U256::from(10u64).pow(U256::from(17u8));
        assert_eq!(table.value_usd(1, None, half_eth), Some(1_000 * MICROS_PER_USD));
        // 250 USDC
        assert_eq!(table.value_usd(1, Some(usdc), U256::from(250_000_000u64)), Some(250 * MICROS_PER_USD));
        // 1 wei rounds up to one micro-dollar
        assert_eq!(table.value_usd(1, None, U256::from(1)), Some(1));
        assert_eq!(table.value_usd(2, None, U256::from(1)), None);
    }
}
