//! Hyperliquid signing and trading guardrails (design §8). Pure: no network.
//!
//! Orders, cancels, modifies and leverage changes are **L1 actions**, signed by the bot's agent
//! key. Approving an agent is a **user-signed action**, signed by the master (the bot's wallet
//! key). Both end in an EIP-712 payload, so every signer still gets the full payload.
//! Encoding follows the official Python SDK (`hyperliquid/utils/signing.py`); the tests use its
//! vectors.

use alloy::dyn_abi::TypedData;
use alloy::primitives::{Address, B256, Signature, keccak256};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::price::UsdMicros;
use crate::refusal::{Refusal, RefusalCode};

/// Hyperliquid's L1 signing domain uses this chain id whatever chain the wallet is on.
const L1_CHAIN_ID: u64 = 1337;
/// `signatureChainId` the SDK uses for user-signed actions (Arbitrum Sepolia).
pub const USER_SIGNATURE_CHAIN_ID: u64 = 0x66eee;
/// Fixed-point scale for sizes and prices: Hyperliquid accepts at most 8 decimals.
pub const E8: i128 = 100_000_000;

/// A decimal with exactly 8 implied decimals. Parsed from strings so no float ever rounds.
pub fn parse_e8(s: &str) -> Result<i128, String> {
    let s = s.trim();
    let (neg, digits) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let (int, frac) = digits.split_once('.').unwrap_or((digits, ""));
    let ok = |p: &str| p.bytes().all(|b| b.is_ascii_digit());
    if int.is_empty() && frac.is_empty() || !ok(int) || !ok(frac) {
        return Err(format!("{s:?} is not a decimal number"));
    }
    if frac.len() > 8 {
        return Err(format!("{s:?} has more than 8 decimals"));
    }
    let int: i128 = if int.is_empty() { 0 } else { int.parse().map_err(|_| format!("{s:?} is too large"))? };
    let frac: i128 = format!("{frac:0<8}").parse().map_err(|_| format!("{s:?} is not a decimal number"))?;
    let v = int.checked_mul(E8).and_then(|v| v.checked_add(frac)).ok_or_else(|| format!("{s:?} is too large"))?;
    Ok(if neg { -v } else { v })
}

/// Hyperliquid's wire form: no trailing zeros, no trailing dot (the SDK's `float_to_wire`).
pub fn wire_e8(v: i128) -> String {
    let sign = if v < 0 { "-" } else { "" };
    let (int, frac) = (v.abs() / E8, v.abs() % E8);
    if frac == 0 {
        return format!("{sign}{int}");
    }
    let frac = format!("{frac:08}");
    format!("{sign}{int}.{}", frac.trim_end_matches('0'))
}

/// Number of decimals in a wire string.
pub fn decimals(wire: &str) -> u32 {
    wire.split_once('.').map_or(0, |(_, f)| f.len() as u32)
}

/// `|size × price|` in micro-USD, rounded up. Inputs are `E8` fixed point.
pub fn notional_usd(sz_e8: i128, px_e8: i128) -> UsdMicros {
    // Saturates rather than wraps: an absurd size reads as an absurd notional and is refused.
    let p = sz_e8.unsigned_abs().saturating_mul(px_e8.unsigned_abs());
    p.div_ceil(10_000_000_000)
}

// ---- wire types. Field order is part of the hash: keep it as the SDK writes it. ----

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tif {
    Alo,
    Ioc,
    Gtc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tpsl {
    Tp,
    Sl,
}

#[derive(Debug, Clone, Serialize)]
pub struct LimitWire {
    pub tif: Tif,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TriggerWire {
    pub is_market: bool,
    pub trigger_px: String,
    pub tpsl: Tpsl,
}

/// `{"limit": …}` or `{"trigger": …}`. A struct, not an enum, so msgpack writes a plain map.
#[derive(Debug, Clone, Serialize)]
pub struct OrderTypeWire {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<LimitWire>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger: Option<TriggerWire>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OrderWire {
    pub a: u32,
    pub b: bool,
    pub p: String,
    pub s: String,
    pub r: bool,
    pub t: OrderTypeWire,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CancelWire {
    pub a: u32,
    pub o: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModifyWire {
    pub oid: u64,
    pub order: OrderWire,
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum L1Action {
    Order {
        #[serde(rename = "type")]
        kind: &'static str,
        orders: Vec<OrderWire>,
        grouping: &'static str,
    },
    Cancel {
        #[serde(rename = "type")]
        kind: &'static str,
        cancels: Vec<CancelWire>,
    },
    Modify {
        #[serde(rename = "type")]
        kind: &'static str,
        modifies: Vec<ModifyWire>,
    },
    UpdateLeverage {
        #[serde(rename = "type")]
        kind: &'static str,
        asset: u32,
        #[serde(rename = "isCross")]
        is_cross: bool,
        leverage: u32,
    },
}

impl L1Action {
    pub fn order(orders: Vec<OrderWire>) -> Self {
        Self::Order { kind: "order", orders, grouping: "na" }
    }

    pub fn cancel(cancels: Vec<CancelWire>) -> Self {
        Self::Cancel { kind: "cancel", cancels }
    }

    pub fn modify(modifies: Vec<ModifyWire>) -> Self {
        Self::Modify { kind: "batchModify", modifies }
    }

    pub fn update_leverage(asset: u32, is_cross: bool, leverage: u32) -> Self {
        Self::UpdateLeverage { kind: "updateLeverage", asset, is_cross, leverage }
    }
}

/// `keccak(msgpack(action) ‖ nonce ‖ vault flag ‖ expiry)`, the phantom agent's connection id.
pub fn action_hash<T: Serialize>(
    action: &T,
    vault: Option<Address>,
    nonce: u64,
    expires_after: Option<u64>,
) -> Result<B256, String> {
    let mut data = rmp_serde::to_vec_named(action).map_err(|e| e.to_string())?;
    data.extend_from_slice(&nonce.to_be_bytes());
    match vault {
        None => data.push(0),
        Some(v) => {
            data.push(1);
            data.extend_from_slice(v.as_slice());
        }
    }
    if let Some(t) = expires_after {
        data.push(0);
        data.extend_from_slice(&t.to_be_bytes());
    }
    Ok(keccak256(data))
}

/// The EIP-712 payload an agent signs for an L1 action.
pub fn l1_typed_data(connection_id: B256, mainnet: bool) -> TypedData {
    let v = json!({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"}
            ],
            "Agent": [
                {"name": "source", "type": "string"},
                {"name": "connectionId", "type": "bytes32"}
            ]
        },
        "primaryType": "Agent",
        "domain": {"name": "Exchange", "version": "1", "chainId": L1_CHAIN_ID, "verifyingContract": Address::ZERO},
        "message": {"source": if mainnet { "a" } else { "b" }, "connectionId": connection_id}
    });
    // The JSON above is fixed and well formed.
    serde_json::from_value(v).unwrap_or_else(|e| unreachable!("l1 typed data: {e}"))
}

pub fn chain_name(mainnet: bool) -> &'static str {
    if mainnet { "Mainnet" } else { "Testnet" }
}

/// EIP-712 payload for a user-signed action (`HyperliquidTransaction:<primary>`). `fields` are
/// `(name, solidity type)` in signing order; `message` must hold each of them.
pub fn user_signed_typed_data(primary: &str, fields: &[(&str, &str)], message: serde_json::Value) -> TypedData {
    let primary = format!("HyperliquidTransaction:{primary}");
    let fields: Vec<_> = fields.iter().map(|(n, t)| json!({"name": n, "type": t})).collect();
    let v = json!({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"}
            ],
            primary.clone(): fields
        },
        "primaryType": primary,
        "domain": {
            "name": "HyperliquidSignTransaction",
            "version": "1",
            "chainId": USER_SIGNATURE_CHAIN_ID,
            "verifyingContract": Address::ZERO
        },
        "message": message
    });
    serde_json::from_value(v).unwrap_or_else(|e| unreachable!("user-signed typed data: {e}"))
}

/// The `approveAgent` action (posted as-is) and the payload the master signs for it.
pub fn approve_agent(agent: Address, name: &str, nonce: u64, mainnet: bool) -> (serde_json::Value, TypedData) {
    let action = json!({
        "type": "approveAgent",
        "signatureChainId": format!("{USER_SIGNATURE_CHAIN_ID:#x}"),
        "hyperliquidChain": chain_name(mainnet),
        "agentAddress": agent,
        "agentName": name,
        "nonce": nonce,
    });
    let data = user_signed_typed_data(
        "ApproveAgent",
        &[("hyperliquidChain", "string"), ("agentAddress", "address"), ("agentName", "string"), ("nonce", "uint64")],
        action.clone(),
    );
    (action, data)
}

/// Signature in the `{r, s, v}` shape the exchange expects.
pub fn signature_json(sig: &Signature) -> serde_json::Value {
    json!({ "r": format!("{:#x}", sig.r()), "s": format!("{:#x}", sig.s()), "v": 27 + u8::from(sig.v()) })
}

// ---- guardrails ----

/// Per-bot trading limits, checked by the connector before the agent key signs (design §8).
/// Reduce-only orders skip the size caps and the loss stop: they can only shrink risk.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HlPolicy {
    /// Coins this bot may trade, e.g. `["ETH", "BTC"]`. Empty means none.
    pub markets: Vec<String>,
    /// Largest single order, size × limit price, in whole USD.
    pub max_order_usd: u64,
    /// Largest position in one coin after this order and every same-side resting order fill, in
    /// whole USD at max(limit, mark).
    pub max_position_usd: u64,
    pub max_leverage: u32,
    /// New risk stops once account value falls this far below its value at the first order of
    /// the UTC day. Deposits and withdrawals during the day move it too.
    pub daily_loss_stop_usd: u64,
}

/// What the connector knows about an order when it checks it.
pub struct OrderCheck<'a> {
    pub coin: &'a str,
    pub reduce_only: bool,
    pub sz_e8: i128,
    /// Price the order is valued at: the larger of its limit and the coin's mark, so a sell
    /// with a token limit can't hide its size. `E8`.
    pub px_e8: i128,
    /// Signed position size if this order and every same-side resting order fill, `E8`.
    pub position_after_e8: i128,
    /// The account's current leverage on this coin; orders use it, not a per-order value.
    pub leverage: u32,
    /// Account value at the start of the UTC day minus now, `E8`. Negative is a gain.
    pub loss_today_e8: i128,
}

fn usd_micros(whole: u64) -> UsdMicros {
    u128::from(whole) * 1_000_000
}

fn usd_str(micros: UsdMicros) -> String {
    format!("{}.{:02}", micros / 1_000_000, (micros % 1_000_000) / 10_000)
}

impl HlPolicy {
    pub fn check_market(&self, coin: &str) -> Result<(), Refusal> {
        if self.markets.iter().any(|m| m == coin) {
            Ok(())
        } else {
            Err(Refusal::new(RefusalCode::MarketNotAllowed, format!("{coin} is not on this bot's market list")))
        }
    }

    pub fn check_order(&self, o: &OrderCheck<'_>) -> Result<(), Refusal> {
        self.check_market(o.coin)?;
        if o.reduce_only {
            return Ok(());
        }
        if o.leverage > self.max_leverage {
            return Err(Refusal::new(
                RefusalCode::LeverageTooHigh,
                format!(
                    "{} is at {}x, over this bot's {}x; call hl_set_leverage first",
                    o.coin, o.leverage, self.max_leverage
                ),
            ));
        }
        let order = notional_usd(o.sz_e8, o.px_e8);
        if order > usd_micros(self.max_order_usd) {
            return Err(Refusal::new(
                RefusalCode::OrderTooLarge,
                format!("order is ${}, over the ${} per-order cap", usd_str(order), self.max_order_usd),
            ));
        }
        let position = notional_usd(o.position_after_e8, o.px_e8);
        if position > usd_micros(self.max_position_usd) {
            return Err(Refusal::new(
                RefusalCode::PositionTooLarge,
                format!("{} position would be ${}, over the ${} cap", o.coin, usd_str(position), self.max_position_usd),
            ));
        }
        let loss = o.loss_today_e8.max(0).unsigned_abs() / 100; // E8 -> micros
        if loss >= usd_micros(self.daily_loss_stop_usd) {
            return Err(Refusal::new(
                RefusalCode::DailyLossStop,
                format!(
                    "down ${} today, at the ${} daily loss stop; only reduce-only orders until 00:00 UTC",
                    usd_str(loss),
                    self.daily_loss_stop_usd
                ),
            ));
        }
        Ok(())
    }

    pub fn check_leverage(&self, coin: &str, leverage: u32) -> Result<(), Refusal> {
        self.check_market(coin)?;
        if leverage == 0 || leverage > self.max_leverage {
            return Err(Refusal::new(
                RefusalCode::LeverageTooHigh,
                format!("leverage {leverage}x is outside 1x to {}x", self.max_leverage),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::{LocalSigner, Signer};

    /// The SDK's test key.
    const KEY: &str = "0x0123456789012345678901234567890123456789012345678901234567890123";

    fn sign_l1<T: Serialize>(action: &T, nonce: u64, mainnet: bool) -> serde_json::Value {
        let hash = action_hash(action, None, nonce, None).unwrap();
        let sig = LocalSigner::from_hex(KEY).unwrap().sign_typed_data(&l1_typed_data(hash, mainnet)).unwrap();
        signature_json(&sig)
    }

    fn rsv(r: &str, s: &str, v: u8) -> serde_json::Value {
        json!({"r": r, "s": s, "v": v})
    }

    fn limit(a: u32, b: bool, px: &str, sz: &str, tif: Tif) -> OrderWire {
        OrderWire {
            a,
            b,
            p: wire_e8(parse_e8(px).unwrap()),
            s: wire_e8(parse_e8(sz).unwrap()),
            r: false,
            t: OrderTypeWire { limit: Some(LimitWire { tif }), trigger: None },
            c: None,
        }
    }

    #[test]
    fn wire_decimals_match_sdk() {
        for (input, wire) in [("100", "100"), ("0.0147", "0.0147"), ("1670.1", "1670.1"), ("1.50000000", "1.5")] {
            assert_eq!(wire_e8(parse_e8(input).unwrap()), wire);
        }
        assert_eq!(wire_e8(parse_e8("-0.00000000").unwrap()), "0");
        assert!(parse_e8("0.000000001").is_err());
        assert!(parse_e8("1e5").is_err());
        assert!(parse_e8("").is_err());
        assert_eq!(notional_usd(parse_e8("0.5").unwrap(), parse_e8("2000.01").unwrap()), 1_000_005_000);
    }

    #[test]
    fn phantom_agent_matches_sdk() {
        let action = L1Action::order(vec![limit(4, true, "1670.1", "0.0147", Tif::Ioc)]);
        let hash = action_hash(&action, None, 1677777606040, None).unwrap();
        assert_eq!(hash.to_string(), "0x0fcbeda5ae3c4950a548021552a4fea2226858c4453571bf3f24ba017eac2908");
    }

    #[test]
    fn l1_signatures_match_sdk() {
        #[derive(Serialize)]
        struct Dummy {
            #[serde(rename = "type")]
            kind: &'static str,
            num: u64,
        }
        let dummy = Dummy { kind: "dummy", num: 100_000_000_000 };
        assert_eq!(
            sign_l1(&dummy, 0, true),
            rsv(
                "0x53749d5b30552aeb2fca34b530185976545bb22d0b3ce6f62e31be961a59298",
                "0x755c40ba9bf05223521753995abb2f73ab3229be8ec921f350cb447e384d8ed8",
                27
            )
        );
        assert_eq!(
            sign_l1(&dummy, 0, false),
            rsv(
                "0x542af61ef1f429707e3c76c5293c80d01f74ef853e34b76efffcb57e574f9510",
                "0x17b8b32f086e8cdede991f1e2c529f5dd5297cbe8128500e00cbaf766204a613",
                28
            )
        );

        let order = L1Action::order(vec![limit(1, true, "100", "100", Tif::Gtc)]);
        assert_eq!(
            sign_l1(&order, 0, true),
            rsv(
                "0xd65369825a9df5d80099e513cce430311d7d26ddf477f5b3a33d2806b100d78e",
                "0x2b54116ff64054968aa237c20ca9ff68000f977c93289157748a3162b6ea940e",
                28
            )
        );
        assert_eq!(
            sign_l1(&order, 0, false),
            rsv(
                "0x82b2ba28e76b3d761093aaded1b1cdad4960b3af30212b343fb2e6cdfa4e3d54",
                "0x6b53878fc99d26047f4d7e8c90eb98955a109f44209163f52d8dc4278cbbd9f5",
                27
            )
        );
    }

    #[test]
    fn trigger_order_matches_sdk() {
        let mut wire = limit(1, true, "100", "100", Tif::Gtc);
        wire.t = OrderTypeWire {
            limit: None,
            trigger: Some(TriggerWire { is_market: true, trigger_px: "103".into(), tpsl: Tpsl::Sl }),
        };
        let order = L1Action::order(vec![wire]);
        assert_eq!(
            sign_l1(&order, 0, true),
            rsv(
                "0x98343f2b5ae8e26bb2587daad3863bc70d8792b09af1841b6fdd530a2065a3f9",
                "0x6b5bb6bb0633b710aa22b721dd9dee6d083646a5f8e581a20b545be6c1feb405",
                27
            )
        );
        assert_eq!(
            sign_l1(&order, 0, false),
            rsv(
                "0x971c554d917c44e0e1b6cc45d8f9404f32172a9d3b3566262347d0302896a2e4",
                "0x206257b104788f80450f8e786c329daa589aa0b32ba96948201ae556d5637eac",
                28
            )
        );
    }

    #[test]
    fn user_signed_action_matches_sdk() {
        // The SDK's usd_transfer vector: same domain and scheme as approveAgent.
        let msg = json!({
            "hyperliquidChain": "Testnet",
            "destination": "0x5e9ee1089755c3435139848e47e6635505d5a13a",
            "amount": "1",
            "time": 1687816341423u64,
        });
        let data = user_signed_typed_data(
            "UsdSend",
            &[("hyperliquidChain", "string"), ("destination", "string"), ("amount", "string"), ("time", "uint64")],
            msg,
        );
        let sig = LocalSigner::from_hex(KEY).unwrap().sign_typed_data(&data).unwrap();
        assert_eq!(
            signature_json(&sig),
            rsv(
                "0x637b37dd731507cdd24f46532ca8ba6eec616952c56218baeff04144e4a77073",
                "0x11a6a24900e6e314136d2592e2f8d502cd89b7c15b198e1bee043c9589f9fad7",
                27
            )
        );
    }

    #[test]
    fn approve_agent_recovers_to_master() {
        let master = LocalSigner::from_hex(KEY).unwrap();
        let agent = LocalSigner::random().address();
        let (action, data) = approve_agent(agent, "keyshare-filltape", 1, false);
        assert_eq!(action["hyperliquidChain"], "Testnet");
        assert_eq!(action["signatureChainId"], "0x66eee");
        let sig = master.sign_typed_data(&data).unwrap();
        let hash = data.eip712_signing_hash().unwrap();
        assert_eq!(sig.recover_address_from_prehash(&hash).unwrap(), master.address());
    }

    fn policy() -> HlPolicy {
        HlPolicy {
            markets: vec!["ETH".into()],
            max_order_usd: 1_000,
            max_position_usd: 2_000,
            max_leverage: 5,
            daily_loss_stop_usd: 100,
        }
    }

    fn check(coin: &str, sz: &str, px: &str, after: &str, loss: &str, reduce_only: bool) -> Result<(), RefusalCode> {
        policy()
            .check_order(&OrderCheck {
                coin,
                reduce_only,
                sz_e8: parse_e8(sz).unwrap(),
                px_e8: parse_e8(px).unwrap(),
                position_after_e8: parse_e8(after).unwrap(),
                leverage: 3,
                loss_today_e8: parse_e8(loss).unwrap(),
            })
            .map_err(|r| r.code)
    }

    #[test]
    fn guardrails() {
        assert_eq!(check("ETH", "0.4", "2500", "0.4", "0", false), Ok(()));
        assert_eq!(check("BTC", "0.01", "60000", "0.01", "0", false), Err(RefusalCode::MarketNotAllowed));
        assert_eq!(check("BTC", "0.01", "60000", "0", "0", true), Err(RefusalCode::MarketNotAllowed));
        assert_eq!(check("ETH", "0.41", "2500", "0.41", "0", false), Err(RefusalCode::OrderTooLarge));
        assert_eq!(check("ETH", "0.4", "2500", "-0.81", "0", false), Err(RefusalCode::PositionTooLarge));
        assert_eq!(check("ETH", "0.4", "2500", "0.4", "100", false), Err(RefusalCode::DailyLossStop));
        assert_eq!(check("ETH", "0.4", "2500", "0.4", "-500", false), Ok(()));
        // Reduce-only gets through even at the stop and over the caps.
        assert_eq!(check("ETH", "5", "2500", "0", "1000", true), Ok(()));
        let mut high = OrderCheck {
            coin: "ETH",
            reduce_only: false,
            sz_e8: E8,
            px_e8: E8,
            position_after_e8: E8,
            leverage: 20,
            loss_today_e8: 0,
        };
        assert_eq!(policy().check_order(&high).map_err(|r| r.code), Err(RefusalCode::LeverageTooHigh));
        high.reduce_only = true;
        assert_eq!(policy().check_order(&high).map_err(|r| r.code), Ok(()));
        assert_eq!(notional_usd(i128::MAX, i128::MAX), u128::MAX.div_ceil(10_000_000_000));
        assert_eq!(policy().check_leverage("ETH", 5).map_err(|r| r.code), Ok(()));
        assert_eq!(policy().check_leverage("ETH", 6).map_err(|r| r.code), Err(RefusalCode::LeverageTooHigh));
        assert_eq!(policy().check_leverage("ETH", 0).map_err(|r| r.code), Err(RefusalCode::LeverageTooHigh));
    }
}
