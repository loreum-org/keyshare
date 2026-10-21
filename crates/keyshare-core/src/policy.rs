//! Per-bot policy (design §6.1) checked in plain Rust. [`PolicyEngine`] is the seam where a
//! proof-based check can replace or sit beside [`PlainPolicy`] later without touching callers.

use alloy::consensus::TxEip1559;
use alloy::dyn_abi::TypedData;
use alloy::primitives::{Address, FixedBytes, TxKind, U256};
use alloy::sol;
use alloy::sol_types::SolCall;
use serde::{Deserialize, Serialize};

use crate::price::{MICROS_PER_USD, PriceSource, UsdMicros};
use crate::refusal::{Refusal, RefusalCode};

sol! {
    function transfer(address to, uint256 amount);
    function approve(address spender, uint256 amount);
    function setApprovalForAll(address operator, bool approved);

    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }
    /// Uniswap SwapRouter02.
    function exactInputSingle(ExactInputSingleParams params);
}

pub type Selector = FixedBytes<4>;

/// What a caller is asking to sign.
#[derive(Debug, Clone, Copy)]
pub enum Action<'a> {
    Transaction(&'a TxEip1559),
    Message(&'a [u8]),
    TypedData(&'a TypedData),
}

/// An approved action and the USD outflow to record against the caller's daily cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    pub outflow_usd: UsdMicros,
}

pub trait PolicyEngine: Send + Sync {
    /// `spent_24h` is the caller's rolling 24h spend from this signer's own counter (§6.4).
    fn check(&self, action: Action<'_>, spent_24h: UsdMicros, prices: &dyn PriceSource) -> Result<Verdict, Refusal>;

    /// The check for a request the wallet's owner approved with an admin key (design §13.2).
    /// Owner-waivable rules (allowlists, caps, the co-sign threshold) are skipped; hard rules
    /// (chains, denied primitives, pricing) still apply. Only transactions can be approved.
    fn check_owner_approved(&self, action: Action<'_>, prices: &dyn PriceSource) -> Result<Verdict, Refusal>;

    /// What the caller may see about its own limits (the `limits` tool). Allowlists are counted,
    /// not listed.
    fn limits(&self) -> Limits;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Limits {
    pub chains: Vec<u64>,
    pub per_tx_cap_usd: u64,
    pub daily_cap_usd: u64,
    pub recipients_allowed: usize,
    pub contracts_allowed: usize,
    pub typed_data_allowed: usize,
    pub max_slippage_bps: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ContractRule {
    pub addr: Address,
    pub selectors: Vec<Selector>,
}

/// One allowlisted kind of EIP-712 payload. It must name the domain's `verifying_contract`, so
/// another protocol's `Order` doesn't match. A domain `name` alone is enough only for domains
/// with no `chainId` (and so a `chainless` rule), since any contract can declare any name. Typed data with no `chainId` in its
/// domain matches only a rule marked `chainless`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedDataRule {
    pub primary_type: String,
    pub verifying_contract: Option<Address>,
    pub name: Option<String>,
    /// Required chain. Default: any of the policy's chains.
    pub chain_id: Option<u64>,
    #[serde(default)]
    pub chainless: bool,
}

impl TypedDataRule {
    fn matches(&self, data: &TypedData) -> bool {
        let d = &data.domain;
        let bound = self.verifying_contract.is_some() || (self.name.is_some() && d.chain_id.is_none());
        let chain_ok = match (d.chain_id, self.chain_id) {
            (None, _) => self.chainless,
            (Some(c), Some(want)) => c == U256::from(want),
            (Some(_), None) => true,
        };
        bound
            && chain_ok
            && self.primary_type == data.primary_type
            && self.verifying_contract.is_none_or(|v| d.verifying_contract == Some(v))
            && self.name.as_deref().is_none_or(|n| d.name.as_deref() == Some(n))
    }
}

/// Typed data that moves funds: never signed as raw typed data, because the policy can't value
/// it against the caps. Hyperliquid user-signed actions go through the `hl_*` tools instead.
fn moves_funds(primary_type: &str) -> bool {
    primary_type.starts_with("HyperliquidTransaction:")
        || matches!(
            primary_type,
            "Permit"
                | "PermitSingle"
                | "PermitBatch"
                | "PermitTransferFrom"
                | "PermitBatchTransferFrom"
                | "PermitWitnessTransferFrom"
                | "PermitBatchWitnessTransferFrom"
        )
}

/// Token functions that move or grant funds in ways the policy doesn't decode yet.
const UNDECODED_TOKEN_SELECTORS: [[u8; 4]; 8] = [
    [0x23, 0xb8, 0x72, 0xdd], // transferFrom (ERC-20 and ERC-721)
    [0x39, 0x50, 0x93, 0x51], // increaseAllowance
    [0xd5, 0x05, 0xac, 0xcf], // permit (EIP-2612)
    [0x8f, 0xcb, 0xaf, 0x0c], // permit (DAI)
    [0x42, 0x84, 0x2e, 0x0e], // safeTransferFrom(address,address,uint256)
    [0xb8, 0x8d, 0x4f, 0xde], // safeTransferFrom(address,address,uint256,bytes)
    [0xf2, 0x42, 0x43, 0x2a], // safeTransferFrom (ERC-1155)
    [0x2e, 0xb2, 0xc2, 0xd6], // safeBatchTransferFrom (ERC-1155)
];

/// Deny-by-default rules for one bot's wallet.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlainPolicy {
    pub chains: Vec<u64>,
    /// Whole US dollars.
    pub per_tx_cap_usd: u64,
    /// Whole US dollars, rolling 24h.
    pub daily_cap_usd: u64,
    #[serde(default)]
    pub recipients_allow: Vec<Address>,
    #[serde(default)]
    pub contracts_allow: Vec<ContractRule>,
    /// EIP-712 payloads this bot may sign, each bound to a primary type and its domain.
    #[serde(default)]
    pub typed_data_allow: Vec<TypedDataRule>,
    /// Sends worth more than this (whole USD) need the owner's approval even inside the caps.
    #[serde(default)]
    pub require_admin_cosign_above_usd: Option<u64>,
    /// Most slippage a swap may accept, in basis points (100 = 1%).
    #[serde(default = "default_slippage_bps")]
    pub max_slippage_bps: u32,
    /// A swap's minimum output, valued at configured prices, may be at most this far under its
    /// input (basis points). Covers slippage, pool fee and price-table drift. Default 500.
    #[serde(default = "default_price_deviation_bps")]
    pub max_price_deviation_bps: u32,
    /// The wallet's own address, set when the wallet is built. Swap output may go here without
    /// being on `recipients_allow`.
    #[serde(skip)]
    pub own_address: Option<Address>,
}

fn default_slippage_bps() -> u32 {
    100
}

fn default_price_deviation_bps() -> u32 {
    500
}

fn refuse(code: RefusalCode, reason: impl Into<String>) -> Refusal {
    Refusal::new(code, reason)
}

impl PlainPolicy {
    fn check_chain(&self, chain_id: u64) -> Result<(), Refusal> {
        if self.chains.contains(&chain_id) {
            Ok(())
        } else {
            Err(refuse(RefusalCode::ChainNotAllowed, format!("chain {chain_id} is not allowed")))
        }
    }

    fn check_recipient(&self, to: Address, approved: bool) -> Result<(), Refusal> {
        if approved || self.recipients_allow.contains(&to) {
            Ok(())
        } else {
            Err(refuse(RefusalCode::RecipientNotAllowed, format!("recipient {to} is not allowlisted")))
        }
    }

    fn contract_allows(&self, to: Address, selector: Selector) -> bool {
        self.contracts_allow.iter().any(|r| r.addr == to && r.selectors.contains(&selector))
    }

    fn is_allowlisted_contract(&self, addr: Address) -> bool {
        self.contracts_allow.iter().any(|r| r.addr == addr)
    }

    fn price(prices: &dyn PriceSource, chain: u64, token: Option<Address>, amount: U256) -> Result<UsdMicros, Refusal> {
        if amount.is_zero() {
            return Ok(0);
        }
        prices.value_usd(chain, token, amount).ok_or_else(|| {
            let what = token.map_or("native token".to_string(), |t| format!("token {t}"));
            refuse(RefusalCode::PriceUnavailable, format!("no USD price for {what} on chain {chain}"))
        })
    }

    /// Static rules for a transaction. Returns its USD outflow.
    fn check_transaction(
        &self,
        tx: &TxEip1559,
        prices: &dyn PriceSource,
        approved: bool,
    ) -> Result<UsdMicros, Refusal> {
        self.check_chain(tx.chain_id)?;
        let TxKind::Call(to) = tx.to else {
            return Err(refuse(RefusalCode::ContractNotAllowed, "contract creation is not allowed"));
        };
        let native = Self::price(prices, tx.chain_id, None, tx.value)?;
        let data = tx.input.as_ref();

        if data.is_empty() {
            self.check_recipient(to, approved)?;
            return Ok(native);
        }

        let selector = Selector::from_slice(
            data.get(..4)
                .ok_or_else(|| refuse(RefusalCode::ContractNotAllowed, "calldata shorter than a function selector"))?,
        );

        if UNDECODED_TOKEN_SELECTORS.contains(&selector.0) {
            return Err(refuse(RefusalCode::DeniedPrimitive, format!("{selector} can move funds the caps don't see")));
        }
        if selector == setApprovalForAllCall::SELECTOR {
            return Err(refuse(RefusalCode::DeniedPrimitive, "setApprovalForAll is always denied"));
        }
        if !approved && !self.contract_allows(to, selector) {
            return Err(refuse(RefusalCode::ContractNotAllowed, format!("call {selector} on {to} is not allowlisted")));
        }

        let token_outflow = if selector == transferCall::SELECTOR {
            let call = transferCall::abi_decode(data)
                .map_err(|e| refuse(RefusalCode::ContractNotAllowed, format!("bad transfer calldata: {e}")))?;
            self.check_recipient(call.to, approved)?;
            Self::price(prices, tx.chain_id, Some(to), call.amount)?
        } else if selector == approveCall::SELECTOR {
            let call = approveCall::abi_decode(data)
                .map_err(|e| refuse(RefusalCode::ContractNotAllowed, format!("bad approve calldata: {e}")))?;
            if call.amount == U256::MAX {
                return Err(refuse(RefusalCode::DeniedPrimitive, "unlimited approve is denied"));
            }
            if !approved && !self.is_allowlisted_contract(call.spender) {
                return Err(refuse(
                    RefusalCode::ContractNotAllowed,
                    format!("approve spender {} is not an allowlisted contract", call.spender),
                ));
            }
            // An approval can move that much later, so it counts as outflow now.
            Self::price(prices, tx.chain_id, Some(to), call.amount)?
        } else if selector == exactInputSingleCall::SELECTOR {
            let call = exactInputSingleCall::abi_decode(data)
                .map_err(|e| refuse(RefusalCode::ContractNotAllowed, format!("bad swap calldata: {e}")))?;
            let p = &call.params;
            // The input was already counted (approve, or native value); the output must not leave.
            if Some(p.recipient) != self.own_address {
                self.check_recipient(p.recipient, approved)?;
            }
            // The guaranteed output must be worth close to the input at configured prices. This
            // binds every route to the router, not only the swap tool: no zero minimum, no
            // unpriced output token, no quote taken from an already-pushed pool.
            // The larger of what is sent and what the router may pull: SwapRouter02 takes
            // `amountIn` of `tokenIn` by transferFrom when `msg.value` doesn't cover it.
            let value_in = native.max(Self::price(prices, tx.chain_id, Some(p.tokenIn), p.amountIn)?);
            let value_out = prices.value_usd(tx.chain_id, Some(p.tokenOut), p.amountOutMinimum).ok_or_else(|| {
                refuse(RefusalCode::PriceUnavailable, format!("swap output token {} has no USD price", p.tokenOut))
            })?;
            let floor = value_in * UsdMicros::from(10_000 - self.max_price_deviation_bps.min(10_000)) / 10_000;
            if value_out < floor {
                return Err(refuse(
                    RefusalCode::SlippageTooHigh,
                    format!(
                        "swap guarantees ${} for ${} in, more than {} bps under configured prices",
                        usd(value_out),
                        usd(value_in),
                        self.max_price_deviation_bps
                    ),
                ));
            }
            0
        } else {
            // Other allowlisted calls (e.g. a router) count native value only until simulation
            // asset deltas feed the check.
            0
        };

        native.checked_add(token_outflow).ok_or_else(|| refuse(RefusalCode::Internal, "USD value overflow"))
    }

    fn check_message(message: &[u8]) -> Result<(), Refusal> {
        let looks_like_tx = || refuse(RefusalCode::MessageLooksLikeTx, "only plain-text messages can be signed");
        let text = std::str::from_utf8(message).map_err(|_| looks_like_tx())?;
        let t = text.trim();
        let hex = t.strip_prefix("0x");
        let body = hex.unwrap_or(t);
        let all_hex = !body.is_empty() && body.chars().all(|c| c.is_ascii_hexdigit());
        // "0x…" of any length, or a long bare hex blob, is calldata or a hash, not text.
        if all_hex && (hex.is_some() || body.len() >= 40) {
            return Err(looks_like_tx());
        }
        Ok(())
    }

    fn check_typed_data(&self, data: &TypedData) -> Result<(), Refusal> {
        if moves_funds(&data.primary_type) {
            return Err(refuse(
                RefusalCode::DeniedPrimitive,
                format!("typed data {:?} moves funds outside the caps", data.primary_type),
            ));
        }
        if let Some(chain) = data.domain.chain_id {
            let chain = u64::try_from(chain)
                .map_err(|_| refuse(RefusalCode::ChainNotAllowed, "typed-data chainId out of range"))?;
            self.check_chain(chain)?;
        }
        if self.typed_data_allow.iter().any(|r| r.matches(data)) {
            Ok(())
        } else {
            Err(refuse(
                RefusalCode::TypedDataNotAllowed,
                format!("typed data {:?} with this domain is not allowlisted", data.primary_type),
            ))
        }
    }
}

impl PlainPolicy {
    fn evaluate(
        &self,
        action: Action<'_>,
        spent_24h: UsdMicros,
        prices: &dyn PriceSource,
        approved: bool,
    ) -> Result<Verdict, Refusal> {
        let outflow_usd = match action {
            Action::Transaction(tx) => self.check_transaction(tx, prices, approved)?,
            Action::Message(_) | Action::TypedData(_) if approved => {
                return Err(refuse(RefusalCode::BadApproval, "only transactions can be owner-approved"));
            }
            Action::Message(m) => {
                Self::check_message(m)?;
                0
            }
            Action::TypedData(d) => {
                self.check_typed_data(d)?;
                0
            }
        };
        if approved {
            return Ok(Verdict { outflow_usd });
        }

        let per_tx = UsdMicros::from(self.per_tx_cap_usd) * MICROS_PER_USD;
        if outflow_usd > per_tx {
            return Err(refuse(
                RefusalCode::PerTxCapExceeded,
                format!("${} is over the ${} per-transaction cap", usd(outflow_usd), self.per_tx_cap_usd),
            ));
        }
        let daily = UsdMicros::from(self.daily_cap_usd) * MICROS_PER_USD;
        if spent_24h.saturating_add(outflow_usd) > daily {
            return Err(refuse(
                RefusalCode::CapExceeded,
                format!(
                    "${} would take today's spend to ${} of a ${} daily cap",
                    usd(outflow_usd),
                    usd(spent_24h.saturating_add(outflow_usd)),
                    self.daily_cap_usd
                ),
            ));
        }
        if let Some(limit) = self.require_admin_cosign_above_usd
            && outflow_usd > UsdMicros::from(limit) * MICROS_PER_USD
        {
            return Err(refuse(
                RefusalCode::AdminApprovalRequired,
                format!("${} is over ${limit}, which needs the owner's approval", usd(outflow_usd)),
            ));
        }
        Ok(Verdict { outflow_usd })
    }
}

impl PolicyEngine for PlainPolicy {
    fn check(&self, action: Action<'_>, spent_24h: UsdMicros, prices: &dyn PriceSource) -> Result<Verdict, Refusal> {
        self.evaluate(action, spent_24h, prices, false)
    }

    fn check_owner_approved(&self, action: Action<'_>, prices: &dyn PriceSource) -> Result<Verdict, Refusal> {
        self.evaluate(action, 0, prices, true)
    }

    fn limits(&self) -> Limits {
        Limits {
            chains: self.chains.clone(),
            per_tx_cap_usd: self.per_tx_cap_usd,
            daily_cap_usd: self.daily_cap_usd,
            recipients_allowed: self.recipients_allow.len(),
            contracts_allowed: self.contracts_allow.len(),
            typed_data_allowed: self.typed_data_allow.len(),
            max_slippage_bps: self.max_slippage_bps,
        }
    }
}

fn usd(micros: UsdMicros) -> String {
    format!("{}.{:02}", micros / MICROS_PER_USD, (micros % MICROS_PER_USD) / 10_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::price::{PriceEntry, PriceTable};
    use alloy::primitives::{Bytes, address};

    const CHAIN: u64 = 84532;
    const USDC: Address = address!("0x036CbD53842c5426634e7929541eC2318f3dCF7e");
    const ROUTER: Address = address!("0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD");
    const FRIEND: Address = address!("0x1111111111111111111111111111111111111111");
    const STRANGER: Address = address!("0x2222222222222222222222222222222222222222");

    fn policy() -> PlainPolicy {
        toml::from_str(&format!(
            r#"
            chains = [{CHAIN}]
            per_tx_cap_usd = 200
            daily_cap_usd = 500
            recipients_allow = ["{FRIEND}"]
            [[typed_data_allow]]
            primary_type = "Order"
            verifying_contract = "{ROUTER}"
            chain_id = {CHAIN}

            [[contracts_allow]]
            addr = "{USDC}"
            selectors = ["0xa9059cbb", "0x095ea7b3"]

            [[contracts_allow]]
            addr = "{ROUTER}"
            selectors = ["0x3593564c"]
            "#
        ))
        .expect("policy toml")
    }

    fn prices() -> PriceTable {
        PriceTable::from_entries(&[
            PriceEntry { chain_id: CHAIN, token: None, decimals: 18, usd: "2000".into() },
            PriceEntry { chain_id: CHAIN, token: Some(USDC), decimals: 6, usd: "1".into() },
        ])
        .expect("prices")
    }

    fn eth(milli: u64) -> U256 {
        U256::from(milli) * U256::from(10u64).pow(U256::from(15u8))
    }

    fn tx(to: Address, value: U256, input: Vec<u8>) -> TxEip1559 {
        TxEip1559 { chain_id: CHAIN, to: TxKind::Call(to), value, input: Bytes::from(input), ..Default::default() }
    }

    fn usdc_transfer(to: Address, dollars: u64) -> TxEip1559 {
        let data = transferCall { to, amount: U256::from(dollars * 1_000_000) }.abi_encode();
        tx(USDC, U256::ZERO, data)
    }

    fn check(t: &TxEip1559, spent: UsdMicros) -> Result<Verdict, Refusal> {
        policy().check(Action::Transaction(t), spent, &prices())
    }

    fn code(r: Result<Verdict, Refusal>) -> RefusalCode {
        r.expect_err("should refuse").code
    }

    #[test]
    fn native_send_to_allowlisted_recipient() {
        // 0.05 ETH = $100
        assert_eq!(check(&tx(FRIEND, eth(50), vec![]), 0).unwrap().outflow_usd, 100 * MICROS_PER_USD);
    }

    #[test]
    fn native_send_to_stranger_is_refused() {
        assert_eq!(code(check(&tx(STRANGER, eth(1), vec![]), 0)), RefusalCode::RecipientNotAllowed);
    }

    #[test]
    fn prompt_injection_send_all_to_attacker_is_refused() {
        let t = usdc_transfer(STRANGER, 50);
        assert_eq!(code(check(&t, 0)), RefusalCode::RecipientNotAllowed);
    }

    #[test]
    fn wrong_chain_is_refused() {
        let mut t = tx(FRIEND, eth(1), vec![]);
        t.chain_id = 1;
        assert_eq!(code(check(&t, 0)), RefusalCode::ChainNotAllowed);
    }

    #[test]
    fn erc20_transfer_counts_token_value() {
        assert_eq!(check(&usdc_transfer(FRIEND, 150), 0).unwrap().outflow_usd, 150 * MICROS_PER_USD);
    }

    #[test]
    fn per_tx_and_daily_caps() {
        assert_eq!(code(check(&usdc_transfer(FRIEND, 201), 0)), RefusalCode::PerTxCapExceeded);
        assert!(check(&usdc_transfer(FRIEND, 200), 300 * MICROS_PER_USD).is_ok());
        assert_eq!(code(check(&usdc_transfer(FRIEND, 200), 301 * MICROS_PER_USD)), RefusalCode::CapExceeded);
    }

    #[test]
    fn swap_output_goes_to_self_or_an_allowlisted_recipient() {
        let mut p = policy();
        p.contracts_allow.push(ContractRule { addr: ROUTER, selectors: vec![exactInputSingleCall::SELECTOR.into()] });
        let me = address!("0x9999999999999999999999999999999999999999");
        p.own_address = Some(me);
        // 100 USDC in; `out` USDC-units out (USDC to USDC keeps the price math obvious).
        let swap = |recipient, token_out, out: u64| {
            let params = ExactInputSingleParams {
                tokenIn: USDC,
                tokenOut: token_out,
                fee: Default::default(),
                recipient,
                amountIn: U256::from(100_000_000u64),
                amountOutMinimum: U256::from(out),
                sqrtPriceLimitX96: Default::default(),
            };
            tx(ROUTER, U256::ZERO, exactInputSingleCall { params }.abi_encode())
        };
        let check = |t: TxEip1559| p.check(Action::Transaction(&t), 0, &prices());
        assert!(check(swap(me, USDC, 99_000_000)).is_ok());
        assert!(check(swap(FRIEND, USDC, 95_000_000)).is_ok(), "5% is the default limit");
        assert_eq!(code(check(swap(STRANGER, USDC, 99_000_000))), RefusalCode::RecipientNotAllowed);
        assert_eq!(code(check(swap(me, USDC, 94_999_999))), RefusalCode::SlippageTooHigh);
        assert_eq!(code(check(swap(me, USDC, 0))), RefusalCode::SlippageTooHigh, "no zero minimum");
        assert_eq!(code(check(swap(me, STRANGER, 99_000_000))), RefusalCode::PriceUnavailable);
        // A native value of 1 wei can't stand in for the amountIn the router will pull.
        let mut dust = swap(me, USDC, 0);
        dust.value = U256::from(1);
        assert_eq!(code(check(dust)), RefusalCode::SlippageTooHigh);
    }

    #[test]
    fn unlisted_selector_and_contract_are_refused() {
        let data = setApprovalForAllCall { operator: STRANGER, approved: true }.abi_encode();
        assert_eq!(code(check(&tx(USDC, U256::ZERO, data), 0)), RefusalCode::DeniedPrimitive);
        assert_eq!(code(check(&tx(STRANGER, U256::ZERO, vec![1, 2, 3, 4]), 0)), RefusalCode::ContractNotAllowed);
        assert_eq!(code(check(&tx(USDC, U256::ZERO, vec![1, 2, 3, 4]), 0)), RefusalCode::ContractNotAllowed);
        let deploy = TxEip1559 { chain_id: CHAIN, to: TxKind::Create, ..Default::default() };
        assert_eq!(code(check(&deploy, 0)), RefusalCode::ContractNotAllowed);
    }

    #[test]
    fn approvals_are_bounded() {
        let pull = [[0x23, 0xb8, 0x72, 0xdd].as_slice(), &[0u8; 96]].concat();
        assert_eq!(
            code(check(&tx(USDC, U256::ZERO, pull), 0)),
            RefusalCode::DeniedPrimitive,
            "transferFrom is refused even on an allowlisted token"
        );
        let unlimited = approveCall { spender: ROUTER, amount: U256::MAX }.abi_encode();
        assert_eq!(code(check(&tx(USDC, U256::ZERO, unlimited), 0)), RefusalCode::DeniedPrimitive);
        let to_stranger = approveCall { spender: STRANGER, amount: U256::from(1) }.abi_encode();
        assert_eq!(code(check(&tx(USDC, U256::ZERO, to_stranger), 0)), RefusalCode::ContractNotAllowed);
        let bounded = approveCall { spender: ROUTER, amount: U256::from(100_000_000u64) }.abi_encode();
        assert_eq!(check(&tx(USDC, U256::ZERO, bounded), 0).unwrap().outflow_usd, 100 * MICROS_PER_USD);
    }

    #[test]
    fn unpriced_token_is_refused() {
        let mut p = policy();
        let other = address!("0x3333333333333333333333333333333333333333");
        p.contracts_allow.push(ContractRule { addr: other, selectors: vec![transferCall::SELECTOR.into()] });
        let data = transferCall { to: FRIEND, amount: U256::from(1) }.abi_encode();
        let r = p.check(Action::Transaction(&tx(other, U256::ZERO, data)), 0, &prices());
        assert_eq!(code(r), RefusalCode::PriceUnavailable);
    }

    #[test]
    fn owner_approval_waives_soft_rules_only() {
        let p = policy();
        let ok = |t: &TxEip1559| p.check_owner_approved(Action::Transaction(t), &prices());
        // Unlisted recipient and over the caps: fine once the owner approves; outflow still counted.
        assert_eq!(ok(&usdc_transfer(STRANGER, 1_000)).unwrap().outflow_usd, 1_000 * MICROS_PER_USD);
        assert!(ok(&tx(STRANGER, U256::ZERO, vec![1, 2, 3, 4])).is_ok());
        // Hard rules still hold.
        let mut wrong_chain = tx(FRIEND, eth(1), vec![]);
        wrong_chain.chain_id = 1;
        assert_eq!(code(ok(&wrong_chain)), RefusalCode::ChainNotAllowed);
        let unlimited = approveCall { spender: ROUTER, amount: U256::MAX }.abi_encode();
        assert_eq!(code(ok(&tx(USDC, U256::ZERO, unlimited))), RefusalCode::DeniedPrimitive);
        let nft = setApprovalForAllCall { operator: STRANGER, approved: true }.abi_encode();
        assert_eq!(code(ok(&tx(USDC, U256::ZERO, nft))), RefusalCode::DeniedPrimitive);
        assert_eq!(code(p.check_owner_approved(Action::Message(b"hi"), &prices())), RefusalCode::BadApproval);
    }

    #[test]
    fn cosign_threshold_needs_owner() {
        let mut p = policy();
        p.require_admin_cosign_above_usd = Some(100);
        assert!(p.check(Action::Transaction(&usdc_transfer(FRIEND, 100)), 0, &prices()).is_ok());
        let r = p.check(Action::Transaction(&usdc_transfer(FRIEND, 101)), 0, &prices());
        assert_eq!(code(r), RefusalCode::AdminApprovalRequired);
    }

    #[test]
    fn messages_must_be_plain_text() {
        let p = policy();
        let ok = |m: &[u8]| p.check(Action::Message(m), 0, &prices());
        assert!(ok(b"Sign in to example.com").is_ok());
        assert_eq!(code(ok(b"0xdeadbeef")), RefusalCode::MessageLooksLikeTx);
        assert_eq!(code(ok("a".repeat(64).as_bytes())), RefusalCode::MessageLooksLikeTx);
        assert_eq!(code(ok(&[0xff, 0xfe])), RefusalCode::MessageLooksLikeTx);
    }

    #[test]
    fn typed_data_is_deny_by_default() {
        let p = policy();
        let make = |primary: &str, domain: serde_json::Value| -> TypedData {
            serde_json::from_value(serde_json::json!({
                "types": {
                    "EIP712Domain": [{"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}],
                    primary: [{"name": "amount", "type": "uint256"}]
                },
                "primaryType": primary,
                "domain": domain,
                "message": {"amount": "1"}
            }))
            .expect("typed data")
        };
        let ok = serde_json::json!({"chainId": CHAIN, "verifyingContract": ROUTER});
        let check = |d: &TypedData| p.check(Action::TypedData(d), 0, &prices()).map_err(|r| r.code);
        assert!(check(&make("Order", ok.clone())).is_ok());
        assert_eq!(check(&make("Permit", ok.clone())), Err(RefusalCode::DeniedPrimitive));
        assert_eq!(check(&make("HyperliquidTransaction:UsdSend", ok)), Err(RefusalCode::DeniedPrimitive));
        // Same type name, another protocol's contract.
        let other = serde_json::json!({"chainId": CHAIN, "verifyingContract": STRANGER});
        assert_eq!(check(&make("Order", other)), Err(RefusalCode::TypedDataNotAllowed));
        // No chainId: only a chainless rule matches.
        assert_eq!(
            check(&make("Order", serde_json::json!({"verifyingContract": ROUTER}))),
            Err(RefusalCode::TypedDataNotAllowed)
        );
        assert_eq!(
            check(&make("Order", serde_json::json!({"chainId": 1, "verifyingContract": ROUTER}))),
            Err(RefusalCode::ChainNotAllowed)
        );
    }

    #[test]
    fn name_only_rule_needs_chainless() {
        let rule = |chainless| TypedDataRule {
            primary_type: "Order".into(),
            verifying_contract: None,
            name: Some("Exchange".into()),
            chain_id: None,
            chainless,
        };
        let data = |domain: serde_json::Value| -> TypedData {
            serde_json::from_value(serde_json::json!({
                "types": {"EIP712Domain": [], "Order": [{"name": "amount", "type": "uint256"}]},
                "primaryType": "Order",
                "domain": domain,
                "message": {"amount": "1"}
            }))
            .expect("typed data")
        };
        // Any contract can call itself "Exchange", so a name-only rule never matches a chain domain.
        let spoof = data(serde_json::json!({"name": "Exchange", "chainId": CHAIN, "verifyingContract": STRANGER}));
        assert!(!rule(false).matches(&spoof));
        assert!(!rule(true).matches(&spoof));
        assert!(rule(true).matches(&data(serde_json::json!({"name": "Exchange"}))));
    }

    #[test]
    fn undecoded_selectors_cover_nft_and_dai_permit() {
        use alloy::primitives::keccak256;
        for sig in [
            "permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)",
            "safeTransferFrom(address,address,uint256)",
            "safeTransferFrom(address,address,uint256,bytes)",
            "safeTransferFrom(address,address,uint256,uint256,bytes)",
            "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)",
        ] {
            let sel: [u8; 4] = keccak256(sig)[..4].try_into().unwrap();
            assert!(UNDECODED_TOKEN_SELECTORS.contains(&sel), "{sig}");
        }
    }
}
