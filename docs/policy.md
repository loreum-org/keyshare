# Policy

Every bot has a policy in the config. Everything is denied unless the policy allows it. This page explains what is checked and in what order.

The same check runs twice: once before anything touches the chain, so a bad request fails fast with a clear reason, and again on the final transaction just before signing, after nonce and gas are filled in.

## Transactions (`send`, `call_contract`, `swap`)

1. **Kill switch.** A frozen bot is refused.
2. **Chain.** The chain must be in the bot's `chains` list and have an RPC configured.
3. **No contract creation.** Deploying contracts is always refused.
4. **What kind of call it is.**
   - **Plain send** (no calldata): the recipient must be on `recipients_allow` for this chain.
   - **Contract call**: the contract and the function selector must be on `contracts_allow` for this chain.
5. **Calls that are always refused**, even if allowlisted:
   - `setApprovalForAll` (hands over every NFT in a collection)
   - unlimited `approve` (an approval for the maximum amount)
   - `transferFrom`, `increaseAllowance`, `permit` (both the standard and the DAI kind), and the NFT `safeTransferFrom` / `safeBatchTransferFrom` functions. These move or grant funds in ways the caps can't see, so they are blocked rather than allowed blind.
6. **Decoded calls get extra checks.**
   - ERC-20 `transfer`: the recipient inside the call must be allowlisted, and the amount counts against the caps.
   - ERC-20 `approve`: the spender must be an allowlisted contract, and the approved amount counts against the caps right away, since the spender can take it later.
   - Uniswap `exactInputSingle`: the output must go to the bot's own wallet (or an allowlisted recipient), and the guaranteed minimum output must be worth close to what goes in. See [Swaps](swaps.md).
7. **Value.** Everything that leaves the wallet is priced in USD using the config's price table: native value plus any decoded token amount. A token with no price is refused.
8. **Caps.**
   - Over `per_tx_cap_usd`: refused (`PER_TX_CAP_EXCEEDED`).
   - Would take the rolling 24-hour total over `daily_cap_usd`: refused (`CAP_EXCEEDED`).
   - Over `require_admin_cosign_above_usd`, if set: needs the owner (`ADMIN_APPROVAL_REQUIRED`).
9. **Simulation.** The call is simulated on the chain. If it would revert, it is refused (`SIM_REVERT`).
10. **Record, then sign.** The spend is written to the spend log before the signature is returned, so a crash can't lose a spend that was signed.

Some refusals can be overridden by the owner: an unlisted recipient or contract, a cap, or the co-sign threshold. If the bot has `admin_keys`, those requests are held for the owner instead of refused. Everything else (wrong chain, blocked calls, missing prices, reverts) can never be overridden. See [Owner approvals](owner-approvals.md).

## Chains in allowlists

The same address can be a different contract on another chain. Each `contracts_allow` rule and each recipient can name the chains it applies to:

```toml
recipients_allow = [
  "0x1111...",                                         # any of the bot's chains
  { addr = "0x2222...", chains = [11155111] },         # Sepolia only
]

[[bots.filltape.policy.contracts_allow]]
addr = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"   # Sepolia USDC
selectors = ["0xa9059cbb"]
chains = [11155111]
```

A rule with no `chains`, or an empty list, applies to every chain in the bot's `chains`.

## What the caps count

- Native value sent.
- ERC-20 amounts in decoded `transfer` and `approve` calls.
- For swaps, the larger of the native value sent and the token amount the router can pull.

What the caps don't count yet:

- **Gas.** Fees are paid from the wallet but not counted.
- **Other allowlisted functions.** If you allowlist a function Keyshare doesn't decode, only its native value is counted. Allowlist only functions you understand.
- **Allowlisted typed data.** An EIP-712 order (for example a Seaport or CoW order) that is allowlisted counts as $0.

## Messages (`sign_message`)

Only plain text is signed. Anything that is all hex starting with `0x`, a long hex string, or not valid text is refused, so a bot can't be tricked into signing a hash or calldata as a "message".

## Typed data (`sign_typed_data`)

Denied unless a `typed_data_allow` rule matches. A rule matches when:

- the primary type is the same, and
- the domain's `verifyingContract` matches the rule, and
- the domain's chain id is allowed (the rule's `chain_id`, or any of the bot's chains).

A rule that names only the domain `name` matches only domains with no chain id, because any contract can claim any name. Domains with no chain id need `chainless = true`.

Always refused, whatever the rules say:

- Permits (`Permit`, `PermitSingle`, `PermitBatch`, `PermitTransferFrom` and their batch and witness forms).
- Hyperliquid user-signed actions such as withdrawals and transfers (`HyperliquidTransaction:*`). Hyperliquid trading goes through the `hl_*` tools instead.

## Money math

All USD amounts are kept as whole micro-dollars (millionths of a dollar) in integers. There is no floating point anywhere on the money path. Values round up, so rounding never lets a request slip under a cap.
