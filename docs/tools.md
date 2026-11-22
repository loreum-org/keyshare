# Tools

These are the MCP tools a bot can call. Every call carries the bot's token, and Keyshare works out which bot is calling from that token alone. A bot can't act as another bot by naming it in a request.

Amounts are decimal strings in whole tokens (`"12.5"`), not base units, unless a field says wei.

## Request ids

Every tool that signs something takes an optional `request_id`. Use it to make retries safe: a request id can only be used once per bot, so if the bot retries after a timeout, the second attempt is refused with `NONCE_REUSED` instead of sending twice. If the bot leaves it out, Keyshare makes one up and returns it.

The exception is a request that was held for the owner and then expired. Its id is freed so the bot can try again.

## Reading

| Tool | Inputs | Returns |
|---|---|---|
| `address` | none | The bot's wallet address and the chains it may use. |
| `limits` | none | The bot's caps, how much of the rolling 24-hour cap it has used, and how many recipients, contracts and typed-data rules it has. When the bot has a Hyperliquid section, `hyperliquid` adds the equity floor: `floor`, `peak_equity`, `equity` (current equity), `headroom` and `breached`. Use this to self-limit. |
| `balances` | `chain_id` (optional) | Native and priced-token balances, on one chain or all configured chains. |
| `tx_status` | `chain_id`, and `tx_hash` or `request_id` | One of `pending_user_approval`, `executing`, `refused`, `pending`, `confirmed`, `failed`, `unknown`. |
| `simulate` | `chain_id`, `to`, `data` (optional), `value_wei` (optional) | The policy verdict, the gas estimate, and whether the call reverts. Nothing is signed or recorded. |

## Moving funds

All of these go through the full policy check and a simulation before anything is signed. Each takes `dry_run: true` to check and simulate without signing.

| Tool | Inputs | What it does |
|---|---|---|
| `send` | `chain_id`, `to`, `amount`, `token` (optional) | Sends native tokens, or an ERC-20 when `token` is given. The recipient must be on the bot's allowlist. |
| `call_contract` | `chain_id`, `to`, `data`, `value_wei` (optional) | Calls a contract function. The contract and function must be on the bot's allowlist. |
| `swap` | `chain_id`, `sell_token` (optional, native if left out), `buy_token`, `amount`, `max_slippage_bps` (optional), `route_provider` (optional, only `uniswap_v3`) | Swaps an exact amount on Uniswap v3. See [Swaps](swaps.md). |

A successful call returns the request id, the transaction hash, the simulation result and the USD value counted against the caps. A call that needs the owner returns `state: pending_user_approval`, the reason, and when the hold expires. See [Owner approvals](owner-approvals.md).

## Signing

| Tool | Inputs | What it does |
|---|---|---|
| `sign_message` | `message` | Signs plain text (EIP-191), e.g. a login message. Text that looks like hex or a transaction is refused, so this can't be used to sign a transaction in disguise. |
| `sign_typed_data` | `typed_data` (`{types, primaryType, domain, message}`) | Signs EIP-712 typed data, only for types allowlisted for that exact contract. Permits and Hyperliquid fund-moving actions are always refused. |

## Hyperliquid testnet

Only for bots with a `hyperliquid` section in the config. See [Hyperliquid](hyperliquid.md).

| Tool | Inputs | What it does |
|---|---|---|
| `hl_positions` | none | Positions, margin and open orders. `account.equity` is current equity, the figure the daily loss stop and the equity floor use. `account.floor`, `account.peak_equity`, `account.headroom` and `account.breached` are the floor state. `account.available_margin` is free margin when the venue reports it. |
| `hl_place_order` | `order` | Places a limit order, or a take-profit / stop-loss trigger order. |
| `hl_modify` | `oid`, `order` | Replaces a resting order. The new order is checked like a new one. |
| `hl_cancel` | `coin`, `oid` | Cancels a resting order. |
| `hl_set_leverage` | `coin`, `leverage`, `is_cross` (default true) | Sets leverage for a coin, up to the bot's maximum. While the equity floor is breached, an increase is refused and a decrease is still allowed. |

An `order` has: `coin` (e.g. `"ETH"`), `is_buy`, `sz` (size in coins), `limit_px`, `tif` (`Gtc`, `Ioc` or `Alo`; default `Gtc`), `reduce_only`, and optionally `cloid`. For a trigger order add `trigger_px`, `tpsl` (`tp` or `sl`) and `trigger_is_market` (default true).

## Refusals

A refused call returns `refused: true`, a `code`, a plain `reason`, and the `request_id`. The codes:

| Code | Meaning |
|---|---|
| `UNKNOWN_CALLER` | The token doesn't match any bot. |
| `KILL_SWITCH` | Signing is frozen for this bot or for everyone. |
| `CHAIN_NOT_ALLOWED` | The bot may not use this chain, or no RPC is configured for it. |
| `RECIPIENT_NOT_ALLOWED` | The recipient isn't on the bot's allowlist for this chain. Owner can approve. |
| `CONTRACT_NOT_ALLOWED` | The contract or function isn't on the bot's allowlist for this chain. Owner can approve. |
| `DENIED_PRIMITIVE` | A call that is never allowed, such as an unlimited approve or a permit. See [Policy](policy.md). |
| `TYPED_DATA_NOT_ALLOWED` | The EIP-712 type and domain aren't allowlisted. |
| `MESSAGE_LOOKS_LIKE_TX` | `sign_message` got hex or binary instead of plain text. |
| `PRICE_UNAVAILABLE` | A token involved has no price in the config. |
| `PER_TX_CAP_EXCEEDED` | This request is over the per-send cap. Owner can approve. |
| `CAP_EXCEEDED` | This request would go over the daily cap. Owner can approve. |
| `ADMIN_APPROVAL_REQUIRED` | Over the bot's co-sign threshold. Owner can approve. |
| `NONCE_REUSED` | The request id was already used. |
| `BAD_APPROVAL` | An owner decision had a bad signature or the request was already decided. |
| `USER_DENIED` | The owner denied the request. |
| `TOO_MANY_PENDING` | The bot already has 16 requests waiting for the owner. |
| `EXPIRED` | A held request ran out of time. |
| `COUNTER_BEHIND_ANCHOR` | The spend log looks rolled back. Signing stops until an operator looks. |
| `SIM_REVERT` | The transaction would revert on chain. |
| `RPC_UNAVAILABLE` | The chain's RPC failed or answered wrongly. |
| `SLIPPAGE_TOO_HIGH` | A swap would accept too little output. |
| `NO_ROUTE` | No Uniswap pool quotes this pair. |
| `MARKET_NOT_ALLOWED` | The bot may not trade this Hyperliquid coin. |
| `ORDER_TOO_LARGE` | The order is over the bot's order size limit. |
| `POSITION_TOO_LARGE` | The order would take the position over the bot's limit. |
| `LEVERAGE_TOO_HIGH` | Over the bot's leverage limit. |
| `DAILY_LOSS_STOP` | The account hit its daily loss stop; only reducing orders are allowed. |
| `EQUITY_FLOOR_BREACHED` | Equity is at or below the floor, or that breach is still latched. The reason names the equity and the floor. Only reduce-only orders are allowed until an operator sets `reset_equity_floor` and restarts. Keyshare does not flatten the account. |
| `NO_AGENT_KEY` | The bot has no valid Hyperliquid agent key. The owner needs to run `hl-approve-agent`. |
| `VENUE_UNAVAILABLE` | Hyperliquid didn't answer or rejected the request. |
| `BAD_ARGS` | The inputs don't make sense (bad amount, unknown option). |
| `THRESHOLD_UNAVAILABLE` | Reserved for threshold signing; not used in Phase 0. |
| `INTERNAL` | A server error. |
