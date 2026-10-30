# Hyperliquid

Bots can trade perpetual futures on Hyperliquid **testnet**. Phase 0 refuses to talk to Hyperliquid mainnet: every signature is marked as testnet, and the API address must be the testnet host (or a local mock for tests).

## Keys

Each bot's normal wallet key is its Hyperliquid **master account**. The master key does not sign orders. Instead:

1. The owner runs `keyshare-mcp hl-approve-agent <config> <bot> [hours]`.
2. Keyshare makes a brand-new **agent key**, and the master key approves it on Hyperliquid for the given time (default 48 hours, at most 7 days).
3. The agent key is saved in the state folder (`hyperliquid/<bot>.agent.json`, readable only by the server's user).
4. Orders are signed by the agent key.

An agent key can trade but can't withdraw or transfer funds, so if it leaks, the funds stay in the account. Keyshare never reuses an agent address. Run `hl-approve-agent` again to replace a key; the new one takes over without a restart. A key within a minute of expiry is treated as expired, and the bot gets `NO_AGENT_KEY` until the owner approves a new one.

To fund the account, deposit testnet USDC to the bot's wallet address on Hyperliquid testnet.

## Tools

`hl_positions`, `hl_place_order`, `hl_modify`, `hl_cancel`, `hl_set_leverage`. Inputs are in [Tools](tools.md). Sizes and prices are decimal strings, never floating point.

## Limits

Set per bot in `[bots.<name>.hyperliquid]`. Without that section the bot can't use these tools.

| Limit | How it is checked |
|---|---|
| `markets` | The coin must be on the list. |
| `max_order_usd` | Size × price must be under this. The price used is the higher of the order's limit price and the current mark price, so a far-off limit price can't hide a large order. |
| `max_position_usd` | The position after this order fills, plus the bot's other open orders on the same side, must stay under this. |
| `max_leverage` | `hl_set_leverage` can't go above it, and a new order is refused if the coin's current leverage is above it. |
| `daily_loss_stop_usd` | Keyshare records the account value the first time it checks the account each UTC day. Once the account is down this much from there, new orders that add risk are refused. |

**Reduce-only orders skip the size, position, leverage and loss checks.** They can only shrink a position, and Hyperliquid enforces that, so a bot can always close out even after hitting a limit or if the account check fails.

`hl_modify` checks the replacement order like a new one. `hl_cancel` only needs the coin to be allowed.

## Kill switch

Every Hyperliquid action, including cancels, checks the kill switch. A frozen bot can't place, change or cancel orders. Whether a frozen bot should still be allowed to cancel is an open question.

## Request ids

Each Hyperliquid action takes an optional request id, used once like the chain tools. The id is claimed before signing, so a retry after a timeout can't place the same order twice.

## Known gaps

- The loss stop starts from the first check of the day, not from midnight. A loss before that first check isn't counted.
- Deposits and withdrawals during the day move the account value and so move the loss stop too.
- The agent key file is plain text, protected only by file permissions.
- Request ids are kept in memory and forgotten on restart.
