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
| `daily_loss_stop_usd` | Keyshare records equity the first time it checks the account each UTC day. Once the account is down this much from there, new orders that add risk are refused. |
| `equity_floor_usd` | Absolute floor in whole USD. Optional. At or below it, new risk is refused and the breach latches. |
| `max_drawdown_from_peak_usd` | Trailing floor in whole USD below the high-water mark. Optional. Reaching it latches the same way. |
| `reset_equity_floor` | Set `true` and restart to clear a latched breach once. Then set it back to `false`. |

**Reduce-only orders skip the size, position, leverage, loss and equity-floor checks.** They can only shrink a position, and Hyperliquid enforces that, so a bot can always close out even after hitting a limit or if the account check fails. Cancels are allowed too. `hl_set_leverage` can still lower leverage while the floor is latched; it cannot raise it.

## Equity floor

The floor protects principal. It sits beside the daily loss stop and uses the same equity figure. Leave both `equity_floor_usd` and `max_drawdown_from_peak_usd` unset and nothing here changes.

When both are set, the binding floor is the higher of the absolute floor and (peak − drawdown). Equity at or below that floor is a breach. A drawdown of exactly the limit is a breach.

The high-water mark is the highest equity Keyshare has read while the account was not latched. It is stored in `hyperliquid/<bot>.equity.json`, the same way the daily baseline is stored in `<bot>.day.json`. The mark only moves up. Deposits raise it. Withdrawals do not lower it, so taking cash out can trip the trailing floor. It survives restarts.

A breach **latches**. `hl_place_order` then refuses every order that is not reduce-only, with `EQUITY_FLOOR_BREACHED`. The reason includes the equity and the floor. `hl_modify` is checked like a new order. `hl_set_leverage` refuses an increase. Reduce-only orders, including reduce-only take-profit and stop-loss orders, and `hl_cancel` still work.

The latch stays after equity recovers, after the floor numbers are edited, and across restarts. Clearing it takes `reset_equity_floor = true` and a restart. That flag is consumed on the next successful equity read: the latch is cleared, and if equity is still at or below the floor it latches again on that same read. The high-water mark is not lowered. Leaving the flag `true` does not clear a later breach; set it back to `false`, then to `true` again, when you mean to clear. Removing both limits turns the check off. Putting them back without a reset enforces a latch that was already on disk.

If equity cannot be read, or the account mode is one this server does not price, new risk is refused (`VENUE_UNAVAILABLE`). A missing read is not treated as zero and is not written as a peak.

Keyshare does not flatten the account. There is no close-all inside the server. The caller closes risk with reduce-only orders.

`limits` (under `hyperliquid`) and `hl_positions` (under `account`) report `floor`, `peak_equity`, current equity (`equity`), `headroom`, and `breached`. `headroom` is equity minus the binding floor. `limits` does not query the venue when both limits are unset.

## Unified accounts

`userAbstraction` decides which balance is equity. A missing or unknown mode fails closed for new risk. Keyshare does not change the mode.

| Mode | Equity the loss stop records | Available margin |
|---|---|---|
| `default`, `disabled`, `dexAbstraction` | Perp `marginSummary.accountValue` (already includes unrealized PnL). Spot balances are not added. | Perp `withdrawable`, when that field is present. |
| `unifiedAccount` | Spot USDC (token 0) `total`, plus unrealized PnL on the default perp dex. Perp `accountValue` is not added. | `tokenToAvailableAfterMaintenance` for token 0. |
| `portfolioMargin` | Not computed. Other collateral is not priced, so new risk is refused. | |

On a unified account the spot clearinghouse is the balance. USDC `total` is cash, not a sum of every spot token. A non-zero non-USDC balance or hold, a missing USDC row, a missing or unreadable available-margin entry, an available figure above the USDC balance, or a position whose unrealized PnL is missing all refuse new risk instead of counting as zero. `hl_positions` reports this under `account`: `abstraction`, `equity`, `equity_source`, `usdc_total`, `unrealized_pnl`, `available_margin`, `available_source`, plus the equity-floor fields `floor`, `peak_equity`, `headroom` and `breached`. The available-margin fields are omitted for a standard account when `withdrawable` is absent. `floor`, `peak_equity` and `headroom` are null when no equity floor is configured.

A same-day baseline of exactly 0 with no `basis` is the old perp reading. It is replaced with unified equity only when that account is flat: no position size and no USDC hold. An open position or a hold leaves the zero in place and refuses new risk. Any other saved baseline is left as it is, including a real zero on a standard account and a non-zero figure.

`hl_modify` checks the replacement order like a new one. `hl_cancel` only needs the coin to be allowed.

## Kill switch

Every Hyperliquid action, including cancels, checks the kill switch. A frozen bot can't place, change or cancel orders. Whether a frozen bot should still be allowed to cancel is an open question.

## Request ids

Each Hyperliquid action takes an optional request id, used once like the chain tools. The id is claimed before signing, so a retry after a timeout can't place the same order twice.

## Known gaps

- The loss stop starts from the first check of the day, not from midnight. A loss before that first check isn't counted.
- Deposits and withdrawals during the day move the account value and so move the loss stop too. A deposit also raises the equity-floor high-water mark. A withdrawal does not lower it.
- Only the default perp dex is in the equity figure, so a HIP-3 position is invisible to the floor, same as the loss stop.
- The agent key file is plain text, protected only by file permissions.
- Request ids are kept in memory and forgotten on restart.
