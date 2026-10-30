# Swaps

The `swap` tool swaps an exact amount of one token for another on Uniswap v3. It needs the chain's Uniswap contracts in the config (`[chains.uniswap_v3]`), and the Uniswap router must be on the bot's `contracts_allow` with the `exactInputSingle` selector (`0x04e45aaf`).

## What happens

1. **Quote.** Keyshare asks Uniswap's quoter for each fee tier (0.05%, 0.3%, 1% by default) and takes the best.
2. **Minimum output.** The minimum the bot will accept is the quote minus the slippage. Slippage defaults to the bot's `max_slippage_bps` (1%). A bot can ask for less, never more.
3. **Policy check.** The swap itself is checked before anything else is signed, so a swap the policy would refuse never leaves an approval behind.
4. **Approve, if needed.** When selling a token, Keyshare checks the router's current allowance. If it's short, it approves the router for exactly the swap amount, never more, and waits up to 90 seconds for that to confirm. The approval counts against the bot's caps.
5. **Swap.** The swap is sent with the bot's own wallet as the recipient.

The result includes the quote: fee tier, amount in, expected out, minimum out and slippage.

With `dry_run: true`, Keyshare quotes and checks without signing. If an approval is needed first, the swap itself can't be simulated until that approval lands, and the result says so.

## Safety checks

These apply to any `exactInputSingle` call, through `swap` or through `call_contract`:

- **Output goes to the bot.** The recipient must be the bot's own wallet or an allowlisted recipient.
- **The guaranteed output must be worth about what goes in.** Keyshare values the input and the minimum output with the config's price table. If the minimum output is worth more than `max_price_deviation_bps` (default 5%) less than the input, the swap is refused with `SLIPPAGE_TOO_HIGH`. This stops a swap with a zero minimum, or one quoted from a pool someone has pushed out of line.
- **The output token needs a price.** Buying an unpriced token is refused, because Keyshare can't check what the bot gets back.
- **What counts against the caps** is the larger of the native value sent and the token amount the router may take.

Only `exactInputSingle` is checked this way. Don't allowlist the router's other functions (`exactInput`, `exactOutputSingle`, `multicall`), because they would skip these checks.

## Selling the native token

Leave out `sell_token` to sell ETH (or the chain's native token). The router wraps it. Use the wrapped token's address (`weth` in the config) as `buy_token` to buy the native token's wrapped form.
