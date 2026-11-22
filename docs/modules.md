# Protocol modules

Keyshare's core holds the key, evaluates policy, simulates, signs, and writes the audit log. A protocol module does not. It turns a tool call into an **intent** — an unsigned transaction or an EIP-712 payload — and hands that intent to the core. The core checks the intent against the module's grant and the bot's policy, then signs. A bug in a module cannot make the core sign something the grant does not name.

Hyperliquid (`hl_*`) and Uniswap v3 (`swap`) are modules. The generic tools (`address`, `balances`, `send`, `call_contract`, `sign_message`, `sign_typed_data`, `simulate`, `limits`, `tx_status`) stay in the connector.

`limits` still reports the bot's caps and `spent_24h_usd`. When Hyperliquid is offered to that bot, it also reports the equity floor under `hyperliquid`, the same figures as before.

## Crates

| Crate | What it is |
|---|---|
| `keyshare-core` | Signer, policy, spend log, audit log, kill switch. No venue client and no marketplace code. Audit this crate on its own with `cargo test -p keyshare-core`. |
| `keyshare-module` | `Intent`, `Grant`, and `authorize` / `authorize_tx` / `authorize_typed`. No signer. |
| `keyshare-hyperliquid` | Hyperliquid testnet orders, the venue client, and the trading limits. Signing goes through `HlHost::sign_l1`. |
| `keyshare-uniswap` | Uniswap v3 quotes and the swap transaction. Signing goes through `SwapHost::submit`, which checks the module grant and then the normal policy. |
| `keyshare-mcp` | The HTTP server, the generic tools, and the host implementations of `HlHost` and `SwapHost`. |

## What the core re-checks

For a transaction intent, `authorize_tx` does two things, in order:

1. The module **grant** must name the call. A swap may call `exactInputSingle` on that chain's router, or `approve` with that router as the spender. Any other call is `CONTRACT_NOT_ALLOWED`, even if the bot's `contracts_allow` would have accepted it from `call_contract`.
2. The bot's `PlainPolicy` runs as it does for `send` and `call_contract`: chain, allowlists, caps, decoded calls.

For typed data, `authorize_typed` refuses fund-moving types (permits, `HyperliquidTransaction:*`) and refuses any domain the grant does not name. Hyperliquid L1 actions are the `Agent` type on the Exchange domain. The host rebuilds that payload from the action and the nonce, checks the wire size against the bot's Hyperliquid limits, opens the agent key, and signs. The module's order path calls `HlHost::sign_l1` and does not sign the wallet key. The owner command `hl-approve-agent` signs that wallet key in `keyshare-mcp`, then hands the signature to the module to post.

## Enabling a module per bot

Every module is offered unless the bot turns it off. That keeps existing configs working: the tools stay listed, and a bot with no `[bots.<name>.hyperliquid]` table still gets `MARKET_NOT_ALLOWED` when it tries to trade.

```toml
[bots.filltape.modules]
hyperliquid = false   # hl_* disappear from tools/list, and calls are rejected
uniswap = false       # swap disappears the same way
```

`limits` omits the Hyperliquid section when that module is off for the bot.

## Writing a module

1. Add a crate that depends on `keyshare-core` and `keyshare-module`. Do not depend on `keyshare-mcp`, and do not take a `Signer`.
2. Declare a `Grant`: the contract/selector pairs, approve spenders, and EIP-712 rules the module may ask the core to sign.
3. Return an `Intent::Transaction` or `Intent::TypedData`. There is no signed variant.
4. Define a small host trait for whatever the connector must do (read the wallet address, submit a vetted transaction, sign typed data). Implement that trait on `Executor` in `keyshare-mcp`, and call `authorize_tx` or `authorize_typed` there before any signature.
5. Name the MCP tools in a `TOOLS` constant. `tools/list` hides them when the bot's `[bots.<name>.modules]` switch is false.
6. Keep amounts as integers. The core's policy still prices transactions from the config's price table.

A module that returns an intent outside its grant fails in the host, before `sign_transaction` or `sign_typed_data`. The tests in `keyshare-module` cover that, including a transaction the bot policy would have allowed and a fund-moving EIP-712 type a grant tried to name.
