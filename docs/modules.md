# Protocol modules

Keyshare's core holds the key, evaluates policy, simulates, signs, and writes the audit log. A protocol module does not. It turns a tool call into an **intent** — an unsigned transaction or an EIP-712 payload — and hands that intent to the core. The core checks the intent against the module's grant and the bot's policy, then signs. A bug in a module cannot make the core sign something the grant does not name.

Hyperliquid (`hl_*`) and Uniswap v3 (`swap`) are modules. The generic tools (`address`, `balances`, `send`, `call_contract`, `sign_message`, `sign_typed_data`, `simulate`, `limits`, `tx_status`) stay in the connector.

`limits` still reports the bot's caps and `spent_24h_usd`. When Hyperliquid is offered to that bot, it also reports the equity floor under `hyperliquid`, the same figures as before.

## Crates

| Crate | What it is |
|---|---|
| `keyshare-core` | `Signer` trait, policy, spend log, audit log, kill switch. No venue client, no marketplace code, and no way to load a key or build a signer. Audit this crate on its own with `cargo test -p keyshare-core`. |
| `keyshare-signer` | `LocalSigner` and the Hyperliquid agent key file. Only `keyshare-mcp` depends on it. |
| `keyshare-module` | `Intent`, `Grant`, `authorize` / `authorize_tx` / `authorize_typed`, and `ModuleView`. No signer. |
| `keyshare-hyperliquid` | Hyperliquid testnet orders, the venue client, and the trading limits. Signing goes through `HlHost::sign_l1`. |
| `keyshare-uniswap` | Uniswap v3 quotes and the swap transaction. Signing goes through `SwapHost::submit`, which checks the module grant and then the normal policy. |
| `keyshare-mcp` | The HTTP server, the generic tools, and the host implementations of `HlHost` and `SwapHost`. |

## Key material stays in the connector

No module crate can reach key material, even if it tries:

- `keyshare-core` exports the `Signer` trait but no key loader and no signer constructor.
- `LocalSigner`, the agent key path, and the agent key file reader and writer live in `keyshare-signer`. Only `keyshare-mcp` depends on it.
- Only `keyshare-signer` turns on alloy's `signer-local` feature. A module built on its own cannot name a private-key type. Unit tests may turn it on under `[dev-dependencies]` to check signature vectors.
- `hl-approve-agent` generates the agent key in the connector, has the module post the approval, and saves the key in the connector. The module only sees the agent's address.

Two checks enforce this. `crates/keyshare-signer/tests/boundary.rs` fails if any crate other than `keyshare-mcp` depends on `keyshare-signer`, or if any crate other than `keyshare-signer` enables `signer-local` as a normal dependency. CI also builds `keyshare-core`, `keyshare-module`, `keyshare-hyperliquid` and `keyshare-uniswap` without the connector, so a module that names a key type fails to compile.

A module still runs in the same process as the connector, so this is a guard against mistakes and careless dependencies, not a sandbox. Moving the key out of the process is the threshold-signing work.

## What the core re-checks

For a transaction intent, `authorize_tx` does two things, in order:

1. The module **grant** must name the call. A swap may call `exactInputSingle` on that chain's router, or `approve` with that router as the spender. Any other call is `CONTRACT_NOT_ALLOWED`, even if the bot's `contracts_allow` would have accepted it from `call_contract`.
2. The bot's `PlainPolicy` runs as it does for `send` and `call_contract`: chain, allowlists, caps, decoded calls.

For typed data, `authorize_typed` refuses fund-moving types (permits, `HyperliquidTransaction:*`) and refuses any domain the grant does not name. Hyperliquid L1 actions are the `Agent` type on the Exchange domain. The host rebuilds that payload from the action and the nonce, checks every asset index against the loaded market list (a missing list is a refusal), checks the wire size against the bot's Hyperliquid limits, loads the agent key, and signs. The module's order path calls `HlHost::sign_l1`. It never receives the wallet, and it cannot read the agent key file: the path and the reader are in `keyshare-signer`. The owner command `hl-approve-agent` signs the wallet key in `keyshare-mcp`, then hands the signature to the module to post.

`HlHost` and `SwapHost` extend [`ModuleView`](../crates/keyshare-module/src/lib.rs): address, limits, 24h spend, kill-switch check, transaction preview, and audit writes. Those methods do not expose `Wallet::sign_transaction`, `sign_message`, or `sign_typed_data`.

## Enabling a module per bot

Every module is offered unless the bot turns it off. That keeps existing configs working: the tools stay listed, and a bot with no `[bots.<name>.hyperliquid]` table still gets `MARKET_NOT_ALLOWED` when it tries to trade.

```toml
[bots.filltape.modules]
hyperliquid = false   # hl_* disappear from tools/list, and calls are rejected
uniswap = false       # swap disappears the same way
```

`limits` omits the Hyperliquid section when that module is off for the bot.

## Writing a module

1. Add a crate that depends on `keyshare-core` and `keyshare-module`. Do not depend on `keyshare-mcp` or `keyshare-signer`, and do not take a `Signer`.
2. Declare a `Grant`: the contract/selector pairs, approve spenders, and EIP-712 rules the module may ask the core to sign.
3. Return an `Intent::Transaction` or `Intent::TypedData`. There is no signed variant.
4. Define a host trait that extends `ModuleView` for whatever else the connector must do (submit a vetted transaction, sign typed data). Do not pass a `Wallet` or a `Signer` into the module. Implement that trait on `Executor` in `keyshare-mcp`, and call `authorize_tx` or `authorize_typed` there before any signature.
5. Name the MCP tools in a `TOOLS` constant. `tools/list` hides them when the bot's `[bots.<name>.modules]` switch is false.
6. Keep amounts as integers. The core's policy still prices transactions from the config's price table.

A module that returns an intent outside its grant fails in the host, before `sign_transaction` or `sign_typed_data`. The tests in `keyshare-module` cover that, including a transaction the bot policy would have allowed and a fund-moving EIP-712 type a grant tried to name.
