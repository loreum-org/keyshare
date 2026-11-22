# Code layout

The workspace splits the signing core from protocol modules. [Protocol modules](modules.md) explains the boundary.

## keyshare-core

The signing path, with no network code and no venue logic. Everything here will stay the same when the single key is replaced by threshold signing. Audit it on its own with `cargo test -p keyshare-core`.

| File | What it does |
|---|---|
| `wallet.rs` | The one path every signature goes through: audit, caller, kill switch, anchor check, request id, policy, record spend, sign, audit. |
| `policy.rs` | The policy rules and checks (`PlainPolicy`). `PolicyEngine` is the trait a later proof-based check can plug into. |
| `signer.rs` | The `Signer` trait. Every method takes the full payload, never a bare hash. Nothing here loads a key or builds a signer. |
| `spend.rs` | Spend log, used request ids, rollback anchor. |
| `chainlog.rs` | The hash-chained JSON-lines file used by the spend and audit logs. |
| `audit.rs` | Audit log entries. |
| `killswitch.rs` | Reads and writes `kill.json`. |
| `approval.rs` | Builds and verifies owner approval messages. |
| `price.rs` | USD values in integer micro-dollars from the config's price table. |
| `refusal.rs` | Refusal codes and messages. |
| `lib.rs` | Exports. |

Tests: `tests/wallet.rs`, plus unit tests in each file.

## keyshare-signer

Key material. `LocalSigner` (one testnet key) and the Hyperliquid agent key file: where it lives, writing it with mode 0600, and loading it with the expiry and address checks. Only `keyshare-mcp` depends on this crate; `tests/boundary.rs` fails if any other crate does.

## keyshare-module

`Intent`, `Grant`, and the authorizers the connector runs before it signs. A module cannot pass a signer in.

## keyshare-hyperliquid

Hyperliquid action encoding (`protocol.rs`, no network) and the venue client (`client.rs`). The client asks the connector to sign.

## keyshare-uniswap

The Uniswap v3 `swap` tool: quote, then an exact approve and `exactInputSingle`. The connector checks the module grant and then the bot policy.

## keyshare-mcp

The server bots talk to, and the command line.

| File | What it does |
|---|---|
| `main.rs` | Command line: `serve`, `new-token`, `freeze`, `unfreeze`, `hl-approve-agent`. |
| `lib.rs` | Builds the HTTP app: MCP at `/mcp`, owner endpoints, host check. |
| `config.rs` | Reads and checks the TOML config. Bot keys come from environment variables. |
| `auth.rs` | Bearer tokens. Matches a token's hash to a bot. |
| `server.rs` | The generic MCP tools, plus dispatch into the Hyperliquid and Uniswap modules. |
| `exec.rs` | Runs transactions: check, simulate, sign, send. Holds requests for the owner. Implements the module host traits and re-checks intents before signing. |
| `admin.rs` | `/admin/pending` and `/admin/decide`. |
| `chain.rs` | RPC calls: nonce, gas, fees, simulation, sending. Hides RPC details from bots. |
| `swap.rs` | Re-exports the Uniswap module. |
| `hl.rs` | Re-exports the Hyperliquid module and the owner `hl-approve-agent` command. |

Tests: `tests/connector.rs` (tools, auth, approvals, against a mock RPC), `tests/swap.rs`, `tests/hyperliquid.rs` (against a mock Hyperliquid API), `tests/modules.rs` (a bot with a module switched off is not offered that module's tools).

The repo root `Dockerfile` and `railway.toml` are the Railway image. It builds with Rust 1.94.1 and runs `keyshare-mcp` as user `keyshare`. `keyshare.railway.example.toml` is the config that image serves. See [Running](running.md).

## Checks

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
cargo audit
```

CI runs all four on every PR.
