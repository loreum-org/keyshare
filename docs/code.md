# Code layout

Two Rust crates in one workspace.

## keyshare-core

The signing path, with no network code. Everything here will stay the same when the single key is replaced by threshold signing.

| File | What it does |
|---|---|
| `wallet.rs` | The one path every signature goes through: audit, caller, kill switch, anchor check, request id, policy, record spend, sign, audit. |
| `policy.rs` | The policy rules and checks (`PlainPolicy`). `PolicyEngine` is the trait a later proof-based check can plug into. |
| `signer.rs` | The `Signer` trait and `LocalSigner` (one testnet key). Every method takes the full payload, never a bare hash. |
| `spend.rs` | Spend log, used request ids, rollback anchor. |
| `chainlog.rs` | The hash-chained JSON-lines file used by the spend and audit logs. |
| `audit.rs` | Audit log entries. |
| `killswitch.rs` | Reads and writes `kill.json`. |
| `approval.rs` | Builds and verifies owner approval messages. |
| `price.rs` | USD values in integer micro-dollars from the config's price table. |
| `refusal.rs` | Refusal codes and messages. |
| `hyperliquid.rs` | Hyperliquid action encoding, signing and trading limits. No network. |
| `lib.rs` | Exports. |

Tests: `tests/wallet.rs`, plus unit tests in each file.

## keyshare-mcp

The server bots talk to, and the command line.

| File | What it does |
|---|---|
| `main.rs` | Command line: `serve`, `new-token`, `freeze`, `unfreeze`, `hl-approve-agent`. |
| `lib.rs` | Builds the HTTP app: MCP at `/mcp`, owner endpoints, host check. |
| `config.rs` | Reads and checks the TOML config. Bot keys come from environment variables. |
| `auth.rs` | Bearer tokens. Matches a token's hash to a bot. |
| `server.rs` | The MCP tools. |
| `exec.rs` | Runs transactions: check, simulate, sign, send. Holds requests for the owner. |
| `admin.rs` | `/admin/pending` and `/admin/decide`. |
| `chain.rs` | RPC calls: nonce, gas, fees, simulation, sending. Hides RPC details from bots. |
| `swap.rs` | The `swap` tool on Uniswap v3. |
| `hl.rs` | The Hyperliquid tools and agent key handling. |

Tests: `tests/connector.rs` (tools, auth, approvals, against a mock RPC), `tests/swap.rs`, `tests/hyperliquid.rs` (against a mock Hyperliquid API).

## Checks

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
cargo audit
```

CI runs all four on every PR.
