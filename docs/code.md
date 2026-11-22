# Code layout

One Cargo workspace. `keyshare-core` does not depend on the protocol crates, so it can be audited on its own (`cargo audit -p keyshare-core`).

## keyshare-core

The signing path, with no network code and no venue code. Everything here stays when the single key is replaced by threshold signing.

| File | What it does |
|---|---|
| `wallet.rs` | The one path every signature goes through: audit, caller, kill switch, anchor check, request id, policy, record spend, sign, audit. |
| `policy.rs` | The policy rules and checks (`PlainPolicy`). `PolicyEngine` is the trait a later proof-based check can plug into. |
| `intent.rs` | Unsigned intents and the module allowlist re-check. A module cannot sign these itself. |
| `signer.rs` | The `Signer` trait and `LocalSigner` (one testnet key). Every method takes the full payload, never a bare hash. The host uses this. Modules do not. |
| `spend.rs` | Spend log, used request ids, rollback anchor. |
| `chainlog.rs` | The hash-chained JSON-lines file used by the spend and audit logs. |
| `audit.rs` | Audit log entries. |
| `killswitch.rs` | Reads and writes `kill.json`. |
| `approval.rs` | Builds and verifies owner approval messages. |
| `price.rs` | USD values in integer micro-dollars from the config's price table. |
| `refusal.rs` | Refusal codes and messages. |
| `lib.rs` | Exports. |

Tests: `tests/wallet.rs`, plus unit tests in each file.

## keyshare-module

The interface modules implement. `ProtocolModule` declares tools, an allowlist, and policy validation. `Core` is the host surface a module may call. It has no private-key argument. `Registry` snapshots allowlists at startup.

## keyshare-hyperliquid

Hyperliquid testnet. `protocol.rs` is encoding and trading limits (no network). `client.rs` is the venue client, the equity read, the daily-loss file, and the equity-floor latch. It asks the host to sign. State files stay `state_dir/hyperliquid/<bot>.agent.json`, `<bot>.day.json`, and `<bot>.equity.json`.

## keyshare-uniswap

The `swap` tool. Quotes Uniswap v3, then submits unsigned approve and swap transactions through the core.

## keyshare-mcp

The server bots talk to, and the command line. It is the host: it owns the wallet, loads the Hyperliquid agent file, and performs the allowlist re-check before signing.

| File | What it does |
|---|---|
| `main.rs` | Command line: `serve`, `new-token`, `freeze`, `unfreeze`, `hl-approve-agent`. |
| `lib.rs` | Builds the HTTP app: MCP at `/mcp`, owner endpoints, host check. |
| `config.rs` | Reads and checks the TOML config, including per-bot module switches. Bot keys come from environment variables. |
| `auth.rs` | Bearer tokens. Matches a token's hash to a bot. |
| `server.rs` | Core MCP tools, and dispatch into the modules. Hides tools whose module is disabled for the caller. |
| `exec.rs` | Runs transactions: allowlist re-check for module intents, simulate, sign, send. Holds requests for the owner. Implements `Core`. |
| `admin.rs` | `/admin/pending` and `/admin/decide`. |
| `chain.rs` | RPC calls: nonce, gas, fees, simulation, sending. Hides RPC details from bots. |
| `hl.rs` | Loads the agent key and runs `hl-approve-agent`. The module does not see the key. |

Tests: `tests/connector.rs` (tools, auth, approvals, disabled modules, against a mock RPC), `tests/swap.rs`, `tests/hyperliquid.rs` (against a mock Hyperliquid API).

The repo root `Dockerfile` and `railway.toml` are the Railway image. It builds the workspace with Rust 1.94.1 and runs `keyshare-mcp` as user `keyshare`. `keyshare.railway.example.toml` is the config that image serves. See [Running](running.md).

## Checks

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
cargo audit
cargo audit -p keyshare-core
```

CI runs fmt, clippy, the tests, and `cargo audit` on every PR.

See [Architecture](architecture.md) and [Writing a module](writing-a-module.md).
