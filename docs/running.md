# Running Keyshare

## Build

You need Rust 1.90 or newer.

```sh
cargo build --release
cargo test
```

The server binary is `keyshare-mcp`.

## First setup

1. **Copy the example config.** Start from `keyshare.example.toml` in the repo root. It sets up one bot, `filltape`, on Sepolia.

2. **Make a login token for each bot.**

   ```sh
   keyshare-mcp new-token
   ```

   This prints a token and its hash. Give the token to the bot. Put only the hash in the config, as the bot's `credential_sha256`. Keyshare never stores the token itself.

3. **Give each bot a key.** Phase 0 reads each bot's private key from an environment variable. The config names the variable with `key_env`, for example `FILLTAPE_KEY`. Keys never go in the config file. Use a fresh testnet key per bot.

4. **Set the bot's rules.** Edit the bot's `policy` section: chains, caps, allowed recipients and contracts. See [Configuration](configuration.md) and [Policy](policy.md).

5. **Start the server.**

   ```sh
   FILLTAPE_KEY=0x... keyshare-mcp serve keyshare.toml
   ```

   On start it prints each bot's wallet address. Fund those addresses with testnet tokens.

6. **Connect the bot.** The bot's MCP client connects to `http://<host>:<port>/mcp` over streamable HTTP and sends `Authorization: Bearer <token>` on every request.

## Command line

| Command | What it does |
|---|---|
| `keyshare-mcp serve <config>` | Runs the server. |
| `keyshare-mcp new-token` | Prints a new bot token and the hash to put in the config. |
| `keyshare-mcp freeze <config> [bot]` | Turns on the kill switch for one bot, or for all bots if no bot is named. Takes effect at once on a running server. |
| `keyshare-mcp unfreeze <config> [bot]` | Turns the kill switch off again. |
| `keyshare-mcp hl-approve-agent <config> <bot> [hours]` | Makes a new Hyperliquid testnet agent key for a bot and has the bot's wallet approve it. Default 48 hours, at most 168. See [Hyperliquid](hyperliquid.md). |

`freeze`, `unfreeze` and `hl-approve-agent` run on the same machine as the server, against the same config and state folder. `hl-approve-agent` needs the bot's key variable set, like `serve`.

## HTTP endpoints

| Path | Who uses it |
|---|---|
| `/mcp` | Bots. Every request needs a bot token. |
| `/admin/pending` | The owner. Lists held requests. Needs the admin token. Off unless `admin_token_sha256` is set. |
| `/admin/decide` | The owner. Approves or denies a held request with a signed message. See [Owner approvals](owner-approvals.md). |
| `/health` | Health checks. Returns `ok`. |

## Deploying

- **Host checks.** By default the server only accepts requests whose Host header is `localhost`, `127.0.0.1` or `::1`. When it sits behind a public domain (for example on Railway), list that domain in `allowed_hosts`.
- **State folder.** `state_dir` holds the spend log, audit log, kill switch and Hyperliquid agent keys. Put it on a persistent volume. Losing it loses the spend history and the audit trail.
- **Spend anchor.** Put `spend_anchor` on a different disk from `state_dir`. If the state folder is restored from an old backup, the anchor catches it and signing stops. The server prints a warning at start if the anchor is inside the state folder.
- **One server per state folder.** Two servers sharing one state folder would each keep their own nonces and in-memory requests.
- **Restarts.** Requests waiting for the owner live in memory and are dropped on restart. They never sign. The bot has to ask again.

## Continuous integration

Every pull request runs formatting, lint (clippy with warnings as errors), all tests, and `cargo audit` for known security advisories. One advisory (RUSTSEC-2026-0387, in a math library that alloy depends on) is ignored in `.cargo/audit.toml` until alloy ships the fix. Issue #13 tracks removing it.
