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

- **Listen address.** `listen` in the config is the bind address when `PORT` is unset. When `PORT` is set, the server listens on `0.0.0.0:$PORT` instead. A blank `PORT` counts as unset.
- **Host checks.** By default the server only accepts `/mcp` requests whose Host header is `localhost`, `127.0.0.1` or `::1`. That DNS-rebinding guard stays on. To serve another hostname, list it in `allowed_hosts` or in `KEYSHARE_ALLOWED_HOSTS` (comma-separated, no scheme). The two lists are merged. A hostname without a port matches that host on any port. When the merged list is empty, the localhost default stays. When it is not empty, that list is the whole allowlist, so include `localhost` too if you still want it.
- **State folder.** `state_dir` holds the spend log, audit log, kill switch and Hyperliquid agent keys. Put it on a persistent volume. Losing it loses the spend history and the audit trail.
- **Spend anchor.** Put `spend_anchor` on a different disk from `state_dir`. If the state folder is restored from an old backup, the anchor catches it and signing stops. The server prints a warning at start if the anchor is inside the state folder.
- **One server per state folder.** Two servers sharing one state folder would each keep their own nonces and in-memory requests.
- **Restarts.** Requests waiting for the owner live in memory and are dropped on restart. They never sign. The bot has to ask again.

### Railway

Phase 0 can run as a public HTTPS testnet MCP server. Railway terminates TLS. The process speaks HTTP on the port Railway assigns.

The repo root `Dockerfile` is a multi-stage build. It compiles the workspace with Rust 1.90 (the `rust-version` in `Cargo.toml`) and runs `keyshare-mcp` as the user `keyshare` (uid 10001). `railway.toml` selects that Dockerfile as the builder and sets the `/health` healthcheck.

1. Point a Railway service at this repo and leave the builder on the Dockerfile.
2. Mount a persistent volume at `/data`. That path is `state_dir` in `keyshare.railway.example.toml`, which the image copies to `/etc/keyshare/keyshare.toml` and serves. The volume holds the spend log, audit log, kill switch and Hyperliquid agent keys. The image user must be able to write `/data`. Losing the volume loses that history. Keep the service at one replica.
3. Set variables in Railway. They never go in the config file or the image.
   - `FILLTAPE_KEY` is the filltape bot's testnet private key. Any other bot uses the variable named by its `key_env`. The process will not start if a configured key variable is missing.
   - `KEYSHARE_ALLOWED_HOSTS` is the Railway hostname, for example `keyshare-mcp.up.railway.app`, with no `https://`. Several hosts are comma-separated. This is merged with `allowed_hosts` from the file. The DNS-rebinding guard still rejects any other Host header on `/mcp`.
   - `PORT` is set by Railway. The process binds `0.0.0.0:$PORT`. You do not pick that port in the file for a Railway deploy. `listen = "0.0.0.0:8080"` in the example is only the fallback when `PORT` is unset.
4. Healthcheck path: `/health`. It returns `ok`. It is not behind bot auth or the host allowlist, so Railway can call it.
5. Start command: `keyshare-mcp serve <config>`. The image default, also set in `railway.toml`, is `keyshare-mcp serve /etc/keyshare/keyshare.toml`. To serve a different file (for example one you put on the volume with a real `credential_sha256`), set the start command to `keyshare-mcp serve <config>`.
6. Bots connect to `https://<railway-domain>/mcp` with `Authorization: Bearer <token>`. The example `credential_sha256` is a placeholder of all zeros and matches no token. Run `keyshare-mcp new-token`, put only the hash in the config the process reads, and give the token to the bot. Do not commit the token.
7. The filltape bot in the Railway example is Sepolia plus Hyperliquid testnet, with the same policy shape as `keyshare.example.toml`. Fund the address printed at startup with testnet tokens.
8. One volume means `spend_anchor` sits inside `state_dir`, so startup prints the anchor warning. A second disk is optional.

`/admin/pending` stays off until `admin_token_sha256` is set in the config the server reads.

## Continuous integration

Every pull request runs formatting, lint (clippy with warnings as errors), all tests, and `cargo audit` for known security advisories. One advisory (RUSTSEC-2026-0387, in a math library that alloy depends on) is ignored in `.cargo/audit.toml` until alloy ships the fix. Issue #13 tracks removing it.
