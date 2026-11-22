# Running Keyshare

## Build

You need Rust 1.94.1 or newer. That is the `rust-version` in `Cargo.toml`. alloy 2.5 in the lockfile does not build on 1.90.

```sh
cargo build --release
cargo test
```

The server binary is `keyshare-mcp`.

## First setup

1. **Copy the example config and policy.** Start from `keyshare.example.toml` and `policy.example.toml` in the repo root. They set up one bot, `filltape`, on Sepolia.

2. **Make a login token for each bot.**

   ```sh
   keyshare-mcp new-token
   ```

   This prints a token and its hash. Give the token to the bot. Put only the hash in the config, as the bot's `credential_sha256`. Keyshare never stores the token itself.

3. **Give each bot a key.** Phase 0 reads each bot's private key from an environment variable. The config names the variable with `key_env`, for example `FILLTAPE_KEY`. Keys never go in the config file. Use a fresh testnet key per bot.

4. **Set the bot's rules and sign them.** Edit the bot's section in the policy file: chains, caps, allowed recipients and contracts. See [Configuration](configuration.md) and [Policy](policy.md). Put your address in `policy_signers` in the config, then sign the policy:

   ```sh
   keyshare-mcp policy-hash policy.toml          # prints the message to sign
   cast wallet sign "<message>" > policy.toml.sig
   ```

   See [Signed policy](policy-signing.md). Later changes get a higher `version` and a new signature; the running server picks them up within a few seconds.

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
| `keyshare-mcp policy-hash <policy>` | Prints the policy's version, its hash, and the exact message to sign. |
| `keyshare-mcp policy-sign <policy> <KEY_ENV>` | Signs the policy with the key in that environment variable and writes `<policy>.sig`. A testnet convenience; for a real owner key, sign the message from `policy-hash` in your own wallet. |
| `keyshare-mcp policy-verify <policy> <audit.jsonl>` | Re-checks every decision the audit log says was made under this policy. Exits non-zero if any doesn't follow. |
| `keyshare-mcp policy-migrate <old-config> <new-config> <policy>` | Splits a config from before signed policies (rules inline under `[bots.<name>.policy]`) into a config and an unsigned version-1 policy. |

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

The repo root `Dockerfile` is a multi-stage build. It compiles the workspace with Rust 1.94.1 (the `rust-version` in `Cargo.toml`) and runs `keyshare-mcp` as the user `keyshare` (uid 10001). `railway.toml` selects that Dockerfile as the builder and sets the `/health` healthcheck.

1. Point a Railway service at this repo and leave the builder on the Dockerfile.
2. Mount a persistent volume at `/data`. That path is `state_dir` in `keyshare.railway.example.toml`, which the image copies to `/etc/keyshare/keyshare.toml` and serves. The volume holds the spend log, audit log, kill switch and Hyperliquid agent keys. The entrypoint gives `/data` to user `keyshare` before the server starts. Losing the volume loses that history. Keep the service at one replica.
3. Set variables in Railway. They never go in the config file or the image.
   - `FILLTAPE_KEY` is the filltape bot's testnet private key. Any other bot uses the variable named by its `key_env`. The process will not start if a configured key variable is missing.
   - `KEYSHARE_ALLOWED_HOSTS` is the Railway hostname, for example `keyshare-mcp.up.railway.app`, with no `https://`. Several hosts are comma-separated. This is merged with `allowed_hosts` from the file. The DNS-rebinding guard still rejects any other Host header on `/mcp`.
   - `PORT` is set by Railway. The process binds `0.0.0.0:$PORT`. You do not pick that port in the file for a Railway deploy. `listen = "0.0.0.0:8080"` in the example is only the fallback when `PORT` is unset.
4. Healthcheck path: `/health`. It returns `ok`. It is not behind bot auth or the host allowlist, so Railway can call it.
5. Give the server a signed policy. The Railway config reads `/data/policy.toml` and `/data/policy.toml.sig`. Either put both files on the volume, or set `KEYSHARE_POLICY` (the policy text) and `KEYSHARE_POLICY_SIG` (the signature), which the entrypoint writes there at start. If the volume already has a higher version (one you hot-loaded since), the entrypoint keeps it and ignores the variables, so a restart never rolls back; update the variables when convenient. Put your address in `policy_signers` in the config you serve. A config from before signed policies won't parse: split it with `keyshare-mcp policy-migrate`, then sign the policy.
6. The process that serves is `keyshare-mcp serve <config>`, running as user `keyshare`. The image entrypoint (`/usr/local/bin/keyshare-entrypoint`) makes `/data` writable, drops to that user, then execs the serve command. Leave the Railway start command as that entrypoint. If `KEYSHARE_TOML` is set, the entrypoint writes it to a file and serves that. Otherwise it serves `/etc/keyshare/keyshare.toml` (the example baked into the image). Put a real `credential_sha256` in `KEYSHARE_TOML` or in the file you serve.
7. Bots connect to `https://<railway-domain>/mcp` with `Authorization: Bearer <token>`. The example `credential_sha256` is a placeholder of all zeros and matches no token. Run `keyshare-mcp new-token`, put only the hash in the config the process reads, and give the token to the bot. Do not commit the token.
7. The filltape bot in the Railway example is Sepolia plus Hyperliquid testnet, with the same policy shape as `keyshare.example.toml`. Fund the address printed at startup with testnet tokens.
8. One volume means `spend_anchor` sits inside `state_dir`, so startup prints the anchor warning. A second disk is optional.

`/admin/pending` stays off until `admin_token_sha256` is set in the config the server reads.

## Continuous integration

Every pull request runs formatting, lint (clippy with warnings as errors), all tests, and `cargo audit` for known security advisories. One advisory (RUSTSEC-2026-0387, in a math library that alloy depends on) is ignored in `.cargo/audit.toml` until alloy ships the fix. Issue #13 tracks removing it.
