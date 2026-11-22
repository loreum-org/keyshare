# Configuration

Keyshare reads two TOML files:

- **The config** (`keyshare.example.toml` in the repo root): the server, chains, and each bot's login and key variable.
- **The policy** (`policy.example.toml`): what each bot may do, and the prices caps are measured in. The owner signs it, and the server refuses to load it otherwise. See [Signed policy](policy-signing.md).

Both examples have comments. Unknown settings are rejected, so a typo fails at start instead of being ignored.

Secrets never go in this file. Bot keys come from environment variables, and bot tokens are stored only as hashes.

## `[server]`

| Setting | Required | Meaning |
|---|---|---|
| `listen` | yes | Address and port to listen on, e.g. `"127.0.0.1:8080"`. If the `PORT` environment variable is set, the server listens on `0.0.0.0:$PORT` instead. |
| `allowed_hosts` | no | Host headers to accept. Empty (the default) accepts only `localhost`, `127.0.0.1` and `::1`. Hosts in `KEYSHARE_ALLOWED_HOSTS` (comma-separated, no scheme) are merged in at startup. The DNS-rebinding guard stays on. |
| `state_dir` | yes | Folder for the spend log, audit log, kill switch file and Hyperliquid agent keys. |
| `spend_anchor` | no | Where to keep a copy of the spend log's latest entry. Default is inside `state_dir`. Put it on another disk. See [Safety and state](safety.md). |
| `admin_token_sha256` | no | Hash of the token for `GET /admin/pending` (make one with `keyshare-mcp new-token`). Without it, the pending list is off. |
| `hold_secs` | no | How long a held request waits for the owner, in seconds. Default 900 (15 minutes). |
| `policy` | yes | Path to the signed policy file. The signature is read from the same path plus `.sig`. |
| `policy_signers` | yes | Addresses allowed to sign the policy. The server won't start without a policy signed by one of them. |
| `policy_reload_secs` | no | How often to look for a newly signed policy, in seconds. Default 5. `0` turns hot reload off. |

## `[hyperliquid]`

| Setting | Required | Meaning |
|---|---|---|
| `api_url` | no | Hyperliquid API. Default `https://api.hyperliquid-testnet.xyz`. Only the testnet host (over https) or a local mock is accepted. |

## `[[chains]]`

One entry per chain the server can reach.

| Setting | Required | Meaning |
|---|---|---|
| `id` | yes | Chain id, e.g. `11155111` for Sepolia. |
| `rpc_url` | yes | RPC endpoint. It may contain an API key; Keyshare never shows it to bots. |
| `uniswap_v3` | no | Uniswap contracts for the `swap` tool. Without them, `swap` refuses this chain. |

`[chains.uniswap_v3]`:

| Setting | Meaning |
|---|---|
| `router` | SwapRouter02 address. |
| `quoter` | QuoterV2 address. |
| `weth` | Wrapped native token (used when selling the native token). |
| `fee_tiers` | Pool fee tiers to try. Default `[500, 3000, 10000]`. |

## `[bots.<name>]` (config)

One section per bot, in the config. The name (e.g. `filltape`) is the bot's id in logs and the kill switch. It can't contain `:`.

| Setting | Required | Meaning |
|---|---|---|
| `credential_sha256` | yes | Hash of the bot's login token. Two bots can't share a token. |
| `key_env` | yes | Environment variable that holds the bot's private key. |
| `admin_keys` | no | Owner addresses that can approve or deny this bot's held requests. With none, over-limit requests are simply refused. |

## Policy file

Everything below this point goes in the policy file, not the config. The policy starts with a `version` number, which must go up with every change:

```toml
version = 3
```

Every bot in the config needs a section in the policy, and the policy can't name a bot the config doesn't have.

### `[[prices]]`

Fixed USD prices used to value every outflow against the caps. Phase 0 has no live price feed.

| Setting | Meaning |
|---|---|
| `chain_id` | Chain the token is on. |
| `token` | Token address. Leave it out for the chain's native token. |
| `decimals` | Token decimals, e.g. 18 for ETH, 6 for USDC. |
| `usd` | Price of one whole token as a decimal string, e.g. `"2500"` or `"1"`. |

A token with no price can't be sent, approved or bought. The request is refused with `PRICE_UNAVAILABLE`. This is on purpose: Keyshare won't move value it can't count.

### `[bots.<name>.core]`

The bot's spending rules. [Policy](policy.md) explains how each is applied.

| Setting | Required | Meaning |
|---|---|---|
| `chains` | yes | Chain ids this bot may use. |
| `per_tx_cap_usd` | yes | Most a single request may move, in whole USD. |
| `daily_cap_usd` | yes | Most the bot may move in any rolling 24 hours, in whole USD. |
| `recipients_allow` | no | Addresses the bot may send to. Each is a bare address (any of the bot's chains) or `{ addr = "0x...", chains = [11155111] }`. |
| `contracts_allow` | no | Contract functions the bot may call. See below. |
| `typed_data_allow` | no | EIP-712 messages the bot may sign. See below. |
| `require_admin_cosign_above_usd` | no | Requests above this amount need the owner's approval even inside the caps. |
| `max_slippage_bps` | no | Most a swap may give up below its quote, in basis points. Default 100 (1%). |
| `max_price_deviation_bps` | no | How far a swap's guaranteed output may fall below the input's value at configured prices. Default 500 (5%). |

`[[bots.<name>.core.contracts_allow]]`:

| Setting | Meaning |
|---|---|
| `addr` | Contract address. |
| `selectors` | Function selectors allowed on it, e.g. `"0xa9059cbb"` for ERC-20 `transfer`. |
| `chains` | Chains this rule applies to. Leave out (or empty) for every chain the bot may use. Set it when the same address means something else on another chain. |

`[[bots.<name>.core.typed_data_allow]]`:

| Setting | Meaning |
|---|---|
| `primary_type` | The EIP-712 primary type, e.g. `"Order"`. |
| `verifying_contract` | The contract in the message's domain. Required, except for domains with no chain id. |
| `name` | The domain name. On its own it is only accepted for domains with no chain id, because any contract can claim any name. |
| `chain_id` | Required chain. Default: any of the bot's chains. |
| `chainless` | Set to `true` to allow domains that have no chain id. |

### `[bots.<name>.modules]`

Which protocol modules this bot is offered. Leave the section out to offer every module. See [Protocol modules](modules.md).

| Setting | Default | Meaning |
|---|---|---|
| `hyperliquid` | `true` | `false` removes the `hl_*` tools from this bot's tool list. |
| `uniswap` | `true` | `false` removes the `swap` tool from this bot's tool list. |

### `[bots.<name>.hyperliquid]`

Without this section the bot can't use the Hyperliquid tools. [Hyperliquid](hyperliquid.md) explains each limit.

| Setting | Meaning |
|---|---|
| `markets` | Coins the bot may trade, e.g. `["ETH", "BTC"]`. |
| `max_order_usd` | Largest single order (size × price), in whole USD. |
| `max_position_usd` | Largest position in one coin after the order and the bot's other open orders on that side fill. |
| `max_leverage` | Highest leverage the bot may set or trade at. |
| `daily_loss_stop_usd` | Once the account is down this much since its first check of the UTC day, only orders that reduce positions are allowed. |
| `equity_floor_usd` | Optional. Positive whole USD, at most 1_000_000_000_000. At or below this equity, new risk is refused until `reset_equity_floor`. Unset means no absolute floor. |
| `max_drawdown_from_peak_usd` | Optional. Same bounds. New risk stops this far below the persisted high-water mark. Unset means no trailing floor. |
| `reset_equity_floor` | Optional, default false. Set `true` and restart to clear a latched equity-floor breach once. Set it back to `false` afterward. It does not lower the high-water mark and it does not flatten the account. |
