# Safety and state

What protects the wallet besides the policy, and the files Keyshare keeps.

## Kill switch

The kill switch stops signing, for every bot or for one.

```sh
keyshare-mcp freeze   keyshare.toml            # all bots
keyshare-mcp freeze   keyshare.toml filltape   # one bot
keyshare-mcp unfreeze keyshare.toml [bot]
```

It is a small file, `kill.json` in the state folder:

```json
{ "global": false, "callers": ["filltape"] }
```

Keyshare reads it before every signature, so a change takes effect on the next request with no restart. You can also edit it by hand. If the file can't be read or parsed, everything is frozen.

A frozen bot can still read (address, limits, balances, status). It can't sign anything, including Hyperliquid cancels.

## Spend log

Every approved spend is written to `spend.jsonl` **before** the signature is returned. The daily cap is the sum of this log over the last 24 hours. The log also holds every used request id, which is how a retry is caught.

Each line includes a hash of the line before it. When Keyshare opens the log it checks the whole chain, so an edited line, or a line removed from the middle, stops the server from starting.

## Rollback guard

Restoring an old copy of the state folder would wipe recent spending and let a bot spend its daily cap again. To catch this, Keyshare copies the latest position and hash of the spend log to an anchor file after every write (`spend.anchor.json`, or wherever `spend_anchor` points). Put it on a different disk from the state folder.

Before signing, Keyshare checks the log against the anchor. If the log is behind, differs, or the anchor is missing while the log has entries, every request is refused with `COUNTER_BEHIND_ANCHOR` until an operator looks.

Limit: if both the log and the anchor are deleted, Keyshare starts fresh with no spending history.

## Audit log

`audit.jsonl` records every signing request: when it arrived, the outcome (`Signed`, `Refused`, or `Held` for the owner), the bot, the request id and the details. The request is logged before it is checked, so nothing is signed without a record. It is hash-chained the same way as the spend log.

## State folder

| File | What it is |
|---|---|
| `spend.jsonl` | Spend log and used request ids. |
| `spend.anchor.json` | Rollback anchor (unless `spend_anchor` points elsewhere). |
| `audit.jsonl` | Audit log. |
| `kill.json` | Kill switch. |
| `hyperliquid/<bot>.agent.json` | Hyperliquid agent keys, readable only by the server's user. |

Back up the folder, but never restore it over a running wallet without understanding the rollback guard above. Only one server may use a state folder at a time.

Bot wallet keys are not in the state folder. They come from environment variables named in the config.

## What is kept only in memory

Held requests and Hyperliquid request ids. A restart drops held requests (they never sign) and forgets which Hyperliquid request ids were used.

## Dependency advisory

CI runs `cargo audit`. `.cargo/audit.toml` ignores RUSTSEC-2026-0387, an advisory in `crypto-bigint` with no fixed version yet. Issue #13 tracks removing the ignore once one ships.

## Before mainnet

Known gaps that are fine on testnet but must be closed first:

- Gas isn't counted against the caps.
- Deleting both the spend log and the anchor resets spending history.
- Allowlisted typed-data orders (for example Seaport or CoW) count as $0.
- Finished requests stay in the server's memory until restart; there is no expiry.
- An owner approval isn't tied to one specific hold (see [Owner approvals](owner-approvals.md)).
- Prices are a fixed table in the config, not a live feed.
- There is one key per bot, not 2-of-3 threshold signing. That is Phase 1.
