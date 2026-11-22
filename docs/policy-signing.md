# Signed policy

A bot's rules (chains, caps, allowlists, prices, Hyperliquid limits, module switches) live in a policy file that the owner signs. The server won't run without a validly signed policy, and every audit entry names the exact policy that was in force. So for any signature Keyshare made, you can point to the rules that allowed it and check that they did.

## The file

```toml
version = 3

[[prices]]
chain_id = 11155111
decimals = 18
usd = "2500"

[bots.filltape.core]          # chains, caps, allowlists (see Configuration)
chains = [11155111]
per_tx_cap_usd = 200
daily_cap_usd = 500

[bots.filltape.hyperliquid]   # optional, one section per module
markets = ["ETH"]
# ...

[bots.filltape.modules]       # optional module switches
uniswap = false
```

`policy.example.toml` in the repo root is a full example. [Configuration](configuration.md) lists every setting.

The config points at the file and names who may sign it:

```toml
[server]
policy = "./policy.toml"
policy_signers = ["0xYourOwnerAddress"]
```

## Signing

The policy's **hash** is keccak256 of a canonical JSON form of the file: keys sorted, no spaces, values as written. Comments, key order and spacing don't change the hash; any changed value does. Decimal numbers and dates aren't allowed, so each value has only one spelling.

The owner signs this message as an Ethereum personal message (EIP-191):

```
keyshare policy
version: 3
hash: 0x…
```

```sh
keyshare-mcp policy-hash policy.toml               # prints version, hash and the message
cast wallet sign "<message>" > policy.toml.sig     # any wallet that does personal_sign works
```

On testnet, `keyshare-mcp policy-sign policy.toml OWNER_KEY` signs with a key from an environment variable and writes the `.sig` file.

The server refuses to load the policy when:

- there is no `.sig` file, or it can't be read;
- the signature recovers to an address not in `policy_signers` (this also catches a file edited after signing, since the edited file has a different hash);
- `version` is lower than the newest version this server has accepted, or equals it with different contents;
- a section doesn't parse, or the bots don't match the config's bots exactly.

## Versions and rollback

The newest accepted version and hash are kept in `policy.state.json` in the state folder. An older version is refused even though its signature is valid, so a stolen old policy with looser limits can't be replayed.

To go back to older rules, sign them again under a new, higher version number. That is an explicit owner decision, recorded like any other version.

## Hot reload

The server checks the policy file every `policy_reload_secs` (default 5). When the contents change, it runs every check above. A valid newer version takes over at once: core rules, prices, Hyperliquid limits and module switches. It logs `PolicyLoaded` with the version, hash and signer. A file that fails any check is logged once as `PolicyRejected`, and the policy already in force stays. Nothing needs a restart.

## In the audit log

Every audit entry has a `policy` field with the `version` and `hash` in force when it was written. `Signed` entries, and `Refused` entries where the policy itself made the call, also carry `policy_check`: the 24-hour spend the check used and whether the owner approved the request. Requests are logged in full, so the check can be run again.

## Checking decisions afterwards

```sh
keyshare-mcp policy-verify policy.toml state/audit.jsonl
```

This opens the audit log (which verifies its hash chain), takes every decision made under this policy's hash, rebuilds the request from its `requested` entry, runs the policy again with the recorded spend, and compares the outcome. It prints how many decisions it checked and lists any that don't follow. It exits non-zero if any don't.

It covers the core rules: `send`, `call_contract`, `swap`, `sign_message` and `sign_typed_data`. Hyperliquid limits are named by the same policy hash but aren't re-checked by the verifier yet, because they depend on live account equity.

## The `policy` tool

A bot can call `policy` to see the version, hash, signer and its own rules in plain words. Allowlists are counted, not listed. See [Tools](tools.md).

## Towards zero-knowledge proofs

Each decision is now a pure function with inputs on record:

```
decision = check(policy, request, spent_24h, prices)
```

- `policy` and `prices` are fixed by the signed hash.
- `request` is the exact transaction, message or typed data in the audit entry.
- `spent_24h` is recorded with the decision.

That is the statement a ZK proof would make. The prover shows "I know a policy whose hash is H, signed by the owner, and running `check` on this request with this spend gives `allow`", without revealing the policy itself. The public inputs are the policy hash, the request digest and the spend; the policy is the private witness.

What changes later, and what doesn't:

- **The hash.** keccak256 over JSON is cheap to compute but expensive inside most proof systems. A proof-friendly hash (Poseidon, or a Merkle root over policy sections so a proof opens only the rules it uses) can be added as a second commitment next to this one, signed in the same message.
- **The check.** `PolicyEngine` in `keyshare-core` is the seam. A proving engine implements the same trait, so callers don't change.
- **Who checks.** With threshold signing (#25), the co-signer can either re-run `check` against the same signed policy hash, or accept a proof and skip seeing the policy.
- **Spend.** `spent_24h` is reported by the server today. A proof of the spend itself (over the spend log's hash chain) would remove that trust.

The verifier CLI is the non-ZK version of the same check: it proves nothing to a third party, but it shows that the inputs on record are enough.
