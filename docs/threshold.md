# Threshold signing (2-of-2)

A bot's wallet can use a threshold key instead of a single private key. Key generation makes two **shares** of one Ethereum address. Neither share can sign alone, and the full private key is never put together, not even during key generation.

- **Share 1** is the bot's. The connector holds it.
- **Share 2** is the **co-signer's**. The co-signer is the owner, or a policy service the owner runs.

Every signature takes both. The co-signer is sent the whole request (the transaction, message or EIP-712 data), never just a hash. It computes the hash itself, checks the request against its own copy of the signed policy and its own spend total, and only then does its half of the signing. If either side says no, there is no signature.

## Setting it up (testnet)

```sh
keyshare-mcp threshold-keygen ./keys      # writes keys/share.json and keys/cosigner.share.json
```

It prints the wallet address. In the config, replace the bot's `key_env` with:

```toml
[bots.filltape.threshold]
share = "./keys/share.json"
cosigner_share = "./keys/cosigner.share.json"
```

A bot has either `key_env` or `threshold`, not both. Nothing changes in the policy file.

With this setup the co-signer runs **inside the connector**. It does its own policy check and keeps its own spend log (`state/cosigner/<bot>.spend.jsonl`), and it picks up each newly signed policy along with the wallet. But both shares are on one machine, so it protects nothing against someone who controls that machine. It is for trying threshold signing on testnet. A co-signer on a separate machine is the next step (see below).

## Refreshing shares

```sh
keyshare-mcp threshold-refresh ./keys/share.json ./keys/cosigner.share.json
```

This replaces both shares with new random ones for the **same address**, so no funds move. An old share does not work with a new one, so a share that leaked before the refresh is useless after it. Stop the server first (a running server keeps the old shares in memory), and back up both new files. Then delete or overwrite every old copy of **both** shares, backups included: the two old shares together still sign for the same address. If the second file can't be replaced, the command says so and leaves the new co-signer share next to it as `.new`; move it into place by hand, since a new bot share and an old co-signer share don't combine.

**Backup.** Losing either share loses the wallet. Keep an encrypted copy of each share in a different place. Never keep both copies together, or the backup is the full key.

## Moving an existing bot to a threshold key

There is no way to split an existing private key into shares safely (the key has already existed whole). So:

1. Run `threshold-keygen` to get a new address.
2. Add a new bot (or switch the existing bot's config to `threshold`) and restart.
3. Send the funds from the old address to the new one, then retire the old key.

On testnet this is cheap. The old address's history stays with the old address. Hyperliquid agent approvals (`hl-approve-agent`) still need a single-key bot for now.

## What each party can and can't do

| If this is compromised | It can | It can't |
|---|---|---|
| **Bot host** (connector and share 1), with a separate co-signer | Ask for any signature; skip or lie in its own checks; wipe its own spend log and audit log | Get a signature the co-signer's policy refuses; reset the co-signer's daily total; replay a request id; get a signature for a different hash than the request the co-signer checked |
| **Co-signer** (share 2) | Refuse to sign (the wallet stops); see every request | Sign anything alone; change what the bot asked for |
| **A protocol module** (Hyperliquid, Uniswap) | Build a request for the connector to check | Reach any share: modules can't depend on the signer crate (`tests/boundary.rs`) |
| **Both shares** (same machine today, or both backups stolen) | Everything: it is the full key | |
| **One old share after a refresh** | Nothing | Combine with a new share |

Other limits:

- **Spend counts at the start.** The co-signer uses up the request id and records the spend before the signing rounds run. A request that then fails part-way (a dropped connection, a protocol error) still counts toward the co-signer's daily cap, but not the wallet's, so the co-signer can refuse for its daily limit while the wallet's total looks lower. Its request id can't be reused: retry with a new one. This errs on the safe side.
- **Unfinished sessions** expire after 60 seconds (a late `finish` is refused), and a co-signer keeps at most 64 open.
- **A cheating counterparty is banned.** If the protocol detects the other party misbehaving in a way that could leak key material, the co-signer refuses all further signing. The ban is saved next to its spend log (`<bot>.spend.banned`), so a restart doesn't clear it. Make a new key and move the funds.
- **Where the co-signer's policy comes from.** The in-process co-signer is handed the policy the connector verified. A co-signer on another machine must verify the owner's signature on the policy file itself.
- **The wallet checks the result.** The connector only returns a signature that recovers to the wallet's address.

## Library

Keyshare uses [`dkls23`](https://crates.io/crates/dkls23) 0.6 by 0xCarbon (MIT or Apache-2.0), an implementation of DKLs23 threshold ECDSA in Rust.

| Option | License | Audit | Why not / why |
|---|---|---|---|
| **0xCarbon `dkls23`** (chosen) | MIT / Apache-2.0 | None public | Permissive license, DKLs23 as designed, full DKG, signing and refresh. Works with our types. |
| Silence Labs `sl-dkls23` | Silence Labs non-commercial license | Trail of Bits | Can't be used in a commercial product without a separate license. |
| `cggmp21` / CGGMP24 (Dfns, LFDT) | MIT / Apache-2.0 | Kudelski | Audited, but a different protocol (more rounds, Paillier keys, slower key generation). A fallback if we need an audited library sooner. |

The chosen library has **no public audit**. Before real money: get it audited (or switch to an audited library), and pin its exact version.

Speed in a release build: key generation about 1 second, each signature about 10 ms (both parties on one machine).

## What's next

- **A separate co-signer.** Run the co-signer as its own service, on another machine, holding only share 2 and its own copy of the signed policy. The protocol messages are already serializable (`CoSignRequest`, `CoSignStarted`), and the connector only needs a client that implements `CoSigner` over a network call.
- **Key generation across two machines**, so share 2 never touches the bot host, even at setup.
- **2-of-3** (bot, co-signer, owner backup) as in the [design](design.md).
- A testnet run: sign and broadcast a Sepolia transaction from a threshold address.
