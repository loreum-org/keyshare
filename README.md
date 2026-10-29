# keyshare

A threshold-signing wallet for humans and agents. The signing key is a plain EOA from a 2-of-3 distributed key generation, so the full private key never exists. Each signer node enforces policy in plain Rust. ZK proofs are a later option, not part of v1. There is no Safe or smart-account layer.

**Status:** Phase 0 (testnet MVP) in progress. Design draft v0.1 (Oct 18, 2026).

**License:** TBD

Full design: [docs/design.md](docs/design.md).

## Code

| Crate | What it does |
|---|---|
| `crates/keyshare-core` | Signer trait (single testnet key now, 2-of-3 later), per-bot policy, spend counter, audit log, kill switch, and the signing path that ties them together. |
| `crates/keyshare-mcp` | MCP connector over streamable HTTP. Bots log in with a bearer token. Tools: `address`, `limits`, `balances`, `simulate`, `send`, `call_contract`, `tx_status`, `sign_message`, `sign_typed_data`. Over-limit requests wait for the owner's signed approval at `/admin/decide`. |

```sh
cargo test
keyshare-mcp new-token                                  # bot token + hash for the config
FILLTAPE_KEY=0x... keyshare-mcp serve keyshare.example.toml
keyshare-mcp freeze keyshare.example.toml [bot]         # kill switch
```

## What it is

One wallet API, with an MCP connector, that can read balances, send, swap, sign messages, call contracts, and trade on Hyperliquid. Two wallet types share the same key system.

**Human wallets.** The device share sits in the phone Secure Enclave or Android Keystore, behind a passkey or biometrics, with an encrypted backup. The user approves every signature on the device. Normal signing is the device plus one node.

**Agent wallets.** Used by an owner's bots. The first deployment is Chad's bots (Loreum, FillTape, TeamShared). Shares are held by nodes, or one share is bot-held, plus the owner's offline backup. Each bot has its own policy and limits. Each signer node enforces the cap from its own counter; the nodes do not have to agree on one spend total before signing. In the bot-held layout only Node A is in the online quorum, so only Node A enforces the cap. A human wallet can also delegate limited, expiring, revocable authority to an agent.

## Owner-admin model

Every user is the admin of their own wallets. Admin keys authorize policy, grants, over-limit approvals, and the kill switch. They are not key shares and cannot sign transactions by themselves. Organizations can use M-of-N admins, and Chamber can hold the admin role. Node operators, including Loreum, enforce policy and can halt signing. They cannot change policy, raise limits, or move funds alone.

## Trust model

Trust rests on fewer than *t* of *n* independent operators being compromised (2-of-3). One bad node cannot sign. Policy is plain Rust on each signer, not a proof. The coordinator holds no key share. There is no on-chain spending limit or time-lock: if the threshold is compromised or a policy bug lets a bad transaction through, the chain will accept it. Mitigations are small balances, separate wallets per bot, independent operators, resharing, and a kill switch.

## Architecture

```mermaid
flowchart LR
  subgraph Callers
    HU[Human app<br/>passkey + biometrics]
    LB[Loreum bot]
    FB[FillTape bot]
    TB[TeamShared bot]
  end

  subgraph MCP["Wallet MCP connector (Railway)"]
    API[Tool API + caller auth<br/>human session / bot credential]
    SIM[Simulator<br/>eth_call / trace / Tenderly-style]
    POL[Policy pre-check<br/>fails fast, not enforcement]
    COORD[Signing coordinator<br/>holds NO key share]
    LOG[(Append-only audit log)]
  end

  subgraph Shares["Key shares (2-of-3 per wallet)"]
    DEV[Device share<br/>Secure Enclave / Keystore<br/>human wallets]
    N1[Node A<br/>share + plain-Rust policy + counters]
    N2[Node B<br/>share + plain-Rust policy + counters]
    BOTS[Bot-held share<br/>optional, agent wallets]
    COLD[Owner offline backup share<br/>agent wallets, offline]
  end

  LH["Human wallet = Device + Node A + Node B<br/>normal signing: Device + 1 node"]
  LA["Agent wallet = Node A + Node B + Owner cold<br/>(or Bot share + Node A + Owner cold)<br/>normal signing: 2 online shares"]

  STATE[(Policy store + per-node spend counters<br/>+ delegation grants<br/>Merkle root committed)]
  ADMIN[Owner admin keys<br/>passkey + hardware key, not shares<br/>or M-of-N org admins / Chamber]
  RPC[(Chain RPCs<br/>Ethereum, Base, Arbitrum)]
  HLAPI[(Hyperliquid API)]

  HU -->|request + on-device approval| API
  LB & FB & TB -->|MCP call + bot credential| API
  API --> SIM --> RPC
  API --> POL --> COORD
  COORD -->|raw tx| N1 & N2
  COORD <-->|TSS rounds DKLs23 / CGGMP| N1 & N2
  COORD <-->|TSS rounds after user approval| DEV
  COORD <-.->|agent wallets that hold a share| BOTS
  COLD -.->|recovery / resharing only| COORD
  DEV --- LH
  BOTS --- LA
  COLD --- LA
  N1 & N2 <--> STATE
  ADMIN -->|signed admin actions: policy, grants, over-limit, kill switch| STATE
  HU -->|signed delegation grants| STATE
  COORD -->|signed tx| RPC
  COORD -->|EIP-712 signed action| HLAPI
  API --> LOG
  N1 & N2 --> LOG
```

## Roadmap

| Phase | Scope |
|---|---|
| **0 — Testnet MVP** | MCP connector, local single-key signer, simulation, plain-Rust policy, audit log, kill switch. No ZK proofs. **In progress.** |
| **1 — Interim production** (optional) | Same API, vendor policy-enforced keys (Turnkey, or Privy/CDP). Small mainnet balances. |
| **2 — Own TSS network** | DKLs23 2-of-3. Each node enforces policy in plain Rust. Human wallet app, owner admin model. |
| **3 — Chamber offering** (optional) | Signer network and plain-Rust policy for DAO and agent treasuries. |
| **4 — Multiple addresses** (later) | Labeled addresses from one threshold key via non-hardened derivation. |
| **5 — ZK policy proofs** (later, optional) | Only if a third party must verify that policy was followed, or policy must be hidden from node operators. Noir, with SP1 as the alternative. |

Details, threat model, the MCP tool API, operations, and recovery are in [docs/design.md](docs/design.md).
