# Overview

## What Keyshare is

Keyshare holds wallets for bots and signs for them, within limits the owner sets. A bot never holds its own key. It asks Keyshare to do something, and Keyshare either does it or refuses with a reason the bot can act on.

One Keyshare server can serve many bots. Each bot has:

- its own wallet address
- its own login token
- its own rules: which chains, which recipients, which contracts, how much per send and per day
- optionally, owner keys that can approve requests above those limits
- optionally, a Hyperliquid trading account with its own trading limits

## What works today (Phase 0)

Phase 0 is for testnets only. It uses one ordinary private key per bot, read from an environment variable. The 2-of-3 threshold signing in the design comes later and will plug into the same place.

Bots can:

- read their address, limits, and balances
- simulate a transaction without signing it
- send native tokens or ERC-20 tokens
- call allowlisted contract functions
- swap tokens on Uniswap v3
- sign plain-text messages and allowlisted EIP-712 typed data
- trade perpetuals on Hyperliquid testnet
- check the status of anything they sent

The owner can:

- set each bot's rules in one config file
- approve or deny requests that go over a bot's limits
- freeze one bot, or all bots, at any time
- read an append-only audit log of every request

## What is not built yet

- Threshold signing (2-of-3 key shares). Today each bot has one plain key.
- Human wallets on phones.
- Live market prices. Prices for the spending caps come from a fixed table in the config.
- Notifications to the owner when a request is held. The owner has to check the pending list.
- Testing against live networks. Everything is tested against mock chains and a mock Hyperliquid. One real Sepolia send, one real Hyperliquid testnet order, and one real swap are still to be done.

## How a request flows

1. The bot calls a tool over MCP with its token.
2. Keyshare looks up which bot the token belongs to. The bot is never taken from the request itself.
3. The kill switch is checked. A frozen bot is refused.
4. The request is checked against the bot's policy: chain, recipient or contract, function, amount, and the per-send and daily caps.
5. If the check fails in a way the owner can override, and the bot has owner keys, the request is held for the owner. Otherwise it is refused.
6. The transaction is simulated on the chain. A transaction that would revert is refused.
7. Nonce, gas and fees are filled in, and the policy check runs again on the final transaction.
8. The spend is recorded, then the transaction is signed and broadcast.
9. Every step is written to the audit log.

A refusal always has a code and a plain reason, for example `CAP_EXCEEDED: daily cap $500 would be exceeded`. Bots should explain the refusal to their owner rather than retry blindly.

## Supported chains

Any EVM chain with an RPC can be added in the config. The example config uses Ethereum Sepolia. Arbitrum, Base and OP Sepolia work the same way: add the chain, its prices, and the chain id in each bot's policy. Allowlist entries can be tied to specific chains, so an address allowed on one chain isn't automatically allowed on another.

Hyperliquid is testnet only in Phase 0. The code refuses to point at mainnet.
