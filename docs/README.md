# Keyshare docs

Keyshare is a wallet service for bots. Each bot gets its own wallet and its own spending rules. A bot talks to Keyshare over MCP, asks it to send, swap, sign or trade, and Keyshare checks the request against that bot's rules before it signs.

These docs cover what is built today (Phase 0). The long-term design, including 2-of-3 threshold signing and human wallets, is in [design.md](design.md).

| Doc | What it covers |
|---|---|
| [Overview](overview.md) | What Keyshare does today, what it doesn't do yet, and how a request flows through it |
| [Running Keyshare](running.md) | Building, first setup, the command line, and deploying |
| [Configuration](configuration.md) | Every setting in the config file |
| [Tools](tools.md) | Every tool a bot can call, its inputs and what it returns, and the refusal codes |
| [Policy](policy.md) | How a request is checked: chains, allowlists, caps, prices, typed data, blocked calls |
| [Owner approvals](owner-approvals.md) | How over-limit requests wait for the owner, and how the owner approves or denies them |
| [Swaps](swaps.md) | Uniswap v3 swaps and their safety checks |
| [Hyperliquid](hyperliquid.md) | Trading on Hyperliquid testnet with agent keys and trading limits |
| [Protocol modules](modules.md) | How Hyperliquid and Uniswap sit outside the core, and how to add a module |
| [Safety and state](safety.md) | The kill switch, the spend log, the audit log, and known gaps before mainnet |
| [Code layout](code.md) | Where things live in the source, for developers |
| [Design](design.md) | The full long-term design (v0.1) |
