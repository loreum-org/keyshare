# Security

keyshare is experimental wallet software. Phase 0 is a testnet signer with one key per bot. It has not been tested on a live network and it has not been independently audited. Do not put real funds behind it.

## Reporting a vulnerability

Report security issues in a [private GitHub security advisory](https://github.com/loreum-org/keyshare/security/advisories/new).

Include what you found, how to reproduce it, and the impact. Please wait for a fix before any public write-up. Do not open a public GitHub issue for a suspected vulnerability.

Private vulnerability reporting has to be enabled in the repository settings. Until the repository is public, only people with access can open an advisory.

## Scope

In scope: the signer, policy enforcement, and the MCP connector in this repository.

Out of scope: already-fixed issues in dependencies, and attacks that need physical access to a machine that already holds key material.
