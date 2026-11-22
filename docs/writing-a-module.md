# Writing a module

A module turns a bot's tool call into an unsigned [intent](architecture.md). It does not hold a key, and it does not import `LocalSigner`. The host (`keyshare-mcp`) is the only crate that loads keys and calls `sign_typed_data` or `sign_transaction`.

OpenSea (#18) is the next module. This is the shape it should follow. Hyperliquid (`crates/keyshare-hyperliquid`) and Uniswap (`crates/keyshare-uniswap`) are the two copies that exist today.

## 1. Add a crate

```toml
[dependencies]
keyshare-core = { path = "../keyshare-core" }
keyshare-module = { path = "../keyshare-module" }
```

The workspace already includes `crates/*`. Do not give the crate a dependency that can sign. `keyshare-core` exports `LocalSigner` for the host and the tests; a module's source must not call it. `crates/keyshare-hyperliquid` keeps a unit test that fails if `client.rs` names the signer.

## 2. Implement `ProtocolModule`

```rust
impl ProtocolModule for MyModule {
    fn id(&self) -> &'static str { "my-protocol" }

    fn tools(&self) -> &'static [ToolDecl] {
        &[ToolDecl { name: "my_tool", description: "What the bot sees." }]
    }

    fn allowlist(&self) -> ModuleAllowlist {
        // Addresses, selectors, and EIP-712 domains this module may ask
        // the core to sign. The host snapshots this at startup.
        my_allowlist()
    }

    fn validate_policy(&self, value: &toml::Value) -> Result<(), String> {
        // Parse this module's own config table. Reject zero caps and
        // unknown fields here. Core caps are not this function's job.
        Ok(())
    }

    fn limits_key(&self) -> &'static str { "my_protocol" }
}
```

`allowlist` is the ceiling. If the running code later builds an intent outside it, `Intent::check` returns `CONTRACT_NOT_ALLOWED` or `TYPED_DATA_NOT_ALLOWED` and nothing is signed.

Patterns:

- `ContractAllow::Call { chain_id, to, selector }` for one function on one contract.
- `ContractAllow::Approve { chain_id, spender }` for an exact `approve` whose spender is a contract you already named. The token address may vary. Any other spender is refused.
- `TypedAllow` for an EIP-712 primary type, domain name, version, chain id, verifying contract, and string fields that must match (`message_equals`). Hyperliquid pins `source` to `"b"` so a mainnet payload cannot slip through.

## 3. Talk to the host through `Core`

The handler takes `&dyn Core`. Use it for:

| Method | Use |
|---|---|
| `address`, `kill_check` | Who the bot is, and whether signing is frozen. |
| `preview_module_tx` | Allowlist re-check plus core policy, nothing signed. |
| `submit_module_tx` | Allowlist re-check, then the normal simulate / sign / broadcast path, including owner approval and `request_id`. |
| `sign_venue` | Allowlist re-check, then a signature from the venue key the host holds. The method does not return the key. |
| `venue_key_ready` | Same key check, before you burn a nonce, still without the key bytes. |
| `log_event`, `log_refusal` | Audit lines. A signature still has a log line because the host writes it. |
| `eth_call`, `token_decimals`, `tx_status`, `uniswap` | Chain reads. No signing. |

Do not add a method that takes a hex key. If the module needs a new host capability, add it to `Core` in `keyshare-module` without a key parameter, and implement it in `keyshare-mcp`.

## 4. Register it

In `Executor::new` (or the builder that loads config), `registry.register(Arc::new(module))` or `registry.claim_tools(id, TOOLS)` if the tool list must exist before the client is constructed. Claimed tools are how a disabled module disappears from `tools/list`.

Wire the config flag in `[bots.<id>.modules]` with a default of `true`, so existing files do not change. `Executor::module_enabled` hides the tool and rejects the call when the flag is false.

If the module has its own policy table, parse it with `deny_unknown_fields` and call `validate_policy` at startup. Keep the old key names if bots already have them. Hyperliquid's table is still `[bots.<id>.hyperliquid]`.

## 5. State files

Put files under `state_dir/<module>/` and do not rename files that already exist. Hyperliquid still uses:

- `state_dir/hyperliquid/<bot>.agent.json`
- `state_dir/hyperliquid/<bot>.day.json`
- `state_dir/hyperliquid/<bot>.equity.json`

The agent file is read by the host, not by the module.

## 6. Tests to add

- The module crate does not call `LocalSigner` or `sign_typed_data`. A source check is enough if the type system already keeps the key off `Core`.
- An intent outside the module allowlist is refused by `Intent::check` even though the module built it.
- With the module disabled for a bot, `tools/list` does not include its tools and `tools/call` returns tool-not-found.
- Existing tool names, argument schemas, refusal codes, and config keys still pass the current integration tests.

Core policy stays strict. A new module must not widen caps, skip the kill switch, or sign a chain or domain the allowlist does not name. Phase 0 still refuses Hyperliquid mainnet.
