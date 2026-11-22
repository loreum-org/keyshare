//! A threshold bot in the connector: the config names two share files, the in-process co-signer
//! gets the signed policy at start and on every reload, and both sides must agree to sign.

#![allow(clippy::unwrap_used)]

use std::path::Path;

use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy::eips::Decodable2718;
use alloy::primitives::{Address, TxKind, U256, address};
use keyshare_mcp::config::Config;
use keyshare_mcp::exec::Reload;
use keyshare_mcp::policy::testing;
use keyshare_signer::threshold::generate_2of2;

const CHAIN: u64 = 11155111;
const OWNER: Address = address!("0x1111111111111111111111111111111111111111");
const NOW: u64 = 1_800_000_000;

fn config_text(state: &Path, keys: &Path, per_tx_cap: u64) -> String {
    format!(
        r#"
        [server]
        listen = "127.0.0.1:0"
        state_dir = "{state}"
        policy_reload_secs = 0

        [[prices]]
        chain_id = {CHAIN}
        decimals = 18
        usd = "2000"

        [bots.bot]
        credential_sha256 = "0x0000000000000000000000000000000000000000000000000000000000000000"
        [bots.bot.threshold]
        share = "{share}"
        cosigner_share = "{co}"
        [bots.bot.policy]
        chains = [{CHAIN}]
        per_tx_cap_usd = {per_tx_cap}
        daily_cap_usd = 1000
        recipients_allow = ["{OWNER}"]
        "#,
        state = state.display(),
        share = keys.join("share.json").display(),
        co = keys.join("cosigner.share.json").display(),
    )
}

fn send(dollars: u64, nonce: u64) -> TxEip1559 {
    TxEip1559 {
        chain_id: CHAIN,
        nonce,
        gas_limit: 21_000,
        max_fee_per_gas: 1,
        max_priority_fee_per_gas: 1,
        to: TxKind::Call(OWNER),
        value: U256::from(dollars) * U256::from(5 * 10u64.pow(14)),
        ..Default::default()
    }
}

#[tokio::test]
async fn threshold_bot_signs_and_cosigner_follows_policy_reloads() {
    let dir = tempfile::tempdir().unwrap();
    let keys = dir.path().join("keys");
    let (share, co) = generate_2of2().unwrap();
    share.save(&keys.join("share.json")).unwrap();
    co.save(&keys.join("cosigner.share.json")).unwrap();

    let state = dir.path().join("state");
    let config_path = testing::write_signed(dir.path(), &config_text(&state, &keys, 100));
    let config = Config::load(&config_path).unwrap();
    let exec = keyshare_mcp::build(&config, |_| None).await.unwrap();
    let wallet = exec.wallet();
    assert_eq!(wallet.lock().unwrap().address("bot").unwrap(), share.address());

    let signed = wallet.lock().unwrap().sign_transaction("bot", "a", send(50, 0), NOW).unwrap();
    let env = TxEnvelope::decode_2718(&mut signed.raw.as_ref()).unwrap();
    let sig = *env.as_eip1559().unwrap().signature();
    assert_eq!(sig.recover_address_from_prehash(&send(50, 0).signature_hash()).unwrap(), share.address());
    assert!(state.join("cosigner/bot.spend.jsonl").exists(), "co-signer keeps its own spend log");

    // A newly signed policy reaches the co-signer too; otherwise it would refuse with
    // POLICY_MISMATCH after the reload.
    testing::write_signed(dir.path(), &config_text(&state, &keys, 200));
    assert!(matches!(exec.reload_policy(&config).await, Reload::Loaded(_)));
    wallet.lock().unwrap().sign_transaction("bot", "b", send(150, 1), NOW).unwrap();
}

#[test]
fn bot_needs_exactly_one_key_source() {
    let dir = tempfile::tempdir().unwrap();
    let both = config_text(dir.path(), dir.path(), 100)
        .replace("[bots.bot.threshold]", "key_env = \"BOT_KEY\"\n        [bots.bot.threshold]");
    let path = testing::write_signed(dir.path(), &both);
    let config = Config::load(&path).unwrap();
    let policy = keyshare_mcp::policy::load(&config).unwrap();
    let err = config.wallet(|_| Some("0x01".into()), &policy.set).err().unwrap();
    assert!(err.to_string().contains("exactly one of key_env or threshold"), "{err}");
}
