//! 2-of-2 threshold signing: the wallet signs only when its co-signer, with its own copy of the
//! policy and its own spend counter, agrees. Neither share signs alone.

#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy::eips::Decodable2718;
use alloy::primitives::{Address, B256, TxKind, U256, address, eip191_hash_message};
use alloy::signers::SignerSync;
use alloy::signers::local::PrivateKeySigner;
use keyshare_core::approval::{Decision, intent_hash, message};
use keyshare_core::policy_file::PolicyRef;
use keyshare_core::price::PriceEntry;
use keyshare_core::{Account, PlainPolicy, PriceTable, RefusalCode, Signer, SignerError, StatePaths, Wallet};
use keyshare_signer::threshold::{
    CoSignerPolicy, KeyShare, LocalCoSigner, ThresholdSigner, generate_2of2, refresh_2of2,
};

const CHAIN: u64 = 11155111;
const OWNER: Address = address!("0x1111111111111111111111111111111111111111");
const NOW: u64 = 1_800_000_000;
const BOT: &str = "bot";

fn shares() -> &'static (KeyShare, KeyShare) {
    static SHARES: OnceLock<(KeyShare, KeyShare)> = OnceLock::new();
    SHARES.get_or_init(|| generate_2of2().unwrap())
}

fn policy(per_tx: u64, daily: u64) -> PlainPolicy {
    toml::from_str(&format!(
        r#"
        chains = [{CHAIN}]
        per_tx_cap_usd = {per_tx}
        daily_cap_usd = {daily}
        recipients_allow = ["{OWNER}"]
        "#
    ))
    .unwrap()
}

fn prices() -> PriceTable {
    PriceTable::from_entries(&[PriceEntry { chain_id: CHAIN, token: None, decimals: 18, usd: "2000".into() }]).unwrap()
}

fn reference(version: u64) -> PolicyRef {
    PolicyRef { version, hash: B256::repeat_byte(version as u8) }
}

fn cosigner(
    share: &KeyShare,
    dir: &Path,
    per_tx: u64,
    daily: u64,
    version: u64,
    admins: &[Address],
) -> Arc<LocalCoSigner> {
    let policy = CoSignerPolicy {
        bot: BOT.into(),
        policy: reference(version),
        engine: Box::new(policy(per_tx, daily)),
        prices: Box::new(prices()),
        admins: admins.to_vec(),
    };
    let co = LocalCoSigner::new(share.clone(), &dir.join("cosigner.spend.jsonl")).unwrap();
    co.set_policy(policy);
    Arc::new(co)
}

/// The bot server's wallet: share 1, its own policy and its own state folder.
fn wallet(state: &Path, signer: ThresholdSigner, per_tx: u64, version: u64, admins: &[Address]) -> Wallet {
    std::fs::create_dir_all(state).unwrap();
    let paths = StatePaths {
        spend_log: state.join("spend.jsonl"),
        spend_anchor: None,
        audit_log: state.join("audit.jsonl"),
        kill_switch: state.join("kill.json"),
    };
    let mut accounts = HashMap::new();
    accounts.insert(
        BOT.to_string(),
        Account { signer: Box::new(signer), policy: Box::new(policy(per_tx, 1000)), admins: admins.to_vec() },
    );
    let mut w = Wallet::open(accounts, Box::new(prices()), &paths).unwrap();
    let mut engines: HashMap<String, Box<dyn keyshare_core::PolicyEngine>> = HashMap::new();
    engines.insert(BOT.into(), Box::new(policy(per_tx, 1000)));
    w.apply_policy(reference(version), engines, Box::new(prices()), serde_json::json!({}), NOW).unwrap();
    w
}

fn send(dollars: u64, nonce: u64) -> TxEip1559 {
    TxEip1559 {
        chain_id: CHAIN,
        nonce,
        gas_limit: 21_000,
        max_fee_per_gas: 1,
        max_priority_fee_per_gas: 1,
        to: TxKind::Call(OWNER),
        // $2000 per ETH: 1 dollar = 0.0005 ETH.
        value: U256::from(dollars) * U256::from(5 * 10u64.pow(14)),
        ..Default::default()
    }
}

#[test]
fn signs_only_with_both_shares_and_signatures_recover() {
    let (bot, co) = shares();
    assert_eq!(bot.address(), co.address());
    assert_eq!((bot.index(), co.index()), (1, 2));
    let dir = tempfile::tempdir().unwrap();
    let signer = ThresholdSigner::new(bot.clone(), cosigner(co, dir.path(), 200, 500, 1, &[])).unwrap();
    let mut w = wallet(&dir.path().join("state"), signer, 200, 1, &[]);

    let signed = w.sign_transaction(BOT, "a", send(100, 0), NOW).unwrap();
    let env = TxEnvelope::decode_2718(&mut signed.raw.as_ref()).unwrap();
    let sig = *env.as_eip1559().unwrap().signature();
    assert_eq!(sig.recover_address_from_prehash(&send(100, 0).signature_hash()).unwrap(), bot.address());

    let sig = w.sign_message(BOT, "m", b"hello", NOW).unwrap();
    assert_eq!(sig.recover_address_from_prehash(&eip191_hash_message(b"hello")).unwrap(), bot.address());

    // Each share is built for exactly one role.
    assert!(ThresholdSigner::new(co.clone(), cosigner(co, dir.path(), 1, 1, 1, &[])).is_err());
}

#[test]
fn cosigner_refusal_means_no_signature() {
    let (bot, co) = shares();
    let dir = tempfile::tempdir().unwrap();
    // The bot server allows $200 per send; the co-signer's own policy allows $50.
    let signer = ThresholdSigner::new(bot.clone(), cosigner(co, dir.path(), 50, 500, 1, &[])).unwrap();
    let mut w = wallet(&dir.path().join("state"), signer, 200, 1, &[]);
    let r = w.sign_transaction(BOT, "a", send(100, 0), NOW).unwrap_err();
    assert_eq!(r.code, RefusalCode::PerTxCapExceeded);
    assert!(r.reason.starts_with("co-signer:"), "{r:?}");
    w.sign_transaction(BOT, "b", send(40, 0), NOW).unwrap();
}

#[test]
fn bot_side_refusal_never_reaches_the_cosigner() {
    let (bot, co) = shares();
    let dir = tempfile::tempdir().unwrap();
    let co_signer = cosigner(co, dir.path(), 200, 500, 1, &[]);
    let signer = ThresholdSigner::new(bot.clone(), co_signer).unwrap();
    let mut w = wallet(&dir.path().join("state"), signer, 50, 1, &[]);
    let r = w.sign_transaction(BOT, "a", send(100, 0), NOW).unwrap_err();
    assert_eq!(r.code, RefusalCode::PerTxCapExceeded);
    assert!(!r.reason.starts_with("co-signer:"));
    // The co-signer recorded nothing, so the same request id still works there.
    let empty = keyshare_core::spend::SpendLog::open(dir.path().join("cosigner.spend.jsonl"), None).unwrap();
    assert_eq!(empty.spent_24h(BOT, NOW), 0);
}

#[test]
fn cosigner_refuses_other_policy_version_and_bare_signing() {
    let (bot, co) = shares();
    let dir = tempfile::tempdir().unwrap();
    // The co-signer has version 2; the bot server still runs version 1.
    let signer = ThresholdSigner::new(bot.clone(), cosigner(co, dir.path(), 200, 500, 2, &[])).unwrap();
    let mut w = wallet(&dir.path().join("state"), signer, 200, 1, &[]);
    assert_eq!(w.sign_transaction(BOT, "a", send(10, 0), NOW).unwrap_err().code, RefusalCode::PolicyMismatch);

    // Calling the signer directly, outside the wallet, carries no request: refused.
    let signer = ThresholdSigner::new(bot.clone(), cosigner(co, dir.path(), 200, 500, 1, &[])).unwrap();
    match signer.sign_transaction(&send(10, 0)) {
        Err(SignerError::Refused(r)) => assert_eq!(r.code, RefusalCode::UnknownCaller),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn cosigner_keeps_its_own_daily_total_when_the_bot_server_forgets() {
    let (bot, co) = shares();
    let dir = tempfile::tempdir().unwrap();
    let co_signer = cosigner(co, dir.path(), 200, 300, 1, &[]);

    let signer = ThresholdSigner::new(bot.clone(), co_signer.clone()).unwrap();
    let mut w = wallet(&dir.path().join("state-a"), signer, 200, 1, &[]);
    w.sign_transaction(BOT, "a", send(200, 0), NOW).unwrap();
    drop(w);

    // A compromised host wipes its state and starts fresh. The co-signer still counts $200.
    let signer = ThresholdSigner::new(bot.clone(), co_signer.clone()).unwrap();
    let mut w = wallet(&dir.path().join("state-b"), signer, 200, 1, &[]);
    let r = w.sign_transaction(BOT, "b", send(150, 1), NOW).unwrap_err();
    assert_eq!(r.code, RefusalCode::CapExceeded, "{r:?}");
    // And it won't sign a request id it has already signed.
    let r = w.sign_transaction(BOT, "a", send(10, 1), NOW).unwrap_err();
    assert_eq!(r.code, RefusalCode::NonceReused, "{r:?}");
}

#[test]
fn owner_approval_is_checked_by_the_cosigner_too() {
    let (bot, co) = shares();
    let dir = tempfile::tempdir().unwrap();
    let admin = PrivateKeySigner::random();
    let co_signer = cosigner(co, dir.path(), 50, 500, 1, &[admin.address()]);
    let signer = ThresholdSigner::new(bot.clone(), co_signer).unwrap();
    let mut w = wallet(&dir.path().join("state"), signer, 50, 1, &[admin.address()]);

    let tx = send(100, 0);
    let approve = |id: &str, tx: &TxEip1559| {
        admin.sign_message_sync(message(Decision::Approve, BOT, id, intent_hash(tx)).as_bytes()).unwrap()
    };
    w.sign_transaction_approved(BOT, "a", tx.clone(), &approve("a", &tx), NOW).unwrap();
    // An approval for another request doesn't carry over.
    assert!(w.sign_transaction_approved(BOT, "b", tx.clone(), &approve("a", &tx), NOW).is_err());
}

#[test]
fn refresh_keeps_the_address_and_retires_old_shares() {
    let (bot, co) = generate_2of2().unwrap();
    let (bot2, co2) = refresh_2of2(&bot, &co).unwrap();
    assert_eq!(bot2.address(), bot.address());
    let dir = tempfile::tempdir().unwrap();

    let signer = ThresholdSigner::new(bot2.clone(), cosigner(&co2, dir.path(), 200, 500, 1, &[])).unwrap();
    let mut w = wallet(&dir.path().join("new"), signer, 200, 1, &[]);
    let signed = w.sign_transaction(BOT, "a", send(10, 0), NOW).unwrap();
    let env = TxEnvelope::decode_2718(&mut signed.raw.as_ref()).unwrap();
    assert_eq!(env.signature_hash(), send(10, 0).signature_hash());

    // A stolen old share is useless with a new one.
    let mixed = tempfile::tempdir().unwrap();
    let signer = ThresholdSigner::new(bot.clone(), cosigner(&co2, mixed.path(), 200, 500, 1, &[])).unwrap();
    let mut w = wallet(&mixed.path().join("state"), signer, 200, 1, &[]);
    assert!(w.sign_transaction(BOT, "a", send(10, 0), NOW).is_err());
}

#[test]
fn share_files_round_trip_privately() {
    let (bot, _) = shares();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bot.share.json");
    bot.save(&path).unwrap();
    let loaded = KeyShare::load(&path).unwrap();
    assert_eq!(loaded.address(), bot.address());
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
}
