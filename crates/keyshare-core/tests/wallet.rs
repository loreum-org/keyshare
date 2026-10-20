#![allow(clippy::unwrap_used)]

use std::collections::HashMap;

use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy::eips::Decodable2718;
use alloy::primitives::{Address, Bytes, TxKind, U256, address};
use alloy::sol;
use alloy::sol_types::SolCall;
use keyshare_core::price::PriceEntry;
use keyshare_core::{Account, LocalSigner, PlainPolicy, PriceTable, RefusalCode, StatePaths, Wallet};

sol! { function transfer(address to, uint256 amount); }

const CHAIN: u64 = 11155111;
const USDC: Address = address!("0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238");
const OWNER: Address = address!("0x1111111111111111111111111111111111111111");
const ATTACKER: Address = address!("0x2222222222222222222222222222222222222222");
const NOW: u64 = 1_800_000_000;

struct Fixture {
    wallet: Wallet,
    paths: StatePaths,
    _dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let paths = StatePaths {
        spend_log: dir.path().join("spend.jsonl"),
        spend_anchor: Some(dir.path().join("spend.anchor.json")),
        audit_log: dir.path().join("audit.jsonl"),
        kill_switch: dir.path().join("kill.json"),
    };
    let policy: PlainPolicy = toml::from_str(&format!(
        r#"
        chains = [{CHAIN}]
        per_tx_cap_usd = 200
        daily_cap_usd = 300
        recipients_allow = ["{OWNER}"]
        [[contracts_allow]]
        addr = "{USDC}"
        selectors = ["0xa9059cbb"]
        "#
    ))
    .unwrap();
    let mut accounts = HashMap::new();
    accounts
        .insert("filltape".to_string(), Account { signer: Box::new(LocalSigner::random()), policy: Box::new(policy) });
    let prices = PriceTable::from_entries(&[
        PriceEntry { chain_id: CHAIN, token: None, decimals: 18, usd: "2000".into() },
        PriceEntry { chain_id: CHAIN, token: Some(USDC), decimals: 6, usd: "1".into() },
    ])
    .unwrap();
    let wallet = Wallet::open(accounts, Box::new(prices), &paths).unwrap();
    Fixture { wallet, paths, _dir: dir }
}

fn usdc_transfer(to: Address, dollars: u64, nonce: u64) -> TxEip1559 {
    TxEip1559 {
        chain_id: CHAIN,
        nonce,
        gas_limit: 60_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        to: TxKind::Call(USDC),
        input: Bytes::from(transferCall { to, amount: U256::from(dollars * 1_000_000) }.abi_encode()),
        ..Default::default()
    }
}

fn audit_events(paths: &StatePaths) -> Vec<String> {
    std::fs::read_to_string(&paths.audit_log)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()["body"]["event"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn signs_in_policy_transfer_and_logs_it() {
    let mut f = fixture();
    let tx = usdc_transfer(OWNER, 150, 0);
    let signed = f.wallet.sign_transaction("filltape", "req-1", tx.clone(), NOW).unwrap();

    let envelope = TxEnvelope::decode_2718(&mut signed.raw.as_ref()).unwrap();
    assert_eq!(*envelope.tx_hash(), signed.hash);
    let sig = envelope.as_eip1559().unwrap().signature();
    assert_eq!(sig.recover_address_from_prehash(&tx.signature_hash()).unwrap(), f.wallet.address("filltape").unwrap());
    assert_eq!(f.wallet.spent_24h("filltape", NOW), 150_000_000);
    assert_eq!(audit_events(&f.paths), ["requested", "signed"]);
}

#[test]
fn red_team_prompt_injection_is_refused() {
    let mut f = fixture();
    let r = f.wallet.sign_transaction("filltape", "req-1", usdc_transfer(ATTACKER, 10, 0), NOW).unwrap_err();
    assert_eq!(r.code, RefusalCode::RecipientNotAllowed);
    assert_eq!(audit_events(&f.paths), ["requested", "refused"]);
    assert_eq!(f.wallet.spent_24h("filltape", NOW), 0);
}

#[test]
fn daily_cap_holds_across_requests() {
    let mut f = fixture();
    f.wallet.sign_transaction("filltape", "a", usdc_transfer(OWNER, 200, 0), NOW).unwrap();
    let r = f.wallet.sign_transaction("filltape", "b", usdc_transfer(OWNER, 101, 1), NOW + 60).unwrap_err();
    assert_eq!(r.code, RefusalCode::CapExceeded);
    f.wallet.sign_transaction("filltape", "c", usdc_transfer(OWNER, 100, 1), NOW + 60).unwrap();
}

#[test]
fn replayed_request_id_is_refused() {
    let mut f = fixture();
    f.wallet.sign_transaction("filltape", "same", usdc_transfer(OWNER, 1, 0), NOW).unwrap();
    let r = f.wallet.sign_transaction("filltape", "same", usdc_transfer(OWNER, 1, 1), NOW).unwrap_err();
    assert_eq!(r.code, RefusalCode::NonceReused);
}

#[test]
fn kill_switch_halts_immediately() {
    let mut f = fixture();
    f.wallet.kill_switch().set(None, true).unwrap();
    let r = f.wallet.sign_transaction("filltape", "a", usdc_transfer(OWNER, 1, 0), NOW).unwrap_err();
    assert_eq!(r.code, RefusalCode::KillSwitch);
    let r = f.wallet.sign_message("filltape", "b", b"hello", NOW).unwrap_err();
    assert_eq!(r.code, RefusalCode::KillSwitch);
    // Read-only calls keep working.
    assert!(f.wallet.address("filltape").is_ok());
}

#[test]
fn unknown_caller_is_refused() {
    let mut f = fixture();
    let r = f.wallet.sign_message("mallory", "a", b"hi", NOW).unwrap_err();
    assert_eq!(r.code, RefusalCode::UnknownCaller);
}

#[test]
fn message_signing_recovers_to_wallet() {
    let mut f = fixture();
    let sig = f.wallet.sign_message("filltape", "m1", b"Sign in to example.com", NOW).unwrap();
    assert_eq!(sig.recover_address_from_msg(b"Sign in to example.com").unwrap(), f.wallet.address("filltape").unwrap());
}
