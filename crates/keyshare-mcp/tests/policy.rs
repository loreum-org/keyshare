//! Signed, versioned policy: the server refuses unsigned, tampered, wrongly signed and older
//! policies; every audit entry names the policy in force; a newly signed version loads without a
//! restart; and `policy-verify` re-derives every logged decision from the policy file.

#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use alloy::consensus::TxEip1559;
use alloy::primitives::{Address, TxKind, U256, address};
use keyshare_core::audit::{AuditEntry, AuditEvent};
use keyshare_core::chainlog::ChainLog;
use keyshare_core::policy_file::PolicyDoc;
use keyshare_core::{RefusalCode, Signer};
use keyshare_mcp::config::Config;
use keyshare_mcp::exec::{Executor, Reload};
use keyshare_mcp::policy::{self, testing};
use keyshare_signer::LocalSigner;

const KEY: &str = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const CHAIN: u64 = 11155111;
const OWNER: Address = address!("0x1111111111111111111111111111111111111111");

fn env(var: &str) -> Option<String> {
    (var == "BOT_KEY").then(|| KEY.to_string())
}

fn legacy(per_tx_cap: u64) -> String {
    format!(
        r#"
        [server]
        listen = "127.0.0.1:0"
        state_dir = "STATE"
        policy_reload_secs = 0

        [[prices]]
        chain_id = {CHAIN}
        decimals = 18
        usd = "2000"

        [bots.bot]
        credential_sha256 = "0x0000000000000000000000000000000000000000000000000000000000000000"
        key_env = "BOT_KEY"
        [bots.bot.policy]
        chains = [{CHAIN}]
        per_tx_cap_usd = {per_tx_cap}
        daily_cap_usd = 1000
        recipients_allow = ["{OWNER}"]
        "#
    )
}

struct Fixture {
    dir: tempfile::TempDir,
    config_path: PathBuf,
}

impl Fixture {
    fn new(per_tx_cap: u64) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let text = legacy(per_tx_cap).replace("STATE", &dir.path().join("state").display().to_string());
        let config_path = testing::write_signed(dir.path(), &text);
        Self { dir, config_path }
    }

    fn config(&self) -> Config {
        Config::load(&self.config_path).unwrap()
    }

    fn policy_path(&self) -> PathBuf {
        self.dir.path().join("policy.toml")
    }

    fn policy_text(&self) -> String {
        std::fs::read_to_string(self.policy_path()).unwrap()
    }

    /// Writes `text` as the policy, signed by the test owner.
    fn sign(&self, text: &str) {
        testing::write_policy(&self.policy_path(), text);
    }

    fn audit(&self) -> Vec<AuditEntry> {
        let path = self.dir.path().join("state/audit.jsonl");
        let (_, entries): (ChainLog<AuditEntry>, _) = ChainLog::open(path).unwrap();
        entries
    }

    async fn build(&self) -> Result<Executor, String> {
        keyshare_mcp::build(&self.config(), env).await
    }
}

fn send(value_eth_milli: u64, nonce: u64) -> TxEip1559 {
    TxEip1559 {
        chain_id: CHAIN,
        nonce,
        gas_limit: 21_000,
        max_fee_per_gas: 1,
        max_priority_fee_per_gas: 1,
        to: TxKind::Call(OWNER),
        value: U256::from(value_eth_milli) * U256::from(10u64.pow(15)),
        ..Default::default()
    }
}

fn with_version(text: &str, version: u64) -> String {
    let mut table: toml::Table = toml::from_str(text).unwrap();
    table.insert("version".into(), toml::Value::Integer(version as i64));
    toml::to_string(&table).unwrap()
}

fn with_cap(text: &str, cap: i64) -> String {
    let mut table: toml::Table = toml::from_str(text).unwrap();
    table["bots"]["bot"]["core"].as_table_mut().unwrap().insert("per_tx_cap_usd".into(), cap.into());
    toml::to_string(&table).unwrap()
}

#[tokio::test]
async fn unsigned_tampered_or_wrongly_signed_policy_does_not_start() {
    let f = Fixture::new(100);
    let sig = policy::sig_path(&f.policy_path());

    let good = std::fs::read(&sig).unwrap();
    std::fs::remove_file(&sig).unwrap();
    assert!(f.build().await.err().unwrap().contains("not signed"));

    // Signed, then edited: the signature names the old hash.
    std::fs::write(&sig, &good).unwrap();
    std::fs::write(f.policy_path(), with_cap(&f.policy_text(), 100_000)).unwrap();
    assert!(f.build().await.err().unwrap().contains("not a configured policy signer"));

    // Signed by a key that is not on policy_signers.
    let text = f.policy_text();
    let doc = PolicyDoc::parse(&text).unwrap();
    let stranger = LocalSigner::random().sign_message(doc.signing_message().as_bytes()).unwrap();
    std::fs::write(&sig, stranger.to_string()).unwrap();
    assert!(f.build().await.err().unwrap().contains("not a configured policy signer"));

    f.sign(&text);
    assert!(f.build().await.is_ok());
}

#[tokio::test]
async fn older_version_is_refused_and_audit_names_the_policy() {
    let f = Fixture::new(100);
    let v1 = f.policy_text();
    let v2 = with_version(&with_cap(&v1, 50), 2);
    f.sign(&v2);
    let exec = f.build().await.unwrap();
    let active = exec.active_policy().unwrap();
    assert_eq!(active.reference.version, 2);
    assert_eq!(active.signer, testing::owner().address());

    let wallet = exec.wallet();
    wallet.lock().unwrap().sign_transaction("bot", "a", send(10, 0), 1_800_000_000).unwrap();
    drop(exec);

    let entries = f.audit();
    assert!(entries.iter().all(|e| e.policy == Some(active.reference)), "every entry names the policy");
    let loaded = entries.iter().find(|e| e.event == AuditEvent::PolicyLoaded).unwrap();
    assert_eq!(loaded.detail["version"], 2);

    // Version 1 is still validly signed, but older than what this state dir accepted.
    f.sign(&v1);
    assert!(f.build().await.err().unwrap().contains("older than version 2"));
    // Same version number, different contents.
    f.sign(&with_cap(&v2, 70));
    assert!(f.build().await.err().unwrap().contains("already loaded with different contents"));
}

#[tokio::test]
async fn newly_signed_policy_loads_without_restart() {
    let f = Fixture::new(100);
    let config = f.config();
    let exec = f.build().await.unwrap();
    let wallet = exec.wallet();
    let t = 1_800_000_000;
    // 0.075 ETH at $2000 = $150, over the $100 cap.
    let r = wallet.lock().unwrap().sign_transaction("bot", "a", send(75, 0), t).unwrap_err();
    assert_eq!(r.code, RefusalCode::PerTxCapExceeded);
    assert_eq!(exec.reload_policy(&config).await, Reload::Unchanged);

    let v2 = with_version(&with_cap(&f.policy_text(), 200), 2);
    f.sign(&v2);
    let Reload::Loaded(v2_ref) = exec.reload_policy(&config).await else { panic!("v2 should load") };
    assert_eq!(v2_ref.version, 2);
    wallet.lock().unwrap().sign_transaction("bot", "b", send(75, 0), t).unwrap();

    // A bad file is refused, logged once, and the policy in force stays.
    std::fs::write(f.policy_path(), with_version(&with_cap(&v2, 100_000), 3)).unwrap();
    assert!(matches!(exec.reload_policy(&config).await, Reload::Rejected(_)));
    assert!(matches!(exec.reload_policy(&config).await, Reload::Rejected(_)));
    assert_eq!(exec.active_policy().unwrap().reference, v2_ref);
    let r = wallet.lock().unwrap().sign_transaction("bot", "c", send(150, 1), t).unwrap_err();
    assert_eq!(r.code, RefusalCode::PerTxCapExceeded);
    drop(exec);
    let rejected = f.audit().into_iter().filter(|e| e.event == AuditEvent::PolicyRejected).count();
    assert_eq!(rejected, 1);
}

#[tokio::test]
async fn verifier_rederives_logged_decisions() {
    let f = Fixture::new(100);
    let exec = f.build().await.unwrap();
    let wallet = exec.wallet();
    let t = 1_800_000_000;
    {
        let mut w = wallet.lock().unwrap();
        w.sign_transaction("bot", "ok", send(10, 0), t).unwrap();
        assert!(w.sign_transaction("bot", "big", send(75, 1), t).is_err());
        let stranger = TxEip1559 { to: TxKind::Call(Address::repeat_byte(9)), ..send(1, 2) };
        assert!(w.sign_transaction("bot", "who", stranger, t).is_err());
        w.sign_message("bot", "msg", b"hello", t).unwrap();
        // Refused before policy ran: not a policy decision.
        assert!(w.sign_message("bot", "msg", b"again", t).is_err());
    }
    drop(exec);
    let audit = f.dir.path().join("state/audit.jsonl");

    let report = policy::verify_audit(&f.policy_text(), &audit).unwrap();
    assert_eq!(report.checked, 4, "{report:?}");
    assert!(report.mismatches.is_empty(), "{report:?}");

    // A different policy (higher cap) does not match: none of these entries name its hash.
    let other = with_cap(&f.policy_text(), 1000);
    let report = policy::verify_audit(&other, &audit).unwrap();
    assert_eq!(report.checked, 0);
    assert!(report.other_policy > 0);

    // Logs claiming this policy but showing a decision it would not make are caught.
    let forged = forge_signed_as_allowed(&audit, "big");
    let report = policy::verify_audit(&f.policy_text(), &forged).unwrap();
    assert_eq!(report.mismatches.len(), 1, "{report:?}");
    assert_eq!(report.mismatches[0].request_id, "big");
    assert_eq!(report.mismatches[0].recomputed, "PER_TX_CAP_EXCEEDED");
}

/// Rewrites the audit log with `request_id`'s refusal turned into a signature, re-chained so the
/// hash chain still verifies. Models an operator who rewrites the whole log.
fn forge_signed_as_allowed(audit: &Path, request_id: &str) -> PathBuf {
    let (_, entries): (ChainLog<AuditEntry>, _) = ChainLog::open(audit).unwrap();
    let out = audit.with_file_name("forged.jsonl");
    let (mut log, _): (ChainLog<AuditEntry>, _) = ChainLog::open(&out).unwrap();
    for mut e in entries {
        if e.request_id == request_id && e.event == AuditEvent::Refused {
            e.event = AuditEvent::Signed;
            let check = e.detail["policy_check"].clone();
            e.detail = serde_json::json!({ "signature": "0x00", "policy_check": check });
        }
        log.append(&e).unwrap();
    }
    out
}

#[test]
fn migrate_round_trips_the_example_shape() {
    let (config, policy) = policy::migrate(&legacy(100).replace("STATE", "/tmp/s"), "/tmp/p.toml").unwrap();
    let config: Config = toml::from_str(&config).unwrap();
    let doc = PolicyDoc::parse(&policy).unwrap();
    let set = policy::PolicySet::from_doc(&doc).unwrap();
    set.check_bots(&config).unwrap();
    let _: HashMap<_, _> = set.modules();
}
