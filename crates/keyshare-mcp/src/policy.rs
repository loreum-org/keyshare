//! The owner-signed policy file: what each bot may do, and the prices caps are measured in.
//!
//! ```toml
//! version = 3                 # must go up with every change
//!
//! [[prices]]                  # same shape as before
//! chain_id = 11155111
//! decimals = 18
//! usd = "2500"
//!
//! [bots.filltape.core]        # PlainPolicy: chains, caps, allowlists
//! [bots.filltape.hyperliquid] # optional Hyperliquid limits
//! [bots.filltape.modules]     # optional module switches
//! ```
//!
//! The signature sits next to it in `<policy>.sig`: the hex output of signing
//! [`keyshare_core::policy_file::signing_message`] with a key listed in `server.policy_signers`.
//! See docs/policy-signing.md.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use alloy::consensus::TxEip1559;
use alloy::dyn_abi::TypedData;
use alloy::primitives::{Address, Bytes};
use keyshare_core::audit::{AuditEntry, AuditEvent};
use keyshare_core::chainlog::ChainLog;
use keyshare_core::policy::{Action, PlainPolicy, PolicyEngine};
use keyshare_core::policy_file::{PolicyDoc, PolicyFileError, PolicyRef};
use keyshare_core::price::{PriceEntry, PriceTable};
use keyshare_hyperliquid::HlPolicy;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::Config;

/// Per-bot module switches. `false` removes that module's tools from `tools/list` and rejects calls.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleToggles {
    #[serde(default = "module_on")]
    pub hyperliquid: bool,
    #[serde(default = "module_on")]
    pub uniswap: bool,
}

fn module_on() -> bool {
    true
}

impl Default for ModuleToggles {
    fn default() -> Self {
        Self { hyperliquid: true, uniswap: true }
    }
}

/// One bot's rules: the core section and one optional section per module.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BotPolicy {
    pub core: PlainPolicy,
    /// Hyperliquid testnet guardrails. Without this section the `hl_*` tools refuse this bot.
    pub hyperliquid: Option<HlPolicy>,
    /// Which protocol modules this bot is offered. Omitted means every module stays available.
    #[serde(default)]
    pub modules: ModuleToggles,
}

/// The parsed policy file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySet {
    pub version: u64,
    #[serde(default)]
    pub prices: Vec<PriceEntry>,
    pub bots: HashMap<String, BotPolicy>,
}

impl PolicySet {
    pub fn from_doc(doc: &PolicyDoc) -> Result<Self, String> {
        toml::Value::Table(doc.table.clone()).try_into().map_err(|e: toml::de::Error| e.message().to_string())
    }

    /// Hyperliquid sections, checked.
    pub fn hyperliquid(&self) -> Result<HashMap<String, HlPolicy>, String> {
        let mut out = HashMap::new();
        for (bot, rules) in &self.bots {
            let Some(policy) = rules.hyperliquid.clone() else { continue };
            policy.validate().map_err(|e| format!("bot {bot}: {e}"))?;
            out.insert(bot.clone(), policy);
        }
        Ok(out)
    }

    pub fn price_table(&self) -> Result<PriceTable, String> {
        PriceTable::from_entries(&self.prices).map_err(|e| e.to_string())
    }

    pub fn modules(&self) -> HashMap<String, ModuleToggles> {
        self.bots.iter().map(|(bot, rules)| (bot.clone(), rules.modules.clone())).collect()
    }

    /// The policy must cover exactly the bots in the config: keys and tokens come from there.
    pub fn check_bots(&self, config: &Config) -> Result<(), String> {
        let mut missing: Vec<&String> = config.bots.keys().filter(|b| !self.bots.contains_key(*b)).collect();
        let mut extra: Vec<&String> = self.bots.keys().filter(|b| !config.bots.contains_key(*b)).collect();
        if missing.is_empty() && extra.is_empty() {
            return Ok(());
        }
        missing.sort();
        extra.sort();
        Err(format!("policy must cover exactly the configured bots; missing {missing:?}, unknown {extra:?}"))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("reading {0}: {1}")]
    Read(PathBuf, std::io::Error),
    #[error("{0}")]
    File(#[from] PolicyFileError),
    #[error("policy is signed but invalid: {0}")]
    Invalid(String),
}

/// A policy whose signature checked out and whose sections parsed.
#[derive(Debug, Clone)]
pub struct LoadedPolicy {
    pub reference: PolicyRef,
    pub signer: Address,
    pub set: PolicySet,
}

/// `<policy>.sig`.
pub fn sig_path(policy: &Path) -> PathBuf {
    let mut name = policy.as_os_str().to_owned();
    name.push(".sig");
    PathBuf::from(name)
}

pub fn read_doc(path: &Path) -> Result<PolicyDoc, PolicyError> {
    let text = std::fs::read_to_string(path).map_err(|e| PolicyError::Read(path.into(), e))?;
    Ok(PolicyDoc::parse(&text)?)
}

/// Reads the policy and its signature, checks the signer, parses every section and checks it
/// against the config. Does not check the version gate; [`crate::exec::Executor::apply_policy`]
/// does that.
pub fn load(config: &Config) -> Result<LoadedPolicy, PolicyError> {
    let path = &config.server.policy;
    let doc = read_doc(path)?;
    let sig = match std::fs::read_to_string(sig_path(path)) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(PolicyError::Read(sig_path(path), e)),
    };
    let signer = doc.verify(sig.as_deref(), &config.server.policy_signers)?;
    let set = PolicySet::from_doc(&doc).map_err(PolicyError::Invalid)?;
    set.check_bots(config).map_err(PolicyError::Invalid)?;
    set.hyperliquid().map_err(PolicyError::Invalid)?;
    set.price_table().map_err(PolicyError::Invalid)?;
    Ok(LoadedPolicy { reference: doc.reference, signer, set })
}

/// Splits an old single-file config (rules inline under `[bots.<id>.policy]`) into a config and a
/// version-1 policy. The policy still has to be signed. Comments are not carried over.
pub fn migrate(old: &str, policy_path: &str) -> Result<(String, String), String> {
    let mut config: toml::Table = toml::from_str(old).map_err(|e| e.to_string())?;
    let mut policy = toml::Table::new();
    policy.insert("version".into(), toml::Value::Integer(1));
    if let Some(prices) = config.remove("prices") {
        policy.insert("prices".into(), prices);
    }
    let mut signers: Vec<toml::Value> = Vec::new();
    let mut bots_policy = toml::Table::new();
    let bots = config.get_mut("bots").and_then(toml::Value::as_table_mut).ok_or("config has no [bots]")?;
    for (bot, value) in bots.iter_mut() {
        let table = value.as_table_mut().ok_or_else(|| format!("bots.{bot} is not a table"))?;
        let mut rules = toml::Table::new();
        let core = table.remove("policy").ok_or_else(|| format!("bots.{bot} has no policy section"))?;
        rules.insert("core".into(), core);
        for section in ["hyperliquid", "modules"] {
            if let Some(v) = table.remove(section) {
                rules.insert(section.into(), v);
            }
        }
        for key in table.get("admin_keys").and_then(toml::Value::as_array).into_iter().flatten() {
            if !signers.contains(key) {
                signers.push(key.clone());
            }
        }
        bots_policy.insert(bot.clone(), toml::Value::Table(rules));
    }
    policy.insert("bots".into(), toml::Value::Table(bots_policy));
    let server = config.get_mut("server").and_then(toml::Value::as_table_mut).ok_or("config has no [server]")?;
    server.insert("policy".into(), toml::Value::String(policy_path.into()));
    // The owners' admin keys are the natural signers. Edit this list if the policy owner differs.
    server.entry("policy_signers").or_insert(toml::Value::Array(signers));
    let config = toml::to_string_pretty(&config).map_err(|e| e.to_string())?;
    let policy = toml::to_string_pretty(&policy).map_err(|e| e.to_string())?;
    Ok((config, policy))
}

/// This bot's rules in plain words, for the `policy` tool. Allowlists are counted, not listed.
pub fn summary(
    active: &crate::exec::ActivePolicy,
    limits: &keyshare_core::Limits,
    hl: Option<&HlPolicy>,
    modules: &ModuleToggles,
) -> String {
    let chains = limits.chains.iter().map(u64::to_string).collect::<Vec<_>>().join(", ");
    let mut lines = vec![
        format!(
            "Policy version {} (hash {}), signed by {}.",
            active.reference.version, active.reference.hash, active.signer
        ),
        format!(
            "Chains: {}. Up to ${} per transaction and ${} per rolling 24 hours.",
            if chains.is_empty() { "none".to_string() } else { chains },
            limits.per_tx_cap_usd,
            limits.daily_cap_usd
        ),
        format!(
            "Allowlisted: {} recipients, {} contracts, {} typed-data kinds. Swaps accept at most {}.{:02}% slippage.",
            limits.recipients_allowed,
            limits.contracts_allowed,
            limits.typed_data_allowed,
            limits.max_slippage_bps / 100,
            limits.max_slippage_bps % 100
        ),
    ];
    match (hl, modules.hyperliquid) {
        (Some(h), true) => lines.push(format!(
            "Hyperliquid: {}; orders up to ${}, positions up to ${} per coin, leverage up to {}x, daily loss stop ${}.",
            if h.markets.is_empty() { "no markets".to_string() } else { h.markets.join(", ") },
            h.max_order_usd,
            h.max_position_usd,
            h.max_leverage,
            h.daily_loss_stop_usd
        )),
        _ => lines.push("Hyperliquid: off.".into()),
    }
    lines.push(format!("Uniswap swaps: {}.", if modules.uniswap { "on" } else { "off" }));
    lines.join("\n")
}

/// One audit decision that does not follow from the policy.
#[derive(Debug, Clone, Serialize)]
pub struct Mismatch {
    pub seq: usize,
    pub caller: String,
    pub request_id: String,
    pub logged: String,
    pub recomputed: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct VerifyReport {
    /// Decisions made under this policy and re-checked.
    pub checked: usize,
    /// Entries under this policy that carry no core policy decision (holds, module refusals,
    /// refusals before the policy ran, policy loads).
    pub not_decisions: usize,
    /// Entries made under another policy, or before policies were signed.
    pub other_policy: usize,
    pub mismatches: Vec<Mismatch>,
}

/// Re-checks every core policy decision in `audit_log` that names this policy's hash: rebuilds
/// the request from its `requested` entry, runs the policy with the recorded 24h spend, and
/// compares the outcome. Opening the log verifies its hash chain first.
pub fn verify_audit(policy_text: &str, audit_log: &Path) -> Result<VerifyReport, String> {
    let doc = PolicyDoc::parse(policy_text).map_err(|e| e.to_string())?;
    let set = PolicySet::from_doc(&doc)?;
    let prices = set.price_table()?;
    let (_, entries): (ChainLog<AuditEntry>, _) = ChainLog::open(audit_log).map_err(|e| e.to_string())?;
    let mut requested: HashMap<(String, String), &Value> = HashMap::new();
    let mut report = VerifyReport::default();
    for (i, entry) in entries.iter().enumerate() {
        let key = (entry.caller.clone(), entry.request_id.clone());
        if entry.event == AuditEvent::Requested {
            requested.insert(key.clone(), &entry.detail);
        }
        if entry.policy.map(|p| p.hash) != Some(doc.reference.hash) {
            report.other_policy += 1;
            continue;
        }
        let Some(check) = entry.detail.get("policy_check") else {
            report.not_decisions += 1;
            continue;
        };
        let logged = match entry.event {
            AuditEvent::Signed => "allow".to_string(),
            AuditEvent::Refused => entry.detail["code"].as_str().unwrap_or("?").to_string(),
            _ => {
                report.not_decisions += 1;
                continue;
            }
        };
        let recomputed = match requested.get(&key) {
            None => "no requested entry".to_string(),
            Some(req) => recheck(&set, &prices, &entry.caller, req, check),
        };
        report.checked += 1;
        if recomputed != logged {
            report.mismatches.push(Mismatch {
                seq: i + 1,
                caller: entry.caller.clone(),
                request_id: entry.request_id.clone(),
                logged,
                recomputed,
            });
        }
    }
    Ok(report)
}

fn recheck(set: &PolicySet, prices: &PriceTable, caller: &str, req: &Value, check: &Value) -> String {
    let Some(rules) = set.bots.get(caller) else { return "bot not in policy".into() };
    let owner_approved = check["owner_approved"].as_bool().unwrap_or(false);
    let Some(spent) = check["spent_24h_usd_micros"].as_u64().map(u128::from) else {
        return "unreadable policy_check".into();
    };
    let from: Option<Address> = serde_json::from_value(req["from"].clone()).ok().flatten();
    let policy = PlainPolicy { own_address: from, ..rules.core.clone() };
    let tx: TxEip1559;
    let typed: TypedData;
    let message: Bytes;
    let action = match req["kind"].as_str() {
        Some("transaction") => match serde_json::from_value(req["tx"].clone()) {
            Ok(t) => {
                tx = t;
                Action::Transaction(&tx)
            }
            Err(_) => return "requested entry has no tx".into(),
        },
        Some("typed_data") => match serde_json::from_value(req["typed_data"].clone()) {
            Ok(t) => {
                typed = t;
                Action::TypedData(&typed)
            }
            Err(_) => return "requested entry has no typed_data".into(),
        },
        Some("message") => match serde_json::from_value(req["message_hex"].clone()) {
            Ok(m) => {
                message = m;
                Action::Message(&message)
            }
            Err(_) => return "requested entry has no message_hex".into(),
        },
        _ => return "unknown request kind".into(),
    };
    let result =
        if owner_approved { policy.check_owner_approved(action, prices) } else { policy.check(action, spent, prices) };
    match result {
        Ok(_) => "allow".into(),
        Err(r) => serde_json::to_value(r.code).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default(),
    }
}

/// Helpers for tests: sign a policy with a fixed key and write config, policy and signature.
#[doc(hidden)]
pub mod testing {
    use std::path::{Path, PathBuf};

    use keyshare_core::Signer;
    use keyshare_core::policy_file::PolicyDoc;
    use keyshare_signer::LocalSigner;

    /// Test-only policy owner key. Never use it outside tests.
    pub const OWNER_KEY: &str = "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba";

    pub fn owner() -> LocalSigner {
        LocalSigner::from_hex(OWNER_KEY).unwrap_or_else(|_| unreachable!("constant key"))
    }

    /// Signs `policy_text` with [`OWNER_KEY`] and writes it plus `<path>.sig`.
    pub fn write_policy(path: &Path, policy_text: &str) {
        let doc = PolicyDoc::parse(policy_text).unwrap_or_else(|e| panic!("bad test policy: {e}"));
        let sig = owner().sign_message(doc.signing_message().as_bytes()).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(path, policy_text).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(super::sig_path(path), sig.to_string()).unwrap_or_else(|e| panic!("{e}"));
    }

    /// Takes an old-style single-file config, splits it with [`super::migrate`], makes the test
    /// owner the only policy signer, signs the policy, and returns the new config's path. When a
    /// policy was already written in `dir`, the new one gets the next version, as an owner would
    /// sign it.
    pub fn write_signed(dir: &Path, legacy_config: &str) -> PathBuf {
        let policy_path = dir.join("policy.toml");
        let (config, policy) =
            super::migrate(legacy_config, &policy_path.display().to_string()).unwrap_or_else(|e| panic!("{e}"));
        let policy = match super::read_doc(&policy_path) {
            Ok(old) => {
                let mut table: toml::Table = toml::from_str(&policy).unwrap_or_else(|e| panic!("{e}"));
                table.insert("version".into(), toml::Value::Integer(old.reference.version as i64 + 1));
                toml::to_string(&table).unwrap_or_else(|e| panic!("{e}"))
            }
            Err(_) => policy,
        };
        let mut config: toml::Table = toml::from_str(&config).unwrap_or_else(|e| panic!("{e}"));
        if let Some(server) = config.get_mut("server").and_then(toml::Value::as_table_mut) {
            server.insert("policy_signers".into(), toml::Value::Array(vec![owner().address().to_string().into()]));
        }
        let config_path = dir.join("keyshare.toml");
        std::fs::write(&config_path, toml::to_string(&config).unwrap_or_default()).unwrap_or_else(|e| panic!("{e}"));
        write_policy(&policy_path, &policy);
        config_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEGACY: &str = r#"
        [server]
        listen = "127.0.0.1:0"
        state_dir = "/tmp/x"

        [[prices]]
        chain_id = 1
        decimals = 18
        usd = "2500"

        [bots.a]
        credential_sha256 = "0x0000000000000000000000000000000000000000000000000000000000000000"
        key_env = "A_KEY"
        admin_keys = ["0x1111111111111111111111111111111111111111"]
        [bots.a.policy]
        chains = [1]
        per_tx_cap_usd = 10
        daily_cap_usd = 20
        [bots.a.modules]
        uniswap = false
    "#;

    #[test]
    fn migrate_moves_rules_into_the_policy() {
        let (config, policy) = migrate(LEGACY, "/data/policy.toml").unwrap();
        let config: Config = toml::from_str(&config).unwrap();
        assert_eq!(config.server.policy, PathBuf::from("/data/policy.toml"));
        assert_eq!(config.server.policy_signers.len(), 1);
        let doc = PolicyDoc::parse(&policy).unwrap();
        assert_eq!(doc.reference.version, 1);
        let set = PolicySet::from_doc(&doc).unwrap();
        assert_eq!(set.prices.len(), 1);
        assert_eq!(set.bots["a"].core.per_tx_cap_usd, 10);
        assert!(!set.bots["a"].modules.uniswap);
        set.check_bots(&config).unwrap();
    }

    #[test]
    fn unknown_sections_are_refused() {
        let doc = PolicyDoc::parse(
            "version = 1\n[bots.a.core]\nchains=[]\nper_tx_cap_usd=0\ndaily_cap_usd=0\n[bots.a.other]\nx=1",
        )
        .unwrap();
        assert!(PolicySet::from_doc(&doc).unwrap_err().contains("other"));
    }

    #[test]
    fn sig_path_appends() {
        assert_eq!(sig_path(Path::new("/data/policy.toml")), PathBuf::from("/data/policy.toml.sig"));
    }
}
