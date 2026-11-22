//! Connector config: one TOML file for the server, chains and bot identities. Secrets (bot keys)
//! come from environment variables named in the file, never from the file itself. The rules each
//! bot runs under (caps, allowlists, prices, module limits) are in a separate owner-signed policy
//! file; see [`crate::policy`].

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use alloy::primitives::{Address, B256};
use keyshare_core::{Account, PlainPolicy, PriceTable, Signer, StatePaths, Wallet};
use keyshare_signer::LocalSigner;
use keyshare_signer::threshold::{KeyShare, LocalCoSigner, ThresholdSigner};
use serde::Deserialize;

use crate::chain::ChainConfig;
use crate::hl::{HlConfig, Hyperliquid};
use crate::policy::PolicySet;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    /// RPC endpoint per chain. Chain tools refuse chains not listed here.
    #[serde(default)]
    pub chains: Vec<ChainConfig>,
    /// Hyperliquid API settings. Bots trade there only with a `hyperliquid` section in the policy.
    pub hyperliquid: Option<HlConfig>,
    /// Keyed by bot id.
    pub bots: HashMap<String, BotConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Address and port from the file, for example `127.0.0.1:8080`. [`ServerConfig::bind_addr`]
    /// listens on `0.0.0.0:$PORT` instead when the `PORT` environment variable is set.
    pub listen: String,
    /// Host header values to accept (DNS-rebinding guard). Empty keeps the default, which accepts
    /// only localhost, 127.0.0.1 and ::1. [`ServerConfig::effective_allowed_hosts`] appends
    /// `KEYSHARE_ALLOWED_HOSTS` so a public hostname does not have to be committed.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// Holds the spend log, audit log and kill switch file.
    pub state_dir: PathBuf,
    /// Copy of the spend log head, ideally on another disk. Defaults to inside `state_dir`.
    pub spend_anchor: Option<PathBuf>,
    /// SHA-256 of the token for `GET /admin/pending`. Without it that endpoint is off.
    pub admin_token_sha256: Option<B256>,
    /// How long a held request waits for the owner. Default 15 minutes.
    pub hold_secs: Option<u64>,
    /// The owner-signed policy file. Its signature is read from the same path plus `.sig`.
    pub policy: PathBuf,
    /// Addresses allowed to sign the policy. The server refuses to start without a policy signed
    /// by one of them.
    pub policy_signers: Vec<Address>,
    /// How often to look for a newly signed policy, in seconds. Default 5. 0 turns reloading off.
    pub policy_reload_secs: Option<u64>,
}

impl ServerConfig {
    /// Address to bind. A set `PORT` (Railway injects this) listens on all interfaces at that
    /// port. Unset or blank keeps `listen` from the file.
    pub fn bind_addr(&self, port: Option<&str>) -> Result<String, ConfigError> {
        let Some(raw) = port.map(str::trim).filter(|p| !p.is_empty()) else {
            return Ok(self.listen.clone());
        };
        match raw.parse::<u16>() {
            Ok(port) if port != 0 => Ok(format!("0.0.0.0:{port}")),
            _ => Err(ConfigError::Other(format!("PORT {raw:?} is not a TCP port (1-65535)"))),
        }
    }

    /// `allowed_hosts` from the file, then any extra comma-separated hosts not already listed.
    /// Blank pieces are skipped. Duplicates are compared case-insensitively and the first spelling
    /// is kept. An empty result means "use the localhost default": callers must not pass that
    /// empty list to rmcp, which would allow every host and turn the DNS-rebinding guard off.
    pub fn effective_allowed_hosts(&self, extra: Option<&str>) -> Vec<String> {
        let mut hosts = Vec::new();
        for host in &self.allowed_hosts {
            push_allowed_host(&mut hosts, host);
        }
        if let Some(extra) = extra {
            for part in extra.split(',') {
                push_allowed_host(&mut hosts, part);
            }
        }
        hosts
    }
}

fn push_allowed_host(hosts: &mut Vec<String>, raw: &str) {
    let host = raw.trim();
    if host.is_empty() || hosts.iter().any(|existing| existing.eq_ignore_ascii_case(host)) {
        return;
    }
    hosts.push(host.to_string());
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BotConfig {
    /// SHA-256 of the bot's bearer token (`keyshare-mcp new-token` prints both).
    pub credential_sha256: B256,
    /// Environment variable holding this bot's testnet private key. Set this or `threshold`.
    #[serde(default)]
    pub key_env: Option<String>,
    /// A 2-of-2 threshold key instead of `key_env` (`keyshare-mcp threshold-keygen`).
    #[serde(default)]
    pub threshold: Option<ThresholdConfig>,
    /// The owner's admin keys (Ethereum addresses). With at least one, refusals the owner can
    /// waive are held for approval instead of refused (design §13.2).
    #[serde(default)]
    pub admin_keys: Vec<Address>,
}

/// Where a threshold bot's key shares live. Both are files written with mode 0600.
///
/// With `cosigner_share` the co-signer runs inside this server: it re-checks every request against
/// its own copy of the signed policy and its own spend log, but it is on the same machine, so a
/// compromised host has both shares. That is for testnet. A co-signer on another machine is the
/// next step (docs/threshold.md).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdConfig {
    pub share: PathBuf,
    pub cosigner_share: PathBuf,
}

/// A bot's signer, and its in-process co-signer if it has a threshold key.
type BotSigner = (Box<dyn Signer>, Option<Arc<LocalCoSigner>>);

/// In-process co-signers by bot id. The executor hands each one the signed policy on every load.
pub type CoSigners = HashMap<String, (Arc<LocalCoSigner>, Vec<Address>)>;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading {0}: {1}")]
    Read(PathBuf, std::io::Error),
    #[error("parsing {0}: {1}")]
    Parse(PathBuf, toml::de::Error),
    #[error("bot {bot}: environment variable {var} is not set")]
    MissingKey { bot: String, var: String },
    #[error("bot {bot}: {why}")]
    BadKey { bot: String, why: String },
    #[error("two bots share one credential: {0} and {1}")]
    DuplicateCredential(String, String),
    #[error("{0}")]
    Other(String),
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Read(path.into(), e))?;
        toml::from_str(&text).map_err(|e| ConfigError::Parse(path.into(), e))
    }

    /// True when the spend anchor sits inside `state_dir`, where restoring or deleting that one
    /// directory would defeat the rollback check.
    pub fn anchor_in_state_dir(&self) -> bool {
        // Compare resolved paths so `./state/x` or a symlink into state_dir is still caught. A path
        // that doesn't exist yet resolves through its parent.
        fn resolve(p: &Path) -> PathBuf {
            p.canonicalize()
                .or_else(|_| match (p.parent(), p.file_name()) {
                    (Some(dir), Some(name)) => dir.canonicalize().map(|d| d.join(name)),
                    _ => Err(std::io::ErrorKind::NotFound.into()),
                })
                .unwrap_or_else(|_| std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf()))
        }
        self.server.spend_anchor.as_ref().is_none_or(|a| resolve(a).starts_with(resolve(&self.server.state_dir)))
    }

    pub fn state_paths(&self) -> StatePaths {
        let dir = &self.server.state_dir;
        StatePaths {
            spend_log: dir.join("spend.jsonl"),
            spend_anchor: Some(self.server.spend_anchor.clone().unwrap_or_else(|| dir.join("spend.anchor.json"))),
            audit_log: dir.join("audit.jsonl"),
            kill_switch: dir.join("kill.json"),
        }
    }

    /// Bearer-token hash -> bot id.
    pub fn credentials(&self) -> Result<HashMap<B256, String>, ConfigError> {
        let mut out = HashMap::new();
        for (bot, cfg) in &self.bots {
            // Request ids are scoped as "bot:id"; a ':' in a bot id could collide with another's.
            if bot.is_empty() || bot.contains(':') {
                return Err(ConfigError::Other(format!("bot id {bot:?} must be non-empty and contain no ':'")));
            }
            if let Some(other) = out.insert(cfg.credential_sha256, bot.clone()) {
                return Err(ConfigError::DuplicateCredential(other, bot.clone()));
            }
        }
        Ok(out)
    }

    /// Where the policy's version record lives.
    pub fn policy_state_path(&self) -> PathBuf {
        self.server.state_dir.join("policy.state.json")
    }

    /// Where an in-process co-signer keeps its own spend log, apart from the wallet's.
    pub fn cosigner_spend_log(&self, bot: &str) -> PathBuf {
        self.server.state_dir.join("cosigner").join(format!("{bot}.spend.jsonl"))
    }

    /// Builds one bot's signer: a single key from `key_env`, or a threshold share and its co-signer.
    fn signer(
        &self,
        bot: &str,
        cfg: &BotConfig,
        env: &impl Fn(&str) -> Option<String>,
    ) -> Result<BotSigner, ConfigError> {
        let bad = |why: String| ConfigError::BadKey { bot: bot.to_string(), why };
        match (&cfg.key_env, &cfg.threshold) {
            (Some(var), None) => {
                let key = env(var).ok_or_else(|| ConfigError::MissingKey { bot: bot.to_string(), var: var.clone() })?;
                let signer = LocalSigner::from_hex(&key).map_err(|e| bad(e.to_string()))?;
                Ok((Box::new(signer), None))
            }
            (None, Some(t)) => {
                let share = KeyShare::load(&t.share).map_err(|e| bad(e.to_string()))?;
                let co_share = KeyShare::load(&t.cosigner_share).map_err(|e| bad(e.to_string()))?;
                if share.address() != co_share.address() {
                    return Err(bad("share and cosigner_share are for different addresses".into()));
                }
                let log = self.cosigner_spend_log(bot);
                if let Some(dir) = log.parent() {
                    std::fs::create_dir_all(dir).map_err(|e| ConfigError::Read(dir.to_path_buf(), e))?;
                }
                let co = Arc::new(LocalCoSigner::new(co_share, &log).map_err(|e| bad(e.to_string()))?);
                let signer = ThresholdSigner::new(share, co.clone()).map_err(|e| bad(e.to_string()))?;
                Ok((Box::new(signer), Some(co)))
            }
            _ => Err(bad("set exactly one of key_env or threshold".into())),
        }
    }

    /// Builds the wallet under `policy`, reading each bot's key with `env`. Also returns the
    /// in-process co-signers of threshold bots, which refuse everything until given a policy.
    pub fn wallet(
        &self,
        env: impl Fn(&str) -> Option<String>,
        policy: &PolicySet,
    ) -> Result<(Wallet, CoSigners), ConfigError> {
        let mut accounts = HashMap::new();
        let mut cosigners = CoSigners::new();
        std::fs::create_dir_all(&self.server.state_dir)
            .map_err(|e| ConfigError::Read(self.server.state_dir.clone(), e))?;
        for (bot, cfg) in &self.bots {
            let rules = policy.bots.get(bot).ok_or_else(|| ConfigError::Other(format!("policy has no bot {bot}")))?;
            let (signer, co) = self.signer(bot, cfg, &env)?;
            if let Some(co) = co {
                cosigners.insert(bot.clone(), (co, cfg.admin_keys.clone()));
            }
            let own = signer.address();
            accounts.insert(
                bot.clone(),
                Account {
                    signer,
                    policy: Box::new(PlainPolicy { own_address: Some(own), ..rules.core.clone() }),
                    admins: cfg.admin_keys.clone(),
                },
            );
        }
        let prices = PriceTable::from_entries(&policy.prices).map_err(|e| ConfigError::Other(e.to_string()))?;
        std::fs::create_dir_all(&self.server.state_dir)
            .map_err(|e| ConfigError::Read(self.server.state_dir.clone(), e))?;
        let wallet = Wallet::open(accounts, Box::new(prices), &self.state_paths())
            .map_err(|e| ConfigError::Other(e.to_string()))?;
        Ok((wallet, cosigners))
    }

    pub fn hyperliquid(&self, policy: &PolicySet) -> Result<Hyperliquid, ConfigError> {
        crate::hl::check_api_url(self.hyperliquid.as_ref()).map_err(ConfigError::Other)?;
        let policies = policy.hyperliquid().map_err(ConfigError::Other)?;
        Ok(Hyperliquid::new(self.hyperliquid.as_ref(), self.server.state_dir.clone(), policies))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(listen: &str, hosts: &[&str]) -> ServerConfig {
        ServerConfig {
            listen: listen.to_string(),
            allowed_hosts: hosts.iter().map(|h| (*h).to_string()).collect(),
            state_dir: PathBuf::from("/data"),
            spend_anchor: None,
            admin_token_sha256: None,
            hold_secs: None,
            policy: PathBuf::from("/data/policy.toml"),
            policy_signers: Vec::new(),
            policy_reload_secs: None,
        }
    }

    #[test]
    fn port_overrides_listen_on_all_interfaces() {
        let cfg = server("127.0.0.1:8080", &[]);
        assert_eq!(cfg.bind_addr(None).unwrap(), "127.0.0.1:8080");
        assert_eq!(cfg.bind_addr(Some("")).unwrap(), "127.0.0.1:8080");
        assert_eq!(cfg.bind_addr(Some("   ")).unwrap(), "127.0.0.1:8080");
        assert_eq!(cfg.bind_addr(Some("4000")).unwrap(), "0.0.0.0:4000");
        assert_eq!(cfg.bind_addr(Some(" 8080\n")).unwrap(), "0.0.0.0:8080");
        assert!(cfg.bind_addr(Some("0")).is_err());
        assert!(cfg.bind_addr(Some("65536")).is_err());
        assert!(cfg.bind_addr(Some("abc")).is_err());
    }

    #[test]
    fn extra_hosts_merge_without_emptying_the_guard() {
        let local = server("127.0.0.1:8080", &[]);
        assert!(local.effective_allowed_hosts(None).is_empty());
        assert!(local.effective_allowed_hosts(Some(" , , ")).is_empty());
        let cfg = server("127.0.0.1:8080", &["localhost"]);
        assert_eq!(cfg.effective_allowed_hosts(Some(" , , ")), vec!["localhost".to_string()]);
        assert_eq!(
            cfg.effective_allowed_hosts(Some(" , keyshare.up.railway.app , localhost , ")),
            vec!["localhost".to_string(), "keyshare.up.railway.app".to_string()]
        );
        let mixed = server("127.0.0.1:8080", &["Example.COM"]);
        assert_eq!(
            mixed.effective_allowed_hosts(Some("example.com, other.example")),
            vec!["Example.COM".to_string(), "other.example".to_string()]
        );
    }

    #[test]
    fn railway_example_is_testnet_with_runtime_hosts() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../keyshare.railway.example.toml");
        let config = Config::load(&path).unwrap();
        assert_eq!(config.server.listen, "0.0.0.0:8080");
        assert_eq!(config.server.state_dir, PathBuf::from("/data"));
        assert!(config.server.allowed_hosts.is_empty());
        assert_eq!(config.server.bind_addr(None).unwrap(), "0.0.0.0:8080");
        assert_eq!(config.server.bind_addr(Some("1234")).unwrap(), "0.0.0.0:1234");
        assert_eq!(
            config.server.effective_allowed_hosts(Some("keyshare.up.railway.app")),
            vec!["keyshare.up.railway.app".to_string()]
        );
        assert!(config.hyperliquid.is_none());
        assert_eq!(config.chains[0].id, 11155111);
        assert_eq!(config.server.policy, PathBuf::from("/data/policy.toml"));
        {
            let bot = config.bots.get("filltape").unwrap();
            assert_eq!(bot.credential_sha256, B256::ZERO);
            assert_eq!(bot.key_env.as_deref(), Some("FILLTAPE_KEY"));
        }

        // The image ships policy.example.toml as the starting point for /data/policy.toml.
        let text = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../policy.example.toml"));
        let doc = keyshare_core::policy_file::PolicyDoc::parse(&text.unwrap()).unwrap();
        let mut policy = PolicySet::from_doc(&doc).unwrap();
        {
            let bot = policy.bots.get("filltape").unwrap();
            assert_eq!(bot.core.chains, vec![11155111]);
            let hl = bot.hyperliquid.as_ref().unwrap();
            assert_eq!(hl.markets, vec!["ETH".to_string(), "BTC".to_string()]);
            assert!(!hl.equity_floor_enabled());
        }
        assert!(config.hyperliquid(&policy).is_ok());

        {
            let hl = policy.bots.get_mut("filltape").unwrap().hyperliquid.as_mut().unwrap();
            hl.equity_floor_usd = Some(0);
        }
        let err = config.hyperliquid(&policy).err().unwrap().to_string();
        assert!(err.contains("filltape") && err.contains("positive"), "{err}");
        {
            let hl = policy.bots.get_mut("filltape").unwrap().hyperliquid.as_mut().unwrap();
            hl.equity_floor_usd = Some(500);
            hl.max_drawdown_from_peak_usd = Some(100);
        }
        assert!(config.hyperliquid(&policy).is_ok());
    }
}
