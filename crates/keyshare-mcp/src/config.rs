//! Connector config: one TOML file. Secrets (bot keys) come from environment variables named in
//! the file, never from the file itself.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use alloy::primitives::{Address, B256};
use keyshare_core::price::PriceEntry;
use keyshare_core::{Account, LocalSigner, PlainPolicy, PriceTable, Signer, StatePaths, Wallet};
use keyshare_hyperliquid::HlPolicy;
use serde::Deserialize;

use crate::chain::ChainConfig;
use crate::hl::{HlConfig, Hyperliquid};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    /// RPC endpoint per chain. Chain tools refuse chains not listed here.
    #[serde(default)]
    pub chains: Vec<ChainConfig>,
    #[serde(default)]
    pub prices: Vec<PriceEntry>,
    /// Hyperliquid API settings. Bots trade there only with a `[bots.<id>.hyperliquid]` table.
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
    /// Environment variable holding this bot's testnet private key.
    pub key_env: String,
    /// The owner's admin keys (Ethereum addresses). With at least one, refusals the owner can
    /// waive are held for approval instead of refused (design §13.2).
    #[serde(default)]
    pub admin_keys: Vec<Address>,
    pub policy: PlainPolicy,
    /// Hyperliquid testnet guardrails. Without this table the `hl_*` tools refuse this bot.
    pub hyperliquid: Option<HlPolicy>,
    /// Which protocol modules this bot is offered. Omitted means every module stays available,
    /// which is how the tools behaved before modules could be switched off.
    #[serde(default)]
    pub modules: ModuleToggles,
}

/// Per-bot module switches. `false` removes that module's tools from `tools/list` and rejects calls.
#[derive(Debug, Clone, Deserialize)]
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

    /// Builds the wallet, reading each bot's key with `env`.
    pub fn wallet(&self, env: impl Fn(&str) -> Option<String>) -> Result<Wallet, ConfigError> {
        let mut accounts = HashMap::new();
        for (bot, cfg) in &self.bots {
            let key = env(&cfg.key_env)
                .ok_or_else(|| ConfigError::MissingKey { bot: bot.clone(), var: cfg.key_env.clone() })?;
            let signer = LocalSigner::from_hex(&key)
                .map_err(|e| ConfigError::BadKey { bot: bot.clone(), why: e.to_string() })?;
            let own = signer.address();
            accounts.insert(
                bot.clone(),
                Account {
                    signer: Box::new(signer),
                    policy: Box::new(PlainPolicy { own_address: Some(own), ..cfg.policy.clone() }),
                    admins: cfg.admin_keys.clone(),
                },
            );
        }
        let prices = PriceTable::from_entries(&self.prices).map_err(|e| ConfigError::Other(e.to_string()))?;
        std::fs::create_dir_all(&self.server.state_dir)
            .map_err(|e| ConfigError::Read(self.server.state_dir.clone(), e))?;
        Wallet::open(accounts, Box::new(prices), &self.state_paths()).map_err(|e| ConfigError::Other(e.to_string()))
    }

    pub fn hyperliquid(&self) -> Result<Hyperliquid, ConfigError> {
        crate::hl::check_api_url(self.hyperliquid.as_ref()).map_err(ConfigError::Other)?;
        let mut policies = HashMap::new();
        for (bot, cfg) in &self.bots {
            let Some(policy) = cfg.hyperliquid.clone() else { continue };
            policy.validate().map_err(|e| ConfigError::Other(format!("bot {bot}: {e}")))?;
            policies.insert(bot.clone(), policy);
        }
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
        let mut config = Config::load(&path).unwrap();
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
        {
            let bot = config.bots.get("filltape").unwrap();
            assert_eq!(bot.credential_sha256, B256::ZERO);
            assert_eq!(bot.key_env, "FILLTAPE_KEY");
            assert_eq!(bot.policy.chains, vec![11155111]);
            let hl = bot.hyperliquid.as_ref().unwrap();
            assert_eq!(hl.markets, vec!["ETH".to_string(), "BTC".to_string()]);
            assert!(!hl.equity_floor_enabled());
        }
        assert!(config.hyperliquid().is_ok());

        {
            let hl = config.bots.get_mut("filltape").unwrap().hyperliquid.as_mut().unwrap();
            hl.equity_floor_usd = Some(0);
        }
        let err = config.hyperliquid().err().unwrap().to_string();
        assert!(err.contains("filltape") && err.contains("positive"), "{err}");
        {
            let hl = config.bots.get_mut("filltape").unwrap().hyperliquid.as_mut().unwrap();
            hl.equity_floor_usd = Some(500);
            hl.max_drawdown_from_peak_usd = Some(100);
        }
        assert!(config.hyperliquid().is_ok());
    }
}
