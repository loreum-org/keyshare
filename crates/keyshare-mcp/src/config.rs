//! Connector config: one TOML file. Secrets (bot keys) come from environment variables named in
//! the file, never from the file itself.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use alloy::primitives::{Address, B256};
use keyshare_core::hyperliquid::HlPolicy;
use keyshare_core::price::PriceEntry;
use keyshare_core::{Account, LocalSigner, PlainPolicy, PriceTable, Signer, StatePaths, Wallet};
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
    pub listen: String,
    /// Host header values to accept (DNS-rebinding guard). Empty leaves the guard off, so bind
    /// `listen` to localhost unless this lists the hosts you actually serve.
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
        let policies =
            self.bots.iter().filter_map(|(bot, cfg)| Some((bot.clone(), cfg.hyperliquid.clone()?))).collect();
        Ok(Hyperliquid::new(self.hyperliquid.as_ref(), self.server.state_dir.clone(), policies))
    }
}
