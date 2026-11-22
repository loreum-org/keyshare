//! Host side of the Hyperliquid module.
//!
//! The module builds intents. This file is the part that is allowed to hold a key:
//! loading the agent file, signing through the core's allowlist check, and the
//! owner CLI that approves a new agent with the bot's wallet key.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use alloy::primitives::B256;
use keyshare_core::killswitch::KillSwitch;
use keyshare_core::{LocalSigner, Refusal, RefusalCode, Signer};
use keyshare_hyperliquid as hl;

use crate::config::Config;

pub use hl::{AgentFile, HlConfig, Hyperliquid, OrderSpec, TESTNET_API, agent_path, check_api_url, now_ms};

/// Phase 0 signs for testnet only.
const MAINNET: bool = false;

/// Reads the agent file and checks it. The signer is for the host, not for a module.
pub fn load_agent(state_dir: &Path, bot: &str) -> Result<LocalSigner, Refusal> {
    let none = |why: &str| {
        Refusal::new(
            RefusalCode::NoAgentKey,
            format!("{why}; the owner runs `keyshare-mcp hl-approve-agent <config> {bot}`"),
        )
    };
    let text = std::fs::read_to_string(hl::agent_path(state_dir, bot)).map_err(|_| none("no agent key"))?;
    let file: AgentFile = serde_json::from_str(&text).map_err(|_| none("agent key file is unreadable"))?;
    if file.valid_until_ms <= hl::now_ms() + hl::EXPIRY_MARGIN_MS {
        return Err(none("agent key has expired"));
    }
    let signer = LocalSigner::from_hex(&file.key).map_err(|_| none("agent key file is unreadable"))?;
    if signer.address() != file.address {
        return Err(none("agent key does not match its address"));
    }
    Ok(signer)
}

/// Generates a brand-new agent key, has the bot's wallet key (the master) approve it on
/// Hyperliquid testnet, and saves it where the server reads it. Run by the owner, not a bot.
/// An agent address is never reused (design §8).
pub async fn approve_agent(
    config: &Config,
    bot: &str,
    hours: u64,
    env: impl Fn(&str) -> Option<String>,
) -> Result<AgentFile, String> {
    let cfg = config.bots.get(bot).ok_or_else(|| format!("no bot {bot} in the config"))?;
    if cfg.hyperliquid.is_none() {
        return Err(format!("bot {bot} has no [bots.{bot}.hyperliquid] table"));
    }
    KillSwitch::new(config.state_paths().kill_switch).check(bot).map_err(|r| r.reason)?;
    let key = env(&cfg.key_env).ok_or_else(|| format!("{} is not set", cfg.key_env))?;
    let master = LocalSigner::from_hex(&key).map_err(|e| e.to_string())?;
    let agent_key = B256::random().to_string();
    let agent = LocalSigner::from_hex(&agent_key).map_err(|e| e.to_string())?;
    let nonce = hl::now_ms();
    let valid_until_ms = nonce + hours * 3_600_000;
    // Hyperliquid reads an agent's expiry from this suffix on its name.
    let name = format!("keyshare-{bot} valid_until {valid_until_ms}");
    // Testnet only. A mainnet payload is not what this command builds.
    let (action, data) = hl::approve_agent(agent.address(), &name, nonce, MAINNET);
    let sig = master.sign_typed_data(&data).map_err(|e| e.to_string())?;
    let body = serde_json::json!({
        "action": action,
        "nonce": nonce,
        "signature": hl::signature_json(&sig),
        "vaultAddress": serde_json::Value::Null,
        "expiresAfter": serde_json::Value::Null,
    });
    let venue = config.hyperliquid().map_err(|e| e.to_string())?;
    let resp = venue.post("/exchange", &body).await.map_err(|r| r.reason)?;
    if resp["status"] != "ok" {
        return Err(format!("Hyperliquid refused the agent: {resp}"));
    }
    let file = AgentFile { address: agent.address(), key: agent_key, name, valid_until_ms };
    let text = serde_json::to_vec_pretty(&file).map_err(|e| e.to_string())?;
    write_private(&hl::agent_path(&config.server.state_dir, bot), &text).map_err(|e| e.to_string())?;
    Ok(file)
}

/// Writes a file only its owner can read, replacing any old one.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    // A stale tmp file could carry looser permissions; start fresh so mode 0600 applies.
    match std::fs::remove_file(&tmp) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}
