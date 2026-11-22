//! Re-exports the Hyperliquid module and the owner command that approves an agent key.
//! The owner command signs the bot wallet key here. Bot tools sign through
//! [`keyshare_hyperliquid::HlHost::sign_l1`] on the executor.

pub use keyshare_hyperliquid::{AgentFile, HlConfig, Hyperliquid, OrderSpec, agent_path, check_api_url, now_ms};

use keyshare_core::{LocalSigner, Refusal, RefusalCode, Signer};
use keyshare_hyperliquid::agent_expired;

use crate::config::Config;

/// Loads the agent key the owner approved. Only the connector does this; the module asks
/// [`keyshare_hyperliquid::HlHost::sign_l1`] and never sees the key bytes.
pub(crate) fn open_agent(hl: &Hyperliquid, bot: &str) -> Result<LocalSigner, Refusal> {
    let none = |why: &str| {
        Refusal::new(
            RefusalCode::NoAgentKey,
            format!("{why}; the owner runs `keyshare-mcp hl-approve-agent <config> {bot}`"),
        )
    };
    let text = std::fs::read_to_string(hl.agent_path_for(bot)).map_err(|_| none("no agent key"))?;
    let file: AgentFile = serde_json::from_str(&text).map_err(|_| none("agent key file is unreadable"))?;
    if agent_expired(file.valid_until_ms, now_ms()) {
        return Err(none("agent key has expired"));
    }
    let signer = LocalSigner::from_hex(&file.key).map_err(|_| none("agent key file is unreadable"))?;
    if signer.address() != file.address {
        return Err(none("agent key does not match its address"));
    }
    Ok(signer)
}

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
    let key = env(&cfg.key_env).ok_or_else(|| format!("{} is not set", cfg.key_env))?;
    let master = LocalSigner::from_hex(&key).map_err(|e| e.to_string())?;
    let venue = config.hyperliquid().map_err(|e| e.to_string())?;
    keyshare_hyperliquid::approve_agent(
        &venue,
        bot,
        hours,
        &config.server.state_dir,
        &config.state_paths().kill_switch,
        move |data| master.sign_typed_data(data).map_err(|e| e.to_string()),
    )
    .await
}
