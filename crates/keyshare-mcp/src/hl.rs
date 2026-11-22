//! Re-exports the Hyperliquid module and the owner command that approves an agent key.
//! The owner command signs the bot wallet key here. Bot tools sign through
//! [`keyshare_hyperliquid::HlHost::sign_l1`] on the executor.

pub use keyshare_hyperliquid::{AgentFile, HlConfig, Hyperliquid, OrderSpec, agent_path, check_api_url, now_ms};

use keyshare_core::{LocalSigner, Signer};

use crate::config::Config;

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
