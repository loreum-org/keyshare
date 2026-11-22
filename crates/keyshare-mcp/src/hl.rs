//! Re-exports the Hyperliquid module and the owner command that approves an agent key.
//! The owner command signs the bot wallet key here. Bot tools sign through
//! [`keyshare_hyperliquid::HlHost::sign_l1`] on the executor.

pub use keyshare_hyperliquid::{HlConfig, Hyperliquid, OrderSpec, check_api_url, now_ms};
pub use keyshare_signer::agent::{SavedAgent, path as agent_path};

use keyshare_core::{Refusal, RefusalCode, Signer};
use keyshare_signer::LocalSigner;
use keyshare_signer::agent::{self, NewAgent};

use crate::config::Config;

/// Loads the agent key the owner approved. Only the connector does this; the module asks
/// [`keyshare_hyperliquid::HlHost::sign_l1`] and never sees the key bytes or the file.
pub(crate) fn open_agent(hl: &Hyperliquid, bot: &str) -> Result<LocalSigner, Refusal> {
    agent::open(hl.state_dir(), bot, now_ms()).map_err(|e| {
        Refusal::new(
            RefusalCode::NoAgentKey,
            format!("{}; the owner runs `keyshare-mcp hl-approve-agent <config> {bot}`", e.reason()),
        )
    })
}

pub async fn approve_agent(
    config: &Config,
    bot: &str,
    hours: u64,
    env: impl Fn(&str) -> Option<String>,
) -> Result<SavedAgent, String> {
    let cfg = config.bots.get(bot).ok_or_else(|| format!("no bot {bot} in the config"))?;
    if cfg.hyperliquid.is_none() {
        return Err(format!("bot {bot} has no [bots.{bot}.hyperliquid] table"));
    }
    let key = env(&cfg.key_env).ok_or_else(|| format!("{} is not set", cfg.key_env))?;
    let master = LocalSigner::from_hex(&key).map_err(|e| e.to_string())?;
    let venue = config.hyperliquid().map_err(|e| e.to_string())?;
    let agent = NewAgent::generate()?;
    let approved = keyshare_hyperliquid::approve_agent(
        &venue,
        bot,
        agent.address(),
        hours,
        &config.state_paths().kill_switch,
        move |data| master.sign_typed_data(data).map_err(|e| e.to_string()),
    )
    .await?;
    agent.save(&config.server.state_dir, bot, approved.name, approved.valid_until_ms)
}
