use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use keyshare_core::killswitch::KillSwitch;
use keyshare_mcp::auth::new_token;
use keyshare_mcp::chain::Chains;
use keyshare_mcp::config::Config;
use keyshare_mcp::exec::{DEFAULT_HOLD_SECS, Executor};
use keyshare_mcp::hl;

const USAGE: &str = "\
usage:
  keyshare-mcp serve <config.toml>             run the connector
  keyshare-mcp new-token                       print a bot token and its sha256 for the config
  keyshare-mcp freeze <config.toml> [bot]      kill switch on (all bots, or one)
  keyshare-mcp unfreeze <config.toml> [bot]    kill switch off
  keyshare-mcp hl-approve-agent <config.toml> <bot> [hours]
                                               new Hyperliquid testnet agent key for a bot,
                                               approved by its wallet key (default 48 hours)";

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["serve", path] => serve(PathBuf::from(path)).await,
        ["new-token"] => {
            let (token, hash) = new_token();
            println!("token:             {token}\ncredential_sha256: \"{hash}\"");
            Ok(())
        }
        ["freeze", path, rest @ ..] if rest.len() <= 1 => kill(path, rest.first().copied(), true),
        ["unfreeze", path, rest @ ..] if rest.len() <= 1 => kill(path, rest.first().copied(), false),
        ["hl-approve-agent", path, bot] => approve_agent(path, bot, 48).await,
        ["hl-approve-agent", path, bot, hours] => match hours.parse() {
            Ok(h) if (1..=24 * 7).contains(&h) => approve_agent(path, bot, h).await,
            _ => Err("hours must be 1 to 168".into()),
        },
        _ => Err(USAGE.into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

async fn serve(path: PathBuf) -> Result<()> {
    let config = Config::load(&path)?;
    let creds = Arc::new(config.credentials()?);
    if config.anchor_in_state_dir() {
        eprintln!(
            "warning: spend_anchor is inside state_dir; put it on another disk so a restored or deleted state dir is caught"
        );
    }
    let wallet = config.wallet(|var| std::env::var(var).ok())?;
    for bot in config.bots.keys() {
        eprintln!("bot {bot}: {}", wallet.address(bot)?);
    }
    let chains = Arc::new(Chains::new(&config.chains)?);
    let tokens = Arc::new(config.prices.clone());
    let hold = config.server.hold_secs.unwrap_or(DEFAULT_HOLD_SECS);
    let hl = config.hyperliquid()?;
    let exec = Arc::new(Executor::new(Arc::new(Mutex::new(wallet)), chains, tokens, hold).with_hyperliquid(hl));
    let port = std::env::var("PORT").ok();
    let listen = config.server.bind_addr(port.as_deref())?;
    let extra_hosts = std::env::var("KEYSHARE_ALLOWED_HOSTS").ok();
    let allowed_hosts = config.server.effective_allowed_hosts(extra_hosts.as_deref());
    let app = keyshare_mcp::app(exec, creds, config.server.admin_token_sha256, &allowed_hosts);
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    eprintln!("listening on {}", listener.local_addr()?);
    if allowed_hosts.is_empty() {
        eprintln!("allowed hosts: default (localhost, 127.0.0.1, ::1)");
    } else {
        eprintln!("allowed hosts: {}", allowed_hosts.join(", "));
    }
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

fn kill(path: &str, bot: Option<&str>, on: bool) -> Result<()> {
    let config = Config::load(path.as_ref())?;
    std::fs::create_dir_all(&config.server.state_dir)?;
    let state = KillSwitch::new(config.state_paths().kill_switch).set(bot, on)?;
    println!("{}", serde_json::to_string_pretty(&state)?);
    Ok(())
}

async fn approve_agent(path: &str, bot: &str, hours: u64) -> Result<()> {
    let config = Config::load(path.as_ref())?;
    let file = hl::approve_agent(&config, bot, hours, |var| std::env::var(var).ok()).await?;
    println!("approved agent {} until {} (unix ms)", file.address, file.valid_until_ms);
    println!("saved to {}", hl::agent_path(&config.server.state_dir, bot).display());
    Ok(())
}
