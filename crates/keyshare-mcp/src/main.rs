use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use keyshare_core::killswitch::KillSwitch;
use keyshare_mcp::auth::new_token;
use keyshare_mcp::config::Config;

const USAGE: &str = "\
usage:
  keyshare-mcp serve <config.toml>             run the connector
  keyshare-mcp new-token                       print a bot token and its sha256 for the config
  keyshare-mcp freeze <config.toml> [bot]      kill switch on (all bots, or one)
  keyshare-mcp unfreeze <config.toml> [bot]    kill switch off";

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
    let wallet = config.wallet(|var| std::env::var(var).ok())?;
    for bot in config.bots.keys() {
        eprintln!("bot {bot}: {}", wallet.address(bot)?);
    }
    let app = keyshare_mcp::app(Arc::new(Mutex::new(wallet)), creds, &config.server.allowed_hosts);
    let listener = tokio::net::TcpListener::bind(&config.server.listen).await?;
    eprintln!("listening on {}", listener.local_addr()?);
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
