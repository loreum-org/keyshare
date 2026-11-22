use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use keyshare_core::Signer;
use keyshare_core::killswitch::KillSwitch;
use keyshare_mcp::auth::new_token;
use keyshare_mcp::config::Config;
use keyshare_mcp::{hl, policy};
use keyshare_signer::LocalSigner;

const USAGE: &str = "\
usage:
  keyshare-mcp serve <config.toml>             run the connector
  keyshare-mcp new-token                       print a bot token and its sha256 for the config
  keyshare-mcp freeze <config.toml> [bot]      kill switch on (all bots, or one)
  keyshare-mcp unfreeze <config.toml> [bot]    kill switch off
  keyshare-mcp hl-approve-agent <config.toml> <bot> [hours]
                                               new Hyperliquid testnet agent key for a bot,
                                               approved by its wallet key (default 48 hours)
  keyshare-mcp policy-hash <policy.toml>       print the policy's version, hash and the message to sign
  keyshare-mcp policy-sign <policy.toml> <KEY_ENV>
                                               sign it with the key in that environment variable
                                               and write <policy.toml>.sig (testnet convenience)
  keyshare-mcp policy-verify <policy.toml> <audit.jsonl>
                                               re-check every logged decision made under this policy
  keyshare-mcp policy-migrate <old-config.toml> <new-config.toml> <policy.toml>
                                               split an old config with inline rules into a config
                                               and an unsigned version-1 policy";

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
        ["policy-hash", path] => policy_hash(path),
        ["policy-sign", path, key_env] => policy_sign(path, key_env),
        ["policy-verify", path, audit] => policy_verify(path, audit),
        ["policy-migrate", old, new, out] => policy_migrate(old, new, out),
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
    let exec = Arc::new(keyshare_mcp::build(&config, |var| std::env::var(var).ok()).await?);
    if let Some(p) = exec.active_policy() {
        eprintln!("policy version {} ({}), signed by {}", p.reference.version, p.reference.hash, p.signer);
    }
    for bot in config.bots.keys() {
        let b = bot.clone();
        eprintln!("bot {bot}: {}", exec.with_wallet(move |w| w.address(&b)).await??);
    }
    let port = std::env::var("PORT").ok();
    let listen = config.server.bind_addr(port.as_deref())?;
    let extra_hosts = std::env::var("KEYSHARE_ALLOWED_HOSTS").ok();
    let allowed_hosts = config.server.effective_allowed_hosts(extra_hosts.as_deref());
    let admin_token = config.server.admin_token_sha256;
    let config = Arc::new(config);
    keyshare_mcp::spawn_policy_reload(exec.clone(), config.clone());
    let app = keyshare_mcp::app(exec, creds, admin_token, &allowed_hosts);
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
    let saved = hl::approve_agent(&config, bot, hours, |var| std::env::var(var).ok()).await?;
    println!("approved agent {} until {} (unix ms)", saved.address, saved.valid_until_ms);
    println!("saved to {}", saved.path.display());
    Ok(())
}

fn policy_hash(path: &str) -> Result<()> {
    let doc = policy::read_doc(Path::new(path))?;
    println!(
        "version: {}\nhash:    {}\n\nmessage to sign (EIP-191 personal_sign):\n{}",
        doc.reference.version,
        doc.reference.hash,
        doc.signing_message()
    );
    Ok(())
}

fn policy_sign(path: &str, key_env: &str) -> Result<()> {
    let doc = policy::read_doc(Path::new(path))?;
    let key = std::env::var(key_env).map_err(|_| format!("{key_env} is not set"))?;
    let signer = LocalSigner::from_hex(&key)?;
    let sig = signer.sign_message(doc.signing_message().as_bytes())?;
    let out = policy::sig_path(Path::new(path));
    std::fs::write(&out, format!("{sig}\n"))?;
    println!(
        "signed version {} ({}) as {}\nwrote {}",
        doc.reference.version,
        doc.reference.hash,
        signer.address(),
        out.display()
    );
    Ok(())
}

fn policy_verify(path: &str, audit: &str) -> Result<()> {
    if !Path::new(audit).exists() {
        return Err(format!("{audit} does not exist").into());
    }
    let text = std::fs::read_to_string(path)?;
    let report = policy::verify_audit(&text, Path::new(audit))?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    if report.mismatches.is_empty() {
        println!("ok: {} decisions follow from this policy", report.checked);
        Ok(())
    } else {
        Err(format!("{} of {} decisions do not follow from this policy", report.mismatches.len(), report.checked)
            .into())
    }
}

fn policy_migrate(old: &str, new: &str, out: &str) -> Result<()> {
    for target in [new, out] {
        if Path::new(target).exists() {
            return Err(format!("{target} exists; pick a new path").into());
        }
    }
    let (config, policy) = policy::migrate(&std::fs::read_to_string(old)?, out)?;
    std::fs::write(new, config)?;
    std::fs::write(out, policy)?;
    println!("wrote {new} and {out}. Check policy_signers in {new}, then sign:\n  keyshare-mcp policy-hash {out}");
    Ok(())
}
