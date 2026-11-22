//! The Hyperliquid agent key file. `hl-approve-agent` writes it (mode 0600) and the connector
//! reads it to sign L1 actions. A module never sees the key bytes or the file path.

use std::path::{Path, PathBuf};

use alloy::primitives::{Address, B256};
use keyshare_core::signer::Signer;
use serde::{Deserialize, Serialize};

use crate::LocalSigner;

/// An agent this close to expiry is treated as expired, so an order never races the cutoff.
const EXPIRY_MARGIN_MS: u64 = 60_000;

/// Whether the connector should refuse to load an agent key valid until `valid_until_ms`.
pub fn expired(valid_until_ms: u64, now_ms: u64) -> bool {
    valid_until_ms <= now_ms.saturating_add(EXPIRY_MARGIN_MS)
}

/// Where the agent key for `bot` lives under the server's state directory.
pub fn path(state_dir: &Path, bot: &str) -> PathBuf {
    state_dir.join("hyperliquid").join(format!("{bot}.agent.json"))
}

/// The file on disk. A new key every time: an agent address is never reused (design §8).
#[derive(Serialize, Deserialize)]
struct AgentFile {
    address: Address,
    key: String,
    name: String,
    valid_until_ms: u64,
}

/// A freshly generated agent key that has not been approved or saved yet.
pub struct NewAgent {
    key: String,
    address: Address,
}

impl NewAgent {
    pub fn generate() -> Result<Self, String> {
        let key = B256::random().to_string();
        let address = LocalSigner::from_hex(&key).map_err(|e| e.to_string())?.address();
        Ok(Self { key, address })
    }

    pub fn address(&self) -> Address {
        self.address
    }

    /// Writes the key file once Hyperliquid has accepted the approval.
    pub fn save(self, state_dir: &Path, bot: &str, name: String, valid_until_ms: u64) -> Result<SavedAgent, String> {
        let file = AgentFile { address: self.address, key: self.key, name, valid_until_ms };
        let text = serde_json::to_vec_pretty(&file).map_err(|e| e.to_string())?;
        let at = path(state_dir, bot);
        write_private(&at, &text).map_err(|e| e.to_string())?;
        Ok(SavedAgent { address: file.address, valid_until_ms, path: at })
    }
}

/// What the owner command prints after saving. No key bytes.
#[derive(Debug, Clone)]
pub struct SavedAgent {
    pub address: Address,
    pub valid_until_ms: u64,
    pub path: PathBuf,
}

/// Why an agent key could not be loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    Missing,
    Unreadable,
    Expired,
    Mismatch,
}

impl OpenError {
    pub fn reason(self) -> &'static str {
        match self {
            Self::Missing => "no agent key",
            Self::Unreadable => "agent key file is unreadable",
            Self::Expired => "agent key has expired",
            Self::Mismatch => "agent key does not match its address",
        }
    }
}

/// Loads the agent key the owner approved, refusing one that is expired or does not match the
/// address recorded next to it.
pub fn open(state_dir: &Path, bot: &str, now_ms: u64) -> Result<LocalSigner, OpenError> {
    let text = std::fs::read_to_string(path(state_dir, bot)).map_err(|_| OpenError::Missing)?;
    let file: AgentFile = serde_json::from_str(&text).map_err(|_| OpenError::Unreadable)?;
    if expired(file.valid_until_ms, now_ms) {
        return Err(OpenError::Expired);
    }
    let signer = LocalSigner::from_hex(&file.key).map_err(|_| OpenError::Unreadable)?;
    if signer.address() != file.address {
        return Err(OpenError::Mismatch);
    }
    Ok(signer)
}

/// Writes a file only its owner can read, replacing any old one.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_agent_round_trips_and_expires() {
        let dir = tempfile::tempdir().unwrap();
        let agent = NewAgent::generate().unwrap();
        let address = agent.address();
        let saved = agent.save(dir.path(), "filltape", "n".into(), 10_000_000).unwrap();
        assert_eq!(saved.address, address);
        assert_eq!(open(dir.path(), "filltape", 0).unwrap().address(), address);
        assert_eq!(open(dir.path(), "filltape", 10_000_000).err(), Some(OpenError::Expired));
        assert_eq!(open(dir.path(), "other", 0).err(), Some(OpenError::Missing));
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&saved.path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn mismatched_address_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let saved = NewAgent::generate().unwrap().save(dir.path(), "b", "n".into(), u64::MAX).unwrap();
        let mut file: serde_json::Value = serde_json::from_slice(&std::fs::read(&saved.path).unwrap()).unwrap();
        file["address"] = serde_json::json!(Address::ZERO);
        std::fs::write(&saved.path, file.to_string()).unwrap();
        assert_eq!(open(dir.path(), "b", 0).err(), Some(OpenError::Mismatch));
    }
}
