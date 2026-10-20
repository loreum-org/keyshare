//! Kill switch (design §9.4). The state is a small JSON file that is re-read before every
//! signature, so an operator can halt signing by editing it by hand, with no restart and no
//! network. A file that can't be read halts everything (fail closed).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::refusal::{Refusal, RefusalCode};
use crate::spend::write_atomic;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillState {
    #[serde(default)]
    pub global: bool,
    /// Callers (bot ids) that are frozen.
    #[serde(default)]
    pub callers: BTreeSet<String>,
}

pub struct KillSwitch {
    path: PathBuf,
}

impl KillSwitch {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self { path: path.as_ref().to_path_buf() }
    }

    pub fn state(&self) -> Result<KillState, String> {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| e.to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(KillState::default()),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn check(&self, caller: &str) -> Result<(), Refusal> {
        let halted = |why: String| Refusal::new(RefusalCode::KillSwitch, why);
        let state = self.state().map_err(|e| halted(format!("kill switch file unreadable, failing closed: {e}")))?;
        if state.global {
            return Err(halted("signing is frozen for all wallets".into()));
        }
        if state.callers.contains(caller) {
            return Err(halted(format!("signing is frozen for {caller}")));
        }
        Ok(())
    }

    /// `caller: None` sets the global flag.
    pub fn set(&self, caller: Option<&str>, on: bool) -> std::io::Result<KillState> {
        let mut state = self.state().map_err(std::io::Error::other)?;
        match caller {
            None => state.global = on,
            Some(c) if on => {
                state.callers.insert(c.to_string());
            }
            Some(c) => {
                state.callers.remove(c);
            }
        }
        write_atomic(&self.path, &serde_json::to_vec_pretty(&state)?)?;
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_and_per_caller() {
        let dir = tempfile::tempdir().unwrap();
        let ks = KillSwitch::new(dir.path().join("kill.json"));
        assert!(ks.check("filltape").is_ok());
        ks.set(Some("filltape"), true).unwrap();
        assert!(ks.check("filltape").is_err());
        assert!(ks.check("loreum").is_ok());
        ks.set(None, true).unwrap();
        assert!(ks.check("loreum").is_err());
        ks.set(None, false).unwrap();
        ks.set(Some("filltape"), false).unwrap();
        assert!(ks.check("filltape").is_ok());
    }

    #[test]
    fn hand_edit_takes_effect_and_garbage_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kill.json");
        let ks = KillSwitch::new(&path);
        std::fs::write(&path, r#"{"global": true}"#).unwrap();
        assert_eq!(ks.check("x").unwrap_err().code, RefusalCode::KillSwitch);
        std::fs::write(&path, "not json").unwrap();
        assert_eq!(ks.check("x").unwrap_err().code, RefusalCode::KillSwitch);
    }
}
