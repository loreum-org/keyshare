//! This signer's own spend counter (design §6.4). It records a spend when the signer approves a
//! request, before signing, and never asks another node for its total. It also holds the used
//! request ids, so a request id can't be replayed.
//!
//! Rollback guard: the head is copied to an anchor file after every append (point it at a
//! different disk or mount). If the local log is ever behind the anchor, as after restoring an old
//! disk image, the signer refuses until an operator fixes it.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::chainlog::{ChainLog, Head, LogError};
use crate::price::UsdMicros;
use crate::refusal::{Refusal, RefusalCode};

pub const WINDOW_SECS: u64 = 24 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendEntry {
    pub caller: String,
    pub request_id: String,
    pub usd_micros: UsdMicros,
    /// Unix seconds.
    pub at: u64,
}

pub struct SpendLog {
    log: ChainLog<SpendEntry>,
    anchor: Option<PathBuf>,
    by_caller: HashMap<String, Vec<(u64, UsdMicros)>>,
    used_requests: HashSet<String>,
}

impl SpendLog {
    pub fn open(path: impl AsRef<Path>, anchor: Option<PathBuf>) -> Result<Self, LogError> {
        let (log, entries) = ChainLog::open(path)?;
        let mut s = Self { log, anchor, by_caller: HashMap::new(), used_requests: HashSet::new() };
        for e in entries {
            s.index(e);
        }
        Ok(s)
    }

    fn index(&mut self, e: SpendEntry) {
        self.used_requests.insert(e.request_id);
        self.by_caller.entry(e.caller).or_default().push((e.at, e.usd_micros));
    }

    pub fn head(&self) -> Head {
        self.log.head()
    }

    /// Rolling 24h total for `caller` as of `now`.
    pub fn spent_24h(&self, caller: &str, now: u64) -> UsdMicros {
        let since = now.saturating_sub(WINDOW_SECS);
        self.by_caller
            .get(caller)
            .map(|v| v.iter().filter(|(at, _)| *at > since).map(|(_, usd)| usd).sum())
            .unwrap_or(0)
    }

    pub fn check_request_id(&self, request_id: &str) -> Result<(), Refusal> {
        if self.used_requests.contains(request_id) {
            return Err(Refusal::new(RefusalCode::NonceReused, format!("request {request_id} was already used")));
        }
        Ok(())
    }

    /// Refuses if the local log is behind, or differs from, the last anchored head.
    pub fn check_anchor(&self) -> Result<(), Refusal> {
        let Some(path) = &self.anchor else { return Ok(()) };
        let behind = |why: String| Refusal::new(RefusalCode::CounterBehindAnchor, why);
        let anchored: Head = match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| behind(format!("unreadable anchor: {e}")))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(behind(format!("unreadable anchor: {e}"))),
        };
        match self.log.hash_at(anchored.seq) {
            Some(hash) if hash == anchored.hash => Ok(()),
            Some(_) => Err(behind(format!("spend log differs from anchor at seq {}", anchored.seq))),
            None => Err(behind(format!(
                "spend log is at seq {} but the anchor is at {}",
                self.log.head().seq,
                anchored.seq
            ))),
        }
    }

    /// Records a spend (and burns its request id). Call before signing.
    pub fn record(&mut self, entry: SpendEntry) -> Result<Head, LogError> {
        let head = self.log.append(&entry)?;
        self.index(entry);
        if let Some(path) = &self.anchor {
            write_atomic(path, &serde_json::to_vec(&head)?)?;
        }
        Ok(head)
    }
}

pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::File::open(&tmp)?.sync_all()?;
    std::fs::rename(tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::price::MICROS_PER_USD;

    fn entry(caller: &str, id: &str, usd: u128, at: u64) -> SpendEntry {
        SpendEntry { caller: caller.into(), request_id: id.into(), usd_micros: usd * MICROS_PER_USD, at }
    }

    #[test]
    fn rolling_window_per_caller() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = SpendLog::open(dir.path().join("spend.jsonl"), None).unwrap();
        log.record(entry("filltape", "r1", 100, 1_000)).unwrap();
        log.record(entry("filltape", "r2", 50, 1_000 + WINDOW_SECS - 1)).unwrap();
        log.record(entry("loreum", "r3", 7, 1_000)).unwrap();
        assert_eq!(log.spent_24h("filltape", 1_000 + 10), 150 * MICROS_PER_USD);
        assert_eq!(log.spent_24h("filltape", 1_000 + WINDOW_SECS), 50 * MICROS_PER_USD);
        assert_eq!(log.spent_24h("loreum", 1_000), 7 * MICROS_PER_USD);
        assert_eq!(log.spent_24h("nobody", 1_000), 0);
    }

    #[test]
    fn request_ids_survive_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spend.jsonl");
        SpendLog::open(&path, None).unwrap().record(entry("filltape", "r1", 1, 1)).unwrap();
        let log = SpendLog::open(&path, None).unwrap();
        assert_eq!(log.check_request_id("r1").unwrap_err().code, RefusalCode::NonceReused);
        assert!(log.check_request_id("r2").is_ok());
        assert_eq!(log.spent_24h("filltape", 2), MICROS_PER_USD);
    }

    #[test]
    fn restored_old_disk_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spend.jsonl");
        let anchor = dir.path().join("anchor.json");
        let mut log = SpendLog::open(&path, Some(anchor.clone())).unwrap();
        log.record(entry("filltape", "r1", 100, 1)).unwrap();
        let snapshot = std::fs::read(&path).unwrap();
        log.record(entry("filltape", "r2", 100, 2)).unwrap();
        assert!(log.check_anchor().is_ok());
        drop(log);

        // Roll the spend log back to the earlier snapshot; the anchor still has seq 2.
        std::fs::write(&path, snapshot).unwrap();
        let log = SpendLog::open(&path, Some(anchor)).unwrap();
        assert_eq!(log.check_anchor().unwrap_err().code, RefusalCode::CounterBehindAnchor);
    }
}
