//! Append-only, hash-chained JSON-lines log. Used for the audit log (design §9.3) and the per-node
//! spend counter (§6.4). Each line commits to the previous one, and opening a log re-verifies the
//! whole chain, so an edited or truncated-in-the-middle file is refused.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use alloy::primitives::{B256, keccak256};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum LogError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("log {path} is broken at line {line}: {why}")]
    Broken { path: PathBuf, line: usize, why: &'static str },
}

/// Sequence number and hash of the newest entry. `seq` 0 with a zero hash is the empty log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Head {
    pub seq: u64,
    pub hash: B256,
}

impl Head {
    pub const EMPTY: Head = Head { seq: 0, hash: B256::ZERO };
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Line<T> {
    pub seq: u64,
    pub prev: B256,
    pub hash: B256,
    pub body: T,
}

fn line_hash(seq: u64, prev: &B256, body_json: &[u8]) -> B256 {
    let mut buf = Vec::with_capacity(8 + 32 + body_json.len());
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(prev.as_slice());
    buf.extend_from_slice(body_json);
    keccak256(buf)
}

pub struct ChainLog<T> {
    path: PathBuf,
    file: File,
    /// `hashes[i]` is the hash of the entry with `seq == i + 1`.
    hashes: Vec<B256>,
    _body: std::marker::PhantomData<T>,
}

impl<T: Serialize + DeserializeOwned> ChainLog<T> {
    /// Opens or creates the log and returns it with every existing body, oldest first.
    pub fn open(path: impl AsRef<Path>) -> Result<(Self, Vec<T>), LogError> {
        let path = path.as_ref().to_path_buf();
        let mut hashes = Vec::new();
        let mut bodies = Vec::new();
        if path.exists() {
            let broken = |line, why| LogError::Broken { path: path.clone(), line, why };
            for (i, raw) in BufReader::new(File::open(&path)?).lines().enumerate() {
                let raw = raw?;
                let line: Line<serde_json::Value> =
                    serde_json::from_str(&raw).map_err(|_| broken(i + 1, "not a log line"))?;
                let prev = hashes.last().copied().unwrap_or(B256::ZERO);
                if line.seq != i as u64 + 1 {
                    return Err(broken(i + 1, "sequence gap"));
                }
                if line.prev != prev {
                    return Err(broken(i + 1, "previous hash does not match"));
                }
                if line.hash != line_hash(line.seq, &line.prev, serde_json::to_string(&line.body)?.as_bytes()) {
                    return Err(broken(i + 1, "hash does not match contents"));
                }
                hashes.push(line.hash);
                bodies.push(serde_json::from_value(line.body).map_err(|_| broken(i + 1, "unexpected body"))?);
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok((Self { path, file, hashes, _body: std::marker::PhantomData }, bodies))
    }

    pub fn head(&self) -> Head {
        match self.hashes.last() {
            Some(hash) => Head { seq: self.hashes.len() as u64, hash: *hash },
            None => Head::EMPTY,
        }
    }

    /// Hash of the entry at `seq`, if this log has it.
    pub fn hash_at(&self, seq: u64) -> Option<B256> {
        if seq == 0 {
            return Some(B256::ZERO);
        }
        self.hashes.get(usize::try_from(seq - 1).ok()?).copied()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends and fsyncs before returning, so an approval is on disk before anything is signed.
    pub fn append(&mut self, body: &T) -> Result<Head, LogError> {
        let prev = self.head();
        let seq = prev.seq + 1;
        // Hash the body exactly as it is re-read on open (a serde_json::Value, keys sorted).
        let value = serde_json::to_value(body)?;
        let hash = line_hash(seq, &prev.hash, serde_json::to_string(&value)?.as_bytes());
        let mut out = serde_json::to_vec(&Line { seq, prev: prev.hash, hash, body: value })?;
        out.push(b'\n');
        self.file.write_all(&out)?;
        self.file.sync_data()?;
        self.hashes.push(hash);
        Ok(Head { seq, hash })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Body {
        n: u32,
        name: String,
    }

    #[test]
    fn reopens_and_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        {
            let (mut log, existing) = ChainLog::<Body>::open(&path).unwrap();
            assert!(existing.is_empty());
            log.append(&Body { n: 1, name: "a".into() }).unwrap();
            let head = log.append(&Body { n: 2, name: "b".into() }).unwrap();
            assert_eq!(head.seq, 2);
        }
        let (log, existing) = ChainLog::<Body>::open(&path).unwrap();
        assert_eq!(existing.len(), 2);
        assert_eq!(existing[1], Body { n: 2, name: "b".into() });
        assert_eq!(log.head().seq, 2);
    }

    #[test]
    fn edited_line_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        {
            let (mut log, _) = ChainLog::<Body>::open(&path).unwrap();
            log.append(&Body { n: 1, name: "a".into() }).unwrap();
            log.append(&Body { n: 500, name: "b".into() }).unwrap();
        }
        let text = std::fs::read_to_string(&path).unwrap().replace("\"n\":500", "\"n\":5");
        std::fs::write(&path, text).unwrap();
        assert!(matches!(ChainLog::<Body>::open(&path), Err(LogError::Broken { line: 2, .. })));
    }

    #[test]
    fn dropped_line_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        {
            let (mut log, _) = ChainLog::<Body>::open(&path).unwrap();
            for n in 0..3 {
                log.append(&Body { n, name: "x".into() }).unwrap();
            }
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let kept: Vec<&str> = text.lines().enumerate().filter(|(i, _)| *i != 1).map(|(_, l)| l).collect();
        std::fs::write(&path, kept.join("\n") + "\n").unwrap();
        assert!(matches!(ChainLog::<Body>::open(&path), Err(LogError::Broken { line: 2, .. })));
    }
}
