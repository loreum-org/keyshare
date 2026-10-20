//! Append-only audit log (design §9.3). Every request is logged before it is checked, and its
//! outcome after, so a signature with no audit trail can't happen.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::chainlog::{ChainLog, Head, LogError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEvent {
    Requested,
    Refused,
    Signed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub at: u64,
    pub request_id: String,
    pub caller: String,
    pub event: AuditEvent,
    pub detail: serde_json::Value,
}

pub struct AuditLog(ChainLog<AuditEntry>);

impl AuditLog {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LogError> {
        Ok(Self(ChainLog::open(path)?.0))
    }

    pub fn append(&mut self, entry: &AuditEntry) -> Result<Head, LogError> {
        self.0.append(entry)
    }

    pub fn head(&self) -> Head {
        self.0.head()
    }
}
