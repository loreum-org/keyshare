//! Append-only audit log (design §9.3). Every request is logged before it is checked, and its
//! outcome after, so a signature with no audit trail can't happen.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::chainlog::{ChainLog, Head, LogError};
use crate::policy_file::PolicyRef;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEvent {
    Requested,
    /// Held for the owner's approval.
    Held,
    Refused,
    Signed,
    /// A signed policy was accepted and is now active.
    PolicyLoaded,
    /// A policy file was refused (unsigned, wrong key, older version). The old one stays active.
    PolicyRejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub at: u64,
    pub request_id: String,
    pub caller: String,
    pub event: AuditEvent,
    pub detail: serde_json::Value,
    /// The signed policy that was active when this entry was written. Absent on entries written
    /// before policies were signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyRef>,
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
