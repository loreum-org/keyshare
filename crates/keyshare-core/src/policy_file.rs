//! Signed, versioned policy (policy as data).
//!
//! The owner writes the policy as TOML, gives it a `version`, and signs a short EIP-191 message
//! naming that version and the policy's content hash. The core refuses a policy that is unsigned,
//! signed by a key not on the configured signer list, edited after signing, or older than one
//! already loaded. Every audit entry then carries the [`PolicyRef`] that was active, so each
//! signature is tied to the exact policy that allowed it.
//!
//! The hash is over a canonical JSON form of the parsed TOML: object keys sorted, no whitespace,
//! integers as written. Comments, key order and formatting do not change it; any change to a
//! value does. Floats and dates are refused so there is only one way to write each value.
//!
//! This module knows nothing about module sections. The connector parses `bots.<id>.core`,
//! `bots.<id>.hyperliquid` and so on into their types after the signature checks out.

use std::fmt::Write as _;
use std::path::Path;

use alloy::primitives::{Address, B256, Signature, keccak256};
use serde::{Deserialize, Serialize};

/// Which policy was active. Carried on audit entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRef {
    pub version: u64,
    pub hash: B256,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyFileError {
    #[error("policy is not valid TOML: {0}")]
    Parse(String),
    #[error("policy needs a whole-number `version` of 1 or more")]
    MissingVersion,
    #[error("policy can't use {0} values; write amounts as integers or strings")]
    Unsupported(&'static str),
    #[error("policy is not signed: no signature file")]
    Unsigned,
    #[error("policy signature is unreadable: {0}")]
    BadSignature(String),
    #[error("policy is signed by {0}, which is not a configured policy signer")]
    WrongSigner(Address),
    #[error("no policy signers are configured")]
    NoSigners,
    #[error("policy version {got} is older than version {active}, which is already loaded")]
    Rollback { got: u64, active: u64 },
    #[error("policy version {version} was already loaded with different contents")]
    VersionReused { version: u64 },
    #[error("policy version state: {0}")]
    State(String),
}

/// Sorted-key, whitespace-free JSON for a TOML value. Floats and datetimes are refused.
pub fn canonical_json(value: &toml::Value) -> Result<String, PolicyFileError> {
    let mut out = String::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &toml::Value, out: &mut String) -> Result<(), PolicyFileError> {
    match value {
        toml::Value::String(s) => out.push_str(&serde_json::Value::String(s.clone()).to_string()),
        toml::Value::Integer(i) => {
            let _ = write!(out, "{i}");
        }
        toml::Value::Boolean(b) => out.push_str(if *b { "true" } else { "false" }),
        toml::Value::Float(_) => return Err(PolicyFileError::Unsupported("float")),
        toml::Value::Datetime(_) => return Err(PolicyFileError::Unsupported("date")),
        toml::Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        toml::Value::Table(table) => {
            let mut keys: Vec<&String> = table.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::Value::String(key.clone()).to_string());
                out.push(':');
                write_canonical(&table[key], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// The message the owner signs (EIP-191 personal message), e.g. with `cast wallet sign`.
pub fn signing_message(policy: &PolicyRef) -> String {
    format!("keyshare policy\nversion: {}\nhash: {}", policy.version, policy.hash)
}

/// A policy document parsed and hashed, not yet checked against a signature.
#[derive(Debug, Clone)]
pub struct PolicyDoc {
    pub reference: PolicyRef,
    pub table: toml::Table,
}

impl PolicyDoc {
    pub fn parse(text: &str) -> Result<Self, PolicyFileError> {
        let table: toml::Table = toml::from_str(text).map_err(|e| PolicyFileError::Parse(e.to_string()))?;
        let version = match table.get("version") {
            Some(toml::Value::Integer(v)) if *v >= 1 => *v as u64,
            _ => return Err(PolicyFileError::MissingVersion),
        };
        let json = canonical_json(&toml::Value::Table(table.clone()))?;
        Ok(Self { reference: PolicyRef { version, hash: keccak256(json.as_bytes()) }, table })
    }

    pub fn signing_message(&self) -> String {
        signing_message(&self.reference)
    }

    /// Checks `signature` (hex, as `cast wallet sign` prints it) and returns the signer.
    pub fn verify(&self, signature: Option<&str>, signers: &[Address]) -> Result<Address, PolicyFileError> {
        if signers.is_empty() {
            return Err(PolicyFileError::NoSigners);
        }
        let raw = signature.map(str::trim).filter(|s| !s.is_empty()).ok_or(PolicyFileError::Unsigned)?;
        let sig: Signature =
            raw.parse().map_err(|e: alloy::primitives::SignatureError| PolicyFileError::BadSignature(e.to_string()))?;
        let who = sig
            .recover_address_from_msg(self.signing_message().as_bytes())
            .map_err(|e| PolicyFileError::BadSignature(e.to_string()))?;
        if signers.contains(&who) { Ok(who) } else { Err(PolicyFileError::WrongSigner(who)) }
    }
}

/// The newest policy this server has accepted, kept so an older signed policy can't be loaded
/// again. Lives in the state directory, next to the spend log.
pub struct VersionGate {
    path: std::path::PathBuf,
}

impl VersionGate {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self { path: path.as_ref().to_path_buf() }
    }

    pub fn current(&self) -> Result<Option<PolicyRef>, PolicyFileError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|e| PolicyFileError::State(e.to_string())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(PolicyFileError::State(e.to_string())),
        }
    }

    /// Refuses a lower version, or the same version with other contents. A rollback is the old
    /// contents signed again under a new, higher version number.
    pub fn check(&self, next: &PolicyRef) -> Result<(), PolicyFileError> {
        match self.current()? {
            Some(active) if next.version < active.version => {
                Err(PolicyFileError::Rollback { got: next.version, active: active.version })
            }
            Some(active) if next.version == active.version && next.hash != active.hash => {
                Err(PolicyFileError::VersionReused { version: next.version })
            }
            _ => Ok(()),
        }
    }

    /// Records `next` as the newest accepted policy. Call after [`VersionGate::check`].
    pub fn record(&self, next: &PolicyRef) -> Result<(), PolicyFileError> {
        let state = |e: std::io::Error| PolicyFileError::State(e.to_string());
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(state)?;
        }
        let tmp = self.path.with_extension("tmp");
        let bytes = serde_json::to_vec(next).map_err(|e| PolicyFileError::State(e.to_string()))?;
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp).map_err(state)?;
            f.write_all(&bytes).map_err(state)?;
            f.sync_all().map_err(state)?;
        }
        std::fs::rename(&tmp, &self.path).map_err(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::signers::SignerSync;
    use alloy::signers::local::PrivateKeySigner;

    const DOC: &str = r#"
        version = 2
        # comment
        [bots.a.core]
        chains = [11155111]
        per_tx_cap_usd = 200
    "#;

    fn sign(doc: &PolicyDoc, key: &PrivateKeySigner) -> String {
        key.sign_message_sync(doc.signing_message().as_bytes()).unwrap().to_string()
    }

    #[test]
    fn hash_ignores_formatting_but_not_values() {
        let a = PolicyDoc::parse(DOC).unwrap();
        let b = PolicyDoc::parse("version=2\n[bots.a.core]\nper_tx_cap_usd=200\nchains=[11155111]").unwrap();
        assert_eq!(a.reference, b.reference);
        let c = PolicyDoc::parse("version=2\n[bots.a.core]\nper_tx_cap_usd=201\nchains=[11155111]").unwrap();
        assert_ne!(a.reference.hash, c.reference.hash);
        assert_eq!(
            canonical_json(&toml::Value::Table(a.table)).unwrap(),
            r#"{"bots":{"a":{"core":{"chains":[11155111],"per_tx_cap_usd":200}}},"version":2}"#
        );
    }

    #[test]
    fn floats_and_bad_versions_are_refused() {
        assert_eq!(PolicyDoc::parse("version = 1\nx = 1.5").unwrap_err(), PolicyFileError::Unsupported("float"));
        assert_eq!(PolicyDoc::parse("version = 0").unwrap_err(), PolicyFileError::MissingVersion);
        assert_eq!(PolicyDoc::parse("version = \"1\"").unwrap_err(), PolicyFileError::MissingVersion);
    }

    #[test]
    fn unsigned_tampered_and_wrong_key_are_refused() {
        let owner = PrivateKeySigner::random();
        let doc = PolicyDoc::parse(DOC).unwrap();
        let sig = sign(&doc, &owner);
        assert_eq!(doc.verify(Some(&sig), &[owner.address()]).unwrap(), owner.address());
        assert_eq!(doc.verify(None, &[owner.address()]).unwrap_err(), PolicyFileError::Unsigned);
        assert_eq!(doc.verify(Some(&sig), &[]).unwrap_err(), PolicyFileError::NoSigners);

        let tampered = PolicyDoc::parse(&DOC.replace("200", "900")).unwrap();
        assert!(matches!(tampered.verify(Some(&sig), &[owner.address()]), Err(PolicyFileError::WrongSigner(_))));

        let stranger = PrivateKeySigner::random();
        let err = doc.verify(Some(&sign(&doc, &stranger)), &[owner.address()]).unwrap_err();
        assert_eq!(err, PolicyFileError::WrongSigner(stranger.address()));
        assert!(matches!(doc.verify(Some("0x12"), &[owner.address()]), Err(PolicyFileError::BadSignature(_))));
    }

    #[test]
    fn older_versions_and_reused_versions_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let gate = VersionGate::new(dir.path().join("policy.state.json"));
        let v2 = PolicyDoc::parse(DOC).unwrap().reference;
        gate.check(&v2).unwrap();
        gate.record(&v2).unwrap();
        gate.check(&v2).unwrap(); // reloading the same policy is fine

        let v1 = PolicyDoc::parse(&DOC.replace("version = 2", "version = 1")).unwrap().reference;
        assert_eq!(gate.check(&v1).unwrap_err(), PolicyFileError::Rollback { got: 1, active: 2 });

        let other_v2 = PolicyDoc::parse(&DOC.replace("200", "300")).unwrap().reference;
        assert_eq!(gate.check(&other_v2).unwrap_err(), PolicyFileError::VersionReused { version: 2 });

        let v3 = PolicyDoc::parse(&DOC.replace("version = 2", "version = 3")).unwrap().reference;
        gate.check(&v3).unwrap();
        gate.record(&v3).unwrap();
        assert_eq!(gate.current().unwrap(), Some(v3));
    }
}
