//! The module boundary (docs/modules.md): only the connector may reach key material.
//!
//! - No workspace crate except `keyshare-mcp` depends on `keyshare-signer`, in any dependency kind.
//! - No workspace crate except `keyshare-signer` turns on alloy's `signer-local` feature as a normal
//!   dependency, so a module built on its own cannot name a private-key type. Test-only
//!   (`[dev-dependencies]`) use is allowed.
//!
//! CI also builds the core and the module crates on their own (`cargo check -p ...`), which fails
//! if one of them names a key type that only exists when `keyshare-signer` is in the build.
#![allow(clippy::unwrap_used)]

use serde_json::Value;

const SIGNER: &str = "keyshare-signer";
const CONNECTOR: &str = "keyshare-mcp";

fn metadata() -> Value {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = std::process::Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--no-deps", "--offline"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run cargo metadata");
    assert!(out.status.success(), "cargo metadata failed: {}", String::from_utf8_lossy(&out.stderr));
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn only_the_connector_depends_on_the_signer_crate() {
    let meta = metadata();
    let packages = meta["packages"].as_array().unwrap();
    assert!(packages.iter().any(|p| p["name"] == CONNECTOR), "workspace has no {CONNECTOR}");
    for package in packages {
        let name = package["name"].as_str().unwrap();
        if name == CONNECTOR {
            continue;
        }
        for dep in package["dependencies"].as_array().unwrap() {
            assert_ne!(dep["name"], SIGNER, "{name} depends on {SIGNER}; only {CONNECTOR} may");
        }
    }
}

#[test]
fn only_the_signer_crate_builds_local_keys() {
    let meta = metadata();
    for package in meta["packages"].as_array().unwrap() {
        let name = package["name"].as_str().unwrap();
        if name == SIGNER {
            continue;
        }
        for dep in package["dependencies"].as_array().unwrap() {
            let normal = dep["kind"].is_null();
            let local = dep["features"].as_array().unwrap().iter().any(|f| f == "signer-local");
            assert!(
                !(dep["name"] == "alloy" && normal && local),
                "{name} enables alloy/signer-local; key types belong in {SIGNER}"
            );
        }
    }
}
