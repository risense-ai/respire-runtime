//! Pins the CLI version string for shared clap help and version output.
//!
//! The rsrs binary reports its own package version through `--version`, `v`,
//! `version` and doctor. This crate keeps its own independent version, so the
//! CLI manifest version is read here at build time and exposed to the crate
//! as `RSRS_CLI_VERSION` (see `app_version`).

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=../../Cargo.toml");
    let manifest_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    let manifest = match std::fs::read_to_string(&manifest_path) {
        Ok(manifest) => manifest,
        Err(error) => panic!(
            "respire_commands build: cannot read the CLI manifest {}: {error}",
            manifest_path.display()
        ),
    };
    let version = match workspace_package_version(&manifest) {
        Some(version) => version,
        None => panic!(
            "respire_commands build: no [package] version found in {}",
            manifest_path.display()
        ),
    };
    println!("cargo:rustc-env=RSRS_CLI_VERSION={version}");
}

/// Read `[workspace.package] version` from the runtime workspace manifest.
fn workspace_package_version(manifest: &str) -> Option<String> {
    let mut in_package = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
        in_package = line == "[workspace.package]";
            continue;
        }
        if !in_package {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            if key.trim() == "version" {
                return Some(value.trim().trim_matches('"').to_owned());
            }
        }
    }
    None
}
