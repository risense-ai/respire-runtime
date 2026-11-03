//! Platform scanner registry.
//!
//! Each module exposes `pub fn platforms() -> Vec<PlatformDef>` (see
//! [`common`]). The registry flattens them into the trait-object list the CLI
//! drives, in a stable order that matches `extract --targets`.

pub mod aside;
pub mod claude;
pub mod codex;
pub mod common;
pub mod file_platforms;
pub mod kiro;
pub mod opencode;
pub mod optional_platforms;
pub mod pi_family;
pub mod sqlite_platforms;

use crate::session_import::SessionScanner;

use common::FnScanner;

/// All supported scanners as trait objects.
pub fn registry() -> Vec<Box<dyn SessionScanner>> {
    let mut defs = Vec::new();
    defs.extend(codex::platforms());
    defs.extend(opencode::platforms());
    defs.extend(claude::platforms());
    defs.extend(file_platforms::platforms());
    defs.extend(sqlite_platforms::platforms());
    defs.extend(optional_platforms::platforms());
    defs.extend(pi_family::platforms());
    defs.extend(aside::platforms());
    defs.extend(kiro::platforms());
    defs.into_iter()
        .map(|def| Box::new(FnScanner::new(def)) as Box<dyn SessionScanner>)
        .collect()
}

/// Normalize a user-supplied platform alias to a canonical id.
pub fn normalize_alias(id: &str) -> String {
    let normalized = id.trim().to_lowercase();
    match normalized.as_str() {
        "cursor" => "cursor-cli",
        "factory" => "droid",
        "roo" | "roocode" => "roo-code",
        "kilocode" => "kilo-code",
        "kilo" => "kilo-cli",
        "omp" | "ohmypi" | "oh_my_pi" => "oh-my-pi",
        "gjc" | "gajae" | "gajaecode" => "gajae-code",
        "aside-browser" => "aside",
        other => other,
    }
    .to_owned()
}
