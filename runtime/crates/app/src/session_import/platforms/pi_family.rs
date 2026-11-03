//! pi-family scanners: Senpi, oh-my-pi (omp) and gajae-code (gjc).
//!
//! Ported from the reference finder's `agent_sessions/pi_family.py`. All three
//! platforms share one on-disk layout — `<config>/agent/sessions/**/*.jsonl` —
//! so a single parameterized scanner serves each under its own platform id.

use std::path::{Path, PathBuf};

use super::common::{self, PlatformDef};
use crate::session_import::{scan_util, ScanOptions, Session};

/// Directory levels walked below `<root>/sessions` (reference uses `rglob`).
const SESSIONS_DEPTH: usize = 12;

/// pi-family scanner definitions (`senpi`, `oh-my-pi`, `gajae-code`).
pub fn platforms() -> Vec<PlatformDef> {
    vec![
        PlatformDef {
            id: "senpi",
            name: "Senpi",
            roots: roots_senpi,
            scan: scan_senpi,
        },
        PlatformDef {
            id: "oh-my-pi",
            name: "oh-my-pi",
            roots: roots_oh_my_pi,
            scan: scan_oh_my_pi,
        },
        PlatformDef {
            id: "gajae-code",
            name: "gajae-code",
            roots: roots_gajae_code,
            scan: scan_gajae_code,
        },
    ]
}

fn roots_senpi() -> Vec<PathBuf> {
    family_roots(&[".senpi", ".pi"], "senpi", &[])
}

fn roots_oh_my_pi() -> Vec<PathBuf> {
    family_roots(&[".omp"], "omp", &["PI_CONFIG_DIR", "PI_CODING_AGENT_DIR"])
}

fn roots_gajae_code() -> Vec<PathBuf> {
    family_roots(&[".gjc"], "gjc", &["PI_CONFIG_DIR", "PI_CODING_AGENT_DIR"])
}

fn scan_senpi(opts: &ScanOptions) -> Vec<Session> {
    scan_family("senpi", &roots_senpi(), opts)
}

fn scan_oh_my_pi(opts: &ScanOptions) -> Vec<Session> {
    scan_family("oh-my-pi", &roots_oh_my_pi(), opts)
}

fn scan_gajae_code(opts: &ScanOptions) -> Vec<Session> {
    scan_family("gajae-code", &roots_gajae_code(), opts)
}

/// Collect `<root>/sessions/**/*.jsonl` for every root, keep the newest files
/// and parse each one; the fallback id is the segment after the last `_`.
fn scan_family(platform: &str, defaults: &[PathBuf], opts: &ScanOptions) -> Vec<Session> {
    let roots = common::merge_roots(defaults.to_vec(), &opts.roots);
    let mut paths = Vec::new();
    for root in &roots {
        paths.extend(scan_util::files_below(
            &root.join("sessions"),
            SESSIONS_DEPTH,
            "*.jsonl",
        ));
    }
    scan_util::recent(paths, scan_util::MAX_PLATFORM_FILES)
        .into_iter()
        .map(|path| common::jsonl_session(platform, &path, scan_util::stem_id(&path, "_")))
        .collect()
}

/// Mirrors `_pi_family_roots`: home config dirs (plus named profiles), the
/// XDG store, and any requested environment overrides.
fn family_roots(config_dirs: &[&str], xdg_app: &str, env_overrides: &[&str]) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(home) = scan_util::home() {
        for config_dir in config_dirs {
            let base = home.join(config_dir);
            roots.push(base.join("agent"));
            roots.extend(profile_agent_dirs(&base));
        }
    }
    if let Some(xdg) = scan_util::env_path("XDG_DATA_HOME") {
        let app_root = xdg.join(xdg_app);
        roots.push(app_root.clone());
        roots.extend(sorted_subdirs(&app_root.join("profiles")));
    }
    for name in env_overrides {
        if let Some(path) = scan_util::env_path(name) {
            roots.push(path.join("agent"));
            roots.push(path);
        }
    }
    scan_util::existing(roots)
}

/// `<config>/profiles/*/agent` directories, sorted (reference `sorted(glob)`).
fn profile_agent_dirs(base: &Path) -> Vec<PathBuf> {
    sorted_subdirs(&base.join("profiles"))
        .into_iter()
        .map(|profile| profile.join("agent"))
        .collect()
}

/// Immediate subdirectories of `dir`, sorted for deterministic root order.
fn sorted_subdirs(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    out.sort();
    out
}
