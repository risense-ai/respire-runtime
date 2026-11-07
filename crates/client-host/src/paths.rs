//! Shared client paths; only environment, filesystem paths and home lookup.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

/// Expand `~` (`~/` and Windows `~\` both count) — **the only impl**; do not rewrite elsewhere.
///
/// Why (2026-09-20 audit): this fn used to have three independent impls (two here + web.rs),
/// and they disagreed — inject.rs accepted `~\`, service.rs three sites only `~/`, so on Windows
/// `~\...` paths did not expand. Now collected here; every caller uses this.
pub fn expand_tilde(v: &str) -> PathBuf {
    if let Some(rest) = v.strip_prefix("~/").or_else(|| v.strip_prefix("~\\")) {
        if let Ok(h) = home_dir() {
            return h.join(rest);
        }
    }
    PathBuf::from(v)
}

/// Resolve `RSRS_DATA_DIR` to an absolute path (None if unset or empty).
/// Semantics: the env var names the profile root — the `main` profile is that root, space profiles live under its `accounts/`,
/// and client.json lives there too (an isolated instance must not write config into the real user dir).
pub fn env_root_dir() -> Option<PathBuf> {
    let v = crate::env::var("RSRS_DATA_DIR").ok()?;
    let v = v.trim();
    if v.is_empty() {
        return None;
    }
    if internally_configured_root(v) {
        return None;
    }
    Some(expand_tilde(v))
}

// Sunk from the client-side migration module (WP-2c): engine flows must classify the
// internally configured default home, and the domain crate cannot reach back into the
// client crate. The client migration module re-imports this function.
const DEFAULT_ENV: &str = "RSRS_DEFAULT_DATA_DIR";

/// The SDK accepts the original data-root environment variable. This marker lets
/// app configuration retain its default-home and active-profile semantics.
pub fn internally_configured_root(value: &str) -> bool {
    crate::env::var(DEFAULT_ENV).ok().is_some_and(|marker| {
        equivalent_path(
            &expand_tilde(&marker),
            &expand_tilde(value),
        ) && equivalent_path(
            &expand_tilde(value),
            &default_data_dir(),
        )
    })
}

fn equivalent_path(left: &Path, right: &Path) -> bool {
    let absolute = |path: &Path| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|root| root.join(path))
                .unwrap_or_else(|_| path.to_path_buf())
        }
    };
    let normalize = |path: PathBuf| {
        let mut normalized = PathBuf::new();
        for component in path.components() {
            match component {
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    normalized.pop();
                }
                _ => normalized.push(component.as_os_str()),
            }
        }
        normalized
    };
    let left = normalize(absolute(left));
    let right = normalize(absolute(right));
    if cfg!(windows) {
        left.to_string_lossy()
            .replace('/', "\\")
            .eq_ignore_ascii_case(&right.to_string_lossy().replace('/', "\\"))
    } else {
        left == right
    }
}

pub fn default_data_dir() -> PathBuf {
    home_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".rsrs")
}

/// Main profile root: `RSRS_DATA_DIR` when isolated, otherwise `~/.rsrs`.
/// Returning to main must retain this override, not use the default home directly.
pub fn main_data_dir() -> PathBuf {
    env_root_dir().unwrap_or_else(default_data_dir)
}

/// Component binary directory, preserving the explicit host override.
pub fn bin_dir() -> PathBuf {
    if let Ok(raw) = crate::env::var("RSRS_BIN_DIR") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    main_data_dir().join("bin")
}

/// Device configuration stays in the installation root, not the active account.
pub fn client_config_path() -> PathBuf {
    if let Some(root) = env_root_dir() {
        return root.join("client.json");
    }
    home_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".rsrs")
        .join("client.json")
}

/// Preserve account selection within an explicit installation root.
pub fn data_dir_from_config(config: Option<&serde_json::Value>) -> PathBuf {
    let env_root = env_root_dir();
    let from_config = config
        .and_then(|d| {
            d["data_dir"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
        })
        .map(|v| expand_tilde(&v));
    match (env_root, from_config) {
        (Some(root), Some(cfg)) if cfg.starts_with(&root) => cfg,
        (Some(root), _) => root,
        (None, Some(cfg)) => cfg,
        (None, None) => default_data_dir(),
    }
}

/// Legacy token lookup retains the service's permissive config-read behavior.
pub fn legacy_token_data_dir() -> PathBuf {
    let config = std::fs::read_to_string(client_config_path())
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok());
    data_dir_from_config(config.as_ref())
}

pub fn home_dir() -> Result<PathBuf> {
    if let Ok(home) = crate::env::var("HOME") {
        if !home.trim().is_empty() {
            return Ok(PathBuf::from(home));
        }
    }
    dirs::home_dir().ok_or_else(|| anyhow!("cannot determine home directory"))
}

/// Configure the current home before parsing. Legacy import is always explicit.
pub fn ensure_default_home() -> Result<()> {
    if ["RSRS_CLIENT_ONLY", "RSRS_NO_AUTOSTART"]
        .iter()
        .any(|name| {
            crate::env::var(name).ok().is_some_and(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "on" | "yes"
                )
            })
        })
    {
        return Ok(());
    }
    if let Ok(value) = crate::env::var("RSRS_DATA_DIR") {
        if !value.trim().is_empty() && !internally_configured_root(value.trim()) {
            return Ok(());
        }
    }
    let home = home_dir().context("cannot locate the user home")?;
    let root = home.join(".rsrs");
    // Set both markers before starting any independent Runtime child.
    std::env::set_var("RSRS_DATA_DIR", &root);
    std::env::set_var(DEFAULT_ENV, &root);
    Ok(())
}
