//! Canonical environment names with read-only compatibility for previous clients.
use std::{env::VarError, ffi::OsString};

pub fn var_os(name: &str) -> Option<OsString> {
    std::env::var_os(name).or_else(|| {
        let suffix = name.strip_prefix("RSRS_")?;
        std::env::var_os(format!("ONEMEMORY_{suffix}"))
            .or_else(|| std::env::var_os(format!("RESPIRE_{suffix}")))
    })
}

pub fn var(name: &str) -> Result<String, VarError> {
    match var_os(name) {
        Some(value) => value.into_string().map_err(VarError::NotUnicode),
        None => Err(VarError::NotPresent),
    }
}

/// Filter candidates: trim, drop empty, take the first non-empty (an env var set to empty is also dropped —
/// the old impl did not filter, COMPUTERNAME="" became an empty hostname; fixed 2026-09-20)
fn first_non_empty<I: IntoIterator<Item = String>>(vals: I) -> Option<String> {
    vals.into_iter()
        .map(|s| s.trim().to_owned())
        .find(|s| !s.is_empty())
}

/// Hostname. Four-tier order: /etc/hostname (Linux authoritative static name) → COMPUTERNAME (Windows)
/// → HOSTNAME (env, only on a login shell) → syscall gethostname (fallback).
/// Fourth tier added 2026-09-20: macOS has no /etc/hostname, and a GUI-launched process does not inherit
/// HOSTNAME (launchd does not set it); without the syscall the first tiers all missed and became unknown-host —
/// a user screenshot showed mac as unknown-host/mac when HOSTNAME/COMPUTERNAME were unset.
pub fn host_name() -> Option<String> {
    first_non_empty([
        std::fs::read_to_string("/etc/hostname").unwrap_or_default(),
        var("COMPUTERNAME").unwrap_or_default(),
        var("HOSTNAME").unwrap_or_default(),
        whoami::hostname().unwrap_or_default(),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    /// Empty-value filter: env set to empty/whitespace must be dropped (old impl did not filter, empty hostname)
    #[test]
    fn first_non_empty_skips_blank() {
        assert_eq!(
            first_non_empty(["".to_owned(), "  ".to_owned(), "real".to_owned()]),
            Some("real".to_owned())
        );
        assert_eq!(
            first_non_empty(["  padded  ".to_owned()]),
            Some("padded".to_owned())
        );
        assert_eq!(first_non_empty([String::new()]), None);
        assert_eq!(first_non_empty(Vec::<String>::new()), None);
    }

    /// Syscall fallback: simulate mac — no /etc/hostname, no HOSTNAME/COMPUTERNAME,
    /// when earlier tiers are blank gethostname must supply the name (dropping the whoami tier fails)
    #[test]
    fn syscall_fallback_used_when_earlier_tiers_blank() -> anyhow::Result<()> {
        let syscall = whoami::hostname().map_err(|e| anyhow!("hostname: {e}"))?;
        let host = first_non_empty(["".to_owned(), "".to_owned(), "".to_owned(), syscall.clone()]);
        assert_eq!(
            host.as_deref(),
            Some(syscall.as_str()),
            "syscall tier unused when first three tiers are blank"
        );
        assert!(!host
            .ok_or_else(|| anyhow!("missing host"))?
            .trim()
            .is_empty());
        Ok(())
    }

}
