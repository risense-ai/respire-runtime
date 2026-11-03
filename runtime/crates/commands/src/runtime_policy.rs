//! A sandbox is an HTTP client; only the host owns runtime lifecycle.

use std::sync::OnceLock;

use anyhow::{bail, Result};

pub fn client_only() -> bool {
    if ["RSRS_CLIENT_ONLY", "RSRS_NO_AUTOSTART"]
        .iter()
        .any(|name| {
            respire_app::env::var(name).is_ok_and(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "on" | "yes"
                )
            })
        })
    {
        return true;
    }
    static RESTRICTED: OnceLock<bool> = OnceLock::new();
    *RESTRICTED.get_or_init(|| match respire_spawn::is_restricted() {
        Ok(restricted) => restricted,
        Err(error) => {
            eprintln!("cannot inspect process confinement; using client-only mode: {error}");
            true
        }
    })
}

pub fn require_host(action: &str) -> Result<()> {
    if client_only() {
        bail!("client_only: {action} is host-managed; connect to the host loopback HTTP runtime. Start or update rsrs from the host terminal, outside the sandbox");
    }
    Ok(())
}

pub fn takeover_lock() -> Result<respire_app::lock::LibraryLock> {
    require_host("runtime lifecycle")?;
    respire_app::lock::LibraryLock::acquire(
        &crate::rpc_worker::runtime_dir_path().join("takeover"),
        std::time::Duration::from_secs(60),
    )
}

/// Background commits must yield to a lifecycle owner that is draining them,
/// rather than wait for that owner's lock and deadlock the drain.
pub fn try_takeover_lock() -> Result<respire_app::lock::LibraryLock> {
    require_host("background diary cache commit")?;
    respire_app::lock::LibraryLock::acquire(
        &crate::rpc_worker::runtime_dir_path().join("takeover"),
        std::time::Duration::ZERO,
    )
}
