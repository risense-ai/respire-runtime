//! Command engine assembly: library/store/session construction shared by the
//! engine arms and the runtime worker threads.
//!
//! The command arms themselves (`run_local`) and the per-command functions
//! migrate here from the CLI binary in later steps of the runtime split.

use std::sync::Arc;

use anyhow::{anyhow, Result};

use respire_app::auth;
use respire_app::env;
use respire_app::service;
use respire_app::transport::local::LocalStore;
use respire_app::transport::remote::{RemoteConfig, RemoteTransport};
use respire_app::{MemoryTransport, SessionKeys};


pub fn build_transport() -> Result<Arc<dyn MemoryTransport>> {
            address: addr,
            token,
        })));
    }
    Ok(Arc::new(respire_app::service::open_store()?))
}

pub fn build_local() -> Result<LocalStore> {
    respire_app::service::open_store()
}

/// Remote config: session.json first (addr/token written by client login), then env vars.
pub fn remote_config_from_session_or_env() -> Result<Option<(String, String)>> {
    // 1) session.json
    if let Ok(data) = read_session_json() {
        if let (Some(addr), Some(token)) = (
            data["addr"].as_str().filter(|s| !s.is_empty()),
            data["token"].as_str().filter(|s| !s.is_empty()),
        ) {
            return Ok(Some((addr.to_owned(), token.to_owned())));
        }
    }
    // 2) env vars
    if let Ok(addr) = respire_app::env::var("RSRS_ADDR") {
        if !addr.trim().is_empty() {
            let token = respire_app::env::var("RSRS_TOKEN")
                .map_err(|_| anyhow!("remote mode needs RSRS_TOKEN"))?;
            return Ok(Some((addr, token)));
        }
    }
    Ok(None)
}

pub fn build_remote() -> Result<RemoteTransport> {
    let (addr, token) = remote_config_from_session_or_env()?
        .ok_or_else(|| anyhow!("remote store is not configured - have the client/account tool write session.json (addr/token), or set RSRS_ADDR and RSRS_TOKEN"))?;
    Ok(RemoteTransport::new(RemoteConfig {
        address: addr,
        token,
    }))
}

/// Unlock session keys: local keyfile first (from keygen/register), else env vars.
pub fn build_session() -> Result<SessionKeys> {
    build_session_with_owner().map(|(keys, _)| keys)
}

/// Preserve only the owner alias from the local snapshot that supplied these keys.
/// Environment-key fallback must never inherit identity from an unrelated profile.
pub fn build_session_with_owner() -> Result<(SessionKeys, Option<String>)> {
    let result = build_session_with_owner_inner();
    crate::host_hooks::note_credential_access(result.is_ok());
    result
}

pub fn build_session_with_owner_inner() -> Result<(SessionKeys, Option<String>)> {
    if let Ok(session) = auth::load_local_session_with_owner() {
        return Ok(session);
    }
    if read_session_json().is_err() {
        // no local session -> first-run guide
        anyhow::bail!(
            "no local session: rsrs keygen --pass <password> to start fully local (no cloud); \
             or rsrs register / login for a cloud identity; or set the five-keys env vars \
             (RSRS_PASS/SECRET/KDF_SALT/WRAPPED_URK/URK_NONCE)"
        );
    }
    let password = respire_app::env::var("RSRS_PASS")
        .map_err(|_| anyhow!("need RSRS_PASS (master password)"))?;
    let secret = respire_app::env::var("RSRS_SECRET")
        .map_err(|_| anyhow!("need RSRS_SECRET (recovery key)"))?;
    let kdf_salt = respire_app::env::var("RSRS_KDF_SALT")
        .map_err(|_| anyhow!("need RSRS_KDF_SALT (from keygen/register)"))?;
    let wrapped_urk = respire_app::env::var("RSRS_WRAPPED_URK")
        .map_err(|_| anyhow!("need RSRS_WRAPPED_URK (from keygen/login)"))?;
    let urk_nonce = respire_app::env::var("RSRS_URK_NONCE")
        .map_err(|_| anyhow!("need RSRS_URK_NONCE (from keygen/login)"))?;
    Ok((SessionKeys::unlock(&password, &secret, &kdf_salt, &wrapped_urk, &urk_nonce)?, None))
}

pub fn read_session_json() -> Result<serde_json::Value> {
    auth::read_session_json()
}
