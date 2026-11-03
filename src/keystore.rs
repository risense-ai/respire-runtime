//! keystore — super-password (v4 single-factor key) storage.
//!
//! Read priority: explicit nonempty RSRS_SUPER, then native credentials.
//! Native priority: persistent Secret Service on Linux, then its volatile kernel
//! store; Keychain/Credential Manager elsewhere.
//! > none. Plaintext is never written to session.json from v4 on — a disk copy cannot decrypt.
//! Headless servers (no keyring) use RSRS_SUPER or pass --super each time.

use anyhow::{anyhow, Context, Result};

const SERVICE: &str = "rsrs";
const VAULT_SERVICE: &str = "rsrs";

#[derive(Clone, Copy)]
enum Backend {
    #[cfg(any(not(target_os = "linux"), test))]
    Native,
    #[cfg(all(target_os = "linux", not(test)))]
    SecretService,
    #[cfg(all(target_os = "linux", not(test)))]
    Kernel,
}

impl Backend {
    fn name(self) -> &'static str {
        match self {
            #[cfg(any(not(target_os = "linux"), test))]
            Self::Native => "native",
            #[cfg(all(target_os = "linux", not(test)))]
            Self::SecretService => "secret_service",
            #[cfg(all(target_os = "linux", not(test)))]
            Self::Kernel => "kernel",
        }
    }
}

fn backends() -> &'static [Backend] {
    #[cfg(all(target_os = "linux", not(test)))]
    {
        &[Backend::SecretService, Backend::Kernel]
    }
    #[cfg(any(not(target_os = "linux"), test))]
    {
        &[Backend::Native]
    }
}

fn credential_entry(service: &str, label: &str, backend: Backend) -> Result<keyring::Entry> {
    match backend {
        #[cfg(any(not(target_os = "linux"), test))]
        Backend::Native => keyring::Entry::new(service, label)
            .map_err(|_| anyhow!("keyring initialization failed")),
        #[cfg(all(target_os = "linux", not(test)))]
        Backend::SecretService => keyring::secret_service::default_credential_builder()
            .build(None, service, label)
            .map(keyring::Entry::new_with_credential)
            .map_err(|_| anyhow!("Secret Service initialization failed")),
        #[cfg(all(target_os = "linux", not(test)))]
        Backend::Kernel => keyring::keyutils::default_credential_builder()
            .build(None, service, label)
            .map(keyring::Entry::new_with_credential)
            .map_err(|_| anyhow!("kernel keyring initialization failed")),
    }
}

/// Read every applicable legacy backend without writing or self-healing it.
pub(crate) fn read_credentials(service: &str, label: &str) -> Vec<String> {
    let mut values = Vec::new();
    for backend in backends() {
        if let Ok(entry) = credential_entry(service, label, *backend) {
            if let Ok(value) = entry.get_password() {
                if !value.is_empty() && !values.contains(&value) {
                    values.push(value);
                }
            }
        }
    }
    values
}

fn save_label(label: &str, value: &str) -> Result<()> {
    for backend in backends() {
        let entry = credential_entry(SERVICE, label, *backend)?;
        if entry.set_password(value).is_ok() {
            if backend.name() == "kernel" {
                eprintln!("warning: Linux credentials are in the volatile kernel keyring; enabling Secret Service alone does not preserve existing keys across reboot; restore or re-import them into the persistent store");
            }
            return Ok(());
        }
    }
    Err(anyhow!(
        "keyring write failed; no available credential backend"
    ))
}

fn delete_label(label: &str) {
    for backend in backends() {
        let result = credential_entry(SERVICE, label, *backend).and_then(|entry| {
            match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(_) => Err(anyhow!("keyring deletion failed")),
            }
        });
        if result.is_err() {
            eprintln!(
                "warning: {} credential could not be deleted; clear the rsrs entry in that store",
                backend.name()
            );
        }
    }
}

fn credential_account(user: &str) -> String {
    let account = if user.trim().is_empty() {
        "local"
    } else {
        user.trim()
    };
    if let Ok(session) = crate::auth::read_session_json() {
        let session_user = session["user"].as_str().unwrap_or("");
        let session_user = if session_user.trim().is_empty() {
            "local"
        } else {
            session_user.trim()
        };
        if session_user == account {
            if let Some(alias) = session["keyring_account"].as_str().filter(|alias| {
                (alias.starts_with("legacy-") || alias.starts_with("login-"))
                    && alias
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
            }) {
                return alias.to_owned();
            }
        }
    }
    account.to_owned()
}

/// Import into a separate namespace. Existing credentials are never overwritten.
pub(crate) fn import_credential(account: &str, slot: &str, value: &str) -> Result<&'static str> {
    import_credential_checkpoint(account, slot, value, |_| Ok(()))
}

/// Record the selected backend before a credential can be created.
pub(crate) fn import_credential_checkpoint(account: &str, slot: &str, value: &str, mut checkpoint: impl FnMut(&str) -> Result<()>) -> Result<&'static str> {
    let label = format!("{slot}:{account}");
    if read_credentials(VAULT_SERVICE, &label)
        .iter()
        .any(|existing| existing != value)
    {
        return Err(anyhow!(
            "migration keyring destination contains a different credential"
        ));
    }
    for backend in backends() {
        let entry = credential_entry(VAULT_SERVICE, &label, *backend)?;
        let mut created = false;
        match entry.get_password() {
            Ok(existing) if existing != value => {
                return Err(anyhow!(
                    "migration keyring destination contains a different credential"
                ))
            }
            Ok(_) => {}
            Err(keyring::Error::NoEntry) => {
                checkpoint(backend.name())?;
                if entry.set_password(value).is_err() {
                    continue;
                }
                created = true;
            }
            Err(keyring::Error::Ambiguous(_))
            | Err(keyring::Error::BadEncoding(_))
            | Err(keyring::Error::Invalid(_, _)) => {
                return Err(anyhow!("migration keyring destination is ambiguous or invalid; original credentials were preserved"));
            }
            Err(_) => continue,
        }
        let readback = credential_entry(VAULT_SERVICE, &label, *backend)
            .and_then(|entry| entry.get_password().map_err(Into::into));
        match readback {
            Ok(found) if found == value => {
                if backend.name() == "kernel" {
                    eprintln!("warning: migrated credentials use the volatile Linux kernel keyring; original keys were preserved; restore or re-import them into an available Secret Service store for reboot-safe storage");
                }
                return Ok(backend.name());
            }
            Ok(_) => {
                if created {
                    entry.delete_credential().context("remove new credential after readback mismatch")?;
                }
                return Err(anyhow!("migration keyring readback mismatch"));
            },
            Err(_) => {
                if created {
                    match entry.delete_credential() {
                        Ok(()) | Err(keyring::Error::NoEntry) => {},
                        Err(error) => return Err(anyhow!("credential readback failed and its new entry could not be removed: {error}")),
                    }
                }
                continue;
            },
        }
    }
    Err(anyhow!(
        "migration keyring write/readback failed; no snapshot was published"
    ))
}

/// Remove only the entry created by this login when its transaction rolls back.
pub(crate) fn remove_imported(account: &str, slot: &str, backend_name: &str) -> Result<()> {
    let backend = backends().iter().find(|backend| backend.name() == backend_name)
        .ok_or_else(|| anyhow!("credential backend is unavailable during login rollback"))?;
    let entry = credential_entry(VAULT_SERVICE, &format!("{slot}:{account}"), *backend)?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(anyhow!("login credential rollback failed: {error}")),
    }
}

/// Classification settings are global per endpoint, unlike per-library vaults.
/// Preserve an existing new setting; import known legacy slots into new entries.
pub(crate) fn import_classification(services: &[&str]) -> Result<()> {
    let mut slots = vec![
        "typesafe".to_owned(),
        "ds".to_owned(),
        "last-backend".to_owned(),
        "ds-last-base".to_owned(),
    ];
    for service in services {
        for base in read_credentials(service, "classify:ds-last-base") {
            let host = host_of(&base);
            if !host.is_empty() {
                slots.push(format!("ds@{host}"));
                slots.push(format!("ds-model@{host}"));
            }
        }
    }
    slots.sort();
    slots.dedup();
    for slot in slots {
        if !read_credentials(SERVICE, &format!("classify:{slot}")).is_empty() {
            continue;
        }
        for service in services {
            if let Some(value) = read_credentials(service, &format!("classify:{slot}")).first() {
                import_credential(&slot, "classify", value)?;
                break;
            }
        }
    }
    Ok(())
}

/// Save the super password into the OS keyring. Headless with no keyring returns Err
/// (caller warns and falls back to the env var).
pub fn save_super(user: &str, super_pass: &str) -> Result<()> {
    save_label(&format!("super:{}", credential_account(user)), super_pass)
}

/// Save the server login password next to the super password.
/// The web client reads it back so a later open does not ask again.
/// Plaintext still never goes into session.json.
pub fn save_login_pass(user: &str, pass: &str) -> Result<()> {
    if pass.is_empty() {
        return Ok(());
    }
    save_label(&format!("pass:{}", credential_account(user)), pass)
}

/// Load the server login password from the OS keyring. None if the slot is missing.
pub fn load_login_pass(user: &str) -> Option<String> {
    read_credentials(SERVICE, &format!("pass:{}", credential_account(user)))
        .into_iter()
        .next()
}

/// Delete the stored login password (logout --full).
pub fn delete_login_pass(user: &str) {
    delete_label(&format!("pass:{}", credential_account(user)));
}

/// Load super password: explicit nonempty RSRS_SUPER → OS keyring → None.
/// Headless login supplies its verified key through the environment; an old
/// credential for the same user must not replace that explicitly selected key.
pub fn load_super(user: &str) -> Option<String> {
    crate::env::var("RSRS_SUPER").ok().filter(|s| !s.is_empty()).or_else(|| {
        read_credentials(SERVICE, &format!("super:{}", credential_account(user)))
            .into_iter()
            .next()
    })
}

/// Delete the super password from the keyring (logout --full / post-reset cleanup).
///
/// Failures must be reported (L8, 2026-09-20 audit): a silent failure makes the user
/// think the key is gone while the keyring still holds a code that unlocks all memories.
pub fn delete_super(user: &str) {
    delete_label(&format!("super:{}", credential_account(user)));
}

// ───────────────────── classify (classification backend) API key ─────────────────────

/// classify backend slot (separate account under the same OS keyring service).
/// DS backends are keyed by **endpoint host** — official deepseek.com and b.ai relay keys
/// are not interchangeable; sharing one slot overwrites the other (hit 2026-09-20).
/// Host from an endpoint URL, used as the DS key-slot suffix (e.g. api.deepseek.com / api.b.ai).
pub fn host_of(base: &str) -> String {
    let b = base.trim();
    let rest = b.split_once("://").map(|(_, r)| r).unwrap_or(b);
    rest.split(['/', '?', '#'])
        .next()
        .unwrap_or(rest)
        .to_owned()
}

#[cfg(test)]
mod host_tests {
    use super::*;

    #[test]
    fn host_of_strips_scheme_and_path() {
        assert_eq!(host_of("https://api.deepseek.com/v1"), "api.deepseek.com");
        assert_eq!(host_of("api.b.ai/chat"), "api.b.ai");
        assert_eq!(host_of("  https://x.test/a?b=1#c  "), "x.test");
    }

    #[test]
    fn load_super_falls_back_to_env() {
        let _guard = crate::test_lock::guard();
        let saved = crate::env::var("RSRS_SUPER").ok();
        std::env::set_var("RSRS_SUPER", "env-super");
        let got = load_super("no-such-user-zzzz");
        assert_eq!(got.as_deref(), Some("env-super"));
        match saved {
            Some(v) => std::env::set_var("RSRS_SUPER", v),
            None => std::env::remove_var("RSRS_SUPER"),
        }
    }
}

/// Save a classify backend key (backend ∈ "ds" | "typesafe").
pub fn save_classify_key(backend: &str, key: &str) -> Result<()> {
    save_label(&format!("classify:{backend}"), key)
}

/// Load a classify backend key: OS keyring → env (DS_API_KEY / TYPESAFE_API_KEY) → None.
pub fn load_classify_key(backend: &str) -> Option<String> {
    let from_ring = read_credentials(SERVICE, &format!("classify:{backend}"))
        .into_iter()
        .next();
    from_ring.or_else(|| {
        let var = if backend.starts_with("ds") {
            "DS_API_KEY"
        } else {
            "TYPESAFE_API_KEY"
        };
        crate::env::var(var).ok().filter(|s| !s.is_empty())
    })
}

/// Remember the last DS endpoint used (including path, e.g. https://api.b.ai/v1)
/// so a stored key is not paired with a host that dropped the path.
pub fn save_ds_last_base(base: &str) {
    if save_label("classify:ds-last-base", base).is_err() {
        eprintln!("warning: classification endpoint could not be saved");
    }
}

/// Load the last DS endpoint used (full base).
pub fn load_ds_last_base() -> Option<String> {
    read_credentials(SERVICE, "classify:ds-last-base")
        .into_iter()
        .next()
}

/// Remember the last model used for an endpoint (relay names differ: official deepseek-chat, b.ai deepseek-v4.1-flash).
pub fn save_ds_model(host: &str, model: &str) {
    if save_label(&format!("classify:ds-model@{host}"), model).is_err() {
        eprintln!("warning: classification model could not be saved");
    }
}

/// Load the last model used for an endpoint.
pub fn load_ds_model(host: &str) -> Option<String> {
    read_credentials(SERVICE, &format!("classify:ds-model@{host}"))
        .into_iter()
        .next()
}

/// Remember the classify backend choice (GUI "AI backend" dropdown; "jev" | "ds").
pub fn save_classify_backend(backend: &str) {
    if save_label("classify:last-backend", backend).is_err() {
        eprintln!("warning: classification backend could not be saved");
    }
}

/// Load the last classify backend (None if unset; caller picks the default).
pub fn load_classify_backend() -> Option<String> {
    read_credentials(SERVICE, "classify:last-backend")
        .into_iter()
        .next()
        .filter(|v| v == "jev" || v == "ds")
}

/// Delete a classify key from the keyring (key rotation / revoke).
pub fn delete_classify_key(backend: &str) {
    delete_label(&format!("classify:{backend}"));
}
