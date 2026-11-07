//! Host provider settings in the existing rsrs/classify:* credential namespace.
//! No account credentials or arbitrary service/label access are exposed.

use anyhow::{anyhow, Result};

const SERVICE: &str = "rsrs";

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

fn credential_entry(label: &str, backend: Backend) -> Result<keyring::Entry> {
    match backend {
        #[cfg(any(not(target_os = "linux"), test))]
        Backend::Native => keyring::Entry::new(SERVICE, label)
            .map_err(|_| anyhow!("keyring initialization failed")),
        #[cfg(all(target_os = "linux", not(test)))]
        Backend::SecretService => keyring::secret_service::default_credential_builder()
            .build(None, SERVICE, label)
            .map(keyring::Entry::new_with_credential)
            .map_err(|_| anyhow!("Secret Service initialization failed")),
        #[cfg(all(target_os = "linux", not(test)))]
        Backend::Kernel => keyring::keyutils::default_credential_builder()
            .build(None, SERVICE, label)
            .map(keyring::Entry::new_with_credential)
            .map_err(|_| anyhow!("kernel keyring initialization failed")),
    }
}

/// Read every applicable legacy backend without writing or self-healing it.
fn read_credentials(label: &str) -> Vec<String> {
    let mut values = Vec::new();
    for backend in backends() {
        if let Ok(entry) = credential_entry(label, *backend) {
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
        let entry = credential_entry(label, *backend)?;
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

/// Save a classify backend key (backend ∈ "ds" | "typesafe").
pub fn save_classify_key(backend: &str, key: &str) -> Result<()> {
    save_label(&format!("classify:{backend}"), key)
}

/// Load a classify backend key: OS keyring → env (DS_API_KEY / TYPESAFE_API_KEY) → None.
pub fn load_classify_key(backend: &str) -> Option<String> {
    let from_ring = read_credentials(&format!("classify:{backend}"))
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
    read_credentials("classify:ds-last-base")
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
    read_credentials(&format!("classify:ds-model@{host}"))
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
    read_credentials("classify:last-backend")
        .into_iter()
        .next()
        .filter(|v| v == "jev" || v == "ds")
}
