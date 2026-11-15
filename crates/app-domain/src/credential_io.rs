//! Private host-owned credential delivery. Serving Runtime has no native credential backend.
use std::io::{Read, Write};
use std::sync::{mpsc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result};
use respire_protocol::credentials::{
    CredentialError, CredentialOperation, CredentialReply, CredentialRequest, CREDENTIAL_SCHEMA_V,
};
use respire_protocol::HOST_CONTROL_MAX_FRAME_BYTES;

struct Channel {
    replies: mpsc::Receiver<CredentialReply>,
}

static CHANNEL: OnceLock<Mutex<Channel>> = OnceLock::new();
struct ProviderState {
    values: Vec<respire_protocol::credentials::ProvidedCredential>,
    status: respire_protocol::credentials::ProviderCredentialStatus,
}

static PROVIDED: Mutex<ProviderState> = Mutex::new(ProviderState {
    values: Vec::new(),
    status: respire_protocol::credentials::ProviderCredentialStatus::NotLoaded,
});

pub fn supply_credentials(values: Vec<respire_protocol::credentials::ProvidedCredential>) -> Result<()> {
    let mut provided = PROVIDED.lock().map_err(|_| anyhow::anyhow!("provided credentials lock poisoned"))?;
    provided.values = values;
    provided.status = respire_protocol::credentials::ProviderCredentialStatus::Ready;
    Ok(())
}

impl ProviderState {
    fn apply(&mut self, update: respire_protocol::credentials::ProviderCredentialUpdate) -> Result<()> {
        use respire_protocol::credentials::{ProviderCredentialStatus, ProviderCredentialUpdate};
        match update {
            ProviderCredentialUpdate::Replace { credentials } => {
                let mut slots = std::collections::HashSet::new();
                for entry in &credentials {
                    anyhow::ensure!(!entry.service.is_empty() && !entry.account.is_empty() && !entry.value.is_empty()
                        && slots.insert((&entry.service, &entry.account)), "invalid provider credential snapshot");
                }
                self.values = credentials;
                self.status = ProviderCredentialStatus::Ready;
            }
            ProviderCredentialUpdate::Unavailable { code } => {
                self.status = ProviderCredentialStatus::Unavailable { code };
            }
        }
        Ok(())
    }

    fn read(&self, service: &str, account: &str) -> Result<String, CredentialError> {
        if self.status != respire_protocol::credentials::ProviderCredentialStatus::Ready {
            return Err(CredentialError::Unavailable);
        }
        self.values.iter().find(|entry| entry.service == service && entry.account == account)
            .map(|entry| entry.value.clone()).ok_or(CredentialError::NoEntry)
    }

    fn ensure_available(&self, allow_not_loaded: bool) -> Result<()> {
        use respire_protocol::credentials::ProviderCredentialStatus;
        match self.status {
            ProviderCredentialStatus::Unavailable { code } => anyhow::bail!("provider credentials unavailable: {code:?}"),
            ProviderCredentialStatus::NotLoaded if !allow_not_loaded =>
                anyhow::bail!("provider credentials have not been loaded"),
            _ => Ok(()),
        }
    }
}

pub fn apply_provider_update(update: respire_protocol::credentials::ProviderCredentialUpdate) -> Result<()> {
    PROVIDED.lock().map_err(|_| anyhow::anyhow!("provided credentials lock poisoned"))?.apply(update)
}

pub fn provider_status() -> Result<respire_protocol::credentials::ProviderCredentialStatus> {
    Ok(PROVIDED.lock().map_err(|_| anyhow::anyhow!("provided credentials lock poisoned"))?.status)
}

pub fn ensure_provider_credentials_available() -> Result<()> {
    PROVIDED.lock().map_err(|_| anyhow::anyhow!("provided credentials lock poisoned"))?
        .ensure_available(is_private_control() || cfg!(any(test, feature = "test-support")))
}

pub fn is_private_control() -> bool {
    CHANNEL.get().is_some()
}

/// One reader owns stdin, including parent revocation and credential replies.
pub fn watch_parent(revoked: impl FnOnce() + Send + 'static) -> std::io::Result<()> {
    if CHANNEL.get().is_some() {
        return Ok(());
    }
    let (send, replies) = mpsc::channel();
    CHANNEL.set(Mutex::new(Channel { replies }))
        .map_err(|_| std::io::Error::other("private credential channel already initialized"))?;
    std::thread::Builder::new().name("host-credential-input".into()).spawn(move || {
        let mut input = std::io::stdin().lock();
        while let Ok(reply) = read_frame::<CredentialReply>(&mut input) {
            if reply.credential_reply != CREDENTIAL_SCHEMA_V || send.send(reply).is_err() {
                break;
            }
        }
        revoked();
    })?;
    Ok(())
}

pub struct Entry {
    service: String,
    account: String,
    backend: String,
}

impl Entry {
    pub fn new(service: &str, account: &str, backend: &str) -> Self {
        Self { service: service.into(), account: account.into(), backend: backend.into() }
    }

    #[cfg(not(any(test, feature = "test-support")))]
    fn exchange(&self, operation: CredentialOperation) -> Result<Option<String>, CredentialError> {
        let channel = CHANNEL.get().ok_or(CredentialError::Unavailable)?;
        let channel = channel.lock().map_err(|_| CredentialError::Unavailable)?;
        let id = uuid::Uuid::new_v4().to_string();
        let request = CredentialRequest {
            credential_request: CREDENTIAL_SCHEMA_V, id: id.clone(),
            service: self.service.clone(), account: self.account.clone(),
            backend: self.backend.clone(), operation,
        };
        write_frame(&mut std::io::stdout().lock(), &request)
            .map_err(|_| CredentialError::Unavailable)?;
        let reply = channel.replies.recv_timeout(Duration::from_secs(15))
            .map_err(|_| CredentialError::Unavailable)?;
        if reply.credential_reply != CREDENTIAL_SCHEMA_V || reply.id != id {
            return Err(CredentialError::Unavailable);
        }
        reply.result
    }

    #[cfg(any(test, feature = "test-support"))]
    fn exchange(&self, operation: CredentialOperation) -> Result<Option<String>, CredentialError> {
        let map_error = |error: keyring::Error| match error {
            keyring::Error::NoEntry => CredentialError::NoEntry,
            keyring::Error::Ambiguous(_) => CredentialError::Ambiguous,
            keyring::Error::BadEncoding(_) => CredentialError::BadEncoding,
            keyring::Error::Invalid(_, _) => CredentialError::Invalid,
            _ => CredentialError::Unavailable,
        };
        let entry = keyring::Entry::new(&self.service, &self.account).map_err(map_error)?;
        match operation {
            CredentialOperation::Read => entry.get_password().map(Some).map_err(map_error),
            CredentialOperation::ReadConfigured => {
                let name = if self.account.starts_with("super:") { "RSRS_SUPER" } else { "RSRS_PASS" };
                crate::env::var(name).ok().filter(|value| !value.is_empty())
                    .map(|value| Ok(Some(value)))
                    .unwrap_or_else(|| entry.get_password().map(Some).map_err(map_error))
            }
            CredentialOperation::Write(value) => entry.set_password(&value).map(|()| None).map_err(map_error),
            CredentialOperation::Delete => entry.delete_credential().map(|()| None).map_err(map_error),
        }
    }

    pub fn get_password(&self) -> Result<String, CredentialError> {
        ensure_provider_credentials_available().map_err(|_| CredentialError::Unavailable)?;
        if !is_private_control() && !cfg!(any(test, feature = "test-support")) {
            return PROVIDED.lock().map_err(|_| CredentialError::Unavailable)?.read(&self.service, &self.account);
        }
        self.exchange(CredentialOperation::Read)?.ok_or(CredentialError::NoEntry)
    }

    pub fn set_password(&self, value: &str) -> Result<(), CredentialError> {
        self.exchange(CredentialOperation::Write(value.into())).map(|_| ())
    }

    pub fn get_configured_password(&self) -> Result<String, CredentialError> {
        if !is_private_control() && !cfg!(any(test, feature = "test-support")) {
            return self.get_password();
        }
        self.exchange(CredentialOperation::ReadConfigured)?.ok_or(CredentialError::NoEntry)
    }

    pub fn delete_credential(&self) -> Result<(), CredentialError> {
        self.exchange(CredentialOperation::Delete).map(|_| ())
    }
}

pub fn read_frame<T: serde::de::DeserializeOwned>(input: &mut impl Read) -> Result<T> {
    let mut length = [0u8; 4];
    input.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    anyhow::ensure!(length > 0 && length <= HOST_CONTROL_MAX_FRAME_BYTES, "invalid private frame size");
    let mut bytes = vec![0; length];
    input.read_exact(&mut bytes)?;
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid private credential frame"))
}

fn write_frame(output: &mut impl Write, value: &impl serde::Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    anyhow::ensure!(!bytes.is_empty() && bytes.len() <= HOST_CONTROL_MAX_FRAME_BYTES, "private credential frame too large");
    output.write_all(&u32::try_from(bytes.len())?.to_be_bytes())?;
    output.write_all(&bytes)?;
    output.flush().context("private credential delivery failed")
}

#[cfg(test)]
mod provider_tests {
    use super::*;
    use respire_protocol::credentials::{ProvidedCredential, ProviderCredentialStatus,
        ProviderCredentialUpdate, ProviderUnavailableCode};

    fn snapshot(value: &str) -> ProvidedCredential {
        ProvidedCredential { service: "rsrs".into(), account: "classify:typesafe".into(), value: value.into() }
    }

    #[test]
    fn unavailable_retains_but_revokes_old_values_until_complete_replace() -> Result<()> {
        let mut state = ProviderState { values: Vec::new(), status: ProviderCredentialStatus::NotLoaded };
        assert!(state.ensure_available(false).is_err());
        state.apply(ProviderCredentialUpdate::Replace { credentials: vec![snapshot("old-synthetic-key")] })?;
        assert_eq!(state.read("rsrs", "classify:typesafe")?, "old-synthetic-key");
        state.apply(ProviderCredentialUpdate::Unavailable { code: ProviderUnavailableCode::AccessDenied })?;
        assert_eq!(state.values[0].value, "old-synthetic-key");
        assert!(matches!(state.read("rsrs", "classify:typesafe"), Err(CredentialError::Unavailable)));
        for allow_not_loaded in [false, true] {
            let error = state.ensure_available(allow_not_loaded).err().ok_or_else(|| anyhow::anyhow!("unavailable state was accepted"))?;
            assert!(!error.to_string().contains("old-synthetic-key"));
        }
        assert!(state.apply(ProviderCredentialUpdate::Replace { credentials: vec![snapshot("a"), snapshot("b")] }).is_err());
        assert!(state.apply(ProviderCredentialUpdate::Replace { credentials: vec![snapshot("")] }).is_err());
        assert_eq!(state.values[0].value, "old-synthetic-key");
        assert_eq!(state.status, ProviderCredentialStatus::Unavailable { code: ProviderUnavailableCode::AccessDenied });
        state.apply(ProviderCredentialUpdate::Replace { credentials: vec![snapshot("new-synthetic-key")] })?;
        state.ensure_available(false)?;
        assert_eq!(state.read("rsrs", "classify:typesafe")?, "new-synthetic-key");
        state.apply(ProviderCredentialUpdate::Replace { credentials: Vec::new() })?;
        assert!(matches!(state.read("rsrs", "classify:typesafe"), Err(CredentialError::NoEntry)));
        assert_eq!(state.status, ProviderCredentialStatus::Ready);
        Ok(())
    }
}
