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
static PROVIDED: Mutex<Vec<respire_protocol::credentials::ProvidedCredential>> = Mutex::new(Vec::new());

pub fn supply_credentials(values: Vec<respire_protocol::credentials::ProvidedCredential>) -> Result<()> {
    *PROVIDED.lock().map_err(|_| anyhow::anyhow!("provided credentials lock poisoned"))? = values;
    Ok(())
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
        if !is_private_control() && !cfg!(any(test, feature = "test-support")) {
            return PROVIDED.lock().map_err(|_| CredentialError::Unavailable)?
                .iter().find(|entry| entry.service == self.service && entry.account == self.account)
                .map(|entry| entry.value.clone()).ok_or(CredentialError::NoEntry);
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
