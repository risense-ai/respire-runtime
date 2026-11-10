#![forbid(unsafe_code)]
//! Shared host ownership for Runtime account transactions, not business execution.
//! Public constructors are for trusted host embeddings, never deserialized input.
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

mod account;
mod account_control;
mod exchange;
mod key;
mod launch;
pub mod lifecycle_io;
mod maintenance;

pub use account::{
    AccountContinuation, AccountCoordinator, AccountHandoffPending, AccountOutcomeUnknown,
};
pub use key::{KeyCoordinator, KeyRecoveryRequired};
pub use launch::spawn_serving;
pub use maintenance::{HostLifecycle, LaunchContext, Maintenance, RegistrationMode, KeygenAccountTransfer, KeygenAccountAdmission};

pub(crate) const PROTOCOL_V: u32 = respire_commands::rpc_client::PROTOCOL_V;

/// An actual regular installed image, bound to the embedding host's selected
/// manifest. The embedding remains responsible for selection/provenance policy;
/// this handle never accepts a caller-provided authorization boolean or grant.
#[derive(Clone)]
pub struct VerifiedRuntime {
    pub(crate) image_path: PathBuf,
    pub(crate) image_sha256: String,
    pub(crate) version: String,
    pub(crate) port: u16,
}

impl VerifiedRuntime {
    pub fn verify_installed(
        path: &Path,
        expected_sha256: &str,
        version: &str,
        port: u16,
    ) -> Result<Self> {
        anyhow::ensure!(
            path.is_absolute()
                && !version.is_empty()
                && port > 0
                && expected_sha256.len() == 64
                && expected_sha256.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid installed Runtime selection"
        );
        let path = respire_client_host::config::normalize_control_path(path)?;
        let metadata = std::fs::symlink_metadata(&path)?;
        anyhow::ensure!(metadata.is_file(), "Runtime image is not a regular file");
        let mut file = std::fs::File::open(&path)?;
        let mut hash = Sha256::new();
        std::io::copy(&mut file, &mut hash)?;
        let image_sha256 = format!("{:x}", hash.finalize());
        anyhow::ensure!(
            image_sha256.eq_ignore_ascii_case(expected_sha256),
            "Runtime image differs from the selected manifest"
        );
        Ok(Self {
            image_path: path.canonicalize()?,
            image_sha256,
            version: version.to_owned(),
            port,
        })
    }

    pub fn path(&self) -> &Path {
        &self.image_path
    }
    pub fn sha256(&self) -> &str {
        &self.image_sha256
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    pub(crate) fn revalidate(&self) -> Result<()> {
        let current = Self::verify_installed(
            &self.image_path,
            &self.image_sha256,
            &self.version,
            self.port,
        )?;
        anyhow::ensure!(
            current.image_path == self.image_path,
            "Runtime image path changed"
        );
        Ok(())
    }
}

pub(crate) fn identity(profile: &Path) -> Result<respire_protocol::HostAuthIdentity> {
    use respire_client_host::identity::{auth_session_identity, AuthSessionIdentity};
    use respire_protocol::HostAuthIdentity;
    Ok(
        match auth_session_identity(profile, |bytes| format!("{:x}", Sha256::digest(bytes)))? {
            AuthSessionIdentity::Absent => HostAuthIdentity::Absent,
            AuthSessionIdentity::Unbound {
                operation_id,
                session_sha256,
            } => HostAuthIdentity::Unbound {
                operation_id,
                session_sha256,
            },
            AuthSessionIdentity::Bound {
                account_id,
                session_sha256,
            } => HostAuthIdentity::Bound {
                account_id,
                session_sha256,
            },
        },
    )
}
