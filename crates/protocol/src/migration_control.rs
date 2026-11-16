//! Fixed legacy-profile migration over the inherited maintenance channel.
use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use crate::{ControlBinding, HostAuthIdentity};

pub const HOST_MIGRATION_SCHEMA_V: u32 = 1;
pub const HOST_MIGRATION_PROFILE_METHOD: &str = "control.migration.profile";
pub const HOST_MIGRATION_RESULT_METHOD: &str = "control.migration.result";

/// Persisted in the existing migration completion marker before publication.
#[derive(Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostMigrationOperation {
    pub schema_version: u32,
    pub operation_id: String,
    pub key: String,
    pub installation_root: PathBuf,
    pub profile: PathBuf,
    pub identity: HostAuthIdentity,
    pub source_id: String,
    pub account: String,
    pub fingerprint: String,
}

impl HostMigrationOperation {
    /// Shared preimage; consumers use their existing SHA-256 implementation.
    pub fn fingerprint_bytes(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(&(HOST_MIGRATION_SCHEMA_V, "control.migration.profile",
            &self.installation_root, &self.profile, &self.identity, &self.source_id, &self.account))
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostMigrationParams {
    pub schema_version: u32,
    pub binding: ControlBinding,
    pub identity: HostAuthIdentity,
    pub original: HostMigrationOperation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub material: Option<HostMigrationMaterial>,
}

/// Ephemeral factors and custody acknowledgement, excluded from durable intent identity.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostMigrationMaterial {
    pub candidates: Vec<crate::host_control::HostAuthSessionMaterial>,
    pub custody: Option<HostMigrationCustody>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostMigrationCustody {
    pub keyring_account: String,
    pub keyring_backend: String,
    pub legacy_secret_backend: Option<String>,
    pub login_password_retained: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostMigrationOutcome {
    Completed,
    AlreadyMigrated,
    Unknown,
    /// Private intermediate response; the host must supply custody before completion.
    CredentialsRequired,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostMigrationResult {
    pub operation_id: String,
    pub fingerprint: String,
    pub identity: HostAuthIdentity,
    pub outcome: HostMigrationOutcome,
    pub details: serde_json::Value,
}
