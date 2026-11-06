//! Fixed metadata maintenance and an offline, read-only status probe.
use std::path::{Component, Path, PathBuf};
use serde::{Deserialize, Serialize};
use crate::ControlBinding;

pub const HOST_METADATA_SCHEMA_V: u32 = 1;
pub const HOST_METADATA_ENABLE_METHOD: &str = "control.metadata.enable";
pub const HOST_METADATA_DISABLE_METHOD: &str = "control.metadata.disable";
pub const HOST_METADATA_RESULT_METHOD: &str = "control.metadata.result";
pub const HOST_METADATA_STATUS_METHOD: &str = "control.metadata.status";
pub const HOST_AGENT_CONFIG_READ_METHOD: &str = "control.agent_config.read";
pub const HOST_SNAPSHOT_PREFLIGHT_METHOD: &str = "control.snapshot.preflight";

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataDeploymentReview {
    pub operator: String,
    pub upgraded_writers: String,
    pub disconnected_old_clients: String,
    pub reconciled_offline_writes: String,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostMetadataIntent {
    Enable { mode: String, deployment_review: Option<MetadataDeploymentReview> },
    Disable,
}

impl HostMetadataIntent {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Disable => Ok(()),
            Self::Enable { mode, deployment_review } => match (mode.as_str(), deployment_review) {
                ("isolated", None) => Ok(()),
                ("controlled_writers", Some(review)) if [&review.operator, &review.upgraded_writers,
                    &review.disconnected_old_clients, &review.reconciled_offline_writes]
                    .iter().all(|value| !value.trim().is_empty()) => Ok(()),
                _ => Err("metadata deployment needs isolated without review, or controlled_writers with a nonempty operator and all three written explanations".into()),
            },
        }
    }
}

#[derive(Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostMetadataIdentity {
    pub account_id: Option<String>,
    pub session_sha256: Option<String>,
}

#[derive(Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostMetadataOperation {
    pub schema_version: u32,
    pub operation_id: String,
    pub key: String,
    pub installation_root: PathBuf,
    pub profile: PathBuf,
    pub identity: HostMetadataIdentity,
    pub intent: HostMetadataIntent,
    pub fingerprint: String,
}

impl HostMetadataOperation {
    pub fn fingerprint_bytes(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(&(HOST_METADATA_SCHEMA_V, "control.metadata",
            &self.installation_root, &self.profile, &self.identity, &self.intent))
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostMetadataParams {
    pub schema_version: u32,
    pub binding: ControlBinding,
    pub identity: HostMetadataIdentity,
    pub original: HostMetadataOperation,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostMetadataReadParams {
    pub schema_version: u32,
    pub binding: ControlBinding,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub legacy_snapshot_discovery: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SnapshotPreflightPayload {
    pub allowed: bool,
    #[serde(default)]
    pub legacy_recovery: Option<crate::maintenance_control::LegacySnapshotDescriptor>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HostOfflineRead { MetadataStatus, AgentConfigRead, SnapshotPreflight }

impl HostOfflineRead {
    pub fn method(self) -> &'static str {
        match self { Self::MetadataStatus => HOST_METADATA_STATUS_METHOD,
            Self::AgentConfigRead => HOST_AGENT_CONFIG_READ_METHOD,
            Self::SnapshotPreflight => HOST_SNAPSHOT_PREFLIGHT_METHOD }
    }

    pub fn command(self) -> &'static str {
        match self { Self::MetadataStatus => "metadata", Self::AgentConfigRead => "agent-config",
            Self::SnapshotPreflight => "snapshot-preflight" }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostMetadataOutcome { Committed, Unknown }

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostMetadataResult {
    pub original: HostMetadataOperation,
    pub outcome: HostMetadataOutcome,
    pub details: serde_json::Value,
}

/// Read-only local profiles may have no cloud user. This is not write authorization.
pub fn offline_read_user(profile: &Path) -> std::io::Result<Option<String>> {
    let Some((value, _)) = offline_session(profile)? else { return Ok(None); };
    offline_user(&value)
}

/// Bind exact local session bytes without unlocking or requiring a cloud account.
pub fn metadata_identity(profile: &Path, hash: impl Fn(&[u8]) -> String)
    -> std::io::Result<HostMetadataIdentity> {
    let Some((value, bytes)) = offline_session(profile)? else {
        return Ok(HostMetadataIdentity { account_id: None, session_sha256: None });
    };
    Ok(HostMetadataIdentity { account_id: offline_user(&value)?.map(|user| hash(user.as_bytes())),
        session_sha256: Some(hash(&bytes)) })
}

fn offline_session(profile: &Path) -> std::io::Result<Option<(serde_json::Value, Vec<u8>)>> {
    use std::io::{Error, ErrorKind, Read};
    let path = metadata_status_path(&profile.join("session.json"))?;
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.is_file() || metadata.len() > 65536 {
        return Err(Error::new(ErrorKind::InvalidData, "invalid offline session record"));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)?.take(65537).read_to_end(&mut bytes)?;
    if bytes.len() > 65536 { return Err(Error::new(ErrorKind::InvalidData, "offline session record exceeds its bound")); }
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "invalid offline session JSON"))?;
    if !value.is_object() { return Err(Error::new(ErrorKind::InvalidData, "offline session must be an object")); }
    Ok(Some((value, bytes)))
}

fn offline_user(value: &serde_json::Value) -> std::io::Result<Option<String>> {
    use std::io::{Error, ErrorKind};
    match value.get("user") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(user)) => Ok((!user.is_empty()).then(|| user.clone())),
        _ => Err(Error::new(ErrorKind::InvalidData, "offline session user must be a string or null")),
    }
}

/// Status alone accepts an absent profile without creating it or following links.
pub fn metadata_status_path(path: &Path) -> std::io::Result<PathBuf> {
    use std::io::{Error, ErrorKind};
    let absolute = std::path::absolute(path)?;
    if absolute.components().any(|part| part == Component::ParentDir) {
        return Err(Error::new(ErrorKind::InvalidInput, "metadata status path contains a parent component"));
    }
    let mut existing = None;
    for ancestor in absolute.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(Error::new(ErrorKind::InvalidInput, "metadata status path is a symlink"));
                }
                #[cfg(windows)] {
                    use std::os::windows::fs::MetadataExt;
                    if metadata.file_attributes() & 0x400 != 0 {
                        return Err(Error::new(ErrorKind::InvalidInput, "metadata status path is a reparse point"));
                    }
                }
                if existing.is_none() { existing = Some(ancestor.to_path_buf()); }
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    let existing = existing.ok_or_else(|| Error::new(ErrorKind::NotFound, "metadata status path has no existing ancestor"))?;
    let suffix = absolute.strip_prefix(&existing).map_err(|_| Error::new(ErrorKind::InvalidInput, "metadata status path changed"))?;
    let canonical = existing.canonicalize()?;
    // Joining an empty suffix adds a separator and changes display-based identity hashes.
    Ok(if suffix.as_os_str().is_empty() { canonical } else { canonical.join(suffix) })
}
