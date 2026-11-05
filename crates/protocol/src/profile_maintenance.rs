//! Fixed private profile removal. No credentials or arbitrary filesystem paths.
use crate::{ControlBinding, HostAuthIdentity};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const HOST_PROFILE_SCHEMA_V: u32 = 1;
pub const HOST_PROFILE_REMOVE_METHOD: &str = "control.profile.remove";
pub const HOST_PROFILE_RESULT_METHOD: &str = "control.profile.result";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostProfileRemoveOperation {
    pub schema_version: u32,
    pub operation_id: String,
    pub key: String,
    pub installation_root: PathBuf,
    pub profile: PathBuf,
    pub identity: HostAuthIdentity,
    pub name: String,
    pub target_identity: HostAuthIdentity,
    pub fingerprint: String,
}

impl HostProfileRemoveOperation {
    pub fn fingerprint_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&(
            HOST_PROFILE_REMOVE_METHOD,
            self.schema_version,
            &self.installation_root,
            &self.profile,
            &self.identity,
            &self.name,
            &self.target_identity,
        ))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostProfileRemoveParams {
    pub schema_version: u32,
    pub binding: ControlBinding,
    pub identity: HostAuthIdentity,
    pub original: HostProfileRemoveOperation,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostProfileRemoveOutcome {
    Committed,
    Unknown,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostProfileRemoveResult {
    pub operation_id: String,
    pub fingerprint: String,
    pub identity: HostAuthIdentity,
    pub outcome: HostProfileRemoveOutcome,
}
