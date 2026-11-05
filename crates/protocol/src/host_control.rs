//! Private, one-request host control. Scope fields are constraints, not credentials.
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub const HOST_CONTROL_SCHEMA_V: u32 = 1;
pub const HOST_CONTROL_MAX_FRAME_BYTES: usize = 64 * 1024;

/// The serving grant's identity checks are also used by the inherited channel.
/// This value never authorizes a public HTTP request or a detached process.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostControlLaunchGrant {
    pub schema_version: u32,
    pub protocol_version: u32,
    pub nonce: String,
    pub instance_id: String,
    pub installation_root: PathBuf,
    pub installation_id: String,
    pub profile: PathBuf,
    pub account_id: String,
    pub sync_generation: usize,
    pub image_path: PathBuf,
    pub image_sha256: String,
    pub supervisor_pid: u32,
    pub supervisor_birth: String,
    pub managed_id: Option<String>,
    pub registration_sha256: Option<String>,
    pub maintenance: Option<HostControlMaintenanceBinding>,
    pub port: u16,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostControlMaintenanceBinding {
    pub marker_sha256: String,
    pub coordinator_id: String,
    pub controller_pid: u32,
    pub controller_birth: String,
    pub issuer_cli_version: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostControlOperation {
    MemoryRevision,
}

impl HostControlOperation {
    pub fn method(self) -> &'static str {
        match self {
            Self::MemoryRevision => "control.memory_revision",
        }
    }
}

/// Checked against the grant already consumed from the inherited channel.
/// None asserts absence of an account; it never means "accept any account".
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ControlBinding {
    pub installation_root: PathBuf,
    pub profile: PathBuf,
    pub launch_id: String,
    pub expected_account_id: Option<String>,
}

/// The sole JSON argument of the fixed control RPC method, never CLI argv.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostControlParams {
    pub schema_version: u32,
    pub binding: ControlBinding,
}
