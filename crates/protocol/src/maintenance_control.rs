//! Fixed inherited-channel snapshot maintenance contract. No HTTP dispatch.
use serde::{Deserialize, Serialize};

use crate::ControlBinding;

pub const MAINTENANCE_CONTROL_SCHEMA_V: u32 = 1;
pub const MAINTENANCE_CONTROL_METHOD: &str = "control.snapshot_maintenance";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceAction {
    Restore,
    Rollback,
    Recover,
    Query,
    Commit,
    Release,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceControlParams {
    pub schema_version: u32,
    pub binding: ControlBinding,
    pub operation_id: String,
    pub request_fingerprint: String,
    pub sync_generation: usize,
    pub snapshot_id: String,
    pub action: MaintenanceAction,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceState {
    Unknown,
    Prepared,
    Installed,
    Verified,
    Released,
    RolledBack,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceControlResult {
    pub operation_id: String,
    pub request_fingerprint: String,
    pub snapshot_id: String,
    pub state: MaintenanceState,
    pub before_restore: Option<String>,
    pub sync_quarantined: Option<bool>,
    pub cleanup_pending: bool,
    pub cleanup_warning: Option<String>,
}


pub const LEGACY_SNAPSHOT_RECOVERY_METHOD: &str = "control.snapshot_legacy_recovery";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LegacySnapshotRecoveryAction {
    Query,
    Recover,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LegacySnapshotRecoveryParams {
    pub schema_version: u32,
    pub binding: ControlBinding,
    /// A new recovery operation, never the original restore operation.
    pub recovery_operation_id: String,
    pub request_fingerprint: String,
    pub journal_sha256: String,
    pub action: LegacySnapshotRecoveryAction,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LegacySnapshotRecoveryResult {
    pub recovery_operation_id: String,
    pub request_fingerprint: String,
    pub journal_sha256: String,
    pub state: MaintenanceState,
    pub cleanup_pending: bool,
    pub cleanup_warning: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LegacySnapshotDescriptor {
    pub journal_sha256: String,
    pub stage: MaintenanceState,
    /// Account fingerprint, never a plaintext account identifier.
    pub account_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LegacySnapshotRecoveryBinding {
    pub recovery_operation_id: String,
    pub request_fingerprint: String,
    pub journal_sha256: String,
    pub account_id: String,
}
