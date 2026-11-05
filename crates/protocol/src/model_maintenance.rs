//! Fixed host model maintenance; file installation/deletion stays with the CLI.
use crate::{ControlBinding, ModelPreparation};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const MODEL_MAINTENANCE_METHOD: &str = "control.model_maintenance";
pub const MODEL_MAINTENANCE_SCHEMA_V: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelMaintenanceKind {
    InstallEngines,
    UninstallM3,
    ResetCpu,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelMaintenancePhase {
    Plan,
    Apply,
    Verify,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelMaintenanceReview {
    pub selection_sha256: String,
    pub revision_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelMaintenanceParams {
    pub schema_version: u32,
    pub binding: ControlBinding,
    pub kind: ModelMaintenanceKind,
    pub phase: ModelMaintenancePhase,
    pub expected: Option<ModelMaintenanceReview>,
}

/// The package pin is independent of provider readiness and of the DLL pin.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCatalogPin {
    pub version: String,
    pub package_source: String,
    pub package_sha256: String,
    pub archive_member: String,
    pub destination: PathBuf,
    pub dll_size: u64,
    pub dll_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelMaintenancePlan {
    pub kind: ModelMaintenanceKind,
    pub review: ModelMaintenanceReview,
    pub preparation: Option<ModelPreparation>,
    pub catalog: Option<ModelCatalogPin>,
    pub uninstall_directory: Option<PathBuf>,
    pub cpu_candidate_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelMaintenanceReceipt {
    pub plan: ModelMaintenancePlan,
    pub phase: ModelMaintenancePhase,
    pub verified: bool,
    pub config_applied: bool,
    pub npu_ready: bool,
    pub warning: Option<String>,
}
