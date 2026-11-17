//! Process-local query configuration. Hosts own persistence and transaction journals.
use crate::HostControlMaintenanceBinding;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const VALIDATE_METHOD: &str = "core_config.validate";
pub const APPLY_METHOD: &str = "core_config.apply";
pub const READ_METHOD: &str = "core_config.read";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreConfigCandidate {
    pub read_heat: Value,
    pub recall_fusion: Value,
}

/// The sole JSON argument in RpcRequest.args; maintenance is required while Paused.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreConfigParams {
    pub schema_version: u32,
    pub maintenance: Option<HostControlMaintenanceBinding>,
    pub candidate: Option<CoreConfigCandidate>,
    pub expected_revision: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreConfigReceipt {
    pub state: String,
    pub revision: u64,
    pub candidate: CoreConfigCandidate,
    pub effective: Value,
    pub capabilities: Value,
    pub applies: String,
}
