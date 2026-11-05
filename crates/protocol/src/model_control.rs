//! Private model preparation. Paths and mirrors never grant client-side authority.

use serde::{Deserialize, Serialize};

use crate::{AssetsStatus, ControlBinding};

pub const HOST_MODEL_SCHEMA_V: u32 = 1;

/// Matches the existing install flags; neither field changes the saved selection.
/// Mirror policy is supplied by the local CLI, not inferred from a response.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelInstallIntent {
    pub model: Option<String>,
    pub for_engine: Option<String>,
    pub mirror: Option<String>,
}

/// Plan requests require no digest; verification requires the exact returned digest.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostModelParams {
    pub schema_version: u32,
    pub binding: ControlBinding,
    pub intent: ModelInstallIntent,
    pub selection_sha256: Option<String>,
}

/// Opaque binding to the authoritative selection, install intent and pinned plan.
/// The same digest is returned after successful verification of that preparation.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelPreparation {
    pub selection_sha256: String,
    pub assets: AssetsStatus,
}
