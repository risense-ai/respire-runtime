//! runtime/CLI split-era wire contract (version pinning, compat window, asset reporting).
//!
//! Pure serde data shared by the `rsrs` CLI and the `rsrs-runtime` binary across
//! repository boundaries. The published crate is the single source of truth for
//! these shapes; both consumers must depend on the same released version.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// CLI versions accepted by a runtime build (semver window, `max_cli` may be `*`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeCompat {
    pub min_cli: String,
    pub max_cli: String,
}

/// Runtime identity block embedded in the `/health` body extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeIdentity {
    /// Version of the `rsrs-runtime` binary itself (its own `CARGO_PKG_VERSION`).
    pub runtime_version: String,
    pub runtime_compat: RuntimeCompat,
}

/// Identity fixed by the caller for one Runtime business operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeRequestScope {
    pub account_id: String,
    pub instance_id: String,
    pub generation: u64,
}

/// Runtime RPC request shared by producers and consumers.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<RuntimeRequestScope>,
    pub v: u32,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_operation_id: Option<String>,
    pub method: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_wait_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<String>,
}

/// Runtime RPC response; the caller supplies its existing output envelope.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(deserialize = "Envelope: Deserialize<'de>"))]
pub struct RpcResponse<Envelope> {
    pub v: u32,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<RuntimeRequestScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    pub ok: bool,
    pub exit: i32,
    #[serde(default)]
    pub bin: String,
    #[serde(default)]
    pub envelope: Option<Envelope>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub web_url: Option<String>,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub data_dir: Option<String>,
}

/// A final stop receipt is consumed only after the exact process has exited.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeStopReceipt {
    pub schema_version: u32,
    pub protocol_version: u32,
    pub operation_id: String,
    pub installation_id: String,
    pub instance_id: String,
    pub pid: u32,
    pub process_start_id: String,
    pub image_path: String,
    pub image_sha256: String,
    pub runtime_version: String,
    pub account_id: String,
    pub generation: u64,
    pub state: RuntimeStopOutcome,
    pub unfinished: Vec<RuntimeUnfinishedOperation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeStopOutcome {
    Drained,
    ForcedTimeout,
    CompatibilityTimeout,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeUnfinishedOperation {
    pub operation_id: String,
    pub result: RuntimeUnfinishedOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeUnfinishedOutcome {
    Aborted,
    Unknown,
}

impl RuntimeIdentity {
    /// Health-body extension under the `runtime` key; additive, older CLIs ignore it.
    pub fn health_extension_json(&self) -> serde_json::Value {
        serde_json::json!({
            "runtime_version": self.runtime_version,
            "runtime_compat": {
                "min_cli": self.runtime_compat.min_cli,
                "max_cli": self.runtime_compat.max_cli,
            }
        })
    }
}

/// One host asset the runtime consumes but never downloads (models, ORT, providers.json).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetRequirement {
    /// Stable asset name (e.g. `bge-m3`, `ort-cpu`, `providers.json`).
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Where the CLI installer should fetch it (mirror or official source hint).
    pub suggested_source: String,
    #[serde(default, skip_serializing_if = "AssetState::is_default")]
    pub state: AssetState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetState {
    #[default]
    Missing,
    Incomplete,
    Corrupt,
    Incompatible,
    Complete,
}

/// Payload of the `assets.status` RPC method: what the runtime is missing, if anything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetsStatus {
    /// Wire readiness requires verified files and a successful fresh backend load.
    pub complete: bool,
    pub missing: Vec<AssetRequirement>,
    #[serde(default)]
    pub assets: Vec<AssetRequirement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_load: Option<BackendLoadStatus>,
}

/// File-only checks may omit this block; wire consumers enforce readiness separately.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendLoadStatus {
    pub state: BackendLoadState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<BackendLoadEvidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendLoadState {
    NotRun,
    Loaded,
    Failed,
}

/// Public sanitized SDK probe result, never native handles, symbols or paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendLoadEvidence {
    pub contract: u32,
    pub status: BackendLoadState,
    pub ready: bool,
    pub backend: BackendLoadBackend,
    pub engine: BackendLoadEngine,
    pub selected: String,
    pub provider: String,
    pub fresh_session: bool,
    pub inference_completed: bool,
    pub model: String,
    pub index_identity: String,
    pub dimensions: u32,
    pub node_assignment: BackendLoadNodeAssignment,
    pub cpu_node_fallback: BackendLoadCpuNodeFallback,
    pub runtime: BackendLoadRuntime,
    pub sdk_pin: BackendLoadSdkPin,
    pub modules: Vec<BackendLoadModule>,
    pub module_identity_source: BackendLoadModuleIdentitySource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendLoadBackend { Onnx }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendLoadEngine { Cpu, Gpu, Npu }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendLoadNodeAssignment { NotMeasured }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendLoadCpuNodeFallback { Allowed, Disabled, HostManaged, NotApplicable }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendLoadModuleIdentitySource { HostVerified }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendLoadRuntimeKind { Onnxruntime }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendLoadRuntime {
    pub kind: BackendLoadRuntimeKind,
    pub api_version: u32,
    pub version: String,
    pub build_info_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendLoadSdkPin {
    pub target: String,
    pub sdk_version: String,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendLoadModule {
    pub id: String,
    pub sha256: String,
}

impl AssetState {
    fn is_default(&self) -> bool {
        *self == Self::Missing
    }
}

/// Published metadata for one runtime build (`runtime-build-<triple>.json`).
///
/// Consumed verbatim by the CLI downloader and client2; `tag` strips to
/// `runtime_version` by dropping the leading `v`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeBuildMeta {
    pub schema_version: u32,
    pub runtime_version: String,
    /// Release tag, e.g. `v1.0.21-dev.1`.
    pub tag: String,
    pub target_triple: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_file: Option<String>,
    pub archive_sha256: String,
    /// Triple-qualified binary name inside the tarball and release inventory,
    /// e.g. `rsrs-runtime-x86_64-pc-windows-msvc.exe`.
    pub binary_file: String,
    /// sha256 of the triple-qualified binary.
    pub binary_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_commit: Option<String>,
    pub compat: RuntimeCompat,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_range: Option<ProtocolRange>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub capabilities: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<RuntimeBuildFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolRange {
    pub minimum: u32,
    pub maximum: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeBuildFile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct RawRuntimeBuildMeta {
    schema_version: u64,
    runtime_version: Option<String>,
    tag: Option<String>,
    triple: Option<String>,
    target_triple: Option<String>,
    archive_file: Option<String>,
    sha256: Option<String>,
    archive_sha256: Option<String>,
    binary_file: Option<String>,
    binary_sha256: Option<String>,
    source_commit: Option<String>,
    compat: Option<RuntimeCompat>,
    protocol_range: Option<ProtocolRange>,
    #[serde(default)]
    capabilities: BTreeMap<String, String>,
    #[serde(default)]
    files: Vec<RuntimeBuildFile>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeBuildMetaError {
    UnsupportedSchema(u64),
    MissingField(&'static str),
    InvalidDigest(&'static str),
    AliasConflict(&'static str),
    MalformedJson,
}

impl fmt::Display for RuntimeBuildMetaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchema(version) => {
                write!(formatter, "unsupported schema version {version}")
            }
            Self::MissingField(field) => write!(formatter, "missing field {field}"),
            Self::InvalidDigest(field) => write!(formatter, "invalid SHA-256 in {field}"),
            Self::AliasConflict(field) => {
                write!(formatter, "legacy and canonical {field} values conflict")
            }
            Self::MalformedJson => write!(formatter, "malformed runtime build metadata"),
        }
    }
}

impl std::error::Error for RuntimeBuildMetaError {}

impl RuntimeBuildMeta {
    pub fn from_json(value: &serde_json::Value) -> Result<Self, RuntimeBuildMetaError> {
        let raw: RawRuntimeBuildMeta = serde_json::from_value(value.clone())
            .map_err(|_| RuntimeBuildMetaError::MalformedJson)?;
        if raw.schema_version != 1 && raw.schema_version != 2 {
            return Err(RuntimeBuildMetaError::UnsupportedSchema(raw.schema_version));
        }
        let runtime_version = raw
            .runtime_version
            .ok_or(RuntimeBuildMetaError::MissingField("runtime_version"))?;
        let tag = raw.tag.ok_or(RuntimeBuildMetaError::MissingField("tag"))?;
        let target = alias_field(
            raw.target_triple.as_deref(),
            raw.triple.as_deref(),
            "target_triple",
        )?
        .ok_or(RuntimeBuildMetaError::MissingField("target_triple"))?;
        let archive = alias_field(
            raw.archive_sha256.as_deref(),
            raw.sha256.as_deref(),
            "archive_sha256",
        )?
        .ok_or(RuntimeBuildMetaError::MissingField("archive_sha256"))?;
        let binary_file = raw
            .binary_file
            .ok_or(RuntimeBuildMetaError::MissingField("binary_file"))?;
        let binary = raw
            .binary_sha256
            .ok_or(RuntimeBuildMetaError::MissingField("binary_sha256"))?;
        let compat = raw
            .compat
            .ok_or(RuntimeBuildMetaError::MissingField("compat"))?;
        if tag.strip_prefix('v') != Some(runtime_version.as_str()) {
            return Err(RuntimeBuildMetaError::AliasConflict("tag/runtime_version"));
        }
        valid_digest(
            &archive,
            RuntimeBuildMetaError::InvalidDigest("archive_sha256"),
        )?;
        valid_digest(
            &binary,
            RuntimeBuildMetaError::InvalidDigest("binary_sha256"),
        )?;

        if raw.schema_version == 2 {
            if raw.archive_file.is_none() {
                return Err(RuntimeBuildMetaError::MissingField("archive_file"));
            }
            if raw.source_commit.is_none() {
                return Err(RuntimeBuildMetaError::MissingField("source_commit"));
            }
            if raw.protocol_range.is_none() {
                return Err(RuntimeBuildMetaError::MissingField("protocol_range"));
            }
            if raw.capabilities.is_empty() {
                return Err(RuntimeBuildMetaError::MissingField("capabilities"));
            }
            if raw.files.is_empty() {
                return Err(RuntimeBuildMetaError::MissingField("files"));
            }
            if raw.source_commit.as_deref().is_some_and(|commit| {
                commit.len() != 40
                    || !commit
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            }) {
                return Err(RuntimeBuildMetaError::MalformedJson);
            }
            if raw
                .protocol_range
                .as_ref()
                .is_some_and(|range| range.minimum > range.maximum)
            {
                return Err(RuntimeBuildMetaError::MalformedJson);
            }
            for file in &raw.files {
                if file.path.is_empty() {
                    return Err(RuntimeBuildMetaError::MissingField("files.path"));
                }
                valid_digest(
                    &file.sha256,
                    RuntimeBuildMetaError::InvalidDigest("files.sha256"),
                )?;
            }
        }

        Ok(Self {
            schema_version: raw.schema_version as u32,
            runtime_version,
            tag,
            target_triple: target,
            archive_file: raw.archive_file,
            archive_sha256: archive,
            binary_file,
            binary_sha256: binary,
            source_commit: raw.source_commit,
            compat,
            protocol_range: raw.protocol_range,
            capabilities: raw.capabilities,
            files: raw.files,
        })
    }

    pub fn target_is(&self, target: &str) -> bool {
        self.target_triple == target
    }
}

fn alias_field(
    canonical: Option<&str>,
    legacy: Option<&str>,
    field: &'static str,
) -> Result<Option<String>, RuntimeBuildMetaError> {
    match (canonical, legacy) {
        (Some(value), Some(alias)) if value == alias => Ok(Some(value.to_owned())),
        (Some(_), Some(_)) => Err(RuntimeBuildMetaError::AliasConflict(field)),
        (Some(value), None) => Ok(Some(value.to_owned())),
        (None, Some(value)) => Ok(Some(value.to_owned())),
        (None, None) => Ok(None),
    }
}

fn valid_digest(value: &str, error: RuntimeBuildMetaError) -> Result<(), RuntimeBuildMetaError> {
    let valid = value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if valid {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn identity() -> RuntimeIdentity {
        RuntimeIdentity {
            runtime_version: "1.0.21-dev.1".to_owned(),
            runtime_compat: RuntimeCompat {
                min_cli: "1.0.20".to_owned(),
                max_cli: "*".to_owned(),
            },
        }
    }

    #[test]
    fn health_extension_roundtrip() -> anyhow::Result<()> {
        let json = identity().health_extension_json();
        assert_eq!(json["runtime_version"], "1.0.21-dev.1");
        assert_eq!(json["runtime_compat"]["min_cli"], "1.0.20");
        let back: RuntimeIdentity = serde_json::from_value(serde_json::json!({
            "runtime_version": "1.0.21-dev.1",
            "runtime_compat": {"min_cli": "1.0.20", "max_cli": "*"}
        }))?;
        assert_eq!(back, identity());
        Ok(())
    }

    #[test]
    fn assets_status_defaults_incomplete() -> anyhow::Result<()> {
        let raw = r#"{"complete":false,"missing":[{"name":"bge-m3","suggested_source":"mirror"}]}"#;
        let status: AssetsStatus = serde_json::from_str(raw)?;
        assert!(!status.complete);
        assert!(status.backend_load.is_none());
        let file_only: AssetsStatus = serde_json::from_str(r#"{"complete":true,"missing":[]}"#)?;
        assert!(file_only.complete);
        assert!(file_only.backend_load.is_none());
        assert!(serde_json::to_value(file_only)?.get("backend_load").is_none());
        assert_eq!(status.missing.len(), 1);
        assert_eq!(status.missing[0].name, "bge-m3");
        assert!(status.missing[0].version.is_none());
        Ok(())
    }

    #[test]
    fn asset_state_values_roundtrip() -> anyhow::Result<()> {
        let raw = r#"["missing","incomplete","corrupt","incompatible","complete"]"#;
        let states: Vec<AssetState> = serde_json::from_str(raw)?;
        assert_eq!(
            states,
            [
                AssetState::Missing,
                AssetState::Incomplete,
                AssetState::Corrupt,
                AssetState::Incompatible,
                AssetState::Complete,
            ]
        );
        assert_eq!(serde_json::to_string(&states)?, raw);
        Ok(())
    }

    #[test]
    fn build_meta_roundtrip() -> anyhow::Result<()> {
        let meta = RuntimeBuildMeta {
            schema_version: 2,
            runtime_version: "1.0.21-dev.1".to_owned(),
            tag: "v1.0.21-dev.1".to_owned(),
            target_triple: "x86_64-pc-windows-msvc".to_owned(),
            archive_file: Some("rsrs-runtime-x86_64-pc-windows-msvc.tar.gz".to_owned()),
            archive_sha256: "1111111111111111111111111111111111111111111111111111111111111111"
                .to_owned(),
            binary_file: "rsrs-runtime-x86_64-pc-windows-msvc.exe".to_owned(),
            binary_sha256: "2222222222222222222222222222222222222222222222222222222222222222"
                .to_owned(),
            source_commit: Some("dd45330c9848ebb73f2d98a363e6af0de3fc5a91".to_owned()),
            compat: RuntimeCompat {
                min_cli: "1.0.20".to_owned(),
                max_cli: "*".to_owned(),
            },
            protocol_range: Some(ProtocolRange {
                minimum: 1,
                maximum: 1,
            }),
            capabilities: BTreeMap::from([("business_executor".to_owned(), "1".to_owned())]),
            files: vec![RuntimeBuildFile {
                path: "rsrs-runtime-x86_64-pc-windows-msvc.exe".to_owned(),
                size: 4096,
                sha256: "2222222222222222222222222222222222222222222222222222222222222222"
                    .to_owned(),
            }],
        };
        let json = serde_json::to_string(&meta)?;
        let back: RuntimeBuildMeta = serde_json::from_str(&json)?;
        assert_eq!(back, meta);
        assert_eq!(back.tag.trim_start_matches('v'), back.runtime_version);
        Ok(())
    }

    #[test]
    fn release_metadata_accepts_schema_one_alias_mapping() -> anyhow::Result<()> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../contracts/runtime-control/fixtures/positive");
        let v1: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(
            root.join("release-metadata-v1.json"),
        )?)?;
        let meta = RuntimeBuildMeta::from_json(&v1["payload"])
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        assert_eq!(meta.schema_version, 1);
        assert_eq!(meta.target_triple, "x86_64-pc-windows-msvc");
        assert_ne!(meta.archive_sha256, meta.binary_sha256);
        assert!(meta.source_commit.is_none());

        let v2: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(
            root.join("release-metadata-v2.json"),
        )?)?;
        let canonical = RuntimeBuildMeta::from_json(&v2["payload"])
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        assert_eq!(canonical.schema_version, 2);
        assert!(canonical.target_is("x86_64-pc-windows-msvc"));
        assert_ne!(canonical.archive_sha256, canonical.binary_sha256);
        Ok(())
    }

    #[test]
    fn release_metadata_rejects_alias_conflicts_and_unknown_schema() -> anyhow::Result<()> {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/runtime-control/fixtures");
        let conflict: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(
            root.join("negative/release-metadata-conflicting-hash.json"),
        )?)?;
        assert_eq!(
            RuntimeBuildMeta::from_json(&conflict["payload"]),
            Err(RuntimeBuildMetaError::AliasConflict("target_triple"))
        );
        let mut archive_conflict = conflict.clone();
        archive_conflict["payload"]["triple"] =
            archive_conflict["payload"]["target_triple"].clone();
        assert_eq!(
            RuntimeBuildMeta::from_json(&archive_conflict["payload"]),
            Err(RuntimeBuildMetaError::AliasConflict("archive_sha256"))
        );
        let missing: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(
            root.join("negative/release-metadata-missing-binary-hash.json"),
        )?)?;
        assert_eq!(
            RuntimeBuildMeta::from_json(&missing["payload"]),
            Err(RuntimeBuildMetaError::MissingField("binary_sha256"))
        );

        let mut unknown = serde_json::json!({"schema_version": 3});
        assert_eq!(
            RuntimeBuildMeta::from_json(&unknown),
            Err(RuntimeBuildMetaError::UnsupportedSchema(3))
        );
        unknown["schema_version"] = serde_json::json!(2);
        assert_eq!(
            RuntimeBuildMeta::from_json(&unknown),
            Err(RuntimeBuildMetaError::MissingField("runtime_version"))
        );
        Ok(())
    }
}
