//! runtime/CLI split-era wire contract (version pinning, compat window, asset reporting).
//!
//! Pure serde data shared by the `rsrs` CLI and the `rsrs-runtime` binary across
//! repository boundaries. The published crate is the single source of truth for
//! these shapes; both consumers must depend on the same released version.

use serde::{Deserialize, Serialize};

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
}

/// Payload of the `assets.status` RPC method: what the runtime is missing, if anything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetsStatus {
    /// True when every required asset is present and hash-verified.
    pub complete: bool,
    pub missing: Vec<AssetRequirement>,
}

/// Published metadata for one runtime build (`runtime-build-<triple>.json`).
///
/// Consumed verbatim by the CLI downloader and client2; `tag` strips to
/// `runtime_version` by dropping the leading `v`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeBuildMeta {
    pub runtime_version: String,
    /// Release tag, e.g. `v1.0.21-dev.1`.
    pub tag: String,
    pub triple: String,
    /// sha256 of `rsrs-runtime-<triple>.tar.gz`.
    pub sha256: String,
    /// Triple-qualified binary name inside the tarball and release inventory,
    /// e.g. `rsrs-runtime-x86_64-pc-windows-msvc.exe`.
    pub binary_file: String,
    /// sha256 of the triple-qualified binary.
    pub binary_sha256: String,
    pub compat: RuntimeCompat,
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let back: RuntimeIdentity = serde_json::from_value(
            serde_json::json!({
                "runtime_version": "1.0.21-dev.1",
                "runtime_compat": {"min_cli": "1.0.20", "max_cli": "*"}
            }),
        )?;
        assert_eq!(back, identity());
        Ok(())
    }

    #[test]
    fn assets_status_defaults_incomplete() -> anyhow::Result<()> {
        let raw = r#"{"complete":false,"missing":[{"name":"bge-m3","suggested_source":"mirror"}]}"#;
        let status: AssetsStatus = serde_json::from_str(raw)?;
        assert!(!status.complete);
        assert_eq!(status.missing.len(), 1);
        assert_eq!(status.missing[0].name, "bge-m3");
        assert!(status.missing[0].version.is_none());
        Ok(())
    }

    #[test]
    fn build_meta_roundtrip() -> anyhow::Result<()> {
        let meta = RuntimeBuildMeta {
            runtime_version: "1.0.21-dev.1".to_owned(),
            tag: "v1.0.21-dev.1".to_owned(),
            triple: "x86_64-pc-windows-msvc".to_owned(),
            sha256: "abc".to_owned(),
            binary_file: "rsrs-runtime-x86_64-pc-windows-msvc.exe".to_owned(),
            binary_sha256: "def".to_owned(),
            compat: RuntimeCompat { min_cli: "1.0.20".to_owned(), max_cli: "*".to_owned() },
        };
        let json = serde_json::to_string(&meta)?;
        let back: RuntimeBuildMeta = serde_json::from_str(&json)?;
        assert_eq!(back, meta);
        assert_eq!(back.tag.trim_start_matches('v'), back.runtime_version);
        Ok(())
    }
}
