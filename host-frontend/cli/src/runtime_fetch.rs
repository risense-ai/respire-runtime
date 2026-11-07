//! Managed `rsrs-runtime` discovery, download and installation for the host CLI.
//!
//! The runtime ships as a separate `rsrs-runtime` binary from the
//! `risense-ai/respire-runtime` repository. This module owns everything the CLI
//! needs to find, verify, download and retire runtime installations:
//!
//! * Discovery order (see [`resolve_runtime_bin`]): explicit `RSRS_RUNTIME_BIN`
//!   override, the managed directory (verified against `runtime.json`), the
//!   portable layout next to the CLI binary, the legacy combined-binary stable
//!   location, and finally an automatic pinned download.
//! * Downloads come from the official release assets with a gh-proxy mirror
//!   fallback (same rule as client2 `mirrorURL` and the model installer's
//!   `RSRS_MIRROR` override). Archives are sha256-verified against the released
//!   `runtime-build-<triple>.json` (`archive_sha256`, with `sha256` as its
//!   legacy alias; `binary_sha256` independently checks the extracted image) and extracted with a strict whitelist (regular
//!   files and directories only, no absolute/`..`/`\`/`:`
//!   paths, bounded sizes, 0700/0600 modes). Release archives name the binary
//!   with the full triple (`rsrs-runtime-<triple>(.exe)`); install placement
//!   renames it to the bare [`RUNTIME_BINARY`] without touching its bytes.
//! * Concurrent first launches (CLI and client2) serialize on the
//!   `<installation_root>/runtime/.install.lock` file lock and the switch into
//!   `<installation_root>/runtime/<version>/` is atomic; the previous version
//!   directory is kept as a rollback point.
//!
//! `runtime-pin.json` (repository root, embedded at build time) selects the
//! download version: `required` is the exact pinned version fetched by
//! [`download_and_install`]; `accept` is a range such as `>=1.0.21-dev.1,<2.0.0`
//! (comma-separated `>=min` / `<max` bounds, min inclusive, max exclusive,
//! compared with the same numeric rules as `respire_client_host::version_cmp`) that
//! an already-installed runtime must satisfy to be reused instead of replaced.
//! Runtime releases publish `runtime-build-<triple>.json` with
//! `{"runtime_version","tag","triple","binary_sha256","binary_file","compat":{"min_cli","max_cli"}}`
//! (`sha256` is an alias for `archive_sha256` only);
//! `compat` states which CLI versions the runtime accepts and is enforced
//! before an archive is installed.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::io::Write;
use std::path::Component;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::model_progress;
use respire_commands::rpc_client::PROTOCOL_V;

/// Release repository that publishes the runtime artifacts.
pub const RUNTIME_REPO: &str = "risense-ai/respire-runtime";
const RELEASE_BASE: &str = "https://github.com";
const MIRROR_PREFIX: &str = "https://gh-proxy.com";

/// Managed runtime binary name for the running platform.
pub const RUNTIME_BINARY: &str = if cfg!(windows) {
    "rsrs-runtime.exe"
} else {
    "rsrs-runtime"
};
/// Binary name of the legacy combined CLI+runtime layout.
pub const LEGACY_COMBINED_BINARY: &str = if cfg!(windows) { "rsrs.exe" } else { "rsrs" };
/// CLI managed-install manifest, next to `<installation_root>/runtime/`.
pub const MANIFEST_FILE: &str = "runtime.json";
/// Per-release integrity manifest shipped inside the archive.
pub const CORE_MANIFEST_FILE: &str = "core-runtime.json";

/// Release archives and `runtime-build-<triple>.json` name the binary with
/// the full triple (`rsrs-runtime-<triple>(.exe)`). The managed layout stores
/// it under the bare [`RUNTIME_BINARY`]; this helper returns the archive-side
/// name for `triple`.
pub fn release_binary_name(triple: &str) -> String {
    let extension = if cfg!(windows) { ".exe" } else { "" };
    format!("rsrs-runtime-{triple}{extension}")
}

/// Release asset triples, aligned with client2's target list plus the musl
/// flavors published by the runtime repository:
/// `x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`, `aarch64-apple-darwin`,
/// `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
/// `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`.
///
/// Note: client2 maps darwin-amd64 releases to the obfuscated asset triple
/// `x86_64-apple-darwin` (a legacy name scramble kept for asset-name
/// compatibility with older clients). That triple is deliberately not part of
/// this list constant; the host selection lives in [`release_triple`], which
/// returns it for `x86_64` Apple platforms so both managers consume the same
/// asset name.
pub const TRIPLES: &[&str] = &[
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
    "aarch64-apple-darwin",
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
];

/// Obfuscated release triple used for darwin-amd64 assets (see [`TRIPLES`]).
pub const DARWIN_AMD64_RELEASE_TRIPLE: &str = "x86_64-apple-darwin";

/// Hard extraction bounds, matching client2 `extractRuntime` exactly.
const MAX_ENTRY_BYTES: u64 = 256 << 20;
const MAX_TOTAL_BYTES: u64 = 512 << 20;
/// Hard cap for the compressed archive transfer itself.
const MAX_ARCHIVE_BYTES: u64 = 512 << 20;
/// Release metadata documents are tiny; refuse anything larger (client2: 2 MiB).
const MAX_METADATA_BYTES: usize = 2 << 20;
// The original metadata JSON is embedded as a string in the atomic selection.
const MAX_MANAGED_MANIFEST_BYTES: u64 = (MAX_METADATA_BYTES * 6 + 64 * 1024) as u64;
/// Concurrent CLI installs serialize on this lock in the existing CLI layout.
const INSTALL_LOCK_WAIT: Duration = Duration::from_secs(120);

/// Build-time embedded pin file (repository root `runtime-pin.json`).
const PIN_JSON: &str = include_str!("../../runtime-pin.json");

// ---------------------------------------------------------------------------
// Version pin and accept range
// ---------------------------------------------------------------------------

/// Inclusive lower / exclusive upper accept bounds parsed from `runtime-pin.json`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptRange {
    min: Option<String>,
    max: Option<String>,
}

impl AcceptRange {
    /// Parse a range such as `>=1.0.21-dev.1,<2.0.0`. Bounds are comma
    /// separated; `>=min` is inclusive, `<max` is exclusive. Empty bounds are
    /// rejected so a typo never silently accepts every version.
    pub fn parse(raw: &str) -> Result<Self> {
        let mut range = Self {
            min: None,
            max: None,
        };
        for part in raw.split(',') {
            let part = part.trim();
            if let Some(min) = part.strip_prefix(">=") {
                anyhow::ensure!(range.min.is_none(), "duplicate accept lower bound");
                anyhow::ensure!(valid_version(min), "invalid accept lower bound: {part:?}");
                range.min = Some(min.to_owned());
            } else if let Some(max) = part.strip_prefix('<') {
                anyhow::ensure!(range.max.is_none(), "duplicate accept upper bound");
                anyhow::ensure!(valid_version(max), "invalid accept upper bound: {part:?}");
                range.max = Some(max.to_owned());
            } else {
                bail!("unsupported accept bound {part:?}; use >=min or <max");
            }
        }
        anyhow::ensure!(
            range.min.is_some() || range.max.is_some(),
            "empty accept range"
        );
        if let (Some(min), Some(max)) = (range.min.as_deref(), range.max.as_deref()) {
            anyhow::ensure!(
                respire_client_host::version_cmp(min, max) == std::cmp::Ordering::Less,
                "accept lower bound is not below its upper bound"
            );
        }
        Ok(range)
    }

    /// True when `version` satisfies every configured bound.
    pub fn contains(&self, version: &str) -> bool {
        let ordering = |bound: &str| semver_cmp(version, bound);
        self.min
            .as_deref()
            .is_none_or(|min| ordering(min) != std::cmp::Ordering::Less)
            && self
                .max
                .as_deref()
                .is_none_or(|max| ordering(max) == std::cmp::Ordering::Less)
    }
}

/// Semver-aware ordering for `M.m.p[-pre]` release names. Core triples
/// compare numerically; a release outranks any prerelease of the same
/// triple; prerelease identifiers compare per semver (numeric numerically,
/// alphanumeric lexically, numeric below alphanumeric).
fn semver_cmp(ours: &str, theirs: &str) -> std::cmp::Ordering {
    fn split(value: &str) -> (Vec<u64>, Option<String>) {
        let (core, pre) = match value.split_once('-') {
            Some((core, pre)) => (core, Some(pre.to_owned())),
            None => (value, None),
        };
        let numbers = core
            .split('.')
            .map(|part| part.parse().unwrap_or(0))
            .collect();
        (numbers, pre)
    }
    let (ours_core, ours_pre) = split(ours);
    let (theirs_core, theirs_pre) = split(theirs);
    let by_core = ours_core.cmp(&theirs_core);
    if by_core != std::cmp::Ordering::Equal {
        return by_core;
    }
    match (ours_pre.as_deref(), theirs_pre.as_deref()) {
        (None, None) => std::cmp::Ordering::Equal,
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(a), Some(b)) => {
            // Numeric identifiers compare numerically; None ranks below any
            // number (the semver numeric-below-alphanumeric rule); two
            // alphanumeric identifiers compare lexically via Option<u64>.
            let rank = |id: &str| id.parse::<u64>().ok();
            let left = a.split('.').map(rank).collect::<Vec<_>>();
            let right = b.split('.').map(rank).collect::<Vec<_>>();
            for (x, y) in left.iter().zip(right.iter()) {
                if x != y {
                    return x.cmp(y);
                }
            }
            left.len().cmp(&right.len())
        }
    }
}

/// The build-time pinned runtime version plus its accept range.
#[derive(Clone, Debug)]
pub struct RuntimePin {
    pub required: String,
    pub accept: AcceptRange,
    /// The raw `accept` expression, for display in inventory output.
    pub accept_raw: String,
}

static PIN: OnceLock<std::result::Result<RuntimePin, String>> = OnceLock::new();

/// Parse the embedded `runtime-pin.json`. Pin errors are cached so every
/// caller reports the same configuration defect.
pub fn pinned() -> Result<&'static RuntimePin> {
    PIN.get_or_init(|| parse_pin(PIN_JSON).map_err(|error| format!("{error:#}")))
        .as_ref()
        .map_err(|error| anyhow::anyhow!("invalid runtime-pin.json: {error}"))
}

fn parse_pin(raw: &str) -> Result<RuntimePin> {
    #[derive(Deserialize)]
    struct PinDocument {
        required: String,
        accept: String,
    }
    let document: PinDocument =
        serde_json::from_str(raw).context("pin document is not valid JSON")?;
    anyhow::ensure!(valid_version(&document.required), "invalid pinned version");
    Ok(RuntimePin {
        required: document.required,
        accept: AcceptRange::parse(&document.accept)?,
        accept_raw: document.accept,
    })
}

/// True when `version` satisfies the build-time accept range.
pub fn version_in_accept(version: &str) -> bool {
    if let Some(selected) = crate::embedding::selection() {
        return version == selected.version();
    }
    pinned().is_ok_and(|pin| pin.accept.contains(version))
}

/// Semver-shaped version charset shared with client2 (`semver.IsValid` plus a
/// separator ban), so version strings are always safe path components.
pub fn valid_version(version: &str) -> bool {
    fn identifier(part: &str) -> bool {
        !part.is_empty()
            && part.split('.').all(|piece| {
                !piece.is_empty()
                    && piece
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
    }
    fn core_and_prerelease(version: &str) -> bool {
        let (core, prerelease) = version.split_once('-').unwrap_or((version, ""));
        let numbers = core.split('.');
        if numbers.clone().count() != 3
            || !numbers
                .clone()
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        {
            return false;
        }
        prerelease.is_empty() || identifier(prerelease)
    }
    match version.split_once('+') {
        Some((core_pre, build)) => {
            !build.is_empty() && identifier(build) && core_and_prerelease(core_pre)
        }
        None => core_and_prerelease(version),
    }
}

/// Release asset triple for the running platform. The darwin-amd64 asset keeps
/// its obfuscated triple name (see [`TRIPLES`]); Linux follows the compiled
/// ABI, with an explicit asset override available through `RSRS_RUNTIME_TRIPLE`.
pub fn release_triple() -> Result<String> {
    if let Ok(raw) = respire_client_host::env::var("RSRS_RUNTIME_TRIPLE") {
        let trimmed = raw.trim();
        anyhow::ensure!(
            TRIPLES.contains(&trimmed),
            "RSRS_RUNTIME_TRIPLE must be one of the published triples"
        );
        return Ok(trimmed.to_owned());
    }
    let triple = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
        ("windows", "aarch64") => "aarch64-pc-windows-msvc",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("macos", "x86_64") => DARWIN_AMD64_RELEASE_TRIPLE,
        ("linux", "x86_64") if cfg!(target_env = "musl") => "x86_64-unknown-linux-musl",
        ("linux", "aarch64") if cfg!(target_env = "musl") => "aarch64-unknown-linux-musl",
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        ("linux", "aarch64") => "aarch64-unknown-linux-gnu",
        _ => bail!("no published rsrs-runtime asset for this platform"),
    };
    Ok(triple.to_owned())
}

// ---------------------------------------------------------------------------
// Managed layout
// ---------------------------------------------------------------------------

/// CLI installation root (`~/.rsrs` unless isolated).
pub fn installation_root() -> PathBuf {
    respire_client_host::paths::main_data_dir()
}

/// Managed runtime directory: `<installation_root>/runtime/`.
pub fn runtime_dir() -> PathBuf {
    if let Some(selected) = crate::embedding::selection() {
        return selected.runtime_dir.clone();
    }
    installation_root().join("runtime")
}

/// Shared manifest read and written by both the CLI and client2.
pub fn manifest_path() -> PathBuf {
    if let Some(selected) = crate::embedding::selection() {
        return selected.manifest_path.clone();
    }
    installation_root().join(MANIFEST_FILE)
}

/// Installed version directory: `<installation_root>/runtime/<version>/`.
pub fn version_dir(version: &str) -> PathBuf {
    runtime_dir().join(version)
}

/// Expected managed binary path for `version`.
pub fn managed_binary_path(version: &str) -> PathBuf {
    version_dir(version).join(RUNTIME_BINARY)
}

/// CLI version selection in `<installation_root>/runtime.json`. Existing
/// version/hash fields remain readable; reuse also requires the release proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManagedManifest {
    pub version: String,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release: Option<ReleaseProof>,
}

/// Exact metadata accepted from the official release or a trusted offline file.
/// Its digest and full file inventory travel with the atomic version selection.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseProof {
    pub metadata_sha256: String,
    pub metadata_json: String,
}

/// Callers must propagate this error instead of falling back to a serve shim.
#[derive(Debug)]
pub struct ManagedRuntimeRepairRequired;

impl std::fmt::Display for ManagedRuntimeRepairRequired {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("repair required: managed Runtime integrity verification failed")
    }
}

impl std::error::Error for ManagedRuntimeRepairRequired {}

/// An automatic install must not select a new protocol for an unbound old owner.
#[derive(Debug)]
pub struct LegacyRuntimeMigrationRequired;

impl std::fmt::Display for LegacyRuntimeMigrationRequired {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("legacy_runtime_migration_required: automatic Runtime replacement is blocked; the existing CLI, Runtime selection and data were preserved; keep using the existing client until a compatible host migration is available")
    }
}

impl std::error::Error for LegacyRuntimeMigrationRequired {}

impl ManagedManifest {
    fn from_release(metadata: &BuildMetadata, bytes: &[u8]) -> Result<Self> {
        let manifest = Self {
            version: metadata.runtime_version.clone(),
            sha256: metadata.binary_sha256()?.to_owned(),
            release: Some(ReleaseProof {
                metadata_sha256: hex::encode(Sha256::digest(bytes)),
                metadata_json: std::str::from_utf8(bytes)?.to_owned(),
            }),
        };
        manifest.bound_metadata(metadata.target_triple()?)?;
        Ok(manifest)
    }

    fn bound_metadata(&self, triple: &str) -> Result<BuildMetadata> {
        let proof = self.release.as_ref().context(
            "repair required: managed Runtime has no complete release proof; \
             reinstall with trusted schema-2 metadata and the complete archive",
        )?;
        anyhow::ensure!(
            proof.metadata_json.len() <= MAX_METADATA_BYTES
                && valid_sha256(&proof.metadata_sha256)
                && hex::encode(Sha256::digest(proof.metadata_json.as_bytes()))
                    .eq_ignore_ascii_case(&proof.metadata_sha256),
            "managed Runtime release metadata digest mismatch"
        );
        let metadata: BuildMetadata = serde_json::from_str(&proof.metadata_json)?;
        anyhow::ensure!(
            metadata.schema_version == 2,
            "repair required: legacy release metadata does not prove the complete resource set"
        );
        metadata.validate(&self.version, triple)?;
        anyhow::ensure!(
            metadata
                .files
                .iter()
                .any(|file| file.path == CORE_MANIFEST_FILE),
            "repair required: release proof does not authenticate core-runtime.json"
        );
        anyhow::ensure!(
            metadata.binary_sha256()?.eq_ignore_ascii_case(&self.sha256),
            "managed Runtime selection disagrees with its release proof"
        );
        Ok(metadata)
    }
}

/// Read the managed manifest without validating the binary on disk.
pub fn read_manifest() -> Result<Option<ManagedManifest>> {
    if let Some(selected) = crate::embedding::selection() {
        let runtime = selected.verify()?;
        // The embedding verifies Client2's selection and inventory. Do not invent
        // an official release proof for that independently validated layout.
        return Ok(Some(ManagedManifest {
            version: runtime.version().to_owned(),
            sha256: runtime.sha256().to_owned(),
            release: None,
        }));
    }
    let path = manifest_path();
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.len() <= MAX_MANAGED_MANIFEST_BYTES,
        "repair required: invalid runtime manifest"
    );
    let manifest: ManagedManifest = serde_json::from_slice(&fs::read(&path)?)
        .context("repair required: invalid runtime manifest")?;
    anyhow::ensure!(
        valid_version(&manifest.version) && valid_sha256(&manifest.sha256),
        "repair required: invalid runtime manifest"
    );
    Ok(Some(manifest))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn safe_metadata_path(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= 1024
        && !raw.contains(['\\', ':'])
        && raw.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && {
                    let stem = part.split('.').next().unwrap_or(part).to_ascii_uppercase();
                    !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                        && !(stem.len() == 4
                            && (stem.starts_with("COM") || stem.starts_with("LPT"))
                            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
                }
                && !part.ends_with(['.', ' '])
                && !part.chars().any(char::is_control)
        })
        && Path::new(raw)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn validate_installed(manifest: &ManagedManifest) -> Result<PathBuf> {
    if let Some(selected) = crate::embedding::selection() {
        let runtime = selected.verify()?;
        anyhow::ensure!(manifest.version == runtime.version()
            && manifest.sha256.eq_ignore_ascii_case(runtime.sha256()),
            "embedded Runtime differs from its selected manifest");
        return Ok(runtime.path().to_path_buf());
    }
    (|| {
        let triple = release_triple()?;
        let metadata = manifest.bound_metadata(&triple)?;
        let directory = version_dir(&manifest.version);
        // Authenticate core-runtime.json before trusting its resource declarations.
        metadata.verify_files(&directory)?;
        verify_stage(&directory, RUNTIME_BINARY, &triple, &manifest.sha256)
    })()
    .context(ManagedRuntimeRepairRequired)
}

/// The managed binary the running CLI should currently use, if any. Used by
/// lifecycle checks to compare a live runtime's reported executable path.
pub fn managed_runtime_path() -> Result<Option<PathBuf>> {
    match read_manifest().context(ManagedRuntimeRepairRequired)? {
        Some(manifest) => Ok(Some(validate_installed(&manifest)?)),
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// Outcome of [`resolve_runtime_bin`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolvedRuntime {
    /// A verified `rsrs-runtime` executable, ready to spawn.
    Ready(PathBuf),
    /// A legacy combined `rsrs` binary occupies the old stable location and no
    /// usable runtime was found first. Automatic replacement requires proving
    /// this is the current CLI image, not an old combined service.
    LegacyCombined(PathBuf),
}

/// Discover the runtime binary, downloading the pinned release when nothing
/// usable is installed.
///
/// Order: `RSRS_RUNTIME_BIN` (explicit override, no integrity check), the
/// managed directory (version within the accept range plus binary sha256
/// verified), the portable layout next to this CLI binary, the legacy combined
/// stable location, and finally [`download_and_install`].
pub fn resolve_runtime_bin() -> Result<ResolvedRuntime> {
    if let Some(selected) = crate::embedding::selection() {
        return Ok(ResolvedRuntime::Ready(selected.verify()?.path().to_path_buf()));
    }
    if let Ok(raw) = respire_client_host::env::var("RSRS_RUNTIME_BIN") {
        let explicit = PathBuf::from(raw.trim());
        anyhow::ensure!(
            !explicit.as_os_str().is_empty(),
            "RSRS_RUNTIME_BIN is empty"
        );
        anyhow::ensure!(explicit.is_file(), "RSRS_RUNTIME_BIN does not name a file");
        return Ok(ResolvedRuntime::Ready(explicit));
    }
    if let Some(manifest) = read_manifest().context(ManagedRuntimeRepairRequired)? {
        let binary = validate_installed(&manifest)?;
        if version_in_accept(&manifest.version) {
            return Ok(ResolvedRuntime::Ready(binary));
        }
    }
    if let Ok(self_exe) = std::env::current_exe() {
        if let Some(portable) = self_exe.parent() {
            let candidate = portable.join(RUNTIME_BINARY);
            if candidate.is_file() {
                return Ok(ResolvedRuntime::Ready(candidate));
            }
        }
    }
    let legacy = respire_client_host::paths::bin_dir().join(LEGACY_COMBINED_BINARY);
    if legacy.is_file() {
        return Ok(ResolvedRuntime::LegacyCombined(legacy));
    }
    Ok(ResolvedRuntime::Ready(download_and_install(None, None)?))
}

// ---------------------------------------------------------------------------
// Release metadata and download sources
// ---------------------------------------------------------------------------

/// `compat` block of `runtime-build-<triple>.json`: which CLI versions the
/// runtime release accepts.
#[derive(Clone, Debug, Deserialize)]
pub struct CompatBounds {
    pub min_cli: String,
    pub max_cli: String,
}

/// Released runtime build metadata consumed by the CLI downloader and client2.
#[derive(Clone, Debug, Deserialize)]
pub struct BuildMetadata {
    pub schema_version: u64,
    pub runtime_version: String,
    pub tag: String,
    #[serde(default, deserialize_with = "deserialize_metadata_string")]
    pub triple: Option<String>,
    #[serde(default, deserialize_with = "deserialize_metadata_string")]
    pub target_triple: Option<String>,
    #[serde(default, deserialize_with = "deserialize_metadata_string")]
    pub archive_file: Option<String>,
    /// Legacy archive checksum field; it must agree with `archive_sha256`.
    #[serde(default, deserialize_with = "deserialize_metadata_string")]
    pub sha256: Option<String>,
    #[serde(default, deserialize_with = "deserialize_metadata_string")]
    pub archive_sha256: Option<String>,
    #[serde(default)]
    pub binary_sha256: String,
    #[serde(default, deserialize_with = "deserialize_metadata_string")]
    pub source_commit: Option<String>,
    /// Archive-side binary file name, the full-triple name.
    pub binary_file: String,
    pub compat: CompatBounds,
    #[serde(default)]
    pub protocol_range: Option<ProtocolRange>,
    #[serde(default, deserialize_with = "deserialize_capabilities")]
    pub capabilities: BTreeMap<String, String>,
    #[serde(default)]
    pub files: Vec<BuildFile>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ProtocolRange {
    pub minimum: u32,
    pub maximum: u32,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BuildFile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

fn deserialize_metadata_string<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Some)
}

fn deserialize_capabilities<'de, D>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Capabilities;
    impl<'de> serde::de::Visitor<'de> for Capabilities {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("unique capability names")
        }
        fn visit_map<M>(self, mut access: M) -> std::result::Result<Self::Value, M::Error>
        where
            M: serde::de::MapAccess<'de>,
        {
            let mut values = BTreeMap::new();
            while let Some((name, version)) = access.next_entry::<String, String>()? {
                if values.insert(name, version).is_some() {
                    return Err(serde::de::Error::custom("duplicate runtime capability"));
                }
            }
            Ok(values)
        }
    }
    deserializer.deserialize_map(Capabilities)
}

impl BuildMetadata {
    /// Resolve the legacy `triple` alias without mixing different values.
    fn target_triple(&self) -> Result<&str> {
        match (self.triple.as_deref(), self.target_triple.as_deref()) {
            (Some(legacy), Some(canonical)) => {
                anyhow::ensure!(
                    legacy == canonical,
                    "release metadata carries conflicting target triples"
                );
                Ok(legacy)
            }
            (Some(value), None) | (None, Some(value)) => Ok(value),
            (None, None) => bail!("release metadata has no target triple"),
        }
    }

    /// Resolve the archive digest. In schema 1, legacy `sha256` is an archive
    /// digest; it must never be reused as the unpacked binary digest.
    fn archive_sha256(&self) -> Result<&str> {
        match (self.sha256.as_deref(), self.archive_sha256.as_deref()) {
            (Some(legacy), Some(canonical)) => {
                anyhow::ensure!(
                    legacy == canonical,
                    "release metadata carries conflicting archive checksums"
                );
                Ok(legacy)
            }
            (Some(value), None) | (None, Some(value)) => Ok(value),
            (None, None) => bail!("release metadata has no archive sha256"),
        }
    }

    fn binary_sha256(&self) -> Result<&str> {
        anyhow::ensure!(
            !self.binary_sha256.is_empty(),
            "release metadata has no binary sha256"
        );
        Ok(&self.binary_sha256)
    }

    fn validate(&self, required: &str, triple: &str) -> Result<()> {
        anyhow::ensure!(
            self.schema_version == 1 || self.schema_version == 2,
            "unsupported runtime metadata schema {}",
            self.schema_version
        );
        anyhow::ensure!(
            valid_version(&self.runtime_version) && self.runtime_version == required,
            "release metadata targets runtime {}, expected {required}",
            self.runtime_version
        );
        anyhow::ensure!(
            self.tag == format!("v{required}"),
            "release metadata has an invalid tag"
        );
        anyhow::ensure!(
            self.target_triple()? == triple,
            "release metadata targets triple {}, expected {triple}",
            self.target_triple()?
        );
        anyhow::ensure!(
            valid_sha256(self.binary_sha256()?),
            "release metadata has an invalid sha256"
        );
        anyhow::ensure!(
            self.binary_file == release_binary_name(triple),
            "release metadata names an unexpected binary file: {}",
            self.binary_file
        );
        anyhow::ensure!(
            valid_sha256(self.archive_sha256()?),
            "release metadata has an invalid archive sha256"
        );
        let archive_name = format!("rsrs-runtime-{triple}.tar.gz");
        match self.archive_file.as_deref() {
            Some(name) => anyhow::ensure!(
                name == archive_name,
                "release metadata names an unexpected archive: {name}"
            ),
            None => anyhow::ensure!(
                self.schema_version == 1,
                "release metadata is missing archive_file"
            ),
        }
        if self.schema_version == 2 {
            self.validate_schema2()?;
        }
        let cli = env!("CARGO_PKG_VERSION");
        anyhow::ensure!(
            valid_version(&self.compat.min_cli),
            "release metadata has an invalid compat range"
        );
        anyhow::ensure!(
            self.compat.max_cli == "*" || valid_version(&self.compat.max_cli),
            "release metadata has an invalid compat range"
        );
        anyhow::ensure!(
            respire_client_host::version_cmp(cli, &self.compat.min_cli) != std::cmp::Ordering::Less,
            "runtime {} requires CLI >= {}; upgrade the CLI first",
            self.runtime_version,
            self.compat.min_cli
        );
        anyhow::ensure!(
            self.compat.max_cli == "*"
                || respire_client_host::version_cmp(cli, &self.compat.max_cli)
                    == std::cmp::Ordering::Less,
            "runtime {} only accepts CLI versions below {}; upgrade the runtime explicitly",
            self.runtime_version,
            self.compat.max_cli
        );
        Ok(())
    }

    fn validate_schema2(&self) -> Result<()> {
        let commit = self
            .source_commit
            .as_deref()
            .context("release metadata is missing source_commit")?;
        anyhow::ensure!(
            commit.len() == 40
                && commit
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "release metadata has an invalid source_commit"
        );
        let protocol = self
            .protocol_range
            .as_ref()
            .context("release metadata is missing protocol_range")?;
        anyhow::ensure!(
            protocol.minimum > 0
                && protocol.maximum >= protocol.minimum
                && protocol.minimum <= PROTOCOL_V
                && PROTOCOL_V <= protocol.maximum,
            "runtime protocol range does not include CLI protocol {PROTOCOL_V}"
        );
        for capability in ["business_executor", "mcp_server"] {
            anyhow::ensure!(
                self.capabilities.get(capability).map(String::as_str) == Some("1"),
                "runtime release does not advertise {capability} version 1"
            );
        }
        anyhow::ensure!(
            !self.files.is_empty() && self.files.len() <= 4096,
            "release metadata has an invalid file count"
        );

        let mut paths = BTreeSet::new();
        let mut binary_seen = false;
        let mut total_size = 0u64;
        let binary_hash = self.binary_sha256()?;
        for file in &self.files {
            anyhow::ensure!(
                safe_metadata_path(&file.path),
                "unsafe release metadata path: {}",
                file.path
            );
            anyhow::ensure!(
                paths.insert(file.path.to_ascii_lowercase()),
                "duplicate release metadata path: {}",
                file.path
            );
            anyhow::ensure!(
                file.size > 0 && file.size <= MAX_ENTRY_BYTES,
                "release metadata file has invalid size: {}",
                file.path
            );
            anyhow::ensure!(
                valid_sha256(&file.sha256),
                "invalid release metadata sha256: {}",
                file.path
            );
            total_size += file.size;
            anyhow::ensure!(
                total_size <= MAX_TOTAL_BYTES,
                "release files exceed extraction limit"
            );
            if file.path == self.binary_file {
                anyhow::ensure!(
                    file.sha256.eq_ignore_ascii_case(binary_hash),
                    "release metadata files disagree with the binary digest"
                );
                binary_seen = true;
            }
        }
        anyhow::ensure!(
            binary_seen,
            "release metadata files omit the runtime binary"
        );
        Ok(())
    }

    fn verify_files(&self, stage: &Path) -> Result<()> {
        if self.schema_version < 2 {
            return Ok(());
        }
        let mut expected = BTreeSet::new();
        for file in &self.files {
            let name = if file.path == self.binary_file && !stage.join(&file.path).exists() {
                RUNTIME_BINARY
            } else {
                file.path.as_str()
            };
            expected.insert(stage.join(name));
            let path = regular_install_file(stage, name)?;
            let metadata = fs::symlink_metadata(&path)
                .with_context(|| format!("release file is missing: {}", file.path))?;
            anyhow::ensure!(
                metadata.is_file(),
                "release file is not a regular file: {}",
                file.path
            );
            anyhow::ensure!(
                metadata.len() == file.size,
                "release file size mismatch: {}",
                file.path
            );
            let actual = sha256_file(&path)?;
            anyhow::ensure!(
                actual.eq_ignore_ascii_case(&file.sha256),
                "release file checksum mismatch: {}",
                file.path
            );
        }
        // Version directories are immutable payloads. Extra files must not
        // become loader inputs outside the authenticated release inventory.
        let mut directories = vec![stage.to_path_buf()];
        let mut entries = 0usize;
        while let Some(directory) = directories.pop() {
            for entry in fs::read_dir(directory)? {
                let entry = entry?;
                entries += 1;
                anyhow::ensure!(entries <= 4096, "installed runtime has too many entries");
                let kind = entry.file_type()?;
                if kind.is_dir() {
                    directories.push(entry.path());
                } else {
                    anyhow::ensure!(
                        kind.is_file() && expected.remove(&entry.path()),
                        "unexpected runtime payload entry: {}",
                        entry.path().display()
                    );
                }
            }
        }
        anyhow::ensure!(expected.is_empty(), "runtime release files disappeared");
        Ok(())
    }
}

fn release_asset(origin: &str, path: &str) -> String {
    format!("{origin}/{RUNTIME_REPO}/releases/download/{path}")
}

/// Normalize a user-supplied mirror into a prefix origin, using the same rules
/// as the model installer: http/https origin only, bare hosts default to
/// https, and credentials, paths, queries or fragments are rejected.
fn mirror_origin(raw: &str) -> Result<String> {
    anyhow::ensure!(!raw.trim().is_empty(), "--mirror must not be empty");
    let with_scheme = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("https://{}", raw.trim())
    };
    let parsed = url::Url::parse(&with_scheme).context("--mirror is invalid")?;
    anyhow::ensure!(
        matches!(parsed.scheme(), "http" | "https"),
        "--mirror only supports http/https"
    );
    anyhow::ensure!(
        parsed.username().is_empty() && parsed.password().is_none(),
        "--mirror must be an origin without credentials"
    );
    anyhow::ensure!(
        parsed.query().is_none() && parsed.fragment().is_none(),
        "--mirror must be an origin without query or fragment"
    );
    anyhow::ensure!(
        matches!(parsed.path(), "" | "/"),
        "--mirror must be an origin without a path"
    );
    let host = parsed.host_str().context("--mirror is missing a host")?;
    let origin = format!("{}://{}", parsed.scheme(), host);
    if let Some(port) = parsed.port() {
        return Ok(format!("{origin}:{port}"));
    }
    Ok(origin)
}

/// Download origins in fallback order: an explicit mirror (or `RSRS_MIRROR`)
/// is tried first and the official source last; without an override the
/// official source is tried first and the gh-proxy mirror last, matching
/// client2 `mirrorURL`.
fn download_origins(mirror: Option<&str>) -> Result<Vec<String>> {
    let official = RELEASE_BASE.to_owned();
    let proxied = format!("{MIRROR_PREFIX}/{official}");
    let setting = match mirror {
        Some(value) => Some(value.to_owned()),
        None => respire_client_host::settings::mirror_from_env()?,
    }
    .filter(|value| !value.trim().is_empty());
    match setting {
        Some(value) => {
            let origin = mirror_origin(value.trim())?;
            anyhow::ensure!(
                origin == MIRROR_PREFIX || origin == RELEASE_BASE,
                "runtime mirror is not approved"
            );
            let mirrored = if origin == RELEASE_BASE {
                official.clone()
            } else {
                format!("{origin}/{official}")
            };
            if mirrored == official {
                Ok(vec![official])
            } else {
                Ok(vec![mirrored, official])
            }
        }
        None => Ok(vec![official, proxied]),
    }
}

#[derive(Clone, Copy)]
struct DownloadTimeouts {
    connect: Duration,
    read: Duration,
    write: Duration,
}

impl Default for DownloadTimeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(10),
            read: Duration::from_secs(30),
            write: Duration::from_secs(10),
        }
    }
}

fn download_agent(timeouts: DownloadTimeouts) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(timeouts.connect)
        .timeout_read(timeouts.read)
        .timeout_write(timeouts.write)
        .build()
}

/// Fetch a small release metadata document, bounded like client2 `fetchJSON`.
fn fetch_metadata(url: &str) -> Result<Vec<u8>> {
    let response = download_agent(DownloadTimeouts::default())
        .get(url)
        .timeout(Duration::from_secs(30))
        .call()
        .with_context(|| format!("release metadata request failed ({url})"))?;
    let mut reader = response.into_reader().take((MAX_METADATA_BYTES + 1) as u64);
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .context("release metadata read failed")?;
    anyhow::ensure!(
        bytes.len() <= MAX_METADATA_BYTES,
        "release metadata too large"
    );
    Ok(bytes)
}

/// Stream the release archive into `dest` while hashing it. Returns the hex
/// sha256 of the received bytes. A failed transfer leaves no retry state; the
/// caller decides whether to try the next origin.
fn download_archive(url: &str, dest: &Path) -> Result<String> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let item = dest.file_name().unwrap_or_default().to_string_lossy();
    model_progress::update("connect", &item, 0, None)?;
    let response = download_agent(DownloadTimeouts::default())
        .get(url)
        .set("Accept-Encoding", "identity")
        .call()
        .with_context(|| format!("download failed ({url})"))?;
    model_progress::check()?;
    let mut reader = response.into_reader();
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(dest)
        .with_context(|| format!("failed to create {}", dest.display()))?;
    let mut hasher = Sha256::new();
    let mut written: u64 = 0;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buf)
            .with_context(|| format!("download interrupted ({url})"))?;
        if read == 0 {
            break;
        }
        model_progress::check()?;
        written += read as u64;
        anyhow::ensure!(
            written <= MAX_ARCHIVE_BYTES,
            "release archive exceeds the {}-byte limit",
            MAX_ARCHIVE_BYTES
        );
        hasher.update(&buf[..read]);
        file.write_all(&buf[..read])
            .with_context(|| format!("failed to write {}", dest.display()))?;
        model_progress::update("download", &item, written, None)?;
    }
    file.flush()
        .with_context(|| format!("failed to write {}", dest.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to flush {}", dest.display()))?;
    drop(file);
    model_progress::update("verify", &item, written, Some(written))?;
    Ok(hex::encode(hasher.finalize()))
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        fs::File::open(path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buf)
            .with_context(|| format!("failed to read {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

// ---------------------------------------------------------------------------
// Whitelist archive extraction (client2 `extractRuntime` semantics)
// ---------------------------------------------------------------------------

fn regular_install_file(root: &Path, name: &str) -> Result<PathBuf> {
    anyhow::ensure!(safe_metadata_path(name), "unsafe install path: {name}");
    anyhow::ensure!(
        fs::symlink_metadata(root)?.is_dir(),
        "installation root is not a directory"
    );
    let mut path = root.to_path_buf();
    let mut parts = name.split('/').peekable();
    while let Some(part) = parts.next() {
        path.push(part);
        let metadata = fs::symlink_metadata(&path)?;
        anyhow::ensure!(
            if parts.peek().is_some() {
                metadata.is_dir()
            } else {
                metadata.is_file()
            },
            "install path contains a link or unsupported file: {}",
            path.display()
        );
    }
    Ok(path)
}

fn safe_entry_name(raw: &str) -> Option<String> {
    let name = raw.strip_prefix("./").unwrap_or(raw).trim_end_matches('/');
    safe_metadata_path(name).then(|| name.to_owned())
}

struct TarHeader {
    name: String,
    size: u64,
    typeflag: u8,
    mode: u64,
}

fn octal_field(field: &[u8]) -> Result<u64> {
    anyhow::ensure!(
        field.first().is_none_or(|byte| byte & 0x80 == 0),
        "archive uses unsupported base-256 header fields"
    );
    let text = String::from_utf8_lossy(field);
    let trimmed = text.trim_matches(|c| c == ' ' || c == '\0');
    anyhow::ensure!(!trimmed.is_empty(), "archive header field is empty");
    u64::from_str_radix(trimmed, 8).context("archive header field is not valid octal")
}

fn c_string_field(field: &[u8]) -> String {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

fn verify_header_checksum(header: &[u8; 512]) -> Result<()> {
    let stored = octal_field(&header[148..156])?;
    let mut sum: u64 = 0;
    for (index, byte) in header.iter().enumerate() {
        sum += if (148..156).contains(&index) {
            u64::from(b' ')
        } else {
            u64::from(*byte)
        };
    }
    anyhow::ensure!(sum == stored, "archive header checksum mismatch");
    Ok(())
}

/// Parse plain ustar headers. Extensions, links and special files are rejected.
fn parse_header(header: &[u8; 512]) -> Result<Option<TarHeader>> {
    if header.iter().all(|byte| *byte == 0) {
        return Ok(None);
    }
    anyhow::ensure!(
        &header[257..262] == b"ustar",
        "archive is not a ustar tarball"
    );
    verify_header_checksum(header)?;
    let typeflag = header[156];
    anyhow::ensure!(
        matches!(typeflag, b'0' | 0 | b'5'),
        "archive contains unsupported links or special files"
    );
    let mut name = c_string_field(&header[0..100]);
    let prefix = c_string_field(&header[345..500]);
    if !prefix.is_empty() {
        name = format!("{prefix}/{name}");
    }
    Ok(Some(TarHeader {
        name,
        size: octal_field(&header[124..136])?,
        mode: octal_field(&header[100..108])?,
        typeflag,
    }))
}

/// Extract a gzipped tar archive into `dest` with the client2 whitelist:
/// directories and regular files only, per-entry 256 MiB and total 512 MiB
/// caps, directory mode 0700 and file mode 0600 (0700 when any execute bit is
/// set in the archive).
fn extract_archive(archive: &Path, dest: &Path) -> Result<()> {
    let file =
        fs::File::open(archive).with_context(|| format!("failed to read {}", archive.display()))?;
    let mut reader = flate2::read::MultiGzDecoder::new(file);
    create_private_dir(dest)?;
    let mut paths = BTreeSet::new();
    let mut entries = 0usize;
    let mut total: u64 = 0;
    let mut payload = [0u8; 64 * 1024];
    loop {
        let mut header = [0u8; 512];
        read_exact_bounded(&mut reader, &mut header, archive)?;
        let entry = match parse_header(&header)? {
            Some(entry) => entry,
            None => {
                let mut trailer = Vec::new();
                reader.take((1 << 20) + 1).read_to_end(&mut trailer)?;
                anyhow::ensure!(
                    trailer.len() >= 512
                        && trailer.len() <= 1 << 20
                        && trailer.iter().all(|byte| *byte == 0),
                    "invalid archive trailer"
                );
                break;
            }
        };
        // client2 skips plain "./" directory markers and rejects every other
        // name that fails the whitelist.
        entries += 1;
        anyhow::ensure!(entries <= 4096, "runtime archive has too many entries");
        let bare = entry
            .name
            .strip_prefix("./")
            .unwrap_or(&entry.name)
            .trim_end_matches('/');
        if bare.is_empty() || bare == "." {
            anyhow::ensure!(
                entry.typeflag == b'5' && entry.size == 0,
                "unsafe archive path: {}",
                entry.name
            );
            continue;
        }
        let Some(name) = safe_entry_name(&entry.name) else {
            bail!("unsafe archive path: {}", entry.name);
        };
        anyhow::ensure!(
            entry.size <= MAX_ENTRY_BYTES && total + entry.size <= MAX_TOTAL_BYTES,
            "runtime archive exceeds extraction limit"
        );
        anyhow::ensure!(
            paths.insert(name.to_ascii_lowercase()),
            "duplicate archive path: {name}"
        );
        let mut parent = dest.to_path_buf();
        for component in name
            .split('/')
            .take(name.split('/').count().saturating_sub(1))
        {
            parent.push(component);
            match fs::symlink_metadata(&parent) {
                Ok(metadata) => anyhow::ensure!(
                    metadata.is_dir(),
                    "archive parent is a link or non-directory"
                ),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        let target = dest.join(&name);
        if entry.typeflag == b'5' {
            anyhow::ensure!(entry.size == 0, "archive directory contains data");
            create_private_dir(&target)?;
            continue;
        }
        if let Some(parent) = target.parent() {
            create_private_dir(parent)?;
        }
        let mut out = {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(if entry.mode & 0o111 != 0 {
                    0o700
                } else {
                    0o600
                });
            }
            options.open(&target)
        }
        .with_context(|| format!("failed to create {}", target.display()))?;
        let mut remaining = entry.size;
        while remaining > 0 {
            let chunk = remaining.min(payload.len() as u64) as usize;
            read_exact_bounded(&mut reader, &mut payload[..chunk], archive)?;
            out.write_all(&payload[..chunk])
                .with_context(|| format!("failed to write {}", target.display()))?;
            total += chunk as u64;
            remaining -= chunk as u64;
        }
        out.flush()
            .with_context(|| format!("failed to write {}", target.display()))?;
        out.sync_all()
            .with_context(|| format!("failed to flush {}", target.display()))?;
        drop(out);
        // Entries are padded to whole 512-byte blocks.
        let padding = (512 - (entry.size % 512)) % 512;
        if padding > 0 {
            let mut skip = [0u8; 512];
            read_exact_bounded(&mut reader, &mut skip[..padding as usize], archive)?;
        }
    }
    Ok(())
}

fn create_private_dir(dir: &Path) -> Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(metadata) => anyhow::ensure!(
            metadata.is_dir(),
            "private directory is a link or non-directory"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    fs::create_dir_all(dir)
        .with_context(|| format!("failed to create directory {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to set mode on {}", dir.display()))?;
    }
    #[cfg(windows)]
    let _ = dir;
    Ok(())
}

fn read_exact_bounded(reader: &mut impl Read, buf: &mut [u8], archive: &Path) -> Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let read = reader
            .read(&mut buf[filled..])
            .with_context(|| format!("failed to read {}", archive.display()))?;
        if read == 0 {
            bail!("archive is truncated: {}", archive.display());
        }
        filled += read;
    }
    Ok(())
}

/// `core-runtime.json` shipped inside each release archive.
#[derive(Debug, Deserialize)]
struct CoreManifest {
    schema_version: u32,
    target: String,
    files: Vec<CoreManifestFile>,
}

#[derive(Debug, Deserialize)]
struct CoreManifestFile {
    path: String,
    sha256: String,
}

/// Verify the extracted stage against the shipped manifest and the expected
/// binary hash (client2 `verifyRuntime` semantics). `binary_file` is the
/// archive-side binary name inside `stage`.
fn verify_stage(
    stage: &Path,
    binary_file: &str,
    triple: &str,
    binary_hash: &str,
) -> Result<PathBuf> {
    let binary = regular_install_file(stage, binary_file)?;
    let actual = sha256_file(&binary)?;
    anyhow::ensure!(
        actual.eq_ignore_ascii_case(binary_hash),
        "runtime checksum mismatch: expected {binary_hash}, found {actual}"
    );
    let manifest_path = regular_install_file(stage, CORE_MANIFEST_FILE)?;
    anyhow::ensure!(
        manifest_path.is_file(),
        "archive did not contain {}",
        CORE_MANIFEST_FILE
    );
    anyhow::ensure!(
        fs::metadata(&manifest_path)?.len() <= MAX_METADATA_BYTES as u64,
        "runtime manifest is too large"
    );
    let bytes = fs::read(&manifest_path)?;
    let manifest: CoreManifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid {} manifest", CORE_MANIFEST_FILE))?;
    anyhow::ensure!(
        manifest.schema_version == 1 && manifest.target == triple && !manifest.files.is_empty(),
        "invalid {} manifest",
        CORE_MANIFEST_FILE
    );
    let mut paths = BTreeSet::new();
    anyhow::ensure!(
        manifest.files.len() <= 4096,
        "runtime manifest has too many files"
    );
    for file in &manifest.files {
        anyhow::ensure!(
            paths.insert(file.path.to_ascii_lowercase()),
            "duplicate runtime manifest path: {}",
            file.path
        );
        anyhow::ensure!(
            safe_metadata_path(&file.path),
            "unsafe runtime manifest path: {}",
            file.path
        );
        anyhow::ensure!(
            valid_sha256(&file.sha256),
            "invalid runtime manifest checksum"
        );
        let target = regular_install_file(stage, &file.path)?;
        anyhow::ensure!(
            target.is_file(),
            "runtime manifest file is missing: {}",
            file.path
        );
        let actual = sha256_file(&target)?;
        anyhow::ensure!(
            actual.eq_ignore_ascii_case(&file.sha256),
            "runtime checksum mismatch: {}",
            file.path
        );
    }
    Ok(binary)
}

/// Install placement: release archives name the binary with the full triple,
/// but the managed layout stores it under the bare [`RUNTIME_BINARY`]. The
/// rename stays inside the staging directory and never changes file bytes, so
/// the verified checksum still applies.
fn place_managed_binary(stage: &Path, binary_file: &str) -> Result<()> {
    if binary_file == RUNTIME_BINARY {
        return Ok(());
    }
    anyhow::ensure!(
        safe_entry_name(binary_file).is_some(),
        "unexpected release binary name: {}",
        binary_file
    );
    let full = stage.join(binary_file);
    anyhow::ensure!(full.is_file(), "archive did not contain {}", binary_file);
    let bare = stage.join(RUNTIME_BINARY);
    anyhow::ensure!(
        !bare.exists(),
        "archive contains both release and managed binary names"
    );
    fs::rename(&full, &bare).with_context(|| format!("failed to place {}", bare.display()))
}

// ---------------------------------------------------------------------------
// Install transactions
// ---------------------------------------------------------------------------

fn install_lock() -> Result<respire_client_host::lock::LibraryLock> {
    respire_client_host::lock::LibraryLock::acquire(&runtime_dir().join(".install.lock"), INSTALL_LOCK_WAIT)
        .context("another process is installing the runtime")
}

fn publish_manifest(manifest: &ManagedManifest) -> Result<()> {
    let path = manifest_path();
    let bytes = serde_json::to_vec_pretty(manifest)?;
    let temporary = installation_root().join(format!(".runtime-manifest-{}", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            let mut file = options.open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        if path.is_file() {
            respire_spawn::durable::replace_file(&temporary, &path)?;
        } else {
            respire_spawn::durable::publish_new_file(&temporary, &path)?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// Publish a staged version directory atomically. An existing directory with
/// the identical build is reused; a different build occupying the same version
/// fails loudly instead of being overwritten.
fn adopt_or_verify_version_dir(stage: &Path, manifest: &ManagedManifest) -> Result<PathBuf> {
    let dest = version_dir(&manifest.version);
    if dest.is_dir() {
        // An explicit install may repair a legacy selection only after verifying
        // the existing bytes against the newly supplied trusted release proof.
        return validate_installed(manifest)
            .context("a different build already occupies this runtime version");
    }
    // Renaming stays inside <runtime/>, so it is atomic on every platform.
    fs::rename(stage, &dest).with_context(|| format!("failed to publish {}", dest.display()))?;
    respire_spawn::durable::sync_directory(&runtime_dir()).ok();
    Ok(dest.join(RUNTIME_BINARY))
}

fn staging_dir() -> Result<PathBuf> {
    create_private_dir(&runtime_dir())?;
    let stage = runtime_dir().join(format!(".download-{}", uuid::Uuid::new_v4()));
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(&stage)
        .with_context(|| format!("failed to create {}", stage.display()))?;
    Ok(stage)
}

fn is_progress_abort(error: &anyhow::Error) -> bool {
    error.is::<LegacyRuntimeMigrationRequired>()
        || error.is::<ManagedRuntimeRepairRequired>()
        || error
        .downcast_ref::<model_progress::OperationStopped>()
        .is_some()
        || error.downcast_ref::<std::io::Error>().is_some()
}

/// Read-only admission before progress, downloads, install locks or selection writes.
/// A different pin is not permission to discard an unverified existing selection.
fn automatic_install_preflight(required: &str) -> Result<Option<PathBuf>> {
    let manifest = read_manifest().context(ManagedRuntimeRepairRequired)?;
    let selected = if let Some(manifest) = &manifest {
        let binary = validate_installed(manifest).map_err(|error| {
            if manifest.release.is_none() {
                error.context(LegacyRuntimeMigrationRequired)
            } else {
                error
            }
        })?;
        (manifest.version == required).then_some(binary)
    } else {
        // Resolve configured paths read-only. This never imports records or
        // turns the selected profile into request identity or migration authority.
        let (_, profile) = respire_client_host::config::control_roots()
            .context(LegacyRuntimeMigrationRequired)?;
        let records = [
            "runtime/endpoint.json",
            "runtime/autostart/registration.json",
            "session.json",
            "rsrs.db",
            "onememory.db",
        ].into_iter().map(|relative| installation_root().join(relative))
            .chain(["session.json", "rsrs.db", "onememory.db"].into_iter()
                .map(|name| profile.join(name)));
        // Missing executable bytes do not prove a fresh installation.
        for record in records {
            match fs::symlink_metadata(record) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context(LegacyRuntimeMigrationRequired),
                Ok(_) => anyhow::bail!(LegacyRuntimeMigrationRequired),
            }
        }
        None
    };
    let legacy = crate::mcp::stable_bin_path();
    match fs::symlink_metadata(&legacy) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(selected),
        Err(error) => return Err(error).context(LegacyRuntimeMigrationRequired),
        Ok(metadata) => {
            anyhow::ensure!(metadata.is_file() && !metadata.file_type().is_symlink(),
                LegacyRuntimeMigrationRequired);
        }
    }
    // Release provenance is not permission to overwrite a different host CLI.
    // A materialized copy of this CLI is a normal fresh-install layout. Compare
    // bytes, not filenames, version strings or the currently selected account.
    let current = std::env::current_exe().context(LegacyRuntimeMigrationRequired)?;
    let different = crate::mcp::bin_needs_refresh(&current, &legacy)
        .map_err(anyhow::Error::msg)
        .context(LegacyRuntimeMigrationRequired)?;
    anyhow::ensure!(!different, LegacyRuntimeMigrationRequired);
    Ok(selected)
}

/// Materialization and managed replacement must use the same read-only boundary
/// before changing the old CLI image, supervisor registration or maintenance state.
pub(crate) fn require_automatic_migration_safe() -> Result<()> {
    if let Some(selected) = crate::embedding::selection() {
        // Client2 has already selected this image. Host commands do not migrate
        // or materialize a CLI; installation entry points reject embedding.
        return selected.verify().map(|_| ());
    }
    automatic_install_preflight(&pinned()?.required).map(|_| ())
}

/// Install the pinned release (or an explicit `pin` version override),
/// returning the managed binary path. An explicit `mirror` origin overrides
/// the `RSRS_MIRROR` selection for this call. Already-installed matching
/// builds are reused. Concurrent CLI instances serialize on the install lock;
/// the switch into the version directory is
/// atomic and the previous version directory is retained as the rollback
/// point.
/// A damaged selected build requires repair; it never triggers automatic
/// replacement. An explicit trusted offline install can re-establish proof.
pub fn download_and_install(pin: Option<&str>, mirror: Option<&str>) -> Result<PathBuf> {
    anyhow::ensure!(crate::embedding::selection().is_none(),
        "Runtime installation is owned by Client2; the embedded frontend cannot download or replace it");
    let required = match pin {
        Some(explicit) => {
            anyhow::ensure!(
                valid_version(explicit),
                "invalid runtime version: {explicit:?}"
            );
            explicit.to_owned()
        }
        None => pinned()?.required.clone(),
    };
    if let Some(binary) = automatic_install_preflight(&required)? {
        return Ok(binary);
    }
    let triple = release_triple()?;
    // Hermetic tests fail explicitly instead of downloading or synthesizing a shim.
    anyhow::ensure!(
        !respire_client_host::env::var("RSRS_CORE_TEST_MODE").is_ok_and(|value| value == "1"),
        "runtime downloads are disabled in core test mode"
    );
    let lock = install_lock()?;
    if let Some(binary) = automatic_install_preflight(&required)? {
        return Ok(binary);
    }
    let _operation = model_progress::Operation::begin_download()?;
    let metadata_name = format!("runtime-build-{triple}.json");
    let origins = download_origins(mirror)?;
    // Mirrors carry archives only; metadata remains bound to the official source.
    let metadata_bytes = fetch_metadata(&release_asset(
        RELEASE_BASE,
        &format!("v{required}/{metadata_name}"),
    ))?;
    let metadata: BuildMetadata =
        serde_json::from_slice(&metadata_bytes).context("invalid runtime release metadata")?;
    metadata.validate(&required, &triple)?;
    let manifest = ManagedManifest::from_release(&metadata, &metadata_bytes)?;
    let mut installed = None;
    let mut failures = Vec::new();
    for origin in &origins {
        let stage = staging_dir()?;
        let outcome = (|| -> Result<PathBuf> {
            let binary_sha256 = metadata.binary_sha256()?.to_owned();
            let archive_sha256 = metadata.archive_sha256()?.to_owned();
            let archive_name = metadata
                .archive_file
                .clone()
                .unwrap_or_else(|| format!("rsrs-runtime-{triple}.tar.gz"));
            let archive = stage.join(&archive_name);
            let actual = download_archive(
                &release_asset(origin, &format!("v{required}/{archive_name}")),
                &archive,
            )?;
            anyhow::ensure!(
                actual.eq_ignore_ascii_case(&archive_sha256),
                "archive checksum failed: found {actual}, expected {archive_sha256}"
            );
            let unpacked = stage.join("unpacked");
            extract_archive(&archive, &unpacked)?;
            verify_stage(&unpacked, &metadata.binary_file, &triple, &binary_sha256)?;
            metadata.verify_files(&unpacked)?;
            // Release archives carry the full-triple binary name; publish the
            // bare managed name before switching the version directory.
            place_managed_binary(&unpacked, &metadata.binary_file)?;
            automatic_install_preflight(&required)?;
            adopt_or_verify_version_dir(&unpacked, &manifest)?;
            publish_manifest(&manifest)?;
            Ok(managed_binary_path(&required))
        })();
        let outcome = match (outcome, fs::remove_dir_all(&stage)) {
            (result, Ok(())) => result,
            (Ok(_), Err(cleanup)) => Err(anyhow::anyhow!(
                "runtime staged successfully but staging cleanup failed: {cleanup}"
            )),
            (Err(error), Err(cleanup)) => {
                Err(error.context(format!("staging cleanup also failed: {cleanup}")))
            }
        };
        match outcome {
            Ok(binary) => {
                installed = Some(binary);
                break;
            }
            Err(error) => {
                // Cancellation and local filesystem failures do not advance to
                // the next source; network/checksum failures do.
                if is_progress_abort(&error) {
                    drop(lock);
                    return Err(error);
                }
                failures.push(format!("{origin}: {error:#}"));
            }
        }
    }
    drop(lock);
    let Some(binary) = installed else {
        anyhow::bail!("runtime download failed: {}", failures.join("; "));
    };
    // Running older instances may still load resources; retire versions only via explicit cleanup.
    Ok(binary)
}

/// Offline manual installation from a local release archive
/// (`rsrs runtime install --file <archive> --version x.y.z`). The archive must
/// still satisfy the extraction whitelist and ship `core-runtime.json`; the
/// adjacent `runtime-build-<triple>.json` must be supplied from a trusted
/// release source. Both archive and binary digests are checked before publish.
/// Managed activation requires schema 2 with a complete file inventory;
/// parsing historical schema-1 metadata alone does not establish this proof.
pub fn install_from_file(archive: &Path, version: &str) -> Result<PathBuf> {
    anyhow::ensure!(crate::embedding::selection().is_none(),
        "Runtime installation is owned by Client2; the embedded frontend cannot replace or remove it");
    anyhow::ensure!(
        archive.is_file(),
        "archive {} does not exist",
        archive.display()
    );
    anyhow::ensure!(
        valid_version(version),
        "invalid runtime version: {version:?}"
    );
    let triple = release_triple()?;
    let metadata_path = archive.with_file_name(format!("runtime-build-{triple}.json"));
    let mut bytes = Vec::new();
    fs::File::open(&metadata_path)
        .with_context(|| {
            format!(
                "offline installation requires trusted metadata {}",
                metadata_path.display()
            )
        })?
        .take((MAX_METADATA_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= MAX_METADATA_BYTES,
        "release metadata too large"
    );
    let metadata: BuildMetadata = serde_json::from_slice(&bytes)?;
    metadata.validate(version, &triple)?;
    let manifest = ManagedManifest::from_release(&metadata, &bytes)?;
    anyhow::ensure!(
        fs::metadata(archive)?.len() <= MAX_ARCHIVE_BYTES,
        "archive exceeds size limit"
    );
    let _operation = model_progress::Operation::begin_download()?;
    let lock = install_lock()?;
    let stage = staging_dir()?;
    let outcome = (|| -> Result<()> {
        let unpacked = stage.join("unpacked");
        let staged_archive = stage.join("runtime.tar.gz");
        let mut source = fs::File::open(archive)?.take(MAX_ARCHIVE_BYTES + 1);
        let mut target = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged_archive)?;
        anyhow::ensure!(
            std::io::copy(&mut source, &mut target)? <= MAX_ARCHIVE_BYTES,
            "archive exceeds size limit"
        );
        target.sync_all()?;
        drop(target);
        anyhow::ensure!(
            sha256_file(&staged_archive)?.eq_ignore_ascii_case(metadata.archive_sha256()?),
            "offline archive checksum mismatch"
        );
        extract_archive(&staged_archive, &unpacked)?;
        let binary_file = metadata.binary_file.clone();
        let binary_hash = metadata.binary_sha256()?.to_owned();
        verify_stage(&unpacked, &binary_file, &triple, &binary_hash)?;
        metadata.verify_files(&unpacked)?;
        place_managed_binary(&unpacked, &binary_file)?;
        adopt_or_verify_version_dir(&unpacked, &manifest)?;
        publish_manifest(&manifest)?;
        Ok(())
    })();
    let cleanup = fs::remove_dir_all(&stage);
    if let Err(error) = outcome {
        return Err(match cleanup {
            Ok(()) => error,
            Err(cleanup) => error.context(format!("staging cleanup also failed: {cleanup}")),
        });
    }
    cleanup.context("runtime staged successfully but staging cleanup failed")?;
    let installed = managed_binary_path(version);
    drop(lock);
    // Keep the prior installation intact while its instance may still be running.
    Ok(installed)
}

// ---------------------------------------------------------------------------
// Inventory and cleanup
// ---------------------------------------------------------------------------

/// One installed runtime version directory.
#[derive(Clone, Debug)]
pub struct InstalledRuntime {
    pub version: String,
    pub path: PathBuf,
    /// True when `runtime.json` currently selects this version.
    pub current: bool,
}

/// List installed runtime version directories, newest first. Without a
/// manifest the newest installed version counts as current.
pub fn list_installed() -> Result<Vec<InstalledRuntime>> {
    let mut installed = Vec::new();
    for entry in fs::read_dir(runtime_dir()).context("failed to list the runtime directory")? {
        let entry = entry.context("failed to list the runtime directory")?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !valid_version(name) || !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let path = entry.path().join(RUNTIME_BINARY);
        if !path.is_file() {
            continue;
        }
        installed.push(InstalledRuntime {
            version: name.to_owned(),
            path,
            current: false,
        });
    }
    // Newest first; equal comparisons keep a stable relative order.
    installed.sort_by(|a, b| respire_client_host::version_cmp(&b.version, &a.version));
    let current = read_manifest()?
        .map(|manifest| manifest.version)
        .or_else(|| installed.first().map(|entry| entry.version.clone()));
    if let Some(current) = current {
        for entry in &mut installed {
            entry.current = entry.version == current;
        }
    }
    Ok(installed)
}

/// Remove old version directories, keeping the current version and the newest
/// remaining one as the rollback point. Returns the removed versions.
pub fn clean_old() -> Result<Vec<String>> {
    anyhow::ensure!(crate::embedding::selection().is_none(),
        "Runtime installation is owned by Client2; the embedded frontend cannot replace or remove it");
    let keep = list_installed()?
        .iter()
        .find(|entry| entry.current)
        .map(|entry| entry.version.clone())
        .context("no managed runtime version is selected")?;
    remove_superseded(&keep)
}

fn remove_superseded(keep: &str) -> Result<Vec<String>> {
    let installed = list_installed()?;
    let mut removed = Vec::new();
    let mut kept_previous = false;
    for entry in installed {
        if entry.version == keep {
            continue;
        }
        if !kept_previous {
            // The newest remaining version stays as the rollback point.
            kept_previous = true;
            continue;
        }
        remove_version_dir(&entry.version)?;
        removed.push(entry.version);
    }
    Ok(removed)
}

fn remove_version_dir(version: &str) -> Result<()> {
    let dir = version_dir(version);
    // Never delete a directory that does not look like a runtime install.
    anyhow::ensure!(
        dir.join(RUNTIME_BINARY).is_file() || dir.join(LEGACY_COMBINED_BINARY).is_file(),
        "refusing to remove {}: not a runtime version directory",
        dir.display()
    );
    fs::remove_dir_all(&dir).with_context(|| format!("failed to remove {}", dir.display()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "runtime_fetch_tests.rs"]
pub(crate) mod runtime_fetch_tests;

#[cfg(test)]
mod revision4_install_validation {
    use super::*;

    #[test]
    fn schema2_accepts_unique_files_and_rejects_alias_duplicates() -> Result<()> {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../contracts/runtime-control/fixtures/positive/release-metadata-v2.json"
        ))?;
        let mut metadata: BuildMetadata = serde_json::from_value(fixture["payload"].clone())?;
        metadata.validate_schema2()?;
        let duplicate = metadata.files.first().context("fixture has no binary")?;
        metadata.files.push(BuildFile {
            path: duplicate.path.to_ascii_uppercase(),
            size: duplicate.size,
            sha256: duplicate.sha256.clone(),
        });
        anyhow::ensure!(metadata.validate_schema2().is_err());
        Ok(())
    }

    #[test]
    fn metadata_rejects_null_aliases_and_duplicate_capabilities() -> Result<()> {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../contracts/runtime-control/fixtures/positive/release-metadata-v2.json"
        ))?;
        let mut payload = fixture["payload"].clone();
        payload["sha256"] = serde_json::Value::Null;
        anyhow::ensure!(serde_json::from_value::<BuildMetadata>(payload).is_err());
        let json = fixture["payload"].to_string().replace(
            "\"business_executor\":\"1\"",
            "\"business_executor\":\"1\",\"business_executor\":\"0\"",
        );
        anyhow::ensure!(serde_json::from_str::<BuildMetadata>(&json).is_err());
        Ok(())
    }

    #[test]
    fn paths_and_mirrors_fail_closed() {
        for name in [
            "../escape",
            "a/../b",
            "/absolute",
            "a//b",
            "a/./b",
            "NUL.txt",
            "dir/COM1",
            "trailing.",
            "space ",
            "C:stream",
            "a\\b",
        ] {
            assert!(!safe_metadata_path(name), "unsafe path accepted: {name}");
        }
        assert!(safe_metadata_path("core-notices/models/LICENSE.txt"));
        assert!(download_origins(Some("https://unapproved.invalid")).is_err());
    }
}
