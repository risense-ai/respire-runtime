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
//!   `runtime-build-<triple>.json` (its `binary_sha256` field, with `sha256`
//!   accepted as an alias) and extracted with a strict whitelist (regular
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
//! compared with the same numeric rules as `crate::net_rpc::version_cmp`) that
//! an already-installed runtime must satisfy to be reused instead of replaced.
//! Runtime releases publish `runtime-build-<triple>.json` with
//! `{"runtime_version","tag","triple","binary_sha256","binary_file","compat":{"min_cli","max_cli"}}`
//! (`sha256` accepted as an alias for the checksum field);
//! `compat` states which CLI versions the runtime accepts and is enforced
//! before an archive is installed.

use std::fs;
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::model_progress;

/// Release repository that publishes the runtime artifacts.
pub const RUNTIME_REPO: &str = "risense-ai/respire-runtime";
const RELEASE_BASE: &str = "https://github.com";
const MIRROR_PREFIX: &str = "https://gh-proxy.com";

/// Managed runtime binary name for the running platform.
pub const RUNTIME_BINARY: &str = if cfg!(windows) { "rsrs-runtime.exe" } else { "rsrs-runtime" };
/// Binary name of the legacy combined CLI+runtime layout.
pub const LEGACY_COMBINED_BINARY: &str = if cfg!(windows) { "rsrs.exe" } else { "rsrs" };
/// Shared managed-install manifest, written next to `<installation_root>/runtime/`.
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
/// Concurrent first-launch installs serialize on this lock (CLI + client2).
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
        let mut range = Self { min: None, max: None };
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
        anyhow::ensure!(range.min.is_some() || range.max.is_some(), "empty accept range");
        if let (Some(min), Some(max)) = (range.min.as_deref(), range.max.as_deref()) {
            anyhow::ensure!(
                crate::net_rpc::version_cmp(min, max) == std::cmp::Ordering::Less,
                "accept lower bound is not below its upper bound"
            );
        }
        Ok(range)
    }

    /// True when `version` satisfies every configured bound.
    pub fn contains(&self, version: &str) -> bool {
        let ordering = |bound: &str| semver_cmp(version, bound);
        self.min.as_deref().is_none_or(|min| ordering(min) != std::cmp::Ordering::Less)
            && self.max.as_deref().is_none_or(|max| ordering(max) == std::cmp::Ordering::Less)
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
    PIN
        .get_or_init(|| parse_pin(PIN_JSON).map_err(|error| format!("{error:#}")))
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
    pinned().is_ok_and(|pin| pin.accept.contains(version))
}

/// Semver-shaped version charset shared with client2 (`semver.IsValid` plus a
/// separator ban), so version strings are always safe path components.
pub fn valid_version(version: &str) -> bool {
    fn identifier(part: &str) -> bool {
        !part.is_empty()
            && part.split('.').all(|piece| {
                !piece.is_empty()
                    && piece.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
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
        Some((core_pre, build)) => !build.is_empty() && identifier(build) && core_and_prerelease(core_pre),
        None => core_and_prerelease(version),
    }
}

/// Release asset triple for the running platform. The darwin-amd64 asset keeps
/// its obfuscated triple name (see [`TRIPLES`]); Linux defaults to the gnu
/// ABI and can be redirected to a musl asset with `RSRS_RUNTIME_TRIPLE`.
pub fn release_triple() -> Result<String> {
    if let Ok(raw) = respire::env::var("RSRS_RUNTIME_TRIPLE") {
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
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        ("linux", "aarch64") => "aarch64-unknown-linux-gnu",
        _ => bail!("no published rsrs-runtime asset for this platform"),
    };
    Ok(triple.to_owned())
}

// ---------------------------------------------------------------------------
// Managed layout
// ---------------------------------------------------------------------------

/// Installation root shared with client2 (`~/.rsrs` unless isolated).
pub fn installation_root() -> PathBuf {
    respire::service::main_data_dir()
}

/// Managed runtime directory: `<installation_root>/runtime/`.
pub fn runtime_dir() -> PathBuf {
    installation_root().join("runtime")
}

/// Shared manifest read and written by both the CLI and client2.
pub fn manifest_path() -> PathBuf {
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

/// Content of the shared `<installation_root>/runtime.json` manifest. The
/// field names match client2 so both managers consume the same file.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManagedManifest {
    pub version: String,
    pub sha256: String,
}

/// Read the managed manifest without validating the binary on disk.
pub fn read_manifest() -> Result<Option<ManagedManifest>> {
    let path = manifest_path();
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= 64 * 1024,
        "invalid runtime manifest"
    );
    let manifest: ManagedManifest = serde_json::from_slice(&fs::read(&path)?)
        .context("invalid runtime manifest")?;
    anyhow::ensure!(
        valid_version(&manifest.version) && valid_sha256(&manifest.sha256),
        "invalid runtime manifest"
    );
    Ok(Some(manifest))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Validate an installed version directory: the managed binary exists and its
/// sha256 matches the manifest entry.
fn validate_installed(manifest: &ManagedManifest) -> Result<PathBuf> {
    let binary = managed_binary_path(&manifest.version);
    anyhow::ensure!(binary.is_file(), "managed runtime {} is missing its binary", manifest.version);
    let actual = sha256_file(&binary)?;
    anyhow::ensure!(
        actual.eq_ignore_ascii_case(&manifest.sha256),
        "managed runtime {} does not match its recorded checksum",
        manifest.version
    );
    Ok(binary)
}

/// The managed binary the running CLI should currently use, if any. Used by
/// lifecycle checks to compare a live runtime's reported executable path.
pub fn managed_runtime_path() -> Result<Option<PathBuf>> {
    match read_manifest()? {
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
    /// usable runtime was found first. The caller runs the migration flow:
    /// install the pinned runtime, stop the old owner, rewrite autostart.
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
    if let Ok(raw) = respire::env::var("RSRS_RUNTIME_BIN") {
        let explicit = PathBuf::from(raw.trim());
        anyhow::ensure!(!explicit.as_os_str().is_empty(), "RSRS_RUNTIME_BIN is empty");
        anyhow::ensure!(explicit.is_file(), "RSRS_RUNTIME_BIN does not name a file");
        return Ok(ResolvedRuntime::Ready(explicit));
    }
    if let Some(manifest) = read_manifest()? {
        if version_in_accept(&manifest.version) {
            if let Ok(binary) = validate_installed(&manifest) {
                return Ok(ResolvedRuntime::Ready(binary));
            }
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
    let legacy = crate::mcp::bin_dir().join(LEGACY_COMBINED_BINARY);
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
    pub runtime_version: String,
    pub tag: String,
    pub triple: String,
    /// Archive checksum field (`sha256`); `binary_sha256` is accepted as an
    /// alias and both must agree when present.
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub binary_sha256: String,
    /// Archive-side binary file name, the full-triple name.
    pub binary_file: String,
    pub compat: CompatBounds,
}

impl BuildMetadata {
    /// The authoritative binary checksum, accepting either metadata field.
    fn binary_sha256(&self) -> Result<&str> {
        match (self.sha256.is_empty(), self.binary_sha256.is_empty()) {
            (false, true) => Ok(&self.sha256),
            (true, false) => Ok(&self.binary_sha256),
            (true, true) => bail!("release metadata has no sha256"),
            (false, false) => {
                anyhow::ensure!(
                    self.sha256.eq_ignore_ascii_case(&self.binary_sha256),
                    "release metadata carries conflicting archive checksums"
                );
                Ok(&self.sha256)
            }
        }
    }

    fn validate(&self, required: &str, triple: &str) -> Result<()> {
        anyhow::ensure!(
            valid_version(&self.runtime_version) && self.runtime_version == required,
            "release metadata targets runtime {}, expected {required}",
            self.runtime_version
        );
        anyhow::ensure!(
            !self.tag.is_empty()
                && !self.tag.chars().any(|c| c.is_control() || matches!(c, '/' | '\\' | ':' | ' ')),
            "release metadata has an invalid tag"
        );
        anyhow::ensure!(
            self.triple == triple,
            "release metadata targets triple {}, expected {triple}",
            self.triple
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
        let cli = env!("CARGO_PKG_VERSION");
        anyhow::ensure!(valid_version(&self.compat.min_cli), "release metadata has an invalid compat range");
        anyhow::ensure!(
            self.compat.max_cli == "*" || valid_version(&self.compat.max_cli),
            "release metadata has an invalid compat range"
        );
        anyhow::ensure!(
            crate::net_rpc::version_cmp(cli, &self.compat.min_cli) != std::cmp::Ordering::Less,
            "runtime {} requires CLI >= {}; upgrade the CLI first",
            self.runtime_version,
            self.compat.min_cli
        );
        anyhow::ensure!(
            self.compat.max_cli == "*"
                || crate::net_rpc::version_cmp(cli, &self.compat.max_cli) == std::cmp::Ordering::Less,
            "runtime {} only accepts CLI versions below {}; upgrade the runtime explicitly",
            self.runtime_version,
            self.compat.max_cli
        );
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
    let setting = mirror
        .map(str::to_owned)
        .or_else(crate::model_install::mirror_from_env)
        .filter(|value| !value.trim().is_empty());
    match setting {
        Some(value) => {
            let mirrored = format!("{}/{official}", mirror_origin(value.trim())?);
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
fn fetch_metadata(url: &str) -> Result<BuildMetadata> {
    let response = download_agent(DownloadTimeouts::default())
        .get(url)
        .timeout(Duration::from_secs(30))
        .call()
        .with_context(|| format!("release metadata request failed ({url})"))?;
    let mut reader = response.into_reader().take((MAX_METADATA_BYTES + 1) as u64);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).context("release metadata read failed")?;
    anyhow::ensure!(bytes.len() <= MAX_METADATA_BYTES, "release metadata too large");
    serde_json::from_slice(&bytes)
        .with_context(|| format!("release metadata is not valid JSON ({url})"))
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
    let mut file =
        fs::File::create(dest).with_context(|| format!("failed to write {}", dest.display()))?;
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

/// Rejects `\`, `:`, absolute paths, empty or `.`/`..` components and
/// everything outside the allowlisted entry types. Mirrors client2's
/// `strings.ContainsAny(name, "\\:") || !filepath.IsLocal(...)` guard.
fn safe_entry_name(raw: &str) -> Option<String> {
    let name = raw.trim_start_matches("./").trim_end_matches('/');
    if name.is_empty() || name == "." {
        return None;
    }
    if name.contains('\\') || name.contains(':') || name.starts_with('/') {
        return None;
    }
    for component in name.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return None;
        }
    }
    Some(name.to_owned())
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
    let end = field.iter().position(|byte| *byte == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

fn verify_header_checksum(header: &[u8; 512]) -> Result<()> {
    let stored = octal_field(&header[148..156])?;
    let mut sum: u64 = 0;
    for (index, byte) in header.iter().enumerate() {
        sum += if (148..156).contains(&index) { u64::from(b' ') } else { u64::from(*byte) };
    }
    anyhow::ensure!(sum == stored, "archive header checksum mismatch");
    Ok(())
}

/// Parse one ustar header block. Release archives are plain ustar, gnu or
/// pax; extension headers (`L`/`K`/`x`/`g`) are parsed so their payload can
/// be skipped, every other non-regular/directory type is rejected.
fn parse_header(header: &[u8; 512]) -> Result<Option<TarHeader>> {
    if header.iter().all(|byte| *byte == 0) {
        return Ok(None);
    }
    anyhow::ensure!(&header[257..262] == b"ustar", "archive is not a ustar tarball");
    verify_header_checksum(header)?;
    let typeflag = header[156];
    anyhow::ensure!(
        matches!(typeflag, b'0' | 0 | b'5' | b'L' | b'K' | b'x' | b'g'),
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
    let mut reader = flate2::read::GzDecoder::new(file);
    let mut total: u64 = 0;
    let mut payload = [0u8; 64 * 1024];
    loop {
        let mut header = [0u8; 512];
        read_exact_bounded(&mut reader, &mut header, archive)?;
        let entry = match parse_header(&header)? {
            Some(entry) => entry,
            None => break,
        };
        // client2 skips plain "./" directory markers and rejects every other
        // name that fails the whitelist.
        let bare = entry.name.trim_start_matches("./").trim_end_matches('/');
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
        let target = dest.join(&name);
        if entry.typeflag == b'5' {
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
                options.mode(if entry.mode & 0o111 != 0 { 0o700 } else { 0o600 });
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
    fs::create_dir_all(dir).with_context(|| format!("failed to create directory {}", dir.display()))?;
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
    let binary = stage.join(binary_file);
    anyhow::ensure!(binary.is_file(), "archive did not contain {}", binary_file);
    let actual = sha256_file(&binary)?;
    anyhow::ensure!(
        actual.eq_ignore_ascii_case(binary_hash),
        "runtime checksum mismatch: expected {binary_hash}, found {actual}"
    );
    let manifest_path = stage.join(CORE_MANIFEST_FILE);
    anyhow::ensure!(
        manifest_path.is_file(),
        "archive did not contain {}",
        CORE_MANIFEST_FILE
    );
    let bytes = fs::read(&manifest_path)?;
    let manifest: CoreManifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid {} manifest", CORE_MANIFEST_FILE))?;
    anyhow::ensure!(
        manifest.schema_version == 1 && manifest.target == triple && !manifest.files.is_empty(),
        "invalid {} manifest",
        CORE_MANIFEST_FILE
    );
    for file in &manifest.files {
        let Some(name) = safe_entry_name(&file.path) else {
            bail!("unsafe runtime manifest path: {}", file.path);
        };
        anyhow::ensure!(valid_sha256(&file.sha256), "invalid runtime manifest checksum");
        let target = stage.join(name);
        anyhow::ensure!(target.is_file(), "runtime manifest file is missing: {}", file.path);
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
    if bare.exists() {
        fs::remove_file(&bare)
            .with_context(|| format!("failed to replace {}", bare.display()))?;
    }
    fs::rename(&full, &bare)
        .with_context(|| format!("failed to place {}", bare.display()))
}

// ---------------------------------------------------------------------------
// Install transactions
// ---------------------------------------------------------------------------

fn install_lock() -> Result<respire::lock::LibraryLock> {
    respire::lock::LibraryLock::acquire(&runtime_dir().join(".install.lock"), INSTALL_LOCK_WAIT)
        .context("another process is installing the runtime")
}

fn publish_manifest(manifest: &ManagedManifest) -> Result<()> {
    let path = manifest_path();
    let bytes = serde_json::to_vec_pretty(manifest)?;
    let temporary =
        installation_root().join(format!(".runtime-manifest-{}", uuid::Uuid::new_v4()));
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
fn adopt_or_verify_version_dir(
    stage: &Path,
    version: &str,
    binary_hash: &str,
) -> Result<PathBuf> {
    let dest = version_dir(version);
    if dest.is_dir() {
        let existing = ManagedManifest {
            version: version.to_owned(),
            sha256: binary_hash.to_owned(),
        };
        return validate_installed(&existing)
            .context("a different build already occupies this runtime version");
    }
    // Renaming stays inside <runtime/>, so it is atomic on every platform.
    fs::rename(stage, &dest).with_context(|| format!("failed to publish {}", dest.display()))?;
    respire_spawn::durable::sync_directory(&runtime_dir()).ok();
    Ok(dest.join(RUNTIME_BINARY))
}

fn staging_dir() -> Result<PathBuf> {
    fs::create_dir_all(runtime_dir())
        .with_context(|| format!("failed to create {}", runtime_dir().display()))?;
    Ok(runtime_dir().join(format!(".download-{}", uuid::Uuid::new_v4())))
}

fn is_progress_abort(error: &anyhow::Error) -> bool {
    error.downcast_ref::<model_progress::OperationStopped>().is_some()
        || error.downcast_ref::<std::io::Error>().is_some()
}

/// Install the pinned release (or an explicit `pin` version override),
/// returning the managed binary path. An explicit `mirror` origin overrides
/// the `RSRS_MIRROR` selection for this call. Already-installed matching
/// builds are reused. Concurrency with client2 or another CLI instance
/// serializes on the install lock; the switch into the version directory is
/// atomic and the previous version directory is retained as the rollback
/// point.
pub fn download_and_install(pin: Option<&str>, mirror: Option<&str>) -> Result<PathBuf> {
    let _operation = model_progress::Operation::begin_download()?;
    let required = match pin {
        Some(explicit) => {
            anyhow::ensure!(valid_version(explicit), "invalid runtime version: {explicit:?}");
            explicit.to_owned()
        }
        None => pinned()?.required.clone(),
    };
    let triple = release_triple()?;
    // Idempotent: an already-installed matching build wins over re-downloading.
    if let Some(manifest) = read_manifest()? {
        if manifest.version == required {
            if let Ok(binary) = validate_installed(&manifest) {
                return Ok(binary);
            }
        }
    }
    // Test harnesses set RSRS_CORE_TEST_MODE=1 for hermetic runs: downloads
    // are refused so every caller takes its local fallback (the in-process
    // shim) deterministically instead of touching the network.
    anyhow::ensure!(
        !respire::env::var("RSRS_CORE_TEST_MODE").is_ok_and(|value| value == "1"),
        "runtime downloads are disabled in core test mode"
    );
    let archive_name = format!("rsrs-runtime-{triple}.tar.gz");
    let metadata_name = format!("runtime-build-{triple}.json");
    let origins = download_origins(mirror)?;
    let lock = install_lock()?;
    let mut installed = None;
    let mut failures = Vec::new();
    for origin in &origins {
        let stage = staging_dir()?;
        let outcome = (|| -> Result<PathBuf> {
            let metadata =
                fetch_metadata(&release_asset(origin, &format!("v{required}/{metadata_name}")))?;
            metadata.validate(&required, &triple)?;
            let binary_sha256 = metadata.binary_sha256()?.to_owned();
            let archive = stage.join(&archive_name);
            let actual = download_archive(
                &release_asset(origin, &format!("v{required}/{archive_name}")),
                &archive,
            )?;
            anyhow::ensure!(
                actual.eq_ignore_ascii_case(&binary_sha256),
                "archive checksum failed: found {actual}, expected {binary_sha256}"
            );
            let unpacked = stage.join("unpacked");
            extract_archive(&archive, &unpacked)?;
            verify_stage(&unpacked, &metadata.binary_file, &triple, &binary_sha256)?;
            // Release archives carry the full-triple binary name; publish the
            // bare managed name before switching the version directory.
            place_managed_binary(&unpacked, &metadata.binary_file)?;
            adopt_or_verify_version_dir(&unpacked, &required, &binary_sha256)?;
            publish_manifest(&ManagedManifest {
                version: required.clone(),
                sha256: binary_sha256,
            })?;
            Ok(managed_binary_path(&required))
        })();
        let _ = fs::remove_dir_all(&stage);
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
    retain_one_previous_version(&required);
    Ok(binary)
}

/// Offline manual installation from a local release archive
/// (`rsrs runtime install --file <archive> --version x.y.z`). The archive must
/// still satisfy the extraction whitelist and ship `core-runtime.json`; the
/// binary checksum recorded in the manifest is computed from the archive
/// itself, since no release metadata is available offline.
pub fn install_from_file(archive: &Path, version: &str) -> Result<PathBuf> {
    anyhow::ensure!(archive.is_file(), "archive {} does not exist", archive.display());
    anyhow::ensure!(valid_version(version), "invalid runtime version: {version:?}");
    let _operation = model_progress::Operation::begin_download()?;
    let lock = install_lock()?;
    let stage = staging_dir()?;
    let outcome = (|| -> Result<()> {
        let unpacked = stage.join("unpacked");
        extract_archive(archive, &unpacked)?;
        let triple = release_triple()?;
        // Official archives use the full-triple binary name; hand-built
        // archives may use the bare managed name. Either installs identically.
        let full_name = release_binary_name(&triple);
        let binary_file = if unpacked.join(&full_name).is_file() {
            full_name
        } else {
            RUNTIME_BINARY.to_owned()
        };
        let binary_hash = sha256_file(&unpacked.join(&binary_file))?;
        let binary = verify_stage(&unpacked, &binary_file, &triple, &binary_hash)?;
        place_managed_binary(&unpacked, &binary_file)?;
        adopt_or_verify_version_dir(&unpacked, version, &binary_hash)?;
        publish_manifest(&ManagedManifest {
            version: version.to_owned(),
            sha256: binary_hash,
    })?;
    Ok(())
    })();
    let installed = match outcome {
        Ok(()) => managed_binary_path(version),
        Err(error) => {
            let _ = fs::remove_dir_all(&stage);
            return Err(error);
        }
    };
    drop(lock);
    retain_one_previous_version(version);
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
    installed.sort_by(|a, b| crate::net_rpc::version_cmp(&b.version, &a.version));
    let current = read_manifest()?.map(|manifest| manifest.version).or_else(|| {
        installed.first().map(|entry| entry.version.clone())
    });
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
    let keep = list_installed()?
        .iter()
        .find(|entry| entry.current)
        .map(|entry| entry.version.clone())
        .context("no managed runtime version is selected")?;
    remove_superseded(&keep)
}

/// Keep only `keep` plus one rollback version after a successful install.
fn retain_one_previous_version(keep: &str) {
    if let Err(error) = remove_superseded(keep) {
        eprintln!("runtime cleanup after install failed: {error:#}");
    }
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
    fs::remove_dir_all(&dir)
        .with_context(|| format!("failed to remove {}", dir.display()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "runtime_fetch_tests.rs"]
mod runtime_fetch_tests;
