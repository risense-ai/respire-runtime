//! Account host facade for an unchanged Client2's inherited stdin transport.
//! The shared coordinator owns maintenance and private Runtime authorization.
use anyhow::{Context, Result};
use respire_host_commands::net_rpc::Health;
use respire_host_control::{HostLifecycle, LaunchContext, RegistrationMode, VerifiedRuntime};
use respire_protocol::host_control::{HostAuthAccountOutcome, HostAuthAccountResult};
use serde::Deserialize;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(crate) fn install_frontend() -> Result<()> {
    respire_frontend::install_runtime_embedding(respire_frontend::RuntimeEmbedding {
        verify_runtime: installed_client2_runtime,
        account_host: || Arc::new(RuntimeHost),
        // This image includes the durable coordinator and completion RPC. This is
        // process-local code authority, never an untrusted runtime.json flag.
        offline_keygen_handoff: Some(installed_client2_runtime),
    })
}

struct RuntimeHost;
impl HostLifecycle for RuntimeHost {
    fn require_account_write(&self) -> Result<()> {
        respire_commands::runtime_policy::require_host("account host control")?;
        respire_app::service::validate_client_config()?;
        let (root, profile) = respire_client_host::config::control_roots()?;
        anyhow::ensure!(
            root == respire_client_host::config::normalize_control_path(
                &respire_app::service::main_data_dir()
            )? && profile
                == respire_client_host::config::normalize_control_path(
                    &respire_app::service::data_dir()
                )?,
            "host and Runtime account selection disagree"
        );
        anyhow::ensure!(
            !respire_client_host::settings::off_mode()? && !respire_app::service::off_mode(),
            "account changes are unavailable while this device is off"
        );
        respire_client_host::settings::ensure_writable()?;
        respire_app::service::ensure_writable()
    }
    fn verified_runtime(&self) -> Result<VerifiedRuntime> {
        installed_client2_runtime()
    }
    fn issuer_version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn inspect_registration(&self, root: &Path) -> Result<RegistrationMode> {
        match std::fs::symlink_metadata(root.join("runtime/autostart/registration.json")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(RegistrationMode::Unregistered),
            Err(error) => Err(error).context("cannot inspect existing Runtime service registration"),
            Ok(_) => anyhow::bail!("this installation has a registered CLI owner; its host coordinator must perform account changes"),
        }
    }
    fn set_maintenance(&self, _: &Path, _: bool) -> Result<()> {
        anyhow::bail!("Runtime host cannot modify a CLI service registration")
    }
    fn probe_runtime(&self) -> Result<Option<Health>> {
        respire_host_control::lifecycle_io::probe_runtime()
    }
    fn endpoint_path(&self) -> PathBuf {
        respire_host_control::lifecycle_io::endpoint_path()
    }
    fn drain_runtime(&self, health: &Health) -> Result<()> {
        respire_host_control::lifecycle_io::drain_runtime(health)
    }
    fn start_account_runtime(&self, context: &LaunchContext) -> Result<()> {
        respire_host_control::lifecycle_io::start_account_runtime(
            context,
            &self.verified_runtime()?,
        )
    }
    fn finish_account_handoff(&self, receipt: &HostAuthAccountResult) -> Result<()> {
        anyhow::ensure!(
            receipt.outcome == HostAuthAccountOutcome::Committed,
            "legacy host handoff requires committed account evidence"
        );
        let profile = receipt
            .target_profile
            .as_ref()
            .context("committed target missing")?;
        let identity = respire_protocol::HostAuthIdentity::Bound {
            account_id: receipt
                .account_id
                .clone()
                .context("committed account missing")?,
            session_sha256: receipt
                .session_sha256
                .clone()
                .context("committed session missing")?,
        };
        finish_legacy_handoff(profile, &identity, true, true)
    }
    fn finish_key_handoff(
        &self,
        profile: &Path,
        identity: &respire_protocol::HostAuthIdentity,
        serving: bool,
    ) -> Result<()> {
        finish_legacy_handoff(profile, identity, serving, false)
    }
}

fn session_identity(profile: &Path) -> Result<respire_protocol::HostAuthIdentity> {
    use respire_client_host::identity::{auth_session_identity, AuthSessionIdentity};
    use respire_protocol::HostAuthIdentity;
    Ok(match auth_session_identity(profile, hash)? {
        AuthSessionIdentity::Absent => HostAuthIdentity::Absent,
        AuthSessionIdentity::Unbound {
            operation_id,
            session_sha256,
        } => HostAuthIdentity::Unbound {
            operation_id,
            session_sha256,
        },
        AuthSessionIdentity::Bound {
            account_id,
            session_sha256,
        } => HostAuthIdentity::Bound {
            account_id,
            session_sha256,
        },
    })
}

/// Runs only from the shared coordinator after verified commit and marker removal,
/// before it releases takeover. There is no in-place account/lane rebinding.
fn finish_legacy_handoff(
    profile: &Path,
    identity: &respire_protocol::HostAuthIdentity,
    serving: bool,
    require_ready: bool,
) -> Result<()> {
    let host = RuntimeHost;
    host.require_account_write()?;
    let (root, selected) = respire_client_host::config::control_roots()?;
    anyhow::ensure!(
        selected.canonicalize()? == profile.canonicalize()?
            && &session_identity(profile)? == identity,
        "committed account changed before legacy host handoff"
    );
    anyhow::ensure!(
        !root
            .join("runtime/autostart/maintenance.json")
            .try_exists()?
            && matches!(
                host.inspect_registration(&root)?,
                RegistrationMode::Unregistered
            ),
        "legacy host handoff cannot inherit maintenance or a registered owner"
    );
    let expected =
        crate::startup_identity::background_start_context(respire_commands::net_rpc::rpc_port())?;
    let observed = host.probe_runtime()?;
    if !serving {
        anyhow::ensure!(
            observed.is_none() && !host.endpoint_path().try_exists()?,
            "non-serving key completion unexpectedly has an owner"
        );
        return Ok(());
    }
    let old = observed.context("committed strict verification Runtime is missing")?;
    // Both are the same wire Health contract. The host-only crate intentionally
    // does not share the Runtime server's process-global dispatch state.
    let server_health = serde_json::from_value(serde_json::to_value(&old)?)?;
    expected.verify(&server_health)?;
    anyhow::ensure!(
        !require_ready || old.store_ready,
        "committed verification Runtime is not ready"
    );
    host.drain_runtime(&old)?;
    expected.verify_current()?;
    anyhow::ensure!(
        &session_identity(profile)? == identity,
        "committed account changed after strict Runtime drain"
    );
    let ready = crate::background_start::start_quiet(&crate::Flags::default())?;
    expected.verify(&ready)?;
    anyhow::ensure!(
        (!old.store_ready || ready.store_ready)
            && ready.instance_id != old.instance_id
            && &session_identity(profile)? == identity,
        "new legacy Runtime did not verify the committed account"
    );
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Client2Selection {
    version: String,
    sha256: String,
}

fn bounded_file(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let path = respire_client_host::config::normalize_control_path(path)?;
    let metadata = std::fs::symlink_metadata(&path)?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= limit,
        "installed Runtime record is not a bounded regular file"
    );
    let file = std::fs::File::open(&path)?;
    let opened = file.metadata()?;
    anyhow::ensure!(
        opened.is_file() && opened.len() <= limit,
        "installed Runtime record changed while opening"
    );
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= limit,
        "installed Runtime record exceeds its bound"
    );
    Ok(bytes)
}

fn hash(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(bytes))
}
fn file_hash(path: &Path) -> Result<String> {
    use sha2::Digest;
    let path = respire_client_host::config::normalize_control_path(path)?;
    anyhow::ensure!(
        std::fs::symlink_metadata(&path)?.is_file(),
        "installed Runtime payload is not regular"
    );
    let mut file = std::fs::File::open(path)?;
    let mut hash = sha2::Sha256::new();
    std::io::copy(&mut file, &mut hash)?;
    Ok(format!("{:x}", hash.finalize()))
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Recheck the exact installed selection which old Client2 verifies before it
/// starts this host process. This does not assert a signed release provenance.
fn installed_client2_runtime() -> Result<VerifiedRuntime> {
    let (root, _) = respire_client_host::config::control_roots()?;
    let binary_name = if cfg!(windows) {
        "rsrs-runtime.exe"
    } else {
        "rsrs-runtime"
    };
    let current_image = std::env::current_exe()?.canonicalize()?;
    let shared_image = root
        .join("bin/runtime")
        .join(env!("CARGO_PKG_VERSION"))
        .join(binary_name);
    // Older Client2 versions can still start their independently installed image.
    let installation = if shared_image.try_exists()?
        && respire_client_host::config::normalize_control_path(&shared_image)?.canonicalize()?
            == current_image
    {
        root.join("bin")
    } else {
        root.join("client2")
    };
    let selected_path = installation.join("runtime.json");
    let selection_bytes = bounded_file(&selected_path, 13 * 1024 * 1024)?;
    let selection: Client2Selection = serde_json::from_slice(&selection_bytes)
        .map_err(|_| anyhow::anyhow!("invalid Client2 Runtime selection"))?;
    anyhow::ensure!(
        selection.version == env!("CARGO_PKG_VERSION") && valid_hash(&selection.sha256),
        "this Runtime is not the selected Client2 version"
    );
    let directory = installation.join("runtime").join(&selection.version);
    let image = respire_client_host::config::normalize_control_path(&directory.join(binary_name))?;
    anyhow::ensure!(
        image.canonicalize()? == current_image,
        "account host is not the selected Client2 Runtime image"
    );
    let manifest_bytes = bounded_file(&directory.join("core-runtime.json"), 2 * 1024 * 1024)?;
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| anyhow::anyhow!("invalid installed Core runtime manifest"))?;
    anyhow::ensure!(
        manifest["schema_version"] == 1 && manifest["target"] == current_target(),
        "installed Core runtime manifest target mismatch"
    );
    let files = manifest["files"]
        .as_array()
        .filter(|files| !files.is_empty() && files.len() <= 4096)
        .context("installed Core runtime inventory is missing")?;
    let mut seen = std::collections::BTreeSet::new();
    for file in files {
        let relative = file["path"]
            .as_str()
            .context("installed Runtime inventory path missing")?;
        let digest = file["sha256"]
            .as_str()
            .filter(|value| valid_hash(value))
            .context("installed Runtime inventory digest invalid")?;
        let path = Path::new(relative);
        anyhow::ensure!(
            !relative.is_empty()
                && !relative.contains(['\\', ':'])
                && path.is_relative()
                && path
                    .components()
                    .all(|part| matches!(part, std::path::Component::Normal(_)))
                && seen.insert(relative),
            "unsafe or duplicate installed Runtime inventory path"
        );
        // Notices are optional documentation, never executable dependencies.
        if relative.starts_with("core-notices/") && !directory.join(path).try_exists()? {
            continue;
        }
        anyhow::ensure!(
            file_hash(&directory.join(path))?.eq_ignore_ascii_case(digest),
            "installed Runtime payload digest mismatch"
        );
    }
    let verified = VerifiedRuntime::verify_installed(
        &image,
        &selection.sha256,
        &selection.version,
        respire_commands::net_rpc::rpc_port(),
    )?;
    anyhow::ensure!(
        bounded_file(&selected_path, 13 * 1024 * 1024)? == selection_bytes
            && hash(&bounded_file(
                &directory.join("core-runtime.json"),
                2 * 1024 * 1024
            )?) == hash(&manifest_bytes),
        "installed Runtime selection or inventory changed during verification"
    );
    Ok(verified)
}

fn current_target() -> &'static str {
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    {
        return "x86_64-unknown-linux-gnu";
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64", target_env = "gnu"))]
    {
        return "aarch64-unknown-linux-gnu";
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "musl"))]
    {
        return "x86_64-unknown-linux-musl";
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64", target_env = "musl"))]
    {
        return "aarch64-unknown-linux-musl";
    }
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        return "x86_64-pc-windows-msvc";
    }
    #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
    {
        return "aarch64-pc-windows-msvc";
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        return "aarch64-apple-darwin";
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        return "x86_64-apple-darwin";
    }
    #[allow(unreachable_code)]
    "unsupported"
}
