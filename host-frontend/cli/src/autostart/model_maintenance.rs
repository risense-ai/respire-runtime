//! Mount below launch_authorization. Only these three host maintenance actions
//! are accepted; Runtime owns selection/config semantics, this host owns files.
use anyhow::{Context, Result};
use respire_client_host::lock::LibraryLock;
use respire_commands::output::{Item, ResultEnvelope, Status};
use respire_protocol::model_maintenance::*;
use respire_protocol::{ControlBinding, HostControlLaunchGrant, RpcRequest};
use serde_json::json;
use sha2::{Digest, Sha256};
#[cfg(windows)]
use std::io::{Read, Write};
use std::{
    fs,
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};

#[cfg(windows)]
const PACKAGE_SOURCE: &str = "https://api.nuget.org/v3-flatcontainer/microsoft.windows.ai.machinelearning/2.4.89/microsoft.windows.ai.machinelearning.2.4.89.nupkg";
#[cfg(windows)]
const PACKAGE_SHA256: &str = "5c68ecfb947223267abf159a023f5192ad42725e4e9cc995e7c1470dd54dff63";

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn control_install_engines() -> Result<ResultEnvelope> {
    coordinate(ModelMaintenanceKind::InstallEngines)
}
pub(crate) fn control_uninstall_m3() -> Result<ResultEnvelope> {
    coordinate(ModelMaintenanceKind::UninstallM3)
}
pub(crate) fn control_reset_cpu() -> Result<ResultEnvelope> {
    coordinate(ModelMaintenanceKind::ResetCpu)
}

fn roots() -> Result<(PathBuf, PathBuf)> {
    let (root, profile) = respire_client_host::config::control_roots()?;
    fs::create_dir_all(&root)?;
    fs::create_dir_all(&profile)?;
    Ok((root.canonicalize()?, profile.canonicalize()?))
}

fn account(profile: &Path) -> Result<Option<String>> {
    Ok(respire_client_host::identity::session_user_of_dir(profile)?
        .map(|user| hash(user.as_bytes())))
}

fn verify_owner(
    health: &crate::net_rpc::Health,
    root: &Path,
    profile: &Path,
    binary: &Path,
    manifest: &crate::runtime_fetch::ManagedManifest,
    managed: Option<&super::super::super::Registration>,
    expected_account: Option<&str>,
) -> Result<()> {
    crate::net_rpc::request_scope(health)?;
    if let Some(config) = managed {
        super::lifecycle::verify_owned_runtime(config, health)?;
    }
    let birth =
        crate::autostart::process_birth(health.pid)?.context("model maintenance owner exited")?;
    let process = crate::net_rpc::runtime_process_identity(health.pid)?;
    let prefix = if cfg!(windows) {
        "windows-filetime-"
    } else if cfg!(target_os = "linux") {
        "linux-starttime-"
    } else {
        "darwin-lstart-"
    };
    let expected_scope = super::model_control::owner_scope_id(profile, expected_account)?;
    // Unlike normal preparation, reset must accept a correctly identified owner
    // whose inference is stalled. Identity and installation checks are unchanged.
    anyhow::ensure!(
        health.managed_id.as_deref() == managed.map(|config| config.id.as_str())
            && health.account_id == expected_scope
            && Path::new(&health.installation_root).canonicalize()? == root
            && Path::new(&health.data_dir).canonicalize()? == profile
            && health.installation_id == hash(root.display().to_string().as_bytes())
            && Path::new(&health.exe).canonicalize()? == binary
            && Path::new(&health.image_path).canonicalize()? == binary
            && Path::new(&process.executable).canonicalize()? == binary
            && health.runtime_version == manifest.version
            && health.image_sha256.eq_ignore_ascii_case(&manifest.sha256)
            && health.process_start_id == format!("{prefix}{birth}")
            && (process.started_at == birth || process.started_at == health.process_start_id),
        "model maintenance owner identity/profile/image mismatch"
    );
    anyhow::ensure!(
        crate::net_rpc::runtime_process_identity(health.pid)? == process,
        "model maintenance owner changed during verification"
    );
    Ok(())
}

fn coordinate(kind: ModelMaintenanceKind) -> Result<ResultEnvelope> {
    crate::runtime_policy::require_host("model maintenance")?;
    anyhow::ensure!(
        super::lifecycle::current_boot_token().is_none(),
        "model maintenance cannot nest"
    );
    let takeover = crate::runtime_policy::takeover_lock()?;
    if crate::runtime_fetch::read_manifest()?.is_none() {
        crate::runtime_fetch::download_and_install(None, None)?;
    }
    let (binary, manifest) = super::model_control::installed_model_runtime()?;
    let (root, profile) = roots()?;
    let expected_account = account(&profile)?;
    let registration = super::read_registration(&root)?;
    let managed = registration
        .as_ref()
        .filter(|config| config.enabled && !config.manually_stopped);
    let owner = crate::rpc::probe_runtime()?;
    // Reuse the complete dead-owner claim verifier. A legacy/live unobservable
    // locator cannot authorize forced termination of a possibly foreign owner.
    let stale = if owner.is_none() && crate::rpc::endpoint_path().try_exists()? {
        Some(
            super::super::super::recovery::StaleOwner::prepare_locked().context(
                "model maintenance cannot prove owner exit; no force-stop or config mutation",
            )?,
        )
    } else {
        None
    };
    if let Some(config) = managed {
        super::lifecycle::owned(config)?;
        super::lifecycle::ensure_control_endpoint(config)?;
        anyhow::ensure!(
            owner.is_some() || !super::super::super::manager::inspect(config)?.running,
            "model maintenance has a running supervisor without an observable owner"
        );
    }
    if let Some(owner) = owner.as_ref() {
        verify_owner(
            owner,
            &root,
            &profile,
            &binary,
            &manifest,
            managed,
            expected_account.as_deref(),
        )?;
        anyhow::ensure!(
            kind == ModelMaintenanceKind::ResetCpu || !owner.inference_stalled(),
            "inference is stalled; use model reset-cpu first"
        );
    }
    let unchanged = || -> Result<()> {
        let (current, release) = super::model_control::installed_model_runtime()?;
        anyhow::ensure!(
            current == binary
                && release.version == manifest.version
                && release.sha256.eq_ignore_ascii_case(&manifest.sha256)
                && roots()? == (root.clone(), profile.clone())
                && account(&profile)? == expected_account,
            "model maintenance installation/profile/account changed"
        );
        Ok(())
    };
    let mut maintenance = super::lifecycle::begin_maintenance_locked()?;
    let result = (|| -> Result<ResultEnvelope> {
        maintenance.check_account_runtime()?;
        maintenance
            .auth_launch_binding(&profile)?
            .context("model maintenance requires durable Paused authority")?;
        let cpu_plan = if kind == ModelMaintenanceKind::ResetCpu {
            Some(exchange(
                &takeover,
                &mut maintenance,
                kind,
                ModelMaintenancePhase::Plan,
                None,
            )?)
        } else {
            None
        };
        if let Some(stale) = stale {
            stale.remove_endpoint_locked()?;
        }
        if let Some(owner) = owner.as_ref() {
            let drained = maintenance.drain_runtime(owner);
            if let Err(error) = drained {
                if kind != ModelMaintenanceKind::ResetCpu || managed.is_some() {
                    return Err(error);
                }
                // Manual CPU recovery retains the explicit force-stop behavior,
                // but only for the full owner we observed and verified above.
                force_stop_observed(
                    owner,
                    &root,
                    &profile,
                    &binary,
                    &manifest,
                    expected_account.as_deref(),
                )?;
            }
        }
        unchanged()?;
        let planned = match cpu_plan {
            Some(plan) => plan,
            None => exchange(
                &takeover,
                &mut maintenance,
                kind,
                ModelMaintenancePhase::Plan,
                None,
            )?,
        };
        anyhow::ensure!(
            planned.phase == ModelMaintenancePhase::Plan
                && !planned.config_applied
                && !planned.verified
                && !planned.npu_ready
                && planned.plan.kind == kind,
            "Runtime returned an invalid model maintenance plan"
        );
        let plan = planned.plan;
        let mut providers: Vec<String> = Vec::new();
        let mut removed = false;
        let mut reset_reconciled = false;
        let receipt = match kind {
            ModelMaintenanceKind::ResetCpu => {
                match exchange(
                    &takeover,
                    &mut maintenance,
                    kind,
                    ModelMaintenancePhase::Apply,
                    Some(&plan.review),
                ) {
                    Ok(receipt) => {
                        anyhow::ensure!(
                            receipt.config_applied && receipt.verified,
                            "CPU reset was not confirmed"
                        );
                        receipt
                    }
                    Err(error) => {
                        // Read the postcondition once. Never repeat the uncertain CAS.
                        let inspected = exchange(
                            &takeover,
                            &mut maintenance,
                            kind,
                            ModelMaintenancePhase::Plan,
                            None,
                        )
                        .context("CPU reset outcome unknown; no Apply was replayed")?;
                        let candidate = plan
                            .cpu_candidate_sha256
                            .as_deref()
                            .context("CPU reset candidate missing")?;
                        let bytes = fs::read(root.join("inference.json"))?;
                        anyhow::ensure!(
                            hash(&bytes) == candidate
                                && inspected.plan.cpu_candidate_sha256.as_deref()
                                    == Some(candidate),
                            "CPU reset outcome unknown: {error:#}; no Apply was replayed"
                        );
                        reset_reconciled = true;
                        inspected
                    }
                }
            }
            ModelMaintenanceKind::InstallEngines | ModelMaintenanceKind::UninstallM3 => {
                {
                    let _installation =
                        LibraryLock::acquire(&root.join("runtime"), Duration::ZERO)?;
                    let _library = LibraryLock::acquire(&profile, Duration::ZERO)?;
                    check_path(&root.join("inference.json.lock"))?;
                    let lock = fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .truncate(false)
                        .open(root.join("inference.json.lock"))?;
                    lock.lock()?;
                    unchanged()?;
                    if kind == ModelMaintenanceKind::InstallEngines {
                        providers = install_catalog(&root, plan.catalog.as_ref())?;
                    } else {
                        removed = remove_m3(
                            &root,
                            &profile,
                            plan.uninstall_directory
                                .as_deref()
                                .context("Runtime uninstall directory missing")?,
                        )?;
                    }
                }
                let receipt = exchange(
                    &takeover,
                    &mut maintenance,
                    kind,
                    ModelMaintenancePhase::Verify,
                    Some(&plan.review),
                )?;
                anyhow::ensure!(
                    receipt.verified && !receipt.config_applied && !receipt.npu_ready,
                    "Runtime did not verify host model maintenance"
                );
                receipt
            }
        };
        unchanged()?;
        if kind == ModelMaintenanceKind::ResetCpu {
            anyhow::ensure!(
                Some(hash(&fs::read(root.join("inference.json"))?)) == plan.cpu_candidate_sha256,
                "CPU reset configuration changed before owner restoration"
            );
        }
        let restart =
            owner.is_some() && (kind != ModelMaintenanceKind::ResetCpu || managed.is_some());
        if restart {
            maintenance.start_account_runtime()?;
            let restored =
                crate::rpc::probe_runtime()?.context("model maintenance owner did not resume")?;
            verify_owner(
                &restored,
                &root,
                &profile,
                &binary,
                &manifest,
                managed,
                expected_account.as_deref(),
            )?;
            anyhow::ensure!(
                !owner.as_ref().is_some_and(|owner| owner.store_ready) || restored.store_ready,
                "restored model owner lost store readiness"
            );
        }
        unchanged()?;
        if kind == ModelMaintenanceKind::ResetCpu {
            anyhow::ensure!(
                Some(hash(&fs::read(root.join("inference.json"))?)) == plan.cpu_candidate_sha256,
                "CPU reset configuration changed during owner restoration"
            );
        }
        let mut output = match kind {
            ModelMaintenanceKind::InstallEngines => ResultEnvelope::new(
                "model",
                if receipt.warning.is_some() {
                    Status::Warn
                } else {
                    Status::Ok
                },
                json!({"providers":providers,"npu_ready":false}),
                Vec::new(),
            ),
            ModelMaintenanceKind::UninstallM3 => {
                let status = if removed { Status::Ok } else { Status::Skip };
                let directory = plan
                    .uninstall_directory
                    .as_ref()
                    .context("uninstall directory missing")?;
                ResultEnvelope::new(
                    "model",
                    status,
                    json!({"dir":directory,"removed":removed,"model":"bge-m3"}),
                    vec![Item::new(
                        "model",
                        status,
                        if removed {
                            directory.display().to_string()
                        } else {
                            "not installed".into()
                        },
                    )],
                )
            }
            ModelMaintenanceKind::ResetCpu => ResultEnvelope::new(
                "model",
                Status::Ok,
                json!({"engine":"cpu","force_cpu":true,"runtime_restarted":restart,
                    "stopped_pid":owner.as_ref().map(|owner| owner.pid)}),
                Vec::new(),
            ),
        };
        output.details = serde_json::to_value(&receipt)?;
        if reset_reconciled {
            output.details["reset_postcondition_confirmed_by_read"] = json!(true);
        }
        if let Some(warning) = receipt.warning {
            output.errors.push(warning);
        }
        // Files/config are already accepted. Marker cleanup must not undo them.
        if let Err(error) = maintenance.finish() {
            output.status = Status::Warn;
            output.errors.push(format!(
                "model maintenance completed; marker cleanup pending: {error:#}"
            ));
        }
        Ok(output)
    })();
    if result.is_err() {
        maintenance
            .mark(super::lifecycle::Phase::Paused)
            .context("model maintenance failed and Paused fencing could not be restored")?;
    }
    result
}

fn force_stop_observed(
    health: &crate::net_rpc::Health,
    root: &Path,
    profile: &Path,
    binary: &Path,
    manifest: &crate::runtime_fetch::ManagedManifest,
    expected_account: Option<&str>,
) -> Result<()> {
    let endpoint = crate::rpc::endpoint_path();
    let original = fs::read(&endpoint)?;
    let record: serde_json::Value = serde_json::from_slice(&original)?;
    anyhow::ensure!(
        record["pid"].as_u64() == Some(u64::from(health.pid)),
        "CPU reset endpoint changed"
    );
    if crate::autostart::process_birth(health.pid)?.is_some() {
        verify_owner(
            health,
            root,
            profile,
            binary,
            manifest,
            None,
            expected_account,
        )?;
        let identity = crate::net_rpc::runtime_process_identity(health.pid)?;
        crate::net_rpc::kill_runtime(health.pid, &identity)?;
        crate::net_rpc::wait_until_exited(health.pid)?;
    }
    let _installation = LibraryLock::acquire(&root.join("runtime"), Duration::ZERO)?;
    let _library = LibraryLock::acquire(profile, Duration::ZERO)?;
    anyhow::ensure!(
        crate::autostart::process_birth(health.pid)?.is_none() && fs::read(&endpoint)? == original,
        "CPU reset old owner/endpoint changed; cleanup refused"
    );
    fs::remove_file(&endpoint)?;
    respire_spawn::durable::sync_directory(endpoint.parent().context("endpoint parent missing")?)?;
    Ok(())
}

fn exchange(
    takeover: &LibraryLock,
    maintenance: &mut super::lifecycle::Maintenance,
    kind: ModelMaintenanceKind,
    phase: ModelMaintenancePhase,
    expected: Option<&ModelMaintenanceReview>,
) -> Result<ModelMaintenanceReceipt> {
    let (binary, manifest) = super::model_control::installed_model_runtime()?;
    let (root, profile) = roots()?;
    anyhow::ensure!(
        takeover.protects(&root.join("runtime/takeover"))?,
        "model maintenance takeover mismatch"
    );
    let paused = maintenance
        .auth_launch_binding(&profile)?
        .context("model maintenance Paused marker missing")?;
    let expected_account = account(&profile)?;
    let grant_account = expected_account
        .clone()
        .unwrap_or_else(|| hash(profile.display().to_string().as_bytes()));
    let config = super::read_registration(&root)?;
    let managed = config
        .as_ref()
        .filter(|config| config.enabled && !config.manually_stopped)
        .map(|config| config.id.as_str());
    let (grant, _) = super::prepare_grant_for_identity(
        &binary,
        &root,
        &profile,
        managed,
        crate::net_rpc::rpc_port(),
        &grant_account,
        Some(paused),
    )?;
    let grant: HostControlLaunchGrant = serde_json::from_value(grant)?;
    anyhow::ensure!(
        grant.image_sha256.eq_ignore_ascii_case(&manifest.sha256),
        "model maintenance helper image changed"
    );
    let params = ModelMaintenanceParams {
        schema_version: MODEL_MAINTENANCE_SCHEMA_V,
        binding: ControlBinding {
            installation_root: root.clone(),
            profile: profile.clone(),
            launch_id: grant.instance_id.clone(),
            expected_account_id: expected_account.clone(),
        },
        kind,
        phase,
        expected: expected.cloned(),
    };
    let request = RpcRequest {
        v: respire_commands::rpc_client::PROTOCOL_V,
        id: uuid::Uuid::new_v4().to_string(),
        method: MODEL_MAINTENANCE_METHOD.into(),
        args: vec![serde_json::to_string(&params)?],
        scope: None,
        operation_id: None,
        idempotency_key: None,
        parent_operation_id: None,
        queue_wait_ms: None,
        lifecycle: None,
    };
    let mut receipt = None;
    super::exchange_control(
        &binary,
        &grant,
        &request,
        Instant::now() + Duration::from_secs(185),
        |response, pid| {
            anyhow::ensure!(
                response.v == request.v
                    && response.id == request.id
                    && response.pid == Some(pid)
                    && response.ok
                    && response.exit == 0
                    && response.scope.is_none()
                    && response.operation_id.is_none()
                    && response.idempotency_key.is_none()
                    && response.error.is_none()
                    && response.code.is_none(),
                "model maintenance response identity/failure"
            );
            if let Some(directory) = response.data_dir.as_ref() {
                anyhow::ensure!(
                    Path::new(directory).canonicalize()? == profile,
                    "model maintenance response profile mismatch"
                );
            }
            let envelope = response
                .envelope
                .context("model maintenance envelope missing")?;
            anyhow::ensure!(
                envelope.command == "model-maintenance"
                    && matches!(envelope.status, Status::Ok)
                    && envelope.errors.is_empty(),
                "invalid model maintenance envelope"
            );
            for (name, value) in [("control_ready", "true"), ("store_ready", "false")] {
                let mut items = envelope.items.iter().filter(|item| item.name == name);
                anyhow::ensure!(
                    items.next().is_some_and(|item| item.value == value
                        && if name == "control_ready" {
                            matches!(item.status, Status::Ok)
                        } else {
                            matches!(item.status, Status::Skip)
                        })
                        && items.next().is_none(),
                    "model maintenance helper readiness missing"
                );
            }
            let read: ModelMaintenanceReceipt = serde_json::from_value(envelope.details.clone())?;
            anyhow::ensure!(
                read.plan.kind == kind
                    && read.phase == phase
                    && [
                        &read.plan.review.selection_sha256,
                        &read.plan.review.revision_sha256
                    ]
                    .into_iter()
                    .all(|digest| digest.len() == 64
                        && digest
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
                    && expected.is_none_or(|expected| read.plan.review == *expected),
                "model maintenance returned another reviewed operation"
            );
            receipt = Some(read);
            Ok(envelope)
        },
    )?;
    anyhow::ensure!(
        roots()? == (root, profile.clone()) && account(&profile)? == expected_account,
        "model maintenance scope changed during exchange"
    );
    maintenance
        .auth_launch_binding(&profile)?
        .context("model maintenance lost Paused authority")?;
    receipt.context("model maintenance receipt missing")
}

fn check_path(path: &Path) -> Result<()> {
    anyhow::ensure!(
        path.is_absolute() && path.to_str().is_some(),
        "model maintenance path must be absolute Unicode"
    );
    let mut prefix = PathBuf::new();
    for component in path.components() {
        anyhow::ensure!(
            !matches!(component, Component::ParentDir | Component::CurDir),
            "model path has dot components"
        );
        if let Component::Normal(name) = component {
            let text = name.to_str().context("model path must be Unicode")?;
            anyhow::ensure!(
                !text.contains([':', '\\']) && !text.ends_with(['.', ' ']),
                "ambiguous model path"
            );
        }
        prefix.push(component.as_os_str());
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        match fs::symlink_metadata(&prefix) {
            Ok(metadata) => {
                anyhow::ensure!(
                    !metadata.file_type().is_symlink(),
                    "model maintenance cannot follow symlinks"
                );
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    anyhow::ensure!(
                        metadata.file_attributes() & 0x400 == 0,
                        "model maintenance cannot follow reparse points"
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn local_m3_directory() -> Result<PathBuf> {
    let home = || {
        dirs::home_dir()
            .or_else(|| respire_client_host::env::var_os("HOME").map(PathBuf::from))
            .or_else(|| respire_client_host::env::var_os("USERPROFILE").map(PathBuf::from))
    };
    let raw = respire_client_host::env::var_os("RSRS_M3_DIR");
    let path = if let Some(raw) = raw {
        let raw = raw.to_str().context("RSRS_M3_DIR must be Unicode")?.trim();
        anyhow::ensure!(!raw.is_empty(), "RSRS_M3_DIR must not be empty");
        match raw.strip_prefix("~/") {
            Some(rest) => home().context("model override home missing")?.join(rest),
            None => PathBuf::from(raw),
        }
    } else if let Some(root) = respire_client_host::env::var_os("RSRS_DATA_DIR") {
        PathBuf::from(root).join("models/bge-m3")
    } else {
        home()
            .context("model home missing")?
            .join(".rsrs/models/bge-m3")
    };
    Ok(std::path::absolute(path)?)
}

fn remove_m3(root: &Path, profile: &Path, target: &Path) -> Result<bool> {
    let local = local_m3_directory()?;
    anyhow::ensure!(
        target == local
            && !target
                .to_string_lossy()
                .replace('\\', "/")
                .contains("/usr/lib/respire/models")
            && target.parent().is_some(),
        "uninstall target is outside the exact local model destination"
    );
    check_path(target)?;
    for protected in [
        Some(root.to_path_buf()),
        Some(profile.to_path_buf()),
        dirs::home_dir(),
    ]
    .into_iter()
    .flatten()
    {
        anyhow::ensure!(
            target != protected && !protected.starts_with(target),
            "refusing to remove an installation/profile/home ancestor"
        );
    }
    match fs::symlink_metadata(target) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
        Ok(metadata) => anyhow::ensure!(
            metadata.is_dir(),
            "model uninstall target is not a directory"
        ),
    }
    let canonical = target.canonicalize()?;
    for protected in [
        Some(root.to_path_buf()),
        Some(profile.to_path_buf()),
        dirs::home_dir(),
    ]
    .into_iter()
    .flatten()
    {
        let protected = protected.canonicalize()?;
        anyhow::ensure!(
            canonical != protected && !protected.starts_with(&canonical),
            "canonical model target is an installation/profile/home ancestor"
        );
    }
    let mut pending = vec![target.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            check_path(&path)?;
            anyhow::ensure!(
                path.canonicalize()?.starts_with(&canonical),
                "model deletion escapes its exact target"
            );
            let metadata = fs::symlink_metadata(&path)?;
            anyhow::ensure!(
                metadata.is_dir() || metadata.is_file(),
                "model deletion refuses special files"
            );
            if metadata.is_dir() {
                pending.push(path);
            }
        }
    }
    check_path(target)?;
    anyhow::ensure!(
        target.canonicalize()? == canonical,
        "model uninstall target changed"
    );
    fs::remove_dir_all(target)?;
    Ok(true)
}

#[cfg(not(windows))]
fn install_catalog(_root: &Path, pin: Option<&ModelCatalogPin>) -> Result<Vec<String>> {
    anyhow::ensure!(pin.is_none(), "Windows ML plan is invalid on this host");
    Ok(Vec::new())
}

#[cfg(windows)]
fn install_catalog(root: &Path, pin: Option<&ModelCatalogPin>) -> Result<Vec<String>> {
    let pin = pin.context("Windows ML catalog plan missing")?;
    let arch = if cfg!(target_arch = "x86_64") {
        "x64"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        anyhow::bail!("unsupported Windows ML architecture")
    };
    let directory = root.join("engines/winml-2.4.89");
    let dll = directory.join("Microsoft.Windows.AI.MachineLearning.dll");
    anyhow::ensure!(
        pin.version == "2.4.89"
            && pin.package_source == PACKAGE_SOURCE
            && pin.package_sha256 == PACKAGE_SHA256
            && pin.destination == dll
            && pin.archive_member
                == format!("runtimes/win-{arch}/native/Microsoft.Windows.AI.MachineLearning.dll"),
        "catalog plan differs from local official pin/architecture/destination"
    );
    check_path(&dll)?;
    fs::create_dir_all(&directory)?;
    let package = directory.join(".winml-2.4.89.nupkg");
    check_path(&package)?;
    respire_commands::model_download::download_with_fallback(
        &[PACKAGE_SOURCE.into()],
        &package,
        PACKAGE_SHA256,
        false,
        Default::default(),
        None,
    )?;
    let mut archive = zip::ZipArchive::new(fs::File::open(&package)?)?;
    for (member, destination, limit) in [
        (
            pin.archive_member.as_str(),
            dll.clone(),
            64 * 1024 * 1024u64,
        ),
        ("license.txt", directory.join("license.txt"), 1024 * 1024u64),
    ] {
        let file = archive.by_name(member)?;
        anyhow::ensure!(
            file.is_file() && file.size() <= limit,
            "catalog package member is not a bounded regular file"
        );
        let mut bytes = Vec::new();
        file.take(limit + 1).read_to_end(&mut bytes)?;
        anyhow::ensure!(
            bytes.len() as u64 <= limit,
            "catalog package member exceeds bound"
        );
        if destination == dll {
            anyhow::ensure!(
                bytes.len() as u64 == pin.dll_size && hash(&bytes) == pin.dll_sha256,
                "catalog DLL differs from Runtime official pin"
            );
        }
        publish(&destination, &bytes)?;
    }
    // Only the host invokes Windows ML's installer. A provider manifest is not
    // proof that an unpinned hardware payload is safe or ready for inference.
    let providers = respire_spawn::install_accelerators(&dll)?;
    publish(
        &root.join("engines/providers.json"),
        &serde_json::to_vec_pretty(&providers)?,
    )?;
    Ok(providers.into_keys().collect())
}

#[cfg(windows)]
fn publish(target: &Path, bytes: &[u8]) -> Result<()> {
    check_path(target)?;
    let parent = target.parent().context("catalog target parent missing")?;
    let staged = parent.join(format!(".catalog-{}", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&staged)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        check_path(target)?;
        if target.try_exists()? {
            respire_spawn::durable::replace_file(&staged, target)?;
        } else {
            respire_spawn::durable::publish_new_file(&staged, target)?;
        }
        Ok(())
    })();
    if result.is_err() && staged.try_exists()? {
        fs::remove_file(staged)?;
    }
    result
}
