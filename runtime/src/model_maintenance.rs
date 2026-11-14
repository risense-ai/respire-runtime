//! Fixed model maintenance adapter. Never downloads, extracts or deletes assets.
use anyhow::{Context, Result};
use respire_commands::output::{ResultEnvelope, Status};
use respire_protocol::model_maintenance::*;
#[cfg(windows)]
use respire_protocol::ModelInstallIntent;
use respire_protocol::{HostControlLaunchGrant, RpcRequest};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
#[cfg(windows)]
use std::io::Read;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(windows)]
const PACKAGE_SOURCE: &str = "https://api.nuget.org/v3-flatcontainer/microsoft.windows.ai.machinelearning/2.4.89/microsoft.windows.ai.machinelearning.2.4.89.nupkg";
#[cfg(windows)]
const PACKAGE_SHA256: &str = "5c68ecfb947223267abf159a023f5192ad42725e4e9cc995e7c1470dd54dff63";

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn read(path: &Path) -> Result<Option<Vec<u8>>> {
    crate::startup_identity::read_private_file(path)
}

struct Settings {
    target: PathBuf,
    source: PathBuf,
    target_bytes: Option<Vec<u8>>,
    source_bytes: Option<Vec<u8>>,
    value: Value,
}

fn settings(root: &Path) -> Result<Settings> {
    let target = root.join("inference.json");
    let target_bytes = read(&target)?;
    let mut source = target.clone();
    let mut source_bytes = target_bytes.clone();
    if source_bytes.is_none() && respire_app::env::var_os("RSRS_DATA_DIR").is_none() {
        for legacy in ["~/.respire/inference.json", "~/.onememory/inference.json"] {
            let candidate = respire_app::memory::bge::expand_home(legacy);
            if let Some(bytes) = read(&candidate)? {
                source = candidate;
                source_bytes = Some(bytes);
                break;
            }
        }
    }
    let value: Value = source_bytes
        .as_deref()
        .map(serde_json::from_slice)
        .transpose()?
        .unwrap_or_else(|| json!({"engine":"cpu"}));
    anyhow::ensure!(value.is_object(), "inference.json must contain an object");
    Ok(Settings {
        target,
        source,
        target_bytes,
        source_bytes,
        value,
    })
}

fn cpu_candidate(value: &Value) -> Result<Vec<u8>> {
    let mut value = value.clone();
    if let Some(model) = value.get("model") {
        let model = respire_app::memory::onnx::parse_variant(
            model
                .as_str()
                .context("inference.json model must be a string")?,
        )?;
        value["model"] = json!(model.name);
    }
    value["engine"] = json!("cpu");
    value["force_cpu"] = json!(true);
    Ok(serde_json::to_vec_pretty(&value)?)
}

fn plan(
    kind: ModelMaintenanceKind,
    root: &Path,
    profile: &Path,
    settings: &Settings,
) -> Result<ModelMaintenancePlan> {
    let selected = respire_app::embedding::saved_selection()?;
    if kind == ModelMaintenanceKind::ResetCpu {
        anyhow::ensure!(selected.is_none(), "library uses a model profile; use model switch PROFILE --backend onnx --engine cpu for CPU recovery");
    }
    let registry = read(&root.join("embedding-profiles-v1.json"))?;
    let client = read(&respire_app::service::client_config_path())?;
    let selection_sha256 = hash(&serde_json::to_vec(&(
        MODEL_MAINTENANCE_SCHEMA_V,
        kind,
        root,
        profile,
        &selected,
        &registry,
        respire_app::env::var_os("RSRS_ENGINE"),
        respire_app::env::var_os("RSRS_MODEL_VARIANT"),
        respire_app::env::var_os("RSRS_M3_DIR"),
    ))?);
    let revision_sha256 = hash(&serde_json::to_vec(&(
        &selection_sha256,
        &settings.target,
        &settings.target_bytes,
        &settings.source,
        &settings.source_bytes,
        &client,
    ))?);
    let mut result = ModelMaintenancePlan {
        kind,
        review: ModelMaintenanceReview {
            selection_sha256,
            revision_sha256,
        },
        preparation: None,
        catalog: None,
        uninstall_directory: None,
        cpu_candidate_sha256: None,
    };
    match kind {
        ModelMaintenanceKind::ResetCpu => {
            result.cpu_candidate_sha256 = Some(hash(&cpu_candidate(&settings.value)?))
        }
        ModelMaintenanceKind::UninstallM3 => {
            let directory =
                std::path::absolute(respire_commands::model_assets::model_directory()?)?;
            anyhow::ensure!(
                !directory
                    .to_string_lossy()
                    .replace('\\', "/")
                    .contains("/usr/lib/respire/models"),
                "refusing to delete the system model dir"
            );
            result.uninstall_directory = Some(directory);
        }
        ModelMaintenanceKind::InstallEngines => {
            #[cfg(windows)]
            {
                let intent = ModelInstallIntent {
                    for_engine: Some("npu".into()),
                    ..Default::default()
                };
                result.preparation = Some(respire_commands::model_assets::model_preparation_plan(
                    &intent,
                )?);
                let (_, dll_size, dll_sha256) =
                    respire_app::memory::onnx::accelerator_catalog_metadata();
                let destination =
                    root.join("engines/winml-2.4.89/Microsoft.Windows.AI.MachineLearning.dll");
                let arch = if cfg!(target_arch = "x86_64") {
                    "x64"
                } else if cfg!(target_arch = "aarch64") {
                    "arm64"
                } else {
                    anyhow::bail!("unsupported Windows ML architecture")
                };
                result.catalog = Some(ModelCatalogPin {
                    version: "2.4.89".into(),
                    package_source: PACKAGE_SOURCE.into(),
                    package_sha256: PACKAGE_SHA256.into(),
                    archive_member: format!(
                        "runtimes/win-{arch}/native/Microsoft.Windows.AI.MachineLearning.dll"
                    ),
                    destination,
                    dll_size,
                    dll_sha256,
                });
            }
        }
    }
    Ok(result)
}

/// The shared dispatcher consumes the same bounded two frames, then calls this
/// adapter and appends control_ready=true/store_ready=false to its envelope.
pub(crate) fn execute(
    grant: HostControlLaunchGrant,
    request: &RpcRequest,
) -> Result<ResultEnvelope> {
    anyhow::ensure!(
        request.v == respire_commands::rpc_worker::PROTOCOL_V
            && request.method == MODEL_MAINTENANCE_METHOD
            && request.args.len() == 1
            && uuid::Uuid::parse_str(&request.id)
                .is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == request.id)
            && request.scope.is_none()
            && request.operation_id.is_none()
            && request.idempotency_key.is_none()
            && request.parent_operation_id.is_none()
            && request.queue_wait_ms.is_none()
            && request.lifecycle.is_none(),
        "invalid model maintenance request"
    );
    let params: ModelMaintenanceParams = serde_json::from_str(&request.args[0])?;
    anyhow::ensure!(
        params.schema_version == MODEL_MAINTENANCE_SCHEMA_V
            && (params.phase == ModelMaintenancePhase::Plan) == params.expected.is_none()
            && params.expected.as_ref().is_none_or(
                |review| digest(&review.selection_sha256) && digest(&review.revision_sha256)
            )
            && !(params.phase == ModelMaintenancePhase::Apply
                && params.kind != ModelMaintenanceKind::ResetCpu)
            && !(params.phase == ModelMaintenancePhase::Verify
                && params.kind == ModelMaintenanceKind::ResetCpu),
        "invalid fixed model maintenance phase/revision"
    );
    crate::startup_identity::authorize_model_control(grant)?;
    crate::host_control::watch_control_parent()?;
    crate::startup_identity::verify_control_binding(&params.binding)?;
    if params.phase == ModelMaintenancePhase::Verify {
        respire_commands::model_assets::enable_backend_probe_host(
            respire_commands::model_assets::BackendProbeHost::PrivateControl);
    }
    let root = &params.binding.installation_root;
    let profile = &params.binding.profile;
    let sdk_root = respire_app::env::var_os("RSRS_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| respire_app::memory::bge::expand_home("~/.rsrs"));
    anyhow::ensure!(
        sdk_root.canonicalize()? == *root,
        "SDK inference settings root differs from authorized installation"
    );
    // CPU Plan is a read-only preflight: reject active profiles before stopping
    // the owner. Apply recomputes this review after owning both existing locks.
    let _ownership = if params.kind == ModelMaintenanceKind::ResetCpu
        && params.phase == ModelMaintenancePhase::Plan
    {
        None
    } else {
        let installation =
            respire_app::lock::LibraryLock::acquire(&root.join("runtime"), Duration::ZERO)
                .context("model maintenance requires installation owner exit")?;
        let library = respire_app::lock::LibraryLock::acquire(profile, Duration::ZERO)
            .context("model maintenance requires library owner exit")?;
        Some((installation, library))
    };
    // Same cross-process lock as the existing engine/variant setters.
    let lock_path = root.join("inference.json.lock");
    match fs::symlink_metadata(&lock_path) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "inference configuration lock is not a regular local path"
            );
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                anyhow::ensure!(
                    metadata.file_attributes() & 0x400 == 0,
                    "inference configuration lock is a reparse point"
                );
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let config_lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)?;
    config_lock.lock()?;
    let before = settings(root)?;
    let _legacy_lock = if before.source != before.target {
        let path = before.source.with_file_name("inference.json.lock");
        read(&path)?;
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        lock.lock()?;
        anyhow::ensure!(
            read(&before.source)? == before.source_bytes,
            "legacy inference source changed while obtaining its configuration lock"
        );
        Some(lock)
    } else {
        None
    };
    let planned = plan(params.kind, root, profile, &before)?;
    anyhow::ensure!(
        params
            .expected
            .as_ref()
            .is_none_or(|expected| *expected == planned.review),
        "model maintenance selection/revision conflict; no mutation performed"
    );
    crate::startup_identity::verify_control_binding(&params.binding)?;
    let mut receipt = ModelMaintenanceReceipt {
        plan: planned,
        phase: params.phase,
        verified: false,
        config_applied: false,
        npu_ready: false,
        warning: None,
    };
    match (params.kind, params.phase) {
        (_, ModelMaintenancePhase::Plan) => {}
        (ModelMaintenanceKind::ResetCpu, ModelMaintenancePhase::Apply) => {
            let candidate = cpu_candidate(&before.value)?;
            // Recheck the complete read set under the existing configuration lock.
            anyhow::ensure!(
                plan(params.kind, root, profile, &settings(root)?)?.review == receipt.plan.review,
                "model reset revision changed before CAS"
            );
            let staged = root.join(format!(".inference-reset-{}.json", uuid::Uuid::new_v4()));
            let result = (|| -> Result<()> {
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&staged)?;
                file.write_all(&candidate)?;
                file.sync_all()?;
                crate::startup_identity::verify_control_binding(&params.binding)?;
                anyhow::ensure!(
                    read(&before.target)? == before.target_bytes,
                    "model reset target revision conflict"
                );
                if before.target_bytes.is_some() {
                    respire_spawn::durable::replace_file(&staged, &before.target)?;
                } else {
                    respire_spawn::durable::publish_new_file(&staged, &before.target)?;
                }
                Ok(())
            })();
            if result.is_err() && staged.try_exists()? {
                fs::remove_file(&staged)?;
            }
            result?;
            anyhow::ensure!(
                read(&before.target)?.as_deref() == Some(candidate.as_slice()),
                "CPU reset outcome unknown; inspect configuration, do not replay"
            );
            receipt.config_applied = true;
            receipt.verified = true;
        }
        (ModelMaintenanceKind::UninstallM3, ModelMaintenancePhase::Verify) => {
            let directory = receipt
                .plan
                .uninstall_directory
                .as_ref()
                .context("uninstall target missing")?;
            anyhow::ensure!(
                fs::symlink_metadata(directory)
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                "model uninstall not complete; target still exists or cannot be inspected"
            );
            receipt.verified = true;
        }
        (ModelMaintenanceKind::InstallEngines, ModelMaintenancePhase::Verify) => {
            #[cfg(windows)]
            {
                let pin = receipt
                    .plan
                    .catalog
                    .as_ref()
                    .context("catalog pin missing")?;
                let metadata = fs::symlink_metadata(&pin.destination)?;
                anyhow::ensure!(
                    metadata.is_file() && metadata.len() == pin.dll_size,
                    "installed catalog is not the pinned regular file"
                );
                let mut bytes = Vec::new();
                fs::File::open(&pin.destination)?
                    .take(pin.dll_size + 1)
                    .read_to_end(&mut bytes)?;
                anyhow::ensure!(
                    bytes.len() as u64 == pin.dll_size && hash(&bytes) == pin.dll_sha256,
                    "installed catalog differs from the official pin"
                );
                let preparation = receipt
                    .plan
                    .preparation
                    .as_ref()
                    .context("NPU preparation selection missing")?;
                let intent = ModelInstallIntent {
                    for_engine: Some("npu".into()),
                    ..Default::default()
                };
                receipt.plan.preparation =
                    Some(respire_commands::model_assets::model_preparation_verify(
                        &intent,
                        &preparation.selection_sha256,
                    )?);
                // Hardware-specific provider payloads have no pin in this contract.
                receipt.warning = Some("npu_provider_unverified: providers installed; catalog integrity does not attest provider payloads or NPU readiness".into());
            }
            receipt.verified = true;
        }
        _ => anyhow::bail!("unsupported model maintenance phase"),
    }
    crate::startup_identity::verify_control_binding(&params.binding)?;
    if !receipt.config_applied {
        anyhow::ensure!(
            plan(params.kind, root, profile, &settings(root)?)?.review == receipt.plan.review,
            "model maintenance selection/revision changed during verification"
        );
    }
    let mut envelope = ResultEnvelope::new(
        "model-maintenance",
        Status::Ok,
        json!({"kind":params.kind,"phase":params.phase,"verified":receipt.verified}),
        Vec::new(),
    );
    envelope.details = serde_json::to_value(receipt)?;
    Ok(envelope)
}
