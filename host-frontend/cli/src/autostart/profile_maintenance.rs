//! Profile removal owns existing host maintenance; all destructive effects stay in Runtime.
use anyhow::{Context, Result};
use respire_client_host::lock::LibraryLock;
use respire_commands::output::{Item as OutputItem, ResultEnvelope, Status};
use respire_protocol::profile_maintenance::*;
use respire_protocol::{HostAuthIdentity, RpcRequest, RpcResponse};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Original {
    operation: HostProfileRemoveOperation,
    token: String,
    coordinator: String,
    was_serving: bool,
    store_ready: bool,
    sent: bool,
    receipt: Option<HostProfileRemoveResult>,
    finished: bool,
}

fn canonical_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value)
        .is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == value)
}

fn read_record(path: &Path) -> Result<Option<(Vec<u8>, String)>> {
    let path = respire_client_host::config::normalize_control_path(path)?;
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(metadata.is_file() && metadata.len() <= 16 * 1024,
        "invalid profile removal recovery record");
    let mut bytes = Vec::new();
    std::fs::File::open(&path)?.take(16 * 1024 + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 16 * 1024, "profile removal recovery record exceeds its bound");
    let digest = super::hash(&bytes);
    Ok(Some((bytes, digest)))
}

fn validate_receipt(receipt: &HostProfileRemoveResult, original: &HostProfileRemoveOperation) -> Result<()> {
    anyhow::ensure!(receipt.operation_id == original.operation_id
        && receipt.fingerprint == original.fingerprint && receipt.identity == original.identity,
        "profile removal receipt changed its original operation");
    Ok(())
}

pub(crate) fn control_account_remove(name: &str) -> Result<ResultEnvelope> {
    remove(Some(name), None, false)
}

pub(crate) fn control_space_remove(name: &str) -> Result<ResultEnvelope> {
    let name = crate::profile_control::validated_space_name(name)?;
    remove(Some(name), None, true)
}

/// Query an original operation. This entry never sends FirstAttempt, even if no
/// journal record exists. The saved source profile must still be selected.
pub(crate) fn control_profile_remove_result(operation_id: &str) -> Result<ResultEnvelope> {
    anyhow::ensure!(canonical_id(operation_id), "invalid original profile removal operation ID");
    remove(None, Some(operation_id), false)
}

fn account(identity: &HostAuthIdentity, profile: &Path) -> String {
    match identity {
        HostAuthIdentity::Bound { account_id, .. } => account_id.clone(),
        _ => super::hash(profile.display().to_string().as_bytes()),
    }
}

fn remove(name: Option<&str>, query: Option<&str>, space: bool) -> Result<ResultEnvelope> {
    crate::runtime_policy::require_host("profile removal")?;
    anyhow::ensure!(super::lifecycle::current_boot_token().is_none(), "profile removal must own host maintenance");
    let takeover = crate::runtime_policy::takeover_lock()?;
    let (binary, manifest) = super::model_control::installed_model_runtime()?;
    let (root, profile) = respire_client_host::config::control_roots()?;
    std::fs::create_dir_all(&profile)?;
    let root = root.canonicalize()?;
    let profile = profile.canonicalize()?;
    let directory = root.join("runtime/autostart/profile-removals");
    let pending = directory.join("pending.json");
    let pending_record = read_record(&pending)?;
    let pending_id: Option<String> = pending_record.as_ref().map(|(bytes, _)|
        serde_json::from_slice(bytes)).transpose().context("invalid profile removal pending operation")?;
    if let Some(id) = pending_id.as_ref() {
        anyhow::ensure!(canonical_id(id), "invalid pending profile removal ID");
    }
    let selected = query.map(str::to_owned).or_else(|| pending_id.clone());
    let (mut original, path, mut digest, existing) = if let Some(id) = selected {
        let path = directory.join(format!("{id}.json"));
        let (bytes, digest) = read_record(&path)?.context(
            "original profile removal request missing; outcome unknown; no deletion was replayed")?;
        let original: Original = serde_json::from_slice(&bytes).context("invalid original profile removal request")?;
        anyhow::ensure!(original.operation.operation_id == id && canonical_id(&id)
            && original.operation.key == id && original.operation.schema_version == HOST_PROFILE_SCHEMA_V
            && original.operation.fingerprint == super::hash(&original.operation.fingerprint_bytes()?)
            && canonical_id(&original.token) && canonical_id(&original.coordinator)
            && name.is_none_or(|name| original.operation.name == name),
            "another original profile removal owns recovery; do not replace it");
        (original, path, Some(digest), true)
    } else {
        let name = name.context("profile removal needs an original operation")?;
        anyhow::ensure!(name != "main", "main is reserved and cannot be removed");
        let target = crate::profile_control::ProfileTarget::new(name, false)?;
        target.verify_existing()?;
        let target = target.directory().canonicalize()?;
        if target == profile {
            return Err(respire_client_host::input_error::InputError(
                "this profile is in use; select another profile before deleting".into(),
            ).into());
        }
        let id = uuid::Uuid::new_v4().to_string();
        let mut operation = HostProfileRemoveOperation { schema_version: HOST_PROFILE_SCHEMA_V,
            operation_id: id.clone(), key: id.clone(), installation_root: root.clone(), profile: profile.clone(),
            identity: super::control::identity(&profile)?, name: name.to_owned(),
            target_identity: super::control::identity(&target)?, fingerprint: String::new() };
        operation.fingerprint = super::hash(&operation.fingerprint_bytes()?);
        (Original { operation, token: String::new(), coordinator: String::new(), was_serving: false,
            store_ready: false, sent: false, receipt: None, finished: false },
            directory.join(format!("{id}.json")), None, false)
    };
    anyhow::ensure!(original.operation.installation_root == root && original.operation.profile == profile
        && super::control::identity(&profile)? == original.operation.identity,
        "select the original source profile and identity before querying removal");
    if let Some(receipt) = original.receipt.as_ref() {
        validate_receipt(receipt, &original.operation)?;
        anyhow::ensure!(original.sent && receipt.outcome == HostProfileRemoveOutcome::Committed,
            "invalid saved terminal profile removal receipt");
    }
    if original.finished {
        let receipt = original.receipt.as_ref().context("finished profile removal lacks a receipt")?;
        let mut envelope = rendered(&original.operation, receipt, space);
        if pending_id.as_deref() == Some(original.operation.operation_id.as_str()) {
            if let Err(error) = clear_pending(&pending, &original.operation.operation_id) {
                envelope.status = Status::Warn;
                envelope.errors.push(format!("profile removal committed; pending cleanup warning: {error:#}"));
            }
        }
        return Ok(envelope);
    }
    anyhow::ensure!(pending_id.is_none() || pending_id.as_deref() == Some(original.operation.operation_id.as_str()),
        "another profile removal owns active maintenance");
    let registration = super::read_registration(&root)?;
    let managed = registration.as_ref().filter(|config| config.enabled && !config.manually_stopped);
    let owner = crate::rpc::probe_runtime()?;
    anyhow::ensure!(owner.is_some() || !crate::rpc::endpoint_path().try_exists()?,
        "profile removal has a recorded owner without verifiable health; no offline stop was inferred");
    if let Some(config) = managed {
        super::lifecycle::owned(config)?;
        super::lifecycle::ensure_control_endpoint(config)?;
        anyhow::ensure!(owner.is_some() || !super::super::super::manager::inspect(config)?.running,
            "profile removal cannot identify the registered serving owner");
    }
    let account = account(&original.operation.identity, &profile);
    if let Some(owner) = owner.as_ref() {
        super::model_control::verify_model_owner(owner, &root, &profile, managed, &binary, &manifest, Some(&account))?;
    }
    let mut maintenance = if existing {
        super::lifecycle::resume_identity_write_maintenance(&root, &profile, &original.token, &original.coordinator)?
    } else {
        let mut maintenance = super::lifecycle::begin_maintenance_locked()?;
        let binding = maintenance.auth_launch_binding(&profile)?.context("profile removal needs actual Paused maintenance")?;
        original.token = super::lifecycle::current_boot_token().context("profile removal maintenance token missing")?;
        original.coordinator = binding["coordinator_id"].as_str().context("profile removal coordinator missing")?.to_owned();
        original.was_serving = owner.is_some();
        original.store_ready = owner.as_ref().is_some_and(|health| health.store_ready);
        let bytes = serde_json::to_vec(&original)?;
        super::private_write(&path, &bytes, None)?;
        digest = Some(super::hash(&bytes));
        super::private_write(&pending, &serde_json::to_vec(&original.operation.operation_id)?, None)?;
        maintenance
    };
    let source_identity = original.operation.identity.clone();
    let unchanged = || -> Result<()> {
        let (current_binary, current_manifest) = super::model_control::installed_model_runtime()?;
        let (current_root, current_profile) = respire_client_host::config::control_roots()?;
        anyhow::ensure!(current_binary == binary && current_manifest.version == manifest.version
            && current_manifest.sha256.eq_ignore_ascii_case(&manifest.sha256)
            && current_root.canonicalize()? == root && current_profile.canonicalize()? == profile
            && super::control::identity(&profile)? == source_identity,
            "profile removal source selection, image or identity changed");
        Ok(())
    };
    let mut finished = false;
    let result: Result<ResultEnvelope> = (|| {
        maintenance.check_account_runtime()?;
        if let Some(owner) = owner.as_ref() { maintenance.drain_runtime(owner)?; }
        maintenance.auth_launch_binding(&profile)?.context("profile removal lost its Paused authority")?;
        unchanged()?;
        let receipt = if let Some(receipt) = original.receipt.clone() { receipt } else {
            let method = if query.is_some() || original.sent { HOST_PROFILE_RESULT_METHOD } else {
                original.sent = true;
                let bytes = serde_json::to_vec(&original)?;
                super::private_write(&path, &bytes, digest.as_deref())?;
                digest = Some(super::hash(&bytes));
                HOST_PROFILE_REMOVE_METHOD
            };
            let receipt = exchange(&takeover, &mut maintenance, &original.operation, method)?;
            anyhow::ensure!(receipt.outcome == HostProfileRemoveOutcome::Committed,
                "profile removal outcome unknown; query the original operation; no deletion was replayed");
            original.receipt = Some(receipt.clone());
            let bytes = serde_json::to_vec(&original)?;
            super::private_write(&path, &bytes, digest.as_deref())?;
            digest = Some(super::hash(&bytes));
            receipt
        };
        unchanged()?;
        // A later manual stop overrides the original serving state.
        if original.was_serving && registration.as_ref().is_none_or(|config| !config.manually_stopped) {
            maintenance.start_account_runtime()?;
            let restored = crate::rpc::probe_runtime()?.context("profile removal committed but original owner did not resume")?;
            super::model_control::verify_model_owner(&restored, &root, &profile, managed, &binary, &manifest, Some(&account))?;
            anyhow::ensure!(!original.store_ready || restored.store_ready,
                "profile removal committed but original owner store readiness was not restored");
        }
        unchanged()?;
        maintenance.finish()?;
        finished = true;
        original.finished = true;
        let bytes = serde_json::to_vec(&original)?;
        super::private_write(&path, &bytes, digest.as_deref()).context(
            "profile removal committed and maintenance finished; completion record persistence needs recovery")?;
        let mut envelope = rendered(&original.operation, &receipt, space);
        if let Err(error) = clear_pending(&pending, &original.operation.operation_id) {
            envelope.status = Status::Warn;
            envelope.errors.push(format!("profile removal committed; pending cleanup warning: {error:#}"));
        }
        Ok(envelope)
    })();
    result.map_err(|error| {
        let state = if original.receipt.is_some() { "committed; owner/maintenance completion needs recovery" }
            else { "outcome unknown; query only, never replace the original operation" };
        let pause = if finished { Ok(()) } else { maintenance.mark(super::lifecycle::Phase::Paused) };
        error.context(format!("profile removal {state}; operation_id={}; Paused publication: {pause:?}",
            original.operation.operation_id))
    })
}

fn clear_pending(path: &Path, expected: &str) -> Result<()> {
    let Some((bytes, _)) = read_record(path)? else { return Ok(()); };
    let id: String = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(id == expected, "profile removal pending record changed");
    std::fs::remove_file(path)?;
    respire_spawn::durable::sync_directory(path.parent().context("pending profile removal parent missing")?)?;
    Ok(())
}

fn rendered(original: &HostProfileRemoveOperation, receipt: &HostProfileRemoveResult, space: bool) -> ResultEnvelope {
    let command = if space { "space" } else { "account" };
    let mut envelope = ResultEnvelope::new(command, Status::Ok,
        serde_json::json!({"action":"remove","name":original.name}),
        vec![OutputItem::new(if space { "space" } else { "profile" }, Status::Ok, "deleted")]);
    envelope.details = serde_json::json!({"operation_id":receipt.operation_id,
        "fingerprint":receipt.fingerprint,"outcome":receipt.outcome});
    envelope
}

fn exchange(takeover: &LibraryLock, maintenance: &mut super::lifecycle::Maintenance,
    original: &HostProfileRemoveOperation, method: &str) -> Result<HostProfileRemoveResult> {
    let envelope = super::control::auth_exchange(takeover, maintenance,
        Instant::now() + Duration::from_secs(185), None, |binding, identity| {
            anyhow::ensure!(binding.installation_root == original.installation_root
                && binding.profile == original.profile && identity == original.identity,
                "profile removal exchange source changed");
            let params = HostProfileRemoveParams { schema_version: HOST_PROFILE_SCHEMA_V,
                binding, identity, original: original.clone() };
            Ok(RpcRequest { v: respire_commands::rpc_client::PROTOCOL_V, id: uuid::Uuid::new_v4().to_string(),
                method: method.to_owned(), args: vec![serde_json::to_string(&params)?], scope: None,
                operation_id: Some(original.operation_id.clone()), idempotency_key: Some(original.key.clone()),
                parent_operation_id: None, queue_wait_ms: None, lifecycle: None })
        }, |response, request, profile, pid| validate_response(response, request, profile, pid, original),
        |error| error)?;
    serde_json::from_value(envelope.summary).context("invalid private profile removal receipt")
}

fn validate_response(response: RpcResponse<ResultEnvelope>, request: &RpcRequest, profile: &Path,
    pid: u32, original: &HostProfileRemoveOperation) -> Result<ResultEnvelope> {
    anyhow::ensure!(response.v == request.v && response.id == request.id && response.pid == Some(pid)
        && response.bin == "rsrs-runtime" && response.scope.is_none() && response.web_url.is_none()
        && response.operation_id.as_deref() == Some(original.operation_id.as_str())
        && response.idempotency_key.as_deref() == Some(original.key.as_str()) && response.error.is_none(),
        "profile removal response binding mismatch");
    if let Some(directory) = &response.data_dir {
        anyhow::ensure!(Path::new(directory).canonicalize()? == profile, "profile removal response profile changed");
    }
    let envelope = response.envelope.context("profile removal envelope missing")?;
    anyhow::ensure!(envelope.command == "profile-control" && envelope.details.is_null()
        && envelope.items.len() == 2 && envelope.errors.is_empty() && envelope.actions.is_empty()
        && envelope.related.is_empty(), "invalid private profile removal envelope");
    for (name, value) in [("control_ready", "true"), ("store_ready", "false")] {
        let mut items = envelope.items.iter().filter(|item| item.name == name);
        anyhow::ensure!(items.next().is_some_and(|item| item.value == value && if name == "control_ready" {
            matches!(item.status, Status::Ok) } else { matches!(item.status, Status::Skip) }) && items.next().is_none(),
            "profile removal readiness mismatch");
    }
    let receipt: HostProfileRemoveResult = serde_json::from_value(envelope.summary.clone())?;
    validate_receipt(&receipt, original)?;
    anyhow::ensure!(super::control::identity(profile)? == original.identity, "profile removal source identity changed");
    match receipt.outcome {
        HostProfileRemoveOutcome::Unknown => anyhow::ensure!(!response.ok && response.exit == 2
            && response.code.as_deref() == Some("profile_remove_outcome_unknown")
            && matches!(envelope.status, Status::Fail), "invalid unknown profile removal result"),
        HostProfileRemoveOutcome::Committed => anyhow::ensure!(response.ok && response.exit == 0
            && response.code.is_none() && matches!(envelope.status, Status::Ok), "invalid committed profile removal result"),
    }
    Ok(envelope)
}
