//! Explicit legacy migration: Runtime owns the copy, credentials and completion marker.
use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use respire_client_host::lock::LibraryLock;
use respire_commands::output::{ResultEnvelope, Status};
use respire_protocol::migration_control::*;
use respire_protocol::{HostAuthIdentity, RpcRequest, RpcResponse};
use serde::{Deserialize, Serialize};

/// Original request/owner metadata and its confirmed terminal receipt; no library or credential.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Original {
    operation: HostMigrationOperation,
    token: String,
    coordinator: String,
    was_serving: bool,
    store_ready: bool,
    sent: bool,
    finished: bool,
    #[serde(default)]
    terminal_receipt: Option<HostMigrationResult>,
}

fn canonical_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == value)
}

fn read_original(path: &Path) -> Result<Option<(Original, String)>> {
    for ancestor in path.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                anyhow::ensure!(!metadata.file_type().is_symlink(), "migration recovery path is a symlink");
                #[cfg(windows)] {
                    use std::os::windows::fs::MetadataExt;
                    anyhow::ensure!(metadata.file_attributes() & 0x400 == 0, "migration recovery path is a reparse point");
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(metadata.is_file() && metadata.len() <= 16 * 1024, "invalid migration recovery metadata");
    let mut bytes = Vec::new();
    std::fs::File::open(path)?.take(16 * 1024 + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 16 * 1024, "migration recovery metadata exceeds its bound");
    let original = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid migration recovery metadata"))?;
    Ok(Some((original, super::hash(&bytes))))
}

pub(crate) fn control_migrate_profile(source_id: &str, account: &str) -> Result<ResultEnvelope> {
    crate::runtime_policy::require_host("explicit legacy migration")?;
    anyhow::ensure!(super::lifecycle::current_boot_token().is_none(), "migration must own host maintenance");
    anyhow::ensure!(source_id.len() == 64 && source_id.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        && !account.is_empty() && account != "main"
        && account.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c)), "invalid migration source or account");
    let takeover = crate::runtime_policy::takeover_lock()?;
    if crate::runtime_fetch::read_manifest()?.is_none() {
        crate::runtime_fetch::download_and_install(None, None)?;
    }
    let (binary, manifest) = super::model_control::installed_model_runtime()?;
    let (root, profile) = respire_client_host::config::control_roots()?;
    std::fs::create_dir_all(&root)?;
    std::fs::create_dir_all(&profile)?;
    let root = root.canonicalize()?;
    let profile = profile.canonicalize()?;
    let identity = super::control::identity(&profile)?;
    let mut operation = HostMigrationOperation { schema_version: HOST_MIGRATION_SCHEMA_V,
        operation_id: String::new(), key: String::new(), installation_root: root.clone(), profile: profile.clone(),
        identity, source_id: source_id.to_owned(), account: account.to_owned(), fingerprint: String::new() };
    operation.fingerprint = super::hash(&operation.fingerprint_bytes()?);
    let path = root.join("runtime/autostart/migrations").join(format!("{}.json", operation.fingerprint));
    let saved = read_original(&path)?;
    let registration = super::read_registration(&root)?;
    let managed = registration.as_ref().filter(|config| config.enabled && !config.manually_stopped);
    let owner = crate::rpc::probe_runtime()?;
    anyhow::ensure!(owner.is_some() || !crate::rpc::endpoint_path().try_exists()?,
        "migration has a recorded owner without verifiable health");
    if let Some(config) = managed {
        super::lifecycle::owned(config)?;
        super::lifecycle::ensure_control_endpoint(config)?;
        anyhow::ensure!(owner.is_some() || !super::super::super::manager::inspect(config)?.running,
            "migration cannot identify the registered supervisor's owner");
    }
    let account_id = match &operation.identity {
        HostAuthIdentity::Bound { account_id, .. } => account_id.clone(),
        _ => super::hash(profile.display().to_string().as_bytes()),
    };
    if let Some(owner) = owner.as_ref() {
        super::model_control::verify_model_owner(owner, &root, &profile, managed, &binary, &manifest, Some(&account_id))?;
    }
    let (mut original, mut digest, mut maintenance) = if let Some((original, digest)) = saved {
        operation.operation_id = original.operation.operation_id.clone();
        operation.key = original.operation.key.clone();
        anyhow::ensure!(operation == original.operation && canonical_id(&operation.operation_id)
            && operation.key == operation.operation_id && canonical_id(&original.token), "migration recovery binding changed");
        if original.finished {
            anyhow::ensure!(original.sent, "finished migration was never sent");
            let receipt = original.terminal_receipt.as_ref().context(
                "migration was already confirmed and maintenance finished, but this older recovery record has no terminal details; Runtime was not drained and no migration was replayed")?;
            validate_terminal_receipt(receipt, &original.operation, HOST_MIGRATION_PROFILE_METHOD)?;
            let mut envelope = ResultEnvelope::new("migrate", Status::Ok, receipt.details.clone(), Vec::new());
            envelope.details = receipt.details.clone();
            return Ok(envelope);
        }
        anyhow::ensure!(original.terminal_receipt.is_none(), "unfinished migration contains a terminal receipt");
        let maintenance = super::lifecycle::resume_identity_write_maintenance(
            &root, &profile, &original.token, &original.coordinator)?;
        (original, digest, maintenance)
    } else {
        let mut maintenance = super::lifecycle::begin_maintenance_locked()?;
        let binding = maintenance.auth_launch_binding(&profile)?.context("migration requires actual Paused maintenance")?;
        operation.operation_id = uuid::Uuid::new_v4().to_string();
        operation.key = operation.operation_id.clone();
        let original = Original { operation,
            token: super::lifecycle::current_boot_token().context("migration maintenance token missing")?,
            coordinator: binding["coordinator_id"].as_str().context("migration coordinator missing")?.to_owned(),
            was_serving: owner.is_some(), store_ready: owner.as_ref().is_some_and(|health| health.store_ready),
            sent: false, finished: false, terminal_receipt: None };
        let bytes = serde_json::to_vec(&original)?;
        super::private_write(&path, &bytes, None)?;
        (original, super::hash(&bytes), maintenance)
    };
    let expected_identity = original.operation.identity.clone();
    let unchanged = || -> Result<()> {
        let (current_binary, current_manifest) = super::model_control::installed_model_runtime()?;
        let (current_root, current_profile) = respire_client_host::config::control_roots()?;
        anyhow::ensure!(current_binary == binary && current_manifest.version == manifest.version
            && current_manifest.sha256.eq_ignore_ascii_case(&manifest.sha256)
            && current_root.canonicalize()? == root && current_profile.canonicalize()? == profile
            && super::control::identity(&profile)? == expected_identity, "migration installation or selection changed");
        Ok(())
    };
    let mut finished = false;
    let result: Result<ResultEnvelope> = (|| {
        maintenance.auth_launch_binding(&profile)?.context("migration lost its actual Paused grant")?;
        maintenance.check_account_runtime()?;
        if let Some(owner) = owner.as_ref() { maintenance.drain_runtime(owner)?; }
        anyhow::ensure!(!crate::net_rpc::port_is_open(), "migration requires a drained Runtime");
        unchanged()?;
        let method = if original.sent { HOST_MIGRATION_RESULT_METHOD } else {
            original.sent = true;
            let bytes = serde_json::to_vec(&original)?;
            super::private_write(&path, &bytes, Some(&digest))?;
            digest = super::hash(&bytes);
            HOST_MIGRATION_PROFILE_METHOD
        };
        // A saved sent request always queries. A timeout never admits a replacement operation.
        let receipt = exchange(&takeover, &mut maintenance, &original.operation, method)?;
        if receipt.outcome == HostMigrationOutcome::Unknown {
            let mut envelope = ResultEnvelope::new("migrate", Status::Fail, serde_json::json!({"outcome":"unknown"}), Vec::new());
            envelope.details = serde_json::to_value(&receipt)?;
            envelope.actions.push(format!("repeat migrate --source {} --account {} to query original operation {}; do not start another migration",
                source_id, account, original.operation.operation_id));
            crate::set_exit_code(2);
            return Ok(envelope);
        }
        unchanged()?;
        let restore_owner = original.was_serving;
        let restore_store = original.store_ready;
        if restore_owner {
            maintenance.start_account_runtime()?;
            let restored = crate::rpc::probe_runtime()?.context("original migration owner did not resume")?;
            super::model_control::verify_model_owner(&restored, &root, &profile, managed, &binary, &manifest, Some(&account_id))?;
            anyhow::ensure!(!restore_store || restored.store_ready, "restored migration owner did not confirm its original store readiness");
        }
        unchanged()?;
        maintenance.finish()?;
        finished = true;
        original.finished = true;
        let mut envelope = ResultEnvelope::new("migrate", Status::Ok, receipt.details.clone(), Vec::new());
        envelope.details = receipt.details.clone();
        original.terminal_receipt = Some(receipt);
        super::private_write(&path, &serde_json::to_vec(&original)?, Some(&digest))?;
        Ok(envelope)
    })();
    if !finished {
        maintenance.mark(super::lifecycle::Phase::Paused).map_err(|_| anyhow::anyhow!(
            "migration_outcome_unknown operation_id={}; Paused publication failed; query the original operation before recovery",
            original.operation.operation_id))?;
    }
    result.map_err(|_| anyhow::anyhow!("migration_outcome_unknown operation_id={}; repeat the same migrate --source --account to query; no migration was replayed", original.operation.operation_id))
}


fn exchange(takeover: &LibraryLock, maintenance: &mut super::lifecycle::Maintenance,
    original: &HostMigrationOperation, method: &str) -> Result<HostMigrationResult> {
    let envelope = super::control::auth_exchange(takeover, maintenance,
        Instant::now() + Duration::from_secs(185), None, |binding, identity| {
            anyhow::ensure!(binding.installation_root == original.installation_root && binding.profile == original.profile
                && identity == original.identity, "migration exchange selection changed");
            let params = HostMigrationParams { schema_version: HOST_MIGRATION_SCHEMA_V, binding, identity, original: original.clone() };
            Ok(RpcRequest { v: respire_commands::rpc_client::PROTOCOL_V, id: uuid::Uuid::new_v4().to_string(),
                method: method.to_owned(), args: vec![serde_json::to_string(&params)?], scope: None,
                operation_id: Some(original.operation_id.clone()), idempotency_key: Some(original.key.clone()),
                parent_operation_id: None, queue_wait_ms: None, lifecycle: None })
        }, |response, request, profile, pid| validate_response(response, request, profile, pid, original),
        |_| anyhow::anyhow!("private migration exchange failed; query the original operation"))?;
    serde_json::from_value(envelope.summary).map_err(|_| anyhow::anyhow!("invalid private migration result"))
}

fn validate_response(response: RpcResponse<ResultEnvelope>, request: &RpcRequest, profile: &Path,
    pid: u32, original: &HostMigrationOperation) -> Result<ResultEnvelope> {
    anyhow::ensure!(response.v == request.v && response.id == request.id && response.pid == Some(pid)
        && response.bin == "rsrs-runtime" && response.scope.is_none() && response.web_url.is_none()
        && response.operation_id.as_deref() == Some(original.operation_id.as_str())
        && response.idempotency_key.as_deref() == Some(original.key.as_str()), "migration response binding mismatch");
    if let Some(directory) = &response.data_dir {
        anyhow::ensure!(Path::new(directory).canonicalize()? == profile, "migration response profile mismatch");
    }
    let envelope = response.envelope.context("private migration envelope missing")?;
    anyhow::ensure!(envelope.command == "migration-control" && envelope.details.is_null()
        && envelope.items.len() == 2 && envelope.errors.is_empty() && envelope.actions.is_empty()
        && envelope.related.is_empty(), "invalid private migration envelope");
    for (name, value) in [("control_ready", "true"), ("store_ready", "false")] {
        let mut items = envelope.items.iter().filter(|item| item.name == name);
        anyhow::ensure!(items.next().is_some_and(|item| item.value == value && if name == "control_ready" {
            matches!(item.status, Status::Ok) } else { matches!(item.status, Status::Skip) }) && items.next().is_none(),
            "migration readiness mismatch");
    }
    let receipt: HostMigrationResult = serde_json::from_value(envelope.summary.clone())
        .map_err(|_| anyhow::anyhow!("invalid private migration result"))?;
    anyhow::ensure!(receipt.operation_id == original.operation_id && receipt.fingerprint == original.fingerprint
        && receipt.identity == original.identity && super::control::identity(profile)? == original.identity,
        "migration result changed its original operation or identity");
    if receipt.outcome == HostMigrationOutcome::Unknown {
        anyhow::ensure!(!response.ok && response.exit == 2 && response.code.as_deref() == Some("migration_outcome_unknown")
            && response.error.is_none() && matches!(envelope.status, Status::Fail) && receipt.details.is_null(),
            "invalid unknown migration result");
    } else {
        anyhow::ensure!(response.ok && response.exit == 0 && response.code.is_none() && response.error.is_none()
            && matches!(envelope.status, Status::Ok) && receipt.details.is_object(), "invalid terminal migration result");
        validate_terminal_receipt(&receipt, original, &request.method)?;
    }
    Ok(envelope)
}

fn validate_terminal_receipt(receipt: &HostMigrationResult, original: &HostMigrationOperation,
    method: &str) -> Result<()> {
    anyhow::ensure!(receipt.operation_id == original.operation_id && receipt.fingerprint == original.fingerprint
        && receipt.identity == original.identity && receipt.details.is_object(),
        "terminal migration receipt changed its original operation or identity");
    match receipt.outcome {
        HostMigrationOutcome::Completed => {
            let directory = receipt.details["dir"].as_str().context("migration completion directory missing")?;
            anyhow::ensure!(receipt.details["state"] == "migrated"
                && receipt.details["account"].as_str() == Some(original.account.as_str())
                && Path::new(directory).canonicalize()?
                    == original.installation_root.join("accounts").join(&original.account).canonicalize()?
                && receipt.details["original_preserved"] == true, "migration completion differs from its intent");
        }
        HostMigrationOutcome::AlreadyMigrated => anyhow::ensure!(method == HOST_MIGRATION_PROFILE_METHOD
            && receipt.details["state"] == "already_migrated", "query cannot adopt an unbound legacy receipt"),
        HostMigrationOutcome::Unknown => anyhow::bail!("unknown migration result is not a terminal receipt"),
    }
    Ok(())
}
