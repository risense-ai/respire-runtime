//! One-shot offline control, dispatched before serving or opening a business store.
use std::io::{Read, Write};
use std::time::{Duration, Instant};
use std::sync::{Arc, Mutex, mpsc};

use anyhow::{Context, Result};
use respire_commands::output::{Item, ResultEnvelope, Status};
use respire_protocol::{
    HostControlLaunchGrant, HostControlOperation, HostControlParams, RpcRequest, RpcResponse,
    HOST_CONTROL_MAX_FRAME_BYTES, HOST_CONTROL_SCHEMA_V,
    HostAuthKeygenParams, HostAuthOutcome, HOST_AUTH_SCHEMA_V,
    HOST_AUTH_KEYGEN_METHOD, HOST_AUTH_RESULT_METHOD,
    HostModelParams, HOST_MODEL_SCHEMA_V,
};

const PROTOCOL_V: u32 = respire_commands::rpc_worker::PROTOCOL_V;
const CONTROL_DEADLINE: Duration = Duration::from_secs(10);

enum ControlEvent {
    Finished(RpcResponse<ResultEnvelope>),
    ParentRevoked,
    LongControlStarted,
}

pub(crate) fn run() -> Result<i32> {
    let progress = Arc::new(Mutex::new(response("")));
    let worker_progress = Arc::clone(&progress);
    let (sent, received) = mpsc::sync_channel(1);
    std::thread::Builder::new().name("control-operation".into()).spawn(move || {
        let response = execute(&worker_progress, &sent);
        let _ = sent.send(ControlEvent::Finished(response));
    })?;
    let mut deadline = Instant::now() + CONTROL_DEADLINE;
    let response = loop {
        match received.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(ControlEvent::LongControlStarted) => {
            deadline = Instant::now() + Duration::from_secs(180);
            continue;
        }
        Ok(ControlEvent::Finished(response)) => break response,
        Ok(ControlEvent::ParentRevoked) | Err(_) => {
            let mut response = progress.lock().map_err(|_| anyhow::anyhow!("control progress unavailable"))?.clone();
            response.code = Some("control_outcome_unknown".into());
            response.error = Some("control deadline or parent revocation; query the same operation ID before retrying".into());
            response.envelope = Some(ResultEnvelope::new(
                response.envelope.as_ref().map(|envelope| envelope.command.as_str())
                    .unwrap_or(if response.operation_id.is_some() { "keygen" } else { "memory-revision" }),
                Status::Fail, serde_json::json!({"outcome":"unknown"}), vec![
                    Item::new("control_ready", Status::Skip, "unknown"),
                    Item::new("store_ready", Status::Skip, "false"),
                ],
            ));
            break response;
        }
        }
    };
    // All writes are journaled before effects. Main exits after the response;
    // a deadline never claims rollback or authorizes a replacement operation.
    std::thread::Builder::new().name("control-output-deadline".into()).spawn(|| {
        std::thread::sleep(Duration::from_secs(2));
        std::process::exit(2);
    })?;
    let bytes = serde_json::to_vec(&response)?;
    anyhow::ensure!(bytes.len() <= HOST_CONTROL_MAX_FRAME_BYTES, "host control response too large");
    let mut output = std::io::stdout().lock();
    output.write_all(&(bytes.len() as u32).to_be_bytes())?;
    output.write_all(&bytes)?;
    output.flush()?;
    Ok(response.exit)
}

fn execute(progress: &Mutex<RpcResponse<ResultEnvelope>>, events: &mpsc::SyncSender<ControlEvent>) -> RpcResponse<ResultEnvelope> {
    let mut response = response("");
    let mut control_ready = false;
    let result = receive_and_execute(&mut response, &mut control_ready, progress, events);
    if let Err((code, message)) = result {
        response.code = Some(code.to_owned());
        let diagnostic = response.error.take().unwrap_or_else(|| message.to_owned());
        response.error = Some(diagnostic.clone());
        let mut envelope = ResultEnvelope::new(
            response.envelope.as_ref().map(|envelope| envelope.command.as_str())
                .unwrap_or(if response.operation_id.is_some() { "keygen" } else { "memory-revision" }),
            Status::Fail, serde_json::json!({}), Vec::new(),
        );
        envelope.errors.push(diagnostic);
        response.envelope = Some(envelope);
    }
    if let Some(envelope) = &mut response.envelope {
        envelope.items.push(Item::new("control_ready", if control_ready { Status::Ok } else { Status::Fail }, control_ready.to_string()));
        envelope.items.push(Item::new("store_ready", Status::Skip, "false"));
    }
    response
}

type ControlFailure = (&'static str, &'static str);

fn receive_and_execute(
    response: &mut RpcResponse<ResultEnvelope>,
    control_ready: &mut bool,
    progress: &Mutex<RpcResponse<ResultEnvelope>>,
    events: &mpsc::SyncSender<ControlEvent>,
) -> std::result::Result<(), ControlFailure> {
    let grant: HostControlLaunchGrant = read_frame()
        .map_err(|_| ("invalid_request", "invalid host control grant frame"))?;
    if grant.protocol_version != PROTOCOL_V {
        return Err(("protocol_version_mismatch", "protocol_version_mismatch"));
    }
    let request: RpcRequest = read_frame()
        .map_err(|_| ("invalid_request", "invalid host control RPC frame"))?;
    response.id = request.id.clone();
    use respire_protocol::host_control::{HostLoginRecoveryResult, HostLoginRecoveryState,
        HOST_LOGIN_RECOVERY_METHOD, HOST_LOGIN_RECOVERY_STATUS_METHOD};
    if [HOST_LOGIN_RECOVERY_METHOD, HOST_LOGIN_RECOVERY_STATUS_METHOD].contains(&request.method.as_str()) {
        let params = crate::auth_control::recovery_request(&request)
            .map_err(|_| ("invalid_request", "invalid fixed login recovery request"))?;
        response.envelope = Some(ResultEnvelope::new("login-recovery", Status::Fail,
            serde_json::json!({}), Vec::new()));
        *progress.lock().map_err(|_| ("control_unavailable", "control progress unavailable"))? = response.clone();
        watch_auth_parent(events.clone())
            .map_err(|_| ("unauthorized", "login recovery parent watch failed"))?;
        let recovered = if request.method == HOST_LOGIN_RECOVERY_STATUS_METHOD {
            crate::startup_identity::verify_login_recovery_status(&grant, &params)
                .map_err(|_| ("unauthorized", "login recovery status authorization failed"))?;
            false
        } else {
            crate::startup_identity::authorize_auth_control(grant.clone())
                .map_err(|_| ("unauthorized", "login recovery maintenance authorization failed"))?;
            let ownership = crate::startup_identity::acquire_auth_ownership(&params.binding, &params.identity)
                .map_err(|_| ("auth_ownership_unavailable", "login recovery ownership unavailable"))?;
            crate::startup_identity::verify_auth_control_binding(&params.binding, &params.identity)
                .map_err(|_| ("scope_mismatch", "login recovery binding changed"))?;
            ownership.recover_legacy(&params.identity)
                .map_err(|_| ("auth_recovery_required", "login recovery incomplete; retain maintenance and query the original operation"))?
        };
        let state = respire_app::login_transaction::recovery_state()
            .map_err(|_| ("auth_recovery_required", "invalid login recovery journal; retain it for recovery"))?;
        if request.method == HOST_LOGIN_RECOVERY_STATUS_METHOD {
            crate::startup_identity::verify_login_recovery_status(&grant, &params)
                .map_err(|_| ("scope_mismatch", "login recovery status binding changed"))?;
        } else if state != HostLoginRecoveryState::Clear {
            return Err(("auth_recovery_required", "login recovery did not clear the journal"));
        }
        *control_ready = true;
        response.envelope = Some(ResultEnvelope::new("login-recovery", Status::Ok,
            serde_json::to_value(HostLoginRecoveryResult { state, recovered })
                .map_err(|_| ("auth_recovery_required", "login recovery result encoding failed"))?,
            Vec::new()));
        response.ok = true;
        response.exit = 0;
        return Ok(());
    }
    use respire_protocol::metadata_control::{HostMetadataOutcome, HOST_METADATA_ENABLE_METHOD,
        HOST_METADATA_DISABLE_METHOD, HOST_METADATA_RESULT_METHOD, HOST_METADATA_STATUS_METHOD,
        HOST_AGENT_CONFIG_READ_METHOD, HOST_SNAPSHOT_PREFLIGHT_METHOD};
    if [HOST_METADATA_STATUS_METHOD, HOST_AGENT_CONFIG_READ_METHOD, HOST_SNAPSHOT_PREFLIGHT_METHOD]
        .contains(&request.method.as_str()) {
        let read = crate::metadata_control::OfflineReadRequest::parse(&request)
            .map_err(|_| ("invalid_request", "invalid fixed offline configuration read"))?;
        response.envelope = Some(ResultEnvelope::new(read.kind.command(), Status::Fail,
            serde_json::json!({}), Vec::new()));
        *progress.lock().map_err(|_| ("control_unavailable", "control progress unavailable"))? = response.clone();
        crate::startup_identity::authorize_offline_read(grant, read.kind)
            .map_err(|_| ("unauthorized", "offline read launch authorization failed"))?;
        watch_auth_parent(events.clone())
            .map_err(|_| ("unauthorized", "offline read parent watch failed"))?;
        crate::startup_identity::verify_offline_read_binding(read.binding(), read.kind)
            .map_err(|_| ("scope_mismatch", "offline read binding mismatch"))?;
        events.send(ControlEvent::LongControlStarted)
            .map_err(|_| ("control_unavailable", "offline read deadline unavailable"))?;
        let envelope = read.execute().map_err(|_| {
            if read.kind == respire_protocol::metadata_control::HostOfflineRead::SnapshotPreflight {
                ("snapshot_preflight_blocked", "snapshot validation failed; inspect snapshot recovery before continuing")
            } else { ("offline_read_unavailable", "offline configuration read failed") }
        })?;
        crate::startup_identity::verify_offline_read_binding(read.binding(), read.kind)
            .map_err(|_| ("scope_mismatch", "offline read binding changed"))?;
        *control_ready = true;
        response.ok = true;
        response.exit = 0;
        response.envelope = Some(envelope);
        return Ok(());
    }
    if [HOST_METADATA_ENABLE_METHOD, HOST_METADATA_DISABLE_METHOD, HOST_METADATA_RESULT_METHOD]
        .contains(&request.method.as_str()) {
        let metadata = crate::metadata_control::MetadataChange::parse(&request)
            .map_err(|_| ("invalid_request", "invalid private metadata request"))?;
        response.operation_id = request.operation_id.clone();
        response.idempotency_key = request.idempotency_key.clone();
        response.envelope = Some(ResultEnvelope::new("metadata-control", Status::Fail,
            serde_json::json!({"outcome":"unknown"}), Vec::new()));
        *progress.lock().map_err(|_| ("control_unavailable", "control progress unavailable"))? = response.clone();
        crate::startup_identity::authorize_metadata_control(grant)
            .map_err(|_| ("unauthorized", "private metadata maintenance authorization failed"))?;
        watch_auth_parent(events.clone())
            .map_err(|_| ("unauthorized", "private metadata parent watch failed"))?;
        crate::startup_identity::verify_metadata_control_binding(metadata.binding(), metadata.identity())
            .map_err(|_| ("scope_mismatch", "private metadata binding mismatch"))?;
        events.send(ControlEvent::LongControlStarted)
            .map_err(|_| ("control_unavailable", "private metadata deadline unavailable"))?;
        let result = metadata.execute()
            .map_err(|_| ("metadata_outcome_unknown", "query the original metadata operation before retrying"))?;
        crate::startup_identity::verify_metadata_control_binding(metadata.binding(), metadata.identity())
            .map_err(|_| ("metadata_outcome_unknown", "metadata completion binding changed"))?;
        *control_ready = true;
        response.ok = result.outcome == HostMetadataOutcome::Committed;
        response.exit = if response.ok { 0 } else { 2 };
        if !response.ok { response.code = Some("metadata_outcome_unknown".into()); }
        response.envelope = Some(ResultEnvelope::new("metadata-control",
            if response.ok { Status::Ok } else { Status::Fail },
            serde_json::to_value(result).map_err(|_| ("metadata_outcome_unknown", "metadata receipt encoding failed"))?,
            Vec::new()));
        return Ok(());
    }
    use respire_protocol::migration_control::{HostMigrationOutcome,
        HOST_MIGRATION_PROFILE_METHOD, HOST_MIGRATION_RESULT_METHOD};
    if [HOST_MIGRATION_PROFILE_METHOD, HOST_MIGRATION_RESULT_METHOD].contains(&request.method.as_str()) {
        let migration = crate::migration_control::MigrationRequest::parse(&request)
            .map_err(|_| ("invalid_request", "invalid private migration request"))?;
        response.operation_id = request.operation_id.clone();
        response.idempotency_key = request.idempotency_key.clone();
        response.envelope = Some(ResultEnvelope::new("migration-control", Status::Fail,
            serde_json::json!({"outcome":"unknown"}), Vec::new()));
        *progress.lock().map_err(|_| ("control_unavailable", "control progress unavailable"))? = response.clone();
        if respire_app::login_transaction::auth_recovery_pending()
            .map_err(|_| ("auth_recovery_pending", "authentication recovery state is invalid"))? {
            return Err(("auth_recovery_pending", "finish authentication recovery before migrating a legacy profile"));
        }
        crate::startup_identity::authorize_auth_control(grant)
            .map_err(|_| ("unauthorized", "private migration launch authorization failed"))?;
        watch_auth_parent(events.clone())
            .map_err(|_| ("unauthorized", "private migration parent watch failed"))?;
        let ownership = crate::startup_identity::acquire_auth_ownership(migration.binding(), migration.identity())
            .map_err(|_| ("auth_ownership_unavailable", "private migration ownership unavailable"))?;
        crate::startup_identity::verify_auth_control_binding(migration.binding(), migration.identity())
            .map_err(|_| ("scope_mismatch", "private migration identity mismatch"))?;
        events.send(ControlEvent::LongControlStarted)
            .map_err(|_| ("control_unavailable", "private migration deadline unavailable"))?;
        let result = migration.execute(&ownership)
            .map_err(|_| ("migration_outcome_unknown", "query the original migration operation before retrying"))?;
        crate::startup_identity::verify_auth_control_binding(migration.binding(), &result.identity)
            .map_err(|_| ("migration_outcome_unknown", "migration completion identity could not be verified"))?;
        *control_ready = true;
        response.ok = result.outcome != HostMigrationOutcome::Unknown;
        response.exit = if response.ok { 0 } else { 2 };
        if !response.ok { response.code = Some("migration_outcome_unknown".into()); }
        response.envelope = Some(ResultEnvelope::new("migration-control",
            if response.ok { Status::Ok } else { Status::Fail },
            serde_json::to_value(result).map_err(|_| ("migration_outcome_unknown", "migration receipt encoding failed"))?,
            Vec::new()));
        return Ok(());
    }
    use respire_protocol::key_control::{HostKeyOutcome, HOST_KEY_SUPER_RESET_METHOD,
        HOST_KEY_RESULT_METHOD, HOST_KEY_ROLLBACK_METHOD, HOST_KEY_FIVEKEYS_METHOD, HOST_KEY_COMPLETE_METHOD};
    if [HOST_KEY_SUPER_RESET_METHOD, HOST_KEY_RESULT_METHOD, HOST_KEY_ROLLBACK_METHOD,
        HOST_KEY_FIVEKEYS_METHOD, HOST_KEY_COMPLETE_METHOD]
        .contains(&request.method.as_str()) {
        let key = crate::key_control::KeyRequest::parse(&request)
            .map_err(|_| ("invalid_request", "invalid private key request"))?;
        response.operation_id = request.operation_id.clone();
        response.idempotency_key = request.idempotency_key.clone();
        response.envelope = Some(ResultEnvelope::new("key-control", Status::Fail,
            serde_json::json!({"outcome":"unknown"}), Vec::new()));
        *progress.lock().map_err(|_| ("control_unavailable", "control progress unavailable"))? = response.clone();
        if key.is_complete() { crate::startup_identity::authorize_account_completion(grant) }
        else { crate::startup_identity::authorize_auth_control(grant) }
            .map_err(|_| ("unauthorized", "private key launch authorization failed"))?;
        watch_auth_parent(events.clone())
            .map_err(|_| ("unauthorized", "private key parent watch failed"))?;
        let ownership = if key.is_complete() { None } else {
            Some(crate::startup_identity::acquire_auth_ownership(key.binding(), key.identity())
                .map_err(|_| ("auth_ownership_unavailable", "private key ownership unavailable"))?)
        };
        crate::startup_identity::verify_auth_control_binding(key.binding(), key.identity())
            .map_err(|_| ("scope_mismatch", "private key identity mismatch"))?;
        events.send(ControlEvent::LongControlStarted)
            .map_err(|_| ("control_unavailable", "private key deadline unavailable"))?;
        let result = if key.is_complete() {
            key.complete(&request, crate::key_control::verify_target_runtime)
        } else {
            key.execute(&request, ownership.ok_or(("auth_ownership_unavailable", "private key ownership missing"))?)
        }
            .map_err(|_| ("key_outcome_unknown", "query the original key operation before retrying"))?;
        key.verify_result(&request, &result)
            .map_err(|_| ("key_outcome_unknown", "key operation completion identity could not be verified"))?;
        *control_ready = true;
        response.ok = result.outcome != HostKeyOutcome::Unknown;
        response.exit = if response.ok { 0 } else { 2 };
        if !response.ok { response.code = Some("key_outcome_unknown".into()); }
        let status = match result.outcome {
            HostKeyOutcome::Committed | HostKeyOutcome::RolledBack => Status::Ok,
            HostKeyOutcome::Pending | HostKeyOutcome::AwaitingInput => Status::Pending,
            HostKeyOutcome::Unknown => Status::Fail,
        };
        // This receipt can contain the new super password: never copy it to progress.
        response.envelope = Some(ResultEnvelope::new("key-control", status,
            serde_json::to_value(result)
                .map_err(|_| ("key_outcome_unknown", "private key receipt encoding failed"))?, Vec::new()));
        return Ok(());
    }
    if request.method == respire_protocol::model_maintenance::MODEL_MAINTENANCE_METHOD {
        events.send(ControlEvent::LongControlStarted)
            .map_err(|_| ("control_unavailable", "model maintenance deadline unavailable"))?;
        let result = crate::model_maintenance::execute(grant, &request)
            .map_err(|_| ("model_maintenance_failed", "private model maintenance failed"))?;
        response.envelope = Some(result);
        response.ok = true;
        response.exit = 0;
        *control_ready = true;
        return Ok(());
    }
    use respire_protocol::space_control::{HostSpaceOutcome, HOST_SPACE_INVITE_METHOD,
        HOST_SPACE_JOIN_METHOD, HOST_SPACE_KICK_METHOD, HOST_SPACE_RESULT_METHOD};
    if [HOST_SPACE_INVITE_METHOD, HOST_SPACE_JOIN_METHOD, HOST_SPACE_KICK_METHOD, HOST_SPACE_RESULT_METHOD]
        .contains(&request.method.as_str()) {
        let space = crate::space_control::SpaceRequest::parse(&request)
            .map_err(|_| ("invalid_request", "invalid private space request"))?;
        response.operation_id = request.operation_id.clone();
        response.idempotency_key = request.idempotency_key.clone();
        response.envelope = Some(ResultEnvelope::new("space-control", Status::Fail,
            serde_json::json!({"outcome":"unknown"}), Vec::new()));
        *progress.lock().map_err(|_| ("control_unavailable", "control progress unavailable"))? = response.clone();
        crate::startup_identity::authorize_auth_control(grant)
            .map_err(|_| ("unauthorized", "private space launch authorization failed"))?;
        watch_auth_parent(events.clone())
            .map_err(|_| ("unauthorized", "private space parent watch failed"))?;
        let ownership = crate::startup_identity::acquire_auth_ownership(space.binding(),space.identity())
            .map_err(|_| ("auth_ownership_unavailable", "private space ownership unavailable"))?;
        crate::startup_identity::verify_auth_control_binding(space.binding(),space.identity())
            .map_err(|_| ("scope_mismatch", "private space identity mismatch"))?;
        events.send(ControlEvent::LongControlStarted)
            .map_err(|_| ("control_unavailable", "private space deadline unavailable"))?;
        let result = space.execute(&request,&ownership)
            .map_err(|_| ("space_outcome_unknown", "query the original space operation before retrying"))?;
        crate::startup_identity::verify_auth_control_binding(space.binding(),space.identity())
            .map_err(|_| ("space_outcome_unknown", "space source identity changed"))?;
        *control_ready = true;
        response.ok = matches!(result.outcome,HostSpaceOutcome::Committed | HostSpaceOutcome::Pending);
        response.exit = if response.ok { 0 } else { 2 };
        if !response.ok { response.code = Some(if result.outcome == HostSpaceOutcome::Rejected {
            "space_rejected" } else { "space_outcome_unknown" }.into()); }
        let status = match result.outcome { HostSpaceOutcome::Committed => Status::Ok,
            HostSpaceOutcome::Pending => Status::Pending, HostSpaceOutcome::Unknown | HostSpaceOutcome::Rejected => Status::Fail };
        // Never publish the secret-bearing result through shared progress or logs.
        response.envelope = Some(ResultEnvelope::new("space-control",status,
            serde_json::to_value(result).map_err(|_| ("space_outcome_unknown", "space receipt encoding failed"))?,Vec::new()));
        return Ok(());
    }
    use respire_protocol::profile_maintenance::{HostProfileRemoveOutcome,
        HOST_PROFILE_REMOVE_METHOD, HOST_PROFILE_RESULT_METHOD};
    if [HOST_PROFILE_REMOVE_METHOD, HOST_PROFILE_RESULT_METHOD].contains(&request.method.as_str()) {
        let profile = crate::profile_maintenance::ProfileRemoveRequest::parse(&request)
            .map_err(|_| ("invalid_request", "invalid private profile removal request"))?;
        response.operation_id = request.operation_id.clone();
        response.idempotency_key = request.idempotency_key.clone();
        response.envelope = Some(ResultEnvelope::new("profile-control", Status::Fail,
            serde_json::json!({"outcome":"unknown"}), Vec::new()));
        *progress.lock().map_err(|_| ("control_unavailable", "control progress unavailable"))? = response.clone();
        crate::startup_identity::authorize_auth_control(grant)
            .map_err(|_| ("unauthorized", "private profile launch authorization failed"))?;
        watch_auth_parent(events.clone())
            .map_err(|_| ("unauthorized", "private profile parent watch failed"))?;
        let ownership = crate::startup_identity::acquire_auth_ownership(profile.binding(), profile.identity())
            .map_err(|_| ("auth_ownership_unavailable", "private profile ownership unavailable"))?;
        crate::startup_identity::verify_auth_control_binding(profile.binding(), profile.identity())
            .map_err(|_| ("scope_mismatch", "private profile identity mismatch"))?;
        events.send(ControlEvent::LongControlStarted)
            .map_err(|_| ("control_unavailable", "private profile deadline unavailable"))?;
        let result = profile.execute(&ownership)
            .map_err(|_| ("profile_remove_outcome_unknown", "query the original profile operation before retrying"))?;
        crate::startup_identity::verify_auth_control_binding(profile.binding(), profile.identity())
            .map_err(|_| ("profile_remove_outcome_unknown", "profile source identity changed"))?;
        *control_ready = true;
        response.ok = result.outcome == HostProfileRemoveOutcome::Committed;
        response.exit = if response.ok { 0 } else { 2 };
        if !response.ok { response.code = Some("profile_remove_outcome_unknown".into()); }
        response.envelope = Some(ResultEnvelope::new("profile-control",
            if response.ok { Status::Ok } else { Status::Fail },
            serde_json::to_value(result)
                .map_err(|_| ("profile_remove_outcome_unknown", "profile receipt encoding failed"))?, Vec::new()));
        return Ok(());
    }
    use respire_protocol::identity_write_control::{HostIdentityWriteOutcome,
        HOST_IDENTITY_LOGOUT_METHOD, HOST_IDENTITY_SESSION_REVOKE_METHOD,
        HOST_IDENTITY_WRITE_RESULT_METHOD};
    if [HOST_IDENTITY_LOGOUT_METHOD, HOST_IDENTITY_SESSION_REVOKE_METHOD,
        HOST_IDENTITY_WRITE_RESULT_METHOD].contains(&request.method.as_str()) {
        let identity = crate::identity_write_control::IdentityWriteRequest::parse(&request)
            .map_err(|_| ("invalid_request", "invalid private identity write request"))?;
        response.operation_id = request.operation_id.clone();
        response.idempotency_key = request.idempotency_key.clone();
        response.envelope = Some(ResultEnvelope::new("identity-write", Status::Fail,
            serde_json::json!({"outcome":"unknown"}), Vec::new()));
        *progress.lock().map_err(|_| ("control_unavailable", "control progress unavailable"))? = response.clone();
        crate::startup_identity::authorize_auth_control(grant)
            .map_err(|_| ("unauthorized", "private identity write launch authorization failed"))?;
        watch_auth_parent(events.clone())
            .map_err(|_| ("unauthorized", "private identity write parent watch failed"))?;
        let ownership = crate::startup_identity::acquire_auth_ownership(identity.binding(), identity.identity())
            .map_err(|_| ("auth_ownership_unavailable", "private identity write ownership unavailable"))?;
        crate::startup_identity::verify_auth_control_binding(identity.binding(), identity.identity())
            .map_err(|_| ("scope_mismatch", "private identity write identity mismatch"))?;
        events.send(ControlEvent::LongControlStarted)
            .map_err(|_| ("control_unavailable", "private identity write deadline unavailable"))?;
        let result = identity.execute(&request, &ownership)
            .map_err(|_| ("identity_write_outcome_unknown", "query the original identity operation before retrying"))?;
        crate::startup_identity::verify_identity_write_result(identity.binding(), identity.identity(), &result)
            .map_err(|_| ("identity_write_outcome_unknown", "identity write completion could not be verified"))?;
        *control_ready = true;
        response.ok = result.outcome != HostIdentityWriteOutcome::Unknown;
        response.exit = if response.ok { 0 } else { 2 };
        if !response.ok { response.code = Some("identity_write_outcome_unknown".into()); }
        let status = match result.outcome {
            HostIdentityWriteOutcome::Committed => Status::Ok,
            HostIdentityWriteOutcome::Pending => Status::Pending,
            HostIdentityWriteOutcome::Unknown => Status::Fail,
        };
        response.envelope = Some(ResultEnvelope::new("identity-write", status,
            serde_json::to_value(result)
                .map_err(|_| ("identity_write_outcome_unknown", "identity write receipt encoding failed"))?, Vec::new()));
        return Ok(());
    }
    if [respire_protocol::config_control::AGENT_CONFIG_SET_METHOD,
        respire_protocol::config_control::AGENT_CONFIG_RESULT_METHOD].contains(&request.method.as_str()) {
        response.operation_id = request.operation_id.clone();
        response.idempotency_key = request.idempotency_key.clone();
        response.envelope = Some(ResultEnvelope::new("agent-config-control", Status::Fail,
            serde_json::json!({"outcome":"unknown"}), Vec::new()));
        *progress.lock().map_err(|_| ("control_unavailable", "control progress unavailable"))? = response.clone();
        watch_auth_parent(events.clone())
            .map_err(|_| ("unauthorized", "agent config parent watch failed"))?;
        events.send(ControlEvent::LongControlStarted)
            .map_err(|_| ("control_unavailable", "agent config deadline unavailable"))?;
        let envelope = crate::config_control::execute_agent_config(grant, &request)
            .map_err(|_| ("agent_config_outcome_unknown", "query the original agent config operation; do not replay"))?;
        let receipt: respire_protocol::config_control::AgentConfigReceipt = serde_json::from_value(envelope.summary.clone())
            .map_err(|_| ("agent_config_outcome_unknown", "invalid agent config receipt"))?;
        response.data_dir = Some(receipt.review.profile.to_str()
            .ok_or(("agent_config_outcome_unknown", "agent config profile is not UTF-8"))?.to_owned());
        *control_ready = true;
        response.ok = receipt.outcome != respire_protocol::config_control::AgentConfigOutcome::Unknown;
        response.exit = if response.ok { 0 } else { 2 };
        if !response.ok { response.code = Some("agent_config_outcome_unknown".into()); }
        response.envelope = Some(envelope);
        return Ok(());
    }
    if request.method == respire_protocol::config_control::CONFIG_VALIDATE_METHOD {
        let result = crate::config_control::execute(grant, &request)
            .map_err(|_| ("config_validation_failed", "private configuration validation failed"))?;
        response.envelope = Some(result);
        response.ok = true;
        response.exit = 0;
        *control_ready = true;
        return Ok(());
    }
    if request.method == respire_protocol::identity_control::HOST_IDENTITY_SESSION_LIST_METHOD {
        let identity = crate::identity_control::IdentityRequest::parse(&request)
            .map_err(|_| ("invalid_request", "invalid private identity read request"))?;
        response.envelope = Some(ResultEnvelope::new("session", Status::Fail,
            serde_json::json!({}), Vec::new()));
        crate::startup_identity::authorize_auth_control(grant)
            .map_err(|_| ("unauthorized", "private identity read launch authorization failed"))?;
        watch_auth_parent(events.clone())
            .map_err(|_| ("unauthorized", "private identity read parent watch failed"))?;
        let ownership = crate::startup_identity::acquire_auth_ownership(identity.binding(), identity.identity())
            .map_err(|_| ("auth_ownership_unavailable", "private identity read ownership unavailable"))?;
        crate::startup_identity::verify_auth_control_binding(identity.binding(), identity.identity())
            .map_err(|_| ("scope_mismatch", "private identity read identity mismatch"))?;
        events.send(ControlEvent::LongControlStarted)
            .map_err(|_| ("control_unavailable", "private identity read deadline unavailable"))?;
        let result = identity.execute(&ownership)
            .map_err(|_| ("identity_read_unavailable", "private identity read failed"))?;
        crate::startup_identity::verify_auth_control_binding(identity.binding(), identity.identity())
            .map_err(|_| ("scope_mismatch", "private identity read identity changed"))?;
        let mut envelope = ResultEnvelope::new("session", Status::Ok,
            serde_json::json!({"action":"list"}), Vec::new());
        // Session details use only the inherited response, never progress or a ledger.
        envelope.details = serde_json::to_value(result)
            .map_err(|_| ("identity_read_unavailable", "private identity read encoding failed"))?;
        response.envelope = Some(envelope);
        response.ok = true;
        response.exit = 0;
        *control_ready = true;
        return Ok(());
    }
    if [respire_protocol::secret_control::HOST_SECRET_READ_METHOD,
        respire_protocol::secret_control::HOST_KEYS_EXPORT_READ_METHOD]
        .contains(&request.method.as_str()) {
        let secret = crate::secret_control::SecretRequest::parse(&request)
            .map_err(|_| ("invalid_request", "invalid private secret read request"))?;
        if respire_app::login_transaction::auth_recovery_pending()
            .map_err(|_| ("auth_recovery_pending", "auth recovery status unavailable"))? {
            return Err(("auth_recovery_pending", "finish auth recovery before reading secrets"));
        }
        crate::startup_identity::authorize_auth_control(grant)
            .map_err(|_| ("unauthorized", "private secret read launch authorization failed"))?;
        watch_auth_parent(events.clone())
            .map_err(|_| ("unauthorized", "private secret read parent watch failed"))?;
        let ownership = crate::startup_identity::acquire_auth_ownership(secret.binding(), secret.identity())
            .map_err(|_| ("auth_ownership_unavailable", "private secret read ownership unavailable"))?;
        if respire_app::login_transaction::auth_recovery_pending()
            .map_err(|_| ("auth_recovery_pending", "auth recovery status unavailable"))? {
            return Err(("auth_recovery_pending", "finish auth recovery before reading secrets"));
        }
        crate::startup_identity::verify_auth_control_binding(secret.binding(), secret.identity())
            .map_err(|_| ("scope_mismatch", "private secret read identity mismatch"))?;
        let result = secret.execute(&ownership)
            .map_err(|_| ("secret_read_unavailable", "private secret read failed"))?;
        crate::startup_identity::verify_auth_control_binding(secret.binding(), secret.identity())
            .map_err(|_| ("scope_mismatch", "private secret read identity changed"))?;
        // Secret payloads go only to the inherited response, never progress or receipts.
        response.envelope = Some(result);
        response.ok = true;
        response.exit = 0;
        *control_ready = true;
        return Ok(());
    }
    if request.method == respire_protocol::maintenance_control::MAINTENANCE_CONTROL_METHOD {
        use respire_protocol::maintenance_control::{MaintenanceAction, MaintenanceControlParams, MaintenanceState};
        if request.args.len() != 1 { return Err(("invalid_request", "invalid snapshot maintenance shape")); }
        let params: MaintenanceControlParams = serde_json::from_str(&request.args[0])
            .map_err(|_| ("invalid_request", "invalid snapshot maintenance params"))?;
        response.operation_id = request.operation_id.clone();
        response.idempotency_key = request.idempotency_key.clone();
        response.envelope = Some(ResultEnvelope::new("snapshot", Status::Pending, serde_json::json!({}), Vec::new()));
        *progress.lock().map_err(|_| ("control_unavailable", "control progress unavailable"))? = response.clone();
        let marker = crate::startup_identity::read_private_file(
            &grant.installation_root.join("runtime/autostart/maintenance.json"))
            .map_err(|_| ("unauthorized", "snapshot maintenance marker unavailable"))?
            .ok_or(("unauthorized", "snapshot maintenance marker missing"))?;
        let verified_query = params.action == MaintenanceAction::Query
            && serde_json::from_slice::<serde_json::Value>(&marker)
                .is_ok_and(|value| value["phase"] == "Verified");
        let finalize = matches!(params.action, MaintenanceAction::Commit | MaintenanceAction::Release) || verified_query;
        if finalize {
            crate::snapshot_authority::validate_finalize_launch(&grant, &marker)
        } else {
            crate::snapshot_authority::validate_offline_launch(&grant, &marker)
        }.map_err(|_| ("unauthorized", "snapshot capability or role is invalid"))?;
        crate::startup_identity::authorize_snapshot_control(grant, finalize)
            .map_err(|_| ("unauthorized", "snapshot launch authorization failed"))?;
        watch_auth_parent(events.clone())
            .map_err(|_| ("unauthorized", "snapshot parent watch failed"))?;
        events.send(ControlEvent::LongControlStarted)
            .map_err(|_| ("control_unavailable", "snapshot controller unavailable"))?;
        let session = respire_app::auth::read_session_json()
            .map_err(|_| ("scope_mismatch", "snapshot session is invalid"))?;
        let account = session["user"].as_str().filter(|value| !value.is_empty())
            .ok_or(("scope_mismatch", "snapshot account is missing"))?;
        let result = if finalize {
            crate::snapshot_authority::dispatch_finalize(&request, account)
        } else {
            crate::snapshot_authority::authorize_offline(&params, crate::maintenance_control::Access::Offline)
                .map_err(|_| ("unauthorized", "snapshot offline authorization failed"))?;
            let keys = if params.action == MaintenanceAction::Restore {
                Some(respire_app::auth::load_local_session_with_owner()
                    .map_err(|_| ("credentials_unavailable", "snapshot credentials unavailable"))?.0)
            } else { None };
            crate::snapshot_authority::dispatch_offline(&request, account, keys.as_ref(),
                if params.action == MaintenanceAction::Restore { crate::maintenance_control::RestoreDispatch::FirstAttempt }
                    else { crate::maintenance_control::RestoreDispatch::Resume })
        }.map_err(|failure| {
            response.error = Some(format!("{failure:#}"));
            ("snapshot_outcome_unknown", "query the original snapshot operation before retrying")
        })?;
        *control_ready = true;
        response.ok = result.state != MaintenanceState::Unknown;
        response.exit = if response.ok { 0 } else { 2 };
        if !response.ok { response.code = Some("snapshot_outcome_unknown".into()); }
        response.envelope = Some(ResultEnvelope::new("snapshot",
            if !response.ok { Status::Fail } else if result.cleanup_pending { Status::Warn } else { Status::Ok },
            serde_json::to_value(result).map_err(|_| ("snapshot_outcome_unknown", "snapshot receipt encoding failed"))?, Vec::new()));
        return Ok(());
    }
    use respire_protocol::host_control::{HostAuthAccountOutcome, HOST_AUTH_REGISTER_METHOD,
        HOST_AUTH_LOGIN_METHOD, HOST_AUTH_ACCOUNT_RESULT_METHOD, HOST_AUTH_ACCOUNT_COMPLETE_METHOD,
        HOST_AUTH_ACCOUNT_ROLLBACK_METHOD};
    if [HOST_AUTH_REGISTER_METHOD, HOST_AUTH_LOGIN_METHOD, HOST_AUTH_ACCOUNT_RESULT_METHOD,
        HOST_AUTH_ACCOUNT_COMPLETE_METHOD, HOST_AUTH_ACCOUNT_ROLLBACK_METHOD]
        .contains(&request.method.as_str()) {
        let account = crate::auth_control::AccountRequest::parse(&request)
            .map_err(|_| ("invalid_request", "invalid account control request"))?;
        response.operation_id = request.operation_id.clone();
        response.idempotency_key = request.idempotency_key.clone();
        response.envelope = Some(ResultEnvelope::new("auth-account", Status::Fail,
            serde_json::json!({"outcome":"unknown"}), Vec::new()));
        *progress.lock().map_err(|_| ("control_unavailable", "control progress unavailable"))? = response.clone();
        if account.is_completion() {
            crate::startup_identity::authorize_account_completion(grant)
        } else {
            crate::startup_identity::authorize_auth_control(grant)
        }.map_err(|_| ("unauthorized", "account control launch authorization failed"))?;
        watch_auth_parent(events.clone())
            .map_err(|_| ("unauthorized", "account control parent watch failed"))?;
        let ownership = if account.is_completion() { None } else {
            Some(crate::startup_identity::acquire_auth_ownership(account.binding(), account.identity())
                .map_err(|_| ("auth_ownership_unavailable", "account control library ownership unavailable"))?)
        };
        crate::startup_identity::verify_auth_control_binding(account.binding(), account.identity())
            .map_err(|_| ("scope_mismatch", "account control identity does not match the consumed grant"))?;
        *control_ready = true;
        let result = account.execute(&request, ownership).map_err(|failure| {
            response.error = Some(format!("{failure:#}"));
            ("account_outcome_unknown", "query the same account operation before retrying")
        })?;
        response.ok = matches!(result.outcome,
            HostAuthAccountOutcome::AwaitingInput | HostAuthAccountOutcome::AwaitingVerification
                | HostAuthAccountOutcome::Committed);
        response.exit = if response.ok { 0 } else { 2 };
        response.code = match result.outcome {
            HostAuthAccountOutcome::Unknown => Some("account_outcome_unknown".into()),
            HostAuthAccountOutcome::RolledBack => Some("account_rolled_back".into()),
            _ => None,
        };
        response.envelope = Some(ResultEnvelope::new("auth-account",
            if result.outcome == HostAuthAccountOutcome::AwaitingInput { Status::Pending }
            else if response.ok { Status::Ok } else { Status::Fail },
            serde_json::to_value(result).map_err(|_| ("account_outcome_unknown", "account receipt encoding failed"))?,
            Vec::new()));
        return Ok(());
    }
    let auth = request.method == HOST_AUTH_KEYGEN_METHOD || request.method == HOST_AUTH_RESULT_METHOD;
    if auth {
        let params = validate_auth_request(&request)?;
        response.operation_id = request.operation_id.clone();
        response.idempotency_key = request.idempotency_key.clone();
        *progress.lock().map_err(|_| ("control_unavailable", "control progress unavailable"))? = response.clone();
        crate::startup_identity::authorize_auth_control(grant)
            .map_err(|_| ("unauthorized", "auth control launch authorization failed"))?;
        let ownership = crate::startup_identity::acquire_auth_ownership(&params.binding, &params.identity)
            .map_err(|_| ("auth_ownership_unavailable", "auth control could not acquire the authorized library"))?;
        watch_auth_parent(events.clone())
            .map_err(|_| ("unauthorized", "auth control parent watch failed"))?;
        ownership.recover(&params.identity).map_err(|_| ("auth_recovery_required", "auth transaction recovery requires attention"))?;
        crate::startup_identity::verify_auth_control_binding(&params.binding, &params.identity)
            .map_err(|_| ("scope_mismatch", "auth control identity does not match the consumed grant"))?;
        *control_ready = true;
        let result = respire_app::login_transaction::control_keygen(&ownership, &params.identity,
            request.operation_id.as_deref().ok_or(("invalid_request", "auth operation ID is missing"))?,
            request.idempotency_key.as_deref().ok_or(("invalid_request", "auth idempotency key is missing"))?,
            params.force, request.method == HOST_AUTH_RESULT_METHOD)
            .map_err(|failure| {
                // Diagnostics stay in this private response, never stderr or argv.
                response.error = Some(format!("{failure:#}"));
                ("auth_outcome_unknown", "query the same auth operation ID before retrying")
            })?;
        response.ok = result.outcome == HostAuthOutcome::Committed;
        response.exit = if response.ok { 0 } else { 2 };
        if !response.ok { response.code = Some("auth_not_committed".into()); }
        response.envelope = Some(ResultEnvelope::new("keygen", if response.ok { Status::Ok } else { Status::Fail },
            serde_json::to_value(result).map_err(|_| ("auth_outcome_unknown", "auth result encoding failed"))?, Vec::new()));
        return Ok(());
    }
    let (params, model_params) = validate_request(&request)?;
    let model_plan = request.method == HostControlOperation::ModelInstallPlan.method();
    let model_verify = request.method == HostControlOperation::ModelInstallVerify.method();
    if model_plan || model_verify {
        crate::startup_identity::authorize_model_control(grant)
    } else {
        crate::startup_identity::authorize_control(grant)
    }.map_err(|_| ("unauthorized", "host control launch authorization failed"))?;
    // Read both frames before letting the watcher own stdin. No further request
    // or argv dispatch is accepted; EOF/extra bytes revoke this read-only child.
    respire_spawn::watch_control_parent()
        .map_err(|_| ("unauthorized", "host control parent watch failed"))?;
    crate::startup_identity::verify_control_binding(&params.binding)
        .map_err(|_| ("scope_mismatch", "host control binding does not match consumed grant"))?;
    *control_ready = true;
    if model_plan || model_verify {
        let command = if model_verify { "model-install-verify" } else { "model-install-plan" };
        response.envelope = Some(ResultEnvelope::new(command, Status::Pending, serde_json::json!({}), Vec::new()));
        *progress.lock().map_err(|_| ("control_unavailable", "control progress unavailable"))? = response.clone();
        if model_verify {
            respire_commands::model_install::enable_backend_probe_host(
                respire_commands::model_install::BackendProbeHost::PrivateControl);
            // Only the authenticated Paused operation can extend the initial input deadline.
            events.send(ControlEvent::LongControlStarted)
                .map_err(|_| ("control_unavailable", "model verification controller unavailable"))?;
        }
        let model = model_params.as_ref()
            .ok_or(("invalid_request", "model preparation parameters missing"))?;
        let plan = if model_verify {
            respire_commands::model_install::model_preparation_verify(&model.intent,
                model.selection_sha256.as_deref()
                    .ok_or(("invalid_request", "model preparation selection digest missing"))?)
        } else { respire_commands::model_install::model_preparation_plan(&model.intent) }
            .map_err(|_| ("model_plan_unavailable", "selected model preparation status unavailable"))?;
        crate::startup_identity::verify_control_binding(&params.binding)
            .map_err(|_| ("scope_mismatch", "host control identity changed during model planning"))?;
        let mut envelope = ResultEnvelope::new(command, Status::Ok,
            serde_json::json!({"complete":plan.assets.complete}), Vec::new());
        envelope.details = serde_json::to_value(plan)
            .map_err(|_| ("model_plan_unavailable", "model installation plan encoding failed"))?;
        response.envelope = Some(envelope);
        response.ok = true;
        response.exit = 0;
        return Ok(());
    }
    let revision = match respire_app::service::memory_revision() {
        Ok(revision) => revision,
        Err(failure) => {
            // This path reports DB/schema diagnostics, never grant or session contents.
            response.error = Some(format!("{failure:#}"));
            return Err(("revision_unavailable", "memory revision unavailable"));
        }
    };
    crate::startup_identity::verify_control_binding(&params.binding)
        .map_err(|_| ("scope_mismatch", "host control identity changed during the read"))?;
    let actual_profile = std::path::Path::new(&revision.profile).canonicalize()
        .map_err(|_| ("scope_mismatch", "host control profile is unavailable"))?;
    if actual_profile != params.binding.profile {
        return Err(("scope_mismatch", "memory revision profile does not match control binding"));
    }
    response.envelope = Some(ResultEnvelope::new(
        "memory-revision", Status::Ok,
        serde_json::to_value(revision)
            .map_err(|_| ("revision_unavailable", "memory revision encoding failed"))?,
        Vec::new(),
    ));
    response.ok = true;
    response.exit = 0;
    Ok(())
}

fn watch_auth_parent(events: mpsc::SyncSender<ControlEvent>) -> std::io::Result<()> {
    std::thread::Builder::new().name("auth-control-parent".into()).spawn(move || {
        let mut input = std::io::stdin();
        let mut byte = [0u8; 1];
        loop {
            match input.read(&mut byte) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                _ => { let _ = events.send(ControlEvent::ParentRevoked); break; }
            }
        }
    })?;
    Ok(())
}

pub(crate) fn validate_auth_request(request: &RpcRequest) -> std::result::Result<HostAuthKeygenParams, ControlFailure> {
    if request.v != PROTOCOL_V { return Err(("protocol_version_mismatch", "protocol_version_mismatch")); }
    let uuid = |value: &str| uuid::Uuid::parse_str(value)
        .is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == value);
    if !uuid(&request.id) || !request.operation_id.as_deref().is_some_and(uuid)
        || request.idempotency_key.as_ref().is_none_or(|key| key.is_empty() || key.len() > 128
            || !key.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)))
        || ![HOST_AUTH_KEYGEN_METHOD, HOST_AUTH_RESULT_METHOD].contains(&request.method.as_str())
        || request.args.len() != 1 || request.scope.is_some() || request.parent_operation_id.is_some()
        || request.queue_wait_ms.is_some() || request.lifecycle.is_some() {
        return Err(("invalid_request", "unsupported auth control RPC shape"));
    }
    let params: HostAuthKeygenParams = serde_json::from_str(&request.args[0])
        .map_err(|_| ("invalid_request", "invalid auth control params"))?;
    if params.schema_version != HOST_AUTH_SCHEMA_V {
        return Err(("invalid_request", "unsupported auth control schema"));
    }
    Ok(params)
}

pub(crate) fn validate_request(
    request: &RpcRequest,
) -> std::result::Result<(HostControlParams, Option<HostModelParams>), ControlFailure> {
    if request.v != PROTOCOL_V {
        return Err(("protocol_version_mismatch", "protocol_version_mismatch"));
    }
    if !uuid::Uuid::parse_str(&request.id)
        .is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == request.id)
        || ![HostControlOperation::MemoryRevision.method(), HostControlOperation::ModelInstallPlan.method(),
            HostControlOperation::ModelInstallVerify.method()]
            .contains(&request.method.as_str())
        || request.args.len() != 1
        || request.scope.is_some()
        || request.operation_id.is_some()
        || request.idempotency_key.is_some()
        || request.parent_operation_id.is_some()
        || request.queue_wait_ms.is_some()
        || request.lifecycle.is_some()
    {
        return Err(("invalid_request", "unsupported host control RPC shape"));
    }
    if request.method != HostControlOperation::MemoryRevision.method() {
        let params: HostModelParams = serde_json::from_str(&request.args[0])
            .map_err(|_| ("invalid_request", "invalid model preparation params"))?;
        let verify = request.method == HostControlOperation::ModelInstallVerify.method();
        if params.schema_version != HOST_MODEL_SCHEMA_V
            || if verify {
                !params.selection_sha256.as_deref().is_some_and(|digest| digest.len() == 64
                    && digest.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
            } else { params.selection_sha256.is_some() }
        {
            return Err(("invalid_request", "invalid model preparation schema or selection digest"));
        }
        return Ok((HostControlParams { schema_version: HOST_CONTROL_SCHEMA_V,
            binding: params.binding.clone() }, Some(params)));
    }
    let params: HostControlParams = serde_json::from_str(&request.args[0])
        .map_err(|_| ("invalid_request", "invalid host control params"))?;
    if params.schema_version != HOST_CONTROL_SCHEMA_V {
        return Err(("invalid_request", "unsupported host control schema"));
    }
    Ok((params, None))
}

fn read_frame<T: serde::de::DeserializeOwned>() -> Result<T> {
    let mut input = std::io::stdin().lock();
    let mut length = [0u8; 4];
    input.read_exact(&mut length).context("missing host control frame")?;
    let length = u32::from_be_bytes(length) as usize;
    anyhow::ensure!(length > 0 && length <= HOST_CONTROL_MAX_FRAME_BYTES, "invalid host control frame size");
    let mut bytes = vec![0u8; length];
    input.read_exact(&mut bytes).context("incomplete host control frame")?;
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid host control JSON"))
}

fn response(id: &str) -> RpcResponse<ResultEnvelope> {
    RpcResponse {
        v: PROTOCOL_V,
        id: id.to_owned(),
        operation_id: None,
        scope: None,
        idempotency_key: None,
        ok: false,
        exit: 2,
        bin: "rsrs-runtime".to_owned(),
        envelope: None,
        error: None,
        code: None,
        web_url: None,
        pid: Some(std::process::id()),
        data_dir: None,
    }
}
