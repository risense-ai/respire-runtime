//! One-shot offline control, dispatched before serving or opening a business store.
use std::io::{Read, Write};
use std::time::Duration;
use std::sync::{Arc, Mutex, mpsc};

use anyhow::{Context, Result};
use respire_commands::output::{Item, ResultEnvelope, Status};
use respire_protocol::{
    HostControlLaunchGrant, HostControlOperation, HostControlParams, RpcRequest, RpcResponse,
    HOST_CONTROL_MAX_FRAME_BYTES, HOST_CONTROL_SCHEMA_V,
    HostAuthKeygenParams, HostAuthOutcome, HOST_AUTH_SCHEMA_V,
    HOST_AUTH_KEYGEN_METHOD, HOST_AUTH_RESULT_METHOD,
};

const PROTOCOL_V: u32 = respire_commands::rpc_worker::PROTOCOL_V;
const CONTROL_DEADLINE: Duration = Duration::from_secs(10);

enum ControlEvent {
    Finished(RpcResponse<ResultEnvelope>),
    ParentRevoked,
}

pub(crate) fn run() -> Result<i32> {
    let progress = Arc::new(Mutex::new(response("")));
    let worker_progress = Arc::clone(&progress);
    let (sent, received) = mpsc::sync_channel(1);
    std::thread::Builder::new().name("control-operation".into()).spawn(move || {
        let response = execute(&worker_progress, &sent);
        let _ = sent.send(ControlEvent::Finished(response));
    })?;
    let response = match received.recv_timeout(CONTROL_DEADLINE) {
        Ok(ControlEvent::Finished(response)) => response,
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
            response
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
            HostAuthAccountOutcome::AwaitingVerification | HostAuthAccountOutcome::Committed);
        response.exit = if response.ok { 0 } else { 2 };
        response.code = match result.outcome {
            HostAuthAccountOutcome::Unknown => Some("account_outcome_unknown".into()),
            HostAuthAccountOutcome::RolledBack => Some("account_rolled_back".into()),
            _ => None,
        };
        response.envelope = Some(ResultEnvelope::new("auth-account",
            if response.ok { Status::Ok } else { Status::Fail },
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
    let params = validate_request(&request)?;
    let model_plan = request.method == HostControlOperation::ModelInstallPlan.method();
    if model_plan {
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
    if model_plan {
        let plan = respire_commands::model_install::model_install_plan()
            .map_err(|_| ("model_plan_unavailable", "selected model installation plan unavailable"))?;
        crate::startup_identity::verify_control_binding(&params.binding)
            .map_err(|_| ("scope_mismatch", "host control identity changed during model planning"))?;
        let mut envelope = ResultEnvelope::new("model-install-plan", Status::Ok,
            serde_json::json!({"complete":false}), Vec::new());
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
) -> std::result::Result<HostControlParams, ControlFailure> {
    if request.v != PROTOCOL_V {
        return Err(("protocol_version_mismatch", "protocol_version_mismatch"));
    }
    if !uuid::Uuid::parse_str(&request.id)
        .is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == request.id)
        || ![HostControlOperation::MemoryRevision.method(), HostControlOperation::ModelInstallPlan.method()]
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
    let params: HostControlParams = serde_json::from_str(&request.args[0])
        .map_err(|_| ("invalid_request", "invalid host control params"))?;
    if params.schema_version != HOST_CONTROL_SCHEMA_V {
        return Err(("invalid_request", "unsupported host control schema"));
    }
    Ok(params)
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
