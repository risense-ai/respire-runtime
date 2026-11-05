//! One-shot offline control, dispatched before serving or opening a business store.
use std::io::{Read, Write};
use std::time::Duration;

use anyhow::{Context, Result};
use respire_commands::output::{Item, ResultEnvelope, Status};
use respire_protocol::{
    HostControlLaunchGrant, HostControlOperation, HostControlParams, RpcRequest, RpcResponse,
    HOST_CONTROL_MAX_FRAME_BYTES, HOST_CONTROL_SCHEMA_V,
};

const PROTOCOL_V: u32 = respire_commands::rpc_worker::PROTOCOL_V;
const CONTROL_DEADLINE: Duration = Duration::from_secs(10);

pub(crate) fn run() -> Result<i32> {
    // This process only reads: hard exit bounds blocked input/output and teardown.
    // Pipe revocation handles parent loss; no mutable business state exists.
    std::thread::Builder::new().name("control-deadline".into()).spawn(|| {
        std::thread::sleep(CONTROL_DEADLINE);
        std::process::exit(2);
    })?;
    let mut response = response("");
    let mut control_ready = false;
    let result = receive_and_execute(&mut response, &mut control_ready);
    if let Err((code, message)) = result {
        response.code = Some(code.to_owned());
        let diagnostic = response.error.take().unwrap_or_else(|| message.to_owned());
        response.error = Some(diagnostic.clone());
        let mut envelope = ResultEnvelope::new(
            "memory-revision", Status::Fail, serde_json::json!({}), Vec::new(),
        );
        envelope.errors.push(diagnostic);
        response.envelope = Some(envelope);
    }
    if let Some(envelope) = &mut response.envelope {
        envelope.items.push(Item::new("control_ready", if control_ready { Status::Ok } else { Status::Fail }, control_ready.to_string()));
        envelope.items.push(Item::new("store_ready", Status::Skip, "false"));
    }
    let bytes = serde_json::to_vec(&response)?;
    anyhow::ensure!(bytes.len() <= HOST_CONTROL_MAX_FRAME_BYTES, "host control response too large");
    let mut output = std::io::stdout().lock();
    output.write_all(&(bytes.len() as u32).to_be_bytes())?;
    output.write_all(&bytes)?;
    output.flush()?;
    Ok(response.exit)
}

type ControlFailure = (&'static str, &'static str);

fn receive_and_execute(
    response: &mut RpcResponse<ResultEnvelope>,
    control_ready: &mut bool,
) -> std::result::Result<(), ControlFailure> {
    let grant: HostControlLaunchGrant = read_frame()
        .map_err(|_| ("invalid_request", "invalid host control grant frame"))?;
    if grant.protocol_version != PROTOCOL_V {
        return Err(("protocol_version_mismatch", "protocol_version_mismatch"));
    }
    crate::startup_identity::authorize_control(grant)
        .map_err(|_| ("unauthorized", "host control launch authorization failed"))?;
    let request: RpcRequest = read_frame()
        .map_err(|_| ("invalid_request", "invalid host control RPC frame"))?;
    response.id = request.id.clone();
    let params = validate_request(&request)?;
    // Read both frames before letting the watcher own stdin. No further request
    // or argv dispatch is accepted; EOF/extra bytes revoke this read-only child.
    respire_spawn::watch_control_parent()
        .map_err(|_| ("unauthorized", "host control parent watch failed"))?;
    crate::startup_identity::verify_control_binding(&params.binding)
        .map_err(|_| ("scope_mismatch", "host control binding does not match consumed grant"))?;
    *control_ready = true;
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

pub(crate) fn validate_request(
    request: &RpcRequest,
) -> std::result::Result<HostControlParams, ControlFailure> {
    if request.v != PROTOCOL_V {
        return Err(("protocol_version_mismatch", "protocol_version_mismatch"));
    }
    if !uuid::Uuid::parse_str(&request.id)
        .is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == request.id)
        || request.method != HostControlOperation::MemoryRevision.method()
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
