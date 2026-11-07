//! Single-source envelope emission for the CLI binary and the runtime worker.
//!
//! Every command result funnels through [`emit_result`]; failures that never
//! produced an envelope fall back to [`command_failure`]; detail-only reports
//! use [`emit_details`]. The output pipeline state (captured slot, exit code,
//! deferred-output flags) lives in `output_state` and is shared verbatim.

use anyhow::Result;

use crate::output::{ResultEnvelope, Status as OutputStatus};
use crate::output_state::{
    json_mode, mark_emitted, set_exit_code, status_exit_code, CAPTURED, DEFER_PROFILE_OUTPUT,
    HOST_RPC_OUTPUT,
};
#[cfg(feature = "server")]
use crate::progress;
#[cfg(feature = "server")]
use crate::rpc_worker;
use crate::runtime_error;

pub fn emit_result(result: ResultEnvelope) -> Result<()> {
    let mut result = result;
    result.ensure_failure_diagnostics();
    result.details = crate::output::sanitize_details(&result.command, &result.details);
    let exit_code = status_exit_code(result.status);
    #[cfg(feature = "server")]
    let worker_active = rpc_worker::worker_active();
    #[cfg(not(feature = "server"))]
    let worker_active = false;
    if worker_active || DEFER_PROFILE_OUTPUT.get() || HOST_RPC_OUTPUT.get() {
        CAPTURED.with(|slot| *slot.borrow_mut() = Some(result));
        mark_emitted();
        set_exit_code(exit_code);
        return Ok(());
    }
    #[cfg(feature = "server")]
    progress::finish();
    println!("{}", result.render(json_mode())?);
    mark_emitted();
    set_exit_code(exit_code);
    Ok(())
}

pub fn command_failure(error: &anyhow::Error) -> (ResultEnvelope, i32) {
    let input = error
        .downcast_ref::<respire_client_host::input_error::InputError>()
        .is_some();
    let unknown = match error.downcast_ref::<runtime_error::RuntimeError>() {
        Some(runtime_error::RuntimeError::OutcomeUnknown {
            request_id,
            operation,
            ..
        }) => Some((request_id, operation)),
        _ => None,
    };
    let mut envelope = ResultEnvelope::new(
        "cli",
        OutputStatus::Fail,
        serde_json::json!({"reason": if unknown.is_some() { "request_outcome_unknown" } else if input { "invalid_input" } else { "runtime_error" }}),
        Vec::new(),
    );
    envelope.errors.push(format!("{error:#}"));
    envelope.details = serde_json::json!({"error_type": if input { "user" } else { "runtime" }});
    if let Some((request_id, operation)) = unknown {
        envelope.details = serde_json::json!({
            "error_type":"outcome_unknown",
            "request_id":request_id,
            "operation_id":operation.operation_id,
            "idempotency_key":operation.idempotency_key,
            "scope":operation.scope,
            "replayed":false,
            "result_method":"runtime.result"
        });
    }
    (envelope, if input { 2 } else { 1 })
}

pub fn emit_details(
    command: &str,
    status: OutputStatus,
    summary: serde_json::Value,
    details: serde_json::Value,
) -> Result<()> {
    let mut result = ResultEnvelope::new(command, status, summary, Vec::new());
    result.details = details;
    emit_result(result)
}
