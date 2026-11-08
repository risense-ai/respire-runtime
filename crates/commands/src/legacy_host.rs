//! Original local RPC compatibility: fixed actor, shared queue and last-64 cache.
//! No credential, persistent journal, separate executor or account selection.
use std::sync::{atomic::{AtomicBool, Ordering}, OnceLock};
use anyhow::{Context, Result};
use respire_protocol::{RpcRequest, RuntimeRequestScope};
use crate::{output::ResultEnvelope, rpc_serve};

type RpcResponse = respire_protocol::RpcResponse<ResultEnvelope>;
type Verify = fn() -> Result<()>;
struct Lane {
    scope: RuntimeRequestScope,
    installation: String,
    verify: Verify,
    admission: Option<Verify>,
    revoked: AtomicBool,
}
static LANE: OnceLock<Lane> = OnceLock::new();

/// Only the owning background host installs its startup account and instance.
/// Generation is advanced solely by the existing in-process Runtime machinery.
pub fn install(scope: RuntimeRequestScope, installation: String, verify: Verify) -> Result<()> {
    install_inner(scope, installation, verify, None)
}

pub fn install_with_admission(scope: RuntimeRequestScope, installation: String,
    verify: Verify, admission: Verify) -> Result<()> {
    install_inner(scope, installation, verify, Some(admission))
}

fn install_inner(scope: RuntimeRequestScope, installation: String, verify: Verify,
    admission: Option<Verify>) -> Result<()> {
    verify()?;
    if let Some(admission) = admission { admission()?; }
    anyhow::ensure!(!scope.account_id.is_empty() && !scope.instance_id.is_empty()
        && scope.generation != 0 && !installation.is_empty(), "legacy host identity is absent");
    LANE.set(Lane { scope, installation, verify, admission, revoked: AtomicBool::new(false) })
        .map_err(|_| anyhow::anyhow!("legacy host already installed"))
}
enum VerificationFailure {
    Binding(anyhow::Error),
    Admission(anyhow::Error),
}
impl VerificationFailure {
    fn into_error(self) -> anyhow::Error {
        match self {
            Self::Binding(error) => error,
            Self::Admission(error) => error.context("legacy_host_admission_unavailable"),
        }
    }
}

impl Lane {
    fn verify_binding(&self) -> Result<()> {
        anyhow::ensure!(!self.revoked.load(Ordering::Acquire), "legacy_host_binding_changed");
        if (self.verify)().is_err() {
            self.revoked.store(true, Ordering::Release);
            anyhow::bail!("legacy_host_binding_changed");
        }
        Ok(())
    }
    fn verify_admission(&self) -> std::result::Result<(), VerificationFailure> {
        self.verify_binding().map_err(VerificationFailure::Binding)?;
        if let Some(admission) = self.admission {
            admission().map_err(VerificationFailure::Admission)?;
        }
        Ok(())
    }
    fn same_actor(&self, scope: &RuntimeRequestScope) -> bool {
        scope.account_id == self.scope.account_id && scope.instance_id == self.scope.instance_id
    }
    fn scope(&self) -> RuntimeRequestScope {
        RuntimeRequestScope { generation: crate::rpc_worker::generation_on_wire(
            crate::rpc_worker::sync_generation()), ..self.scope.clone() }
    }
}
pub(crate) fn is_enabled() -> bool { LANE.get().is_some() }

pub(crate) fn verify_execution(scope: &RuntimeRequestScope) -> Result<()> {
    let Some(lane) = LANE.get() else { return Ok(()); };
    anyhow::ensure!(lane.same_actor(scope), "legacy_host_execution_scope_mismatch");
    lane.verify_admission().map_err(VerificationFailure::into_error)
}

pub(crate) fn verify_active_execution(scope: &RuntimeRequestScope) -> Result<()> {
    let Some(lane) = LANE.get() else { return Ok(()); };
    anyhow::ensure!(lane.same_actor(scope), "legacy_host_execution_scope_mismatch");
    lane.verify_binding()
}

pub(crate) fn health() -> Result<()> {
    if let Some(lane) = LANE.get() { lane.verify_binding()?; }
    Ok(())
}

pub(crate) fn stop_identity() -> Result<Option<serde_json::Value>> {
    let Some(lane) = LANE.get() else { return Ok(None); };
    lane.verify_binding()?;
    let scope = lane.scope();
    Ok(Some(serde_json::json!({"installation_id":lane.installation,
        "account_id":scope.account_id,"instance_id":scope.instance_id,"generation":scope.generation})))
}

pub(crate) struct Projection { original: RpcRequest }

/// Scoped callers retain the modern path. Old requests reuse the exact protocol
/// DTO, including the released CLI's lifecycle:null and queue_wait_ms fields.
pub(crate) fn prepare(body: &[u8]) -> Result<Option<(RpcRequest, Projection)>> {
    let Some(lane) = LANE.get() else { return Ok(None); };
    let request: RpcRequest = serde_json::from_slice(body).context("invalid legacy RPC")?;
    if request.scope.is_some() { return Ok(None); }
    anyhow::ensure!(request.operation_id.is_none() && request.idempotency_key.is_none()
        && request.parent_operation_id.is_none(), "scope_required");
    if rpc_serve::maintenance_control_method(&request.method) {
        lane.verify_binding()?;
    } else {
        lane.verify_admission().map_err(VerificationFailure::into_error)?;
    }
    let mut scoped = request.clone();
    scoped.scope = Some(lane.scope());
    if scoped.method != "runtime.result" {
        scoped.operation_id = Some(request.id.clone());
        scoped.idempotency_key = Some(request.id.clone());
    }
    Ok(Some((scoped, Projection { original: request })))
}
fn strip(response: &mut RpcResponse) {
    response.scope = None;
    response.operation_id = None;
    response.idempotency_key = None;
}
pub(crate) fn project(mut response: RpcResponse, projection: Projection) -> RpcResponse {
    let Some(lane) = LANE.get() else {
        return rpc_serve::error_response(&projection.original, "legacy_host_unavailable", "local host is unavailable");
    };
    if lane.verify_binding().is_err() {
        return rpc_serve::error_response(&projection.original, "legacy_host_binding_changed", "local host account changed");
    }
    if response.id != projection.original.id || response.v != crate::rpc_worker::PROTOCOL_V
        || !response.scope.as_ref().is_some_and(|scope| lane.same_actor(scope)) {
        return rpc_serve::error_response(&projection.original, "result_unknown", "original result is unavailable; do not replay automatically");
    }
    if projection.original.method == "runtime.result" {
        if let Some(envelope) = response.envelope.as_mut() {
            if let Some(summary) = envelope.summary.as_object_mut() {
                // v1 reports every retained terminal response as completed; the
                // nested ok/exit/envelope carries the original business failure.
                if summary.get("state").and_then(|v| v.as_str()) == Some("failed") {
                    summary.insert("state".into(), serde_json::json!("completed"));
                }
                if let Some(value) = summary.get_mut("response").filter(|value| !value.is_null()) {
                    let valid = serde_json::from_value::<RpcResponse>(value.clone()).ok()
                        .filter(|child| projection.original.args.first() == Some(&child.id)
                            && child.scope.as_ref().is_some_and(|scope| lane.same_actor(scope)));
                    let Some(mut child) = valid else {
                        return rpc_serve::error_response(&projection.original, "result_unknown", "original result is unavailable");
                    };
                    strip(&mut child);
                    *value = serde_json::to_value(child).unwrap_or(serde_json::Value::Null);
                }
                summary.remove("scope"); summary.remove("operation_id"); summary.remove("idempotency_key");
                summary.insert("request_id".into(), serde_json::json!(projection.original.args.first()));
                summary.insert("retention".into(), serde_json::json!("last 64 completed requests in this runtime; unknown is not proof of non-commit; never replay a write automatically"));
            }
        }
    }
    strip(&mut response);
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_failure_does_not_revoke_immutable_binding() {
        fn valid() -> Result<()> { Ok(()) }
        fn unavailable() -> Result<()> { anyhow::bail!("synthetic admission unavailable") }
        fn changed() -> Result<()> { anyhow::bail!("synthetic binding changed") }
        let mut lane = Lane {
            scope: RuntimeRequestScope {
                account_id: "account".into(), instance_id: "instance".into(), generation: 1,
            },
            installation: "installation".into(), verify: valid, admission: Some(unavailable),
            revoked: AtomicBool::new(false),
        };
        assert!(matches!(lane.verify_admission(), Err(VerificationFailure::Admission(_))));
        assert!(!lane.revoked.load(Ordering::Acquire));
        assert!(lane.verify_binding().is_ok());
        lane.admission = Some(valid);
        assert!(lane.verify_admission().is_ok());
        lane.verify = changed;
        assert!(matches!(lane.verify_admission(), Err(VerificationFailure::Binding(_))));
        assert!(lane.revoked.load(Ordering::Acquire));
        lane.verify = valid;
        assert!(lane.verify_binding().is_err(), "binding revocation must remain permanent");
    }
}
