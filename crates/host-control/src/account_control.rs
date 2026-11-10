//! Account requests and receipt checks extracted from CLI control.rs.
use anyhow::{Context, Result};
use respire_commands::output::{ResultEnvelope, Status};
use respire_protocol::host_control::*;
use respire_protocol::{ControlBinding, HostAuthIdentity, RpcRequest, RpcResponse};
use std::path::Path;

/// Parameters only: the Runtime account response wrapper and completion grant are separate gates.
/// Never derive Debug or put these credentials in process arguments or environment variables.
pub(crate) enum AccountControl {
    Register {
        addr: String,
        user: String,
        password: String,
        super_password: Option<String>,
    },
    Login {
        addr: String,
        user: String,
        authorization: HostAuthAuthorization,
        super_password: String,
    },
    LoginStep {
        addr: String,
        user: String,
        authorization: HostAuthAuthorization,
        super_password: Option<String>,
        input: HostAuthLoginContinuation,
    },
    Result,
    Complete,
    Rollback,
}

pub(crate) fn account_request(
    binding: ControlBinding,
    identity: HostAuthIdentity,
    operation_id: &str,
    operation: AccountControl,
) -> Result<RpcRequest> {
    let id = uuid::Uuid::parse_str(operation_id).context("invalid account operation ID")?;
    anyhow::ensure!(
        id.get_version_num() == 4 && id.to_string() == operation_id,
        "account operation ID must be a canonical random UUID"
    );
    let (method, argument) = match operation {
        AccountControl::Register {
            addr,
            user,
            password,
            super_password,
        } => (
            HOST_AUTH_REGISTER_METHOD,
            serde_json::to_string(&HostAuthRegisterParams {
                schema_version: HOST_AUTH_SCHEMA_V,
                binding,
                identity,
                addr,
                user,
                password,
                super_password,
            })?,
        ),
        AccountControl::Login {
            addr,
            user,
            authorization,
            super_password,
        } => (
            HOST_AUTH_LOGIN_METHOD,
            serde_json::to_string(&HostAuthLoginParams {
                schema_version: HOST_AUTH_SCHEMA_V,
                binding,
                identity,
                addr,
                user,
                authorization,
                super_password: Some(super_password),
                continuation: None,
            })?,
        ),
        AccountControl::LoginStep {
            addr,
            user,
            authorization,
            super_password,
            input,
        } => (
            HOST_AUTH_LOGIN_METHOD,
            serde_json::to_string(&HostAuthLoginParams {
                schema_version: HOST_AUTH_SCHEMA_V,
                binding,
                identity,
                addr,
                user,
                authorization,
                super_password,
                continuation: Some(input),
            })?,
        ),
        receipt => {
            let method = match receipt {
                AccountControl::Result => HOST_AUTH_ACCOUNT_RESULT_METHOD,
                AccountControl::Complete => HOST_AUTH_ACCOUNT_COMPLETE_METHOD,
                AccountControl::Rollback => HOST_AUTH_ACCOUNT_ROLLBACK_METHOD,
                _ => anyhow::bail!("invalid account receipt operation"),
            };
            (
                method,
                serde_json::to_string(&HostAuthAccountParams {
                    schema_version: HOST_AUTH_SCHEMA_V,
                    binding,
                    identity,
                })?,
            )
        }
    };
    Ok(RpcRequest {
        v: crate::PROTOCOL_V,
        id: uuid::Uuid::new_v4().to_string(),
        method: method.to_owned(),
        args: vec![argument],
        scope: None,
        operation_id: Some(operation_id.to_owned()),
        idempotency_key: Some(operation_id.to_owned()),
        parent_operation_id: None,
        queue_wait_ms: None,
        lifecycle: None,
    })
}

/// Validate receipt fields, not transport success or permission to leave maintenance.
pub(crate) fn validate_account_receipt(
    receipt: &HostAuthAccountResult,
    operation_id: &str,
    source_profile: &Path,
    register: bool,
) -> Result<()> {
    let strict_path = |path: &Path| {
        path.is_absolute()
            && !path
                .components()
                .any(|part| part == std::path::Component::ParentDir)
    };
    anyhow::ensure!(
        receipt.operation_id == operation_id
            && strict_path(&receipt.source_profile)
            && receipt.source_profile == source_profile
            && receipt.target_profile.as_deref().is_none_or(strict_path),
        "account receipt operation or profile mismatch"
    );
    anyhow::ensure!(
        !register || receipt.login.is_none(),
        "register receipt contains login continuation state"
    );
    if matches!(
        receipt.outcome,
        HostAuthAccountOutcome::AwaitingInput | HostAuthAccountOutcome::RolledBack
    ) {
        anyhow::ensure!(
            receipt.super_password.is_none()
                && receipt
                    .login
                    .as_ref()
                    .is_none_or(|login| login.super_issued.is_none()),
            "noncommitted outward account receipt contains issued recovery material"
        );
    }
    match receipt.outcome {
        HostAuthAccountOutcome::AwaitingInput => {
            let login = receipt
                .login
                .as_ref()
                .context("awaiting-input login status is missing")?;
            let mut inputs = std::collections::BTreeSet::new();
            anyhow::ensure!(
                !register
                    && receipt.account_id.is_none()
                    && receipt.session_sha256.is_none()
                    && receipt.super_password.is_none()
                    && login.super_issued.is_none()
                    && !login.user.is_empty()
                    && !login.addr.is_empty()
                    && !login.required_inputs.is_empty()
                    && login.required_inputs.iter().all(|input| matches!(
                        input.as_str(),
                        "totp"
                            | "super_password"
                            | "legacy_password"
                            | "account_secret"
                            | "source_secret"
                            | "secret_key"
                            | "new_super"
                            | "merge_local"
                    ) && inputs.insert(input.as_str()))
                    && login.dir.as_deref().is_none_or(strict_path),
                "invalid awaiting-input account receipt"
            );
        }
        HostAuthAccountOutcome::RolledBack => {
            anyhow::ensure!(
                receipt.account_id.is_none()
                    && receipt.session_sha256.is_none()
                    && receipt.super_password.is_none(),
                "invalid rolled-back account receipt"
            );
        }
        HostAuthAccountOutcome::AwaitingVerification | HostAuthAccountOutcome::Committed => {
            let target = receipt
                .target_profile
                .as_ref()
                .context("account receipt target is missing")?;
            let (_, selected) = respire_client_host::config::control_roots()?;
            let target =
                respire_client_host::config::normalize_control_path(target)?.canonicalize()?;
            anyhow::ensure!(
                selected.canonicalize()? == target,
                "account receipt target is not selected"
            );
            let actual = crate::identity(&target)?;
            anyhow::ensure!(
                matches!(actual, HostAuthIdentity::Bound { account_id, session_sha256 }
                if Some(&account_id) == receipt.account_id.as_ref()
                    && Some(&session_sha256) == receipt.session_sha256.as_ref()),
                "account receipt target identity mismatch"
            );
            anyhow::ensure!(
                if register {
                    receipt
                        .super_password
                        .as_deref()
                        .is_some_and(|value| !value.is_empty())
                } else {
                    receipt.super_password.is_none()
                },
                "invalid account recovery-code presence"
            );
        }
        HostAuthAccountOutcome::Unknown => {
            // Even a complete-looking vault-pending receipt is not a terminal result.
            anyhow::ensure!(
                receipt.account_id.is_some() == receipt.session_sha256.is_some()
                    && (receipt.account_id.is_none() || receipt.target_profile.is_some())
                    && (receipt.super_password.is_none()
                        || (register && receipt.account_id.is_some()))
                    && receipt
                        .super_password
                        .as_deref()
                        .is_none_or(|value| !value.is_empty()),
                "invalid unknown account receipt"
            );
        }
    }
    Ok(())
}

pub(crate) fn validate_account_response(
    response: RpcResponse<ResultEnvelope>,
    request: &RpcRequest,
    profile: &Path,
    pid: u32,
    source: &Path,
    register: bool,
) -> Result<ResultEnvelope> {
    anyhow::ensure!(
        response.v == request.v
            && response.id == request.id
            && response.bin == "rsrs-runtime"
            && response.pid == Some(pid)
            && response.operation_id == request.operation_id
            && response.idempotency_key == request.idempotency_key
            && response.scope.is_none()
            && response.web_url.is_none(),
        "account control response identity mismatch"
    );
    if let Some(directory) = &response.data_dir {
        anyhow::ensure!(
            Path::new(directory).canonicalize()? == profile,
            "account response launch profile mismatch"
        );
    }
    if response.error.is_some() {
        let envelope = response
            .envelope
            .as_ref()
            .context("account control rejection envelope missing")?;
        let (code, message) = match response.code.as_deref() {
            Some("unauthorized") => ("unauthorized", "account launch or parent authorization failed"),
            Some("scope_mismatch") => ("scope_mismatch", "account control binding changed or does not match"),
            Some("auth_ownership_unavailable") => ("auth_ownership_unavailable", "account library ownership is unavailable"),
            Some("control_unavailable") => ("control_unavailable", "account controller is unavailable"),
            Some("account_outcome_unknown") => ("account_outcome_unknown", "account outcome is unknown; query the original operation without replaying"),
            Some("control_outcome_unknown") => ("control_outcome_unknown", "account deadline or parent authorization ended; query the original operation without replaying"),
            _ => anyhow::bail!("invalid account control rejection code"),
        };
        let deadline = code == "control_outcome_unknown";
        let executed = code == "account_outcome_unknown";
        anyhow::ensure!(
            !response.ok
                && response.exit == 2
                && response
                    .error
                    .as_deref()
                    .is_some_and(|error| !error.is_empty())
                && envelope.command == "auth-account"
                && matches!(envelope.status, Status::Fail)
                && envelope.details.is_null()
                && envelope.actions.is_empty()
                && envelope.related.is_empty()
                && envelope.items.len() == 2
                && envelope.items[0].name == "control_ready"
                && envelope.items[0].value
                    == (if deadline {
                        "unknown"
                    } else if executed {
                        "true"
                    } else {
                        "false"
                    })
                && (if deadline {
                    matches!(envelope.items[0].status, Status::Skip)
                } else if executed {
                    matches!(envelope.items[0].status, Status::Ok)
                } else {
                    matches!(envelope.items[0].status, Status::Fail)
                })
                && envelope.items[1].name == "store_ready"
                && envelope.items[1].value == "false"
                && matches!(envelope.items[1].status, Status::Skip)
                && (if deadline {
                    envelope.summary == serde_json::json!({"outcome":"unknown"})
                        && envelope.errors.is_empty()
                } else {
                    envelope.summary == serde_json::json!({})
                        && envelope.errors.len() == 1
                        && response.error.as_ref() == envelope.errors.first()
                }),
            "invalid account control rejection envelope"
        );
        // Never echo the Runtime diagnostic; every rejection retains the original operation.
        anyhow::bail!("Runtime rejected account control ({code}): {message}");
    }
    let envelope = response
        .envelope
        .context("account control result is missing")?;
    anyhow::ensure!(
        envelope.command == "auth-account"
            && envelope.details.is_null()
            && envelope.errors.is_empty(),
        "invalid account control envelope"
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
            "account helper readiness was not confirmed"
        );
    }
    let receipt: HostAuthAccountResult = serde_json::from_value(envelope.summary.clone())
        .map_err(|_| anyhow::anyhow!("invalid account receipt shape"))?;
    validate_account_receipt(
        &receipt,
        request
            .operation_id
            .as_deref()
            .context("account operation is missing")?,
        source,
        register,
    )?;
    if request.method == HOST_AUTH_LOGIN_METHOD {
        let params: HostAuthLoginParams = serde_json::from_str(
            request
                .args
                .first()
                .context("login request parameters are missing")?,
        )
        .map_err(|_| anyhow::anyhow!("invalid login request parameters"))?;
        if let Some(login) = receipt.login.as_ref() {
            anyhow::ensure!(
                login.user == params.user
                    && login.addr.trim_end_matches('/') == params.addr.trim().trim_end_matches('/'),
                "login receipt user or server differs from the original request"
            );
        }
    }
    let code = match receipt.outcome {
        HostAuthAccountOutcome::AwaitingInput
        | HostAuthAccountOutcome::AwaitingVerification
        | HostAuthAccountOutcome::Committed => None,
        HostAuthAccountOutcome::Unknown => Some("account_outcome_unknown"),
        HostAuthAccountOutcome::RolledBack => Some("account_rolled_back"),
    };
    anyhow::ensure!(
        response.code.as_deref() == code
            && if code.is_none() {
                response.ok
                    && response.exit == 0
                    && if receipt.outcome == HostAuthAccountOutcome::AwaitingInput {
                        matches!(envelope.status, Status::Pending)
                            && matches!(
                                request.method.as_str(),
                                HOST_AUTH_LOGIN_METHOD | HOST_AUTH_ACCOUNT_RESULT_METHOD
                            )
                    } else {
                        matches!(envelope.status, Status::Ok)
                    }
            } else {
                !response.ok && response.exit == 2 && matches!(envelope.status, Status::Fail)
            },
        "account control outcome/status mismatch"
    );
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rolled_back_receipt_rejects_nested_issued_material() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let source = directory.path().canonicalize()?;
        let mut receipt = HostAuthAccountResult {
            operation_id: uuid::Uuid::new_v4().to_string(),
            outcome: HostAuthAccountOutcome::RolledBack,
            source_profile: source.clone(),
            target_profile: None,
            account_id: None,
            session_sha256: None,
            super_password: None,
            login: Some(respire_protocol::host_control::HostAuthLoginStatus::default()),
        };
        validate_account_receipt(&receipt, &receipt.operation_id, &source, false)?;
        if let Some(login) = receipt.login.as_mut() {
            login.super_issued = Some("synthetic-only".into());
        }
        assert!(validate_account_receipt(&receipt, &receipt.operation_id, &source, false).is_err());
        Ok(())
    }
}
