//! The existing CLI account transaction coordinator, shared with the Runtime host facade.
//! Business effects remain in the one-shot private Runtime helper.
use crate::account_control::{self, AccountControl};
use crate::maintenance::{HostLifecycle, Maintenance, RecoveryMode};
use anyhow::{Context, Result};
use respire_client_host::lock::LibraryLock;
use respire_commands::output::ResultEnvelope;
use respire_protocol::host_control::{
    HostAuthAccountOutcome, HostAuthAccountResult, HostAuthAuthorization, HostAuthLoginContinuation,
};
use respire_protocol::{ControlBinding, HostAuthIdentity};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Can only be created by a live coordinator after an AwaitingInput receipt.
/// Retains the same operation, source identity and maintenance capability.
pub struct AccountContinuation {
    operation_id: String,
    source: PathBuf,
    original_identity: HostAuthIdentity,
    was_serving: bool,
    maintenance: Maintenance,
}

#[derive(Debug)]
pub struct AccountOutcomeUnknown {
    pub operation_id: String,
    pub source_profile: PathBuf,
    pub register: bool,
}
impl std::fmt::Display for AccountOutcomeUnknown {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(output, "account_outcome_unknown operation_id={} source_profile={} register={}; query the same operation, do not replay authentication",
            self.operation_id, self.source_profile.display(), self.register)
    }
}
impl std::error::Error for AccountOutcomeUnknown {}

#[derive(Debug)]
pub struct AccountHandoffPending {
    pub operation_id: String,
    pub source_profile: PathBuf,
    pub register: bool,
}
impl std::fmt::Display for AccountHandoffPending {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str(
            "account committed; Runtime host handoff is pending; do not repeat authentication",
        )
    }
}
impl std::error::Error for AccountHandoffPending {}

pub struct AccountCoordinator {
    host: Arc<dyn HostLifecycle>,
}
impl AccountCoordinator {
    pub fn new(host: Arc<dyn HostLifecycle>) -> Self {
        Self { host }
    }

    /// The old one-request desktop transport cannot retain an in-memory owner.
    /// Continue only the exact durably bound operation, querying its receipt first.
    pub fn login_or_continue(
        &self,
        addr: &str,
        user: &str,
        authorization: HostAuthAuthorization,
        super_password: Option<&str>,
        input: HostAuthLoginContinuation,
    ) -> Result<ResultEnvelope> {
        self.host.require_account_write()?;
        let (root, _) = respire_client_host::config::control_roots()?;
        if let Some((id, source)) =
            crate::maintenance::pending_account(&root.canonicalize()?, false, user, addr)?
        {
            return self.operate(
                &id,
                Some(&source),
                false,
                AccountControl::LoginStep {
                    addr: addr.to_owned(),
                    user: user.to_owned(),
                    authorization,
                    super_password: super_password.map(str::to_owned),
                    input,
                },
                None,
            );
        }
        self.login_step(
            addr,
            user,
            authorization,
            super_password,
            input,
            None,
            &mut None,
        )
    }

    pub fn register_or_query(
        &self,
        addr: &str,
        user: &str,
        password: &str,
    ) -> Result<ResultEnvelope> {
        self.host.require_account_write()?;
        let (root, _) = respire_client_host::config::control_roots()?;
        if let Some((id, source)) =
            crate::maintenance::pending_account(&root.canonicalize()?, true, user, addr)?
        {
            return self.operate(
                &id,
                Some(&source),
                true,
                AccountControl::Register {
                    addr: addr.to_owned(),
                    user: user.to_owned(),
                    password: password.to_owned(),
                    super_password: None,
                },
                None,
            );
        }
        self.register(addr, user, password, None)
    }

    pub fn register(
        &self,
        addr: &str,
        user: &str,
        password: &str,
        super_password: Option<&str>,
    ) -> Result<ResultEnvelope> {
        self.operate(
            &uuid::Uuid::new_v4().to_string(),
            None,
            true,
            AccountControl::Register {
                addr: addr.to_owned(),
                user: user.to_owned(),
                password: password.to_owned(),
                super_password: super_password.map(str::to_owned),
            },
            None,
        )
    }

    pub fn login_step(
        &self,
        addr: &str,
        user: &str,
        authorization: HostAuthAuthorization,
        super_password: Option<&str>,
        input: HostAuthLoginContinuation,
        resume: Option<&HostAuthAccountResult>,
        continuation: &mut Option<AccountContinuation>,
    ) -> Result<ResultEnvelope> {
        let operation = AccountControl::LoginStep {
            addr: addr.to_owned(),
            user: user.to_owned(),
            authorization,
            super_password: super_password.map(str::to_owned),
            input,
        };
        if let Some(previous) = resume {
            account_control::validate_account_receipt(
                previous,
                &previous.operation_id,
                &previous.source_profile,
                false,
            )?;
            if previous.outcome != HostAuthAccountOutcome::AwaitingInput {
                return self.result(&previous.operation_id, &previous.source_profile, false);
            }
            let status = previous
                .login
                .as_ref()
                .context("login continuation status is missing")?;
            anyhow::ensure!(
                status.user == user
                    && status.addr.trim_end_matches('/') == addr.trim().trim_end_matches('/'),
                "login continuation user or server differs from the original operation"
            );
            return self.operate(
                &previous.operation_id,
                Some(&previous.source_profile),
                false,
                operation,
                Some(continuation),
            );
        }
        self.operate(
            &uuid::Uuid::new_v4().to_string(),
            None,
            false,
            operation,
            Some(continuation),
        )
    }

    /// Explicit result reconnect does not issue a new login or registration.
    pub fn result(
        &self,
        operation_id: &str,
        source: &Path,
        register: bool,
    ) -> Result<ResultEnvelope> {
        self.operate(
            operation_id,
            Some(source),
            register,
            AccountControl::Result,
            None,
        )
    }

    pub fn rollback(
        &self,
        operation_id: &str,
        source: &Path,
        register: bool,
    ) -> Result<ResultEnvelope> {
        self.operate(
            operation_id,
            Some(source),
            register,
            AccountControl::Rollback,
            None,
        )
    }

    fn operate(
        &self,
        operation_id: &str,
        original_source: Option<&Path>,
        register: bool,
        operation: AccountControl,
        mut continuation: Option<&mut Option<AccountContinuation>>,
    ) -> Result<ResultEnvelope> {
        self.host.require_account_write()?;
        let id = uuid::Uuid::parse_str(operation_id).context("invalid account operation ID")?;
        anyhow::ensure!(
            id.get_version_num() == 4 && id.to_string() == operation_id,
            "account operation ID must be a canonical random UUID"
        );
        self.host.verified_runtime()?.revalidate()?;
        let (_, selected) = respire_client_host::config::control_roots()?;
        let takeover = crate::maintenance::takeover_lock()?;
        if original_source.is_none() {
            std::fs::create_dir_all(&selected)?;
        }
        let source = original_source.unwrap_or(&selected).canonicalize()?;
        let saved = continuation.as_mut().and_then(|slot| slot.take());
        let is_continuation =
            original_source.is_some() && matches!(&operation, AccountControl::LoginStep { .. });
        anyhow::ensure!(
            saved.is_none() || is_continuation,
            "live login continuation cannot be used for another operation"
        );
        let health = self.host.probe_runtime()?;
        anyhow::ensure!(
            health.is_some() || !self.host.endpoint_path().try_exists()?,
            "account control blocked: recorded owner has no verifiable health/drain receipt"
        );
        let (mut maintenance, original_identity, restore_owner) = if let Some(saved) = saved {
            anyhow::ensure!(
                !register
                    && saved.operation_id == operation_id
                    && saved.source == source
                    && selected.canonicalize()? == source
                    && crate::identity(&source)? == saved.original_identity,
                "login continuation changed its original operation or source identity"
            );
            (
                saved.maintenance,
                saved.original_identity,
                Some(saved.was_serving),
            )
        } else {
            let original_identity = crate::identity(&source)?;
            let mode = if original_source.is_some() {
                RecoveryMode::QueryOriginal
            } else {
                RecoveryMode::Fresh
            };
            let (maintenance, original_identity, was_serving) = Maintenance::begin_account_locked(
                &takeover,
                Arc::clone(&self.host),
                mode,
                operation_id,
                &source,
                register,
                health.as_ref(),
                &original_identity,
                match &operation {
                    AccountControl::Register { user, addr, .. }
                    | AccountControl::LoginStep { user, addr, .. }
                    | AccountControl::Login { user, addr, .. } => {
                        Some((user.as_str(), addr.as_str()))
                    }
                    _ => None,
                },
            )?;
            (maintenance, original_identity, Some(was_serving))
        };
        let restore_owner =
            restore_owner.or_else(|| original_source.is_none().then_some(health.is_some()));
        maintenance.check_account_runtime()?;
        maintenance.drain_observed_runtime(health.as_ref())?;
        let unknown = || AccountOutcomeUnknown {
            operation_id: operation_id.to_owned(),
            source_profile: source.clone(),
            register,
        };
        let sent = maintenance.account_operation_sent()?;
        let mut envelope = if !sent {
            anyhow::ensure!(
                selected.canonicalize()? == source,
                "unadmitted original operation selection changed"
            );
            require_unsent_admission(&operation, &crate::identity(&source)?, &original_identity)?;
            // Same write-ahead rule as the existing key coordinator. Once this
            // bit is durable, uncertainty only permits querying the original id.
            maintenance.mark_account_operation_sent()?;
            exchange_account(
                &takeover,
                &mut maintenance,
                &*self.host,
                operation_id,
                &source,
                register,
                operation,
                None,
            )?
        } else if let (Some(_), AccountControl::LoginStep { addr, user, .. }) =
            (original_source, &operation)
        {
            let queried = exchange_account(
                &takeover,
                &mut maintenance,
                &*self.host,
                operation_id,
                &source,
                register,
                AccountControl::Result,
                None,
            )?;
            let receipt: HostAuthAccountResult = serde_json::from_value(queried.summary.clone())
                .map_err(|_| {
                    anyhow::anyhow!("invalid login continuation receipt shape").context(unknown())
                })?;
            if receipt.outcome == HostAuthAccountOutcome::AwaitingInput {
                let status = receipt
                    .login
                    .as_ref()
                    .context("login continuation status is missing")?;
                anyhow::ensure!(
                    status.user == *user
                        && status.addr.trim_end_matches('/') == addr.trim().trim_end_matches('/'),
                    "queried login user or server differs from the original operation"
                );
                anyhow::ensure!(
                    selected.canonicalize()? == source
                        && crate::identity(&source)? == original_identity,
                    "login continuation changed its original source identity"
                );
                exchange_account(
                    &takeover,
                    &mut maintenance,
                    &*self.host,
                    operation_id,
                    &source,
                    register,
                    operation,
                    None,
                )?
            } else {
                queried
            }
        } else {
            let operation = if original_source.is_some()
                && matches!(&operation, AccountControl::Register { .. })
            {
                AccountControl::Result
            } else {
                operation
            };
            exchange_account(
                &takeover,
                &mut maintenance,
                &*self.host,
                operation_id,
                &source,
                register,
                operation,
                None,
            )?
        };
        let mut receipt: HostAuthAccountResult =
            serde_json::from_value(envelope.summary.clone())
                .map_err(|_| anyhow::anyhow!("invalid account receipt shape").context(unknown()))?;
        if matches!(
            receipt.outcome,
            HostAuthAccountOutcome::AwaitingVerification | HostAuthAccountOutcome::Committed
        ) {
            maintenance
                .start_account_target(&source, operation_id, &receipt, register)
                .map_err(|error| error.context(unknown()))?;
            if receipt.outcome == HostAuthAccountOutcome::AwaitingVerification {
                envelope = exchange_account(
                    &takeover,
                    &mut maintenance,
                    &*self.host,
                    operation_id,
                    &source,
                    register,
                    AccountControl::Complete,
                    Some(&receipt),
                )?;
                receipt = serde_json::from_value(envelope.summary.clone()).map_err(|_| {
                    anyhow::anyhow!("invalid account completion receipt shape").context(unknown())
                })?;
            }
        }
        match receipt.outcome {
            HostAuthAccountOutcome::AwaitingInput => {
                if let (Some(slot), Some(was_serving)) = (continuation, restore_owner) {
                    *slot = Some(AccountContinuation {
                        operation_id: operation_id.to_owned(),
                        source,
                        original_identity,
                        was_serving,
                        maintenance,
                    });
                }
                Ok(envelope)
            }
            HostAuthAccountOutcome::Committed => {
                maintenance
                    .verify_account_target(&source, operation_id, &receipt, register)
                    .map_err(|error| error.context(unknown()))?;
                maintenance.finish().map_err(|error| {
                    error.context(AccountHandoffPending {
                        operation_id: operation_id.to_owned(),
                        source_profile: source.clone(),
                        register,
                    })
                })?;
                self.host
                    .finish_account_handoff(&receipt)
                    .map_err(|error| {
                        error.context(AccountHandoffPending {
                            operation_id: operation_id.to_owned(),
                            source_profile: source.clone(),
                            register,
                        })
                    })?;
                crate::maintenance::finish_account_routing(
                    maintenance.installation_root(),
                    operation_id,
                )
                .map_err(|error| {
                    error.context(AccountHandoffPending {
                        operation_id: operation_id.to_owned(),
                        source_profile: source.clone(),
                        register,
                    })
                })?;
                Ok(envelope)
            }
            HostAuthAccountOutcome::RolledBack => {
                if let Some(was_serving) = restore_owner {
                    maintenance.finish_rollback(&source, &original_identity, was_serving)?;
                    self.host
                        .finish_key_handoff(&source, &original_identity, was_serving)?;
                }
                crate::maintenance::finish_account_routing(
                    maintenance.installation_root(),
                    operation_id,
                )?;
                Ok(envelope)
            }
            HostAuthAccountOutcome::AwaitingVerification | HostAuthAccountOutcome::Unknown => {
                Err(unknown().into())
            }
        }
    }
}

fn exchange_account(
    takeover: &LibraryLock,
    maintenance: &mut Maintenance,
    host: &dyn HostLifecycle,
    operation_id: &str,
    source: &Path,
    register: bool,
    operation: AccountControl,
    completion: Option<&HostAuthAccountResult>,
) -> Result<ResultEnvelope> {
    anyhow::ensure!(
        matches!(&operation, AccountControl::Complete) == completion.is_some(),
        "account completion requires its original receipt and dedicated grant"
    );
    let image = host.verified_runtime()?;
    let (root, profile) = respire_client_host::config::control_roots()?;
    let root = root.canonicalize()?;
    let profile = profile.canonicalize()?;
    anyhow::ensure!(
        takeover.protects(&root.join("runtime/takeover"))?,
        "auth control requires this installation's takeover ownership"
    );
    let maintenance_binding = if let Some(receipt) = completion {
        maintenance.account_complete_launch_binding(source, operation_id, receipt, register)?
    } else {
        maintenance.auth_launch_binding(&profile)?
    }
    .context("account control requires persistent maintenance")?;
    let expected = crate::identity(&profile)?;
    let account_id = match &expected {
        HostAuthIdentity::Bound { account_id, .. } => Some(account_id.clone()),
        _ => None,
    };
    let grant = crate::launch::prepare_grant(&image, &maintenance_binding, &expected)?;
    let request = account_control::account_request(
        ControlBinding {
            installation_root: root,
            profile: profile.clone(),
            launch_id: grant.instance_id.clone(),
            expected_account_id: account_id,
        },
        expected,
        operation_id,
        operation,
    )?;
    crate::exchange::exchange_control(
        &image.image_path,
        &grant,
        &request,
        Instant::now() + Duration::from_secs(120),
        |response, pid| {
            account_control::validate_account_response(
                response, &request, &profile, pid, source, register,
            )
        },
    )
    .map_err(|error| {
        error.context(AccountOutcomeUnknown {
            operation_id: operation_id.to_owned(),
            source_profile: source.to_owned(),
            register,
        })
    })
}

fn require_unsent_admission(
    operation: &AccountControl,
    current: &HostAuthIdentity,
    original: &HostAuthIdentity,
) -> Result<()> {
    anyhow::ensure!(
        matches!(
            operation,
            AccountControl::Register { .. } | AccountControl::LoginStep { .. }
        ) && current == original,
        "unadmitted original operation needs matching explicit authentication input"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unsent_original_query_or_rollback_cannot_admit_authentication() {
        let identity = HostAuthIdentity::Absent;
        assert!(require_unsent_admission(&AccountControl::Result, &identity, &identity).is_err());
        assert!(require_unsent_admission(&AccountControl::Rollback, &identity, &identity).is_err());
        let login = AccountControl::LoginStep {
            addr: "http://127.0.0.1:1".into(),
            user: "synthetic".into(),
            authorization: HostAuthAuthorization::Password {
                password: "synthetic-only".into(),
                totp: None,
            },
            super_password: None,
            input: HostAuthLoginContinuation::default(),
        };
        assert!(require_unsent_admission(&login, &identity, &identity).is_ok());
        assert!(require_unsent_admission(
            &login,
            &HostAuthIdentity::Bound {
                account_id: "other".into(),
                session_sha256: "00".repeat(32)
            },
            &identity
        )
        .is_err());
    }
}
