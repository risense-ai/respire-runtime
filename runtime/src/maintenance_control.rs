//! Fixed snapshot dispatch for the inherited maintenance channel, never HTTP.
//!
//! The parent retains installation takeover ownership across stop, helper exit,
//! restart, verification and compensation. Its authorization callback MUST check
//! the consumed maintenance grant, operation/fingerprint, controller birth and
//! current phase. The read-only `verify_control_binding` is not sufficient.
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use respire_app::{lock::LibraryLock, snapshot, SessionKeys};
use respire_protocol::maintenance_control::{
    MaintenanceAction as Action, MaintenanceControlParams as Params,
    MaintenanceControlResult as Output, MaintenanceState as State, MAINTENANCE_CONTROL_SCHEMA_V,
};
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub(crate) struct OutcomeUnknown;

impl std::fmt::Display for OutcomeUnknown {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("snapshot outcome unknown; query before replay or compensation")
    }
}

impl std::error::Error for OutcomeUnknown {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Access {
    Offline,
    // Authorize an explicit initial restore under the consumed maintenance
    // grant. Snapshot journal history enforces O/fingerprint reuse locally.
    StartRestore,
    // The parent must fence the restarted runtime's complete identity. This
    // authorizes journal finalization only, never offline DB replacement.
    Finalize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RestoreDispatch {
    // Explicit initial dispatch, never inferred from an unknown result query.
    // The journal checks both current and historical IDs before a new restore.
    FirstAttempt,
    Resume,
}

/// SHA-256 of this exact JSON tuple; launch/request IDs and action are excluded
/// so a new helper can query/finalize the same original restore operation.
pub(crate) fn fingerprint(params: &Params) -> Result<String> {
    let bytes = serde_json::to_vec(&(
        "snapshot-restore-v1",
        &params.binding.installation_root,
        &params.binding.profile,
        &params.binding.expected_account_id,
        params.sync_generation,
        &params.snapshot_id,
    ))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn validate(params: &Params, account: &str) -> Result<(PathBuf, snapshot::SnapshotOperation)> {
    anyhow::ensure!(
        params.schema_version == MAINTENANCE_CONTROL_SCHEMA_V
            && uuid::Uuid::parse_str(&params.operation_id)
                .is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == params.operation_id)
            && params.snapshot_id.len() == 32
            && params
                .snapshot_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "invalid snapshot maintenance request"
    );
    anyhow::ensure!(
        fingerprint(params)? == params.request_fingerprint,
        snapshot::OperationConflict
    );
    let root = respire_app::service::data_dir().canonicalize()?;
    anyhow::ensure!(
        root == params.binding.profile
            && !account.is_empty()
            && params.binding.expected_account_id.as_deref()
                == Some(format!("{:x}", Sha256::digest(account.as_bytes())).as_str())
            && respire_app::service::session_user_of_dir(&root) == account,
        "snapshot maintenance profile or account differs from control binding"
    );
    Ok((
        root,
        snapshot::SnapshotOperation {
            operation_id: params.operation_id.clone(),
            request_fingerprint: params.request_fingerprint.clone(),
        },
    ))
}

fn output(params: &Params, status: Option<snapshot::RestoreStatus>) -> Result<Output> {
    let mut result = Output {
        operation_id: params.operation_id.clone(),
        request_fingerprint: params.request_fingerprint.clone(),
        snapshot_id: params.snapshot_id.clone(),
        state: State::Unknown,
        before_restore: None,
        sync_quarantined: None,
        cleanup_pending: false,
        cleanup_warning: None,
    };
    if let Some(status) = status {
        anyhow::ensure!(
            status.receipt.restored == params.snapshot_id,
            snapshot::OperationConflict
        );
        result.state = match status.phase.as_str() {
            "prepared" => State::Prepared,
            "installed" => State::Installed,
            "verified" => State::Verified,
            "released" => State::Released,
            "rolled_back" => State::RolledBack,
            _ => anyhow::bail!("unsupported snapshot recovery journal"),
        };
        result.before_restore = Some(status.receipt.before_restore);
        if result.state != State::RolledBack {
            result.sync_quarantined = Some(status.receipt.sync_quarantined);
        }
        result.cleanup_pending = status.cleanup_pending;
    }
    Ok(result)
}

/// All offline actions require proven occupant/descendant exit. A failed health
/// probe or an available library lock is not a substitute for that proof.
pub(crate) fn execute_offline(
    params: &Params,
    account: &str,
    keys: Option<&SessionKeys>,
    dispatch: RestoreDispatch,
    authorize: impl Fn(&Params, Access) -> Result<()>,
) -> Result<Output> {
    anyhow::ensure!(
        !matches!(params.action, Action::Commit | Action::Release),
        "snapshot finalization requires verified-runtime dispatch"
    );
    authorize(params, Access::Offline)?;
    let (root, operation) = validate(params, account)?;
    let ownership = LibraryLock::acquire(&root, Duration::from_secs(15))?;
    authorize(params, Access::Offline)?;
    let status = snapshot::operation_status(&root, account, &operation)?;
    let mut result = output(params, status.clone())?;
    match params.action {
        Action::Restore => {
            if status.is_none() && dispatch == RestoreDispatch::FirstAttempt {
                authorize(params, Access::StartRestore)?;
                respire_app::service::ensure_writable()?;
                anyhow::ensure!(
                    !respire_app::service::off_mode(),
                    "snapshot restore is unavailable while memory is paused"
                );
            }
            result = output(
                params,
                snapshot::restore_operation_locked(
                    &root,
                    account,
                    keys,
                    &params.snapshot_id,
                    &operation,
                    &ownership,
                    dispatch == RestoreDispatch::FirstAttempt,
                )
                .context(OutcomeUnknown)?,
            )?;
        }
        Action::Rollback | Action::Recover => {
            if let Some(status) = status {
                respire_app::service::ensure_writable()?;
                let cleanup_only = matches!(
                    status.phase.as_str(),
                    "verified" | "released" | "rolled_back"
                );
                let changed = match (params.action, status.phase.as_str()) {
                    (Action::Rollback, "prepared" | "installed") => {
                        snapshot::rollback_locked(&root, &status.receipt, &ownership)
                    }
                    (Action::Rollback, "rolled_back") if !status.cleanup_pending => Ok(()),
                    (Action::Recover, "released" | "rolled_back") if !status.cleanup_pending => {
                        Ok(())
                    }
                    (Action::Rollback, "verified" | "released") => {
                        anyhow::bail!(
                            "snapshot restore is committed; rollback would discard accepted writes"
                        );
                    }
                    _ => snapshot::recover_locked(&root, account, &ownership),
                };
                match changed {
                    Ok(()) => {
                        result = output(
                            params,
                            snapshot::operation_status(&root, account, &operation)
                                .context(OutcomeUnknown)?,
                        )?
                    }
                    Err(error) if cleanup_only => {
                        result.cleanup_pending = true;
                        result.cleanup_warning = Some(format!(
                            "snapshot transaction completed; local cleanup pending: {error:#}"
                        ));
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        Action::Query => {}
        Action::Commit | Action::Release => {
            unreachable!("finalization rejected before authorization")
        }
    }
    authorize(params, Access::Offline).context(OutcomeUnknown)?;
    Ok(result)
}

/// Called after the restarted runtime opens the staged store. The parent keeps
/// takeover ownership; the serving runtime keeps the library lock. No helper
/// may acquire that lock or replace DB files in this path.
pub(crate) fn execute_verified(
    params: &Params,
    account: &str,
    authorize: impl Fn(&Params, Access) -> Result<()>,
    verify_snapshot_store: impl Fn(&respire_protocol::ControlBinding, &str) -> Result<()>,
) -> Result<Output> {
    anyhow::ensure!(
        matches!(
            params.action,
            Action::Query | Action::Commit | Action::Release
        ),
        "offline mutation is forbidden during verified-runtime dispatch"
    );
    authorize(params, Access::Finalize)?;
    let (root, operation) = validate(params, account)?;
    let status = snapshot::operation_status(&root, account, &operation)?;
    let mut result = output(params, status.clone())?;
    if let Some(status) = status {
        if params.action == Action::Commit && status.phase == "installed" {
            verify_snapshot_store(&params.binding, &status.receipt.restored)?;
            authorize(params, Access::Finalize)?;
            snapshot::commit_restore(&root, &status.receipt).context(OutcomeUnknown)?;
            result.state = State::Verified;
            result.cleanup_pending = true;
        }
        if matches!(params.action, Action::Commit | Action::Release) {
            anyhow::ensure!(
                matches!(result.state, State::Verified | State::Released),
                "snapshot finalization requires a verified restore"
            );
            authorize(params, Access::Finalize).context(OutcomeUnknown)?;
            // Once commit is durable, cleanup failure is a warning, never an
            // error that could enter the host's original-state rollback branch.
            let release = if result.state == State::Released && !result.cleanup_pending {
                Ok(())
            } else {
                snapshot::release_restore(&root, &status.receipt)
            };
            match release {
                Ok(()) => {
                    result.state = State::Released;
                    result.cleanup_pending = false;
                }
                Err(error) => {
                    result.cleanup_pending = true;
                    result.cleanup_warning = Some(format!(
                        "restored runtime verified; local rollback cleanup pending: {error:#}"
                    ));
                }
            }
        }
    }
    authorize(params, Access::Finalize).context(OutcomeUnknown)?;
    Ok(result)
}
