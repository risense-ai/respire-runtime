//! Fixed key control. Passwords and issued codes never enter recovery metadata.
//! Extracted from CLI 25ef33a23c87b0c00f1430c23d2c5b6c629ec13d.
//! Host ownership is shared; key execution remains in the private Runtime helper.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::maintenance::{HostLifecycle, Maintenance, RecoveryMode, RegistrationMode};
use crate::VerifiedRuntime;
use anyhow::{Context, Result};
use respire_client_host::lock::LibraryLock;
use respire_commands::output::{Item, ResultEnvelope, Status};
use respire_protocol::key_control::*;
use respire_protocol::{ControlBinding, HostAuthIdentity, RpcRequest, RpcResponse};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Original {
    schema_version: u32,
    root: PathBuf,
    profile: PathBuf,
    operation_id: String,
    key: String,
    source_identity: HostAuthIdentity,
    operation: HostKeyOperation,
    token: String,
    coordinator: String,
    was_serving: bool,
    store_ready: bool,
    sent: bool,
}

pub struct KeyRecoveryRequired {
    pub operation_id: String,
    pub source_profile: PathBuf,
}
impl std::fmt::Display for KeyRecoveryRequired {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "key_outcome_unknown operation_id={}; query this original operation; do not repeat the key operation", self.operation_id)
    }
}
impl std::fmt::Debug for KeyRecoveryRequired {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, out)
    }
}
impl std::error::Error for KeyRecoveryRequired {}

impl Original {
    fn recovery(&self) -> KeyRecoveryRequired {
        KeyRecoveryRequired {
            operation_id: self.operation_id.clone(),
            source_profile: self.profile.clone(),
        }
    }
    fn fingerprint(&self) -> Result<String> {
        Ok(crate::launch::hash(&serde_json::to_vec(
            &json!({"schema_version":HOST_KEY_SCHEMA_V,
            "method":"control.key", "root":self.root,"profile":self.profile,
            "source_identity":self.source_identity,"operation":self.operation}),
        )?))
    }
}

enum Action<'a> {
    Reset {
        operation: HostKeyOperation,
        input: HostKeyInput,
        resume: Option<&'a HostKeyResult>,
    },
    Query(&'a str),
    Rollback(&'a str),
}

/// Trusted host facade. Secret inputs are never journaled or passed in argv/env.
pub struct KeyCoordinator {
    host: Arc<dyn HostLifecycle>,
}

impl KeyCoordinator {
    pub fn new(host: Arc<dyn HostLifecycle>) -> Self {
        Self { host }
    }

    pub fn super_reset(&self, super_password: Option<&str>) -> Result<ResultEnvelope> {
        self.super_reset_step(
            None,
            HostKeyInput {
                password: None,
                super_password: super_password.map(str::to_owned),
                ..HostKeyInput::default()
            },
            None,
        )
    }

    pub fn super_reset_step(
        &self,
        addr: Option<&str>,
        input: HostKeyInput,
        resume: Option<&HostKeyResult>,
    ) -> Result<ResultEnvelope> {
        control_key(
            Arc::clone(&self.host),
            Action::Reset {
                operation: HostKeyOperation::SuperReset {
                    addr: addr.map(str::to_owned),
                },
                input,
                resume,
            },
        )
    }

    /// Query only the original operation. This never admits an unsent operation.
    pub fn result(&self, operation_id: &str) -> Result<ResultEnvelope> {
        control_key(Arc::clone(&self.host), Action::Query(operation_id))
    }

    pub fn rollback(&self, operation_id: &str) -> Result<ResultEnvelope> {
        control_key(Arc::clone(&self.host), Action::Rollback(operation_id))
    }

    pub fn fivekeys(
        &self,
        operation: HostKeyOperation,
        input: HostKeyInput,
        resume: Option<&HostKeyResult>,
    ) -> Result<ResultEnvelope> {
        anyhow::ensure!(
            matches!(operation, HostKeyOperation::Fivekeys { .. }),
            "not a fivekeys intent"
        );
        control_key(
            Arc::clone(&self.host),
            Action::Reset {
                operation,
                input,
                resume,
            },
        )
    }
}

fn execute_method(operation: &HostKeyOperation) -> &'static str {
    match operation {
        HostKeyOperation::SuperReset { .. } => HOST_KEY_SUPER_RESET_METHOD,
        HostKeyOperation::Fivekeys { .. } => HOST_KEY_FIVEKEYS_METHOD,
    }
}

fn canonical(value: &str) -> bool {
    uuid::Uuid::parse_str(value)
        .is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == value)
}

fn read_original(path: &Path) -> Result<Option<(Original, String)>> {
    for ancestor in path.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                anyhow::ensure!(
                    !metadata.file_type().is_symlink(),
                    "key recovery path is a symlink"
                );
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    anyhow::ensure!(
                        metadata.file_attributes() & 0x400 == 0,
                        "key recovery path is a reparse point"
                    );
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
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= 16 * 1024,
        "invalid key recovery file"
    );
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(16 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= 16 * 1024,
        "key recovery context exceeds its bound"
    );
    let original = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid key recovery metadata"))?;
    Ok(Some((original, crate::launch::hash(&bytes))))
}

fn control_key(host: Arc<dyn HostLifecycle>, action: Action<'_>) -> Result<ResultEnvelope> {
    host.require_account_write()?;
    anyhow::ensure!(
        crate::maintenance::current_boot_token().is_none(),
        "key control must own maintenance"
    );
    let (root, profile) = respire_client_host::config::control_roots()?;
    let takeover = crate::maintenance::takeover_lock()?;
    let image = host.verified_runtime()?;
    image.revalidate()?;
    std::fs::create_dir_all(&root)?;
    std::fs::create_dir_all(&profile)?;
    let root = root.canonicalize()?;
    let profile = profile.canonicalize()?;
    let path = root.join("runtime/autostart/key-control.json");
    let active = read_original(&path)?;
    let (saved, archived) = if active.is_some() {
        (active, false)
    } else {
        match &action {
            Action::Query(id) | Action::Rollback(id) => {
                anyhow::ensure!(
                    canonical(id),
                    "key query requires a canonical original operation ID"
                );
                (read_original(&archive_path(&root, id))?, true)
            }
            _ => (None, false),
        }
    };
    let expected = crate::identity(&profile)?;
    let owner = host.probe_runtime()?;
    anyhow::ensure!(
        owner.is_some() || !host.endpoint_path().try_exists()?,
        "key control has a recorded owner without verifiable health"
    );
    if let Some(owner) = owner.as_ref() {
        verify_owner(host.as_ref(), owner, &root, &profile, &image, &expected)?;
    }
    let (mut original, mut digest, mut maintenance, reconnect) = if let Some((original, digest)) =
        saved
    {
        anyhow::ensure!(
            original.schema_version == HOST_KEY_SCHEMA_V
                && canonical(&original.operation_id)
                && original.key == original.operation_id
                && canonical(&original.token),
            "invalid key recovery binding"
        );
        anyhow::ensure!(
            original.root == root
                && (original.profile == profile
                    || matches!(original.operation, HostKeyOperation::Fivekeys { .. })),
            "key recovery belongs to another selection"
        );
        match &action {
            Action::Reset {
                operation, resume, ..
            } => {
                anyhow::ensure!(
                    serde_json::to_value(operation)? == serde_json::to_value(&original.operation)?,
                    "key continuation changed the original operation"
                );
                if let Some(receipt) = resume {
                    validate_receipt(receipt, &original)?;
                }
            }
            Action::Query(id) | Action::Rollback(id) => anyhow::ensure!(
                *id == original.operation_id,
                "key recovery requires the original operation ID"
            ),
        }
        let maintenance = Maintenance::resume_key_locked(
            &takeover,
            Arc::clone(&host),
            &root,
            &profile,
            &original.profile,
            &original.token,
            &original.coordinator,
        )?;
        (original, digest, maintenance, true)
    } else {
        let operation = match &action {
            Action::Reset {
                operation,
                resume: None,
                ..
            } => operation.clone(),
            _ => anyhow::bail!(
                "original key recovery metadata is missing; no new operation was sent"
            ),
        };
        let mut maintenance =
            Maintenance::begin_locked(&takeover, Arc::clone(&host), RecoveryMode::Fresh)?;
        maintenance.drain_observed_runtime(owner.as_ref())?;
        maintenance
            .auth_launch_binding(&profile)?
            .context("key control requires an actual drained Paused binding")?;
        let (token, coordinator) = maintenance.key_recovery_binding()?;
        let id = uuid::Uuid::new_v4().to_string();
        let original = Original {
            schema_version: HOST_KEY_SCHEMA_V,
            root: root.clone(),
            profile: profile.clone(),
            operation_id: id.clone(),
            key: id,
            source_identity: expected,
            operation,
            token,
            coordinator,
            was_serving: owner.is_some(),
            store_ready: owner.as_ref().is_some_and(|health| health.store_ready),
            sent: false,
        };
        let bytes = serde_json::to_vec(&original)?;
        crate::maintenance::write_recovery(&path, &bytes, None)?;
        let digest = crate::launch::hash(&bytes);
        (original, digest, maintenance, false)
    };
    let mut finished = false;
    let result: Result<ResultEnvelope> = (|| {
        maintenance.check_account_runtime()?;
        maintenance.drain_observed_runtime(owner.as_ref())?;
        maintenance
            .auth_launch_binding(&profile)?
            .context("key control requires an actual drained Paused binding")?;
        let deadline = Instant::now() + Duration::from_secs(185);
        let mut receipt = if original.sent {
            exchange(
                &takeover,
                &mut maintenance,
                host.as_ref(),
                &original,
                HOST_KEY_RESULT_METHOD,
                None,
                deadline,
            )?
        } else {
            require_unsent_admission(&action, &original, &crate::identity(&profile)?)?;
            // Persist uncertainty before sending any operation; a failed write is never retried.
            original.sent = true;
            let bytes = serde_json::to_vec(&original)?;
            crate::maintenance::write_recovery(&path, &bytes, Some(&digest))?;
            digest = crate::launch::hash(&bytes);
            let input = match &action {
                Action::Reset { input, .. } => Some(input),
                _ => None,
            };
            exchange(
                &takeover,
                &mut maintenance,
                host.as_ref(),
                &original,
                execute_method(&original.operation),
                input,
                deadline,
            )?
        };
        if reconnect && receipt.outcome == HostKeyOutcome::AwaitingInput {
            match &action {
                Action::Reset {
                    input,
                    resume: Some(previous),
                    ..
                } if previous.outcome == HostKeyOutcome::AwaitingInput => {
                    receipt = exchange(
                        &takeover,
                        &mut maintenance,
                        host.as_ref(),
                        &original,
                        execute_method(&original.operation),
                        Some(input),
                        deadline,
                    )?;
                }
                Action::Rollback(_) => {
                    receipt = exchange(
                        &takeover,
                        &mut maintenance,
                        host.as_ref(),
                        &original,
                        HOST_KEY_ROLLBACK_METHOD,
                        None,
                        deadline,
                    )?;
                }
                _ => {}
            }
        } else if reconnect
            && receipt.outcome == HostKeyOutcome::Pending
            && matches!(action, Action::Rollback(_))
        {
            receipt = exchange(
                &takeover,
                &mut maintenance,
                host.as_ref(),
                &original,
                HOST_KEY_ROLLBACK_METHOD,
                None,
                deadline,
            )?;
        }
        if matches!(original.operation, HostKeyOperation::Fivekeys { .. })
            && (receipt.verification_required || receipt.outcome == HostKeyOutcome::Committed)
        {
            maintenance.start_key_target(&original.profile, &original.operation_id, &receipt)?;
            if receipt.verification_required {
                receipt = exchange_complete(
                    &takeover,
                    &mut maintenance,
                    host.as_ref(),
                    &original,
                    &receipt,
                    deadline,
                )?;
                anyhow::ensure!(
                    receipt.outcome == HostKeyOutcome::Committed && !receipt.verification_required,
                    "fivekeys completion is not committed; retain the original operation"
                );
            }
        }
        match receipt.outcome {
            HostKeyOutcome::Unknown => {
                anyhow::bail!("key_outcome_unknown: query the original operation")
            }
            HostKeyOutcome::Pending | HostKeyOutcome::AwaitingInput => {
                maintenance.pause_key()?;
                let mut output = ResultEnvelope::new(
                    "key-control",
                    Status::Pending,
                    serde_json::to_value(receipt)?,
                    Vec::new(),
                );
                output.actions.push("supply only the requested inputs using this same operation; query after uncertainty".into());
                return Ok(output);
            }
            HostKeyOutcome::Committed | HostKeyOutcome::RolledBack => {}
        }
        unchanged(host.as_ref(), &original, &receipt, &image)?;
        let restore_owner = if archived {
            owner.is_some()
        } else {
            original.was_serving
        };
        let restore_store = if archived {
            owner.as_ref().is_some_and(|health| health.store_ready)
        } else {
            original.store_ready
        };
        let fivekeys = matches!(original.operation, HostKeyOperation::Fivekeys { .. });
        if restore_owner && !(fivekeys && receipt.outcome == HostKeyOutcome::Committed) {
            maintenance.start_account_runtime()?;
            let restored = host
                .probe_runtime()?
                .context("original key owner did not resume")?;
            let (_, selected) = respire_client_host::config::control_roots()?;
            let selected = selected.canonicalize()?;
            verify_owner(
                host.as_ref(),
                &restored,
                &root,
                &selected,
                &image,
                &receipt.identity,
            )?;
            anyhow::ensure!(
                !restore_store || restored.store_ready,
                "restored key owner did not confirm its original store readiness"
            );
        }
        unchanged(host.as_ref(), &original, &receipt, &image)?;
        let (_, selected) = respire_client_host::config::control_roots()?;
        let selected = selected.canonicalize()?;
        let serving = restore_owner || (fivekeys && receipt.outcome == HostKeyOutcome::Committed);
        maintenance.finish_key(&selected, &receipt.identity, serving, restore_store)?;
        finished = true;
        host.finish_key_handoff(&selected, &receipt.identity, serving)?;
        if !archived {
            // Retain only the original nonsecret binding so an explicit O query can recover lost output.
            let archive = archive_path(&root, &original.operation_id);
            let bytes = serde_json::to_vec(&original)?;
            match read_original(&archive)? {
                Some((_, hash)) => anyhow::ensure!(
                    hash == crate::launch::hash(&bytes),
                    "key result binding archive changed"
                ),
                None => crate::maintenance::write_recovery(&archive, &bytes, None)?,
            }
            anyhow::ensure!(
                read_original(&path)?
                    .as_ref()
                    .map(|(_, hash)| hash.as_str())
                    == Some(digest.as_str()),
                "key recovery metadata changed before cleanup"
            );
            std::fs::remove_file(&path)?;
            respire_spawn::durable::sync_directory(
                path.parent().context("key recovery parent missing")?,
            )
            .map_err(|_| {
                anyhow::anyhow!(
                    "key operation completed; recovery namespace cleanup needs verification"
                )
            })?;
        }
        if receipt.outcome == HostKeyOutcome::Committed && fivekeys {
            let HostKeyOperation::Fivekeys { user, addr, .. } = &receipt.operation else {
                anyhow::bail!("fivekeys intent missing");
            };
            return Ok(ResultEnvelope::new(
                "fivekeys",
                Status::Ok,
                json!({"ok":true,"user":user,"addr":addr}),
                vec![Item::new("session", Status::Ok, "ready")],
            ));
        }
        if receipt.outcome == HostKeyOutcome::Committed {
            let issued = receipt
                .super_password
                .context("verified key receipt has no issued code")?;
            return Ok(ResultEnvelope::new(
                "super-reset",
                Status::Ok,
                json!({"ok":true,"super":issued}),
                vec![Item::new("password", Status::Ok, "issued")],
            ));
        }
        Ok(ResultEnvelope::new(
            "key-control",
            Status::Ok,
            serde_json::to_value(receipt)?,
            Vec::new(),
        ))
    })();
    result.map_err(|error| {
        let error = if finished {
            error.context(
                "key operation verified and maintenance finished; cleanup needs verification",
            )
        } else {
            let pause = maintenance.pause_key();
            error.context(format!(
                "key operation retained; Paused publication: {pause:?}"
            ))
        };
        error.context(original.recovery())
    })
}

/// A query, rollback or continuation cannot turn an unsent journal into a new
/// operation. Once the journal says sent, the only initial exchange is a query.
fn require_unsent_admission(
    action: &Action<'_>,
    original: &Original,
    identity: &HostAuthIdentity,
) -> Result<()> {
    anyhow::ensure!(
        !original.sent && matches!(action, Action::Reset { resume: None, .. }),
        "key operation was not sent; explicit queries cannot admit it"
    );
    anyhow::ensure!(
        identity == &original.source_identity,
        "key source identity changed before admission"
    );
    Ok(())
}

fn archive_path(root: &Path, operation_id: &str) -> PathBuf {
    root.join("runtime/autostart/key-results")
        .join(format!("{operation_id}.json"))
}

fn account(identity: &HostAuthIdentity, profile: &Path) -> String {
    match identity {
        HostAuthIdentity::Bound { account_id, .. } => account_id.clone(),
        _ => crate::launch::hash(profile.display().to_string().as_bytes()),
    }
}

fn target_identity_matches(receipt: &HostKeyResult) -> bool {
    let HostKeyOperation::Fivekeys { addr, user, .. } = &receipt.operation else {
        return false;
    };
    if user.is_empty() {
        addr.trim().is_empty()
            && receipt.account_id.is_none()
            && matches!(&receipt.identity, HostAuthIdentity::Unbound { operation_id, session_sha256 }
                if operation_id == &receipt.operation_id && Some(session_sha256) == receipt.session_sha256.as_ref())
    } else {
        let account = crate::launch::hash(user.as_bytes());
        receipt.account_id.as_ref() == Some(&account)
            && matches!(&receipt.identity, HostAuthIdentity::Bound { account_id, session_sha256 }
                if account_id == &account && Some(session_sha256) == receipt.session_sha256.as_ref())
    }
}

/// Key lifecycle checks do not weaken the authenticated-account receipt contract.
pub(crate) fn validate_applied_target(
    receipt: &HostKeyResult,
    operation_id: &str,
    source: &Path,
) -> Result<PathBuf> {
    anyhow::ensure!(
        canonical(operation_id)
            && receipt.operation_id == operation_id
            && receipt.source_profile == source
            && receipt.super_password.is_none()
            && receipt.required_inputs.is_empty()
            && target_identity_matches(receipt)
            && if receipt.verification_required {
                receipt.outcome == HostKeyOutcome::Pending
            } else {
                receipt.outcome == HostKeyOutcome::Committed
            },
        "fivekeys applied receipt identity mismatch"
    );
    let target = receipt
        .target_profile
        .as_ref()
        .context("fivekeys receipt target missing")?;
    let (_, selected) = respire_client_host::config::control_roots()?;
    anyhow::ensure!(
        target.is_absolute()
            && target.canonicalize()? == *target
            && selected.canonicalize()? == *target
            && crate::identity(target)? == receipt.identity,
        "fivekeys applied target changed"
    );
    Ok(target.clone())
}

fn unchanged(
    host: &dyn HostLifecycle,
    original: &Original,
    receipt: &HostKeyResult,
    image: &VerifiedRuntime,
) -> Result<()> {
    let (root, profile) = respire_client_host::config::control_roots()?;
    let current = host.verified_runtime()?;
    current.revalidate()?;
    let selected = if matches!(original.operation, HostKeyOperation::Fivekeys { .. })
        && receipt.outcome == HostKeyOutcome::Committed
    {
        receipt
            .target_profile
            .as_ref()
            .context("fivekeys target missing")?
    } else {
        &original.profile
    };
    anyhow::ensure!(
        root.canonicalize()? == original.root
            && profile.canonicalize()? == *selected
            && current.path() == image.path()
            && current.version() == image.version()
            && current.sha256().eq_ignore_ascii_case(image.sha256())
            && current.port() == image.port()
            && crate::identity(selected)? == receipt.identity,
        "key operation installation, profile, image or identity changed"
    );
    Ok(())
}

/// The former model-control owner verifier, without any asset resolver. The host
/// adapter independently verifies registration and performs the actual drain.
fn verify_owner(
    host: &dyn HostLifecycle,
    health: &respire_commands::net_rpc::Health,
    root: &Path,
    profile: &Path,
    image: &VerifiedRuntime,
    expected: &HostAuthIdentity,
) -> Result<()> {
    respire_commands::net_rpc::request_scope(health)?;
    let registration = host.inspect_registration(root)?;
    let managed_id = match &registration {
        RegistrationMode::Managed { coordinator_id } => Some(coordinator_id.as_str()),
        _ => None,
    };
    let process = respire_commands::net_rpc::runtime_process_identity(health.pid)?;
    let birth = crate::launch::process_birth(health.pid)?
        .context("key owner exited during verification")?;
    let prefix = if cfg!(windows) {
        "windows-filetime-"
    } else if cfg!(target_os = "linux") {
        "linux-starttime-"
    } else {
        "darwin-lstart-"
    };
    anyhow::ensure!(
        health.managed_id.as_deref() == managed_id
            && health.account_id == account(expected, profile)
            && Path::new(&health.installation_root).canonicalize()? == root
            && health.installation_id == crate::launch::hash(root.display().to_string().as_bytes())
            && Path::new(&health.data_dir).canonicalize()? == profile
            && Path::new(&health.exe).canonicalize()? == image.path()
            && Path::new(&health.image_path).canonicalize()? == image.path()
            && Path::new(&process.executable).canonicalize()? == image.path()
            && health.image_sha256.eq_ignore_ascii_case(image.sha256())
            && health.runtime_version == image.version()
            && health.process_start_id == format!("{prefix}{birth}")
            && (process.started_at == birth || process.started_at == health.process_start_id)
            && !health.inference_stalled(),
        "key owner differs from the installed Runtime, account, profile or registration"
    );
    anyhow::ensure!(
        respire_commands::net_rpc::runtime_process_identity(health.pid)? == process,
        "key owner changed during verification"
    );
    Ok(())
}

fn exchange(
    takeover: &LibraryLock,
    maintenance: &mut Maintenance,
    host: &dyn HostLifecycle,
    original: &Original,
    method: &str,
    input: Option<&HostKeyInput>,
    deadline: Instant,
) -> Result<HostKeyResult> {
    exchange_inner(
        takeover,
        maintenance,
        host,
        original,
        method,
        input,
        None,
        deadline,
    )
}

fn exchange_complete(
    takeover: &LibraryLock,
    maintenance: &mut Maintenance,
    host: &dyn HostLifecycle,
    original: &Original,
    receipt: &HostKeyResult,
    deadline: Instant,
) -> Result<HostKeyResult> {
    exchange_inner(
        takeover,
        maintenance,
        host,
        original,
        HOST_KEY_COMPLETE_METHOD,
        None,
        Some(receipt),
        deadline,
    )
}

fn exchange_inner(
    takeover: &LibraryLock,
    maintenance: &mut Maintenance,
    host: &dyn HostLifecycle,
    original: &Original,
    method: &str,
    input: Option<&HostKeyInput>,
    completion: Option<&HostKeyResult>,
    deadline: Instant,
) -> Result<HostKeyResult> {
    let input = input.map(|input| HostKeyInput {
        password: input.password.clone(),
        super_password: input.super_password.clone(),
        account_secret: input.account_secret.clone(),
        totp: input.totp.clone(),
    });
    host.require_account_write()?;
    let image = host.verified_runtime()?;
    let (root, profile) = respire_client_host::config::control_roots()?;
    let root = root.canonicalize()?;
    let profile = profile.canonicalize()?;
    anyhow::ensure!(
        takeover.protects(&root.join("runtime/takeover"))?,
        "key control requires this installation's takeover ownership"
    );
    let maintenance_binding = if let Some(receipt) = completion {
        validate_receipt(receipt, original)?;
        maintenance.key_complete_launch_binding(
            &original.profile,
            &original.operation_id,
            receipt,
        )?
    } else {
        maintenance.auth_launch_binding(&profile)?
    }
    .context("key control requires owned maintenance")?;
    let identity = crate::identity(&profile)?;
    let expected_account_id = match &identity {
        HostAuthIdentity::Bound { account_id, .. } => Some(account_id.clone()),
        _ => None,
    };
    let grant = crate::launch::prepare_grant(&image, &maintenance_binding, &identity)?;
    let binding = ControlBinding {
        installation_root: root,
        profile: profile.clone(),
        launch_id: grant.instance_id.clone(),
        expected_account_id,
    };
    anyhow::ensure!(
        binding.installation_root == original.root
            && (binding.profile == original.profile
                || matches!(original.operation, HostKeyOperation::Fivekeys { .. })),
        "key control launch selection changed"
    );
    let params = HostKeyParams {
        schema_version: HOST_KEY_SCHEMA_V,
        binding,
        identity,
        source_identity: original.source_identity.clone(),
        operation: original.operation.clone(),
        input,
    };
    let argument = serde_json::to_string(&params)
        .map_err(|_| anyhow::anyhow!("cannot encode private key request"))?;
    let request = RpcRequest {
        v: crate::PROTOCOL_V,
        id: uuid::Uuid::new_v4().to_string(),
        method: method.to_owned(),
        args: vec![argument],
        scope: None,
        operation_id: Some(original.operation_id.clone()),
        idempotency_key: Some(original.key.clone()),
        parent_operation_id: None,
        queue_wait_ms: None,
        lifecycle: None,
    };
    // Exactly one exchange. Uncertainty keeps the sent journal and original ID.
    let envelope = crate::exchange::exchange_control(
        &image.image_path,
        &grant,
        &request,
        deadline,
        |response, pid| validate_response(response, &request, &profile, pid, original),
    )
    .map_err(|_| anyhow::anyhow!("private key exchange failed; query the original operation"))?;
    serde_json::from_value(envelope.summary)
        .map_err(|_| anyhow::anyhow!("invalid private key receipt"))
}

fn validate_receipt(receipt: &HostKeyResult, original: &Original) -> Result<()> {
    anyhow::ensure!(
        receipt.operation_id == original.operation_id
            && receipt.fingerprint == original.fingerprint()?
            && serde_json::to_value(&receipt.operation)?
                == serde_json::to_value(&original.operation)?
            && receipt.source_profile == original.profile,
        "key receipt changed its original intent or source"
    );
    if let HostKeyOperation::Fivekeys { .. } = &original.operation {
        anyhow::ensure!(
            receipt.super_password.is_none()
                && receipt.required_inputs.iter().all(|field| matches!(
                    field.as_str(),
                    "password" | "super_password" | "account_secret" | "totp"
                )),
            "invalid fivekeys secret or requested input"
        );
        if receipt.verification_required || receipt.outcome == HostKeyOutcome::Committed {
            validate_applied_target(receipt, &original.operation_id, &original.profile)?;
        } else {
            anyhow::ensure!(
                receipt.account_id.is_none()
                    && receipt.session_sha256.is_none()
                    && receipt.identity == original.source_identity,
                "unpublished fivekeys changed its source identity"
            );
            anyhow::ensure!(
                (receipt.outcome == HostKeyOutcome::AwaitingInput)
                    == !receipt.required_inputs.is_empty(),
                "fivekeys input status mismatch"
            );
        }
        return Ok(());
    }
    anyhow::ensure!(
        !receipt.verification_required
            && receipt
                .target_profile
                .as_ref()
                .is_none_or(|path| path == &original.profile),
        "super-reset changed its profile"
    );
    let source_account = match &original.source_identity {
        HostAuthIdentity::Bound { account_id, .. } => account_id,
        _ => anyhow::bail!("super-reset requires an original bound account"),
    };
    let (account, digest) = match &receipt.identity {
        HostAuthIdentity::Bound {
            account_id,
            session_sha256,
        } => (account_id, session_sha256),
        _ => anyhow::bail!("key receipt lost its bound account"),
    };
    anyhow::ensure!(
        account == source_account,
        "key receipt changed its original account"
    );
    anyhow::ensure!(
        receipt
            .required_inputs
            .iter()
            .all(|key| matches!(key.as_str(), "password" | "super_password")),
        "unsupported key continuation inputs"
    );
    if receipt.outcome == HostKeyOutcome::Committed {
        anyhow::ensure!(
            receipt.target_profile.as_ref() == Some(&original.profile)
                && receipt.account_id.as_ref() == Some(account)
                && receipt.session_sha256.as_ref() == Some(digest)
                && receipt.required_inputs.is_empty()
                && receipt
                    .super_password
                    .as_ref()
                    .is_some_and(|code| !code.is_empty()),
            "invalid committed key receipt"
        );
    } else {
        anyhow::ensure!(
            receipt.super_password.is_none()
                && receipt.session_sha256.is_none()
                && receipt.account_id.is_none()
                && receipt.identity == original.source_identity,
            "noncommitted key receipt exposed a code or changed its source"
        );
        if receipt.outcome == HostKeyOutcome::AwaitingInput {
            anyhow::ensure!(
                !receipt.required_inputs.is_empty(),
                "missing key continuation inputs"
            );
        } else if receipt.outcome != HostKeyOutcome::RolledBack {
            anyhow::ensure!(
                receipt.required_inputs.is_empty(),
                "unexpected key input request"
            );
        }
    }
    Ok(())
}

fn validate_response(
    response: RpcResponse<ResultEnvelope>,
    request: &RpcRequest,
    profile: &Path,
    pid: u32,
    original: &Original,
) -> Result<ResultEnvelope> {
    anyhow::ensure!(
        response.v == request.v
            && response.id == request.id
            && response.pid == Some(pid)
            && response.bin == "rsrs-runtime"
            && response.scope.is_none()
            && response.web_url.is_none()
            && response.operation_id.as_deref() == Some(original.operation_id.as_str())
            && response.idempotency_key.as_deref() == Some(original.key.as_str()),
        "key response binding mismatch"
    );
    if let Some(path) = response.data_dir.as_deref() {
        anyhow::ensure!(
            Path::new(path).canonicalize()? == profile,
            "key response profile mismatch"
        );
    }
    let envelope = response.envelope.context("private key receipt missing")?;
    anyhow::ensure!(
        envelope.command == "key-control"
            && envelope.details.is_null()
            && envelope.actions.is_empty()
            && envelope.items.len() == 2
            && envelope.related.is_empty(),
        "invalid key response envelope"
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
            "key helper readiness mismatch"
        );
    }
    let receipt: HostKeyResult = serde_json::from_value(envelope.summary.clone())
        .map_err(|_| anyhow::anyhow!("invalid private key receipt shape"))?;
    validate_receipt(&receipt, original)?;
    let (_, selected) = respire_client_host::config::control_roots()?;
    anyhow::ensure!(
        crate::identity(&selected.canonicalize()?)? == receipt.identity,
        "key receipt does not match the selected session"
    );
    match receipt.outcome {
        HostKeyOutcome::Committed | HostKeyOutcome::RolledBack => anyhow::ensure!(
            response.ok
                && response.exit == 0
                && response.code.is_none()
                && response.error.is_none()
                && matches!(envelope.status, Status::Ok)
                && envelope.errors.is_empty(),
            "invalid terminal key response"
        ),
        HostKeyOutcome::Pending | HostKeyOutcome::AwaitingInput => anyhow::ensure!(
            response.ok
                && response.exit == 0
                && response.code.is_none()
                && response.error.is_none()
                && matches!(envelope.status, Status::Pending)
                && envelope.errors.is_empty(),
            "invalid pending key response"
        ),
        HostKeyOutcome::Unknown => anyhow::ensure!(
            !response.ok
                && response.exit == 2
                && response.code.as_deref() == Some("key_outcome_unknown")
                && matches!(envelope.status, Status::Fail),
            "invalid unknown key response"
        ),
    }
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn original() -> Original {
        Original {
            schema_version: HOST_KEY_SCHEMA_V,
            root: PathBuf::from("/synthetic/root"),
            profile: PathBuf::from("/synthetic/profile"),
            operation_id: "20000000-0000-4000-8000-000000000001".into(),
            key: "20000000-0000-4000-8000-000000000001".into(),
            source_identity: HostAuthIdentity::Bound {
                account_id: "synthetic-account".into(),
                session_sha256: "synthetic-session".into(),
            },
            operation: HostKeyOperation::SuperReset {
                addr: Some("https://synthetic.invalid".into()),
            },
            token: "20000000-0000-4000-8000-000000000002".into(),
            coordinator: "synthetic-coordinator".into(),
            was_serving: false,
            store_ready: false,
            sent: false,
        }
    }

    fn receipt(original: &Original, outcome: HostKeyOutcome) -> Result<HostKeyResult> {
        Ok(HostKeyResult {
            operation_id: original.operation_id.clone(),
            fingerprint: original.fingerprint()?,
            operation: original.operation.clone(),
            outcome,
            source_profile: original.profile.clone(),
            target_profile: None,
            account_id: None,
            session_sha256: None,
            identity: original.source_identity.clone(),
            required_inputs: Vec::new(),
            verification_required: false,
            super_password: None,
        })
    }

    #[test]
    fn unsent_query_rollback_or_continuation_never_admits_effect() -> Result<()> {
        let mut original = original();
        let previous = receipt(&original, HostKeyOutcome::AwaitingInput)?;
        let fresh = Action::Reset {
            operation: original.operation.clone(),
            input: HostKeyInput::default(),
            resume: None,
        };
        assert!(require_unsent_admission(&fresh, &original, &original.source_identity).is_ok());
        for action in [
            Action::Query(&original.operation_id),
            Action::Rollback(&original.operation_id),
            Action::Reset {
                operation: original.operation.clone(),
                input: HostKeyInput::default(),
                resume: Some(&previous),
            },
        ] {
            assert!(
                require_unsent_admission(&action, &original, &original.source_identity).is_err()
            );
        }
        assert!(require_unsent_admission(&fresh, &original, &HostAuthIdentity::Absent).is_err());
        original.sent = true;
        assert!(require_unsent_admission(&fresh, &original, &original.source_identity).is_err());
        Ok(())
    }

    #[test]
    fn journal_contains_only_original_binding_and_rejects_secret_fields() -> Result<()> {
        let original = original();
        let mut value = serde_json::to_value(&original)?;
        let fields = value
            .as_object()
            .context("synthetic journal is not an object")?;
        for forbidden in [
            "input",
            "password",
            "super_password",
            "account_secret",
            "totp",
        ] {
            assert!(!fields.contains_key(forbidden));
        }
        value["super_password"] = json!("synthetic-issued-code");
        assert!(serde_json::from_value::<Original>(value).is_err());
        assert!(canonical(&original.operation_id));
        assert!(!canonical("20000000-0000-1000-8000-000000000001"));
        assert!(!canonical("not-an-operation"));
        Ok(())
    }

    #[test]
    fn receipt_requires_original_operation_source_and_fingerprint() -> Result<()> {
        let original = original();
        let mut result = receipt(&original, HostKeyOutcome::Pending)?;
        validate_receipt(&result, &original)?;
        result.fingerprint = "foreign".into();
        assert!(validate_receipt(&result, &original).is_err());
        result.fingerprint = original.fingerprint()?;
        result.operation_id = "20000000-0000-4000-8000-000000000003".into();
        assert!(validate_receipt(&result, &original).is_err());
        result.operation_id = original.operation_id.clone();
        result.source_profile = PathBuf::from("/synthetic/foreign");
        assert!(validate_receipt(&result, &original).is_err());
        Ok(())
    }

    #[test]
    fn issued_code_is_only_valid_for_exact_committed_super_reset() -> Result<()> {
        let original = original();
        let mut result = receipt(&original, HostKeyOutcome::Pending)?;
        result.super_password = Some("synthetic-issued-code".into());
        assert!(validate_receipt(&result, &original).is_err());
        result.outcome = HostKeyOutcome::Committed;
        assert!(validate_receipt(&result, &original).is_err());
        result.target_profile = Some(original.profile.clone());
        result.account_id = Some("synthetic-account".into());
        result.session_sha256 = Some("synthetic-session".into());
        validate_receipt(&result, &original)?;
        result.required_inputs.push("password".into());
        assert!(validate_receipt(&result, &original).is_err());
        result.required_inputs.clear();
        result.super_password = Some(String::new());
        assert!(validate_receipt(&result, &original).is_err());
        Ok(())
    }

    #[test]
    fn awaiting_input_cannot_change_the_original_bound_identity() -> Result<()> {
        let original = original();
        let mut result = receipt(&original, HostKeyOutcome::AwaitingInput)?;
        assert!(validate_receipt(&result, &original).is_err());
        result.required_inputs.push("super_password".into());
        validate_receipt(&result, &original)?;
        result.identity = HostAuthIdentity::Absent;
        assert!(validate_receipt(&result, &original).is_err());
        Ok(())
    }

    #[test]
    fn offline_fivekeys_identity_requires_its_original_operation_and_digest() -> Result<()> {
        let mut original = original();
        original.operation = HostKeyOperation::Fivekeys {
            addr: String::new(),
            user: String::new(),
            kdf_salt: "salt".into(),
            wrapped_urk: "wrap".into(),
            urk_nonce: "nonce".into(),
            use_super: true,
        };
        let mut result = receipt(&original, HostKeyOutcome::Pending)?;
        result.verification_required = true;
        result.session_sha256 = Some("a".repeat(64));
        result.identity = HostAuthIdentity::Unbound {
            operation_id: original.operation_id.clone(),
            session_sha256: "a".repeat(64),
        };
        assert!(target_identity_matches(&result));
        result.account_id = Some(crate::launch::hash(b""));
        assert!(!target_identity_matches(&result));
        result.account_id = None;
        result.identity = HostAuthIdentity::Absent;
        assert!(!target_identity_matches(&result));
        result.identity = HostAuthIdentity::Unbound {
            operation_id: "foreign".into(),
            session_sha256: "a".repeat(64),
        };
        assert!(!target_identity_matches(&result));
        result.identity = HostAuthIdentity::Unbound {
            operation_id: original.operation_id.clone(),
            session_sha256: "b".repeat(64),
        };
        assert!(!target_identity_matches(&result));
        result.identity = HostAuthIdentity::Unbound {
            operation_id: original.operation_id,
            session_sha256: "a".repeat(64),
        };
        if let HostKeyOperation::Fivekeys { addr, .. } = &mut result.operation {
            *addr = "https://never-contact.invalid".into();
        }
        assert!(!target_identity_matches(&result));
        Ok(())
    }
}
