//! One-shot launch grants. Public instance IDs cannot replay consumed grants.
use anyhow::{Context, Result};
use respire_protocol::HostControlLaunchGrant as LaunchGrant;
#[cfg(test)]
use respire_protocol::HostControlMaintenanceBinding as MaintenanceBinding;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

static STARTUP: OnceLock<Startup> = OnceLock::new();

#[derive(Clone, Debug, PartialEq, Eq)]
struct LaunchContext {
    root: PathBuf,
    profile: PathBuf,
    account_id: String,
    sync_generation: usize,
    image_path: PathBuf,
    image_sha256: String,
    port: u16,
}

struct Startup {
    context: LaunchContext,
    grant: Option<LaunchGrant>,
    auth_control: bool,
    paused_control: bool,
}

pub(crate) fn authorize(supervised: bool, boot_token: Option<&str>, port: u16) -> Result<()> {
    anyhow::ensure!(!respire_app::login_transaction::auth_recovery_pending()?,
        "interrupted auth control must be recovered before serving");
    anyhow::ensure!(
        STARTUP.get().is_none(),
        "runtime startup was authorized twice"
    );
    fs::create_dir_all(respire_app::service::main_data_dir())?;
    fs::create_dir_all(respire_app::service::data_dir())?;
    let context = current_context(port)?;
    let (grant, instance_id) = if let Some(token) = boot_token {
        let nonce = token
            .strip_prefix("launch-v1:")
            .context("unsupported runtime launch token")?;
        validate_nonce(nonce)?;
        let directory = context
            .root
            .join("runtime")
            .join("autostart")
            .join("launch");
        let path = directory.join(format!("launch-{nonce}.json"));
        let bytes =
            read_private_file(&path)?.context("runtime launch grant is missing or consumed")?;
        let grant: LaunchGrant = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid runtime launch grant JSON"))?;
        validate_grant(&grant, &context, supervised, nonce, now_ms()?)?;
        verify_authority(Some(&grant), &context)?;
        claim(&directory, nonce, &bytes)?;
        fs::remove_file(&path).context("consumed runtime launch grant could not be removed")?;
        sync_directory(&directory)?;
        let instance_id = grant.instance_id.clone();
        (Some(grant), instance_id)
    } else {
        anyhow::ensure!(
            !supervised,
            "supervised startup requires a one-time host launch grant"
        );
        verify_authority(None, &context)?;
        (None, uuid::Uuid::new_v4().to_string())
    };
    respire_commands::rpc_serve::set_launch_instance_id(&instance_id)?;
    STARTUP
        .set(Startup { context, grant, auth_control: false, paused_control: false })
        .map_err(|_| anyhow::anyhow!("runtime startup identity was installed twice"))?;
    Ok(())
}

pub(crate) fn managed_id() -> Option<&'static str> {
    STARTUP.get()?.grant.as_ref()?.managed_id.as_deref()
}

/// An owned inherited channel is the capability, not the serialized identity.
/// Do not consume a serving grant file or create runtime state for a read probe.
pub(crate) fn authorize_control(grant: LaunchGrant) -> Result<()> {
    authorize_control_inner(grant, false, false)
}

/// A fixed read may inspect an absent profile, but cannot create or serve it.
pub(crate) fn authorize_offline_read(grant: LaunchGrant,
    kind: respire_protocol::metadata_control::HostOfflineRead) -> Result<()> {
    anyhow::ensure!(STARTUP.get().is_none(), "offline read grant was already consumed");
    respire_commands::runtime_policy::require_host("offline configuration read")?;
    respire_spawn::verify_control_parent(grant.supervisor_pid)?;
    respire_app::service::validate_client_config()?;
    if kind != respire_protocol::metadata_control::HostOfflineRead::SnapshotPreflight {
        anyhow::ensure!(!respire_app::login_transaction::auth_recovery_pending()?,
            "finish authentication recovery before an offline configuration read");
    }
    let context = offline_read_context(grant.port, kind)?;
    validate_grant(&grant, &context, grant.managed_id.is_some(), &grant.nonce, now_ms()?)?;
    verify_offline_read_authority(&grant, &context, kind)?;
    STARTUP.set(Startup { context, grant: Some(grant), auth_control: false, paused_control: false })
        .map_err(|_| anyhow::anyhow!("offline read grant was already consumed"))?;
    Ok(())
}

pub(crate) fn verify_offline_read_binding(binding: &respire_protocol::ControlBinding,
    kind: respire_protocol::metadata_control::HostOfflineRead) -> Result<()> {
    let startup = STARTUP.get().context("offline read grant is missing")?;
    let grant = startup.grant.as_ref().context("offline read grant is missing")?;
    respire_spawn::verify_control_parent(grant.supervisor_pid)?;
    let current = offline_read_context(startup.context.port, kind)?;
    anyhow::ensure!(current == startup.context, "offline read selection or installation changed");
    let account = if kind == respire_protocol::metadata_control::HostOfflineRead::SnapshotPreflight { None }
        else { respire_protocol::metadata_control::offline_read_user(&current.profile)?
            .map(|user| hash(user.as_bytes())) };
    validate_control_binding(binding, &current, grant, account.as_deref())?;
    if kind != respire_protocol::metadata_control::HostOfflineRead::SnapshotPreflight {
        anyhow::ensure!(!respire_app::login_transaction::auth_recovery_pending()?,
            "authentication recovery interrupted the offline read");
    }
    verify_offline_read_authority(grant, &current, kind)
}

fn offline_read_context(port: u16, kind: respire_protocol::metadata_control::HostOfflineRead) -> Result<LaunchContext> {
    use respire_protocol::metadata_control::metadata_status_path;
    let root = metadata_status_path(&respire_app::service::main_data_dir())?;
    let profile = metadata_status_path(&respire_app::service::data_dir())?;
    let account_id = if kind == respire_protocol::metadata_control::HostOfflineRead::SnapshotPreflight { None }
        else { respire_protocol::metadata_control::offline_read_user(&profile)?
            .map(|user| hash(user.as_bytes())) }
        .unwrap_or_else(|| hash(profile.display().to_string().as_bytes()));
    let image_path = std::env::current_exe()?.canonicalize()?;
    Ok(LaunchContext { root, profile, account_id,
        sync_generation: respire_commands::rpc_worker::sync_generation(),
        image_sha256: hash_file(&image_path)?, image_path, port })
}

pub(crate) fn authorize_auth_control(grant: LaunchGrant) -> Result<()> {
    anyhow::ensure!(grant.maintenance.is_some(), "auth control requires a paused maintenance owner");
    authorize_control_inner(grant, true, true)
}

/// This fixed read reports only journal state and cannot claim a maintenance owner.
pub(crate) fn verify_login_recovery_status(
    grant: &LaunchGrant,
    params: &respire_protocol::host_control::HostLoginRecoveryParams,
) -> Result<()> {
    anyhow::ensure!(STARTUP.get().is_none() && grant.maintenance.is_none(),
        "recovery status cannot inherit a serving or maintenance authorization");
    respire_commands::runtime_policy::require_host("login recovery status")?;
    respire_spawn::verify_control_parent(grant.supervisor_pid)?;
    respire_app::service::validate_client_config()?;
    let context = current_context(grant.port)?;
    validate_grant(grant, &context, grant.managed_id.is_some(), &grant.nonce, now_ms()?)?;
    let registration = read_private_file(&context.root.join("runtime/autostart/registration.json"))?;
    anyhow::ensure!(grant.registration_sha256 == registration.as_deref().map(hash)
        && process_birth(grant.supervisor_pid)?.as_deref() == Some(grant.supervisor_birth.as_str()),
        "recovery status registration or parent changed");
    let account = match &params.identity {
        respire_protocol::HostAuthIdentity::Bound { account_id, .. } => Some(account_id.as_str()),
        _ => None,
    };
    validate_control_binding(&params.binding, &context, grant, account)?;
    respire_app::login_transaction::verify_auth_identity(&context.root, &context.profile, &params.identity)
}

pub(crate) fn authorize_account_completion(grant: LaunchGrant) -> Result<()> {
    anyhow::ensure!(grant.maintenance.is_some(), "account completion requires a verified maintenance owner");
    authorize_control_inner(grant, true, false)?;
    verify_account_completion_authority()
}

pub(crate) fn verify_account_completion_authority() -> Result<()> {
    let startup = STARTUP.get().context("account completion grant is missing")?;
    anyhow::ensure!(startup.auth_control && !startup.paused_control,
        "account completion cannot use an offline auth grant");
    verify_managed_boot()?;
    let grant = startup.grant.as_ref().context("account completion grant is missing")?;
    let binding = grant.maintenance.as_ref().context("account completion maintenance is missing")?;
    let bytes = read_private_file(&startup.context.root.join("runtime/autostart/maintenance.json"))?
        .context("account completion maintenance disappeared")?;
    let marker = parse_control(&bytes)?;
    anyhow::ensure!(hash(&bytes) == binding.marker_sha256 && marker["phase"] == "Verified",
        "account completion requires the exact verified maintenance receipt");
    Ok(())
}

pub(crate) fn consumed_control_grant() -> Result<&'static LaunchGrant> {
    STARTUP.get().and_then(|startup| startup.grant.as_ref())
        .context("runtime control grant is missing")
}

pub(crate) fn authorize_snapshot_control(grant: LaunchGrant, finalize: bool) -> Result<()> {
    anyhow::ensure!(grant.maintenance.is_some(), "snapshot control requires maintenance ownership");
    anyhow::ensure!(!respire_app::login_transaction::auth_recovery_pending()?,
        "interrupted auth control must be recovered before snapshot maintenance");
    authorize_control_inner(grant, false, !finalize)
}

pub(crate) fn authorize_model_control(grant: LaunchGrant) -> Result<()> {
    anyhow::ensure!(grant.maintenance.is_some(), "model preparation requires a paused maintenance owner");
    anyhow::ensure!(!respire_app::login_transaction::auth_recovery_pending()?,
        "interrupted auth control must be recovered before model preparation");
    authorize_control_inner(grant, false, true)?;
    anyhow::ensure!(!respire_app::service::off_mode(), "model preparation is unavailable while memory is off");
    respire_app::service::ensure_writable()?;
    respire_app::snapshot::ensure_no_incomplete_restore(&respire_app::service::data_dir())
}

pub(crate) fn authorize_metadata_control(grant: LaunchGrant) -> Result<()> {
    anyhow::ensure!(grant.maintenance.is_some(), "metadata requires Paused maintenance ownership");
    anyhow::ensure!(!respire_app::login_transaction::auth_recovery_pending()?,
        "finish authentication recovery before metadata maintenance");
    // Local-only sessions have no cloud user. Their exact bytes are checked by
    // verify_metadata_control_binding rather than admitted as a business account.
    authorize_control_inner(grant, true, true)?;
    anyhow::ensure!(!respire_app::service::off_mode(), "restore normal service before changing metadata");
    respire_app::service::ensure_writable()?;
    respire_app::snapshot::ensure_no_incomplete_restore(&respire_app::service::data_dir())
}

pub(crate) fn verify_metadata_control_binding(binding: &respire_protocol::ControlBinding,
    identity: &respire_protocol::metadata_control::HostMetadataIdentity) -> Result<()> {
    let startup = STARTUP.get().context("metadata grant is missing")?;
    anyhow::ensure!(startup.auth_control && startup.paused_control, "metadata requires a Paused grant");
    let grant = startup.grant.as_ref().context("metadata grant is missing")?;
    respire_spawn::verify_control_parent(grant.supervisor_pid)?;
    anyhow::ensure!(current_context(startup.context.port)? == startup.context
        && respire_protocol::metadata_control::metadata_identity(&startup.context.profile, hash)? == *identity,
        "metadata selection or session identity changed");
    validate_control_binding(binding, &startup.context, grant, identity.account_id.as_deref())?;
    anyhow::ensure!(!respire_app::login_transaction::auth_recovery_pending()?,
        "authentication recovery interrupted metadata maintenance");
    verify_authority_for_mode(Some(grant), &startup.context, true)
}

fn authorize_control_inner(grant: LaunchGrant, auth: bool, paused: bool) -> Result<()> {
    anyhow::ensure!(STARTUP.get().is_none(), "runtime control grant was already consumed");
    respire_commands::runtime_policy::require_host("offline host control")?;
    respire_spawn::verify_control_parent(grant.supervisor_pid)?;
    respire_app::service::validate_client_config()?;
    let resolved_profile = respire_app::service::data_dir();
    let context = current_context(grant.port)?;
    anyhow::ensure!(
        resolved_profile.canonicalize()? == context.profile,
        "runtime control profile changed during authorization"
    );
    validate_grant(
        &grant,
        &context,
        grant.managed_id.is_some(),
        &grant.nonce,
        now_ms()?,
    )?;
    verify_authority_for_mode(Some(&grant), &context, paused)?;
    // Strict parsing must precede accepting the legacy account/path hash.
    if !auth { control_account(&context.profile)?; }
    // Pin the exact resolved spelling used by memory_revision before it opens DB.
    if !auth { respire_app::service::install_runtime_profile(resolved_profile); }
    STARTUP.set(Startup { context, grant: Some(grant), auth_control: auth, paused_control: paused })
        .map_err(|_| anyhow::anyhow!("runtime control grant was already consumed"))?;
    Ok(())
}

pub(crate) fn verify_auth_control_binding(
    binding: &respire_protocol::ControlBinding,
    identity: &respire_protocol::HostAuthIdentity,
) -> Result<()> {
    let startup = STARTUP.get().context("runtime control grant is not consumed")?;
    let grant = startup.grant.as_ref().context("runtime control grant is missing")?;
    respire_spawn::verify_control_parent(grant.supervisor_pid)?;
    respire_app::login_transaction::verify_auth_identity(&startup.context.root, &startup.context.profile, identity)?;
    let account = match identity {
        respire_protocol::HostAuthIdentity::Bound { account_id, .. } => Some(account_id.as_str()),
        _ => None,
    };
    validate_control_binding(binding, &startup.context, grant, account)?;
    verify_managed_boot()
}

pub(crate) fn acquire_auth_ownership(
    binding: &respire_protocol::ControlBinding,
    identity: &respire_protocol::HostAuthIdentity,
) -> Result<respire_app::login_transaction::AuthOwnership> {
    let startup = STARTUP.get().context("runtime control grant is not consumed")?;
    let grant = startup.grant.as_ref().context("runtime control grant is missing")?;
    let account = match identity {
        respire_protocol::HostAuthIdentity::Bound { account_id, .. } => Some(account_id.as_str()),
        _ => None,
    };
    validate_control_binding(binding, &startup.context, grant, account)?;
    let ownership = respire_app::login_transaction::AuthOwnership::acquire(&startup.context.root, &startup.context.profile)?;
    respire_spawn::verify_control_parent(grant.supervisor_pid)?;
    verify_managed_boot()?;
    Ok(ownership)
}

/// Called only after the app has matched this result to its durable key receipt.
/// The launch grant stays bound to the initial context; only fivekeys may select
/// the receipt's exact target, and no other launch field is allowed to change.
pub(crate) fn verify_key_control_result(
    binding: &respire_protocol::ControlBinding,
    launched_identity: &respire_protocol::HostAuthIdentity,
    result: &respire_protocol::key_control::HostKeyResult,
) -> Result<()> {
    use respire_protocol::HostAuthIdentity;
    let startup = STARTUP.get().context("key control grant is missing")?;
    anyhow::ensure!(startup.auth_control, "key control requires an auth grant");
    let grant = startup.grant.as_ref().context("key control grant is missing")?;
    let account = match launched_identity { HostAuthIdentity::Bound { account_id, .. } => Some(account_id.as_str()), _ => None };
    validate_control_binding(binding, &startup.context, grant, account)?;
    respire_spawn::verify_control_parent(grant.supervisor_pid)?;
    verify_authority_for_mode(Some(grant), &startup.context, startup.paused_control)?;
    let current = current_context(startup.context.port)?;
    validate_key_result_context(&startup.context, launched_identity, &current, result)?;
    respire_app::login_transaction::verify_auth_identity(&current.root, &current.profile, &result.identity)
}

fn validate_key_result_context(original: &LaunchContext, launched_identity: &respire_protocol::HostAuthIdentity,
    current: &LaunchContext, result: &respire_protocol::key_control::HostKeyResult) -> Result<()> {
    use respire_protocol::HostAuthIdentity;
    use respire_protocol::key_control::{HostKeyOperation, HostKeyOutcome};
    let mut expected = original.clone();
    match &result.operation {
        HostKeyOperation::SuperReset { .. } => {
            anyhow::ensure!(result.source_profile == original.profile
                && result.target_profile.as_ref().is_none_or(|target| *target == original.profile)
                && !result.verification_required, "super-reset changed its profile");
            anyhow::ensure!(matches!((launched_identity, &result.identity),
                (HostAuthIdentity::Bound { account_id: before, .. }, HostAuthIdentity::Bound { account_id: after, .. })
                    if before == after), "super-reset changed its account");
        }
        HostKeyOperation::Fivekeys { user, .. } => {
            if result.verification_required || result.outcome == HostKeyOutcome::Committed {
                let target = result.target_profile.as_ref().context("fivekeys target missing")?;
                let account = hash(user.as_bytes());
                anyhow::ensure!(result.account_id.as_ref() == Some(&account)
                    && matches!(&result.identity, HostAuthIdentity::Bound { account_id, session_sha256 }
                        if account_id == &account && Some(session_sha256) == result.session_sha256.as_ref()),
                    "fivekeys target identity differs from its intent");
                expected.profile = target.clone();
            } else if result.outcome == HostKeyOutcome::RolledBack {
                expected.profile = result.source_profile.clone();
            } else {
                anyhow::ensure!(result.identity == *launched_identity, "unpublished fivekeys changed its identity");
            }
            expected.account_id = match &result.identity {
                HostAuthIdentity::Bound { account_id, .. } => account_id.clone(),
                _ => hash(expected.profile.display().to_string().as_bytes()),
            };
        }
    }
    anyhow::ensure!(*current == expected, "key control changed fields outside its owned target");
    Ok(())
}

/// An owned identity transaction may remove its session; the serving fence stays strict.
pub(crate) fn verify_identity_write_result(
    binding: &respire_protocol::ControlBinding,
    launched_identity: &respire_protocol::HostAuthIdentity,
    result: &respire_protocol::identity_write_control::HostIdentityWriteResult,
) -> Result<()> {
    let startup = STARTUP.get().context("identity write grant is missing")?;
    anyhow::ensure!(startup.auth_control && startup.paused_control,
        "identity write requires a Paused private control grant");
    let grant = startup.grant.as_ref().context("identity write grant is missing")?;
    let original_account = match launched_identity {
        respire_protocol::HostAuthIdentity::Bound { account_id, .. } => Some(account_id.as_str()),
        _ => None,
    };
    validate_control_binding(binding, &startup.context, grant, original_account)?;
    respire_spawn::verify_control_parent(grant.supervisor_pid)?;
    verify_authority_for_mode(Some(grant), &startup.context, true)?;
    respire_app::login_transaction::verify_auth_identity(
        &startup.context.root, &startup.context.profile, &result.identity,
    )?;
    validate_identity_write_context(&startup.context, launched_identity,
        &current_context(startup.context.port)?, result)
}

fn validate_identity_write_context(
    original: &LaunchContext,
    launched_identity: &respire_protocol::HostAuthIdentity,
    current: &LaunchContext,
    result: &respire_protocol::identity_write_control::HostIdentityWriteResult,
) -> Result<()> {
    use respire_protocol::HostAuthIdentity;
    use respire_protocol::identity_write_control::{HostIdentityWriteOperation, HostIdentityWriteOutcome};
    anyhow::ensure!(result.path == original.profile.join("session.json"),
        "identity write receipt path differs from the owned profile");
    match (launched_identity, &result.identity) {
        (_, HostAuthIdentity::Absent) => anyhow::ensure!(
            matches!(launched_identity, HostAuthIdentity::Absent)
                || matches!(&result.operation, HostIdentityWriteOperation::Logout { full: true }),
            "this identity operation cannot remove its session"),
        (HostAuthIdentity::Bound { account_id: before, .. }, HostAuthIdentity::Bound { account_id: after, .. }) =>
            anyhow::ensure!(before == after, "identity write cannot change the account"),
        (HostAuthIdentity::Unbound { operation_id: before, .. }, HostAuthIdentity::Unbound { operation_id: after, .. }) =>
            anyhow::ensure!(before == after, "identity write cannot replace the unbound operation"),
        _ => anyhow::bail!("identity write created a different session identity"),
    }
    let session_sha256 = match &result.identity {
        HostAuthIdentity::Absent => None,
        HostAuthIdentity::Bound { session_sha256, .. }
        | HostAuthIdentity::Unbound { session_sha256, .. } => Some(session_sha256.as_str()),
    };
    anyhow::ensure!(result.session_sha256.as_deref() == session_sha256,
        "identity write receipt session digest mismatch");
    if result.outcome == HostIdentityWriteOutcome::Committed
        && matches!(&result.operation, HostIdentityWriteOperation::Logout { full: true }) {
        anyhow::ensure!(matches!(&result.identity, HostAuthIdentity::Absent),
            "completed full logout still has a session");
    }
    let mut expected = original.clone();
    expected.account_id = match &result.identity {
        respire_protocol::HostAuthIdentity::Bound { account_id, .. } => account_id.clone(),
        _ => hash(original.profile.display().to_string().as_bytes()),
    };
    anyhow::ensure!(*current == expected,
        "identity write changed more than its owned account identity");
    Ok(())
}

pub(crate) fn verify_control_binding(binding: &respire_protocol::ControlBinding) -> Result<()> {
    let startup = STARTUP.get().context("runtime control grant is not consumed")?;
    let grant = startup.grant.as_ref().context("runtime control grant is missing")?;
    respire_spawn::verify_control_parent(grant.supervisor_pid)?;
    let account = control_account(&startup.context.profile)?;
    validate_control_binding(binding, &startup.context, grant, account.as_deref())?;
    verify_managed_boot()
}

fn validate_control_binding(
    binding: &respire_protocol::ControlBinding,
    context: &LaunchContext,
    grant: &LaunchGrant,
    account_id: Option<&str>,
) -> Result<()> {
    anyhow::ensure!(
        binding.installation_root == context.root
            && binding.profile == context.profile
            && binding.launch_id == grant.instance_id
            && binding.expected_account_id.as_deref() == account_id,
        "runtime control binding does not match the consumed grant or account"
    );
    Ok(())
}

fn control_account(profile: &Path) -> Result<Option<String>> {
    let Some(bytes) = read_private_file(&profile.join("session.json"))? else {
        return Ok(None);
    };
    let session: Value = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid control session JSON"))?;
    anyhow::ensure!(session.is_object(), "control session must be an object");
    match session.get("user") {
        None => Ok(None),
        Some(Value::String(user)) if user.is_empty() => Ok(None),
        Some(Value::String(user)) => Ok(Some(hash(user.as_bytes()))),
        _ => anyhow::bail!("control session user must be a string"),
    }
}

pub(crate) fn verify_managed_boot() -> Result<()> {
    let startup = STARTUP
        .get()
        .context("runtime startup authorization is missing")?;
    if !startup.auth_control {
        anyhow::ensure!(!respire_app::login_transaction::auth_recovery_pending()?,
            "interrupted auth control must be recovered before opening the store");
    }
    anyhow::ensure!(
        current_context(startup.context.port)? == startup.context,
        "runtime launch context changed before opening the store"
    );
    verify_authority_for_mode(startup.grant.as_ref(), &startup.context, startup.paused_control)
}

fn current_context(port: u16) -> Result<LaunchContext> {
    let root = respire_app::service::main_data_dir().canonicalize()?;
    let profile = respire_app::service::data_dir().canonicalize()?;
    let account = respire_app::service::session_user_of_dir(&profile);
    let account_source = if account.is_empty() {
        profile.display().to_string()
    } else {
        account
    };
    let image_path = std::env::current_exe()?.canonicalize()?;
    Ok(LaunchContext {
        root,
        profile,
        account_id: hash(account_source.as_bytes()),
        sync_generation: respire_commands::rpc_worker::sync_generation(),
        image_sha256: hash_file(&image_path)?,
        image_path,
        port,
    })
}

fn validate_nonce(nonce: &str) -> Result<()> {
    let uuid = uuid::Uuid::parse_str(nonce)
        .map_err(|_| anyhow::anyhow!("invalid runtime launch nonce"))?;
    anyhow::ensure!(
        uuid.get_version_num() == 4 && uuid.to_string() == nonce,
        "runtime launch nonce must be a canonical random UUID"
    );
    Ok(())
}

fn validate_grant(
    grant: &LaunchGrant,
    context: &LaunchContext,
    supervised: bool,
    nonce: &str,
    now: u64,
) -> Result<()> {
    validate_nonce(nonce)?;
    anyhow::ensure!(
        grant.schema_version == 1
            && grant.protocol_version == respire_commands::rpc_worker::PROTOCOL_V
            && grant.nonce == nonce
            && grant.instance_id == nonce,
        "runtime launch grant schema, protocol or nonce mismatch"
    );
    anyhow::ensure!(
        grant.installation_root == context.root
            && grant.installation_id == hash(context.root.display().to_string().as_bytes())
            && grant.profile == context.profile
            && grant.account_id == context.account_id
            && grant.sync_generation == context.sync_generation
            && grant.image_path == context.image_path
            && grant.image_sha256 == context.image_sha256
            && grant.port != 0
            && grant.port == context.port,
        "runtime launch grant does not match this installation, account, generation or image"
    );
    anyhow::ensure!(
        grant.supervisor_pid > 0
            && grant.supervisor_pid != std::process::id()
            && !grant.supervisor_birth.is_empty()
            && supervised == grant.managed_id.is_some()
            && grant.managed_id.as_ref().is_none_or(|id| !id.is_empty())
            && grant.issued_at_ms <= now
            && now <= grant.expires_at_ms
            && grant.expires_at_ms > grant.issued_at_ms
            && grant.expires_at_ms - grant.issued_at_ms <= 60_000,
        "runtime launch grant owner, mode or expiry is invalid"
    );
    Ok(())
}

fn verify_authority(grant: Option<&LaunchGrant>, context: &LaunchContext) -> Result<()> {
    verify_authority_for_mode(grant, context, false)
}

fn verify_authority_for_mode(grant: Option<&LaunchGrant>, context: &LaunchContext, auth: bool) -> Result<()> {
    verify_control_authority(grant, context, auth, None)
}

fn verify_offline_read_authority(
    grant: &LaunchGrant, context: &LaunchContext,
    kind: respire_protocol::metadata_control::HostOfflineRead,
) -> Result<()> {
    use respire_protocol::metadata_control::HostOfflineRead;
    match kind {
        HostOfflineRead::MetadataStatus | HostOfflineRead::AgentConfigRead | HostOfflineRead::SnapshotPreflight => {}
    }
    verify_control_authority(Some(grant), context, false, Some(kind))
}

fn verify_control_authority(
    grant: Option<&LaunchGrant>, context: &LaunchContext, auth: bool,
    offline_read: Option<respire_protocol::metadata_control::HostOfflineRead>,
) -> Result<()> {
    let control = context.root.join("runtime").join("autostart");
    let registration_bytes = read_private_file(&control.join("registration.json"))?;
    let maintenance_bytes = read_private_file(&control.join("maintenance.json"))?;
    let mut registration = registration_bytes
        .as_ref()
        .map(|bytes| parse_control(bytes))
        .transpose()?;
    if let Some(registration) = &mut registration {
        let raw_root = registration["environment"]["RSRS_DATA_DIR"]
            .as_str()
            .context("registered runtime root is missing")?;
        let registered_root = Path::new(raw_root).canonicalize()?;
        anyhow::ensure!(
            registered_root == context.root,
            "registered runtime root belongs to another installation"
        );
        registration["environment"]["RSRS_DATA_DIR"] = json!(registered_root);
    }
    let maintenance = maintenance_bytes
        .as_ref()
        .map(|bytes| parse_control(bytes))
        .transpose()?;
    validate_control_authority(
        grant,
        context,
        registration.as_ref(),
        registration_bytes.as_deref(),
        maintenance.as_ref(),
        maintenance_bytes.as_deref(),
        auth,
        offline_read,
    )?;
    if let Some(grant) = grant {
        anyhow::ensure!(
            process_birth(grant.supervisor_pid)?.as_deref()
                == Some(grant.supervisor_birth.as_str()),
            "runtime launch supervisor exited or its PID was reused"
        );
        if let Some(binding) = &grant.maintenance {
            anyhow::ensure!(
                process_birth(binding.controller_pid)?.as_deref()
                    == Some(binding.controller_birth.as_str()),
                "runtime maintenance controller exited or its PID was reused"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
fn validate_control(
    grant: Option<&LaunchGrant>,
    context: &LaunchContext,
    registration: Option<&Value>,
    registration_bytes: Option<&[u8]>,
    maintenance: Option<&Value>,
    maintenance_bytes: Option<&[u8]>,
) -> Result<()> {
    validate_control_for_mode(grant, context, registration, registration_bytes, maintenance, maintenance_bytes, false)
}

fn validate_control_for_mode(
    grant: Option<&LaunchGrant>,
    context: &LaunchContext,
    registration: Option<&Value>,
    registration_bytes: Option<&[u8]>,
    maintenance: Option<&Value>,
    maintenance_bytes: Option<&[u8]>,
    auth: bool,
) -> Result<()> {
    validate_control_authority(grant, context, registration, registration_bytes,
        maintenance, maintenance_bytes, auth, None)
}

fn validate_control_authority(
    grant: Option<&LaunchGrant>,
    context: &LaunchContext,
    registration: Option<&Value>,
    registration_bytes: Option<&[u8]>,
    maintenance: Option<&Value>,
    maintenance_bytes: Option<&[u8]>,
    auth: bool,
    offline_read: Option<respire_protocol::metadata_control::HostOfflineRead>,
) -> Result<()> {
    if let Some(grant) = grant {
        anyhow::ensure!(
            grant.registration_sha256 == registration_bytes.map(hash),
            "runtime registration changed after launch authorization"
        );
    }
    if let Some(registration) = registration {
        let owner = registration["owner"]
            .as_str()
            .filter(|v| !v.is_empty())
            .context("runtime registration owner is missing")?;
        let id =
            hash(format!("respire-runtime-v1\0{}\0{owner}", context.root.display()).as_bytes());
        anyhow::ensure!(
            registration["schema"] == 1
                && registration["platform"] == std::env::consts::OS
                && registration["installation"].as_str().map(Path::new)
                    == Some(context.root.as_path())
                && registration["id"].as_str() == Some(&id[..24])
                && registration["environment"]["RSRS_RPC_PORT"]
                    .as_str()
                    .and_then(|v| v.parse::<u16>().ok())
                    == Some(context.port)
                && registration["environment"]["RSRS_DATA_DIR"]
                    .as_str()
                    .map(Path::new)
                    == Some(context.root.as_path()),
            "runtime registration belongs to another installation, platform or port"
        );
        if let Some(managed) = grant.and_then(|grant| grant.managed_id.as_deref()) {
            anyhow::ensure!(
                registration["id"] == managed
                    && registration["enabled"] == true
                    && registration["manually_stopped"] == false,
                "managed runtime launch is disabled or belongs to another registration"
            );
        } else {
            anyhow::ensure!(
                (registration["enabled"] == false && registration["manually_stopped"] == false)
                    || grant.is_some_and(|grant| grant.maintenance.is_some())
                    || (offline_read.is_some() && grant.is_some()
                        && registration["manually_stopped"] == true),
                "registered runtime requires its host lifecycle coordinator"
            );
        }
        anyhow::ensure!(
            registration["maintenance"] == false || maintenance.is_some(),
            "registration maintenance has no matching controller marker"
        );
    } else {
        anyhow::ensure!(
            grant.and_then(|grant| grant.managed_id.as_ref()).is_none(),
            "managed runtime registration disappeared"
        );
    }
    match (
        maintenance,
        grant.and_then(|grant| grant.maintenance.as_ref()),
    ) {
        (None, None) => Ok(()),
        (Some(marker), Some(binding)) => {
            anyhow::ensure!(
                maintenance_bytes.map(hash).as_deref() == Some(binding.marker_sha256.as_str())
                    && marker["schema"] == 1
                    && marker["id"] == binding.coordinator_id
                    && registration
                        .is_none_or(|registration| registration["id"] == binding.coordinator_id)
                    && marker["owner_pid"] == binding.controller_pid
                    && marker["owner_birth"] == binding.controller_birth
                    && marker["expected_version"] == binding.issuer_cli_version
                    && !binding.issuer_cli_version.is_empty()
                    && !binding.controller_birth.is_empty()
                    && binding.controller_pid > 0
                    && marker["expected_profile"].as_str().map(Path::new)
                        == Some(context.profile.as_path())
                    && if auth { marker["phase"] == "Paused" }
                        else { matches!(marker["phase"].as_str(), Some("Starting" | "Verified")) },
                "runtime maintenance does not authorize this launch"
            );
            Ok(())
        }
        _ => anyhow::bail!("runtime maintenance launch binding is missing or stale"),
    }
}

/// Match the CLI launch producer's birth format without inspecting command lines.
pub(crate) fn process_birth(pid: u32) -> Result<Option<String>> {
    anyhow::ensure!(pid > 0, "invalid launch owner PID");
    #[cfg(windows)]
    {
        return Ok(respire_spawn::process_birth(pid)?.map(|birth| birth.to_string()));
    }
    #[cfg(target_os = "linux")]
    {
        let raw = match fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        return linux_process_birth(&raw);
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        let output = std::process::Command::new("/bin/ps")
            .args(["-p", &pid.to_string(), "-o", "lstart="])
            .env("LC_ALL", "C")
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()?;
        if output.status.code() == Some(1) && output.stdout.is_empty() {
            return Ok(None);
        }
        anyhow::ensure!(output.status.success(), "launch owner birth lookup failed");
        let birth = String::from_utf8(output.stdout)?;
        let birth = birth.trim();
        anyhow::ensure!(!birth.is_empty(), "launch owner birth is empty");
        return Ok(Some(birth.to_owned()));
    }
    #[cfg(not(any(windows, unix)))]
    anyhow::bail!("launch owner identity is unsupported on this platform")
}

#[cfg(any(target_os = "linux", test))]
fn linux_process_birth(raw: &str) -> Result<Option<String>> {
    let fields = raw
        .rsplit_once(')')
        .context("invalid launch owner process identity")?
        .1;
    if matches!(fields.split_whitespace().next(), Some("Z" | "X")) {
        return Ok(None);
    }
    let birth = fields
        .split_whitespace()
        .nth(19)
        .context("launch owner birth is missing")?;
    let ticks = birth.parse::<u64>().context("invalid launch owner birth")?;
    anyhow::ensure!(ticks > 0, "launch owner birth cannot be zero");
    Ok(Some(ticks.to_string()))
}

fn claim(directory: &Path, nonce: &str, grant: &[u8]) -> Result<()> {
    let path = directory.join(format!("launch-{nonce}.claimed"));
    let birth = process_birth(std::process::id())?
        .context("runtime claimant process identity is unavailable")?;
    let verified: LaunchGrant = serde_json::from_slice(grant)?;
    let registration = read_private_file(
        &directory.parent().context("launch directory has no parent")?.join("registration.json"),
    )?;
    anyhow::ensure!(
        verified.registration_sha256 == registration.as_deref().map(hash),
        "registration changed before the launch claim was persisted"
    );
    let registration_json = registration.map(String::from_utf8).transpose()?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .context("runtime launch grant was already claimed")?;
    // Retain the claim on any later failure; a failed startup never revives a token.
    file.write_all(&serde_json::to_vec(&json!({
        "schema_version": 2,
        "protocol_version": respire_commands::rpc_worker::PROTOCOL_V,
        "state": "consumed",
        "grant_sha256": hash(grant),
        "grant_json": std::str::from_utf8(grant)?,
        "registration_json": registration_json,
        "pid": std::process::id(), "process_start_id": birth,
    }))?)?;
    file.sync_all()?;
    sync_directory(directory)
}

fn parse_control(bytes: &[u8]) -> Result<Value> {
    serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("invalid runtime startup authorization JSON"))
}

pub(crate) fn read_private_file(path: &Path) -> Result<Option<Vec<u8>>> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                anyhow::ensure!(
                    !metadata.file_type().is_symlink(),
                    "runtime authorization path contains a symlink"
                );
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    anyhow::ensure!(
                        metadata.file_attributes() & 0x400 == 0,
                        "runtime authorization path contains a reparse point"
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= 64 * 1024,
        "runtime startup authorization must be a bounded regular file"
    );
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= 64 * 1024,
        "runtime startup authorization is too large"
    );
    Ok(Some(bytes))
}

fn sync_directory(directory: &Path) -> Result<()> {
    #[cfg(unix)]
    fs::File::open(directory)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = directory;
    Ok(())
}

fn now_ms() -> Result<u64> {
    u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
        .context("runtime launch clock overflow")
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn hash_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (LaunchContext, LaunchGrant) {
        let context = LaunchContext {
            root: PathBuf::from("fixture-root"),
            profile: PathBuf::from("fixture-profile"),
            account_id: "a".repeat(64),
            sync_generation: 0,
            image_path: PathBuf::from("fixture-runtime"),
            image_sha256: "b".repeat(64),
            port: 19169,
        };
        let grant = LaunchGrant {
            schema_version: 1,
            protocol_version: respire_commands::rpc_worker::PROTOCOL_V,
            nonce: "12345678-1234-4234-8234-123456789abc".to_owned(),
            instance_id: "12345678-1234-4234-8234-123456789abc".to_owned(),
            installation_root: context.root.clone(),
            installation_id: hash(context.root.display().to_string().as_bytes()),
            profile: context.profile.clone(),
            account_id: context.account_id.clone(),
            sync_generation: 0,
            image_path: context.image_path.clone(),
            image_sha256: context.image_sha256.clone(),
            supervisor_pid: if std::process::id() == 1 { 2 } else { 1 },
            supervisor_birth: "fixture-birth".to_owned(),
            managed_id: None,
            registration_sha256: None,
            maintenance: None,
            port: context.port,
            issued_at_ms: 1000,
            expires_at_ms: 61_000,
        };
        (context, grant)
    }

    #[test]
    fn detached_grant_accepts_only_its_exact_context() -> Result<()> {
        let (context, grant) = fixture();
        validate_grant(&grant, &context, false, &grant.nonce, 2000)?;
        validate_control(Some(&grant), &context, None, None, None, None)?;
        let value = serde_json::to_value(&grant)?;
        for (field, replacement) in [
            ("schema_version", json!(2)),
            ("protocol_version", json!(0)),
            ("nonce", json!("wrong")),
            ("instance_id", json!("wrong")),
            ("installation_root", json!("other-root")),
            ("installation_id", json!("other")),
            ("profile", json!("other-profile")),
            ("account_id", json!("other")),
            ("sync_generation", json!(1)),
            ("image_path", json!("other-image")),
            ("image_sha256", json!("c".repeat(64))),
            ("supervisor_pid", json!(0)),
            ("supervisor_birth", json!("")),
            ("managed_id", json!("unexpected")),
            ("port", json!(19170)),
            ("issued_at_ms", json!(3000)),
            ("expires_at_ms", json!(1999)),
            ("expires_at_ms", json!(62_000)),
        ] {
            let mut changed = value.clone();
            changed[field] = replacement;
            let changed: LaunchGrant = serde_json::from_value(changed)?;
            assert!(
                validate_grant(&changed, &context, false, &grant.nonce, 2000).is_err(),
                "accepted changed {field}"
            );
        }
        assert!(validate_grant(&grant, &context, true, &grant.nonce, 2000).is_err());
        assert!(validate_nonce("../../outside").is_err());
        assert!(validate_nonce("12345678-1234-1234-8234-123456789abc").is_err());

        let mut binding = respire_protocol::ControlBinding {
            installation_root: context.root.clone(),
            profile: context.profile.clone(),
            launch_id: grant.instance_id.clone(),
            expected_account_id: Some(context.account_id.clone()),
        };
        validate_control_binding(&binding, &context, &grant, Some(&context.account_id))?;
        let params = respire_protocol::HostControlParams {
            schema_version: respire_protocol::HOST_CONTROL_SCHEMA_V,
            binding: binding.clone(),
        };
        let mut request: respire_protocol::RpcRequest = serde_json::from_value(json!({
            "v": respire_commands::rpc_worker::PROTOCOL_V,
            "id": grant.instance_id,
            "method": respire_protocol::HostControlOperation::MemoryRevision.method(),
            "args": [serde_json::to_string(&params)?],
        }))?;
        assert!(request.scope.is_none());
        assert!(crate::host_control::validate_request(&request).is_ok());
        request.method = respire_protocol::HostControlOperation::ModelInstallPlan.method().into();
        assert!(crate::host_control::validate_request(&request).is_err());
        let mut model_params = respire_protocol::HostModelParams {
            schema_version: respire_protocol::HOST_MODEL_SCHEMA_V,
            binding: binding.clone(),
            intent: respire_protocol::ModelInstallIntent::default(),
            selection_sha256: None,
        };
        request.args = vec![serde_json::to_string(&model_params)?];
        assert!(crate::host_control::validate_request(&request).is_ok());
        request.method = respire_protocol::HostControlOperation::ModelInstallVerify.method().into();
        assert!(crate::host_control::validate_request(&request).is_err());
        model_params.selection_sha256 = Some("a".repeat(64));
        request.args = vec![serde_json::to_string(&model_params)?];
        assert!(crate::host_control::validate_request(&request).is_ok());
        model_params.selection_sha256 = Some("A".repeat(64));
        request.args = vec![serde_json::to_string(&model_params)?];
        assert!(crate::host_control::validate_request(&request).is_err());
        model_params.selection_sha256 = Some("a".repeat(64));
        request.args = vec![serde_json::to_string(&model_params)?];
        request.operation_id = Some(grant.instance_id.clone());
        assert!(crate::host_control::validate_request(&request).is_err());
        request.operation_id = None;
        request.method = "control.arbitrary".into();
        assert!(crate::host_control::validate_request(&request).is_err());
        request.method = respire_protocol::HostControlOperation::MemoryRevision.method().into();
        request.args = vec![serde_json::to_string(&params)?];
        request.scope = Some(respire_protocol::RuntimeRequestScope {
            account_id: context.account_id.clone(),
            instance_id: grant.instance_id.clone(),
            generation: 1,
        });
        assert!(crate::host_control::validate_request(&request).is_err());
        let secret_params = respire_protocol::secret_control::HostSecretReadParams {
            schema_version: respire_protocol::secret_control::HOST_SECRET_SCHEMA_V,
            binding: binding.clone(),
            identity: respire_protocol::HostAuthIdentity::Bound {
                account_id: context.account_id.clone(), session_sha256: "a".repeat(64),
            },
            reveal: true,
        };
        let mut secret_request: respire_protocol::RpcRequest = serde_json::from_value(json!({
            "v": respire_commands::rpc_worker::PROTOCOL_V,
            "id": grant.instance_id,
            "method": respire_protocol::secret_control::HOST_SECRET_READ_METHOD,
            "args": [serde_json::to_string(&secret_params)?],
        }))?;
        assert!(crate::secret_control::SecretRequest::parse(&secret_request).is_ok());
        assert!(crate::host_control::validate_request(&secret_request).is_err());
        secret_request.operation_id = Some(grant.instance_id.clone());
        assert!(crate::secret_control::SecretRequest::parse(&secret_request).is_err());
        secret_request.operation_id = None;
        let mut extra = serde_json::to_value(&secret_params)?;
        extra["unexpected"] = json!(true);
        secret_request.args = vec![serde_json::to_string(&extra)?];
        assert!(crate::secret_control::SecretRequest::parse(&secret_request).is_err());
        let sessions = respire_protocol::identity_control::HostIdentitySessionListParams {
            schema_version: respire_protocol::identity_control::HOST_IDENTITY_SCHEMA_V,
            binding: binding.clone(),
            identity: secret_params.identity.clone(),
        };
        let mut sessions_request = secret_request.clone();
        sessions_request.method = respire_protocol::identity_control::HOST_IDENTITY_SESSION_LIST_METHOD.into();
        sessions_request.args = vec![serde_json::to_string(&sessions)?];
        assert!(crate::identity_control::IdentityRequest::parse(&sessions_request).is_ok());
        assert!(crate::host_control::validate_request(&sessions_request).is_err());
        sessions_request.operation_id = Some(grant.instance_id.clone());
        assert!(crate::identity_control::IdentityRequest::parse(&sessions_request).is_err());
        sessions_request.operation_id = None;
        let mut extra = serde_json::to_value(&sessions)?;
        extra["unexpected"] = json!(true);
        sessions_request.args = vec![serde_json::to_string(&extra)?];
        assert!(crate::identity_control::IdentityRequest::parse(&sessions_request).is_err());
        let value = serde_json::to_value(&binding)?;
        for (field, replacement) in [
            ("installation_root", json!("other-root")),
            ("profile", json!("other-profile")),
            ("launch_id", json!("other-launch")),
            ("expected_account_id", json!("other-account")),
            ("expected_account_id", Value::Null),
        ] {
            let mut changed = value.clone();
            changed[field] = replacement;
            let changed = serde_json::from_value(changed)?;
            assert!(
                validate_control_binding(&changed, &context, &grant, Some(&context.account_id)).is_err(),
                "accepted changed control binding {field}"
            );
        }
        binding.expected_account_id = None;
        validate_control_binding(&binding, &context, &grant, None)?;
        assert!(validate_control_binding(&binding, &context, &grant, Some(&context.account_id)).is_err());
        let mut auth: respire_protocol::RpcRequest = serde_json::from_value(json!({
            "v": respire_commands::rpc_worker::PROTOCOL_V,
            "id": grant.instance_id,
            "operation_id": grant.instance_id,
            "idempotency_key": grant.instance_id,
            "method": respire_protocol::HOST_AUTH_KEYGEN_METHOD,
            "args": [serde_json::to_string(&respire_protocol::HostAuthKeygenParams {
                schema_version: respire_protocol::HOST_AUTH_SCHEMA_V,
                binding, identity: respire_protocol::HostAuthIdentity::Absent, force: false,
            })?],
        }))?;
        assert!(crate::host_control::validate_auth_request(&auth).is_ok());
        assert!(crate::host_control::validate_request(&auth).is_err());
        let mut account_request = auth.clone();
        account_request.method = respire_protocol::host_control::HOST_AUTH_REGISTER_METHOD.into();
        account_request.args = vec![serde_json::to_string(&respire_protocol::host_control::HostAuthRegisterParams {
            schema_version: respire_protocol::HOST_AUTH_SCHEMA_V,
            binding: params.binding.clone(),
            identity: respire_protocol::HostAuthIdentity::Absent,
            addr: "https://example.invalid".into(), user: "fixture-user".into(),
            password: "fixture-only-password".into(), super_password: None,
        })?];
        assert!(crate::auth_control::AccountRequest::parse(&account_request).is_ok());
        account_request.operation_id = None;
        assert!(crate::auth_control::AccountRequest::parse(&account_request).is_err());
        account_request.operation_id = auth.operation_id.clone();
        account_request.args.push("unexpected".into());
        assert!(crate::auth_control::AccountRequest::parse(&account_request).is_err());
        let mut changed = auth.clone();
        changed.operation_id = None;
        assert!(crate::host_control::validate_auth_request(&changed).is_err());
        changed = auth.clone();
        changed.idempotency_key = None;
        assert!(crate::host_control::validate_auth_request(&changed).is_err());
        auth.scope = Some(respire_protocol::RuntimeRequestScope {
            account_id: context.account_id.clone(), instance_id: grant.instance_id, generation: 1,
        });
        assert!(crate::host_control::validate_auth_request(&auth).is_err());
        use respire_protocol::identity_write_control::{HostIdentityWriteOperation,
            HostIdentityWriteOutcome, HostIdentityWriteResult};
        let launched = respire_protocol::HostAuthIdentity::Bound {
            account_id: context.account_id.clone(), session_sha256: "c".repeat(64),
        };
        let mut receipt = HostIdentityWriteResult {
            operation_id: auth.id.clone(), fingerprint: "d".repeat(64),
            operation: HostIdentityWriteOperation::Logout { full: true },
            outcome: HostIdentityWriteOutcome::Committed,
            path: context.profile.join("session.json"), session_found: true,
            session_sha256: None, identity: respire_protocol::HostAuthIdentity::Absent,
            revoke: None,
        };
        let mut after_logout = context.clone();
        after_logout.account_id = hash(context.profile.display().to_string().as_bytes());
        validate_identity_write_context(&context, &launched, &after_logout, &receipt)?;
        for field in ["root", "profile", "account", "generation", "image", "digest", "port"] {
            let mut foreign = after_logout.clone();
            match field {
                "root" => foreign.root = PathBuf::from("foreign-root"),
                "profile" => foreign.profile = PathBuf::from("foreign-profile"),
                "account" => foreign.account_id = "e".repeat(64),
                "generation" => foreign.sync_generation += 1,
                "image" => foreign.image_path = PathBuf::from("foreign-runtime"),
                "digest" => foreign.image_sha256 = "f".repeat(64),
                "port" => foreign.port += 1,
                _ => unreachable!("fixed launch context field"),
            }
            assert!(validate_identity_write_context(&context, &launched, &foreign, &receipt).is_err(), "{field}");
        }
        receipt.operation = HostIdentityWriteOperation::SessionRevoke { session_id: auth.id.clone() };
        assert!(validate_identity_write_context(&context, &launched, &after_logout, &receipt).is_err());
        receipt.operation = HostIdentityWriteOperation::Logout { full: true };
        receipt.path = context.root.join("foreign-session.json");
        assert!(validate_identity_write_context(&context, &launched, &after_logout, &receipt).is_err());
        receipt.path = context.profile.join("session.json");
        receipt.identity = launched.clone();
        receipt.session_sha256 = Some("c".repeat(64));
        assert!(validate_identity_write_context(&context, &launched, &context, &receipt).is_err());
        receipt.operation = HostIdentityWriteOperation::Logout { full: false };
        validate_identity_write_context(&context, &launched, &context, &receipt)?;
        receipt.session_sha256 = None;
        assert!(validate_identity_write_context(&context, &launched, &context, &receipt).is_err());
        use respire_protocol::key_control::{HostKeyOperation, HostKeyOutcome, HostKeyResult};
        let mut key_receipt = HostKeyResult { operation_id: auth.id.clone(), fingerprint: "e".repeat(64),
            operation: HostKeyOperation::Fivekeys { addr: String::new(), user: "fivekeys-fixture".into(),
                kdf_salt: "synthetic-salt".into(), wrapped_urk: "synthetic-wrap".into(), urk_nonce: "synthetic-nonce".into(), use_super: true },
            outcome: HostKeyOutcome::Pending, source_profile: context.profile.clone(),
            target_profile: Some(context.root.join("accounts/fivekeys-fixture")),
            account_id: Some(hash(b"fivekeys-fixture")), session_sha256: Some("f".repeat(64)),
            identity: respire_protocol::HostAuthIdentity::Bound { account_id: hash(b"fivekeys-fixture"), session_sha256: "f".repeat(64) },
            required_inputs: Vec::new(), verification_required: true, super_password: None };
        let mut target = context.clone();
        target.profile = key_receipt.target_profile.clone().context("fivekeys target missing")?;
        target.account_id = hash(b"fivekeys-fixture");
        validate_key_result_context(&context, &launched, &target, &key_receipt)?;
        assert!(validate_key_result_context(&context, &launched, &context, &key_receipt).is_err());
        for field in ["root", "profile", "account", "generation", "image", "sha", "port"] {
            let mut foreign = target.clone();
            match field {
                "root" => foreign.root = target.root.join("other"),
                "profile" => foreign.profile = target.profile.join("other"),
                "account" => foreign.account_id.push('x'),
                "generation" => foreign.sync_generation += 1,
                "image" => foreign.image_path.push("other"),
                "sha" => foreign.image_sha256.push('x'),
                _ => foreign.port += 1,
            }
            assert!(validate_key_result_context(&context, &launched, &foreign, &key_receipt).is_err(), "{field}");
        }
        key_receipt.operation = HostKeyOperation::SuperReset { addr: None };
        assert!(validate_key_result_context(&context, &launched, &target, &key_receipt).is_err());
        Ok(())
    }

    #[test]
    fn managed_and_maintenance_grants_bind_exact_control_files() -> Result<()> {
        // Re-enter only this test: environment and consumed startup state stay process-local.
        if let Ok(selection) = std::env::var("RSRS_TEST_OFFLINE_SELECTION") {
            return offline_read_child(&selection)
                .map_err(|_| anyhow::anyhow!("offline-read diagnostic stage failed"));
        }
        let (context, mut grant) = fixture();
        let id = hash(
            format!(
                "respire-runtime-v1\0{}\0fixture-owner",
                context.root.display()
            )
            .as_bytes(),
        );
        let mut registration = json!({
            "schema": 1, "platform": std::env::consts::OS,
            "installation": context.root, "owner": "fixture-owner", "id": &id[..24],
            "enabled": true, "manually_stopped": false, "maintenance": false,
            "environment": { "RSRS_DATA_DIR": context.root, "RSRS_RPC_PORT": "19169" }
        });
        let bytes = serde_json::to_vec(&registration)?;
        grant.managed_id = Some(id[..24].to_owned());
        grant.registration_sha256 = Some(hash(&bytes));
        validate_grant(&grant, &context, true, &grant.nonce, 2000)?;
        validate_control(
            Some(&grant),
            &context,
            Some(&registration),
            Some(&bytes),
            None,
            None,
        )?;
        assert!(validate_control(
            None,
            &context,
            Some(&registration),
            Some(&bytes),
            None,
            None
        )
        .is_err());
        registration["enabled"] = json!(false);
        let changed = serde_json::to_vec(&registration)?;
        assert!(validate_control(
            Some(&grant),
            &context,
            Some(&registration),
            Some(&changed),
            None,
            None
        )
        .is_err());
        grant.registration_sha256 = Some(hash(&changed));
        assert!(validate_control(
            Some(&grant),
            &context,
            Some(&registration),
            Some(&changed),
            None,
            None
        )
        .is_err());
        registration["enabled"] = json!(true);
        let bytes = serde_json::to_vec(&registration)?;
        grant.registration_sha256 = Some(hash(&bytes));
        let mut marker = json!({
            "schema": 1, "id": &id[..24], "owner_pid": grant.supervisor_pid,
            "owner_birth": "controller-birth", "expected_version": "fixture-cli-version",
            "expected_profile": context.profile, "phase": "Starting", "token": "maintenance-secret"
        });
        let marker_bytes = serde_json::to_vec(&marker)?;
        grant.maintenance = Some(MaintenanceBinding {
            marker_sha256: hash(&marker_bytes),
            coordinator_id: id[..24].to_owned(),
            controller_pid: grant.supervisor_pid,
            controller_birth: "controller-birth".to_owned(),
            issuer_cli_version: "fixture-cli-version".to_owned(),
        });
        validate_control(
            Some(&grant),
            &context,
            Some(&registration),
            Some(&bytes),
            Some(&marker),
            Some(&marker_bytes),
        )?;
        assert!(validate_control(
            Some(&grant),
            &context,
            Some(&registration),
            Some(&bytes),
            None,
            None
        )
        .is_err());
        marker["phase"] = json!("Paused");
        let changed = serde_json::to_vec(&marker)?;
        assert!(validate_control(
            Some(&grant),
            &context,
            Some(&registration),
            Some(&bytes),
            Some(&marker),
            Some(&changed)
        )
        .is_err());
        grant.maintenance.as_mut().context("maintenance binding is missing")?.marker_sha256 = hash(&changed);
        assert!(validate_control(Some(&grant), &context, Some(&registration), Some(&bytes), Some(&marker), Some(&changed)).is_err());
        validate_control_for_mode(Some(&grant), &context, Some(&registration), Some(&bytes), Some(&marker), Some(&changed), true)?;
        marker["phase"] = json!("Starting");
        let changed = serde_json::to_vec(&marker)?;
        grant.maintenance.as_mut().context("maintenance binding is missing")?.marker_sha256 = hash(&changed);
        assert!(validate_control_for_mode(Some(&grant), &context, Some(&registration), Some(&bytes), Some(&marker), Some(&changed), true).is_err());
        marker["phase"] = json!("Paused");
        marker["expected_profile"] = json!("other-profile");
        let changed = serde_json::to_vec(&marker)?;
        grant.maintenance.as_mut().context("maintenance binding is missing")?.marker_sha256 = hash(&changed);
        assert!(validate_control_for_mode(Some(&grant), &context, Some(&registration), Some(&bytes), Some(&marker), Some(&changed), true).is_err());
        offline_read_registered_profiles()
            .map_err(|_| anyhow::anyhow!("offline-read registered-profile diagnostic failed"))?;
        Ok(())
    }

    fn offline_read_child(selection: &str) -> Result<()> {
        use respire_protocol::metadata_control::HostOfflineRead;
        let kind = HostOfflineRead::SnapshotPreflight;
        eprintln!("offline-read stage=input");
        let mut input = std::io::stdin().lock();
        let mut size = [0; 4];
        input.read_exact(&mut size)?;
        let size = u32::from_be_bytes(size) as usize;
        anyhow::ensure!(size > 0 && size <= 64 * 1024, "invalid diagnostic frame");
        let mut bytes = vec![0; size];
        input.read_exact(&mut bytes)?;
        let grant: LaunchGrant = serde_json::from_slice(&bytes)?;
        eprintln!("offline-read stage=config");
        respire_app::service::validate_client_config()?;
        eprintln!("offline-read stage=context");
        let context = offline_read_context(grant.port, kind)?;
        let root = PathBuf::from(std::env::var_os("RSRS_DATA_DIR").context("missing test root")?);
        let expected = match selection {
            "main" => root.clone(),
            "secondary" => root.join("accounts/secondary profile"),
            _ => anyhow::bail!("invalid diagnostic selection"),
        };
        let root_eq = context.root == root;
        let profile_eq = context.profile == expected && grant.profile == expected;
        let account_eq = context.account_id == hash(expected.display().to_string().as_bytes());
        let generation_eq = context.sync_generation == 0;
        eprintln!("offline-read root_eq={root_eq} profile_eq={profile_eq} account_eq={account_eq} generation_eq={generation_eq}");
        anyhow::ensure!(root_eq && profile_eq && account_eq && generation_eq,
            "diagnostic context comparison failed");
        // Path equality ignores trailing separators; identity hashes cannot ignore them.
        let representation_eq = context.root.as_os_str() == root.as_os_str()
            && context.profile.as_os_str() == expected.as_os_str();
        let repeated = respire_protocol::metadata_control::metadata_status_path(&context.profile)?;
        let normalization_stable = repeated.as_os_str() == expected.as_os_str();
        eprintln!("offline-read representation_eq={representation_eq} normalization_stable={normalization_stable}");
        anyhow::ensure!(representation_eq && normalization_stable,
            "diagnostic path representation changed");
        eprintln!("offline-read stage=grant");
        validate_grant(&grant, &context, true, &grant.nonce, now_ms()?)?;
        let mut changed = grant.clone();
        changed.profile = if selection == "main" { root.join("accounts/secondary profile") } else { root };
        anyhow::ensure!(validate_grant(&changed, &context, true, &grant.nonce, now_ms()?).is_err(),
            "changed profile accepted");
        eprintln!("offline-read stage=authority");
        verify_offline_read_authority(&grant, &context, kind)?;
        changed = grant.clone();
        changed.registration_sha256 = Some("0".repeat(64));
        anyhow::ensure!(verify_offline_read_authority(&changed, &context, kind).is_err(),
            "changed registration accepted");
        let binding = respire_protocol::ControlBinding {
            installation_root: grant.installation_root.clone(), profile: grant.profile.clone(),
            launch_id: grant.instance_id.clone(), expected_account_id: None,
        };
        eprintln!("offline-read stage=consume");
        authorize_offline_read(grant, kind)?;
        eprintln!("offline-read stage=binding");
        verify_offline_read_binding(&binding, kind)?;
        eprintln!("offline-read stage=complete");
        writeln!(std::io::stdout().lock(), "\noffline-read complete")?;
        Ok(())
    }

    fn offline_read_registered_profiles() -> Result<()> {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        let suffix = if cfg!(unix) { "data spaces % $ \" \\" } else { "data spaces % and $" };
        let root = std::env::temp_dir().join(format!("offline-read-{} {suffix}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("accounts/secondary profile"))?;
        let root = root.canonicalize()?;
        let result = (|| -> Result<()> {
            let control = root.join("runtime/autostart");
            fs::create_dir_all(&control)?;
            let id = hash(format!("respire-runtime-v1\0{}\0offline-test-owner", root.display()).as_bytes());
            let registration = serde_json::to_vec_pretty(&json!({
                "schema": 1, "platform": std::env::consts::OS,
                "installation": root, "owner": "offline-test-owner", "id": &id[..24],
                "enabled": true, "manually_stopped": false, "maintenance": false,
                "environment": {"RSRS_DATA_DIR": root, "RSRS_RPC_PORT": "19169"}
            }))?;
            fs::write(control.join("registration.json"), &registration)?;
            let image = std::env::current_exe()?.canonicalize()?;
            let image_sha256 = hash_file(&image)?;
            for selection in ["main", "secondary"] {
                let profile = if selection == "main" { root.clone() } else { root.join("accounts/secondary profile") };
                // Main preflight runs before config writes the secondary selection.
                let config = if selection == "main" { json!({}) } else { json!({"data_dir": profile}) };
                fs::write(root.join("client.json"), serde_json::to_vec(&config)?)?;
                let (_, mut grant) = fixture();
                grant.installation_root = root.clone();
                grant.installation_id = hash(root.display().to_string().as_bytes());
                grant.account_id = hash(profile.display().to_string().as_bytes());
                grant.profile = profile;
                grant.image_path = image.clone();
                grant.image_sha256 = image_sha256.clone();
                grant.supervisor_pid = std::process::id();
                grant.supervisor_birth = process_birth(grant.supervisor_pid)?.context("missing test parent")?;
                grant.managed_id = Some(id[..24].to_owned());
                grant.registration_sha256 = Some(hash(&registration));
                grant.issued_at_ms = now_ms()?;
                grant.expires_at_ms = grant.issued_at_ms + 60_000;
                let bytes = serde_json::to_vec(&grant)?;
                let mut child = Command::new(&image)
                    .args(["--exact", "startup_identity::tests::managed_and_maintenance_grants_bind_exact_control_files", "--nocapture"])
                    .env("RSRS_TEST_OFFLINE_SELECTION", selection)
                    .env("RSRS_DATA_DIR", &root).env("HOME", &root).env("USERPROFILE", &root)
                    .env_remove("RSRS_DEFAULT_DATA_DIR").env_remove("RSRS_M3_DIR")
                    .env_remove("RSRS_CLIENT_ONLY").env_remove("RSRS_NO_AUTOSTART")
                    .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit())
                    .spawn()?;
                let outcome = (|| -> Result<()> {
                    let mut input = child.stdin.take().context("missing diagnostic pipe")?;
                    input.write_all(&u32::try_from(bytes.len())?.to_be_bytes())?;
                    input.write_all(&bytes)?;
                    input.flush()?;
                    let deadline = Instant::now() + Duration::from_secs(20);
                    loop {
                        if let Some(status) = child.try_wait()? {
                            anyhow::ensure!(status.success(), "diagnostic child failed");
                            break;
                        }
                        anyhow::ensure!(Instant::now() < deadline, "diagnostic child timed out");
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    let mut output = String::new();
                    child.stdout.take().context("missing diagnostic output")?
                        .take(4097).read_to_string(&mut output)?;
                    anyhow::ensure!(output.len() <= 4096 && output.contains("\noffline-read complete\n"),
                        "diagnostic child did not execute the selected test");
                    // Retain the private input owner until authorization and binding finish.
                    drop(input);
                    Ok(())
                })();
                if outcome.is_err() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                outcome?;
            }
            Ok(())
        })();
        let cleanup = fs::remove_dir_all(&root);
        result?;
        cleanup?;
        Ok(())
    }

    #[test]
    fn linux_birth_parser_handles_parentheses_and_dead_or_invalid_processes() -> Result<()> {
        let fields = (1..=20)
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(
            linux_process_birth(&format!("123 (owner ) name) S {fields}"))?,
            Some("19".to_owned())
        );
        assert!(linux_process_birth(&format!("123 (owner) Z {fields}"))?.is_none());
        assert!(linux_process_birth("invalid").is_err());
        assert!(linux_process_birth("123 (owner) S 1 2").is_err());
        Ok(())
    }

    #[test]
    fn launch_claim_cannot_be_replayed() -> Result<()> {
        let root =
            std::env::temp_dir().join(format!("respire-launch-fixture-{}", uuid::Uuid::new_v4()));
        let directory = root.join("launch");
        fs::create_dir_all(&directory)?;
        let result = (|| -> Result<()> {
            let nonce = "12345678-1234-4234-8234-123456789abc";
            let (_, grant) = fixture();
            let bytes = serde_json::to_vec(&grant)?;
            claim(&directory, nonce, &bytes)?;
            let receipt_path = directory.join(format!("launch-{nonce}.claimed"));
            let receipt_bytes = fs::read(&receipt_path)?;
            let receipt: Value = serde_json::from_slice(&receipt_bytes)?;
            assert_eq!(receipt["schema_version"], 2);
            assert_eq!(receipt["state"], "consumed");
            assert_eq!(receipt["grant_sha256"], hash(&bytes));
            assert_eq!(receipt["grant_json"], std::str::from_utf8(&bytes)?);
            assert!(receipt["registration_json"].is_null());
            assert_eq!(receipt["pid"], std::process::id());
            assert_eq!(receipt["process_start_id"], process_birth(std::process::id())?.context("test process exited")?);
            assert!(claim(&directory, nonce, &bytes).is_err());
            assert_eq!(fs::read(&receipt_path)?, receipt_bytes);
            Ok(())
        })();
        fs::remove_dir_all(&root)?;
        result
    }
}
