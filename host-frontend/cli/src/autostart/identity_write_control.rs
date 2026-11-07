//! One identity write; reconnects query its original Runtime journal admission.
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use respire_commands::output::{Item, ResultEnvelope, Status};
use respire_protocol::identity_write_control::*;
use respire_protocol::{HostAuthIdentity, RpcRequest, RpcResponse};
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
    operation: HostIdentityWriteOperation,
    token: String,
    coordinator: String,
    was_serving: bool,
    store_ready: bool,
    sent: bool,
}

pub(crate) struct IdentityWriteRecoveryRequired {
    pub operation_id: String,
    pub key: String,
    pub profile: PathBuf,
    pub operation: HostIdentityWriteOperation,
    pub query_only: bool,
}
impl std::fmt::Debug for IdentityWriteRecoveryRequired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { std::fmt::Display::fmt(self, f) }
}
impl std::fmt::Display for IdentityWriteRecoveryRequired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "identity_write_recovery_required operation_id={}; repeat the same logout/session revoke command to query this operation; never replay the write", self.operation_id)
    }
}
impl std::error::Error for IdentityWriteRecoveryRequired {}

impl Original {
    fn fingerprint(&self) -> Result<String> {
        Ok(super::hash(&serde_json::to_vec(&json!({"schema_version":HOST_IDENTITY_WRITE_SCHEMA_V,
            "method":"control.identity.write", "root":self.root, "profile":self.profile,
            "source_identity":self.source_identity, "operation":self.operation}))?))
    }
    fn recovery(&self) -> IdentityWriteRecoveryRequired {
        IdentityWriteRecoveryRequired { operation_id: self.operation_id.clone(), key: self.key.clone(),
            profile: self.profile.clone(), operation: self.operation.clone(), query_only: self.sent }
    }
}

fn read_original(path: &Path) -> Result<Option<(Original, String)>> {
    for ancestor in path.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                anyhow::ensure!(!metadata.file_type().is_symlink(), "identity recovery path is a symlink");
                #[cfg(windows)] {
                    use std::os::windows::fs::MetadataExt;
                    anyhow::ensure!(metadata.file_attributes() & 0x400 == 0, "identity recovery path is a reparse point");
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
    anyhow::ensure!(metadata.is_file() && metadata.len() <= 16 * 1024, "identity recovery context is not a bounded file");
    let mut bytes = Vec::new();
    std::fs::File::open(path)?.take(16 * 1024 + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 16 * 1024, "identity recovery context exceeds its bound");
    let original = serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid identity recovery context"))?;
    Ok(Some((original, super::hash(&bytes))))
}

pub(crate) fn control_logout(full: bool) -> Result<ResultEnvelope> {
    let receipt = control_write(HostIdentityWriteOperation::Logout { full })?;
    let status = if receipt.session_found { Status::Ok } else { Status::Skip };
    let action = if !receipt.session_found { "absent" } else if full { "deleted" } else { "cleared" };
    let mut output = ResultEnvelope::new("logout", status,
        json!({"mode":if full {"full"} else {"session"},"action":action,"session_found":receipt.session_found}),
        vec![Item::new("session", status, action)]);
    output.details = json!({"path":receipt.path.display().to_string(),
        "identity_deleted":full && receipt.session_found,"credentials_cleared":!full && receipt.session_found});
    if receipt.session_found {
        output.actions.push(if full { "register or import five-key material to reconnect" }
            else { "login to reconnect" }.to_owned());
    }
    Ok(output)
}

pub(crate) fn control_session_revoke(session_id: &str) -> Result<serde_json::Value> {
    uuid::Uuid::parse_str(session_id).context("session id must be a full UUID")?;
    let receipt = control_write(HostIdentityWriteOperation::SessionRevoke { session_id: session_id.to_owned() })?;
    serde_json::to_value(receipt.revoke.context("committed session revoke receipt is missing")?).map_err(Into::into)
}

fn control_write(operation: HostIdentityWriteOperation) -> Result<HostIdentityWriteResult> {
    crate::runtime_policy::require_host("private identity write")?;
    anyhow::ensure!(super::lifecycle::current_boot_token().is_none(), "identity write must own host maintenance");
    let takeover = crate::runtime_policy::takeover_lock()?;
    let (binary, manifest) = super::model_control::installed_model_runtime()?;
    let (root, profile) = respire_client_host::config::control_roots()?;
    std::fs::create_dir_all(&root)?;
    std::fs::create_dir_all(&profile)?;
    let root = root.canonicalize()?;
    let profile = profile.canonicalize()?;
    let path = root.join("runtime/autostart/identity-write.json");
    let saved = read_original(&path)?;
    let expected = super::control::identity(&profile)?;
    let registration = super::read_registration(&root)?;
    let managed = registration.as_ref().filter(|config| config.enabled && !config.manually_stopped);
    let owner = crate::rpc::probe_runtime()?;
    anyhow::ensure!(owner.is_some() || !crate::rpc::endpoint_path().try_exists()?,
        "identity write has a recorded owner without a verifiable drain identity");
    if let Some(config) = managed {
        super::lifecycle::owned(config)?;
        super::lifecycle::ensure_control_endpoint(config)?;
        anyhow::ensure!(owner.is_some() || !super::super::super::manager::inspect(config)?.running,
            "identity write cannot identify the registered supervisor's owner");
    }
    if let Some(owner) = owner.as_ref() {
        super::model_control::verify_model_owner(owner, &root, &profile, managed, &binary, &manifest,
            Some(&account(&expected, &profile)))?;
    }
    let (mut original, mut digest, mut maintenance) = if let Some((original, digest)) = saved {
        let canonical = |value: &str| uuid::Uuid::parse_str(value)
            .is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == value);
        anyhow::ensure!(original.schema_version == HOST_IDENTITY_WRITE_SCHEMA_V
            && canonical(&original.operation_id) && original.key == original.operation_id && canonical(&original.token),
            "invalid identity recovery operation binding");
        if original.root != root || original.profile != profile || original.operation != operation {
            return Err(anyhow::anyhow!("another identity operation owns recovery; do not replace its operation or source identity")
                .context(original.recovery()));
        }
        let maintenance = super::lifecycle::resume_identity_write_maintenance(&root, &profile,
            &original.token, &original.coordinator)?;
        (original, Some(digest), maintenance)
    } else {
        let mut maintenance = super::lifecycle::begin_maintenance_locked()?;
        let binding = maintenance.auth_launch_binding(&profile)?.context("identity write requires persistent Paused maintenance")?;
        let id = uuid::Uuid::new_v4().to_string();
        let original = Original { schema_version: HOST_IDENTITY_WRITE_SCHEMA_V, root: root.clone(), profile: profile.clone(),
            operation_id: id.clone(), key: id, source_identity: expected, operation,
            token: super::lifecycle::current_boot_token().context("identity maintenance token missing")?,
            coordinator: binding["coordinator_id"].as_str().context("identity coordinator missing")?.to_owned(),
            was_serving: owner.is_some(), store_ready: owner.as_ref().is_some_and(|owner| owner.store_ready), sent: false };
        let bytes = serde_json::to_vec(&original)?;
        super::private_write(&path, &bytes, None)?;
        (original, Some(super::hash(&bytes)), maintenance)
    };
    let mut finished = false;
    let result: Result<HostIdentityWriteResult> = (|| {
        maintenance.check_account_runtime()?;
        if let Some(owner) = owner.as_ref() { maintenance.drain_runtime(owner)?; }
        anyhow::ensure!(!crate::net_rpc::port_is_open(), "identity write requires the serving Runtime to be drained");
        let query_only = original.sent;
        if !query_only {
            anyhow::ensure!(super::control::identity(&profile)? == original.source_identity,
                "identity source changed before sending the operation");
            original.sent = true;
            let bytes = serde_json::to_vec(&original)?;
            if let Err(error) = super::private_write(&path, &bytes, digest.as_deref()) {
                // Publication can fail after replacement; recover from the actual durable state.
                if let Ok(Some((saved, _))) = read_original(&path) {
                    original.sent = saved.sent;
                }
                return Err(error);
            }
            digest = Some(super::hash(&bytes));
        }
        let envelope = super::control::auth_exchange(&takeover, &mut maintenance,
            Instant::now() + Duration::from_secs(45), None,
            |binding, identity| {
                anyhow::ensure!(binding.installation_root == original.root && binding.profile == original.profile,
                    "identity write launch selection changed");
                let params = HostIdentityWriteParams { schema_version: HOST_IDENTITY_WRITE_SCHEMA_V, binding, identity,
                    source_identity: original.source_identity.clone(), operation: original.operation.clone() };
                let method = if query_only { HOST_IDENTITY_WRITE_RESULT_METHOD } else { match &original.operation {
                    HostIdentityWriteOperation::Logout { .. } => HOST_IDENTITY_LOGOUT_METHOD,
                    HostIdentityWriteOperation::SessionRevoke { .. } => HOST_IDENTITY_SESSION_REVOKE_METHOD,
                }};
                Ok(RpcRequest { v: respire_commands::rpc_client::PROTOCOL_V, id: uuid::Uuid::new_v4().to_string(),
                    method: method.to_owned(), args: vec![serde_json::to_string(&params)?], scope: None,
                    operation_id: Some(original.operation_id.clone()), idempotency_key: Some(original.key.clone()),
                    parent_operation_id: None, queue_wait_ms: None, lifecycle: None })
            }, |response, request, profile, pid| validate_response(response, request, profile, pid, &original), |error| error)?;
        let receipt: HostIdentityWriteResult = serde_json::from_value(envelope.summary)
            .map_err(|_| anyhow::anyhow!("invalid identity write receipt"))?;
        match receipt.outcome {
            HostIdentityWriteOutcome::Committed => {}
            HostIdentityWriteOutcome::Pending => anyhow::bail!("identity write pending; query the original operation"),
            HostIdentityWriteOutcome::Unknown => anyhow::bail!("identity write outcome unknown; query the original operation"),
        }
        unchanged(&original, &receipt.identity, &binary, &manifest)?;
        if original.was_serving {
            maintenance.start_account_runtime()?;
            let restored = crate::rpc::probe_runtime()?.context("identity owner did not resume")?;
            super::model_control::verify_model_owner(&restored, &root, &profile, managed, &binary, &manifest,
                Some(&account(&receipt.identity, &profile)))?;
            anyhow::ensure!(!original.store_ready || restored.store_ready, "identity owner store readiness was not restored");
        }
        unchanged(&original, &receipt.identity, &binary, &manifest)?;
        maintenance.finish()?;
        finished = true;
        anyhow::ensure!(read_original(&path)?.as_ref().map(|(_, hash)| hash.as_str()) == digest.as_deref(),
            "identity recovery context changed before cleanup");
        std::fs::remove_file(&path)?;
        if respire_spawn::durable::sync_directory(path.parent().context("identity context parent missing")?).is_err() {
            eprintln!("Identity operation committed; recovery namespace cleanup needs a later check.");
        }
        Ok(receipt)
    })();
    result.map_err(|error| {
        let error = if finished {
            error.context("identity operation committed and maintenance finished; recovery context cleanup failed")
        } else {
            let pause = maintenance.mark(super::lifecycle::Phase::Paused);
            error.context(format!("identity operation retained; Paused publication: {pause:?}"))
        };
        error.context(original.recovery())
    })
}

fn account(identity: &HostAuthIdentity, profile: &Path) -> String {
    match identity { HostAuthIdentity::Bound { account_id, .. } => account_id.clone(),
        _ => super::hash(profile.display().to_string().as_bytes()) }
}

fn unchanged(original: &Original, expected: &HostAuthIdentity, binary: &Path,
    manifest: &crate::runtime_fetch::ManagedManifest) -> Result<()> {
    let (root, profile) = respire_client_host::config::control_roots()?;
    let (current, release) = super::model_control::installed_model_runtime()?;
    anyhow::ensure!(root.canonicalize()? == original.root && profile.canonicalize()? == original.profile
        && current == binary && release.version == manifest.version && release.sha256.eq_ignore_ascii_case(&manifest.sha256)
        && super::control::identity(&original.profile)? == *expected,
        "identity write installation, profile, image or resulting identity changed");
    Ok(())
}

fn validate_response(response: RpcResponse<ResultEnvelope>, request: &RpcRequest, profile: &Path,
    pid: u32, original: &Original) -> Result<ResultEnvelope> {
    anyhow::ensure!(response.v == request.v && response.id == request.id && response.pid == Some(pid)
        && response.bin == "rsrs-runtime" && response.scope.is_none() && response.web_url.is_none()
        && response.operation_id.as_deref() == Some(original.operation_id.as_str())
        && response.idempotency_key.as_deref() == Some(original.key.as_str()), "identity write response binding mismatch");
    if let Some(path) = response.data_dir.as_deref() { anyhow::ensure!(Path::new(path).canonicalize()? == profile, "identity response profile mismatch"); }
    let envelope = response.envelope.context("identity write receipt missing")?;
    anyhow::ensure!(envelope.command == "identity-write" && envelope.details.is_null(), "invalid identity write envelope");
    for (name, value) in [("control_ready", "true"), ("store_ready", "false")] {
        let mut items = envelope.items.iter().filter(|item| item.name == name);
        anyhow::ensure!(items.next().is_some_and(|item| item.value == value && if name == "control_ready" {
            matches!(item.status, Status::Ok) } else { matches!(item.status, Status::Skip) }) && items.next().is_none(),
            "identity helper readiness mismatch");
    }
    let receipt: HostIdentityWriteResult = serde_json::from_value(envelope.summary.clone())
        .map_err(|_| anyhow::anyhow!("invalid identity write receipt"))?;
    anyhow::ensure!(receipt.operation_id == original.operation_id && receipt.operation == original.operation
        && receipt.fingerprint == original.fingerprint()? && receipt.path == profile.join("session.json")
        && receipt.session_found == !matches!(original.source_identity, HostAuthIdentity::Absent),
        "identity receipt differs from original operation, source or profile");
    let digest = match &receipt.identity { HostAuthIdentity::Absent => None,
        HostAuthIdentity::Bound { session_sha256, .. } | HostAuthIdentity::Unbound { session_sha256, .. } => Some(session_sha256) };
    anyhow::ensure!(receipt.session_sha256.as_ref() == digest, "identity receipt session digest mismatch");
    let compatible = match (&original.source_identity, &receipt.identity) {
        (HostAuthIdentity::Absent, HostAuthIdentity::Absent) => true,
        (HostAuthIdentity::Bound { account_id: a, .. }, HostAuthIdentity::Bound { account_id: b, .. }) => a == b,
        (HostAuthIdentity::Unbound { operation_id: a, .. }, HostAuthIdentity::Unbound { operation_id: b, .. }) => a == b,
        (_, HostAuthIdentity::Absent) => matches!(original.operation, HostIdentityWriteOperation::Logout { full: true })
            && receipt.outcome == HostIdentityWriteOutcome::Committed,
        _ => false,
    };
    anyhow::ensure!(compatible && super::control::identity(profile)? == receipt.identity, "identity receipt does not match the owned session");
    match receipt.outcome {
        HostIdentityWriteOutcome::Committed => {
            anyhow::ensure!(response.ok && response.exit == 0 && response.code.is_none() && response.error.is_none()
                && matches!(envelope.status, Status::Ok) && envelope.errors.is_empty(), "invalid committed identity outcome");
            match &original.operation {
                HostIdentityWriteOperation::Logout { full } => {
                    anyhow::ensure!(receipt.revoke.is_none() && (!*full || matches!(receipt.identity, HostAuthIdentity::Absent)), "invalid logout receipt");
                }
                HostIdentityWriteOperation::SessionRevoke { session_id } => {
                    let revoked = receipt.revoke.as_ref().context("session revoke receipt missing")?;
                    anyhow::ensure!(uuid::Uuid::parse_str(&revoked.session_id)? == uuid::Uuid::parse_str(session_id)?, "session revoke receipt ID mismatch");
                }
            }
        }
        HostIdentityWriteOutcome::Pending => anyhow::ensure!(response.ok && response.exit == 0
            && response.code.is_none() && response.error.is_none() && matches!(envelope.status, Status::Pending), "invalid pending identity outcome"),
        HostIdentityWriteOutcome::Unknown => anyhow::ensure!(!response.ok && response.exit == 2
            && response.code.as_deref() == Some("identity_write_outcome_unknown") && matches!(envelope.status, Status::Fail), "invalid unknown identity outcome"),
    }
    Ok(envelope)
}
