//! Narrow ownership transfer, not keygen completion or permission to replay auth.
use super::*;
use respire_commands::output::Status;
use respire_protocol::{ControlBinding, HostAuthKeygenParams, HostAuthOutcome, HostAuthResult,
    RpcRequest, RpcResponse, HOST_AUTH_RESULT_METHOD, HOST_AUTH_SCHEMA_V};
use std::time::{Duration, Instant};

/// Input locators only. Neither this value nor the caller's claimed digest grants authority.
/// The live owner marker and an independently queried Runtime receipt must both match.
pub struct KeygenAccountTransfer {
    pub root: PathBuf,
    pub profile: PathBuf,
    pub original_operation_id: String,
    pub force: bool,
    pub token: String,
    pub coordinator: String,
    pub marker_sha256: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct KeygenSource {
    operation_id: String,
    force: bool,
    session_sha256: String,
}

/// Created only after reading back the durable account binding and active route.
/// No user credentials or recovery secret are included. Keep the owner token private.
pub struct KeygenAccountAdmission {
    operation_id: String,
    source_profile: PathBuf,
    root: PathBuf,
    keygen_operation_id: String,
    force: bool,
    session_sha256: String,
    maintenance_token: String,
}
impl KeygenAccountAdmission {
    pub fn operation_id(&self) -> &str { &self.operation_id }
    pub fn source_profile(&self) -> &Path { &self.source_profile }
    pub fn root(&self) -> &Path { &self.root }
    pub fn keygen_operation_id(&self) -> &str { &self.keygen_operation_id }
    pub fn force(&self) -> bool { self.force }
    pub fn session_sha256(&self) -> &str { &self.session_sha256 }
    // Used only for exact private-context retirement; never print or serialize this token.
    pub fn maintenance_token(&self) -> &str { &self.maintenance_token }
}

fn validate_input(takeover: &LibraryLock, source: &KeygenAccountTransfer) -> Result<()> {
    for id in [&source.original_operation_id, &source.token] {
        let parsed = uuid::Uuid::parse_str(id)?;
        anyhow::ensure!(parsed.get_version_num() == 4 && parsed.to_string() == *id,
            "keygen transfer requires original canonical operation and owner");
    }
    anyhow::ensure!(source.root.is_absolute() && source.profile.is_absolute()
        && source.root.canonicalize()? == source.root && source.profile.canonicalize()? == source.profile
        && takeover.protects(&source.root.join("runtime/takeover"))?, "keygen transfer scope or takeover mismatch");
    let (selected_root, _) = selected_roots()?;
    anyhow::ensure!(selected_root == source.root, "keygen transfer installation changed");
    Ok(())
}

fn matches_mapping(binding: &AccountBinding, source: &KeygenAccountTransfer,
    register: bool, user: &str, addr: &str) -> Result<()> {
    let keygen = binding.keygen_source.as_ref().context("active account is not this keygen transfer")?;
    anyhow::ensure!(binding.root == source.root && binding.source == source.profile
        && binding.maintenance_token == source.token && binding.register == register
        && binding.user == user && binding.addr == addr
        && keygen.operation_id == source.original_operation_id && keygen.force == source.force
        && matches!(&binding.original.identity, HostAuthIdentity::Unbound { operation_id, session_sha256 }
            if operation_id == &keygen.operation_id && session_sha256 == &keygen.session_sha256),
        "active account differs from the original keygen transfer; no new authentication admitted");
    anyhow::ensure!(keygen.session_sha256.len() == 64
        && keygen.session_sha256.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "keygen transfer digest is invalid");
    Ok(())
}

pub(crate) fn lookup_keygen_account(takeover: &LibraryLock, source: &KeygenAccountTransfer,
    register: bool, user: &str, addr: &str) -> Result<Option<KeygenAccountAdmission>> {
    validate_input(takeover, source)?;
    lookup_keygen_mapping(source, register, user, addr)
}

// Read-only routing inspection after the public caller has validated takeover and scope.
fn lookup_keygen_mapping(source: &KeygenAccountTransfer,
    register: bool, user: &str, addr: &str) -> Result<Option<KeygenAccountAdmission>> {
    let Some(id) = read_active(&source.root)? else { return Ok(None); };
    let path = respire_client_host::config::normalize_control_path(&binding_path(&source.root, &id)?)?;
    let bytes = private_io::bounded_bytes(&path, MAINTENANCE_MARKER_MAX_BYTES)?
        .context("original keygen account mapping is missing")?;
    let binding: AccountBinding = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid keygen account mapping"))?;
    let prior_bytes = marker_bytes(&source.root)?;
    let prior = prior_bytes.as_deref().map(parse_marker).transpose()?;
    validate_binding(&binding, &source.root, &source.profile, &id, register, prior.as_ref())?;
    matches_mapping(&binding, source, register, user, addr)?;
    let keygen = binding.keygen_source.context("keygen mapping disappeared")?;
    Ok(Some(KeygenAccountAdmission { operation_id: id, source_profile: binding.source,
        root: binding.root, keygen_operation_id: keygen.operation_id, force: keygen.force,
        session_sha256: keygen.session_sha256, maintenance_token: binding.maintenance_token }))
}

fn validate_live_marker(source: &KeygenAccountTransfer, marker: &Marker, bytes: &[u8],
    issuer: &str, registration: &RegistrationMode) -> Result<()> {
    anyhow::ensure!(hash(bytes) == source.marker_sha256 && marker.schema == 1
        && marker.id == source.coordinator && marker.id == registration.coordinator_id(&source.root)
        && marker.token == source.token && marker.phase == Phase::Paused
        && marker.expected_profile.as_deref() == Some(source.profile.as_path())
        && marker.expected_version == issuer && marker.snapshot.is_none() && marker.agent_config.is_none()
        && marker.owner_pid == std::process::id()
        && process_birth(marker.owner_pid)?.as_deref() == Some(marker.owner_birth.as_str()),
        "keygen transfer requires the exact live original Paused owner");
    Ok(())
}

pub(crate) fn prepare_keygen_account(takeover: &LibraryLock, host: Arc<dyn HostLifecycle>,
    source: &KeygenAccountTransfer, register: bool, user: &str, addr: &str,
) -> Result<KeygenAccountAdmission> {
    host.require_account_write()?;
    validate_input(takeover, source)?;
    // This path is checked first even after authentication changed selection or identity.
    // Once routed, uncertainty belongs to the new account O, never to another keygen.
    if let Some(admitted) = lookup_keygen_account(takeover, source, register, user, addr)? { return Ok(admitted); }
    anyhow::ensure!(!user.is_empty() && !addr.trim().is_empty(), "account transfer intent is incomplete");
    verify_selection(&source.root, &source.profile)?;
    anyhow::ensure!(current_boot_token().is_none(), "shared maintenance already has a live controller");
    ensure_no_owner(host.as_ref())?;
    let runtime = host.verified_runtime()?;
    runtime.revalidate()?;
    let registration = host.inspect_registration(&source.root)?;
    validate_registration_mode(&source.root, &registration)?;
    let bytes = marker_bytes(&source.root)?.context("keygen transfer marker missing")?;
    let marker = parse_marker(&bytes)?;
    validate_live_marker(source, &marker, &bytes, host.issuer_version(), &registration)?;
    let identity = crate::identity(&source.profile)?;
    anyhow::ensure!(matches!(&identity, HostAuthIdentity::Unbound { operation_id, .. }
        if operation_id == &source.original_operation_id), "keygen transfer needs its original unbound identity");
    // Adopt, but do not rewrite, the embedding's same-process live marker. The
    // original CLI context continues to recognize exactly these durable bytes.
    ACTIVE.with(|slot| *slot.borrow_mut() = Some(source.token.clone()));
    let owner = Maintenance { root: source.root.clone(), host, registration, marker,
        marker_digest: hash(&bytes), drained: true, original_health: None,
        account_origin: None, account_record: None, completed: false };
    let authority = owner.binding(&source.profile, LaunchPurpose::Account)?;
    let grant = crate::launch::prepare_grant(&runtime, &authority, &identity)?;
    let params = HostAuthKeygenParams { schema_version: HOST_AUTH_SCHEMA_V,
        binding: ControlBinding { installation_root: source.root.clone(), profile: source.profile.clone(),
            launch_id: grant.instance_id.clone(), expected_account_id: None }, identity: identity.clone(), force: source.force };
    let request = RpcRequest { v: crate::PROTOCOL_V, id: uuid::Uuid::new_v4().to_string(),
        method: HOST_AUTH_RESULT_METHOD.to_owned(), args: vec![serde_json::to_string(&params)?],
        scope: None, operation_id: Some(source.original_operation_id.clone()),
        idempotency_key: Some(source.original_operation_id.clone()), parent_operation_id: None,
        queue_wait_ms: None, lifecycle: None };
    let envelope = crate::exchange::exchange_control(runtime.path(), &grant, &request,
        Instant::now() + Duration::from_secs(12), |response, pid| validate_result(response, &request, pid, source, &identity))?;
    let receipt: HostAuthResult = serde_json::from_value(envelope.summary)
        .map_err(|_| anyhow::anyhow!("invalid original keygen receipt"))?;
    // Private recovery material is deliberately dropped, never put in admission records.
    drop(receipt.super_password);
    let session_sha256 = receipt.session_sha256.context("keygen transfer digest missing")?;
    owner.check_owner()?;
    runtime.revalidate()?;
    anyhow::ensure!(crate::identity(&source.profile)? == identity, "keygen transfer source changed after query");
    ensure_no_owner(owner.host.as_ref())?;
    let id = uuid::Uuid::new_v4().to_string();
    let binding = AccountBinding { schema: 1, operation_id: id.clone(), root: source.root.clone(),
        source: source.profile.clone(), register, user: user.to_owned(), addr: addr.to_owned(),
        maintenance_token: source.token.clone(), original: AccountOrigin { identity, was_serving: false, store_ready: false },
        sent: false, keygen_source: Some(KeygenSource { operation_id: source.original_operation_id.clone(),
            force: source.force, session_sha256 }) };
    // Durable mapping then active route, still no account RPC and no marker removal.
    private_write(&binding_path(&source.root, &id)?, &serde_json::to_vec(&binding)?, None)?;
    owner.check_owner()?;
    private_write(&active_path(&source.root), &serde_json::to_vec(&ActiveAccount { schema: 1, operation_id: id })?, None)?;
    lookup_keygen_account(takeover, source, register, user, addr)?
        .context("keygen account route did not persist")
}

fn validate_result(response: RpcResponse<respire_commands::output::ResultEnvelope>, request: &RpcRequest,
    pid: u32, source: &KeygenAccountTransfer, identity: &HostAuthIdentity,
) -> Result<respire_commands::output::ResultEnvelope> {
    anyhow::ensure!(response.v == request.v && response.id == request.id && response.bin == "rsrs-runtime"
        && response.pid == Some(pid) && response.operation_id == request.operation_id
        && response.idempotency_key == request.idempotency_key && response.scope.is_none() && response.web_url.is_none()
        && response.data_dir.as_deref().is_none_or(|path| Path::new(path) == source.profile)
        && response.ok && response.exit == 0 && response.code.is_none() && response.error.is_none(),
        "original keygen result is unknown; no account operation admitted");
    let envelope = response.envelope.context("original keygen receipt missing")?;
    anyhow::ensure!(envelope.command == "keygen" && matches!(envelope.status, Status::Ok)
        && envelope.errors.is_empty() && envelope.details.is_null() && envelope.actions.is_empty()
        && envelope.related.is_empty() && envelope.items.len() == 2, "original keygen result is not committed");
    for (name, value) in [("control_ready", "true"), ("store_ready", "false")] {
        let mut items = envelope.items.iter().filter(|item| item.name == name);
        anyhow::ensure!(items.next().is_some_and(|item| item.value == value && if name == "control_ready" {
            matches!(item.status, Status::Ok) } else { matches!(item.status, Status::Skip) }) && items.next().is_none(),
            "original keygen control readiness missing");
    }
    let receipt: HostAuthResult = serde_json::from_value(envelope.summary.clone())
        .map_err(|_| anyhow::anyhow!("invalid original keygen receipt"))?;
    anyhow::ensure!(receipt.outcome == HostAuthOutcome::Committed && receipt.operation_id == source.original_operation_id
        && receipt.path == source.profile.join("session.json")
        && matches!(identity, HostAuthIdentity::Unbound { operation_id, session_sha256 }
            if operation_id == &receipt.operation_id && receipt.session_sha256.as_ref() == Some(session_sha256))
        && receipt.super_password.as_deref().is_some_and(|secret| !secret.is_empty()),
        "original keygen receipt does not own this account source");
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (KeygenAccountTransfer, AccountBinding) {
        let operation_id = uuid::Uuid::new_v4().to_string();
        let token = uuid::Uuid::new_v4().to_string();
        let source = KeygenAccountTransfer {
            root: PathBuf::from("/installation"), profile: PathBuf::from("/installation/profile"),
            original_operation_id: operation_id.clone(), force: false,
            token: token.clone(), coordinator: "coordinator".into(), marker_sha256: "a".repeat(64),
        };
        let binding = AccountBinding {
            schema: 1, operation_id: uuid::Uuid::new_v4().to_string(), root: source.root.clone(),
            source: source.profile.clone(), register: true, user: "synthetic-user".into(),
            addr: "https://invalid.test".into(), maintenance_token: token,
            original: AccountOrigin { identity: HostAuthIdentity::Unbound {
                operation_id: operation_id.clone(), session_sha256: "b".repeat(64),
            }, was_serving: false, store_ready: false }, sent: false,
            keygen_source: Some(KeygenSource { operation_id, force: false, session_sha256: "b".repeat(64) }),
        };
        (source, binding)
    }

    #[test]
    fn persisted_mapping_is_stable_after_account_send() -> Result<()> {
        let (source, mut binding) = fixture();
        let id = binding.operation_id.clone();
        for sent in [false, true] {
            binding.sent = sent;
            let bytes = serde_json::to_vec(&binding)?;
            let recovered: AccountBinding = serde_json::from_slice(&bytes)?;
            matches_mapping(&recovered, &source, true, "synthetic-user", "https://invalid.test")?;
            assert_eq!(recovered.operation_id, id);
        }
        Ok(())
    }

    #[test]
    fn conflicting_original_or_account_intent_never_admitted() {
        let (mut source, binding) = fixture();
        assert!(matches_mapping(&binding, &source, false, "synthetic-user", "https://invalid.test").is_err());
        assert!(matches_mapping(&binding, &source, true, "other", "https://invalid.test").is_err());
        assert!(matches_mapping(&binding, &source, true, "synthetic-user", "https://other.invalid").is_err());
        source.force = true;
        assert!(matches_mapping(&binding, &source, true, "synthetic-user", "https://invalid.test").is_err());
        source.force = false;
        source.token = uuid::Uuid::new_v4().to_string();
        assert!(matches_mapping(&binding, &source, true, "synthetic-user", "https://invalid.test").is_err());
    }

    #[test]
    fn changed_identity_digest_or_original_operation_is_rejected() -> Result<()> {
        let (source, mut binding) = fixture();
        binding.keygen_source.as_mut().context("synthetic keygen source missing")?.session_sha256 = "c".repeat(64);
        assert!(matches_mapping(&binding, &source, true, "synthetic-user", "https://invalid.test").is_err());
        binding.keygen_source.as_mut().context("synthetic keygen source missing")?.session_sha256 = "b".repeat(64);
        binding.keygen_source.as_mut().context("synthetic keygen source missing")?.operation_id = uuid::Uuid::new_v4().to_string();
        assert!(matches_mapping(&binding, &source, true, "synthetic-user", "https://invalid.test").is_err());
        binding.keygen_source = None;
        assert!(matches_mapping(&binding, &source, true, "synthetic-user", "https://invalid.test").is_err());
        Ok(())
    }

    #[test]
    fn only_original_committed_receipt_admits_transfer() -> Result<()> {
        let (source, binding) = fixture();
        let request = RpcRequest { v: crate::PROTOCOL_V, id: "query".into(),
            method: HOST_AUTH_RESULT_METHOD.into(), args: vec![], scope: None,
            operation_id: Some(source.original_operation_id.clone()),
            idempotency_key: Some(source.original_operation_id.clone()),
            parent_operation_id: None, queue_wait_ms: None, lifecycle: None };
        let response = |outcome: HostAuthOutcome, operation_id: String, pid: u32| -> Result<RpcResponse<respire_commands::output::ResultEnvelope>> {
            let mut envelope = respire_commands::output::ResultEnvelope::new("keygen", Status::Ok,
                serde_json::to_value(HostAuthResult { operation_id, outcome,
                    session_sha256: Some("b".repeat(64)), path: source.profile.join("session.json"),
                    super_password: Some("synthetic-test-secret".into()) })?, vec![]);
            envelope.items = vec![respire_commands::output::Item::new("control_ready", Status::Ok, "true"),
                respire_commands::output::Item::new("store_ready", Status::Skip, "false")];
            Ok(RpcResponse { v: request.v, id: request.id.clone(), operation_id: request.operation_id.clone(),
                idempotency_key: request.idempotency_key.clone(), scope: None, ok: true, exit: 0,
                bin: "rsrs-runtime".into(), envelope: Some(envelope), error: None, code: None,
                web_url: None, pid: Some(pid), data_dir: None })
        };
        assert!(validate_result(response(HostAuthOutcome::Committed, source.original_operation_id.clone(), 42)?,
            &request, 42, &source, &binding.original.identity).is_ok());
        for outcome in [HostAuthOutcome::Unknown, HostAuthOutcome::RolledBack] {
            assert!(validate_result(response(outcome, source.original_operation_id.clone(), 42)?,
                &request, 42, &source, &binding.original.identity).is_err());
        }
        assert!(validate_result(response(HostAuthOutcome::Committed, uuid::Uuid::new_v4().to_string(), 42)?,
            &request, 42, &source, &binding.original.identity).is_err());
        assert!(validate_result(response(HostAuthOutcome::Committed, source.original_operation_id.clone(), 43)?,
            &request, 42, &source, &binding.original.identity).is_err());
        Ok(())
    }

    #[test]
    fn durable_routing_crash_windows_preserve_one_account_operation() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().canonicalize()?;
        let (mut source, mut binding) = fixture();
        source.root = root.clone();
        source.profile = root.clone();
        binding.root = root.clone();
        binding.source = root.clone();
        let file = binding_path(&root, &binding.operation_id)?;
        let initial = serde_json::to_vec(&binding)?;
        private_write(&file, &initial, None)?;
        // Crash before active publication: orphaned, unsent binding is not a route.
        assert!(lookup_keygen_mapping(&source, true, "synthetic-user", "https://invalid.test")?.is_none());
        assert!(pending_account(&root, true, "synthetic-user", "https://invalid.test")?.is_none());
        let pending = root.join("runtime/autostart/offline-keygen.json");
        private_write(&pending, b"synthetic pending evidence", None)?;
        private_write(&active_path(&root), &serde_json::to_vec(&ActiveAccount {
            schema: 1, operation_id: binding.operation_id.clone(),
        })?, None)?;
        // Crash after routing publication, before CLI retires its original context.
        // Repeated read-only inspection returns the same new O, even after send.
        for sent in [false, true] {
            if sent {
                binding.sent = true;
                private_write(&file, &serde_json::to_vec(&binding)?, Some(&hash(&initial)))?;
            }
            let before = fs::read(&file)?;
            for _ in 0..2 {
                let admission = lookup_keygen_mapping(&source, true, "synthetic-user", "https://invalid.test")?
                    .context("synthetic active route missing")?;
                assert_eq!(admission.operation_id(), binding.operation_id);
                assert_eq!(admission.keygen_operation_id(), source.original_operation_id);
            }
            assert_eq!(fs::read(&file)?, before);
            assert_eq!(fs::read(&pending)?, b"synthetic pending evidence");
            assert_eq!(fs::read_dir(file.parent().context("binding parent missing")?)?.count(), 1);
            assert!(reject_offline_keygen(&root).is_err());
        }
        let conflicting = Marker { schema: 1, id: source.coordinator.clone(),
            token: uuid::Uuid::new_v4().to_string(), phase: Phase::Paused,
            expected_profile: Some(root.clone()), expected_version: "synthetic".into(),
            owner_pid: std::process::id(), owner_birth: "synthetic".into(), snapshot: None, agent_config: None };
        private_write(&marker_path(&root), &serde_json::to_vec(&conflicting)?, None)?;
        assert!(lookup_keygen_mapping(&source, true, "synthetic-user", "https://invalid.test").is_err());
        assert_eq!(read_active(&root)?, Some(binding.operation_id));
        Ok(())
    }

    #[test]
    fn malformed_offline_context_fences_generic_recovery() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().canonicalize()?;
        fs::create_dir_all(root.join("runtime/autostart"))?;
        reject_offline_keygen(&root)?;
        fs::write(root.join("runtime/autostart/offline-keygen.json"), b"not-json")?;
        assert!(reject_offline_keygen(&root).is_err());
        Ok(())
    }
}
