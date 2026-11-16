//! Key operations reuse login admission, credential checkpoints and recovery.
use super::*;
use std::io::Read;
use respire_protocol::key_control::*;
mod fivekeys;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct KeyOperation {
    operation: HostKeyOperation,
    source_identity: HostAuthIdentity,
    target: Option<PathBuf>,
    target_original_sha256: Option<String>,
    original_vault: Option<Value>,
    credential_ready: bool,
    required_inputs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fivekeys: Option<fivekeys::FivekeysProgress>,
}

// Compare existing directory identities without changing persisted path spellings.
fn same_directory(left: &Path, right: &Path) -> std::io::Result<bool> {
    let canonical = |path: &Path| -> std::io::Result<Option<PathBuf>> {
        match path.canonicalize() {
            Ok(path) => {
                if std::fs::metadata(&path)?.is_dir() { Ok(Some(path)) }
                else { Err(std::io::Error::new(std::io::ErrorKind::NotADirectory, "key target is not a directory")) }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    };
    Ok(match (canonical(left)?, canonical(right)?) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    })
}

fn operation(journal: &Journal, index: usize) -> Result<&KeyOperation> {
    journal.operations[index].key_operation.as_ref().context("key operation receipt is missing")
}

fn operation_mut(journal: &mut Journal, index: usize) -> Result<&mut KeyOperation> {
    journal.operations[index].key_operation.as_mut().context("key operation receipt is missing")
}

fn fingerprint(root: &Path, profile: &Path, source: &HostAuthIdentity, intent: &HostKeyOperation) -> Result<String> {
    // Factors remain supplemental material, not plaintext or password verifiers in the journal.
    Ok(digest(&serde_json::to_vec(&json!({"schema_version":HOST_KEY_SCHEMA_V,
        "method":"control.key", "root":root,"profile":profile,"source_identity":source,"operation":intent}))?))
}

fn selection(ownership: &AuthOwnership, id: &str, key: &str, params: &HostKeyParams) -> Result<()> {
    crate::service::require_profile_change_host()?;
    canonical_operation_id(id)?;
    ensure!(!key.is_empty() && key.len() <= 128 && key.bytes().all(|byte|
        byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)), "invalid key operation idempotency key");
    ensure!(params.schema_version == HOST_KEY_SCHEMA_V && params.binding.installation_root == ownership.root
        && params.binding.profile == ownership.profile && ownership.root == crate::service::main_data_dir().canonicalize()?
        && ownership.profile == crate::service::data_dir().canonicalize()?, "key operation selection changed");
    verify_locked_auth_identity(&ownership.root, &ownership.profile, &params.identity)
}

fn owned_index(journal: &Journal, root: &Path, profile: &Path, id: &str, key: &str,
    params: &HostKeyParams) -> Result<Option<usize>> {
    let Some(index) = journal.operations.iter().position(|record|
        record.operation_id == id || record.idempotency_key == key) else { return Ok(None); };
    let record = &journal.operations[index];
    let op = operation(journal, index)?;
    if let Some(active) = journal.active.as_ref().filter(|active| active.operation_id.as_deref() == Some(id)) {
        ensure!(active.backends.is_empty() && active.pass_backends.is_empty()
            && active.totp_backends.is_empty() && active.legacy_secret_backends.is_empty(),
            "host_recovery_required: historical key credential cleanup metadata retained");
    }
    let target_matches = match op.target.as_deref() {
        Some(target) => same_directory(target, profile)?,
        None => false,
    };
    ensure!(record.operation_id == id && record.idempotency_key == key && record.root == root
        && (record.profile == profile || target_matches)
        && record.account.is_none() && record.identity.is_none()
        && record.fingerprint == fingerprint(root, &record.profile, &params.source_identity, &params.operation)?
        && record.fingerprint == fingerprint(root, &record.profile, &op.source_identity, &op.operation)?,
        "key operation idempotency conflict");
    if !matches!(record.phase, AuthPhase::Committed | AuthPhase::RolledBack) {
        let active = journal.active.as_ref().context("key recovery is missing")?;
        ensure!(active.operation_id.as_deref() == Some(id) && active.alias == record.alias
            && active.directory == *op.target.as_ref().unwrap_or(&record.profile)
            && active.original.as_deref().map(digest) == if op.target.is_some() {
                op.target_original_sha256.clone()
            } else { record.original_sha256.clone() }, "key recovery owner mismatch");
    }
    let current = read_original(profile)?;
    let source_matches = record.profile == profile && (current.as_deref().map(digest) == record.original_sha256
        || recovery_credentials::matches_restored(record, profile, &current));
    let candidate_matches = target_matches && current.is_some() && current == record.candidate
        && matches!(record.phase, AuthPhase::Prepared | AuthPhase::AwaitingVerification | AuthPhase::Committed);
    let restoring_target = target_matches && (record.phase == AuthPhase::RollingBack
        && current.as_deref().map(digest) == op.target_original_sha256
        || recovery_credentials::matches_restored(record, profile, &current));
    ensure!(source_matches || candidate_matches || restoring_target, "key receipt no longer owns the selected session");
    Ok(Some(index))
}

fn admit(ownership: &AuthOwnership, id: &str, key: &str, params: &HostKeyParams) -> Result<(Journal, usize)> {
    let mut journal = load_journal()?;
    if let Some(index) = owned_index(&journal, &ownership.root, &ownership.profile, id, key, params)? { return Ok((journal, index)); }
    ensure!(journal.active.is_none(), "resolve the existing operation before admitting a key operation");
    ensure!(journal.operations.len() < 4096, "auth receipt capacity reached");
    ensure!(params.identity == params.source_identity, "key source identity differs from its initial launch");
    let original = read_original(&ownership.profile)?;
    let alias = format!("login-{}", id.replace('-', ""));
    journal.active = Some(Recovery { directory: ownership.profile.clone(), original: original.clone(), config: None,
        alias: alias.clone(), backends: Vec::new(), pass_backends: Vec::new(), totp_backends: Vec::new(),
        directory_existed: true, operation_id: Some(id.to_owned()), owns_config: false, ..Recovery::default() });
    let index = journal.operations.len();
    journal.operations.push(AuthRecord { operation_id: id.to_owned(), idempotency_key: key.to_owned(),
        fingerprint: fingerprint(&ownership.root, &ownership.profile, &params.source_identity, &params.operation)?,
        root: ownership.root.clone(), profile: ownership.profile.clone(), original_sha256: original.as_deref().map(digest),
        candidate: None, candidate_backup: None, candidate_sha256: None, restored: None, alias, backend: None, phase: AuthPhase::Admitted,
        account: None, identity: None, space_operation: None, profile_remove: None, key_operation: Some(KeyOperation { operation: params.operation.clone(),
            source_identity: params.source_identity.clone(), target: None, target_original_sha256: None,
            original_vault: None, credential_ready: false, required_inputs: Vec::new(), fivekeys: None }) });
    save_journal(&mut journal)?;
    Ok((journal, index))
}

fn require_inputs(journal: &mut Journal, index: usize, inputs: &[&str]) -> Result<()> {
    operation_mut(journal, index)?.required_inputs = inputs.iter().map(|input| (*input).to_owned()).collect();
    save_journal(journal)
}

fn candidate_session(record: &AuthRecord) -> Result<Value> {
    let bytes = record.candidate.as_deref().context("key candidate is missing")?;
    ensure!(record.candidate_sha256.as_deref() == Some(digest(bytes).as_str()), "key candidate digest mismatch");
    let session: Value = serde_json::from_slice(bytes)?;
    ensure!(session.is_object() && session["keyring_account"].as_str() == Some(record.alias.as_str())
        && session["keyring_backend"].as_str() == record.backend.as_deref()
        && session.get("pass").is_none() && session.get("super").is_none(), "key candidate credential binding changed");
    Ok(session)
}

fn factor_keys(session: &Value, input: &HostKeyInput) -> Result<crate::memory::SessionKeys> {
    let field = |name: &str| session[name].as_str().with_context(|| format!("key vault is missing {name}"));
    let salt = field("kdf_salt")?;
    let wrapped = field("wrapped_urk")?;
    let nonce = field("urk_nonce")?;
    let version = match session.get("vault_version") {
        None => 1,
        Some(value) => value.as_i64().context("invalid key vault version")?,
    };
    let keys = match version {
        1 => crate::memory::SessionKeys::unlock(input.password.as_deref().context("explicit key password required")?,
            input.account_secret.as_deref().context("explicit Account Secret required")?, salt, wrapped, nonce),
        2 => crate::memory::SessionKeys::unlock_super(input.super_password.as_deref().context("explicit Super Key required")?, salt, wrapped, nonce),
        3 => crate::memory::SessionKeys::unlock_vault(input.super_password.as_deref().context("explicit Super Key required")?,
            input.account_secret.as_deref().context("explicit Secret Key required")?, salt, wrapped, nonce),
        4 => crate::memory::SessionKeys::unlock_v4(input.super_password.as_deref().context("explicit Super Key required")?, salt, wrapped, nonce),
        _ => anyhow::bail!("unsupported key vault version"),
    }?;
    if session["crypto_namespace"].as_str() == Some(crate::memory::crypto::RSRS_PREFIX) {
        crate::memory::SessionKeys::from_urk(keys.urk)
    } else { Ok(keys) }
}

fn candidate_keys(record: &AuthRecord, input: &HostKeyInput) -> Result<crate::memory::SessionKeys> {
    let session = candidate_session(record)?;
    let material = input.material.as_ref().context("host key material required")?;
    ensure!(material.keyring_account == record.alias
        && Some(material.keyring_backend.as_str()) == record.backend.as_deref(), "host key custody binding changed");
    if let Some(reset) = material.reset.as_ref() {
        ensure!(session["kdf_salt"].as_str() == Some(reset.kdf_salt.as_str())
            && session["wrapped_urk"].as_str() == Some(reset.wrapped_urk.as_str())
            && session["urk_nonce"].as_str() == Some(reset.urk_nonce.as_str()), "host reset candidate changed");
        let factors = HostKeyInput { super_password: Some(reset.super_password.clone()), ..HostKeyInput::default() };
        factor_keys(&session, &factors)
    } else { factor_keys(&session, input) }
}

pub(super) fn verify_unbound_candidate(journal: &Journal, record: &AuthRecord, profile: &Path, credentials: bool) -> Result<()> {
    let op = record.key_operation.as_ref().context("offline recovery receipt missing")?;
    let HostKeyOperation::Fivekeys { addr, user, kdf_salt, wrapped_urk, urk_nonce, use_super } = &op.operation
        else { anyhow::bail!("unbound recovery is not a fivekeys operation"); };
    ensure!(addr.trim().is_empty() && user.is_empty() && op.credential_ready
        && same_directory(op.target.as_deref().context("offline recovery target missing")?, profile)?
        && record.fingerprint == fingerprint(&record.root, &record.profile, &op.source_identity, &op.operation)?,
        "offline recovery intent or target changed");
    if record.phase != AuthPhase::Committed {
        let active = journal.active.as_ref().context("offline recovery owner missing")?;
        ensure!(matches!(record.phase, AuthPhase::Prepared | AuthPhase::AwaitingVerification)
            && active.operation_id.as_deref() == Some(record.operation_id.as_str())
            && same_directory(&active.directory, profile)? && active.alias == record.alias && active.owns_config
            && recovery_credentials::original_digest(active)? == op.target_original_sha256,
            "offline recovery no longer owns its candidate");
        verify_account_config(active)?;
    }
    let session = candidate_session(record)?;
    let version = session["vault_version"].as_i64().context("offline recovery version missing")?;
    let object = session.as_object().context("offline recovery session must be an object")?;
    ensure!(session["user"] == "" && session["addr"] == ""
        && session["auth_operation_id"].as_str() == Some(record.operation_id.as_str())
        && session["kdf_salt"].as_str() == Some(kdf_salt.as_str())
        && session["wrapped_urk"].as_str() == Some(wrapped_urk.as_str())
        && session["urk_nonce"].as_str() == Some(urk_nonce.as_str())
        && if *use_super { matches!(version, 2 | 4) } else { version == 1 },
        "offline recovery candidate differs from the supplied kit");
    ensure!(object.len() == (if version == 1 { 10 } else { 9 })
        && object.keys().all(|field| matches!(field.as_str(), "user" | "addr" | "vault_version"
            | "kdf_salt" | "wrapped_urk" | "urk_nonce" | "keyring_account" | "keyring_backend" | "auth_operation_id")
            || (version == 1 && field == "legacy_secret_backend")), "offline recovery contains unexpected identity material");
    // Startup checks the durable binding; private key requests verify explicit factors.
    let _ = credentials;
    Ok(())
}

pub(super) fn verify_boot_candidate(record: &AuthRecord, active: &Recovery) -> Result<()> {
    let op = record.key_operation.as_ref().context("key boot receipt missing")?;
    ensure!(matches!(op.operation, HostKeyOperation::Fivekeys { .. }) && op.credential_ready
        && record.phase == AuthPhase::AwaitingVerification && active.owns_config
        && record.root == crate::service::main_data_dir().canonicalize()?
        && op.target.as_deref() == Some(active.directory.as_path())
        && active.directory.canonicalize()? == crate::service::data_dir().canonicalize()?
        && active.alias == record.alias && read_original(&active.directory)? == record.candidate,
        "runtime verification does not own the active fivekeys candidate");
    verify_account_config(active)?;
    candidate_session(record)?;
    require_persistent_auth_backend(record.backend.as_deref().context("key backend is missing")?)
}

fn supplied_credentials(journal: &mut Journal, index: usize, session: &mut Value,
    input: &HostKeyInput) -> Result<()> {
    let material = input.material.as_ref().context("host key material required")?;
    ensure!(material.keyring_account == journal.operations[index].alias,
        "host credential account differs from the key operation");
    require_persistent_auth_backend(&material.keyring_backend)?;
    session["keyring_account"] = json!(material.keyring_account);
    session["keyring_backend"] = json!(material.keyring_backend);
    if session["vault_version"].as_i64() == Some(1) {
        session["legacy_secret_backend"] = json!(material.keyring_backend);
    }
    journal.operations[index].backend = Some(material.keyring_backend.clone());
    checkpoint_account_candidate(journal, index, session)?;
    candidate_keys(&journal.operations[index], input)?;
    operation_mut(journal, index)?.credential_ready = true;
    save_journal(journal)
}

fn read_cloud_vault(addr: &str, token: &str) -> Result<Value> {
    let response = match ureq::AgentBuilder::new().redirects(0).timeout(std::time::Duration::from_secs(30)).build()
        .get(&format!("{}/api/self/vault", addr.trim().trim_end_matches('/')))
        .set("Authorization", &format!("Bearer {token}")).call() {
        Ok(response) => response,
        Err(ureq::Error::Status(404, _)) => return Ok(Value::Null),
        Err(_) => anyhow::bail!("key vault read failed"),
    };
    let limit = respire_protocol::host_control::HOST_CONTROL_MAX_FRAME_BYTES;
    let mut bytes = Vec::new();
    response.into_reader().take(limit as u64 + 1).read_to_end(&mut bytes).map_err(|_| anyhow!("key vault response incomplete"))?;
    ensure!(bytes.len() <= limit, "key vault response exceeds the control limit");
    let response: Value = serde_json::from_slice(&bytes).map_err(|_| anyhow!("invalid key vault response"))?;
    ensure!(response["version"].as_i64().is_some_and(|version| (1..=4).contains(&version)), "invalid key vault version");
    for field in ["kdf_salt", "wrapped_urk", "urk_nonce"] {
        ensure!(response[field].as_str().is_some_and(|value| !value.is_empty()), "incomplete key vault response");
    }
    Ok(json!({"version":response["version"],"kdf_salt":response["kdf_salt"],
        "wrapped_urk":response["wrapped_urk"],"urk_nonce":response["urk_nonce"]}))
}

fn vault(session: &Value) -> Value {
    json!({"version":session["vault_version"],"kdf_salt":session["kdf_salt"],
        "wrapped_urk":session["wrapped_urk"],"urk_nonce":session["urk_nonce"]})
}

fn reset_address(intent: &HostKeyOperation, source: &Value) -> Result<String> {
    let HostKeyOperation::SuperReset { addr } = intent else { anyhow::bail!("not a super-reset operation"); };
    Ok(addr.as_deref().map(str::trim).filter(|value| !value.is_empty())
        .or_else(|| source["addr"].as_str()).unwrap_or(crate::service::DEFAULT_SERVER_ADDR).trim_end_matches('/').to_owned())
}

fn reconcile_reset(journal: &mut Journal, index: usize, input: &HostKeyInput) -> Result<()> {
    if !matches!(operation(journal, index)?.operation, HostKeyOperation::SuperReset { .. }) { return Ok(()); }
    let record = &journal.operations[index];
    if !matches!(record.phase, AuthPhase::RemotePending | AuthPhase::RemoteUnknown) { return Ok(()); }
    let op = operation(journal, index)?;
    let candidate = candidate_session(record)?;
    candidate_keys(record, input)?;
    let addr = reset_address(&op.operation, &candidate)?;
    let token = candidate["token"].as_str().filter(|value| !value.is_empty()).context("reset token missing")?;
    if read_cloud_vault(&addr, token).is_ok_and(|current| current == vault(&candidate)) {
        journal.operations[index].phase = AuthPhase::Prepared;
    } else { journal.operations[index].phase = AuthPhase::RemoteUnknown; }
    save_journal(journal)
}

fn prepare_reset(journal: &mut Journal, index: usize, input: &HostKeyInput) -> Result<()> {
    if journal.operations[index].candidate.is_some() {
        ensure!(operation(journal, index)?.credential_ready, "candidate credential checkpoint is incomplete; retain the original operation");
        candidate_keys(&journal.operations[index], input)?;
        return Ok(());
    }
    let original = journal.active.as_ref().context("reset recovery is missing")?.original.as_deref().context("no local session")?;
    let mut session: Value = serde_json::from_slice(original)?;
    let user = session["user"].as_str().filter(|value| !value.is_empty()).context("super-reset needs an account")?.to_owned();
    let password = input.password.clone();
    if session["vault_version"].as_i64().unwrap_or(1) == 1 && password.is_none() {
        return require_inputs(journal, index, &["password"]);
    }
    if session["vault_version"].as_i64().unwrap_or(1) != 1 && input.super_password.is_none() {
        return require_inputs(journal, index, &["super_password"]);
    }
    let keys = factor_keys(&session, input)?;
    let addr = reset_address(&operation(journal, index)?.operation, &session)?;
    let token = session["token"].as_str().filter(|value| !value.is_empty()).context("not logged in; log in before resetting the super password")?;
    let original_vault = read_cloud_vault(&addr, token)?;
    if !original_vault.is_null() {
        let mut remote = session.clone();
        remote["vault_version"] = original_vault["version"].clone();
        for field in ["kdf_salt", "wrapped_urk", "urk_nonce"] { remote[field] = original_vault[field].clone(); }
        let remote_keys = factor_keys(&remote, input)?;
        ensure!(remote_keys.urk == keys.urk, "remote vault uses a different data key; reset refused");
    }
    let material = input.material.as_ref().context("host key material required")?;
    let reset = material.reset.as_ref().context("host-generated reset material required")?;
    ensure!(reset.keyring_account == material.keyring_account && reset.keyring_backend == material.keyring_backend,
        "reset credential binding changed");
    session["vault_version"] = json!(4);
    session["kdf_salt"] = json!(reset.kdf_salt);
    session["wrapped_urk"] = json!(reset.wrapped_urk);
    session["urk_nonce"] = json!(reset.urk_nonce);
    for field in ["pass", "super", "secret_key", "secret", "legacy_secret_backend"] { session.as_object_mut().map(|object| object.remove(field)); }
    let target = journal.operations[index].profile.clone();
    let original_sha256 = journal.operations[index].original_sha256.clone();
    let op = operation_mut(journal, index)?;
    op.target = Some(target); op.target_original_sha256 = original_sha256;
    op.original_vault = Some(original_vault); op.required_inputs.clear();
    ensure!(factor_keys(&session, &HostKeyInput { super_password: Some(reset.super_password.clone()),
        ..HostKeyInput::default() })?.urk == keys.urk, "reset candidate changed the data key");
    supplied_credentials(journal, index, &mut session, input)?;
    Ok(())
}

fn execute_reset(journal: &mut Journal, index: usize, input: &HostKeyInput) -> Result<()> {
    if journal.operations[index].phase == AuthPhase::Admitted {
        prepare_reset(journal, index, input)?;
        if !operation(journal, index)?.required_inputs.is_empty() { return Ok(()); }
        let session = candidate_session(&journal.operations[index])?;
        let addr = reset_address(&operation(journal, index)?.operation, &session)?;
        let token = session["token"].as_str().context("reset token missing")?;
        ensure!(Some(read_cloud_vault(&addr, token)?) == operation(journal, index)?.original_vault,
            "remote vault changed before reset; retain the candidate and original receipt");
        journal.operations[index].phase = AuthPhase::RemotePending;
        save_journal(journal)?;
        let agent = ureq::AgentBuilder::new().redirects(0).timeout(std::time::Duration::from_secs(30)).build();
        let mut request = agent.post(&format!("{addr}/api/self/vault")).set("Authorization", &format!("Bearer {token}"));
        if operation(journal, index)?.original_vault.as_ref().is_some_and(Value::is_null) { request = request.set("If-None-Match", "*"); }
        // Even an HTTP success is verified by GET. Neither failure nor timeout replays POST.
        let _response = request.send_json(vault(&session));
    }
    reconcile_reset(journal, index, input)
}

fn apply_candidate(ownership: &AuthOwnership, journal: &mut Journal, index: usize, input: &HostKeyInput) -> Result<()> {
    ensure!(journal.operations[index].phase == AuthPhase::Prepared, "key operation is not prepared");
    crate::service::ensure_writable()?;
    let record = &journal.operations[index];
    let op = operation(journal, index)?;
    ensure!(op.credential_ready, "key candidate credential checkpoint incomplete");
    candidate_keys(record, input)?;
    let target = op.target.as_ref().context("key target missing")?.clone();
    let _target_lock = if same_directory(&target, &ownership.root)? || same_directory(&target, &ownership.profile)? { None }
        else { Some(crate::lock::LibraryLock::acquire(&target, std::time::Duration::from_secs(1))?) };
    let active = journal.active.as_ref().context("key recovery missing")?;
    ensure!(active.operation_id.as_deref() == Some(record.operation_id.as_str()) && active.directory == target
        && active.alias == record.alias, "key commit recovery mismatch");
    let current = read_original(&target)?;
    ensure!(current == record.candidate || current == active.original, "key target changed outside its transaction");
    if active.owns_config { verify_account_config(active)?; }
    std::fs::create_dir_all(&target)?;
    private_write(&target.join("session.json"), record.candidate.as_deref().context("key candidate missing")?)?;
    if matches!(op.operation, HostKeyOperation::Fivekeys { .. }) {
        ensure!(active.owns_config, "fivekeys does not own the selection checkpoint");
        crate::service::set_data_dir(&target.to_string_lossy())?;
        journal.operations[index].phase = AuthPhase::AwaitingVerification;
        return save_journal(journal);
    }
    journal.operations[index].phase = AuthPhase::Committed;
    retire_active(journal)
}

fn result(journal: &Journal, index: usize, input: &HostKeyInput) -> Result<HostKeyResult> {
    let record = &journal.operations[index];
    let op = operation(journal, index)?;
    let applied = matches!(record.phase, AuthPhase::Committed | AuthPhase::AwaitingVerification);
    let current = read_original(&crate::service::data_dir())?;
    let identity = match current.as_deref() {
        None => HostAuthIdentity::Absent,
        Some(bytes) => {
            let session: Value = serde_json::from_slice(bytes)?;
            if let Some(user) = session["user"].as_str().filter(|user| !user.is_empty()) {
                HostAuthIdentity::Bound { account_id: digest(user.as_bytes()), session_sha256: digest(bytes) }
            } else if applied {
                HostAuthIdentity::Unbound { operation_id: record.operation_id.clone(), session_sha256: digest(bytes) }
            } else { op.source_identity.clone() }
        }
    };
    verify_locked_auth_identity(&record.root, &crate::service::data_dir().canonicalize()?, &identity)?;
    let target_profile = if applied {
        let target = op.target.as_ref().context("key result target missing")?;
        ensure!(read_original(target)? == record.candidate, "key result candidate changed");
        candidate_keys(record, input)?;
        Some(target.canonicalize()?)
    } else { op.target.clone() };
    let session = if applied { Some(candidate_session(record)?) } else { None };
    Ok(HostKeyResult { operation_id: record.operation_id.clone(), fingerprint: record.fingerprint.clone(), operation: op.operation.clone(),
        outcome: match record.phase {
            AuthPhase::Committed => HostKeyOutcome::Committed,
            AuthPhase::RolledBack => HostKeyOutcome::RolledBack,
            AuthPhase::RemotePending | AuthPhase::RemoteUnknown => HostKeyOutcome::Unknown,
            _ if !op.required_inputs.is_empty() => HostKeyOutcome::AwaitingInput,
            _ => HostKeyOutcome::Pending,
        }, source_profile: record.profile.clone(), target_profile,
        account_id: session.as_ref().and_then(|session| session["user"].as_str().filter(|user| !user.is_empty()).map(|user| digest(user.as_bytes()))),
        session_sha256: if applied { record.candidate_sha256.clone() } else { None }, identity,
        required_inputs: op.required_inputs.clone(), verification_required: record.phase == AuthPhase::AwaitingVerification,
        super_password: if applied && matches!(op.operation, HostKeyOperation::SuperReset { .. }) {
            Some(input.material.as_ref().and_then(|material| material.reset.as_ref())
                .context("host reset material required for private result")?.super_password.clone())
        } else { None },
        challenge: None,
    })
}

pub fn control_key(ownership: &AuthOwnership, id: &str, key: &str, params: &HostKeyParams) -> Result<HostKeyResult> {
    selection(ownership, id, key, params)?;
    crate::service::ensure_writable()?;
    let (mut journal, index) = admit(ownership, id, key, params)?;
    let defaults = HostKeyInput::default();
    let input = params.input.as_ref().unwrap_or(&defaults);
    let challenge = match &params.operation {
        HostKeyOperation::SuperReset { .. } => { execute_reset(&mut journal, index, input)?; None }
        HostKeyOperation::Fivekeys { .. } => fivekeys::execute(ownership, &mut journal, index, input)?,
    };
    if journal.operations[index].phase == AuthPhase::Prepared { apply_candidate(ownership, &mut journal, index, input)?; }
    let mut receipt = result(&journal, index, input)?;
    receipt.challenge = challenge;
    Ok(receipt)
}

pub fn control_key_result(ownership: &AuthOwnership, id: &str, key: &str, params: &HostKeyParams) -> Result<HostKeyResult> {
    let defaults = HostKeyInput::default();
    let input = params.input.as_ref().unwrap_or(&defaults);
    selection(ownership, id, key, params)?;
    let mut journal = load_journal()?;
    let index = owned_index(&journal, &ownership.root, &ownership.profile, id, key, params)?.context("key admission receipt missing")?;
    reconcile_reset(&mut journal, index, input)?;
    if matches!(operation(&journal, index)?.operation, HostKeyOperation::Fivekeys { .. }) {
        fivekeys::resume_candidate(&mut journal, index, input)?;
    }
    if journal.operations[index].phase == AuthPhase::Prepared { apply_candidate(ownership, &mut journal, index, input)?; }
    result(&journal, index, input)
}

/// The caller verifies the live target Runtime independently. No library lock is
/// acquired here because the verified Runtime already owns the selected store.
pub fn control_key_complete(root: &Path, profile: &Path, id: &str, key: &str, params: &HostKeyParams,
    mut verify_runtime: impl FnMut(&HostKeyResult) -> Result<()>) -> Result<HostKeyResult> {
    let defaults = HostKeyInput::default();
    let input = params.input.as_ref().unwrap_or(&defaults);
    crate::service::require_profile_change_host()?;
    canonical_operation_id(id)?;
    ensure!(!key.is_empty() && key.len() <= 128 && key.bytes().all(|byte|
        byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)), "invalid key idempotency key");
    let root = root.canonicalize()?;
    let profile = profile.canonicalize()?;
    ensure!(params.schema_version == HOST_KEY_SCHEMA_V && params.binding.installation_root == root
        && params.binding.profile == profile && root == crate::service::main_data_dir().canonicalize()?
        && profile == crate::service::data_dir().canonicalize()?, "key completion selection changed");
    let _journal_lock = auth_journal_lock()?;
    verify_locked_auth_identity(&root, &profile, &params.identity)?;
    let mut journal = load_journal()?;
    let index = owned_index(&journal, &root, &profile, id, key, params)?.context("key completion receipt missing")?;
    ensure!(matches!(operation(&journal, index)?.operation, HostKeyOperation::Fivekeys { .. })
        && same_directory(operation(&journal, index)?.target.as_deref().context("key completion target missing")?, &profile)?, "key completion target mismatch");
    if journal.operations[index].phase == AuthPhase::Committed { return result(&journal, index, input); }
    ensure!(journal.operations[index].phase == AuthPhase::AwaitingVerification, "key candidate is not awaiting verification");
    let active = journal.active.as_ref().context("key completion recovery missing")?;
    ensure!(active.owns_config && same_directory(&active.directory, &profile)?, "key completion configuration owner changed");
    verify_account_config(active)?;
    verify_runtime(&result(&journal, index, input)?)?;
    journal.operations[index].phase = AuthPhase::Committed;
    retire_active(&mut journal)?;
    result(&journal, index, input)
}

/// Re-read the durable receipt after releasing execution ownership. A serialized
/// target alone is never authority to change the consumed launch context.
pub fn verify_key_receipt(root: &Path, profile: &Path, id: &str, key: &str,
    params: &HostKeyParams, receipt: &HostKeyResult) -> Result<()> {
    let defaults = HostKeyInput::default();
    let input = params.input.as_ref().unwrap_or(&defaults);
    let _journal_lock = auth_journal_lock()?;
    let journal = load_journal()?;
    let index = owned_index(&journal, root, profile, id, key, params)?.context("key receipt owner missing")?;
    if let Some(challenge) = receipt.challenge.as_deref() {
        fivekeys::verify_supplied_challenge(&journal, index, challenge)?;
    }
    let mut expected = result(&journal, index, input)?;
    expected.challenge = receipt.challenge.clone();
    ensure!(serde_json::to_value(expected)? == serde_json::to_value(receipt)?,
        "key result differs from its durable owner receipt");
    Ok(())
}

pub fn control_key_rollback(mut ownership: AuthOwnership, id: &str, key: &str, params: &HostKeyParams) -> Result<HostKeyResult> {
    let defaults = HostKeyInput::default();
    let input = params.input.as_ref().unwrap_or(&defaults);
    selection(&ownership, id, key, params)?;
    crate::service::ensure_writable()?;
    let mut journal = load_journal()?;
    let index = owned_index(&journal, &ownership.root, &ownership.profile, id, key, params)?.context("key receipt missing")?;
    if journal.operations[index].phase == AuthPhase::RolledBack { return result(&journal, index, input); }
    ensure!(!matches!(journal.operations[index].phase, AuthPhase::Committed | AuthPhase::RemotePending | AuthPhase::RemoteUnknown),
        "committed or unknown remote key effects cannot be compensated");
    ensure!(matches!(journal.operations[index].phase, AuthPhase::Admitted | AuthPhase::RollingBack)
        || matches!(operation(&journal, index)?.operation, HostKeyOperation::Fivekeys { .. })
            && matches!(journal.operations[index].phase, AuthPhase::LoginInput | AuthPhase::Authorized
                | AuthPhase::Prepared | AuthPhase::AwaitingVerification), "published reset cannot be compensated");
    let active = journal.active.as_ref().context("key rollback recovery missing")?;
    let target = active.directory.clone();
    let target_lock = if !target.try_exists()? || same_directory(&target, &ownership.root)?
        || same_directory(&target, &ownership.profile)? { None }
        else { Some(crate::lock::LibraryLock::acquire(&target, std::time::Duration::from_secs(1))?) };
    let current = read_original(&target)?;
    ensure!(recovery_credentials::matches_original(active, &current) || current == journal.operations[index].candidate,
        "key rollback target changed");
    if active.owns_config { verify_account_config(active)?; }
    journal.operations[index].phase = AuthPhase::RollingBack;
    save_journal(&mut journal)?;
    rollback_record_inner(&mut journal, false)?;
    drop(target_lock);
    if let Some(active) = journal.active.as_ref() {
        if !active.directory_existed && same_directory(&active.directory, &ownership.profile)? {
            drop(ownership._profile_lock.take());
        }
    }
    quarantine_new_profile(journal.active.as_ref().context("key recovery missing")?)?;
    journal.operations[index].phase = AuthPhase::RolledBack;
    retire_active(&mut journal)?;
    result(&journal, index, input)
}

#[cfg(test)]
pub(super) fn assert_existing_recovery(root: &Path) -> Result<()> {
    let ownership = AuthOwnership::acquire(root, root)?;
    let secret = crate::memory::crypto::generate_secret_key();
    let (salt, wrapped, nonce) = crate::auth::wrap_with_v4(&secret, &crate::memory::crypto::generate_key())?;
    let original = serde_json::to_vec(&json!({"user":"reset-fixture", "addr":"https://never-contact.invalid",
        "token":"synthetic-unused-token", "vault_version":4,"kdf_salt":salt,"wrapped_urk":wrapped,"urk_nonce":nonce}))?;
    private_write(&root.join("session.json"), &original)?;
    let identity = HostAuthIdentity::Bound { account_id: digest(b"reset-fixture"), session_sha256: digest(&original) };
    let mut params = HostKeyParams { schema_version: HOST_KEY_SCHEMA_V,
        binding: respire_protocol::ControlBinding { installation_root: root.to_owned(), profile: root.to_owned(),
            launch_id: uuid::Uuid::new_v4().to_string(), expected_account_id: Some(digest(b"reset-fixture")) },
        identity: identity.clone(), source_identity: identity, operation: HostKeyOperation::SuperReset { addr: None },
        input: Some(HostKeyInput { super_password: Some(secret.clone()), ..HostKeyInput::default() }) };
    let mut invalid = serde_json::to_value(&params)?;
    invalid["argv"] = json!(["unsupported"]);
    assert!(serde_json::from_value::<HostKeyParams>(invalid).is_err());
    let id = uuid::Uuid::new_v4().to_string();
    let (mut journal, index) = admit(&ownership, &id, &id, &params)?;
    let mut candidate: Value = serde_json::from_slice(&original)?;
    candidate["keyring_account"] = json!(journal.operations[index].alias);
    candidate["keyring_backend"] = json!("kernel");
    journal.operations[index].backend = Some("kernel".to_owned());
    checkpoint_account_candidate(&mut journal, index, &candidate)?;
    let op = operation_mut(&mut journal, index)?;
    op.target = Some(root.to_owned()); op.target_original_sha256 = Some(digest(&original));
    journal.operations[index].phase = AuthPhase::RemotePending;
    save_journal(&mut journal)?;
    let pending = std::fs::read(recovery_path())?;
    // An unrecoverable credential fails before GET/POST and cannot become success.
    assert!(control_key_result(&ownership, &id, &id, &params).is_err());
    assert!(control_key(&ownership, &id, &id, &params).is_err());
    assert_eq!(std::fs::read(recovery_path())?, pending);
    assert_eq!(std::fs::read(root.join("session.json"))?, original);
    params.operation = HostKeyOperation::SuperReset { addr: Some("https://other.invalid".into()) };
    assert!(control_key_result(&ownership, &id, &id, &params).is_err());
    params.operation = HostKeyOperation::SuperReset { addr: None };
    // Before any remote effect, a failed checkpoint is explicit and compensatable.
    journal.operations[index].phase = AuthPhase::Admitted;
    save_journal(&mut journal)?;
    let admitted = std::fs::read(recovery_path())?;
    assert!(control_key(&ownership, &id, &id, &params).is_err());
    assert_eq!(std::fs::read(recovery_path())?, admitted);
    assert!(control_key_result(&ownership, &id, "foreign-key", &params).is_err());
    assert!(control_key_rollback(ownership, &id, &id, &params)?.outcome == HostKeyOutcome::RolledBack);
    assert_eq!(std::fs::read(root.join("session.json"))?, original);
    assert!(!auth_recovery_pending()?);
    fivekeys::assert_existing_recovery(root)?;
    Ok(())
}
