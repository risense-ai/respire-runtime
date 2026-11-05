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
    verify_auth_identity(&ownership.root, &ownership.profile, &params.identity)
}

fn owned_index(journal: &Journal, root: &Path, profile: &Path, id: &str, key: &str,
    params: &HostKeyParams) -> Result<Option<usize>> {
    let Some(index) = journal.operations.iter().position(|record|
        record.operation_id == id || record.idempotency_key == key) else { return Ok(None); };
    let record = &journal.operations[index];
    let op = operation(journal, index)?;
    ensure!(record.operation_id == id && record.idempotency_key == key && record.root == root
        && (record.profile == profile || op.target.as_deref() == Some(profile))
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
    let source_matches = record.profile == profile && current.as_deref().map(digest) == record.original_sha256;
    let candidate_matches = op.target.as_deref() == Some(profile) && current.is_some() && current == record.candidate
        && matches!(record.phase, AuthPhase::Prepared | AuthPhase::AwaitingVerification | AuthPhase::Committed);
    let restoring_target = record.phase == AuthPhase::RollingBack && op.target.as_deref() == Some(profile)
        && current.as_deref().map(digest) == op.target_original_sha256;
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
    let alias = format!("login-{}", uuid::Uuid::new_v4().simple());
    journal.active = Some(Recovery { directory: ownership.profile.clone(), original: original.clone(), config: None,
        alias: alias.clone(), backends: Vec::new(), pass_backends: Vec::new(), totp_backends: Vec::new(),
        directory_existed: true, operation_id: Some(id.to_owned()), owns_config: false });
    let index = journal.operations.len();
    journal.operations.push(AuthRecord { operation_id: id.to_owned(), idempotency_key: key.to_owned(),
        fingerprint: fingerprint(&ownership.root, &ownership.profile, &params.source_identity, &params.operation)?,
        root: ownership.root.clone(), profile: ownership.profile.clone(), original_sha256: original.as_deref().map(digest),
        candidate: None, candidate_sha256: None, alias, backend: None, phase: AuthPhase::Admitted,
        account: None, identity: None, space_operation: None, profile_remove: None, key_operation: Some(KeyOperation { operation: params.operation.clone(),
            source_identity: params.source_identity.clone(), target: None, target_original_sha256: None,
            original_vault: None, credential_ready: false, required_inputs: Vec::new(), fivekeys: None }) });
    save_journal(&journal)?;
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

fn candidate_keys(record: &AuthRecord) -> Result<crate::memory::SessionKeys> {
    let session = candidate_session(record)?;
    let backend = record.backend.as_deref().context("key credential backend is missing")?;
    require_persistent_auth_backend(backend)?;
    let version = session["vault_version"].as_i64().context("key candidate version missing")?;
    let secret = if version == 1 { crate::keystore::read_imported_v1_password(&record.alias, backend)? }
        else { crate::keystore::read_imported(&record.alias, "super", backend)? };
    crate::auth::unlock_session_keys(&session, if version == 1 { &secret } else { "" },
        Some(if version == 1 { "" } else { &secret }), &record.alias)
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
    candidate_keys(record).map(|_| ())
}

fn checkpoint_credentials(journal: &mut Journal, index: usize, session: &mut Value,
    super_password: &str, password: Option<&str>) -> Result<()> {
    let alias = journal.operations[index].alias.clone();
    session["keyring_account"] = json!(alias);
    let version = session["vault_version"].as_i64().context("key candidate version missing")?;
    let (slot, secret) = if version == 1 { ("pass", password.context("original v1 password is required")?) }
        else { ("super", super_password) };
    let backend = crate::keystore::import_credential_checkpoint(&alias, slot, secret, |backend| {
        require_persistent_auth_backend(backend)?;
        let active = journal.active.as_mut().context("key recovery is missing")?;
        let backends = if version == 1 { &mut active.pass_backends } else { &mut active.backends };
        if !backends.iter().any(|existing| existing == backend) { backends.push(backend.to_owned()); }
        session["keyring_backend"] = json!(backend);
        journal.operations[index].backend = Some(backend.to_owned());
        checkpoint_account_candidate(journal, index, session)?;
        save_journal(journal)
    })?;
    ensure!(journal.operations[index].backend.as_deref() == Some(backend), "key backend checkpoint changed");
    if version != 1 {
        if let Some(password) = password.filter(|password| !password.is_empty()) {
            crate::keystore::import_credential_checkpoint(&alias, "pass", password, |backend| {
                require_persistent_auth_backend(backend)?;
                let active = journal.active.as_mut().context("key recovery is missing")?;
                if !active.pass_backends.iter().any(|existing| existing == backend) { active.pass_backends.push(backend.to_owned()); }
                save_journal(journal)
            })?;
        }
    }
    candidate_keys(&journal.operations[index])?;
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

fn reconcile_reset(journal: &mut Journal, index: usize) -> Result<()> {
    if !matches!(operation(journal, index)?.operation, HostKeyOperation::SuperReset { .. }) { return Ok(()); }
    let record = &journal.operations[index];
    if !matches!(record.phase, AuthPhase::RemotePending | AuthPhase::RemoteUnknown) { return Ok(()); }
    let op = operation(journal, index)?;
    let candidate = candidate_session(record)?;
    candidate_keys(record)?;
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
        candidate_keys(&journal.operations[index])?;
        return Ok(());
    }
    let original = journal.active.as_ref().context("reset recovery is missing")?.original.as_deref().context("no local session")?;
    let mut session: Value = serde_json::from_slice(original)?;
    let user = session["user"].as_str().filter(|value| !value.is_empty()).context("super-reset needs an account")?.to_owned();
    let alias = session["keyring_account"].as_str().unwrap_or(&user);
    let password = input.password.clone().or_else(|| session["pass"].as_str().map(str::to_owned))
        .or_else(|| crate::keystore::load_login_pass(alias));
    if session["vault_version"].as_i64().unwrap_or(1) == 1 && password.is_none() {
        return require_inputs(journal, index, &["password"]);
    }
    let keys = match crate::auth::unlock_session_keys(&session, password.as_deref().unwrap_or(""), input.super_password.as_deref(), alias) {
        Ok(keys) => keys,
        Err(error) if error.is::<crate::auth::SessionCredentialRequired>() => { return require_inputs(journal, index, &["super_password"]); }
        Err(error) => return Err(error),
    };
    let addr = reset_address(&operation(journal, index)?.operation, &session)?;
    let token = session["token"].as_str().filter(|value| !value.is_empty()).context("not logged in; log in before resetting the super password")?;
    let original_vault = read_cloud_vault(&addr, token)?;
    if !original_vault.is_null() {
        let mut remote = session.clone();
        remote["vault_version"] = original_vault["version"].clone();
        for field in ["kdf_salt", "wrapped_urk", "urk_nonce"] { remote[field] = original_vault[field].clone(); }
        let remote_keys = crate::auth::unlock_session_keys(&remote, password.as_deref().unwrap_or(""), input.super_password.as_deref(), alias)?;
        ensure!(remote_keys.urk == keys.urk, "remote vault uses a different data key; reset refused");
    }
    let secret = crate::memory::crypto::generate_secret_key();
    let (salt, wrapped, nonce) = if session["wrapped_urk"].as_str().is_some_and(|value| value.starts_with(crate::memory::crypto::RSRS_PREFIX))
        || session["crypto_namespace"].as_str() == Some(crate::memory::crypto::RSRS_PREFIX) {
        crate::auth::wrap_with_rsrs(&secret, &keys.urk)?
    } else { crate::auth::wrap_with_v4(&secret, &keys.urk)? };
    session["vault_version"] = json!(4); session["kdf_salt"] = json!(salt);
    session["wrapped_urk"] = json!(wrapped); session["urk_nonce"] = json!(nonce);
    for field in ["pass", "super", "secret_key", "secret"] { session.as_object_mut().map(|object| object.remove(field)); }
    let target = journal.operations[index].profile.clone();
    let original_sha256 = journal.operations[index].original_sha256.clone();
    let op = operation_mut(journal, index)?;
    op.target = Some(target); op.target_original_sha256 = original_sha256;
    op.original_vault = Some(original_vault); op.required_inputs.clear();
    checkpoint_credentials(journal, index, &mut session, &secret, password.as_deref())?;
    ensure!(candidate_keys(&journal.operations[index])?.urk == keys.urk, "reset candidate changed the data key");
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
    reconcile_reset(journal, index)
}

fn apply_candidate(ownership: &AuthOwnership, journal: &mut Journal, index: usize) -> Result<()> {
    ensure!(journal.operations[index].phase == AuthPhase::Prepared, "key operation is not prepared");
    crate::service::ensure_writable()?;
    let record = &journal.operations[index];
    let op = operation(journal, index)?;
    ensure!(op.credential_ready, "key candidate credential checkpoint incomplete");
    candidate_keys(record)?;
    let target = op.target.as_ref().context("key target missing")?.clone();
    let _target_lock = if target == ownership.root || target == ownership.profile { None }
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

fn result(journal: &Journal, index: usize) -> Result<HostKeyResult> {
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
            } else { op.source_identity.clone() }
        }
    };
    verify_auth_identity(&record.root, &crate::service::data_dir().canonicalize()?, &identity)?;
    if applied {
        let target = op.target.as_ref().context("key result target missing")?;
        ensure!(read_original(target)? == record.candidate, "key result candidate changed");
        candidate_keys(record)?;
    }
    let session = if applied { Some(candidate_session(record)?) } else { None };
    Ok(HostKeyResult { operation_id: record.operation_id.clone(), fingerprint: record.fingerprint.clone(), operation: op.operation.clone(),
        outcome: match record.phase {
            AuthPhase::Committed => HostKeyOutcome::Committed,
            AuthPhase::RolledBack => HostKeyOutcome::RolledBack,
            AuthPhase::RemotePending | AuthPhase::RemoteUnknown => HostKeyOutcome::Unknown,
            _ if !op.required_inputs.is_empty() => HostKeyOutcome::AwaitingInput,
            _ => HostKeyOutcome::Pending,
        }, source_profile: record.profile.clone(), target_profile: op.target.clone(),
        account_id: session.as_ref().and_then(|session| session["user"].as_str().map(|user| digest(user.as_bytes()))),
        session_sha256: if applied { record.candidate_sha256.clone() } else { None }, identity,
        required_inputs: op.required_inputs.clone(), verification_required: record.phase == AuthPhase::AwaitingVerification,
        super_password: if applied && matches!(op.operation, HostKeyOperation::SuperReset { .. }) {
            Some(crate::keystore::read_imported(&record.alias, "super", record.backend.as_deref().context("reset backend missing")?)?)
        } else { None },
    })
}

pub fn control_key(ownership: &AuthOwnership, id: &str, key: &str, params: &HostKeyParams) -> Result<HostKeyResult> {
    selection(ownership, id, key, params)?;
    crate::service::ensure_writable()?;
    let (mut journal, index) = admit(ownership, id, key, params)?;
    let defaults = HostKeyInput::default();
    let input = params.input.as_ref().unwrap_or(&defaults);
    match &params.operation {
        HostKeyOperation::SuperReset { .. } => execute_reset(&mut journal, index, input)?,
        HostKeyOperation::Fivekeys { .. } => fivekeys::execute(ownership, &mut journal, index, input)?,
    }
    if journal.operations[index].phase == AuthPhase::Prepared { apply_candidate(ownership, &mut journal, index)?; }
    result(&journal, index)
}

pub fn control_key_result(ownership: &AuthOwnership, id: &str, key: &str, params: &HostKeyParams) -> Result<HostKeyResult> {
    selection(ownership, id, key, params)?;
    let mut journal = load_journal()?;
    let index = owned_index(&journal, &ownership.root, &ownership.profile, id, key, params)?.context("key admission receipt missing")?;
    reconcile_reset(&mut journal, index)?;
    if matches!(operation(&journal, index)?.operation, HostKeyOperation::Fivekeys { .. }) {
        fivekeys::resume_candidate(&mut journal, index)?;
    }
    if journal.operations[index].phase == AuthPhase::Prepared { apply_candidate(ownership, &mut journal, index)?; }
    result(&journal, index)
}

/// The caller verifies the live target Runtime independently. No library lock is
/// acquired here because the verified Runtime already owns the selected store.
pub fn control_key_complete(root: &Path, profile: &Path, id: &str, key: &str, params: &HostKeyParams,
    mut verify_runtime: impl FnMut(&HostKeyResult) -> Result<()>) -> Result<HostKeyResult> {
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
    verify_auth_identity(&root, &profile, &params.identity)?;
    let mut journal = load_journal()?;
    let index = owned_index(&journal, &root, &profile, id, key, params)?.context("key completion receipt missing")?;
    ensure!(matches!(operation(&journal, index)?.operation, HostKeyOperation::Fivekeys { .. })
        && operation(&journal, index)?.target.as_deref() == Some(profile.as_path()), "key completion target mismatch");
    if journal.operations[index].phase == AuthPhase::Committed { return result(&journal, index); }
    ensure!(journal.operations[index].phase == AuthPhase::AwaitingVerification, "key candidate is not awaiting verification");
    let active = journal.active.as_ref().context("key completion recovery missing")?;
    ensure!(active.owns_config && active.directory == profile, "key completion configuration owner changed");
    verify_account_config(active)?;
    verify_runtime(&result(&journal, index)?)?;
    journal.operations[index].phase = AuthPhase::Committed;
    retire_active(&mut journal)?;
    result(&journal, index)
}

/// Re-read the durable receipt after releasing execution ownership. A serialized
/// target alone is never authority to change the consumed launch context.
pub fn verify_key_receipt(root: &Path, profile: &Path, id: &str, key: &str,
    params: &HostKeyParams, receipt: &HostKeyResult) -> Result<()> {
    let _journal_lock = auth_journal_lock()?;
    let journal = load_journal()?;
    let index = owned_index(&journal, root, profile, id, key, params)?.context("key receipt owner missing")?;
    ensure!(serde_json::to_value(result(&journal, index)?)? == serde_json::to_value(receipt)?,
        "key result differs from its durable owner receipt");
    Ok(())
}

pub fn control_key_rollback(mut ownership: AuthOwnership, id: &str, key: &str, params: &HostKeyParams) -> Result<HostKeyResult> {
    selection(&ownership, id, key, params)?;
    crate::service::ensure_writable()?;
    let mut journal = load_journal()?;
    let index = owned_index(&journal, &ownership.root, &ownership.profile, id, key, params)?.context("key receipt missing")?;
    if journal.operations[index].phase == AuthPhase::RolledBack { return result(&journal, index); }
    ensure!(!matches!(journal.operations[index].phase, AuthPhase::Committed | AuthPhase::RemotePending | AuthPhase::RemoteUnknown),
        "committed or unknown remote key effects cannot be compensated");
    ensure!(matches!(journal.operations[index].phase, AuthPhase::Admitted | AuthPhase::RollingBack)
        || matches!(operation(&journal, index)?.operation, HostKeyOperation::Fivekeys { .. })
            && matches!(journal.operations[index].phase, AuthPhase::LoginInput | AuthPhase::Authorized
                | AuthPhase::Prepared | AuthPhase::AwaitingVerification), "published reset cannot be compensated");
    let active = journal.active.as_ref().context("key rollback recovery missing")?;
    let target = active.directory.clone();
    let target_lock = if target == ownership.root || target == ownership.profile || !target.exists() { None }
        else { Some(crate::lock::LibraryLock::acquire(&target, std::time::Duration::from_secs(1))?) };
    let current = read_original(&target)?;
    ensure!(current == active.original || current == journal.operations[index].candidate, "key rollback target changed");
    if active.owns_config { verify_account_config(active)?; }
    journal.operations[index].phase = AuthPhase::RollingBack;
    save_journal(&journal)?;
    rollback_record_inner(journal.active.as_ref().context("key recovery missing")?, false)?;
    drop(target_lock);
    if journal.active.as_ref().is_some_and(|active| !active.directory_existed && active.directory == ownership.profile) {
        drop(ownership._profile_lock.take());
    }
    quarantine_new_profile(journal.active.as_ref().context("key recovery missing")?)?;
    journal.operations[index].phase = AuthPhase::RolledBack;
    retire_active(&mut journal)?;
    result(&journal, index)
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
    save_journal(&journal)?;
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
    save_journal(&journal)?;
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
