//! Fivekeys uses the key receipt, login preparation and its existing recovery owner.
use super::*;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FivekeysProgress {
    authorization: Option<Value>,
    challenge_backend: Option<String>,
    challenge_sha256: Option<String>,
}

fn prepared(intent: &HostKeyOperation, input: &HostKeyInput, authorization: Option<&Value>, target: Option<&Path>) -> Result<PreparedLogin> {
    let HostKeyOperation::Fivekeys { addr, user, kdf_salt, wrapped_urk, urk_nonce, use_super } = intent
        else { anyhow::bail!("not a fivekeys operation"); };
    crate::service::check_runtime_user(user)?;
    let password = input.password.as_deref().context("fivekeys password is required")?;
    let (version, secret) = if *use_super {
        let secret = input.super_password.as_deref().filter(|value| !value.is_empty())
            .context("fivekeys super password is required")?;
        let version = if crate::memory::SessionKeys::unlock_v4(secret, kdf_salt, wrapped_urk, urk_nonce).is_ok() { 4 }
            else {
                crate::memory::SessionKeys::unlock_super(secret, kdf_salt, wrapped_urk, urk_nonce)
                    .context("super password cannot unwrap the kit")?;
                2
            };
        (version, secret.to_owned())
    } else {
        ensure!(input.super_password.as_deref().is_none_or(str::is_empty), "super password was not part of the admitted kit mode");
        let account_secret = input.account_secret.as_deref().filter(|value| !value.is_empty())
            .context("fivekeys Account Secret is required")?;
        crate::memory::SessionKeys::unlock(password, account_secret, kdf_salt, wrapped_urk, urk_nonce)
            .context("fivekeys kit verification failed")?;
        (1, String::new())
    };
    let mut authorized = authorization.cloned().unwrap_or_else(|| json!({"user":user}));
    ensure!(authorized["user"].as_str() == Some(user.as_str()), "fivekeys authorization user changed");
    if authorization.is_some() {
        ensure!(!addr.trim().is_empty() && authorized["addr"].as_str() == Some(addr.trim().trim_end_matches('/'))
            && authorized["token"].as_str().is_some_and(|token| !token.is_empty()), "fivekeys authorization identity changed");
    }
    authorized["pass"] = json!(password);
    if version == 1 { authorized["secret"] = json!(input.account_secret); }
    PreparedLogin::prepare_candidate(addr, &authorized, secret,
        json!({"version":version,"kdf_salt":kdf_salt,"wrapped_urk":wrapped_urk,"urk_nonce":urk_nonce}),
        None, false, authorization.is_none(), target)
}

fn progress(journal: &Journal, index: usize) -> Result<&FivekeysProgress> {
    operation(journal, index)?.fivekeys.as_ref().context("fivekeys continuation receipt is missing")
}

fn save_authorization(journal: &mut Journal, index: usize, authorization: Value) -> Result<()> {
    ensure!(authorization.get("pass").is_none() && authorization.get("secret").is_none(),
        "authorization must not contain decryption factors");
    operation_mut(journal, index)?.fivekeys.as_mut().context("fivekeys continuation missing")?
        .authorization = Some(authorization);
    operation_mut(journal, index)?.required_inputs.clear();
    journal.operations[index].phase = AuthPhase::Authorized;
    save_journal(journal)
}

fn checkpoint_challenge(journal: &mut Journal, index: usize,
    challenge: crate::auth::PasswordAuthorizationChallenge) -> Result<()> {
    ensure!(journal.operations[index].phase == AuthPhase::RemotePending, "fivekeys challenge is not owned");
    let payload = login::encode_challenge(&journal.operations[index], challenge)?;
    let sha256 = digest(payload.as_bytes());
    let alias = journal.operations[index].alias.clone();
    let backend = crate::keystore::import_credential_checkpoint(&alias, "totp", &payload, |backend| {
        require_persistent_auth_backend(backend)?;
        let active = journal.active.as_mut().context("fivekeys recovery missing")?;
        ensure!(active.operation_id.as_deref() == Some(journal.operations[index].operation_id.as_str())
            && active.alias == alias, "fivekeys challenge owner changed");
        if !active.totp_backends.iter().any(|value| value == backend) { active.totp_backends.push(backend.to_owned()); }
        let step = operation_mut(journal, index)?.fivekeys.as_mut().context("fivekeys continuation missing")?;
        step.challenge_backend = Some(backend.to_owned());
        step.challenge_sha256 = Some(sha256.clone());
        save_journal(journal)
    })?;
    let step = progress(journal, index)?;
    ensure!(step.challenge_backend.as_deref() == Some(backend) && step.challenge_sha256.as_deref() == Some(sha256.as_str()),
        "fivekeys challenge checkpoint changed");
    journal.operations[index].phase = AuthPhase::LoginInput;
    require_inputs(journal, index, &["totp"])
}

fn read_challenge(journal: &Journal, index: usize) -> Result<crate::auth::PasswordAuthorizationChallenge> {
    let step = progress(journal, index)?;
    let backend = step.challenge_backend.as_deref().context("fivekeys challenge backend missing")?;
    require_persistent_auth_backend(backend)?;
    let active = journal.active.as_ref().context("fivekeys recovery missing")?;
    ensure!(active.totp_backends.iter().any(|value| value == backend)
        && active.alias == journal.operations[index].alias, "fivekeys challenge recovery changed");
    let payload = crate::keystore::read_imported(&active.alias, "totp", backend)?;
    login::verify_challenge(&journal.operations[index], step.challenge_sha256.as_deref()
        .context("fivekeys challenge digest missing")?, &payload)
}

fn stage(ownership: &AuthOwnership, journal: &mut Journal, index: usize, mut prepared: PreparedLogin) -> Result<()> {
    if journal.operations[index].candidate.is_some() {
        ensure!(operation(journal, index)?.credential_ready, "fivekeys credential checkpoint incomplete; compensate the original operation");
        candidate_keys(&journal.operations[index])?;
        journal.operations[index].phase = AuthPhase::Prepared;
        return save_journal(journal);
    }
    ensure!(read_original(&ownership.profile)?.as_deref().map(digest) == journal.operations[index].original_sha256,
        "fivekeys source changed before staging");
    if operation(journal, index)?.target.is_none() {
        let config = match std::fs::read(crate::service::client_config_path()) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        let active = journal.active.as_mut().context("fivekeys recovery missing")?;
        active.directory = prepared.directory.clone();
        active.original = prepared.original.clone();
        active.directory_existed = prepared.directory.exists();
        active.config = config;
        active.owns_config = true;
        let op = operation_mut(journal, index)?;
        op.target = Some(prepared.directory.clone());
        op.target_original_sha256 = prepared.original.as_deref().map(digest);
        save_journal(journal)?;
    }
    let active = journal.active.as_ref().context("fivekeys recovery missing")?;
    ensure!(active.directory == prepared.directory && active.original == prepared.original, "fivekeys target snapshot changed");
    let target = active.directory.clone();
    let _target_lock = if same_directory(&target, &ownership.root)? || same_directory(&target, &ownership.profile)? { None }
        else { Some(crate::lock::LibraryLock::acquire(&target, std::time::Duration::from_secs(1))?) };
    ensure!(read_original(&target)? == prepared.original, "fivekeys target changed while acquiring ownership");
    verify_account_config(journal.active.as_ref().context("fivekeys recovery missing")?)?;
    prepared.alias = journal.operations[index].alias.clone();
    if prepared.user.is_empty() {
        prepared.session["auth_operation_id"] = json!(journal.operations[index].operation_id);
    }
    checkpoint_credentials(journal, index, &mut prepared.session, &prepared.super_password, prepared.login_password.as_deref())?;
    journal.operations[index].phase = AuthPhase::Prepared;
    operation_mut(journal, index)?.required_inputs.clear();
    save_journal(journal)
}

pub(super) fn resume_candidate(journal: &mut Journal, index: usize) -> Result<bool> {
    if journal.operations[index].phase != AuthPhase::Authorized || journal.operations[index].candidate.is_none() {
        return Ok(false);
    }
    if !operation(journal, index)?.credential_ready { return Ok(false); }
    candidate_keys(&journal.operations[index])?;
    journal.operations[index].phase = AuthPhase::Prepared;
    save_journal(journal)?;
    Ok(true)
}

pub(super) fn execute(ownership: &AuthOwnership, journal: &mut Journal, index: usize, input: &HostKeyInput) -> Result<()> {
    if resume_candidate(journal, index)? { return Ok(()); }
    if !matches!(journal.operations[index].phase, AuthPhase::Admitted | AuthPhase::LoginInput | AuthPhase::Authorized) {
        return Ok(());
    }
    let intent = operation(journal, index)?.operation.clone();
    let HostKeyOperation::Fivekeys { ref addr, ref user, use_super, .. } = intent
        else { anyhow::bail!("not a fivekeys operation"); };
    let mut missing = Vec::new();
    if input.password.is_none() { missing.push("password"); }
    if use_super && input.super_password.as_deref().is_none_or(str::is_empty) { missing.push("super_password"); }
    if !use_super && input.account_secret.as_deref().is_none_or(str::is_empty) { missing.push("account_secret"); }
    if !missing.is_empty() { return require_inputs(journal, index, &missing); }
    // Verify kit and destination before any remote POST or user credential write.
    let preflight = prepared(&intent, input, None, operation(journal, index)?.target.as_deref())?;
    if operation(journal, index)?.fivekeys.is_none() {
        operation_mut(journal, index)?.fivekeys = Some(FivekeysProgress {
            authorization: None, challenge_backend: None, challenge_sha256: None });
        save_journal(journal)?;
    }
    if journal.operations[index].phase == AuthPhase::Admitted {
        if addr.trim().is_empty() {
            journal.operations[index].phase = AuthPhase::Authorized;
            save_journal(journal)?;
        } else {
            journal.operations[index].phase = AuthPhase::RemotePending;
            operation_mut(journal, index)?.required_inputs.clear();
            save_journal(journal)?;
            match crate::auth::begin_password_authorization(addr, user, input.password.as_deref().context("password missing")?) {
                Ok(crate::auth::PasswordAuthorizationStep::Authorized(authorization)) => save_authorization(journal, index, authorization)?,
                Ok(crate::auth::PasswordAuthorizationStep::TotpRequired(challenge)) => checkpoint_challenge(journal, index, challenge)?,
                Err(_) => {
                    journal.operations[index].phase = AuthPhase::RemoteUnknown;
                    return save_journal(journal);
                }
            }
        }
    }
    if journal.operations[index].phase == AuthPhase::LoginInput {
        let Some(code) = input.totp.as_deref().filter(|code| crate::auth::validate_totp_code(code).is_ok())
            else { return require_inputs(journal, index, &["totp"]); };
        let challenge = read_challenge(journal, index)?;
        journal.operations[index].phase = AuthPhase::RemotePending;
        operation_mut(journal, index)?.required_inputs.clear();
        save_journal(journal)?;
        match crate::auth::continue_password_authorization(addr, user, &challenge, code) {
            Ok(authorization) => save_authorization(journal, index, authorization)?,
            Err(_) => {
                journal.operations[index].phase = AuthPhase::RemoteUnknown;
                return save_journal(journal);
            }
        }
    }
    if journal.operations[index].phase == AuthPhase::Authorized {
        let candidate = if addr.trim().is_empty() { preflight }
            else { prepared(&intent, input, Some(progress(journal, index)?.authorization.as_ref()
                .context("fivekeys authorization missing")?), operation(journal, index)?.target.as_deref())? };
        stage(ownership, journal, index, candidate)?;
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn assert_existing_recovery(root: &Path) -> Result<()> {
    let ownership = AuthOwnership::acquire(root, root)?;
    let original = read_original(root)?.context("fivekeys fixture source missing")?;
    let config = std::fs::read(crate::service::client_config_path()).ok();
    let identity = HostAuthIdentity::Bound { account_id: digest(b"reset-fixture"), session_sha256: digest(&original) };
    let secret = crate::memory::crypto::generate_secret_key();
    let (salt, wrapped, nonce) = crate::auth::wrap_with_v4(&secret, &crate::memory::crypto::generate_key())?;
    let mut params = HostKeyParams { schema_version: HOST_KEY_SCHEMA_V,
        binding: respire_protocol::ControlBinding { installation_root: root.to_owned(), profile: root.to_owned(),
            launch_id: uuid::Uuid::new_v4().to_string(), expected_account_id: Some(digest(b"reset-fixture")) },
        identity: identity.clone(), source_identity: identity,
        operation: HostKeyOperation::Fivekeys { addr: String::new(), user: "fivekeys-fixture".to_owned(),
            kdf_salt: salt, wrapped_urk: wrapped, urk_nonce: nonce, use_super: true }, input: None };
    let input = HostKeyInput { password: Some("synthetic-fixture-password".to_owned()),
        super_password: Some(secret), ..HostKeyInput::default() };
    let candidate = prepared(&params.operation, &input, None, None)?;
    assert!(candidate.session.get("token").is_none() && candidate.session.get("session_id").is_none());
    assert!(candidate.session.get("pass").is_none() && candidate.session.get("super").is_none());
    let v1_secret = crate::memory::crypto::generate_account_secret();
    let v1_salt = crate::memory::crypto::random_hex(16);
    let v1_urk = crate::memory::crypto::generate_key();
    let (v1_nonce, v1_wrap) = crate::memory::crypto::wrap_key(&v1_urk,
        &crate::memory::crypto::derive_kek("", &v1_secret, &v1_salt)?)?;
    let v1_intent = HostKeyOperation::Fivekeys { addr: String::new(), user: "fivekeys-v1-fixture".to_owned(),
        kdf_salt: v1_salt, wrapped_urk: v1_wrap, urk_nonce: v1_nonce, use_super: false };
    let mut v1_input = HostKeyInput { password: Some(String::new()), account_secret: Some(v1_secret), ..HostKeyInput::default() };
    let v1_candidate = prepared(&v1_intent, &v1_input, None, None)?;
    assert_eq!(v1_candidate.login_password.as_deref(), Some(""));
    assert!(v1_candidate.session.get("pass").is_none() && v1_candidate.session.get("token").is_none());
    v1_input.password = None;
    assert!(prepared(&v1_intent, &v1_input, None, None).is_err());
    let target = candidate.directory.clone();
    let target_before = read_original(&target)?;
    let existed = target.exists();
    let mut bad_input = HostKeyInput { super_password: Some("not-the-kit-secret".to_owned()), ..input };
    assert!(prepared(&params.operation, &bad_input, None, None).is_err());
    bad_input.super_password = None;
    assert!(prepared(&params.operation, &bad_input, None, None).is_err());
    let id = uuid::Uuid::new_v4().to_string();
    let awaiting = control_key(&ownership, &id, &id, &params)?;
    assert!(awaiting.outcome == HostKeyOutcome::AwaitingInput && !awaiting.verification_required);
    let (mut journal, index) = admit(&ownership, &id, &id, &params)?;
    let mut changed = serde_json::to_value(&params)?;
    changed["operation"]["addr"] = json!("https://never-contact.invalid");
    let changed: HostKeyParams = serde_json::from_value(changed)?;
    assert!(control_key_result(&ownership, &id, &id, &changed).is_err());
    let mut unsupported = serde_json::to_value(&params)?;
    unsupported["operation"]["argv"] = json!(["unsupported"]);
    assert!(serde_json::from_value::<HostKeyParams>(unsupported).is_err());
    // A query or a continuation must not restart a remotely unknown login.
    journal.operations[index].phase = AuthPhase::RemotePending;
    operation_mut(&mut journal, index)?.required_inputs.clear();
    save_journal(&journal)?;
    let pending = std::fs::read(recovery_path())?;
    assert!(control_key_result(&ownership, &id, &id, &params)?.outcome == HostKeyOutcome::Unknown);
    params.input = Some(bad_input);
    assert!(control_key(&ownership, &id, &id, &params)?.outcome == HostKeyOutcome::Unknown);
    assert_eq!(std::fs::read(recovery_path())?, pending);
    assert_eq!(read_original(root)?, Some(original.clone()));
    assert_eq!(read_original(&target)?, target_before);
    assert_eq!(target.exists(), existed);
    assert_eq!(std::fs::read(crate::service::client_config_path()).ok(), config);
    // Restore only this synthetic receipt's pre-network phase for compensation.
    journal.operations[index].phase = AuthPhase::Admitted;
    save_journal(&journal)?;
    assert!(control_key_rollback(ownership, &id, &id, &params)?.outcome == HostKeyOutcome::RolledBack);
    assert_eq!(read_original(root)?, Some(original));
    assert!(!auth_recovery_pending()?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offline_kit(version: i64) -> Result<(HostKeyOperation, HostKeyInput, [u8; 32])> {
        let urk = crate::memory::crypto::generate_key();
        let password = String::new();
        let mut input = HostKeyInput { password: Some(password.clone()), ..HostKeyInput::default() };
        let (salt, wrapped, nonce) = match version {
            1 => {
                let secret = crate::memory::crypto::generate_account_secret();
                let salt = crate::memory::crypto::random_hex(16);
                let (nonce, wrapped) = crate::memory::crypto::wrap_key(&urk,
                    &crate::memory::crypto::derive_kek(&password, &secret, &salt)?)?;
                input.account_secret = Some(secret);
                (salt, wrapped, nonce)
            }
            2 => {
                let secret = "synthetic-legacy-super".to_owned();
                let salt = crate::memory::crypto::random_hex(16);
                let (nonce, wrapped) = crate::memory::crypto::wrap_key(&urk,
                    &crate::memory::crypto::derive_super_kek(&secret, &salt)?)?;
                input.super_password = Some(secret);
                (salt, wrapped, nonce)
            }
            4 => {
                let secret = crate::memory::crypto::generate_secret_key();
                let kit = crate::auth::wrap_with_v4(&secret, &urk)?;
                input.super_password = Some(secret);
                kit
            }
            _ => anyhow::bail!("unsupported offline fixture version"),
        };
        Ok((HostKeyOperation::Fivekeys { addr: String::new(), user: String::new(),
            kdf_salt: salt, wrapped_urk: wrapped, urk_nonce: nonce, use_super: version != 1 }, input, urk))
    }

    #[test]
    fn offline_fivekeys_requires_original_native_credential_and_verification() -> Result<()> {
        let isolated = crate::test_lock::Isolate::new()?;
        let _keyring = crate::migration::memory_keyring_for_test();
        let root = isolated.path().canonicalize()?;
        for version in [1, 2, 4] {
            let (intent, input, urk) = offline_kit(version)?;
            let config = std::fs::read(crate::service::client_config_path()).ok();
            let candidate = prepared(&intent, &input, None, None)?;
            assert_eq!(candidate.directory, root);
            assert_eq!(candidate.session["user"], "");
            assert_eq!(candidate.session["addr"], "");
            assert_eq!(candidate.session["vault_version"], version);
            assert!(!root.join("session.json").exists());
            let ownership = AuthOwnership::acquire(&root, &root)?;
            let id = uuid::Uuid::new_v4().to_string();
            let mut params = HostKeyParams { schema_version: HOST_KEY_SCHEMA_V,
                binding: respire_protocol::ControlBinding { installation_root: root.clone(), profile: root.clone(),
                    launch_id: uuid::Uuid::new_v4().to_string(), expected_account_id: None },
                identity: HostAuthIdentity::Absent, source_identity: HostAuthIdentity::Absent,
                operation: intent, input: Some(input) };
            let receipt = control_key(&ownership, &id, &id, &params)?;
            assert!(receipt.outcome == HostKeyOutcome::Pending && receipt.verification_required);
            assert!(receipt.account_id.is_none() && receipt.super_password.is_none());
            assert!(matches!(&receipt.identity, HostAuthIdentity::Unbound { operation_id, session_sha256 }
                if operation_id == &id && Some(session_sha256) == receipt.session_sha256.as_ref()));
            let journal = load_journal()?;
            let record = journal.operations.iter().find(|record| record.operation_id == id)
                .context("offline fixture receipt missing")?;
            assert_eq!(candidate_keys(record)?.urk, urk);
            assert!(!auth_recovery_pending()?);
            let alias = record.alias.clone();
            let backend = record.backend.as_deref().context("offline fixture backend missing")?;
            let slot = if version == 1 { "pass" } else { "super" };
            let secret = if version == 1 { crate::keystore::read_imported_v1_password(&alias, backend)? }
                else { crate::keystore::read_imported(&alias, slot, backend)? };
            crate::keystore::remove_imported(&alias, slot, backend)?;
            verify_locked_auth_identity(&root, &root, &receipt.identity)?;
            assert!(verify_auth_identity(&root, &root, &receipt.identity).is_err());
            crate::keystore::import_credential(&alias, slot, "synthetic-wrong-credential")?;
            assert!(verify_auth_identity(&root, &root, &receipt.identity).is_err());
            crate::keystore::remove_imported(&alias, slot, backend)?;
            crate::keystore::import_credential(&alias, slot, &secret)?;
            verify_auth_identity(&root, &root, &receipt.identity)?;
            params.identity = receipt.identity;
            params.input = None;
            let pending = control_key_result(&ownership, &id, &id, &params)?;
            assert!(pending.verification_required && pending.outcome == HostKeyOutcome::Pending);
            let checkpoint = std::fs::read(recovery_path())?;
            drop(ownership);
            assert!(control_key_complete(&root, &root, &id, &id, &params,
                |_| anyhow::bail!("synthetic live Runtime is not ready")).is_err());
            assert_eq!(std::fs::read(recovery_path())?, checkpoint);
            let ownership = AuthOwnership::acquire(&root, &root)?;
            let rolled_back = control_key_rollback(ownership, &id, &id, &params)?;
            assert!(rolled_back.outcome == HostKeyOutcome::RolledBack);
            assert!(rolled_back.identity == HostAuthIdentity::Absent);
            assert!(!root.join("session.json").exists());
            assert_eq!(std::fs::read(crate::service::client_config_path()).ok(), config);
            assert!(crate::keystore::read_imported(&alias, slot, backend).is_err());
        }
        Ok(())
    }

    #[test]
    fn offline_fivekeys_preserves_selected_library_on_wrong_kit() -> Result<()> {
        let isolated = crate::test_lock::Isolate::new()?;
        let _keyring = crate::migration::memory_keyring_for_test();
        let root = isolated.path().canonicalize()?;
        let (intent, input, urk) = offline_kit(4)?;
        let keys = crate::memory::SessionKeys::from_urk(urk)?;
        let (nonce, ciphertext) = keys.encrypt_content(&serde_json::to_string(&json!({
            "kind":"Context", "tags":"", "title":"retained", "content":"offline recovery fixture",
            "user":"", "computer":"fixture", "project":"", "created_at":"", "updated_at":""
        }))?)?;
        let database_path = crate::service::database_path(&root)?;
        let database = rusqlite::Connection::open(&database_path)?;
        database.execute_batch("CREATE TABLE memories(ciphertext TEXT, nonce TEXT, deleted INTEGER);")?;
        database.execute("INSERT INTO memories VALUES(?1,?2,0)", rusqlite::params![ciphertext, nonce])?;
        drop(database);
        let database_before = std::fs::read(&database_path)?;
        let good = prepared(&intent, &input, None, None)?;
        assert_eq!(good.directory, root);
        let (wrong_intent, wrong_input, _) = offline_kit(4)?;
        assert!(prepared(&wrong_intent, &wrong_input, None, None).is_err());
        let mut online = intent.clone();
        if let HostKeyOperation::Fivekeys { addr, .. } = &mut online { *addr = "https://never-contact.invalid".into(); }
        assert!(prepared(&online, &input, None, None).is_err());
        assert_eq!(std::fs::read(&database_path)?, database_before);
        assert!(!root.join("session.json").exists());
        assert!(!crate::service::client_config_path().exists());
        assert!(!crate::service::accounts_root().exists());
        Ok(())
    }
}
