//! Resume only the admitted login; never journal the supplemental request object.
use super::*;
use respire_protocol::host_control::{HostAuthLoginContinuation, HostAuthLoginStatus};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportSnapshot {
    target: PathBuf,
    sha256: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeCheckpoint {
    backend: String,
    sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundChallenge {
    binding: String,
    challenge: crate::auth::PasswordAuthorizationChallenge,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LoginProgress {
    migrate_local: bool,
    migrate_vault: bool,
    offer_local_merge: bool,
    merge_local: Option<bool>,
    merge_target: Option<PathBuf>,
    required_inputs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    challenge: Option<ChallengeCheckpoint>,
    snapshot: Option<ImportSnapshot>,
    import_started: bool,
    import: Option<Value>,
    sync: Option<Value>,
    migration_cloud: Option<Value>,
    migration_salt: Option<String>,
    publication_pending: bool,
    publication_done: bool,
    publication_step: Option<String>,
    vault_done: bool,
    password_done: bool,
}

impl LoginProgress {
    pub(super) fn new(migrate_local: bool, migrate_vault: bool, offer_local_merge: bool) -> Self {
        Self { migrate_local, migrate_vault, offer_local_merge, merge_local: None, merge_target: None,
            required_inputs: Vec::new(), challenge: None, snapshot: None,
            import_started: false, import: None, sync: None, migration_cloud: None,
            migration_salt: None, publication_pending: false, publication_done: false,
            publication_step: None, vault_done: false, password_done: false }
    }

    pub(super) fn status(&self, rolled_back: bool, account: &AccountOperation) -> HostAuthLoginStatus {
        HostAuthLoginStatus { required_inputs: if rolled_back { Vec::new() } else { self.required_inputs.clone() },
            user: account.user.clone(), addr: account.addr.clone(),
            dir: account.target.clone().or_else(|| self.merge_target.clone()), super_issued: None,
            import: self.import.clone(), sync: self.sync.clone() }
    }

    pub(super) fn awaiting_input(&self) -> bool { !self.required_inputs.is_empty() }

    fn imports_local(&self) -> bool { self.migrate_local || self.merge_local == Some(true) }

    pub(super) fn offer_merge(&mut self, target: &Path) -> Result<()> {
        ensure!(self.offer_local_merge && !self.migrate_local, "local merge was not admitted");
        ensure!(self.merge_target.as_deref().is_none_or(|original| original == target),
            "local merge offer destination changed");
        self.merge_target = Some(target.to_owned());
        Ok(())
    }

    pub(super) fn confirm_merge(&mut self, target: &Path, confirmed: bool) -> Result<()> {
        ensure!(self.offer_local_merge && !self.migrate_local && self.merge_target.as_deref() == Some(target),
            "local merge confirmation has no admitted offer for this destination");
        ensure!(self.merge_local.is_none_or(|original| original == confirmed), "local merge confirmation cannot change");
        self.merge_local = Some(confirmed);
        Ok(())
    }

    pub(super) fn pending(&self) -> bool {
        !self.required_inputs.is_empty() || self.imports_local() && self.import.is_none()
            || self.publication_pending
    }

    pub(super) fn publication_started(&self) -> bool {
        self.publication_pending || self.publication_done || self.vault_done || self.password_done
    }
}

fn progress(journal: &mut Journal, index: usize) -> Result<&mut LoginProgress> {
    journal.operations[index].account.as_mut().and_then(|account| account.login.as_mut())
        .context("login continuation receipt is missing")
}

fn require_inputs(journal: &mut Journal, index: usize, inputs: &[&str]) -> Result<HostAuthAccountResult> {
    progress(journal, index)?.required_inputs = inputs.iter().map(|input| (*input).to_owned()).collect();
    save_journal(journal)?;
    account_result(&journal.operations[index])
}

fn challenge_binding(record: &AuthRecord) -> Result<String> {
    Ok(digest(&serde_json::to_vec(&(&record.operation_id, &record.idempotency_key,
        &record.fingerprint, &record.root, &record.profile, &record.alias))?))
}

pub(super) fn encode_challenge(record: &AuthRecord, challenge: crate::auth::PasswordAuthorizationChallenge) -> Result<String> {
    serde_json::to_string(&BoundChallenge { binding: challenge_binding(record)?, challenge }).map_err(Into::into)
}

pub(super) fn verify_challenge(record: &AuthRecord, sha256: &str, payload: &str) -> Result<crate::auth::PasswordAuthorizationChallenge> {
    ensure!(digest(payload.as_bytes()) == sha256, "challenge credential changed");
    let bound: BoundChallenge = serde_json::from_str(payload).context("invalid challenge credential")?;
    ensure!(bound.binding == challenge_binding(record)?, "challenge operation binding changed");
    Ok(bound.challenge)
}

fn checkpoint_challenge(journal: &mut Journal, index: usize,
    challenge: crate::auth::PasswordAuthorizationChallenge) -> Result<()> {
    let record = &journal.operations[index];
    ensure!(record.phase == AuthPhase::RemotePending, "challenge does not own a pending password step");
    let payload = encode_challenge(record, challenge)?;
    let sha256 = digest(payload.as_bytes());
    let alias = record.alias.clone();
    // A Windows journal may inherit its directory ACL. Keep the ticket itself
    // in the existing persistent credential backend, never in that file.
    let backend = crate::keystore::import_credential_checkpoint(&alias, "totp", &payload, |backend| {
        require_persistent_auth_backend(backend)?;
        let active = journal.active.as_mut().context("challenge recovery is missing")?;
        ensure!(active.operation_id.as_deref() == Some(journal.operations[index].operation_id.as_str())
            && active.alias == alias, "challenge recovery owner mismatch");
        if !active.totp_backends.iter().any(|original| original == backend) {
            active.totp_backends.push(backend.to_owned());
        }
        progress(journal, index)?.challenge = Some(ChallengeCheckpoint { backend: backend.to_owned(), sha256: sha256.clone() });
        save_journal(journal)
    })?;
    ensure!(progress(journal, index)?.challenge.as_ref().is_some_and(|checkpoint|
        checkpoint.backend == backend && checkpoint.sha256 == sha256), "challenge credential has no owned checkpoint");
    journal.operations[index].phase = AuthPhase::LoginInput;
    progress(journal, index)?.required_inputs = vec!["totp".to_owned()];
    save_journal(journal)
}

fn challenge_checkpoint(journal: &Journal, index: usize) -> Result<&ChallengeCheckpoint> {
    let record = &journal.operations[index];
    ensure!(record.phase == AuthPhase::LoginInput, "challenge is not awaiting input");
    let checkpoint = record.account.as_ref().and_then(|account| account.login.as_ref())
        .and_then(|login| login.challenge.as_ref()).context("challenge checkpoint is missing")?;
    let active = journal.active.as_ref().context("challenge recovery is missing")?;
    ensure!(active.operation_id.as_deref() == Some(record.operation_id.as_str()) && active.alias == record.alias
        && active.totp_backends.contains(&checkpoint.backend), "challenge recovery owner mismatch");
    require_persistent_auth_backend(&checkpoint.backend)?;
    ensure!(checkpoint.sha256.len() == 64 && checkpoint.sha256.bytes().all(|byte|
        byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)), "invalid challenge digest");
    Ok(checkpoint)
}

fn read_challenge(journal: &Journal, index: usize) -> Result<crate::auth::PasswordAuthorizationChallenge> {
    let checkpoint = challenge_checkpoint(journal, index)?;
    let record = &journal.operations[index];
    let payload = crate::keystore::read_imported(&record.alias, "totp", &checkpoint.backend)?;
    verify_challenge(record, &checkpoint.sha256, &payload)
}

fn save_authorization(journal: &mut Journal, index: usize, mut authorization: Value) -> Result<()> {
    let object = authorization.as_object_mut().context("authorization must be an object")?;
    object.remove("pass");
    object.remove("secret");
    journal.operations[index].account.as_mut().context("login receipt missing")?.authorization = Some(authorization);
    journal.operations[index].phase = AuthPhase::Authorized;
    let login = progress(journal, index)?;
    login.required_inputs.clear();
    login.challenge = None;
    save_journal(journal)
}

pub(super) fn control_login(ownership: &AuthOwnership, id: &str, key: &str,
    params: &HostAuthLoginParams) -> Result<HostAuthAccountResult> {
    ensure!(params.schema_version == respire_protocol::HOST_AUTH_SCHEMA_V
        && params.binding.installation_root == ownership.root && params.binding.profile == ownership.profile,
        "login binding mismatch");
    let defaults = HostAuthLoginContinuation::default();
    let input = params.continuation.as_ref().unwrap_or(&defaults);
    ensure!(!(input.migrate_vault && (input.migrate_local || input.offer_local_merge)),
        "local import and explicit vault migration are separate operations");
    ensure!(input.migrate_vault || input.new_super.is_none(), "new-super applies only to explicit vault migration");
    let addr = params.addr.trim().trim_end_matches('/');
    let (mut journal, index, fresh) = admit_account_with_intent(ownership, &params.identity, id, key,
        false, addr, &params.user, Some((input.migrate_local, input.migrate_vault, input.offer_local_merge)))?;
    if journal.operations[index].account.as_ref().is_some_and(|account| account.login.is_none()) {
        // Legacy receipts are queryable, not an opportunity to attach new login effects.
        return control_account_result(ownership, &params.identity, id, key);
    }
    if !fresh && !matches!(journal.operations[index].phase, AuthPhase::Authorized | AuthPhase::LoginInput) {
        // A pending/unknown network request cannot be replayed by supplying new factors.
        return control_account_result(ownership, &params.identity, id, key);
    }
    if fresh {
        journal.operations[index].phase = AuthPhase::RemotePending;
        save_journal(&journal)?;
        let step = match &params.authorization {
            HostAuthAuthorization::Password { password, .. } =>
                crate::auth::begin_password_authorization(addr, &params.user, password),
            HostAuthAuthorization::Browser { token, session_id } => {
                ensure!(!token.is_empty(), "browser authorization token is missing");
                Ok(crate::auth::PasswordAuthorizationStep::Authorized(
                    json!({"addr":addr,"user":params.user,"token":token,"session_id":session_id})))
            }
        };
        match step {
            Ok(crate::auth::PasswordAuthorizationStep::Authorized(authorization)) => save_authorization(&mut journal, index, authorization)?,
            Ok(crate::auth::PasswordAuthorizationStep::TotpRequired(challenge)) => checkpoint_challenge(&mut journal, index, challenge)?,
            Err(error) => {
                journal.operations[index].phase = AuthPhase::RemoteUnknown;
                save_journal(&journal)?;
                return Err(error.context("authorization outcome unknown; query the original operation, do not resend"));
            }
        }
    }
    if journal.operations[index].phase == AuthPhase::LoginInput {
        challenge_checkpoint(&journal, index)?;
        let HostAuthAuthorization::Password { totp, .. } = &params.authorization else {
            anyhow::bail!("the admitted password challenge cannot change authorization method");
        };
        let Some(code) = totp.as_deref() else { return require_inputs(&mut journal, index, &["totp"]); };
        if crate::auth::validate_totp_code(code).is_err() { return require_inputs(&mut journal, index, &["totp"]); }
        let challenge = read_challenge(&journal, index)?;
        journal.operations[index].phase = AuthPhase::RemotePending;
        progress(&mut journal, index)?.required_inputs.clear();
        save_journal(&journal)?;
        match crate::auth::continue_password_authorization(addr, &params.user, &challenge, code) {
            Ok(authorization) => save_authorization(&mut journal, index, authorization)?,
            Err(error) => {
                journal.operations[index].phase = AuthPhase::RemoteUnknown;
                save_journal(&journal)?;
                return Err(error.context("TOTP outcome unknown; query the original operation, do not resend"));
            }
        }
    }
    let mut authorized = journal.operations[index].account.as_ref()
        .and_then(|account| account.authorization.clone()).context("authorized login receipt is missing")?;
    let password = input.legacy_password.as_deref().filter(|value| !value.is_empty())
        .or_else(|| match &params.authorization {
            HostAuthAuthorization::Password { password, .. } if !password.is_empty() => Some(password.as_str()),
            _ => None,
        });
    if let Some(password) = password { authorized["pass"] = json!(password); }
    if let Some(secret) = input.account_secret.as_deref().filter(|value| !value.is_empty()) {
        authorized["secret"] = json!(secret);
    }
    if let Some(secret) = input.secret_key.as_deref().filter(|value| !value.is_empty()) {
        authorized["secret_key"] = json!(secret);
    }
    let mut prepared = if input.migrate_vault {
        let local = crate::auth::read_session_json()?;
        let version = local["vault_version"].as_i64().context("local vault missing version")?;
        ensure!((1..=4).contains(&version), "unsupported local vault version");
        if version == 1 {
            ensure!(params.super_password.is_none(), "v1 requires the original password and Account Secret, not a super key");
        }
        let Some(password) = password else { return require_inputs(&mut journal, index, &["legacy_password"]); };
        let alias = local["keyring_account"].as_str().unwrap_or(&params.user);
        if version == 1 && input.account_secret.as_deref().or(input.secret_key.as_deref()).is_none()
            && local["secret"].as_str().is_none() {
            return require_inputs(&mut journal, index, &["account_secret"]);
        }
        if version != 1 && (params.super_password.as_deref().is_some_and(str::is_empty)
            || params.super_password.is_none() && crate::keystore::load_super(alias).is_none()) {
            return require_inputs(&mut journal, index, &["super_password"]);
        }
        if version == 3 && input.secret_key.as_deref().or(input.account_secret.as_deref()).is_none()
            && local["secret_key"].as_str().is_none() {
            return require_inputs(&mut journal, index, &["secret_key"]);
        }
        PreparedLogin::prepare_migration(addr, &authorized, password,
            params.super_password.as_deref(),
            input.secret_key.as_deref().or(input.account_secret.as_deref()), input.new_super.as_deref())?
    } else {
        let vault = if let Some(vault) = journal.operations[index].account.as_ref().and_then(|account| account.vault.clone()) {
            vault
        } else {
            let vault = PreparedLogin::fetch_vault(addr, &authorized)?;
            ensure!(!vault.is_null(), "account has no cloud vault; use explicit vault migration; original material retained");
            journal.operations[index].account.as_mut().context("login receipt missing")?.vault = Some(vault.clone());
            save_journal(&journal)?;
            vault
        };
        let version = vault["version"].as_i64().context("vault missing version")?;
        ensure!((1..=4).contains(&version), "unsupported vault version; original factors were preserved");
        if version == 1 {
            ensure!(params.super_password.is_none(), "v1 requires the original password and Account Secret, not a super key");
        }
        let target = login_directory(addr, &params.user)?;
        let local: Value = read_original(&target)?.map(|bytes| serde_json::from_slice(&bytes)).transpose()?.unwrap_or(json!({}));
        ensure!(local.is_object(), "target account session must be an object");
        let alias = local["keyring_account"].as_str().unwrap_or(&params.user);
        let super_password = if version == 1 { String::new() } else {
            params.super_password.clone().or_else(|| crate::keystore::load_super(alias)).unwrap_or_default()
        };
        if version == 1 {
            if authorized["pass"].as_str().is_none_or(|value| value.is_empty()) {
                let found = local["pass"].as_str().filter(|value| !value.is_empty()).map(str::to_owned)
                    .or_else(|| crate::env::var("RSRS_PASS").ok().filter(|value| !value.is_empty()))
                    .or_else(|| crate::keystore::load_login_pass(alias));
                if let Some(found) = found { authorized["pass"] = json!(found); }
            }
            if authorized["secret"].as_str().is_none_or(|value| value.is_empty()) { authorized["secret"] = local["secret"].clone(); }
            let missing: Vec<_> = [("pass", "legacy_password"), ("secret", "account_secret")].iter()
                .filter(|(field, _)| authorized[*field].as_str().is_none_or(|value| value.is_empty()))
                .map(|(_, input)| *input).collect();
            if !missing.is_empty() { return require_inputs(&mut journal, index, &missing); }
        } else if super_password.is_empty() {
            return require_inputs(&mut journal, index, &["super_password"]);
        }
        if version == 3 && authorized["secret_key"].as_str().is_none()
            && local["secret_key"].as_str().is_none() {
            return require_inputs(&mut journal, index, &["secret_key"]);
        }
        PreparedLogin::prepare_with_vault(addr, &authorized, super_password, vault, None)?
    };
    if let Some(confirmed) = input.merge_local {
        progress(&mut journal, index)?.confirm_merge(&prepared.directory, confirmed)?;
        save_journal(&journal)?;
    }
    if input.offer_local_merge && !input.migrate_local && prepared.directory != ownership.profile
        && crate::service::database_path(&ownership.profile)?.is_file()
        && progress(&mut journal, index)?.merge_local.is_none() {
        progress(&mut journal, index)?.offer_merge(&prepared.directory)?;
        return require_inputs(&mut journal, index, &["merge_local"]);
    }
    if progress(&mut journal, index)?.imports_local() {
        ensure!(prepared.directory != ownership.profile, "source and destination are the same account; no migration needed");
        ensure!(!crate::service::off_mode(), "memory service is disabled; no local import was started");
        crate::service::ensure_writable()?;
        let snapshot = match local_snapshot(input.source_secret.as_deref().filter(|value| !value.is_empty())) {
            Ok(snapshot) => snapshot,
            Err(error) if error.is::<crate::auth::SessionCredentialRequired>() =>
                return require_inputs(&mut journal, index, &["source_secret"]),
            Err(error) => return Err(error),
        };
        if let Some(original) = progress(&mut journal, index)?.snapshot.as_ref() {
            ensure!(original.sha256 == digest(snapshot.as_bytes()) && original.target == prepared.directory,
                "admitted import source or destination changed; retain its original operation");
        }
        let keys = crate::auth::unlock_session_keys(&prepared.session,
            prepared.login_password.as_deref().unwrap_or_default(), Some(&prepared.super_password), &prepared.alias)?;
        let encryption = import_key(&keys, &journal.operations[index], &prepared.directory)?;
        let (nonce, ciphertext) = crate::memory::crypto::encrypt_bytes(&encryption, snapshot.as_bytes())?;
        progress(&mut journal, index)?.snapshot = Some(ImportSnapshot { target: prepared.directory.clone(),
            sha256: digest(snapshot.as_bytes()), nonce, ciphertext });
    }
    let login = progress(&mut journal, index)?;
    login.required_inputs.clear();
    login.migration_cloud = prepared.migration_cloud.clone();
    login.migration_salt = prepared.migration_auth.as_ref().and_then(|auth| auth["salt"].as_str()).map(str::to_owned);
    save_journal(&journal)?;
    commit_account(ownership, &mut journal, index, &mut prepared)?;
    resume_import(ownership, &mut journal, index)?;
    account_result(&journal.operations[index])
}

fn import_key(keys: &crate::memory::SessionKeys, record: &AuthRecord, target: &Path) -> Result<[u8; 32]> {
    crate::memory::crypto::derive_subkey(&keys.urk, &serde_json::to_vec(
        &("login-import-v1", &record.operation_id, &record.root, &record.profile, target))?)
}

pub(super) fn resume_import(ownership: &AuthOwnership, journal: &mut Journal, index: usize) -> Result<()> {
    let record = &journal.operations[index];
    let Some(login) = record.account.as_ref().and_then(|account| account.login.as_ref()) else { return Ok(()); };
    if !login.imports_local() || login.import.is_some() && login.sync.is_some()
        || record.phase != AuthPhase::AwaitingVerification { return Ok(()); }
    let target = record.account.as_ref().and_then(|account| account.target.as_ref()).context("import target missing")?.clone();
    ensure!(crate::service::data_dir().canonicalize()? == target, "import selection changed");
    let _target_lock = if target == ownership.root || target == ownership.profile { None }
        else { Some(crate::lock::LibraryLock::acquire(&target, std::time::Duration::from_secs(1))?) };
    account_material_keys(record, true)?;
    if login.import.is_none() {
    let keys = account_material_keys(record, true)?;
    let snapshot = login.snapshot.as_ref().context("admitted encrypted import snapshot missing")?;
    ensure!(snapshot.target == target, "admitted import destination changed");
    let bytes = crate::memory::crypto::decrypt_bytes(&import_key(&keys, record, &target)?, &snapshot.ciphertext, &snapshot.nonce)?;
    ensure!(digest(&bytes) == snapshot.sha256, "admitted import snapshot changed");
    let mut entries: Vec<crate::memory::model::MemoryEntry> = serde_json::from_slice(&bytes)?;
    for entry in &mut entries { entry.user = record.account.as_ref().context("account receipt missing")?.user.clone(); }
    let recovered = login.import_started;
    progress(journal, index)?.import_started = true;
    save_journal(journal)?;
    ensure!(!crate::service::off_mode(), "target service disabled; import receipt retained");
    crate::service::ensure_writable()?;
    let _deferred = crate::core_sdk::defer_indexing();
    let target_app = crate::service::App::open()?;
    let before = target_app.sync().context("target sync failed before import; source preserved")?;
    ensure!(before.converged, "target has not converged; import receipt retained");
    drop(target_app);
    // This existing importer commits once and deduplicates exact content on recovery.
    let report = crate::service::import_json_text(&serde_json::to_string(&entries)?)?;
    progress(journal, index)?.import = Some(json!({"report":report,"recovered":recovered}));
    save_journal(journal)?;
    }
    let sync = match crate::service::App::open().and_then(|app| app.sync()) {
        Ok(outcome) => json!({"status":if outcome.converged { "ok" } else { "pending" },"details":outcome}),
        Err(_) => json!({"status":"pending","reason":"post_import_sync_failed"}),
    };
    progress(journal, index)?.sync = Some(sync);
    save_journal(journal)
}

/// Only the Verified completion callback may publish legacy cloud mutations.
pub(super) fn finish_migration(journal: &mut Journal, index: usize) -> Result<()> {
    reconcile_publication(journal, index)?;
    let record = &journal.operations[index];
    let Some(login) = record.account.as_ref().and_then(|account| account.login.as_ref()) else { return Ok(()); };
    if !login.migrate_vault || login.publication_done || login.publication_pending { return Ok(()); }
    let account = record.account.as_ref().context("migration receipt missing")?;
    let authorized = account.authorization.clone().context("migration authorization missing")?;
    let addr = account.addr.clone();
    let session: Value = serde_json::from_slice(record.candidate.as_deref().context("migration candidate missing")?)?;
    let backend = journal.active.as_ref().filter(|active| active.operation_id.as_deref() == Some(record.operation_id.as_str()))
        .and_then(|active| active.pass_backends.last()).context("migration password checkpoint missing")?;
    let password = crate::keystore::read_imported(&record.alias, "pass", backend)?;
    let migration_auth = login.migration_salt.as_ref().filter(|_| !login.password_done).map(|salt| -> Result<Value> {
        Ok(json!({"salt":salt,"pass_hash":crate::memory::crypto::derive_pass_hash(&password, salt)?}))
    }).transpose()?;
    let prepared = PreparedLogin { user: account.user.clone(), directory: account.target.clone().context("migration target missing")?,
        original: None, session, super_password: String::new(), login_password: None, alias: record.alias.clone(),
        recovery_written: false, migration_cloud: if login.vault_done { None } else { login.migration_cloud.clone() }, migration_auth };
    prepared.finish_migration_guarded(&addr, &authorized, |step, complete| {
        let login = progress(journal, index)?;
        ensure!(!login.publication_pending || login.publication_step.as_deref() == Some(step),
            "a different migration effect is still unknown");
        login.publication_pending = !complete;
        login.publication_step = Some(step.to_owned());
        if complete {
            match step { "vault" => login.vault_done = true, "password" => login.password_done = true,
                _ => anyhow::bail!("invalid migration effect") }
        }
        save_journal(journal)
    })?;
    let login = progress(journal, index)?;
    login.publication_pending = false;
    login.publication_done = true;
    save_journal(journal)
}

/// Result recovery only observes the exact pending effect; it never sends a POST.
pub(super) fn reconcile_publication(journal: &mut Journal, index: usize) -> Result<()> {
    let record = &journal.operations[index];
    let account = record.account.as_ref().context("migration receipt missing")?;
    let Some(login) = account.login.as_ref().filter(|login| login.publication_pending) else { return Ok(()); };
    let authorized = account.authorization.as_ref().context("migration authorization missing")?;
    let confirmed = match login.publication_step.as_deref() {
        Some("vault") => {
            let session: Value = serde_json::from_slice(record.candidate.as_deref().context("migration candidate missing")?)?;
            let vault = json!({"version":session["vault_version"],"kdf_salt":session["kdf_salt"],
                "wrapped_urk":session["wrapped_urk"],"urk_nonce":session["urk_nonce"]});
            PreparedLogin::fetch_vault(&account.addr, authorized)? == vault
        }
        Some("password") => {
            let remote: Value = ureq::AgentBuilder::new().redirects(0).timeout(std::time::Duration::from_secs(30)).build()
                .get(&format!("{}/auth/salt", account.addr)).query("user", &account.user).call()?.into_json()?;
            remote["salt"].as_str().is_some_and(|salt| login.migration_salt.as_deref() == Some(salt))
        }
        _ => anyhow::bail!("pending migration effect has no valid checkpoint"),
    };
    if confirmed {
        let login = progress(journal, index)?;
        match login.publication_step.as_deref() {
            Some("vault") => login.vault_done = true,
            Some("password") => login.password_done = true,
            _ => anyhow::bail!("pending migration effect changed"),
        }
        login.publication_pending = false;
        login.publication_done = (login.migration_cloud.is_none() || login.vault_done)
            && (login.migration_salt.is_none() || login.password_done);
        save_journal(journal)?;
    }
    Ok(())
}
