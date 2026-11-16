//! Resume only the admitted login; never journal the supplemental request object.
use super::*;
use crate::MemoryTransport;
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
    #[serde(default)]
    password_slot: bool,
    #[serde(default)]
    pub(super) original_target_key: Option<(String, String)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    challenge: Option<ChallengeCheckpoint>,
    snapshot: Option<ImportSnapshot>,
    import_started: bool,
    #[serde(default)]
    sync_started: bool,
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
            required_inputs: Vec::new(), password_slot: false, original_target_key: None, challenge: None, snapshot: None,
            import_started: false, sync_started: false, import: None, sync: None, migration_cloud: None,
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

    pub(super) fn can_compensate_import(&self) -> bool {
        self.imports_local() && !self.migrate_vault && !self.import_started
            && self.import.is_none() && !self.publication_started()
    }
}

fn progress(journal: &mut Journal, index: usize) -> Result<&mut LoginProgress> {
    journal.operations[index].account.as_mut().and_then(|account| account.login.as_mut())
        .context("login continuation receipt is missing")
}

pub(super) fn factor_keys(session: &Value, factors: &respire_protocol::host_control::HostAuthVaultFactors)
    -> Result<crate::memory::SessionKeys> {
    use respire_protocol::host_control::HostAuthVaultFactors as Factors;
    let salt = session["kdf_salt"].as_str().context("vault salt missing")?;
    let wrapped = session["wrapped_urk"].as_str().context("vault wrap missing")?;
    let nonce = session["urk_nonce"].as_str().context("vault nonce missing")?;
    let version = session["vault_version"].as_i64().context("vault version missing")?;
    match (version, factors) {
        (1, Factors::V1 { password, account_secret }) => crate::memory::SessionKeys::unlock(password, account_secret, salt, wrapped, nonce),
        (2, Factors::V2 { super_password }) => crate::memory::SessionKeys::unlock_super(super_password, salt, wrapped, nonce),
        (3, Factors::V3 { super_password, secret_key }) => crate::memory::SessionKeys::unlock_vault(super_password, secret_key, salt, wrapped, nonce),
        (4, Factors::V4 { super_password }) => crate::memory::SessionKeys::unlock_v4(super_password, salt, wrapped, nonce),
        _ => anyhow::bail!("host factors do not match the original vault version"),
    }.context("explicit host factors do not unlock the original vault")
}

pub(super) fn raw_factor_keys(session: &Value, password: Option<&str>, super_password: Option<&str>, secret: Option<&str>)
    -> Result<crate::memory::SessionKeys> {
    use respire_protocol::host_control::HostAuthVaultFactors as Factors;
    let factors = match session["vault_version"].as_i64() {
        Some(1) => Factors::V1 { password: password.context("explicit v1 password required")?.to_owned(),
            account_secret: secret.context("explicit v1 Account Secret required")?.to_owned() },
        Some(2) => Factors::V2 { super_password: super_password.context("explicit super key required")?.to_owned() },
        Some(3) => Factors::V3 { super_password: super_password.context("explicit super key required")?.to_owned(),
            secret_key: secret.context("explicit v3 Secret Key required")?.to_owned() },
        Some(4) => Factors::V4 { super_password: super_password.context("explicit super key required")?.to_owned() },
        _ => anyhow::bail!("unsupported host vault version"),
    };
    factor_keys(session, &factors)
}

pub(super) fn supplied_keys(bytes: &[u8], material: Option<&respire_protocol::host_control::HostAuthSessionMaterial>)
    -> Result<crate::memory::SessionKeys> {
    let material = material.context("explicit host session material is required")?;
    ensure!(digest(bytes) == material.session_sha256, "host session material digest changed");
    factor_keys(&serde_json::from_slice(bytes)?, &material.factors)
}

fn request_candidate(params: &HostAuthLoginParams, record: &AuthRecord)
    -> Result<Option<respire_protocol::host_control::HostAuthSessionMaterial>> {
    use respire_protocol::host_control::{HostAuthSessionMaterial, HostAuthVaultFactors as Factors};
    let Some(bytes) = record.candidate.as_deref() else { return Ok(None); };
    let session: Value = serde_json::from_slice(bytes)?;
    let input = params.continuation.as_ref();
    let password = input.and_then(|input| input.legacy_password.as_ref()).or_else(|| match &params.authorization {
        HostAuthAuthorization::Password { password, .. } => Some(password), _ => None });
    let secret = input.and_then(|input| input.account_secret.as_ref());
    let factors = match session["vault_version"].as_i64() {
        Some(1) => Factors::V1 { password: password.context("explicit v1 password required")?.clone(),
            account_secret: secret.context("explicit v1 Account Secret required")?.clone() },
        Some(2) => Factors::V2 { super_password: params.super_password.clone().context("explicit super key required")? },
        Some(3) => Factors::V3 { super_password: params.super_password.clone().context("explicit super key required")?,
            secret_key: input.and_then(|input| input.secret_key.as_ref()).context("explicit v3 Secret Key required")?.clone() },
        Some(4) => Factors::V4 { super_password: params.super_password.clone().context("explicit super key required")? },
        _ => anyhow::bail!("unsupported login candidate vault version"),
    };
    Ok(Some(HostAuthSessionMaterial { session_sha256: digest(bytes), factors }))
}

fn reply(receipt: HostAuthAccountResult) -> respire_protocol::host_control::HostAuthLoginReply {
    respire_protocol::host_control::HostAuthLoginReply { receipt, handoff: None }
}

pub(super) fn candidate_reply(record: &AuthRecord) -> Result<respire_protocol::host_control::HostAuthLoginReply> {
    use respire_protocol::host_control::{HostAuthLoginHandoff, HostAuthLoginSlot};
    let mut result = reply(account_result(record)?);
    if record.phase == AuthPhase::Authorized && record.account.as_ref().and_then(|account| account.login.as_ref())
        .is_some_and(|login| login.required_inputs.as_slice() == ["host_credentials"]) {
        let session: Value = serde_json::from_slice(record.candidate.as_deref().context("login custody candidate missing")?)?;
        let mut slots = if session["vault_version"] == 1 { vec![HostAuthLoginSlot::Pass] }
            else { vec![HostAuthLoginSlot::Super] };
        if matches!(session["vault_version"].as_i64(), Some(1 | 3)) { slots.push(HostAuthLoginSlot::LegacySecret); }
        if record.account.as_ref().and_then(|account| account.login.as_ref()).is_some_and(|login| login.password_slot) {
            if session["vault_version"] != 1 { slots.push(HostAuthLoginSlot::Pass); }
        }
        result.handoff = Some(HostAuthLoginHandoff::Credentials {
            candidate_sha256: record.candidate_sha256.clone().context("login custody digest missing")?, session, slots });
    }
    Ok(result)
}

fn require_inputs(journal: &mut Journal, index: usize, inputs: &[&str]) -> Result<respire_protocol::host_control::HostAuthLoginReply> {
    progress(journal, index)?.required_inputs = inputs.iter().map(|input| (*input).to_owned()).collect();
    save_journal(journal)?;
    Ok(reply(account_result(&journal.operations[index])?))
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
    challenge: crate::auth::PasswordAuthorizationChallenge) -> Result<respire_protocol::host_control::HostAuthLoginHandoff> {
    ensure!(journal.operations[index].phase == AuthPhase::RemotePending,
        "challenge does not own a pending password step");
    let payload = encode_challenge(&journal.operations[index], challenge)?;
    let sha256 = digest(payload.as_bytes());
    progress(journal, index)?.challenge = Some(ChallengeCheckpoint { sha256: sha256.clone() });
    journal.operations[index].phase = AuthPhase::LoginInput;
    progress(journal, index)?.required_inputs = vec!["totp".to_owned()];
    save_journal(journal)?;
    Ok(respire_protocol::host_control::HostAuthLoginHandoff::Challenge { payload, sha256 })
}

fn read_challenge(journal: &Journal, index: usize,
    supplied: Option<&respire_protocol::host_control::HostAuthLoginChallenge>) -> Result<crate::auth::PasswordAuthorizationChallenge> {
    let record = &journal.operations[index];
    ensure!(record.phase == AuthPhase::LoginInput, "challenge is not awaiting input");
    let checkpoint = record.account.as_ref().and_then(|account| account.login.as_ref())
        .and_then(|login| login.challenge.as_ref()).context("challenge checkpoint is missing")?;
    let supplied = supplied.context("host challenge material is required; original operation retained")?;
    ensure!(supplied.sha256 == checkpoint.sha256, "host challenge digest changed");
    verify_challenge(record, &checkpoint.sha256, &supplied.payload)
}

fn save_authorization(journal: &mut Journal, index: usize, mut authorization: Value) -> Result<()> {
    let object = authorization.as_object_mut().context("authorization must be an object")?;
    for field in ["pass", "super", "secret", "secret_key"] { object.remove(field); }
    journal.operations[index].account.as_mut().context("login receipt missing")?.authorization = Some(authorization);
    journal.operations[index].phase = AuthPhase::Authorized;
    let login = progress(journal, index)?;
    login.required_inputs.clear();
    login.challenge = None;
    save_journal(journal)
}

pub(super) fn control_login(ownership: &AuthOwnership, id: &str, key: &str,
    params: &HostAuthLoginParams) -> Result<respire_protocol::host_control::HostAuthLoginReply> {
    let material = params.material.as_ref().context("login requires explicit host custody material")?;
    ensure!(material.keyring_account.strip_prefix("login-").is_some_and(|suffix|
        suffix.len() == 32 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())),
        "invalid host login credential owner");
    require_persistent_auth_backend(&material.keyring_backend)?;
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
        let candidate = request_candidate(params, &journal.operations[index])?;
        let receipt = control_account_result(ownership, &params.identity, id, key, candidate.as_ref())?;
        return Ok(reply(receipt));
    }
    if !fresh && !matches!(journal.operations[index].phase, AuthPhase::Authorized | AuthPhase::LoginInput) {
        // A pending/unknown network request cannot be replayed by supplying new factors.
        let candidate = request_candidate(params, &journal.operations[index])?;
        let receipt = control_account_result(ownership, &params.identity, id, key, candidate.as_ref())?;
        return Ok(reply(receipt));
    }
    if fresh {
        journal.operations[index].phase = AuthPhase::RemotePending;
        save_journal(&mut journal)?;
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
            Ok(crate::auth::PasswordAuthorizationStep::TotpRequired(challenge)) => {
                let handoff = checkpoint_challenge(&mut journal, index, challenge)?;
                return Ok(respire_protocol::host_control::HostAuthLoginReply {
                    receipt: account_result(&journal.operations[index])?, handoff: Some(handoff) });
            },
            Err(error) => {
                journal.operations[index].phase = AuthPhase::RemoteUnknown;
                save_journal(&mut journal)?;
                return Err(error.context("authorization outcome unknown; query the original operation, do not resend"));
            }
        }
    }
    if journal.operations[index].phase == AuthPhase::LoginInput {
        ensure!(journal.operations[index].account.as_ref().and_then(|account| account.login.as_ref())
            .and_then(|login| login.challenge.as_ref()).is_some(), "challenge checkpoint missing");
        let HostAuthAuthorization::Password { totp, .. } = &params.authorization else {
            anyhow::bail!("the admitted password challenge cannot change authorization method");
        };
        let Some(code) = totp.as_deref() else { return require_inputs(&mut journal, index, &["totp"]); };
        if crate::auth::validate_totp_code(code).is_err() { return require_inputs(&mut journal, index, &["totp"]); }
        let challenge = read_challenge(&journal, index, params.challenge.as_ref())?;
        journal.operations[index].phase = AuthPhase::RemotePending;
        progress(&mut journal, index)?.required_inputs.clear();
        save_journal(&mut journal)?;
        match crate::auth::continue_password_authorization(addr, &params.user, &challenge, code) {
            Ok(authorization) => save_authorization(&mut journal, index, authorization)?,
            Err(error) => {
                journal.operations[index].phase = AuthPhase::RemoteUnknown;
                save_journal(&mut journal)?;
                return Err(error.context("TOTP outcome unknown; query the original operation, do not resend"));
            }
        }
    }
    let mut authorized = journal.operations[index].account.as_ref()
        .and_then(|account| account.authorization.clone()).context("authorized login receipt is missing")?;
    let password = input.legacy_password.as_deref()
        .or_else(|| match &params.authorization {
            HostAuthAuthorization::Password { password, .. } => Some(password.as_str()),
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
        let mut local = crate::auth::read_session_json()?;
        let version = local["vault_version"].as_i64().context("local vault missing version")?;
        ensure!((1..=4).contains(&version), "unsupported local vault version");
        if version == 1 {
            ensure!(params.super_password.is_none(), "v1 requires the original password and Account Secret, not a super key");
        }
        let Some(password) = password else { return require_inputs(&mut journal, index, &["legacy_password"]); };
        if version == 1 && input.account_secret.as_deref().or(input.secret_key.as_deref()).is_none()
            && local["secret"].as_str().is_none() {
            return require_inputs(&mut journal, index, &["account_secret"]);
        }
        if version != 1 && params.super_password.as_deref().is_none_or(str::is_empty) {
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
            save_journal(&mut journal)?;
            vault
        };
        let version = vault["version"].as_i64().context("vault missing version")?;
        ensure!((1..=4).contains(&version), "unsupported vault version; original factors were preserved");
        if version == 1 {
            ensure!(params.super_password.is_none(), "v1 requires the original password and Account Secret, not a super key");
        }
        let target = login_directory(addr, &params.user)?;
        let mut local: Value = read_original(&target)?.map(|bytes| serde_json::from_slice(&bytes)).transpose()?.unwrap_or(json!({}));
        ensure!(local.is_object(), "target account session must be an object");
        let super_password = if version == 1 { String::new() } else {
            params.super_password.clone().unwrap_or_default()
        };
        if version == 1 {
            let missing: Vec<_> = [("pass", "legacy_password"), ("secret", "account_secret")].iter()
                .filter(|(field, _)| authorized[*field].as_str().is_none_or(|value| *field != "pass" && value.is_empty()))
                .map(|(_, input)| *input).collect();
            if !missing.is_empty() { return require_inputs(&mut journal, index, &missing); }
        } else if super_password.is_empty() {
            return require_inputs(&mut journal, index, &["super_password"]);
        }
        if version == 3 && authorized["secret_key"].as_str().is_none()
            && local["secret_key"].as_str().is_none() {
            return require_inputs(&mut journal, index, &["secret_key"]);
        }
        let config_before = match std::fs::read(crate::service::client_config_path()) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        match PreparedLogin::prepare_candidate_with_material(addr, &authorized, super_password, vault, None,
            false, false, None, material.target_original.as_ref()) {
            Ok(prepared) => prepared,
            Err(error) => {
                let Some(rejected) = error.downcast_ref::<LocalKeyMaterialRejected>() else {
                    return Err(error);
                };
                reject_local_key_material(ownership, &mut journal, index, rejected, &config_before)?;
                return Ok(reply(account_result(&journal.operations[index])?));
            }
        }
    };
    if let Some(confirmed) = input.merge_local {
        progress(&mut journal, index)?.confirm_merge(&prepared.directory, confirmed)?;
        save_journal(&mut journal)?;
    }
    let prepared_is_source = prepared.directory.try_exists()?
        && prepared.directory.canonicalize()? == ownership.profile;
    if input.offer_local_merge && !input.migrate_local && !prepared_is_source
        && crate::service::database_path(&ownership.profile)?.is_file()
        && progress(&mut journal, index)?.merge_local.is_none() {
        progress(&mut journal, index)?.offer_merge(&prepared.directory)?;
        return require_inputs(&mut journal, index, &["merge_local"]);
    }
    if progress(&mut journal, index)?.imports_local() {
        ensure!(!prepared_is_source, "source and destination are the same account; no migration needed");
        ensure!(!crate::service::off_mode(), "memory service is disabled; no local import was started");
        crate::service::ensure_writable()?;
        let source_bytes = read_original(&ownership.profile)?.context("original import source session missing")?;
        let source_keys = supplied_keys(&source_bytes, material.source.as_ref())?;
        let snapshot = crate::service::local_snapshot_with_keys(&source_keys)?;
        if let Some(original) = progress(&mut journal, index)?.snapshot.as_ref() {
            ensure!(original.sha256 == digest(snapshot.as_bytes()) && original.target == prepared.directory,
                "admitted import source or destination changed; retain its original operation");
        }
        let keys = prepared.material_keys()?;
        let encryption = import_key(&keys, &journal.operations[index], &prepared.directory)?;
        let (nonce, ciphertext) = crate::memory::crypto::encrypt_bytes(&encryption, snapshot.as_bytes())?;
        progress(&mut journal, index)?.snapshot = Some(ImportSnapshot { target: prepared.directory.clone(),
            sha256: digest(snapshot.as_bytes()), nonce, ciphertext });
    }
    prepared.alias = material.keyring_account.clone();
    prepared.session["keyring_account"] = json!(material.keyring_account);
    prepared.session["keyring_backend"] = json!(material.keyring_backend);
    if prepared.legacy_secret.is_some() {
        prepared.session["legacy_secret_backend"] = json!(material.keyring_backend);
    }
    let candidate_sha256 = digest(&serde_json::to_vec_pretty(&prepared.session)?);
    if let Some(ack) = &params.custody_ack {
        ensure!(journal.operations[index].candidate_sha256.as_deref() == Some(ack.candidate_sha256.as_str())
            && ack.candidate_sha256 == candidate_sha256,
            "host custody acknowledgement does not match the original login candidate");
    } else {
        if let Some(original) = &journal.operations[index].candidate_sha256 {
            ensure!(*original == candidate_sha256, "login custody candidate changed; original operation retained");
        }
        journal.operations[index].alias = material.keyring_account.clone();
        journal.operations[index].backend = Some(material.keyring_backend.clone());
        journal.operations[index].account.as_mut().context("login account missing")?.target = Some(prepared.directory.clone());
        checkpoint_account_candidate(&mut journal, index, &prepared.session)?;
        let original_target_key = prepared.original.as_deref().map(|bytes| -> Result<_> {
            let keys = supplied_keys(bytes, material.target_original.as_ref())?;
            Ok((digest(bytes), digest(&keys.urk)))
        }).transpose()?;
        let login = progress(&mut journal, index)?;
        login.original_target_key = original_target_key;
        login.password_slot = prepared.login_password.is_some();
        login.required_inputs = vec!["host_credentials".to_owned()];
        save_journal(&mut journal)?;
        return candidate_reply(&journal.operations[index]);
    }
    let login = progress(&mut journal, index)?;
    login.required_inputs.clear();
    login.password_slot = prepared.login_password.is_some();
    login.migration_cloud = prepared.migration_cloud.clone();
    login.migration_salt = prepared.migration_auth.as_ref().and_then(|auth| auth["salt"].as_str()).map(str::to_owned);
    save_journal(&mut journal)?;
    commit_account(ownership, &mut journal, index, &mut prepared)?;
    let candidate = request_candidate(params, &journal.operations[index])?;
    resume_import(ownership, &mut journal, index, candidate.as_ref())?;
    Ok(reply(account_result(&journal.operations[index])?))
}

pub(super) fn reject_local_key_material(ownership: &AuthOwnership, journal: &mut Journal,
    index: usize, rejected: &LocalKeyMaterialRejected, config_before: &Option<Vec<u8>>) -> Result<()> {
    let record = &journal.operations[index];
    let account = record.account.as_ref().context("rejected login receipt missing")?;
    let login = account.login.as_ref().context("rejected login progress missing")?;
    let active = journal.active.as_ref().context("rejected login recovery missing")?;
    ensure!(record.phase == AuthPhase::Authorized && !account.register
        && record.root == ownership.root && record.profile == ownership.profile
        && rejected.directory.canonicalize()? == ownership.profile
        && record.original_sha256.as_deref() == Some(rejected.original_sha256.as_str())
        && account.target.is_none() && record.candidate.is_none()
        && record.candidate_sha256.is_none() && record.backend.is_none()
        && !account.vault_pending && !account.published_vault
        && !login.import_started && !login.sync_started && login.import.is_none()
        && login.sync.is_none() && login.snapshot.is_none() && !login.publication_started()
        && active.operation_id.as_deref() == Some(record.operation_id.as_str())
        && active.alias == record.alias && active.directory == ownership.profile
        && active.original.as_deref().map(digest) == record.original_sha256
        && active.directory_existed && !active.owns_config
        && active.backends.is_empty() && active.pass_backends.is_empty(),
        "local rejection cannot prove an untouched owned account; retain the original operation");
    ensure!(crate::service::main_data_dir().canonicalize()? == ownership.root
        && crate::service::data_dir().canonicalize()? == ownership.profile
        && read_original(&ownership.profile)? == active.original
        && serde_json::to_vec(&load_journal()?)? == serde_json::to_vec(journal)?,
        "local rejection source or durable operation changed");
    verify_auth_identity(&ownership.root, &ownership.profile, &account.source_identity)?;
    let identity = account.source_identity.clone();
    let verify_config = || -> Result<()> {
        let current = match std::fs::read(crate::service::client_config_path()) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        ensure!(&current == config_before, "local rejection configuration changed");
        Ok(())
    };
    verify_config()?;
    rollback_account_material(journal, index)?;
    verify_config()?;
    verify_auth_identity(&ownership.root, &ownership.profile, &identity)?;
    finish_account_rollback(journal, index)
}

fn import_key(keys: &crate::memory::SessionKeys, record: &AuthRecord, target: &Path) -> Result<[u8; 32]> {
    crate::memory::crypto::derive_subkey(&keys.urk, &serde_json::to_vec(
        &("login-import-v1", &record.operation_id, &record.root, &record.profile, target))?)
}

#[derive(Default)]
pub(super) struct ImportSyncControl {
    phase: std::cell::Cell<Option<&'static str>>,
    pub(super) remote_effect_possible: std::cell::Cell<bool>,
}

impl crate::sync::SyncControl for ImportSyncControl {
    fn progress(&self, phase: &str) {
        self.phase.set(match phase {
            "capabilities" => Some("capabilities"),
            "pull" => Some("pull"),
            _ => None,
        });
    }

    fn local<T>(&self, action: impl FnOnce() -> Result<T>) -> Result<T> { action() }

    fn remote<T>(&self, action: impl FnOnce() -> Result<T>) -> Result<T> {
        // Unknown phases, pushes and resolutions must never authorize compensation.
        if self.phase.get().is_none() { self.remote_effect_possible.set(true); }
        action()
    }
}

fn install_candidate_runtime(record: &AuthRecord, candidate: &respire_protocol::host_control::HostAuthSessionMaterial) -> Result<()> {
    use respire_protocol::host_control::HostAuthVaultFactors as Factors;
    let (super_password, login_password, legacy_secret) = match &candidate.factors {
        Factors::V1 { password, account_secret } => (None, Some(password.clone()), Some(account_secret.clone())),
        Factors::V2 { super_password } | Factors::V4 { super_password } => (Some(super_password.clone()), None, None),
        Factors::V3 { super_password, secret_key } => (Some(super_password.clone()), None, Some(secret_key.clone())),
    };
    crate::auth::supply_runtime_session(respire_protocol::credentials::RuntimeUnlock {
        schema_version: respire_protocol::credentials::CREDENTIAL_SCHEMA_V,
        profile: record.account.as_ref().and_then(|account| account.target.clone()).context("import target missing")?,
        session_sha256: candidate.session_sha256.clone(), instance_id: record.operation_id.clone(), generation: 0,
        super_password, login_password, legacy_secret, provider_credentials: Vec::new(),
    })
}

pub(super) fn resume_import(ownership: &AuthOwnership, journal: &mut Journal, index: usize,
    candidate: Option<&respire_protocol::host_control::HostAuthSessionMaterial>) -> Result<()> {
    let record = &journal.operations[index];
    let Some(login) = record.account.as_ref().and_then(|account| account.login.as_ref()) else { return Ok(()); };
    if !login.imports_local() || login.import.is_some() && login.sync.is_some()
        || record.phase != AuthPhase::AwaitingVerification { return Ok(()); }
    let target = record.account.as_ref().and_then(|account| account.target.as_ref()).context("import target missing")?.clone();
    let target_identity = target.canonicalize()?;
    ensure!(crate::service::data_dir().canonicalize()? == target_identity, "import selection changed");
    let _target_lock = if target_identity == ownership.root || target_identity == ownership.profile { None }
        else { Some(crate::lock::LibraryLock::acquire(&target, std::time::Duration::from_secs(1))?) };
    account_material_keys(record, true, candidate)?;
    install_candidate_runtime(record, candidate.context("explicit import candidate required")?)?;
    if login.import.is_none() {
    let keys = account_material_keys(record, true, candidate)?;
    let snapshot = login.snapshot.as_ref().context("admitted encrypted import snapshot missing")?;
    ensure!(snapshot.target == target, "admitted import destination changed");
    let bytes = crate::memory::crypto::decrypt_bytes(&import_key(&keys, record, &target)?, &snapshot.ciphertext, &snapshot.nonce)?;
    ensure!(digest(&bytes) == snapshot.sha256, "admitted import snapshot changed");
    let mut entries: Vec<crate::memory::model::MemoryEntry> = serde_json::from_slice(&bytes)?;
    for entry in &mut entries { entry.user = record.account.as_ref().context("account receipt missing")?.user.clone(); }
    let recovered = login.import_started;
    let first_sync = !login.sync_started && !recovered;
    let original_material = original_import_material(record, journal.active.as_ref().context("import recovery missing")?);
    progress(journal, index)?.sync_started = true;
    save_journal(journal)?;
    ensure!(!crate::service::off_mode(), "target service disabled; import receipt retained");
    crate::service::ensure_writable()?;
    let _deferred = crate::core_sdk::defer_indexing();
    let target_app = crate::service::App::open()?;
    // Inspect all epochs/states, not only the currently sendable outbox batch.
    let database = rusqlite::Connection::open_with_flags(crate::service::database_path(&target)?,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW)?;
    let empty_target: bool = database.query_row("SELECT NOT EXISTS(SELECT 1 FROM memories)
        AND NOT EXISTS(SELECT 1 FROM sync_outbox) AND NOT EXISTS(SELECT 1 FROM sync_resolution_outbox)",
        [], |row| row.get(0))?;
    drop(database);
    let control = ImportSyncControl::default();
    let before = (|| -> Result<()> {
        let remote = crate::sync::build_remote_from_env()?;
        let stats = crate::sync::sync_controlled(&target_app.keys, &target_app.store, &remote, &control, None)?;
        let blobs = target_app.store.all(true)?;
        ensure!(blobs.len() == stats.remote_total
            && blobs.iter().filter(|entry| !entry.deleted).count() == stats.remote_alive,
            "target has not converged; import receipt retained");
        Ok(())
    })();
    drop(target_app);
    if let Err(error) = before {
        if first_sync && empty_target && !control.remote_effect_possible.get() {
            progress(journal, index)?.sync = Some(json!({"status":"failed","reason":"target_sync_failed_before_copying"}));
            rollback_import_before_copy(ownership, journal, index, _target_lock, original_material?.as_deref(), candidate)
                .context("target sync failed before copying; compensation unconfirmed; retain the original operation")?;
            return Ok(());
        }
        return Err(error.context("target sync failed before copying; outcome unknown; retain the original operation"));
    }
    progress(journal, index)?.import_started = true;
    save_journal(journal)?;
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
pub(super) fn finish_migration(journal: &mut Journal, index: usize, password: Option<&str>) -> Result<()> {
    reconcile_publication(journal, index)?;
    let record = &journal.operations[index];
    let Some(login) = record.account.as_ref().and_then(|account| account.login.as_ref()) else { return Ok(()); };
    if !login.migrate_vault || login.publication_done || login.publication_pending { return Ok(()); }
    let account = record.account.as_ref().context("migration receipt missing")?;
    let authorized = account.authorization.clone().context("migration authorization missing")?;
    let addr = account.addr.clone();
    let session: Value = serde_json::from_slice(record.candidate.as_deref().context("migration candidate missing")?)?;
    let password = password.context("explicit host migration password is required")?;
    let migration_auth = login.migration_salt.as_ref().filter(|_| !login.password_done).map(|salt| -> Result<Value> {
        Ok(json!({"salt":salt,"pass_hash":crate::memory::crypto::derive_pass_hash(&password, salt)?}))
    }).transpose()?;
    let prepared = PreparedLogin { user: account.user.clone(), directory: account.target.clone().context("migration target missing")?,
        original: None, session, super_password: String::new(), login_password: None, legacy_secret: None, alias: record.alias.clone(),
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
