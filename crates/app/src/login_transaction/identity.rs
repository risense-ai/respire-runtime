//! Identity writes share the existing durable admission and recovery journal.
use super::*;
use std::io::Read;
use respire_protocol::identity_write_control::{
    HostIdentityWriteOperation, HostIdentityWriteOutcome, HostIdentityWriteParams,
    HostIdentityWriteResult, HostSessionRevokeResult, HOST_IDENTITY_WRITE_SCHEMA_V,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IdentityOperation {
    operation: HostIdentityWriteOperation,
    source_identity: HostAuthIdentity,
    revoke: Option<HostSessionRevokeResult>,
}

fn fingerprint(root: &Path, profile: &Path, source: &HostAuthIdentity,
    operation: &HostIdentityWriteOperation) -> Result<String> {
    Ok(digest(&serde_json::to_vec(&json!({"schema_version":HOST_IDENTITY_WRITE_SCHEMA_V,
        "method":"control.identity.write", "root":root,"profile":profile,
        "source_identity":source,"operation":operation}))?))
}

fn selection(ownership: &AuthOwnership, id: &str, key: &str, params: &HostIdentityWriteParams) -> Result<()> {
    crate::service::require_profile_change_host()?;
    canonical_operation_id(id)?;
    ensure!(!key.is_empty() && key.len() <= 128 && key.bytes().all(|byte|
        byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)), "invalid identity idempotency key");
    ensure!(params.schema_version == HOST_IDENTITY_WRITE_SCHEMA_V
        && params.binding.installation_root == ownership.root && params.binding.profile == ownership.profile
        && ownership.root == crate::service::main_data_dir().canonicalize()?
        && ownership.profile == crate::service::data_dir().canonicalize()?, "identity write selection changed");
    verify_auth_identity(&ownership.root, &ownership.profile, &params.identity)
}

fn owned_index(journal: &Journal, ownership: &AuthOwnership, id: &str, key: &str,
    params: &HostIdentityWriteParams) -> Result<Option<usize>> {
    let Some(index) = journal.operations.iter().position(|record|
        record.operation_id == id || record.idempotency_key == key) else { return Ok(None); };
    let record = &journal.operations[index];
    let operation = record.identity.as_ref().context("operation is not an identity write")?;
    ensure!(record.operation_id == id && record.idempotency_key == key
        && record.root == ownership.root && record.profile == ownership.profile && record.account.is_none()
        && record.fingerprint == fingerprint(&ownership.root, &ownership.profile, &params.source_identity, &params.operation)?
        && record.fingerprint == fingerprint(&record.root, &record.profile, &operation.source_identity, &operation.operation)?,
        "identity idempotency conflict");
    if record.phase != AuthPhase::Committed {
        let active = journal.active.as_ref().context("identity recovery is missing")?;
        ensure!(active.operation_id.as_deref() == Some(id) && active.directory == record.profile
            && active.alias == record.alias && !active.owns_config && active.config.is_none()
            && active.backends.is_empty() && active.pass_backends.is_empty() && active.totp_backends.is_empty()
            && active.original.as_deref().map(digest) == record.original_sha256,
            "identity recovery binding mismatch");
    }
    verify_owned_session(journal, index)?;
    Ok(Some(index))
}

fn verify_owned_session(journal: &Journal, index: usize) -> Result<()> {
    let record = &journal.operations[index];
    let current = read_original(&record.profile)?;
    if record.phase == AuthPhase::Prepared || record.phase == AuthPhase::Committed {
        ensure!(record.candidate.as_deref().map(digest) == record.candidate_sha256, "identity candidate digest mismatch");
        let original = journal.active.as_ref().filter(|active|
            active.operation_id.as_deref() == Some(record.operation_id.as_str())).map(|active| &active.original);
        ensure!(current == record.candidate || (record.phase == AuthPhase::Prepared && original == Some(&current)),
            "identity candidate no longer owns the selected session");
    } else {
        ensure!(current.as_deref().map(digest) == record.original_sha256, "identity source session changed");
    }
    Ok(())
}

fn result(journal: &Journal, index: usize) -> Result<HostIdentityWriteResult> {
    verify_owned_session(journal, index)?;
    let record = &journal.operations[index];
    let operation = record.identity.as_ref().context("identity receipt is missing")?;
    let current_sha256 = read_original(&record.profile)?.as_deref().map(digest);
    let identity = match (&current_sha256, &operation.source_identity) {
        (None, _) => HostAuthIdentity::Absent,
        (Some(session_sha256), HostAuthIdentity::Bound { account_id, .. }) =>
            HostAuthIdentity::Bound { account_id: account_id.clone(), session_sha256: session_sha256.clone() },
        (Some(session_sha256), HostAuthIdentity::Unbound { operation_id, .. }) =>
            HostAuthIdentity::Unbound { operation_id: operation_id.clone(), session_sha256: session_sha256.clone() },
        _ => anyhow::bail!("identity write created an unowned session"),
    };
    verify_auth_identity(&record.root, &record.profile, &identity)?;
    Ok(HostIdentityWriteResult {
        operation_id: record.operation_id.clone(), fingerprint: record.fingerprint.clone(),
        operation: operation.operation.clone(), outcome: match record.phase {
            AuthPhase::Committed => HostIdentityWriteOutcome::Committed,
            AuthPhase::RemotePending | AuthPhase::RemoteUnknown => HostIdentityWriteOutcome::Unknown,
            AuthPhase::Admitted | AuthPhase::Prepared => HostIdentityWriteOutcome::Pending,
            _ => anyhow::bail!("invalid identity transaction phase"),
        }, path: record.profile.join("session.json"), session_found: record.original_sha256.is_some(),
        session_sha256: current_sha256, identity, revoke: operation.revoke.clone(),
    })
}

fn without_token(original: Option<&[u8]>) -> Result<Option<Vec<u8>>> {
    original.map(|bytes| -> Result<Vec<u8>> {
        let mut session: Value = serde_json::from_slice(bytes).context("invalid logout session")?;
        if let Some(fields) = session.as_object_mut() { fields.remove("token"); fields.remove("session_id"); }
        Ok(serde_json::to_vec_pretty(&session)?)
    }).transpose()
}

fn revoke_credentials(original: Option<&[u8]>) -> Result<(String, String)> {
    let session: Value = serde_json::from_slice(original.context("no local session")?)?;
    let addr = session["addr"].as_str().filter(|value| !value.is_empty()).context("cloud address is not configured")?;
    let token = session["token"].as_str().filter(|value| !value.is_empty()).context("no cloud token; log in first")?;
    Ok((addr.trim_end_matches('/').to_owned(), token.to_owned()))
}

fn admit(ownership: &AuthOwnership, id: &str, key: &str, params: &HostIdentityWriteParams) -> Result<(Journal, usize)> {
    let mut journal = load_journal()?;
    if let Some(index) = owned_index(&journal, ownership, id, key, params)? { return Ok((journal, index)); }
    ensure!(journal.active.is_none(), "resolve the existing transaction before admitting an identity write");
    ensure!(journal.operations.len() < 4096, "auth receipt capacity reached");
    ensure!(serde_json::to_value(&params.source_identity)? == serde_json::to_value(&params.identity)?,
        "initial identity differs from the admitted source");
    let original = read_original(&ownership.profile)?;
    match &params.operation {
        HostIdentityWriteOperation::Logout { full: false } => { without_token(original.as_deref())?; }
        HostIdentityWriteOperation::Logout { full: true } => {}
        HostIdentityWriteOperation::SessionRevoke { session_id } => {
            uuid::Uuid::parse_str(session_id).context("session id must be a full UUID")?;
            revoke_credentials(original.as_deref())?;
        }
    }
    let alias = format!("login-{}", uuid::Uuid::new_v4().simple());
    journal.active = Some(Recovery { directory: ownership.profile.clone(), original: original.clone(), config: None,
        alias: alias.clone(), backends: Vec::new(), pass_backends: Vec::new(), totp_backends: Vec::new(),
        directory_existed: true, operation_id: Some(id.to_owned()), owns_config: false });
    let index = journal.operations.len();
    journal.operations.push(AuthRecord { operation_id: id.to_owned(), idempotency_key: key.to_owned(),
        fingerprint: fingerprint(&ownership.root, &ownership.profile, &params.source_identity, &params.operation)?,
        root: ownership.root.clone(), profile: ownership.profile.clone(), original_sha256: original.as_deref().map(digest),
        candidate: None, candidate_sha256: None, alias, backend: None, phase: AuthPhase::Admitted, account: None, key_operation: None,
        identity: Some(IdentityOperation { operation: params.operation.clone(), source_identity: params.source_identity.clone(), revoke: None }) });
    save_journal(&journal)?;
    Ok((journal, index))
}

fn prepare(journal: &mut Journal, index: usize, candidate: Option<Vec<u8>>) -> Result<()> {
    journal.operations[index].candidate_sha256 = candidate.as_deref().map(digest);
    journal.operations[index].candidate = candidate;
    journal.operations[index].phase = AuthPhase::Prepared;
    save_journal(journal)
}

fn commit(journal: &mut Journal, index: usize) -> Result<()> {
    crate::service::ensure_writable()?;
    verify_owned_session(journal, index)?;
    let record = &journal.operations[index];
    ensure!(record.phase == AuthPhase::Prepared, "identity operation is not prepared");
    // Full logout deletes only session.json. No keyring or configuration is owned here.
    restore(&record.profile.join("session.json"), record.candidate.as_deref())?;
    #[cfg(unix)] { std::fs::File::open(&record.profile)?.sync_all()?; }
    journal.operations[index].phase = AuthPhase::Committed;
    retire_active(journal)
}

fn send_revoke(addr: &str, token: &str, session_id: &str) -> Result<HostSessionRevokeResult> {
    let session_id = uuid::Uuid::parse_str(session_id)?;
    let response = ureq::AgentBuilder::new().redirects(0).timeout(std::time::Duration::from_secs(30)).build()
        .post(&format!("{addr}/api/self/sessions/{session_id}/revoke"))
        .set("Authorization", &format!("Bearer {token}")).send_json(json!({}))
        .map_err(|_| anyhow!("session revoke outcome is unknown"))?;
    let mut bytes = Vec::new();
    let limit = respire_protocol::host_control::HOST_CONTROL_MAX_FRAME_BYTES;
    response.into_reader().take(limit as u64 + 1).read_to_end(&mut bytes)
        .map_err(|_| anyhow!("session revoke response is incomplete"))?;
    ensure!(bytes.len() <= limit, "session revoke response exceeds the control limit");
    let reply: Value = serde_json::from_slice(&bytes).map_err(|_| anyhow!("invalid session revoke response"))?;
    let revoked = reply["revoked"].as_bool().context("session revoke outcome is missing")?;
    let returned = reply["session_id"].as_str().context("session revoke identity is missing")?;
    ensure!(uuid::Uuid::parse_str(returned).ok() == Some(session_id), "session revoke response identity mismatch");
    // Do not retain arbitrary server fields (or credentials) in the durable receipt.
    Ok(HostSessionRevokeResult { revoked, session_id: returned.to_owned() })
}

/// The dispatcher must consume a Paused launch grant and bind ownership first.
/// A replay of RemotePending/Unknown never repeats the remote POST.
pub fn control_identity_write(ownership: &AuthOwnership, id: &str, key: &str,
    params: &HostIdentityWriteParams) -> Result<HostIdentityWriteResult> {
    selection(ownership, id, key, params)?;
    crate::service::ensure_writable()?;
    let (mut journal, index) = admit(ownership, id, key, params)?;
    if journal.operations[index].phase == AuthPhase::Admitted {
        let original = journal.active.as_ref().context("identity recovery is missing")?.original.clone();
        match &params.operation {
            HostIdentityWriteOperation::Logout { full } => {
                prepare(&mut journal, index, if *full { None } else { without_token(original.as_deref())? })?;
            }
            HostIdentityWriteOperation::SessionRevoke { session_id } => {
                let (addr, token) = revoke_credentials(original.as_deref())?;
                journal.operations[index].phase = AuthPhase::RemotePending;
                save_journal(&journal)?;
                let reply = match send_revoke(&addr, &token, session_id) {
                    Ok(reply) => reply,
                    Err(_) => {
                        journal.operations[index].phase = AuthPhase::RemoteUnknown;
                        save_journal(&journal)?;
                        return result(&journal, index);
                    }
                };
                let session: Value = serde_json::from_slice(original.as_deref().context("revoke source is missing")?)?;
                let candidate = if reply.revoked && session["session_id"].as_str() == Some(reply.session_id.as_str()) {
                    without_token(original.as_deref())?
                } else { original };
                journal.operations[index].identity.as_mut().context("identity receipt is missing")?.revoke = Some(reply);
                prepare(&mut journal, index, candidate)?;
            }
        }
    }
    if journal.operations[index].phase == AuthPhase::Prepared { commit(&mut journal, index)?; }
    result(&journal, index)
}

/// Result queries can finish only a checkpointed local commit, never a remote write.
pub fn control_identity_write_result(ownership: &AuthOwnership, id: &str, key: &str,
    params: &HostIdentityWriteParams) -> Result<HostIdentityWriteResult> {
    selection(ownership, id, key, params)?;
    let mut journal = load_journal()?;
    let index = owned_index(&journal, ownership, id, key, params)?.context("identity admission receipt is missing")?;
    if journal.operations[index].phase == AuthPhase::Prepared { commit(&mut journal, index)?; }
    result(&journal, index)
}

/// Extend the existing admission/recovery test without a network or new runner.
#[cfg(test)]
pub(super) fn assert_existing_recovery(root: &Path) -> Result<()> {
    use respire_protocol::ControlBinding;
    let ownership = AuthOwnership::acquire(root, root)?;
    let session_id = uuid::Uuid::new_v4().to_string();
    let original = serde_json::to_vec(&json!({"user":"identity-fixture", "addr":"https://never-contact.invalid",
        "token":"synthetic-unused-token", "session_id":session_id, "wrapped_urk":"preserved-wrap"}))?;
    let source = HostAuthIdentity::Bound { account_id: digest(b"identity-fixture"), session_sha256: digest(&original) };
    let mut params = HostIdentityWriteParams { schema_version: HOST_IDENTITY_WRITE_SCHEMA_V,
        binding: ControlBinding { installation_root: root.to_owned(), profile: root.to_owned(),
            launch_id: uuid::Uuid::new_v4().to_string(), expected_account_id: Some(digest(b"identity-fixture")) },
        identity: source.clone(), source_identity: source.clone(), operation: HostIdentityWriteOperation::Logout { full: false } };
    private_write(&root.join("session.json"), &original)?;
    let id = uuid::Uuid::new_v4().to_string();
    crate::service::set_workspace_mode("readonly")?;
    let before_readonly = std::fs::read(recovery_path())?;
    assert!(control_identity_write(&ownership, &id, &id, &params).is_err());
    assert_eq!(std::fs::read(recovery_path())?, before_readonly);
    crate::service::set_workspace_mode("off")?;
    let config = std::fs::read(crate::service::client_config_path())?;
    // Simulate loss after publishing a prepared local candidate, before its receipt.
    let (mut journal, index) = admit(&ownership, &id, &id, &params)?;
    let candidate = without_token(Some(&original))?.context("logout candidate missing")?;
    prepare(&mut journal, index, Some(candidate.clone()))?;
    private_write(&root.join("session.json"), &candidate)?;
    params.identity = HostAuthIdentity::Bound { account_id: digest(b"identity-fixture"), session_sha256: digest(&candidate) };
    ownership.recover(&params.identity)?;
    assert!(load_journal()?.operations[index].identity.is_some());
    let completed = control_identity_write_result(&ownership, &id, &id, &params)?;
    assert!(completed.outcome == HostIdentityWriteOutcome::Committed);
    assert_eq!(std::fs::read(root.join("session.json"))?, candidate);
    assert_eq!(std::fs::read(crate::service::client_config_path())?, config);
    assert!(control_identity_write_result(&ownership, &id, "foreign-key", &params).is_err());

    // A remote checkpoint is unknown after interruption, never permission to POST again.
    private_write(&root.join("session.json"), &original)?;
    params.identity = source.clone();
    params.operation = HostIdentityWriteOperation::SessionRevoke { session_id: session_id.clone() };
    let revoke_id = uuid::Uuid::new_v4().to_string();
    let (mut journal, index) = admit(&ownership, &revoke_id, &revoke_id, &params)?;
    journal.operations[index].phase = AuthPhase::RemotePending;
    save_journal(&journal)?;
    let pending = std::fs::read(recovery_path())?;
    assert!(control_identity_write_result(&ownership, &revoke_id, &revoke_id, &params)?.outcome == HostIdentityWriteOutcome::Unknown);
    assert!(control_identity_write(&ownership, &revoke_id, &revoke_id, &params)?.outcome == HostIdentityWriteOutcome::Unknown);
    assert_eq!(std::fs::read(recovery_path())?, pending);
    assert_eq!(std::fs::read(root.join("session.json"))?, original);
    params.operation = HostIdentityWriteOperation::SessionRevoke { session_id: uuid::Uuid::new_v4().to_string() };
    assert!(control_identity_write(&ownership, &revoke_id, &revoke_id, &params).is_err());
    params.operation = HostIdentityWriteOperation::SessionRevoke { session_id: session_id.clone() };
    params.source_identity = HostAuthIdentity::Absent;
    assert!(control_identity_write_result(&ownership, &revoke_id, &revoke_id, &params).is_err());
    params.source_identity = source;
    // Model the already durable successful reply; recovery applies only its local half.
    journal.operations[index].identity.as_mut().context("identity receipt missing")?.revoke =
        Some(HostSessionRevokeResult { revoked: true, session_id });
    prepare(&mut journal, index, Some(candidate.clone()))?;
    assert!(control_identity_write_result(&ownership, &revoke_id, &revoke_id, &params)?.outcome == HostIdentityWriteOutcome::Committed);
    assert_eq!(std::fs::read(root.join("session.json"))?, candidate);

    params.identity = HostAuthIdentity::Bound { account_id: digest(b"identity-fixture"), session_sha256: digest(&candidate) };
    params.source_identity = params.identity.clone();
    params.operation = HostIdentityWriteOperation::Logout { full: true };
    let full_id = uuid::Uuid::new_v4().to_string();
    let full = control_identity_write(&ownership, &full_id, &full_id, &params)?;
    assert!(full.outcome == HostIdentityWriteOutcome::Committed && full.session_found);
    assert!(full.identity == HostAuthIdentity::Absent && !root.join("session.json").exists());
    assert_eq!(std::fs::read(crate::service::client_config_path())?, config);
    params.identity = HostAuthIdentity::Absent;
    params.binding.expected_account_id = None;
    assert!(control_identity_write_result(&ownership, &full_id, &full_id, &params)?.outcome == HostIdentityWriteOutcome::Committed);
    params.operation = HostIdentityWriteOperation::Logout { full: false };
    assert!(control_identity_write(&ownership, &full_id, &full_id, &params).is_err());
    params.operation = HostIdentityWriteOperation::Logout { full: true };
    params.source_identity = HostAuthIdentity::Absent;
    let absent_id = uuid::Uuid::new_v4().to_string();
    let absent = control_identity_write(&ownership, &absent_id, &absent_id, &params)?;
    assert!(!absent.session_found && absent.outcome == HostIdentityWriteOutcome::Committed);
    assert!(!auth_recovery_pending()?);
    Ok(())
}
