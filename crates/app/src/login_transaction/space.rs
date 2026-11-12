//! Membership shares auth admission, fencing and durable credential checkpoints.
use super::*;
use std::io::Read;
use respire_protocol::space_control::*;

const MEMBERS: &str = "space_sessions.json";
const PREFIX: &str = "1mem-invite:";

#[derive(Debug)]
struct RemoteRejected;
impl std::fmt::Display for RemoteRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("space request rejected before a remote effect") }
}
impl std::error::Error for RemoteRejected {}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Member {
    session_id: String,
    device_name: String,
    readonly: bool,
    issued_at: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SpaceOperation {
    intent: HostSpaceOperation,
    source_identity: HostAuthIdentity,
    members_original: Option<Vec<u8>>,
    members_candidate: Option<Vec<u8>>,
    kick: Vec<HostSpaceKickItem>,
    session_id: Option<String>,
    code_backend: Option<String>,
    code_sha256: Option<String>,
    issued_at: Option<String>,
    target: Option<PathBuf>,
    credential_ready: bool,
}

fn op(journal: &Journal, index: usize) -> Result<&SpaceOperation> {
    journal.operations[index].space_operation.as_ref().context("space receipt missing")
}
fn op_mut(journal: &mut Journal, index: usize) -> Result<&mut SpaceOperation> {
    journal.operations[index].space_operation.as_mut().context("space receipt missing")
}

fn fingerprint(root: &Path, profile: &Path, source: &HostAuthIdentity, intent: &HostSpaceOperation) -> Result<String> {
    Ok(digest(&serde_json::to_vec(&json!({"schema_version":HOST_SPACE_SCHEMA_V,
        "method":"control.space", "root":root,"profile":profile,"source_identity":source,"operation":intent}))?))
}

fn safe_path(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                ensure!(!metadata.file_type().is_symlink(), "space path must not be a symbolic link");
                #[cfg(windows)] {
                    use std::os::windows::fs::MetadataExt;
                    ensure!(metadata.file_attributes() & 0x400 == 0, "space path must not be a reparse point");
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    safe_path(path)?;
    match std::fs::read(path) {
        Ok(bytes) => { ensure!(bytes.len() <= 64 * 1024, "space record exceeds limit"); Ok(Some(bytes)) }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn members(bytes: Option<&[u8]>) -> Result<Vec<Member>> {
    let rows: Vec<Member> = bytes.map(serde_json::from_slice).transpose()?.unwrap_or_default();
    let mut seen = std::collections::HashSet::new();
    for row in &rows {
        ensure!(uuid::Uuid::parse_str(&row.session_id)?.to_string() == row.session_id
            && seen.insert(row.session_id.clone()) && row.device_name.len() <= 128
            && row.issued_at.len() <= 128, "invalid or duplicate member record");
    }
    Ok(rows)
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key].as_str().filter(|value| !value.trim().is_empty()).context("space credential field missing")
}

fn parse_code(code: &str) -> Result<Value> {
    let raw = code.trim();
    let raw = raw.strip_prefix(PREFIX).unwrap_or(raw);
    ensure!(!raw.is_empty() && raw.len() <= 32 * 1024, "invalid invite code length");
    let bytes = hex::decode(raw).map_err(|_| anyhow!("invalid invite encoding"))?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| anyhow!("invalid invite payload"))?;
    for key in ["space", "addr", "user", "token", "super"] { field(&value, key)?; }
    let name = field(&value, "space")?.trim();
    ensure!(name.len() <= 40 && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte)), "invalid space name");
    ensure!(value.get("readonly").is_none_or(Value::is_boolean), "invalid invite readonly flag");
    Ok(value)
}

fn check_code(intent: &HostSpaceOperation, code: &str) -> Result<Value> {
    let HostSpaceOperation::Join { invite_sha256, space, addr, user, readonly } = intent
        else { anyhow::bail!("invite input is only valid for join"); };
    let value = parse_code(code)?;
    ensure!(*invite_sha256 == digest(code.trim().as_bytes()) && field(&value,"space")?.trim() == space
        && field(&value,"addr")?.trim().trim_end_matches('/') == addr && field(&value,"user")?.trim() == user
        && value["readonly"].as_bool().unwrap_or(false) == *readonly, "invite differs from the original space intent");
    Ok(value)
}

fn source_session(record: &AuthRecord) -> Result<Value> {
    let bytes = read_original(&record.profile)?.context("space owner session missing")?;
    ensure!(Some(digest(&bytes)) == record.original_sha256, "space source session changed");
    let session: Value = serde_json::from_slice(&bytes)?;
    for key in ["addr","user","token"] { field(&session,key)?; }
    Ok(session)
}

fn source_super(session: &Value) -> Result<String> {
    let alias = session["keyring_account"].as_str().unwrap_or(field(session,"user")?);
    let secret = if let Some(backend) = session["keyring_backend"].as_str() {
        require_persistent_auth_backend(backend)?;
        crate::keystore::read_imported(alias,"super",backend)?
    } else { crate::keystore::load_super(alias).context("space super password unavailable")? };
    crate::auth::unlock_session_keys(session,"",Some(&secret),alias)?;
    Ok(secret)
}

fn selection(ownership: &AuthOwnership, id: &str, key: &str, params: &HostSpaceParams) -> Result<()> {
    crate::service::require_profile_change_host()?;
    crate::service::ensure_writable()?;
    canonical_operation_id(id)?;
    ensure!(!key.is_empty() && key.len() <= 128 && key.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)), "invalid space key");
    ensure!(params.schema_version == HOST_SPACE_SCHEMA_V && params.binding.installation_root == ownership.root
        && params.binding.profile == ownership.profile && ownership.root == crate::service::main_data_dir().canonicalize()?
        && ownership.profile == crate::service::data_dir().canonicalize()?, "space selection changed");
    verify_auth_identity(&ownership.root,&ownership.profile,&params.identity)
}

fn owned_index(journal: &Journal, ownership: &AuthOwnership, id: &str, key: &str, params: &HostSpaceParams) -> Result<Option<usize>> {
    let Some(index) = journal.operations.iter().position(|record| record.operation_id == id || record.idempotency_key == key)
        else { return Ok(None); };
    let record = &journal.operations[index];
    let operation = op(journal,index)?;
    ensure!(record.operation_id == id && record.idempotency_key == key && record.root == ownership.root
        && record.profile == ownership.profile && record.account.is_none() && record.identity.is_none() && record.key_operation.is_none()
        && record.fingerprint == fingerprint(&record.root,&record.profile,&params.source_identity,&params.operation)?
        && record.fingerprint == fingerprint(&record.root,&record.profile,&operation.source_identity,&operation.intent)?
        && read_original(&record.profile)?.as_deref().map(digest) == record.original_sha256, "space idempotency or source conflict");
    if !matches!(record.phase,AuthPhase::Committed | AuthPhase::RolledBack) {
        let active = journal.active.as_ref().context("space recovery missing")?;
        ensure!(active.operation_id.as_deref() == Some(id) && active.alias == record.alias && !active.owns_config
            && active.config.is_none() && active.directory == *operation.target.as_ref().unwrap_or(&record.profile)
            && if operation.target.is_some() { active.original.is_none() && !active.directory_existed }
                else { active.original.as_deref().map(digest) == record.original_sha256 && active.directory_existed }, "space recovery owner mismatch");
    }
    Ok(Some(index))
}

fn admit(ownership: &AuthOwnership, id: &str, key: &str, params: &HostSpaceParams) -> Result<(Journal,usize)> {
    let mut journal = load_journal()?;
    if let Some(index) = owned_index(&journal,ownership,id,key,params)? { return Ok((journal,index)); }
    ensure!(journal.active.is_none() && journal.operations.len() < 4096, "resolve the existing operation before space admission");
    ensure!(params.identity == params.source_identity, "space initial identity changed");
    let original = read_original(&ownership.profile)?;
    let members_original = read_optional(&ownership.profile.join(MEMBERS))?;
    let rows = members(members_original.as_deref())?;
    let mut kick = Vec::new();
    let target = match &params.operation {
        HostSpaceOperation::Join { space, .. } => {
            check_code(&params.operation,params.invite_code.as_deref().context("join invite input missing")?)?;
            let target = ownership.root.join("accounts").join(space);
            safe_path(&target)?;
            ensure!(target.starts_with(&ownership.root) && !target.try_exists()?, "space target already exists or is outside the installation");
            Some(target)
        }
        HostSpaceOperation::Invite { note, .. } => {
            let device = format!("member-{}",note.as_deref().unwrap_or("invited").trim());
            ensure!(device.len() <= 128 && serde_json::to_vec_pretty(&rows)?.len() + device.len() + 256 <= 64 * 1024,
                "space member record or device-name limit exceeded");
            None
        }
        HostSpaceOperation::Kick { session_id, all } => {
            ensure!(!rows.is_empty(), "space has no issued member sessions");
            for row in &rows {
                if *all || session_id.as_deref() == Some(row.session_id.as_str()) {
                    kick.push(HostSpaceKickItem { session_id: row.session_id.clone(), state: HostSpaceKickState::Queued });
                }
            }
            ensure!(!kick.is_empty(), "space has no matching member session");
            None
        }
    };
    if target.is_none() {
        ensure!(matches!(params.identity,HostAuthIdentity::Bound { .. }), "space owner must have a bound identity");
        let session: Value = serde_json::from_slice(original.as_deref().context("space owner session missing")?)?;
        for field_name in ["addr","user","token"] { field(&session,field_name)?; }
        if matches!(params.operation,HostSpaceOperation::Invite { .. }) { source_super(&session)?; }
    }
    let alias = format!("login-{}",uuid::Uuid::new_v4().simple());
    journal.active = Some(Recovery { directory: target.clone().unwrap_or_else(|| ownership.profile.clone()),
        original: if target.is_some() { None } else { original.clone() }, config: None, alias: alias.clone(),
        backends: Vec::new(), pass_backends: Vec::new(), totp_backends: Vec::new(), directory_existed: target.is_none(),
        operation_id: Some(id.to_owned()), owns_config: false });
    let index = journal.operations.len();
    journal.operations.push(AuthRecord { operation_id: id.to_owned(), idempotency_key: key.to_owned(),
        fingerprint: fingerprint(&ownership.root,&ownership.profile,&params.source_identity,&params.operation)?,
        root: ownership.root.clone(), profile: ownership.profile.clone(), original_sha256: original.as_deref().map(digest),
        candidate: None, candidate_sha256: None, alias, backend: None, phase: AuthPhase::Admitted,
        account: None, identity: None, key_operation: None,
        profile_remove: None,
        space_operation: Some(SpaceOperation { intent: params.operation.clone(), source_identity: params.source_identity.clone(),
            members_original, members_candidate: None, kick, session_id: None, code_backend: None,
            code_sha256: None, issued_at: None, target, credential_ready: false }) });
    save_journal(&journal)?;
    Ok((journal,index))
}

fn reject_unadmitted(ownership: &AuthOwnership, id: &str, key: &str, params: &HostSpaceParams) -> Result<(Journal,usize)> {
    let mut journal = load_journal()?;
    ensure!(journal.active.is_none() && journal.operations.len() < 4096
        && !journal.operations.iter().any(|record| record.operation_id == id || record.idempotency_key == key),
        "space admission may exist; retain the original operation");
    // No remote write can precede durable admission. Keep a terminal negative
    // receipt even when the helper was lost before admission or input was invalid.
    ensure!(params.identity == params.source_identity, "rejected admission source changed");
    let original = read_original(&ownership.profile)?;
    let index = journal.operations.len();
    journal.operations.push(AuthRecord { operation_id:id.to_owned(),idempotency_key:key.to_owned(),
        fingerprint:fingerprint(&ownership.root,&ownership.profile,&params.source_identity,&params.operation)?,
        root:ownership.root.clone(),profile:ownership.profile.clone(),original_sha256:original.as_deref().map(digest),
        candidate:None,candidate_sha256:None,alias:format!("login-{}",uuid::Uuid::new_v4().simple()),backend:None,
        phase:AuthPhase::RolledBack,account:None,identity:None,key_operation:None,profile_remove:None,
        space_operation:Some(SpaceOperation { intent:params.operation.clone(),source_identity:params.source_identity.clone(),
            members_original:None,members_candidate:None,kick:Vec::new(),session_id:None,code_backend:None,code_sha256:None,
            issued_at:None,target:None,credential_ready:false }) });
    save_journal(&journal)?;
    Ok((journal,index))
}

fn remote(addr: &str, token: &str, path: &str, body: Option<Value>) -> Result<Value> {
    let agent = ureq::AgentBuilder::new().redirects(0).timeout(std::time::Duration::from_secs(10)).build();
    let url = format!("{}{path}",addr.trim_end_matches('/'));
    let request = if body.is_some() { agent.post(&url) } else { agent.get(&url) };
    let request = request.set("Authorization",&format!("Bearer {token}"));
    let response = match match body { Some(body) => request.send_json(body), None => request.call() } {
        Ok(response) => response,
        Err(ureq::Error::Status(400 | 401 | 403 | 404 | 405 | 422, _)) => return Err(RemoteRejected.into()),
        Err(_) => anyhow::bail!("space remote outcome unavailable"),
    };
    let mut bytes = Vec::new();
    response.into_reader().take(64 * 1024 + 1).read_to_end(&mut bytes).map_err(|_| anyhow!("space response incomplete"))?;
    ensure!(bytes.len() <= 64 * 1024, "space response exceeds limit");
    serde_json::from_slice(&bytes).map_err(|_| anyhow!("invalid space response"))
}

fn checkpoint_secret(journal: &mut Journal, index: usize, slot: &str, secret: &str) -> Result<String> {
    let alias = journal.operations[index].alias.clone();
    let backend = crate::keystore::import_credential_checkpoint(&alias,slot,secret,|backend| {
        require_persistent_auth_backend(backend)?;
        let active = journal.active.as_mut().context("space recovery missing")?;
        let slots = if slot == "pass" { &mut active.pass_backends } else { &mut active.backends };
        if !slots.iter().any(|value| value == backend) { slots.push(backend.to_owned()); }
        if slot == "pass" { op_mut(journal,index)?.code_backend = Some(backend.to_owned()); }
        else { journal.operations[index].backend = Some(backend.to_owned()); }
        save_journal(journal)
    })?;
    ensure!(crate::keystore::read_imported(&alias,slot,backend)? == secret, "space credential readback mismatch");
    Ok(backend.to_owned())
}

fn invite(journal: &mut Journal, index: usize) -> Result<()> {
    let HostSpaceOperation::Invite { note, readonly } = op(journal,index)?.intent.clone() else { anyhow::bail!("not invite"); };
    let session = source_session(&journal.operations[index])?;
    let record = &journal.operations[index];
    let name = if record.profile == record.root {
        field(&session,"user")?.to_owned()
    } else {
        // Journal paths are canonical; resolve accounts under the admitted root before comparing.
        let accounts = record.root.join("accounts");
        safe_path(&accounts)?;
        let accounts = accounts.canonicalize().context("cannot resolve space accounts root")?;
        ensure!(record.profile.parent() == Some(accounts.as_path()), "space profile is not directly under its installation accounts root");
        record.profile.file_name().and_then(|name| name.to_str())
            .context("space profile name is not UTF-8")?.to_owned()
    };
    let secret = source_super(&session)?;
    checkpoint_secret(journal,index,"super",&secret)?;
    let device = format!("member-{}",note.as_deref().unwrap_or("invited").trim());
    op_mut(journal,index)?.issued_at = Some(chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs,true));
    journal.operations[index].phase = AuthPhase::RemotePending;
    save_journal(journal)?;
    let reply = remote(field(&session,"addr")?,field(&session,"token")?,"/api/self/sessions",Some(json!({"device_name":device,"readonly":readonly})));
    let reply = match reply {
        Ok(reply) => reply,
        Err(error) if error.is::<RemoteRejected>() => {
            journal.operations[index].phase = AuthPhase::RollingBack;
            save_journal(journal)?;
            return reject_invite(journal,index);
        }
        Err(_) => { journal.operations[index].phase = AuthPhase::RemoteUnknown; return save_journal(journal); }
    };
    let sid = field(&reply,"session_id")?.to_owned();
    ensure!(uuid::Uuid::parse_str(&sid)?.to_string() == sid, "invalid member session identity");
    let code = format!("{PREFIX}{}",hex::encode(serde_json::to_vec(&json!({"space":name,"addr":field(&session,"addr")?,
        "user":field(&session,"user")?,"token":field(&reply,"token")?,"session_id":sid,"super":secret,
        "secret_key":session["secret_key"],"readonly":readonly,"control_operation_id":journal.operations[index].operation_id,
        "control_fingerprint":journal.operations[index].fingerprint}))?));
    ensure!(code.len() <= 32 * 1024, "invite result exceeds private control limit");
    checkpoint_secret(journal,index,"pass",&code)?;
    stage_invite_code(journal,index,&code)
}

fn stage_invite_code(journal: &mut Journal, index: usize, code: &str) -> Result<()> {
    let value = parse_code(code)?;
    let record = &journal.operations[index];
    let operation = op(journal,index)?;
    let HostSpaceOperation::Invite { note,readonly } = &operation.intent else { anyhow::bail!("not invite"); };
    let source = source_session(record)?;
    let backend = record.backend.as_deref().context("invite source credential checkpoint missing")?;
    require_persistent_auth_backend(backend)?;
    ensure!(value["control_operation_id"].as_str() == Some(record.operation_id.as_str())
        && value["control_fingerprint"].as_str() == Some(record.fingerprint.as_str())
        && field(&value,"user")? == field(&source,"user")? && field(&value,"addr")? == field(&source,"addr")?
        && value["readonly"].as_bool() == Some(*readonly)
        && field(&value,"super")? == crate::keystore::read_imported(&record.alias,"super",backend)?, "invite checkpoint owner mismatch");
    let sid = field(&value,"session_id")?.to_owned();
    ensure!(uuid::Uuid::parse_str(&sid)?.to_string() == sid, "invalid invite checkpoint session");
    let mut rows = members(operation.members_original.as_deref())?;
    rows.push(Member { session_id:sid.clone(),device_name:format!("member-{}",note.as_deref().unwrap_or("invited").trim()),
        readonly:*readonly,issued_at:operation.issued_at.clone().context("invite admission time missing")? });
    let operation = op_mut(journal,index)?;
    operation.session_id = Some(sid);
    operation.code_sha256 = Some(digest(code.as_bytes()));
    operation.members_candidate = Some(serde_json::to_vec_pretty(&rows)?);
    journal.operations[index].phase = AuthPhase::Prepared;
    save_journal(journal)
}

fn reject_invite(journal: &mut Journal, index: usize) -> Result<()> {
    ensure!(matches!(op(journal,index)?.intent,HostSpaceOperation::Invite { .. })
        && journal.operations[index].phase == AuthPhase::RollingBack, "space rejection is not an owned invite");
    let active = journal.active.as_ref().context("invite recovery missing")?;
    // Only discard this admission's credential copies. It never owned session/config.
    for (slot,backends) in [("super",&active.backends),("pass",&active.pass_backends)] {
        for backend in backends { crate::keystore::remove_imported(&active.alias,slot,backend)?; }
    }
    journal.operations[index].phase = AuthPhase::RolledBack;
    retire_active(journal)
}

fn join(journal: &mut Journal, index: usize, params: &HostSpaceParams) -> Result<()> {
    let code = params.invite_code.as_deref().context("join invite input missing")?;
    let value = check_code(&op(journal,index)?.intent,code)?;
    let HostSpaceOperation::Join { addr,user, .. } = op(journal,index)?.intent.clone() else { anyhow::bail!("not join"); };
    let target = op(journal,index)?.target.clone().context("join target missing")?;
    safe_path(&target)?;
    ensure!(read_original(&target)?.is_none(), "join target session already exists");
    let token = field(&value,"token")?;
    let who = remote(&addr,token,"/api/self",None)?;
    ensure!(field(&who,"user")? == user, "invite token belongs to a different account");
    let mut vault = remote(&addr,token,"/api/self/vault",None)?;
    if vault.get("version").is_none() { vault["version"] = json!(4); }
    let secret = field(&value,"super")?;
    let authorized = json!({"user":user,"token":token,"session_id":value["session_id"],"secret_key":value["secret_key"]});
    let prepared = PreparedLogin::prepare_candidate(&addr,&authorized,secret.to_owned(),vault,None,false,false,Some(&target))?;
    ensure!(prepared.original.is_none() && prepared.directory == target, "join candidate changed target");
    let mut session = prepared.session.clone();
    session["keyring_account"] = json!(journal.operations[index].alias);
    // Publish the candidate and its credential backend before either owned file.
    checkpoint_account_candidate(journal,index,&session)?;
    journal.operations[index].phase = AuthPhase::Authorized;
    save_journal(journal)?;
    let backend = checkpoint_secret(journal,index,"super",secret)?;
    session["keyring_backend"] = json!(backend);
    checkpoint_account_candidate(journal,index,&session)?;
    op_mut(journal,index)?.credential_ready = true;
    journal.operations[index].phase = AuthPhase::Prepared;
    save_journal(journal)
}

fn kick(journal: &mut Journal, index: usize) -> Result<()> {
    let session = source_session(&journal.operations[index])?;
    for item in 0..op(journal,index)?.kick.len() {
        if op(journal,index)?.kick[item].state != HostSpaceKickState::Queued { continue; }
        let sid = op(journal,index)?.kick[item].session_id.clone();
        op_mut(journal,index)?.kick[item].state = HostSpaceKickState::RemotePending;
        journal.operations[index].phase = AuthPhase::RemotePending;
        save_journal(journal)?;
        let reply = remote(field(&session,"addr")?,field(&session,"token")?,&format!("/api/self/sessions/{sid}/revoke"),Some(json!({})));
        let state = match reply {
            Ok(reply) if reply["session_id"].as_str() == Some(sid.as_str()) => match reply["revoked"].as_bool() {
                Some(true) => HostSpaceKickState::Revoked,
                Some(false) => HostSpaceKickState::Absent,
                None => HostSpaceKickState::Unknown,
            },
            Err(error) if error.is::<RemoteRejected>() => HostSpaceKickState::Rejected,
            _ => HostSpaceKickState::Unknown,
        };
        op_mut(journal,index)?.kick[item].state = state;
        save_journal(journal)?;
    }
    prepare_kick(journal,index)
}

fn prepare_kick(journal: &mut Journal, index: usize) -> Result<()> {
    for item in &mut op_mut(journal,index)?.kick {
        if item.state == HostSpaceKickState::RemotePending { item.state = HostSpaceKickState::Unknown; }
    }
    let operation = op(journal,index)?;
    let rows: Vec<Member> = members(operation.members_original.as_deref())?.into_iter().filter(|row|
        !operation.kick.iter().any(|item| item.session_id == row.session_id && item.state == HostSpaceKickState::Revoked)).collect();
    op_mut(journal,index)?.members_candidate = Some(serde_json::to_vec_pretty(&rows)?);
    journal.operations[index].phase = AuthPhase::Prepared;
    save_journal(journal)
}

fn verify_join_candidate(journal: &Journal, index: usize) -> Result<()> {
    let record = &journal.operations[index];
    let operation = op(journal,index)?;
    let HostSpaceOperation::Join { addr,user, .. } = &operation.intent else { anyhow::bail!("not join"); };
    let target = operation.target.as_ref().context("join target missing")?;
    safe_path(target)?;
    ensure!(operation.credential_ready && record.candidate.as_deref().map(digest) == record.candidate_sha256,
        "join candidate credential checkpoint missing");
    let session: Value = serde_json::from_slice(record.candidate.as_deref().context("join candidate missing")?)?;
    ensure!(session["user"].as_str() == Some(user) && session["addr"].as_str() == Some(addr)
        && session["keyring_account"].as_str() == Some(record.alias.as_str())
        && session["keyring_backend"].as_str() == record.backend.as_deref(), "join candidate identity changed");
    let backend = record.backend.as_deref().context("join backend missing")?;
    require_persistent_auth_backend(backend)?;
    let secret = crate::keystore::read_imported(&record.alias,"super",backend)?;
    crate::auth::unlock_session_keys(&session,"",Some(&secret),&record.alias)?;
    // Admission required an absent profile. Never adopt a library created later.
    ensure!(!crate::service::database_path(target)?.try_exists()?, "join target acquired an unowned library");
    Ok(())
}

fn verify_join(journal: &Journal, index: usize) -> Result<()> {
    verify_join_candidate(journal,index)?;
    let record = &journal.operations[index];
    let operation = op(journal,index)?;
    let target = operation.target.as_ref().context("join target missing")?;
    ensure!(read_original(target)? == record.candidate, "join candidate not durably installed");
    let readonly = matches!(operation.intent,HostSpaceOperation::Join { readonly:true, .. });
    let agent = read_optional(&target.join("agent.json"))?;
    if readonly { ensure!(agent.as_deref() == Some(br#"{"readonly":true,"readonly_team":true}"#.as_slice()), "join readonly_team changed"); }
    else { ensure!(agent.is_none(), "join unexpectedly created agent configuration"); }
    Ok(())
}

fn commit(journal: &mut Journal, index: usize) -> Result<()> {
    crate::service::ensure_writable()?;
    let record = &journal.operations[index];
    ensure!(read_original(&record.profile)?.as_deref().map(digest) == record.original_sha256, "space source changed before commit");
    let operation = op(journal,index)?;
    if let Some(target) = &operation.target {
        safe_path(target)?;
        let _lock = crate::lock::LibraryLock::acquire(target,std::time::Duration::from_secs(1))?;
        verify_join_candidate(journal,index)?;
        let current = read_original(target)?;
        ensure!(current.is_none() || current == record.candidate, "join destination no longer owned");
        let agent_path = target.join("agent.json");
        let agent = read_optional(&agent_path)?;
        let readonly = matches!(operation.intent,HostSpaceOperation::Join { readonly:true, .. });
        let expected = br#"{"readonly":true,"readonly_team":true}"#;
        ensure!(agent.is_none() || readonly && agent.as_deref() == Some(expected.as_slice()), "join agent configuration no longer owned");
        // Set the durable team gate before publishing the selectable session.
        if readonly { private_write(&agent_path,expected)?; }
        private_write(&target.join("session.json"),record.candidate.as_deref().context("join candidate missing")?)?;
        verify_join(journal,index)?;
    } else {
        let path = record.profile.join(MEMBERS);
        let current = read_optional(&path)?;
        ensure!(current == operation.members_original || current == operation.members_candidate, "space member record changed outside the original operation");
        private_write(&path,operation.members_candidate.as_deref().context("space member candidate missing")?)?;
    }
    if op(journal,index)?.kick.iter().any(|item| matches!(item.state,HostSpaceKickState::Unknown | HostSpaceKickState::Queued | HostSpaceKickState::RemotePending)) {
        journal.operations[index].phase = AuthPhase::RemoteUnknown;
        save_journal(journal)
    } else {
        journal.operations[index].phase = AuthPhase::Committed;
        retire_active(journal)
    }
}

fn result(journal: &Journal, index: usize) -> Result<HostSpaceResult> {
    let record = &journal.operations[index];
    let operation = op(journal,index)?;
    let committed = record.phase == AuthPhase::Committed;
    if committed && operation.target.is_some() { verify_join(journal,index)?; }
    let invite_code = if matches!(operation.intent,HostSpaceOperation::Invite { .. }) && committed {
        let backend = operation.code_backend.as_deref().context("invite credential checkpoint missing")?;
        require_persistent_auth_backend(backend)?;
        let code = crate::keystore::read_imported(&record.alias,"pass",backend)?;
        ensure!(operation.code_sha256.as_deref() == Some(digest(code.as_bytes()).as_str()), "invite credential digest changed");
        Some(code)
    } else { None };
    Ok(HostSpaceResult { operation_id: record.operation_id.clone(), fingerprint: record.fingerprint.clone(),
        profile: record.profile.clone(), identity: operation.source_identity.clone(), operation: operation.intent.clone(),
        outcome: if committed { HostSpaceOutcome::Committed } else if record.phase == AuthPhase::RolledBack { HostSpaceOutcome::Rejected }
        else if matches!(record.phase,AuthPhase::RemotePending | AuthPhase::RemoteUnknown) {
            HostSpaceOutcome::Unknown
        } else { HostSpaceOutcome::Pending }, invite_code, session_id: operation.session_id.clone(),
        target_profile: if record.phase == AuthPhase::RolledBack { None } else { operation.target.clone() },
        target_account_id: if committed { match &operation.intent { HostSpaceOperation::Join { user, .. } => Some(digest(user.as_bytes())), _ => None } } else { None },
        target_session_sha256: if committed && operation.target.is_some() { record.candidate_sha256.clone() } else { None },
        kick: operation.kick.clone(), remaining: if operation.target.is_none() && operation.members_candidate.is_some() {
            Some(members(operation.members_candidate.as_deref())?.len())
        } else { None },
    })
}

/// The caller has consumed a Paused launch grant and owns the source locks.
pub fn control_space(ownership: &AuthOwnership, id: &str, key: &str, params: &HostSpaceParams, query_only: bool) -> Result<HostSpaceResult> {
    selection(ownership,id,key,params)?;
    let (mut journal,index) = if query_only {
        let journal = load_journal()?;
        match owned_index(&journal,ownership,id,key,params)? {
            Some(index) => (journal,index),
            None => reject_unadmitted(ownership,id,key,params)?,
        }
    } else {
        match admit(ownership,id,key,params) {
            Ok(admission) => admission,
            Err(error) => match reject_unadmitted(ownership,id,key,params) {
                Ok(rejected) => rejected,
                Err(_) => return Err(error),
            },
        }
    };
    if journal.operations[index].phase == AuthPhase::RollingBack { reject_invite(&mut journal,index)?; }
    if matches!(params.operation,HostSpaceOperation::Invite { .. })
        && matches!(journal.operations[index].phase,AuthPhase::RemotePending | AuthPhase::RemoteUnknown) {
        if let Some(backend) = op(&journal,index)?.code_backend.as_deref() {
            require_persistent_auth_backend(backend)?;
            // This slot is written only after the remote reply. Never resend a POST.
            if let Ok(code) = crate::keystore::read_imported(&journal.operations[index].alias,"pass",backend) {
                stage_invite_code(&mut journal,index,&code)?;
            }
        }
    }
    let resume_join = matches!(params.operation,HostSpaceOperation::Join { .. }) && params.invite_code.is_some()
        && matches!(journal.operations[index].phase,AuthPhase::Admitted | AuthPhase::Authorized);
    if !query_only && journal.operations[index].phase == AuthPhase::Admitted || resume_join {
        match params.operation {
            HostSpaceOperation::Invite { .. } => invite(&mut journal,index)?,
            HostSpaceOperation::Join { .. } => {
                if let Err(error) = join(&mut journal,index,params) {
                    if !error.is::<RemoteRejected>() { return Err(error); }
                    ensure!(owned_index(&journal,ownership,id,key,params)? == Some(index), "rejected join owner changed");
                    let record = &journal.operations[index];
                    let operation = op(&journal,index)?;
                    let active = journal.active.as_ref().context("rejected join recovery missing")?;
                    let target = operation.target.as_ref().context("rejected join target missing")?;
                    safe_path(target)?;
                    ensure!(record.phase == AuthPhase::Admitted && record.candidate.is_none()
                        && record.candidate_sha256.is_none() && record.backend.is_none()
                        && !operation.credential_ready && operation.code_backend.is_none()
                        && operation.code_sha256.is_none() && operation.session_id.is_none()
                        && operation.members_candidate.is_none() && operation.kick.is_empty()
                        && active.backends.is_empty() && active.pass_backends.is_empty()
                        && active.totp_backends.is_empty() && !target.try_exists()?,
                        "rejected join may already own effects; retain the original operation");
                    // Publish the terminal receipt and clear only this admission in one journal write.
                    journal.operations[index].phase = AuthPhase::RolledBack;
                    retire_active(&mut journal)?;
                }
            }
            HostSpaceOperation::Kick { .. } => kick(&mut journal,index)?,
        }
    }
    // A query never sends a remote write. Checkpointed per-member outcomes survive interruption.
    if matches!(params.operation,HostSpaceOperation::Kick { .. }) && matches!(journal.operations[index].phase,AuthPhase::RemotePending | AuthPhase::RemoteUnknown) {
        prepare_kick(&mut journal,index)?;
    }
    if journal.operations[index].phase == AuthPhase::Prepared { commit(&mut journal,index)?; }
    result(&journal,index)
}

#[cfg(test)]
pub(super) fn assert_existing_recovery(root: &Path) -> Result<()> {
    let ownership = AuthOwnership::acquire(root,root)?;
    let original = serde_json::to_vec(&json!({"user":"space-fixture","addr":"https://never-contact.invalid",
        "token":"synthetic-unused-token"}))?;
    private_write(&root.join("session.json"),&original)?;
    let first = uuid::Uuid::new_v4().to_string();
    let second = uuid::Uuid::new_v4().to_string();
    let rows = vec![Member { session_id: first.clone(),device_name:"member-first".into(),readonly:false,issued_at:"fixture".into() },
        Member { session_id: second.clone(),device_name:"member-second".into(),readonly:true,issued_at:"fixture".into() }];
    private_write(&root.join(MEMBERS),&serde_json::to_vec(&rows)?)?;
    let identity = HostAuthIdentity::Bound { account_id:digest(b"space-fixture"),session_sha256:digest(&original) };
    let mut params = HostSpaceParams { schema_version: HOST_SPACE_SCHEMA_V,
        binding: respire_protocol::ControlBinding { installation_root:root.to_owned(),profile:root.to_owned(),
            launch_id:uuid::Uuid::new_v4().to_string(),expected_account_id:Some(digest(b"space-fixture")) },
        identity:identity.clone(),source_identity:identity,operation:HostSpaceOperation::Kick { session_id:None,all:true },invite_code:None };
    let mut unsupported = serde_json::to_value(&params)?;
    unsupported["argv"] = json!(["unsupported"]);
    assert!(serde_json::from_value::<HostSpaceParams>(unsupported).is_err());
    let id = uuid::Uuid::new_v4().to_string();
    let before = std::fs::read(recovery_path())?;
    crate::service::set_workspace_mode("readonly")?;
    assert!(control_space(&ownership,&id,&id,&params,false).is_err());
    assert_eq!(std::fs::read(recovery_path())?,before);
    crate::service::set_workspace_mode("off")?;
    let config = std::fs::read(crate::service::client_config_path())?;
    let rejected_id = uuid::Uuid::new_v4().to_string();
    params.operation = HostSpaceOperation::Kick { session_id:Some(uuid::Uuid::new_v4().to_string()),all:false };
    assert!(control_space(&ownership,&rejected_id,&rejected_id,&params,false)?.outcome == HostSpaceOutcome::Rejected);
    assert!(control_space(&ownership,&rejected_id,&rejected_id,&params,true)?.outcome == HostSpaceOutcome::Rejected);
    assert!(!auth_recovery_pending()?);
    let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow!(error.to_string()))?;
    let addr = format!("http://{}",server.server_addr());
    let code = format!("{PREFIX}{}",hex::encode(serde_json::to_vec(&json!({"space":"rejected-join",
        "addr":addr,"user":"rejected-user","token":"revoked-token","super":"synthetic-super"}))?));
    params.operation = HostSpaceOperation::Join { invite_sha256:digest(code.as_bytes()),space:"rejected-join".into(),
        addr,user:"rejected-user".into(),readonly:false };
    params.invite_code = Some(code);
    let worker = std::thread::spawn(move || -> std::result::Result<tiny_http::Server,String> {
        let request = server.recv_timeout(std::time::Duration::from_secs(20))
            .map_err(|error| error.to_string())?.ok_or("rejected join never fetched its identity")?;
        assert_eq!(request.method(),&tiny_http::Method::Get);
        assert_eq!(request.url(),"/api/self");
        request.respond(tiny_http::Response::empty(401)).map_err(|error| error.to_string())?;
        Ok(server)
    });
    let join_id = uuid::Uuid::new_v4().to_string();
    let rejected = control_space(&ownership,&join_id,&join_id,&params,false);
    let server = worker.join().map_err(|_| anyhow!("rejected join fixture panicked"))?
        .map_err(|error| anyhow!(error))?;
    let rejected = rejected?;
    assert!(rejected.outcome == HostSpaceOutcome::Rejected);
    assert_eq!(rejected.operation_id,join_id);
    assert!(rejected.target_profile.is_none() && rejected.target_account_id.is_none()
        && rejected.target_session_sha256.is_none());
    let rejected_journal = load_journal()?;
    let index = owned_index(&rejected_journal,&ownership,&join_id,&join_id,&params)?
        .context("rejected join receipt missing")?;
    assert!(rejected_journal.operations[index].phase == AuthPhase::RolledBack);
    assert!(rejected_journal.active.is_none() && !auth_recovery_pending()?);
    assert!(!root.join("accounts/rejected-join").try_exists()?);
    let rejected_bytes = std::fs::read(recovery_path())?;
    for query_only in [true,false] {
        let queried = control_space(&ownership,&join_id,&join_id,&params,query_only)?;
        assert_eq!(serde_json::to_value(&queried)?,serde_json::to_value(&rejected)?);
    }
    assert!(server.recv_timeout(std::time::Duration::from_millis(50))?.is_none(), "terminal join was sent again");
    assert_eq!(std::fs::read(recovery_path())?,rejected_bytes);
    assert_eq!(std::fs::read(root.join("session.json"))?,original);
    assert_eq!(std::fs::read(crate::service::client_config_path())?,config);
    params.invite_code = None;
    params.operation = HostSpaceOperation::Kick { session_id:None,all:true };
    let (mut journal,index) = admit(&ownership,&id,&id,&params)?;
    op_mut(&mut journal,index)?.kick[0].state = HostSpaceKickState::Revoked;
    op_mut(&mut journal,index)?.kick[1].state = HostSpaceKickState::RemotePending;
    journal.operations[index].phase = AuthPhase::RemotePending;
    save_journal(&journal)?;
    // Recovery must not route a space write through keygen/login rollback.
    ownership.recover(&params.identity)?;
    drop(ownership);
    assert!(recover_interrupted().is_err());
    let ownership = AuthOwnership::acquire(root,root)?;
    let receipt = control_space(&ownership,&id,&id,&params,true)?;
    assert!(receipt.outcome == HostSpaceOutcome::Unknown && receipt.remaining == Some(1));
    assert!(receipt.kick[0].state == HostSpaceKickState::Revoked && receipt.kick[1].state == HostSpaceKickState::Unknown);
    assert_eq!(members(read_optional(&root.join(MEMBERS))?.as_deref())?[0].session_id,second);
    // Repeating even the execute method cannot repeat the unknown remote POST.
    assert!(control_space(&ownership,&id,&id,&params,false)?.outcome == HostSpaceOutcome::Unknown);
    assert_eq!(load_journal()?.active.as_ref().and_then(|active| active.operation_id.as_deref()),Some(id.as_str()));
    assert!(control_space(&ownership,&id,"foreign-key",&params,true).is_err());
    params.operation = HostSpaceOperation::Kick { session_id:Some(first),all:false };
    assert!(control_space(&ownership,&id,&id,&params,true).is_err());
    params.operation = HostSpaceOperation::Kick { session_id:None,all:true };
    params.source_identity = HostAuthIdentity::Absent;
    assert!(control_space(&ownership,&id,&id,&params,true).is_err());
    assert_eq!(std::fs::read(root.join("session.json"))?,original);
    assert_eq!(std::fs::read(crate::service::client_config_path())?,config);
    assert!(auth_recovery_pending()?);
    let code = format!("{PREFIX}{}",hex::encode(serde_json::to_vec(&json!({"space":"joined-space","addr":"https://never-contact.invalid",
        "user":"joined-user","token":"synthetic-unused-token","super":"synthetic-unused-factor","readonly":true}))?));
    let mut intent = HostSpaceOperation::Join { invite_sha256:digest(code.as_bytes()),space:"joined-space".into(),
        addr:"https://never-contact.invalid".into(),user:"joined-user".into(),readonly:true };
    check_code(&intent,&code)?;
    if let HostSpaceOperation::Join { readonly, .. } = &mut intent { *readonly = false; }
    assert!(check_code(&intent,&code).is_err());
    assert!(members(Some(b"not json")).is_err());
    Ok(())
}
