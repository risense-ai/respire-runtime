//! Durable, secret-free continuation for an explicitly requested offline keygen.
//! Only Runtime Start may move a committed original operation toward serving.
use anyhow::{Context, Result};
use respire_commands::output::{Item, ResultEnvelope, Status};
use respire_protocol::{HostAuthIdentity, HostAuthOutcome, HostAuthResult};
use serde::{Deserialize, Serialize};
use std::{io::Read, path::{Path, PathBuf}};
use super::super::{hash, private_write, lifecycle};
use super::launch_authorization::control;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Stage { Prepared, Sent, Committed, Starting, Verified, Finished, HandedOff, RolledBack, RollbackStarting, RollbackFinished, RollbackHandedOff }
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Original {
    schema: u32, operation_id: String, force: bool,
    root: PathBuf, source: PathBuf, profile: PathBuf,
    binary: PathBuf, image_sha256: String,
    token: String, coordinator: String, marker_sha256: String,
    original_identity: HostAuthIdentity, session_sha256: Option<String>, stage: Stage,
    actor: Option<RuntimeIdentity>,
    was_serving: bool, store_ready: bool,
}
fn path(root: &Path) -> PathBuf { root.join("runtime/autostart/offline-keygen.json") }
/// Generic restart/recovery must not replace this operation's private marker.
/// Even malformed, unreadable or dangling-link evidence blocks generic recovery.
pub(crate) fn reject_generic_recovery(root:&Path) -> Result<()> {
    let file=path(root); no_links(&file)?;
    match std::fs::symlink_metadata(file) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => anyhow::bail!("offline_keygen_handoff_pending: recovery evidence unreadable"),
        Ok(_) => anyhow::bail!("offline_keygen_handoff_pending: use the original operation's explicit handoff"),
    }
}
fn canonical_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == value)
}
fn no_links(path: &Path) -> Result<()> {
    for component in path.ancestors() {
        match std::fs::symlink_metadata(component) {
            Ok(meta) => {
                anyhow::ensure!(!meta.file_type().is_symlink(), "offline keygen path is a link");
                #[cfg(windows)] {
                    use std::os::windows::fs::MetadataExt;
                    anyhow::ensure!(meta.file_attributes() & 0x400 == 0, "offline keygen path is a reparse point");
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
fn load(root: &Path) -> Result<Option<(Original, String)>> {
    let file = path(root); no_links(&file)?;
    let meta = match std::fs::symlink_metadata(&file) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    anyhow::ensure!(meta.is_file() && meta.len() <= 16384, "invalid offline keygen record");
    let mut bytes=Vec::new();
    std::fs::File::open(file)?.take(16385).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 16384, "offline keygen record exceeds bound");
    let record: Original=serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid offline keygen record"))?;
    // Existing evidence is bound to the OS canonical root (including Windows
    // verbatim prefixes). Missing roots remain a read-only first-use probe.
    let canonical_root = root.canonicalize()?;
    no_links(&path(&canonical_root))?;
    validate_record(&record,&canonical_root)?;
    Ok(Some((record,hash(&bytes))))
}
pub(crate) fn pending_for_selected_root() -> Result<bool> {
    let (root, _) = respire_client_host::config::control_roots()?;
    Ok(load(&root)?.is_some())
}

fn valid_digest(value:&str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
fn validate_record(record:&Original,root:&Path) -> Result<()> {
    anyhow::ensure!(record.schema == 1 && canonical_id(&record.operation_id) && canonical_id(&record.token)
        && record.root == root && record.source == record.profile && record.profile.is_absolute()
        && record.binary.is_absolute() && !record.coordinator.is_empty()
        && valid_digest(&record.image_sha256) && valid_digest(&record.marker_sha256),
        "offline keygen original binding mismatch");
    let committed=matches!(record.stage,Stage::Committed|Stage::Starting|Stage::Verified|Stage::Finished|Stage::HandedOff);
    anyhow::ensure!(if committed { record.session_sha256.as_deref().is_some_and(valid_digest) }
        else { record.session_sha256.is_none() }, "offline keygen stage has inconsistent receipt evidence");
    let actor_required=matches!(record.stage,Stage::Verified|Stage::Finished|Stage::HandedOff)
        || (record.was_serving && matches!(record.stage,Stage::RollbackFinished|Stage::RollbackHandedOff));
    anyhow::ensure!(record.actor.is_some() == actor_required && (record.was_serving || !record.store_ready),
        "offline keygen stage has inconsistent live actor evidence");
    Ok(())
}
fn require_startable(stage:Stage) -> Result<()> {
    anyhow::ensure!(matches!(stage,Stage::Sent|Stage::Committed),
        "offline_keygen_handoff_pending: prior launch/completion requires independent recovery; no spawn retried");
    Ok(())
}
fn save(record: &Original, digest: &mut Option<String>) -> Result<()> {
    validate_record(record,&record.root)?;
    let file=path(&record.root); no_links(&file)?;
    if let Some((previous,observed))=load(&record.root)? {
        anyhow::ensure!(digest.as_deref() == Some(observed.as_str()), "offline keygen record changed");
        validate_transition(&previous,record)?;
    } else {
        anyhow::ensure!(digest.is_none() && record.stage == Stage::Prepared, "offline keygen admission missing");
    }
    let bytes=serde_json::to_vec(record)?;
    // A failed publish is not retried here, even if it may have taken effect.
    if private_write(&file,&bytes,digest.as_deref()).is_err() {
        // Observe a possible after-write error without retrying or overwriting.
        // Equal readback is not proof that the failed durability step succeeded.
        let published=load(&record.root).ok().flatten().is_some_and(|(_,actual)| actual == hash(&bytes));
        if published { anyhow::bail!("offline_keygen_record_durability_unknown: exact record visible; no subsequent action taken"); }
        anyhow::bail!("offline_keygen_record_publication_unknown: original evidence retained; no subsequent action taken");
    }
    *digest=Some(hash(&bytes)); Ok(())
}
fn validate_transition(previous:&Original,next:&Original) -> Result<()> {
    let mut binding=next.clone();
    binding.stage=previous.stage;
    binding.marker_sha256=previous.marker_sha256.clone();
    binding.session_sha256=previous.session_sha256.clone();
    binding.actor=previous.actor.clone();
    anyhow::ensure!(serde_json::to_value(&binding)? == serde_json::to_value(previous)?
        && previous.session_sha256.as_ref().is_none_or(|digest| next.session_sha256.as_ref() == Some(digest))
        && previous.actor.as_ref().is_none_or(|actor| next.actor.as_ref() == Some(actor)),
        "offline keygen original operation changed");
    anyhow::ensure!(matches!((previous.stage,next.stage),
        (Stage::Prepared,Stage::Sent) | (Stage::Sent,Stage::Sent) | (Stage::Sent,Stage::Committed)
        | (Stage::Committed,Stage::Committed) | (Stage::Sent,Stage::Starting)
        | (Stage::Committed,Stage::Starting) | (Stage::Starting,Stage::Verified)
        | (Stage::Verified,Stage::Finished) | (Stage::Finished,Stage::HandedOff)
        | (Stage::Sent,Stage::RolledBack) | (Stage::RolledBack,Stage::RollbackStarting)
        | (Stage::RolledBack,Stage::RollbackFinished) | (Stage::RollbackStarting,Stage::RollbackFinished)
        | (Stage::RollbackFinished,Stage::RollbackHandedOff)), "offline keygen phase cannot be replayed or regressed");
    Ok(())
}
fn verify_selection(record: &Original) -> Result<()> {
    let (root,profile)=respire_client_host::config::control_roots()?;
    let (binary,digest)=crate::runtime_fetch::require_offline_keygen_handoff()?;
    anyhow::ensure!(root.canonicalize()? == record.root && profile.canonicalize()? == record.profile
        && binary == record.binary && digest == record.image_sha256,
        "offline keygen installation, selection or image changed");
    Ok(())
}
fn update_marker(record: &mut Original, maintenance: &mut lifecycle::Maintenance) -> Result<()> {
    let binding=maintenance.auth_launch_binding(&record.profile)?.context("offline keygen requires Paused maintenance")?;
    anyhow::ensure!(binding["coordinator_id"].as_str() == Some(record.coordinator.as_str())
        && lifecycle::current_boot_token().as_deref() == Some(record.token.as_str()), "offline keygen marker binding changed");
    record.marker_sha256=binding["marker_sha256"].as_str().context("offline keygen marker digest missing")?.to_owned();
    Ok(())
}

pub(crate) fn keygen(operation: Option<&str>, force: bool) -> Result<ResultEnvelope> {
    if let Some(id) = operation {
        anyhow::ensure!(canonical_id(id), "auth operation ID must be a canonical random UUID");
    }
    crate::runtime_policy::require_host("offline keygen handoff")?;
    anyhow::ensure!(lifecycle::current_boot_token().is_none(), "offline keygen requires its own controller");
    let (binary,image_sha256)=crate::runtime_fetch::require_offline_keygen_handoff()?;
    let (root,profile)=respire_client_host::config::control_roots()?;
    let takeover=crate::runtime_policy::takeover_lock()?;
    if operation.is_none() { std::fs::create_dir_all(&profile)?; }
    let root=root.canonicalize()?; let profile=profile.canonicalize()?;
    let saved=load(&root)?;
    let (mut record,mut digest,mut maintenance)=if let Some((record,digest))=saved {
        anyhow::ensure!(record.force == force && operation.is_none_or(|id| id == record.operation_id),
            "offline keygen requires the original operation and force");
        anyhow::ensure!(matches!(record.stage, Stage::Sent | Stage::Committed),
            "offline keygen handoff requires explicit recovery; no write was repeated");
        verify_selection(&record)?;
        lifecycle::verify_offline_keygen_marker(&root,&profile,&record.token,&record.coordinator,&record.marker_sha256)?;
        let maintenance=lifecycle::resume_key_maintenance(&root,&profile,&record.source,&record.token,&record.coordinator)?;
        (record,Some(digest),maintenance)
    } else {
        anyhow::ensure!(operation.is_none(), "offline keygen original record missing; no operation admitted");
        let health=crate::rpc::probe_runtime()?;
        anyhow::ensure!(health.is_some() || !crate::rpc::endpoint_path().try_exists()?, "offline keygen owner is unverifiable");
        if let Some(owner)=health.as_ref() {
            let manifest=crate::runtime_fetch::read_manifest()?.context("offline keygen Runtime manifest missing")?;
            let registration=super::super::read_registration(&root)?;
            let managed=registration.as_ref().filter(|config| config.enabled && !config.manually_stopped);
            let account=match control::identity(&profile)? {
                HostAuthIdentity::Bound { account_id, .. } => account_id,
                _ => hash(profile.display().to_string().as_bytes()),
            };
            super::launch_authorization::model_control::verify_model_owner(owner,&root,&profile,managed,&binary,&manifest,Some(&account))?;
        }
        let mut saved_record=None;
        let mut digest=None;
        let mut maintenance=lifecycle::begin_offline_keygen_maintenance(&root,&profile,|token,coordinator,marker_sha256| {
            let record=Original { schema:1,operation_id:uuid::Uuid::new_v4().to_string(),force,
                root:root.clone(),source:profile.clone(),profile:profile.clone(),binary:binary.clone(),image_sha256:image_sha256.clone(),
                token:token.to_owned(),coordinator:coordinator.to_owned(),marker_sha256:marker_sha256.to_owned(),
                original_identity:control::identity(&profile)?,session_sha256:None,stage:Stage::Prepared,actor:None,
                was_serving:health.is_some(),store_ready:health.as_ref().is_some_and(|owner| owner.store_ready) };
            verify_selection(&record)?;
            save(&record,&mut digest)?;
            saved_record=Some(record);
            Ok(())
        })?;
        let record=saved_record.context("offline keygen admission missing")?;
        // The complete original operation is durable before draining any owner.
        verify_selection(&record)?;
        if let Some(health)=health.as_ref() { maintenance.drain_runtime(health)?; }
        (record,digest,maintenance)
    };
    verify_selection(&record)?;
    update_marker(&mut record,&mut maintenance)?;
    let send=record.stage == Stage::Prepared;
    if send {
        anyhow::ensure!(control::identity(&record.profile)? == record.original_identity, "offline keygen source identity changed");
        record.stage=Stage::Sent;
    }
    save(&record,&mut digest)?; // sent + current controller durable before any exchange.
    let envelope=if send { control::auth_keygen_locked(&takeover,&mut maintenance,&record.operation_id,force)? }
        else { control::auth_result_locked(&takeover,&mut maintenance,&record.operation_id,force)? };
    verify_selection(&record)?;
    let result:HostAuthResult=serde_json::from_value(envelope.summary.clone())?;
    anyhow::ensure!(result.operation_id == record.operation_id && result.path == record.profile.join("session.json"),
        "offline keygen result binding mismatch");
    if result.outcome == HostAuthOutcome::RolledBack {
        anyhow::ensure!(result.session_sha256.is_none() && result.super_password.is_none()
            && control::identity(&record.profile)? == record.original_identity,
            "offline keygen rollback source identity changed");
        record.stage=Stage::RolledBack; save(&record,&mut digest)?;
        if send { finish_initial_rollback(&mut record,&mut digest,&mut maintenance)?; }
        // A query-only process never guesses whether it should restore an owner.
        return Ok(envelope);
    }
    anyhow::ensure!(result.outcome == HostAuthOutcome::Committed, "offline keygen outcome unresolved; original operation retained");
    let session=result.session_sha256.context("offline keygen receipt digest missing")?;
    anyhow::ensure!(record.session_sha256.as_ref().is_none_or(|old| old == &session)
        && control::identity(&record.profile)? == (HostAuthIdentity::Unbound {operation_id:record.operation_id.clone(),session_sha256:session.clone()}),
        "offline keygen committed identity changed");
    let secret=result.super_password.filter(|s| !s.is_empty()).context("offline keygen recovery material missing")?;
    record.session_sha256=Some(session); record.stage=Stage::Committed;
    update_marker(&mut record,&mut maintenance)?; save(&record,&mut digest)?;
    // Deliberately retain Paused. No serving owner, automatic login or finish here.
    let mut output=ResultEnvelope::new("keygen",Status::Ok,serde_json::json!({"path":result.path,"super":secret}),
        vec![Item::new("keys",Status::Ok,result.path.display().to_string())]);
    output.actions.push("runtime start".into());
    Ok(output)
}

pub(crate) use respire_protocol::host_control::HostKeygenRuntimeIdentity as RuntimeIdentity;
use respire_protocol::host_control::{HostKeygenHandoffReceipt as CompleteReceipt, HOST_AUTH_KEYGEN_COMPLETE_METHOD};
pub(crate) fn verify_target(root:&Path,profile:&Path,operation:&str,session:&str) -> Result<RuntimeIdentity> {
    anyhow::ensure!(control::identity(profile)? == (HostAuthIdentity::Unbound {
        operation_id:operation.to_owned(),session_sha256:session.to_owned()}), "offline keygen identity changed");
    verify_original_target(root,profile,&HostAuthIdentity::Unbound {operation_id:operation.to_owned(),session_sha256:session.to_owned()},true)
}
pub(crate) fn verify_original_target(root:&Path,profile:&Path,identity:&HostAuthIdentity,store_ready:bool) -> Result<RuntimeIdentity> {
    anyhow::ensure!(&control::identity(profile)? == identity, "offline keygen rollback source identity changed");
    let health=crate::net_rpc::health()?; crate::net_rpc::request_scope(&health)?;
    let (binary,_)=control::installed_auth_runtime()?;
    let manifest=crate::runtime_fetch::read_manifest()?.context("offline keygen Runtime manifest missing")?;
    let registration=super::super::read_registration(root)?;
    let managed=registration.as_ref().filter(|config| config.enabled && !config.manually_stopped);
    let account=match identity { HostAuthIdentity::Bound {account_id,..} => account_id.clone(),
        _ => hash(profile.display().to_string().as_bytes()) };
    super::launch_authorization::model_control::verify_model_owner(&health,root,profile,managed,&binary,&manifest,Some(&account))?;
    anyhow::ensure!(health.store_ready == store_ready && health.server == "respire" && !health.instance_id.is_empty(),
        "offline keygen store is not ready");
    Ok(RuntimeIdentity { pid:health.pid,process_start_id:health.process_start_id,
        instance_id:health.instance_id,generation:health.generation,image_path:health.image_path,
        image_sha256:health.image_sha256,installation_root:health.installation_root,
        installation_id:health.installation_id,profile:health.data_dir,account_id:health.account_id })
}

fn finish_initial_rollback(record:&mut Original,digest:&mut Option<String>,maintenance:&mut lifecycle::Maintenance) -> Result<()> {
    verify_selection(record)?;
    anyhow::ensure!(control::identity(&record.profile)? == record.original_identity,
        "offline keygen rollback original identity changed");
    if record.was_serving {
        record.stage=Stage::RollbackStarting; save(record,digest)?;
        maintenance.start_account_runtime()?;
        let actor=verify_original_target(&record.root,&record.profile,&record.original_identity,record.store_ready)?;
        maintenance.offline_keygen_rollback_verified(&record.profile,&record.original_identity,record.store_ready)?;
        record.actor=Some(actor);
        maintenance.offline_keygen_complete_binding(&record.profile)?;
    } else {
        lifecycle::verify_offline_keygen_marker(&record.root,&record.profile,&record.token,&record.coordinator,&record.marker_sha256)?;
    }
    maintenance.finish()?;
    record.stage=Stage::RollbackFinished; save(record,digest)?;
    maintenance.finish_handoff()?;
    record.stage=Stage::RollbackHandedOff; save(record,digest)?;
    remove_rollback(record,digest.as_deref().context("offline keygen rollback cleanup digest missing")?)
}
fn remove_rollback(record:&Original,digest:&str) -> Result<()> {
    anyhow::ensure!(record.stage == Stage::RollbackHandedOff, "offline keygen rollback cleanup is premature");
    let file=path(&record.root); no_links(&file)?;
    let (_,actual)=load(&record.root)?.context("offline keygen rollback evidence missing")?;
    anyhow::ensure!(actual == digest, "offline keygen rollback evidence changed");
    std::fs::remove_file(&file)?;
    respire_spawn::durable::sync_directory(file.parent().context("offline keygen rollback cleanup parent missing")?)?;
    Ok(())
}

fn complete(takeover:&respire_client_host::lock::LibraryLock, maintenance:&lifecycle::Maintenance,
    record:&Original, actor:&RuntimeIdentity) -> Result<()> {
    use respire_protocol::{ControlBinding,HostAuthKeygenParams,HostControlLaunchGrant,RpcRequest};
    use std::time::{Duration,Instant};
    verify_selection(record)?;
    anyhow::ensure!(takeover.protects(&record.root.join("runtime/takeover"))?, "offline keygen takeover mismatch");
    let session=record.session_sha256.as_deref().context("offline keygen committed digest missing")?;
    anyhow::ensure!(verify_target(&record.root,&record.profile,&record.operation_id,session)? == *actor,
        "offline keygen actor changed before completion");
    let binding=maintenance.offline_keygen_complete_binding(&record.profile)?;
    let registration=super::super::read_registration(&record.root)?;
    let managed=registration.as_ref().filter(|c| c.enabled && !c.manually_stopped).map(|c| c.id.as_str());
    let (grant,_)=super::launch_authorization::prepare_grant_for_identity(&record.binary,&record.root,
        &record.profile,managed,crate::net_rpc::rpc_port(),&actor.account_id,binding)?;
    let grant:HostControlLaunchGrant=serde_json::from_value(grant)?;
    anyhow::ensure!(grant.image_path == record.binary && grant.image_sha256.eq_ignore_ascii_case(&record.image_sha256),
        "offline keygen completion image changed");
    let params=HostAuthKeygenParams { schema_version:1, binding:ControlBinding {
        installation_root:record.root.clone(),profile:record.profile.clone(),launch_id:grant.instance_id.clone(),expected_account_id:None },
        identity:HostAuthIdentity::Unbound {operation_id:record.operation_id.clone(),session_sha256:session.to_owned()},force:record.force };
    let request=RpcRequest {v:respire_commands::rpc_client::PROTOCOL_V,id:uuid::Uuid::new_v4().to_string(),
        method:HOST_AUTH_KEYGEN_COMPLETE_METHOD.into(),args:vec![serde_json::to_string(&params)?],scope:None,
        operation_id:Some(record.operation_id.clone()),idempotency_key:Some(record.operation_id.clone()),
        parent_operation_id:None,queue_wait_ms:None,lifecycle:None};
    super::launch_authorization::exchange_control(&record.binary,&grant,&request,Instant::now()+Duration::from_secs(12),|response,pid| {
        anyhow::ensure!(response.v == request.v && response.id == request.id && response.bin == "rsrs-runtime"
            && response.pid == Some(pid) && response.operation_id == request.operation_id
            && response.idempotency_key == request.idempotency_key && response.scope.is_none() && response.web_url.is_none()
            && response.ok && response.exit == 0 && response.code.is_none() && response.error.is_none(),
            "offline keygen completion response mismatch");
        let envelope=response.envelope.context("offline keygen completion receipt missing")?;
        anyhow::ensure!(envelope.command == "keygen-handoff" && matches!(envelope.status,Status::Ok) && envelope.errors.is_empty(),
            "offline keygen completion rejected");
        if let Some(directory)=response.data_dir.as_ref() {
            anyhow::ensure!(Path::new(directory).canonicalize()? == record.profile,
                "offline keygen completion response profile mismatch");
        }
        for (name,value) in [("control_ready","true"),("store_ready","false")] {
            let mut items=envelope.items.iter().filter(|item| item.name == name);
            anyhow::ensure!(items.next().is_some_and(|item| item.value == value
                && if name == "control_ready" { matches!(item.status,Status::Ok) } else { matches!(item.status,Status::Skip) })
                && items.next().is_none(), "offline keygen completion readiness mismatch");
        }
        let receipt:CompleteReceipt=serde_json::from_value(envelope.summary.clone())
            .map_err(|_| anyhow::anyhow!("offline keygen completion receipt invalid"))?;
        anyhow::ensure!(receipt.schema_version == 1 && receipt.operation_id == record.operation_id
            && receipt.session_sha256 == session && receipt.path == record.profile.join("session.json") && receipt.runtime == *actor,
            "offline keygen completion binding mismatch");
        Ok(envelope)
    })?;
    anyhow::ensure!(verify_target(&record.root,&record.profile,&record.operation_id,session)? == *actor,
        "offline keygen actor changed during completion");
    Ok(())
}

/// Only the user-facing Start dispatcher calls this with its existing takeover.
/// An uncertain prior spawn is never retried here.
pub(crate) fn start_explicit(takeover:&respire_client_host::lock::LibraryLock) -> Result<bool> {
    let (root,profile)=respire_client_host::config::control_roots()?;
    let Some((mut record,digest))=load(&root)? else { return Ok(false); };
    let root=root.canonicalize()?; let profile=profile.canonicalize()?;
    anyhow::ensure!(takeover.protects(&root.join("runtime/takeover"))?, "offline keygen takeover mismatch");
    if record.stage == Stage::RollbackHandedOff {
        verify_selection(&record)?; lifecycle::verify_offline_keygen_finished(&root)?;
        anyhow::ensure!(control::identity(&profile)? == record.original_identity,
            "offline keygen rolled-back identity changed");
        if record.was_serving {
            anyhow::ensure!(record.actor.as_ref() == Some(&verify_original_target(&root,&profile,&record.original_identity,record.store_ready)?),
                "offline keygen rollback actor changed; no spawn retried");
        } else {
            anyhow::ensure!(crate::rpc::probe_runtime()?.is_none() && !crate::rpc::endpoint_path().try_exists()?,
                "offline keygen rollback gained an unknown owner");
        }
        remove_rollback(&record,&digest)?;
        return Ok(record.was_serving);
    }
    if record.stage == Stage::HandedOff {
        verify_selection(&record)?;
        lifecycle::verify_offline_keygen_finished(&root)?;
        let session=record.session_sha256.as_deref().context("offline keygen completed digest missing")?;
        anyhow::ensure!(record.actor.as_ref() == Some(&verify_target(&root,&profile,&record.operation_id,session)?),
            "offline keygen finished actor changed; no spawn attempted");
        remove_finished(&record,&digest)?;
        return Ok(true);
    }
    require_startable(record.stage)?;
    verify_selection(&record)?;
    lifecycle::verify_offline_keygen_marker(&root,&profile,&record.token,&record.coordinator,&record.marker_sha256)?;
    anyhow::ensure!(crate::rpc::probe_runtime()?.is_none() && !crate::rpc::endpoint_path().try_exists()?,
        "offline keygen owner already exists; no spawn attempted");
    let mut maintenance=lifecycle::resume_key_maintenance(&root,&profile,&record.source,&record.token,&record.coordinator)?;
    let mut digest=Some(digest);
    update_marker(&mut record,&mut maintenance)?; save(&record,&mut digest)?;
    let envelope=control::auth_result_locked(takeover,&mut maintenance,&record.operation_id,record.force)?;
    let receipt:HostAuthResult=serde_json::from_value(envelope.summary)
        .map_err(|_| anyhow::anyhow!("offline keygen query receipt invalid"))?;
    anyhow::ensure!(receipt.outcome == HostAuthOutcome::Committed && receipt.operation_id == record.operation_id
        && receipt.path == profile.join("session.json"), "offline keygen original is not committed");
    let session=receipt.session_sha256.context("offline keygen receipt digest missing")?;
    anyhow::ensure!(record.session_sha256.as_ref().is_none_or(|saved| saved == &session)
        && control::identity(&profile)? == (HostAuthIdentity::Unbound {operation_id:record.operation_id.clone(),session_sha256:session.clone()}),
        "offline keygen original identity changed");
    // Never retain the auth.result recovery code, including in the continuation file.
    drop(receipt.super_password);
    record.session_sha256=Some(session.clone()); record.stage=Stage::Starting;
    update_marker(&mut record,&mut maintenance)?; save(&record,&mut digest)?;
    maintenance.start_account_runtime()?;
    let actor=verify_target(&root,&profile,&record.operation_id,&session)?;
    maintenance.offline_keygen_target_verified(&profile,&record.operation_id,&session)?;
    record.stage=Stage::Verified; record.actor=Some(actor.clone()); save(&record,&mut digest)?;
    complete(takeover,&maintenance,&record,&actor)?;
    maintenance.offline_keygen_complete_binding(&profile)?;
    maintenance.finish()?;
    record.stage=Stage::Finished; save(&record,&mut digest)?;
    maintenance.finish_handoff()?;
    record.stage=Stage::HandedOff; save(&record,&mut digest)?;
    remove_finished(&record,digest.as_deref().context("offline keygen cleanup digest missing")?)?;
    Ok(true)
}

fn remove_finished(record:&Original,digest:&str) -> Result<()> {
    anyhow::ensure!(record.stage == Stage::HandedOff, "offline keygen cleanup requires completed handoff");
    let file=path(&record.root); no_links(&file)?;
    let (_,actual)=load(&record.root)?.context("offline keygen cleanup record disappeared")?;
    anyhow::ensure!(actual == digest, "offline keygen cleanup record changed");
    std::fs::remove_file(&file)?;
    respire_spawn::durable::sync_directory(file.parent().context("offline keygen cleanup parent missing")?)?;
    Ok(())
}

/// Hand the original Paused keygen controller to a separately durable account O.
/// The coordinator proves the original committed receipt; caller input is not proof.
/// New account authentication is sent only by the existing coordinator after this
/// function releases takeover. Pending records never store account credentials.
pub(crate) fn prepare_account(register:bool,user:&str,addr:&str) -> Result<()> {
    use respire_host_control::KeygenAccountTransfer;
    let (root,_) = respire_client_host::config::control_roots()?;
    // Ordinary account paths remain read-only/no-op here, including first use.
    // The shared coordinator repeats its pending fence under takeover.
    if load(&root)?.is_none() { return Ok(()); }
    let takeover=crate::runtime_policy::takeover_lock()?;
    let Some((mut record,observed))=load(&root)? else { return Ok(()); };
    let root=root.canonicalize()?;
    require_startable(record.stage)?;
    let (binary,image)=crate::runtime_fetch::require_offline_keygen_handoff()?;
    anyhow::ensure!(binary == record.binary && image == record.image_sha256,
        "offline keygen account transfer image changed");
    let source=|record:&Original| KeygenAccountTransfer {root:record.root.clone(),profile:record.profile.clone(),
        original_operation_id:record.operation_id.clone(),force:record.force,token:record.token.clone(),
        coordinator:record.coordinator.clone(),marker_sha256:record.marker_sha256.clone()};
    let accounts=super::launch_authorization::shared_host::accounts();
    // Account selection may already have moved after a lost response. Durable
    // mapping lookup comes before old-profile/Paused checks, and never sends auth.
    if let Some(admission)=accounts.lookup_existing_keygen_transfer(&takeover,&source(&record),register,user,addr)? {
        return remove_transferred(&record,&observed,&admission);
    }
    verify_selection(&record)?;
    lifecycle::verify_offline_keygen_marker(&root,&record.profile,&record.token,&record.coordinator,&record.marker_sha256)?;
    anyhow::ensure!(crate::rpc::probe_runtime()?.is_none() && !crate::rpc::endpoint_path().try_exists()?,
        "offline keygen account transfer cannot replace a live or unknown owner");
    let mut maintenance=lifecycle::resume_key_maintenance(&root,&record.profile,&record.source,&record.token,&record.coordinator)?;
    let mut digest=Some(observed);
    update_marker(&mut record,&mut maintenance)?; save(&record,&mut digest)?;
    // Drop only the CLI process-local active slot. The durable exact Paused
    // marker remains and the shared coordinator independently adopts it.
    drop(maintenance);
    let admission=accounts.prepare_keygen_account(&takeover,&source(&record),register,user,addr)?;
    remove_transferred(&record,digest.as_deref().context("offline keygen transfer digest missing")?,&admission)
}

fn remove_transferred(record:&Original,digest:&str,admission:&respire_host_control::KeygenAccountAdmission) -> Result<()> {
    anyhow::ensure!(admission.root() == record.root && admission.source_profile() == record.source
        && admission.keygen_operation_id() == record.operation_id && admission.force() == record.force
        && admission.maintenance_token() == record.token && canonical_id(admission.operation_id())
        && admission.operation_id() != record.operation_id && valid_digest(admission.session_sha256())
        && record.session_sha256.as_deref().is_none_or(|saved| saved == admission.session_sha256()),
        "offline keygen durable account transfer mismatch");
    let file=path(&record.root); no_links(&file)?;
    let (_,actual)=load(&record.root)?.context("offline keygen transfer record disappeared")?;
    anyhow::ensure!(actual == digest, "offline keygen transfer record changed");
    // Never remove the marker: account-active now owns the same maintenance token.
    std::fs::remove_file(&file)?;
    respire_spawn::durable::sync_directory(file.parent().context("offline keygen transfer parent missing")?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn original(root:&Path) -> Original {
        Original { schema:1,operation_id:uuid::Uuid::new_v4().to_string(),force:false,
            root:root.to_owned(),source:root.to_owned(),profile:root.to_owned(),binary:root.join("runtime-image"),
            image_sha256:"a".repeat(64),token:uuid::Uuid::new_v4().to_string(),coordinator:"synthetic-coordinator".into(),
            marker_sha256:"b".repeat(64),original_identity:HostAuthIdentity::Absent,session_sha256:None,stage:Stage::Prepared,actor:None,was_serving:false,store_ready:false }
    }
    #[test]
    fn absent_pending_probe_does_not_create_first_use_paths() -> Result<()> {
        let _lock=crate::TEST_ENV_LOCK.lock().map_err(|_| anyhow::anyhow!("test environment lock poisoned"))?;
        struct Restore(Option<std::ffi::OsString>);
        impl Drop for Restore {
            fn drop(&mut self) {
                match &self.0 {
                    Some(value) => std::env::set_var("RSRS_DATA_DIR",value),
                    None => std::env::remove_var("RSRS_DATA_DIR"),
                }
            }
        }
        let _restore=Restore(std::env::var_os("RSRS_DATA_DIR"));
        let temp=tempfile::tempdir()?;
        let root=temp.path().canonicalize()?.join("not-yet-created");
        std::env::set_var("RSRS_DATA_DIR",&root);
        let (selected,profile)=respire_client_host::config::control_roots()?;
        assert_eq!(selected,root);
        assert!(!profile.exists());
        assert!(load(&root)?.is_none());
        assert!(!pending_for_selected_root()?);
        prepare_account(true,"synthetic-user","https://example.invalid")?;
        prepare_account(false,"synthetic-user","https://example.invalid")?;
        assert!(!root.exists() && !profile.exists());
        assert_eq!(std::fs::read_dir(temp.path())?.count(),0);
        Ok(())
    }
    #[test]
    fn existing_pending_uses_canonical_root_without_accepting_a_foreign_binding() -> Result<()> {
        let temp=tempfile::tempdir()?;
        let canonical=temp.path().canonicalize()?;
        #[cfg(not(windows))]
        let lexical=canonical.clone();
        #[cfg(windows)]
        let lexical={
            // Test-only spellings of one real root, including a verbatim TMP.
            // Production authorization never strips prefixes or normalizes strings.
            let value=canonical.to_str().context("synthetic root is not UTF-8")?;
            if let Some(unc)=value.strip_prefix(r"\\?\UNC\") {
                PathBuf::from(format!(r"\\{}",unc))
            } else {
                PathBuf::from(value.strip_prefix(r"\\?\").context("synthetic canonical root lacks verbatim prefix")?)
            }
        };
        let record=original(&canonical);
        save(&record,&mut None)?;
        let (loaded,_)=load(&lexical)?.context("canonical pending unavailable")?;
        assert_eq!(loaded.root,canonical);
        #[cfg(windows)] assert_ne!(lexical,canonical);
        let mut foreign=record.clone(); foreign.root=canonical.join("different-root");
        std::fs::write(path(&lexical),serde_json::to_vec(&foreign)?)?;
        assert!(load(&lexical).is_err());
        std::fs::write(path(&lexical),b"invalid pending")?;
        assert!(load(&lexical).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn canonical_pending_does_not_authorize_a_symlink_alias() -> Result<()> {
        let temp=tempfile::tempdir()?;
        let base=temp.path().canonicalize()?;
        let root=base.join("real-root"); std::fs::create_dir(&root)?;
        save(&original(&root),&mut None)?;
        let alias=base.join("alias");
        std::os::unix::fs::symlink(&root,&alias)?;
        assert!(load(&alias).is_err());
        assert!(reject_generic_recovery(&alias).is_err());
        Ok(())
    }

    #[test]
    fn journal_is_secret_free_exact_owner_and_cas_bound() -> Result<()> {
        let temp=tempfile::tempdir()?; let root=temp.path().canonicalize()?;
        let mut record=original(&root); let mut digest=None;
        save(&record,&mut digest)?;
        record.stage=Stage::Sent; save(&record,&mut digest)?;
        let (actual,observed)=load(&root)?.context("missing original")?;
        assert!(actual.stage == Stage::Sent && actual.operation_id == record.operation_id);
        assert_eq!(Some(observed),digest);
        let bytes=std::fs::read(path(&root))?;
        let json:serde_json::Value=serde_json::from_slice(&bytes)?;
        assert!(json.get("super_password").is_none() && json.get("secret").is_none());
        let mut other=original(&root); other.stage=Stage::Sent;
        assert!(save(&other,&mut None).is_err());
        assert_eq!(std::fs::read(path(&root))?,bytes);
        let mut changed=json; changed["super_password"]=serde_json::json!("synthetic-only");
        std::fs::write(path(&root),serde_json::to_vec(&changed)?)?;
        assert!(load(&root).is_err());
        assert!(save(&record,&mut digest).is_err());
        Ok(())
    }
    #[test]
    fn record_rejects_changed_selection_and_phase_replay() -> Result<()> {
        let temp=tempfile::tempdir()?; let root=temp.path().canonicalize()?;
        let mut record=original(&root); let mut digest=None;
        save(&record,&mut digest)?;
        let original_id=record.operation_id.clone();
        record.operation_id="not-original-operation".into(); record.stage=Stage::Sent;
        assert!(save(&record,&mut digest).is_err());
        record.operation_id=original_id;
        save(&record,&mut digest)?;
        record.source=root.join("other");
        assert!(save(&record,&mut digest).is_err());
        record.source=root.clone(); record.session_sha256=Some("a".repeat(64)); record.stage=Stage::Starting;
        save(&record,&mut digest)?;
        record.stage=Stage::Sent;
        assert!(save(&record,&mut digest).is_err());
        Ok(())
    }
    #[test]
    fn rollback_evidence_retains_original_context_and_cannot_replay() -> Result<()> {
        let temp=tempfile::tempdir()?; let root=temp.path().canonicalize()?;
        let mut record=original(&root); let mut digest=None;
        save(&record,&mut digest)?;
        record.stage=Stage::Sent; save(&record,&mut digest)?;
        record.was_serving=true;
        assert!(save(&record,&mut digest).is_err());
        record.was_serving=false; record.stage=Stage::RolledBack; save(&record,&mut digest)?;
        assert!(require_startable(record.stage).is_err());
        record.stage=Stage::Sent;
        assert!(save(&record,&mut digest).is_err());
        record.stage=Stage::RollbackFinished; save(&record,&mut digest)?;
        assert!(remove_rollback(&record,digest.as_deref().context("synthetic journal digest missing")?).is_err());
        record.stage=Stage::RollbackHandedOff; save(&record,&mut digest)?;
        assert!(remove_rollback(&record,"foreign-digest").is_err());
        remove_rollback(&record,digest.as_deref().context("synthetic journal digest missing")?)?;
        assert!(!path(&root).exists());
        Ok(())
    }
    #[test]
    fn prior_spawn_or_finished_state_never_authorizes_another_spawn() {
        for stage in [Stage::Prepared,Stage::Starting,Stage::Verified,Stage::Finished,Stage::HandedOff,Stage::RolledBack,Stage::RollbackStarting,Stage::RollbackFinished,Stage::RollbackHandedOff] {
            assert!(require_startable(stage).is_err());
        }
        assert!(require_startable(Stage::Sent).is_ok());
        assert!(require_startable(Stage::Committed).is_ok());
    }
    #[test]
    fn generic_recovery_rejects_even_malformed_pending_evidence() -> Result<()> {
        let temp=tempfile::tempdir()?; let root=temp.path().canonicalize()?;
        reject_generic_recovery(&root)?;
        std::fs::create_dir_all(path(&root).parent().context("synthetic journal parent missing")?)?;
        std::fs::write(path(&root),b"malformed-original")?;
        assert!(reject_generic_recovery(&root).is_err());
        assert_eq!(std::fs::read(path(&root))?,b"malformed-original");
        Ok(())
    }
    #[test]
    fn cleanup_is_cas_bound_and_only_after_handoff() -> Result<()> {
        let temp=tempfile::tempdir()?; let root=temp.path().canonicalize()?;
        let mut record=original(&root); let mut digest=None;
        save(&record,&mut digest)?;
        assert!(remove_finished(&record,digest.as_deref().context("synthetic journal digest missing")?).is_err());
        record.stage=Stage::Sent; save(&record,&mut digest)?;
        record.session_sha256=Some("c".repeat(64)); record.stage=Stage::Starting; save(&record,&mut digest)?;
        record.actor=Some(RuntimeIdentity {pid:12,process_start_id:"synthetic".into(),instance_id:"synthetic".into(),generation:1,
            image_path:record.binary.display().to_string(),image_sha256:record.image_sha256.clone(),
            installation_root:root.display().to_string(),installation_id:"synthetic".into(),profile:root.display().to_string(),account_id:"synthetic".into()});
        record.stage=Stage::Verified; save(&record,&mut digest)?;
        record.stage=Stage::Finished; save(&record,&mut digest)?;
        assert!(remove_finished(&record,digest.as_deref().context("synthetic journal digest missing")?).is_err());
        record.stage=Stage::HandedOff; save(&record,&mut digest)?;
        assert!(remove_finished(&record,"wrong-digest").is_err());
        assert!(path(&root).exists());
        remove_finished(&record,digest.as_deref().context("synthetic journal digest missing")?)?;
        assert!(!path(&root).exists());
        Ok(())
    }
    #[test]
    fn completed_receipt_never_accepts_recovery_secret() {
        let value=serde_json::json!({"schema_version":1,"operation_id":uuid::Uuid::new_v4().to_string(),
            "session_sha256":"a".repeat(64),"path":"/synthetic/session.json","runtime":{
                "pid":12,"process_start_id":"synthetic","instance_id":"synthetic","generation":1,
                "image_path":"/synthetic/runtime","image_sha256":"a".repeat(64),
                "installation_root":"/synthetic","installation_id":"synthetic","profile":"/synthetic","account_id":"synthetic"},
            "super_password":"synthetic-only"});
        assert!(serde_json::from_value::<CompleteReceipt>(value).is_err());
    }
}
