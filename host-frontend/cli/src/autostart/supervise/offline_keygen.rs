//! Durable, secret-free continuation for an explicitly requested offline keygen.
//! Only Runtime Start may move a committed original operation toward serving.
use anyhow::{Context, Result};
use respire_commands::output::{Item, ResultEnvelope, Status};
use respire_protocol::{HostAuthIdentity, HostAuthOutcome, HostAuthResult};
use serde::{Deserialize, Serialize};
use std::{io::Read, path::{Path, PathBuf}};
use super::super::{hash, private_write, lifecycle};
use super::launch_authorization::control;
mod launch;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_marker_sha256: Option<String>,
    original_identity: HostAuthIdentity, session_sha256: Option<String>, stage: Stage,
    actor: Option<RuntimeIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    final_actor: Option<RuntimeIdentity>,
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
    anyhow::ensure!(record.pending_marker_sha256.as_deref().is_none_or(|digest|
        valid_digest(digest) && matches!(record.stage,Stage::Prepared|Stage::RolledBack)),
        "offline keygen marker intent is outside a pre-effect stage");
    let committed=matches!(record.stage,Stage::Committed|Stage::Starting|Stage::Verified|Stage::Finished|Stage::HandedOff);
    anyhow::ensure!(if committed { record.session_sha256.as_deref().is_some_and(valid_digest) }
        else { record.session_sha256.is_none() }, "offline keygen stage has inconsistent receipt evidence");
    let actor_required=matches!(record.stage,Stage::Verified|Stage::Finished|Stage::HandedOff)
        || (record.was_serving && matches!(record.stage,Stage::RollbackFinished|Stage::RollbackHandedOff));
    anyhow::ensure!(record.actor.is_some() == actor_required && (record.was_serving || !record.store_ready),
        "offline keygen stage has inconsistent live actor evidence");
    anyhow::ensure!(record.final_actor.is_none() || matches!(record.stage, Stage::HandedOff | Stage::RollbackHandedOff)
        && record.actor.is_some(), "offline keygen final actor precedes durable handoff");
    Ok(())
}
fn require_startable(stage:Stage) -> Result<()> {
    anyhow::ensure!(matches!(stage,Stage::Sent|Stage::Committed),
        "offline_keygen_handoff_pending: prior launch/completion requires independent recovery; no spawn retried");
    Ok(())
}
fn keygen_sends_original(stage:Stage,query_only:bool) -> Result<bool> {
    match stage {
        Stage::Prepared => {
            anyhow::ensure!(!query_only,
                "offline keygen original was not sent; repeat keygen with the original force to resume preparation");
            Ok(true)
        }
        Stage::Sent | Stage::Committed => Ok(false),
        _ => anyhow::bail!("offline keygen handoff requires explicit recovery; no write was repeated"),
    }
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
    let published=private_write(&file,&bytes,digest.as_deref());
    #[cfg(test)]
    let published=published.and_then(|()| tests::journal_publish_result());
    if published.is_err() {
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
    binding.pending_marker_sha256=previous.pending_marker_sha256.clone();
    binding.session_sha256=previous.session_sha256.clone();
    binding.actor=previous.actor.clone();
    binding.final_actor=previous.final_actor.clone();
    if matches!(previous.stage,Stage::Prepared|Stage::RolledBack) {
        anyhow::ensure!(if next.stage == previous.stage {
            (next.marker_sha256 == previous.marker_sha256
                || previous.pending_marker_sha256.as_ref() == Some(&next.marker_sha256))
                && (next.pending_marker_sha256.is_some()
                    || previous.pending_marker_sha256.as_ref().is_none_or(|target| target == &next.marker_sha256))
        } else {
            previous.pending_marker_sha256.is_none() && next.pending_marker_sha256.is_none()
                && next.marker_sha256 == previous.marker_sha256
        }, "offline keygen marker intent must settle before any effect claim");
    } else {
        anyhow::ensure!(next.pending_marker_sha256 == previous.pending_marker_sha256,
            "offline keygen cannot create a marker intent from an effect-bearing stage");
    }
    anyhow::ensure!(if let Some(final_actor) = &previous.final_actor {
        next.final_actor.as_ref() == Some(final_actor)
    } else {
        next.final_actor.is_none() || matches!((previous.stage,next.stage),
            (Stage::Finished,Stage::HandedOff) | (Stage::RollbackFinished,Stage::RollbackHandedOff))
    }, "offline keygen final actor changed outside handoff");
    anyhow::ensure!(serde_json::to_value(&binding)? == serde_json::to_value(previous)?
        && previous.session_sha256.as_ref().is_none_or(|digest| next.session_sha256.as_ref() == Some(digest))
        && previous.actor.as_ref().is_none_or(|actor| next.actor.as_ref() == Some(actor)),
        "offline keygen original operation changed");
    anyhow::ensure!(matches!((previous.stage,next.stage),
        (Stage::Prepared,Stage::Prepared) | (Stage::Prepared,Stage::Sent)
        | (Stage::Sent,Stage::Sent) | (Stage::Sent,Stage::Committed)
        | (Stage::Committed,Stage::Committed) | (Stage::Sent,Stage::Starting)
        | (Stage::Committed,Stage::Starting) | (Stage::Starting,Stage::Verified)
        | (Stage::Verified,Stage::Finished) | (Stage::Finished,Stage::HandedOff)
        | (Stage::Sent,Stage::RolledBack) | (Stage::RolledBack,Stage::RolledBack)
        | (Stage::RolledBack,Stage::RollbackStarting)
        | (Stage::RollbackStarting,Stage::RollbackFinished)
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

/// A new controller may replace only one of the exact marker digests already
/// recorded for this original. Persist its target before publishing that marker.
fn record_marker_intent(record:&mut Original,digest:&mut Option<String>,observed:Option<&str>,target:&str) -> Result<()> {
    anyhow::ensure!(matches!(record.stage,Stage::Prepared|Stage::RolledBack)
        && match observed {
            Some(actual) => actual == record.marker_sha256 || record.pending_marker_sha256.as_deref() == Some(actual),
            None => record.stage == Stage::Prepared,
        }, "offline keygen rebind does not match its original marker intent");
    if let Some(actual)=observed { record.marker_sha256=actual.to_owned(); }
    record.pending_marker_sha256=Some(target.to_owned());
    save(record,digest)
}
fn resume_prelaunch_maintenance(record:&mut Original,digest:&mut Option<String>) -> Result<lifecycle::Maintenance> {
    anyhow::ensure!(matches!(record.stage,Stage::Prepared|Stage::RolledBack),
        "offline keygen cannot rebind an uncertain effect or launch");
    let root=record.root.clone(); let profile=record.profile.clone();
    let token=record.token.clone(); let coordinator=record.coordinator.clone();
    let marker=record.marker_sha256.clone(); let pending=record.pending_marker_sha256.clone();
    lifecycle::resume_offline_keygen_prelaunch_maintenance(&root,&profile,&token,&coordinator,
        &marker,pending.as_deref(),record.stage == Stage::Prepared,
        |observed,target| record_marker_intent(record,digest,observed,target))
}
fn settle_marker_intent(record:&mut Original,digest:&mut Option<String>,maintenance:&mut lifecycle::Maintenance) -> Result<()> {
    let target=record.pending_marker_sha256.clone().context("offline keygen marker rebind intent missing")?;
    update_marker(record,maintenance)?;
    anyhow::ensure!(record.marker_sha256 == target, "offline keygen rebound marker differs from durable intent");
    record.pending_marker_sha256=None;
    save(record,digest)
}

pub(crate) fn keygen(operation: Option<&str>, force: bool) -> Result<ResultEnvelope> {
    if let Some(id) = operation {
        anyhow::ensure!(canonical_id(id), "auth operation ID must be a canonical random UUID");
    }
    crate::runtime_policy::require_host("offline keygen handoff")?;
    anyhow::ensure!(lifecycle::current_boot_token().is_none(), "offline keygen requires its own controller");
    let (binary,image_sha256)=crate::runtime_fetch::require_offline_keygen_handoff()?;
    #[cfg(test)]
    tests::assert_no_forbidden_admission();
    let (root,profile)=respire_client_host::config::control_roots()?;
    let takeover=crate::runtime_policy::takeover_lock()?;
    if operation.is_none() { std::fs::create_dir_all(&profile)?; }
    let root=root.canonicalize()?; let profile=profile.canonicalize()?;
    let saved=load(&root)?;
    let (mut record,mut digest,mut maintenance)=if let Some((mut record,digest))=saved {
        anyhow::ensure!(record.force == force && operation.is_none_or(|id| id == record.operation_id),
            "offline keygen requires the original operation and force");
        let prepared=keygen_sends_original(record.stage,operation.is_some())?;
        verify_selection(&record)?;
        if prepared {
            anyhow::ensure!(control::identity(&profile)? == record.original_identity,
                "offline keygen prepared source identity changed");
            let health=crate::rpc::probe_runtime()?;
            verify_prepared_owner(&record,health.as_ref())?;
            let mut digest=Some(digest);
            let mut maintenance=resume_prelaunch_maintenance(&mut record,&mut digest)?;
            // Preserve the rebound marker before a drain can fail or time out.
            settle_marker_intent(&mut record,&mut digest,&mut maintenance)?;
            if let Some(health)=health.as_ref() { maintenance.drain_runtime(health)?; }
            (record,digest,maintenance)
        } else {
            lifecycle::verify_offline_keygen_marker(&root,&profile,&record.token,&record.coordinator,&record.marker_sha256)?;
            let maintenance=lifecycle::resume_key_maintenance(&root,&profile,&record.source,&record.token,&record.coordinator)?;
            (record,Some(digest),maintenance)
        }
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
                token:token.to_owned(),coordinator:coordinator.to_owned(),marker_sha256:marker_sha256.to_owned(),pending_marker_sha256:None,
                original_identity:control::identity(&profile)?,session_sha256:None,stage:Stage::Prepared,actor:None,final_actor:None,
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
    let send=keygen_sends_original(record.stage,operation.is_some())?;
    if send {
        anyhow::ensure!(control::identity(&record.profile)? == record.original_identity, "offline keygen source identity changed");
        require_no_owner()?;
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
        record_rollback(&mut record,&mut digest,&result)?;
        if send { finish_initial_rollback(&takeover,&mut record,&mut digest,&mut maintenance)?; }
        // Queries reconcile O but never restore a serving owner. Explicit Start
        // may consume the durable RolledBack pre-launch stage exactly once.
        let mut envelope=envelope;
        if !send { envelope.actions.push("runtime start".into()); }
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

/// Private continuation-file snapshot of existing Health evidence. This is not
/// an RPC DTO or a new auth result and must never accept recovery material.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeIdentity {
    pub pid: u32,
    pub process_start_id: String,
    pub instance_id: String,
    pub generation: u64,
    pub image_path: String,
    pub image_sha256: String,
    pub installation_root: String,
    pub installation_id: String,
    pub profile: String,
    pub account_id: String,
}

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

fn require_no_owner() -> Result<()> {
    anyhow::ensure!(crate::rpc::probe_runtime()?.is_none() && !crate::rpc::endpoint_path().try_exists()?,
        "offline keygen live or unknown owner exists; no spawn or write attempted");
    Ok(())
}

fn verify_prepared_owner(record:&Original,health:Option<&crate::net_rpc::Health>) -> Result<()> {
    let Some(health)=health else { return require_no_owner(); };
    anyhow::ensure!(record.was_serving && health.store_ready == record.store_ready,
        "offline keygen prepared operation gained a different owner");
    let manifest=crate::runtime_fetch::read_manifest()?.context("offline keygen Runtime manifest missing")?;
    let registration=super::super::read_registration(&record.root)?;
    let managed=registration.as_ref().filter(|config| config.enabled && !config.manually_stopped);
    let account=match &record.original_identity {
        HostAuthIdentity::Bound { account_id, .. } => account_id.clone(),
        _ => hash(record.profile.display().to_string().as_bytes()),
    };
    super::launch_authorization::model_control::verify_model_owner(health,&record.root,&record.profile,
        managed,&record.binary,&manifest,Some(&account))
}

fn rollback_receipt(record:&Original,result:&HostAuthResult,identity:&HostAuthIdentity) -> Result<()> {
    anyhow::ensure!(record.stage == Stage::Sent && result.outcome == HostAuthOutcome::RolledBack
        && result.operation_id == record.operation_id && result.path == record.profile.join("session.json")
        && result.session_sha256.is_none() && result.super_password.is_none()
        && identity == &record.original_identity,
        "offline keygen rollback original receipt or identity changed");
    Ok(())
}
fn record_rollback(record:&mut Original,digest:&mut Option<String>,result:&HostAuthResult) -> Result<()> {
    rollback_receipt(record,result,&control::identity(&record.profile)?)?;
    record.stage=Stage::RolledBack;
    save(record,digest)
}
fn claim_rollback(record:&mut Original,digest:&mut Option<String>) -> Result<()> {
    anyhow::ensure!(record.stage == Stage::RolledBack,
        "offline keygen rollback already attempted; no completion or spawn retried");
    // Fence completion as well as spawning, even if the original had no owner.
    record.stage=Stage::RollbackStarting;
    save(record,digest)
}

fn finish_initial_rollback(takeover:&respire_client_host::lock::LibraryLock,record:&mut Original,
    digest:&mut Option<String>,maintenance:&mut lifecycle::Maintenance) -> Result<()> {
    verify_selection(record)?;
    anyhow::ensure!(takeover.protects(&record.root.join("runtime/takeover"))?, "offline keygen takeover mismatch");
    anyhow::ensure!(control::identity(&record.profile)? == record.original_identity,
        "offline keygen rollback original identity changed");
    lifecycle::verify_offline_keygen_marker(&record.root,&record.profile,&record.token,&record.coordinator,&record.marker_sha256)?;
    require_no_owner()?;
    claim_rollback(record,digest)?;
    if record.was_serving {
        maintenance.start_account_runtime()?;
        let actor=verify_original_target(&record.root,&record.profile,&record.original_identity,record.store_ready)?;
        let binding=maintenance.offline_keygen_start_binding(&record.profile,&record.token,&record.coordinator)?;
        let launch=launch::Evidence::capture(record,&actor,&binding)?;
        let process=crate::net_rpc::runtime_process_identity(actor.pid)?;
        maintenance.offline_keygen_rollback_verified(&record.profile,&record.original_identity,record.store_ready)?;
        finish_checked(&actor,|| {
            launch.verify()?;
            verify_selection(record)?;
            anyhow::ensure!(takeover.protects(&record.root.join("runtime/takeover"))?
                && load(&record.root)?.is_some_and(|(_,actual)| Some(actual) == *digest)
                && crate::net_rpc::runtime_process_identity(actor.pid)? == process,
                "offline keygen rollback evidence changed before completion");
            let live=verify_original_target(&record.root,&record.profile,&record.original_identity,record.store_ready)?;
            anyhow::ensure!(crate::net_rpc::runtime_process_identity(actor.pid)? == process
                && crate::net_rpc::process_is_running(actor.pid)?,
                "offline keygen rollback OS actor changed during completion");
            Ok(live)
        },|| {
            maintenance.verify_offline_keygen_completion(&record.profile)?;
            maintenance.finish()
        })?;
        record.actor=Some(actor);
    } else {
        maintenance.finish()?;
    }
    lifecycle::verify_offline_keygen_finished(&record.root)?;
    record.stage=Stage::RollbackFinished; save(record,digest)?;
    maintenance.finish_handoff()?;
    if record.was_serving {
        record.final_actor=finish_embedded_serving_handoff(takeover,record,&record.original_identity,record.store_ready)?;
    }
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

/// The Paused auth.result has already proved the original operation/key/force and
/// committed candidate before launch. Runtime rechecks that Unbound identity
/// after taking the library lock and holds it through serving. Do not acquire a
/// second library lock or introduce a completion RPC beside that live actor.
fn complete(takeover: &respire_client_host::lock::LibraryLock,
    maintenance: &mut lifecycle::Maintenance, record: &Original, actor: &RuntimeIdentity,
    launch: &launch::Evidence,
) -> Result<()> {
    anyhow::ensure!(record.stage == Stage::Verified && record.actor.as_ref() == Some(actor),
        "offline keygen completion lacks its durable verified actor");
    let process = crate::net_rpc::runtime_process_identity(actor.pid)?;
    finish_checked(actor, || {
        launch.verify()?;
        verify_selection(record)?;
        anyhow::ensure!(takeover.protects(&record.root.join("runtime/takeover"))?,
            "offline keygen takeover mismatch");
        let (durable, _) = load(&record.root)?.context("offline keygen original evidence missing")?;
        anyhow::ensure!(serde_json::to_value(&durable)? == serde_json::to_value(record)?,
            "offline keygen original evidence changed during completion");
        let session = record.session_sha256.as_deref().context("offline keygen committed digest missing")?;
        anyhow::ensure!(crate::net_rpc::runtime_process_identity(actor.pid)? == process,
            "offline keygen OS actor changed before completion check");
        let live = verify_target(&record.root, &record.profile, &record.operation_id, session)?;
        anyhow::ensure!(crate::net_rpc::runtime_process_identity(actor.pid)? == process
            && crate::net_rpc::process_is_running(actor.pid)?,
            "offline keygen OS actor changed during completion check");
        Ok(live)
    }, || {
        maintenance.verify_offline_keygen_completion(&record.profile)?;
        maintenance.finish()
    })?;
    lifecycle::verify_offline_keygen_finished(&record.root)
}

/// Retain the expected exact actor across the local state transition. A failed
/// post-check is an uncertain completion, never permission to spawn or replay O.
fn finish_checked(actor: &RuntimeIdentity,
    mut observe: impl FnMut() -> Result<RuntimeIdentity>, finish: impl FnOnce() -> Result<()>,
) -> Result<()> {
    anyhow::ensure!(observe()? == *actor, "offline keygen actor changed before completion");
    finish()?;
    anyhow::ensure!(observe()? == *actor, "offline keygen actor changed during completion");
    Ok(())
}

/// Authentication status alone is not live/terminal evidence. This admission
/// runs only after the original Paused auth.result exchange succeeds.
fn committed_start_session(record: &Original, receipt: &HostAuthResult,
    identity: &HostAuthIdentity,
) -> Result<String> {
    require_startable(record.stage)?;
    anyhow::ensure!(receipt.outcome == HostAuthOutcome::Committed
        && receipt.operation_id == record.operation_id
        && receipt.path == record.profile.join("session.json"),
        "offline keygen original is not committed");
    let session = receipt.session_sha256.as_deref().filter(|value| valid_digest(value))
        .context("offline keygen receipt digest missing or invalid")?;
    anyhow::ensure!(record.session_sha256.as_deref().is_none_or(|saved| saved == session)
        && identity == &(HostAuthIdentity::Unbound {
            operation_id: record.operation_id.clone(), session_sha256: session.to_owned(),
        }), "offline keygen original identity changed");
    Ok(session.to_owned())
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
            anyhow::ensure!(completed_actor(&record)? == &verify_original_target(&root,&profile,&record.original_identity,record.store_ready)?,
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
        anyhow::ensure!(completed_actor(&record)? == &verify_target(&root,&profile,&record.operation_id,session)?,
            "offline keygen finished actor changed; no spawn attempted");
        remove_finished(&record,&digest)?;
        return Ok(true);
    }
    if record.stage == Stage::RolledBack {
        verify_selection(&record)?;
        anyhow::ensure!(control::identity(&profile)? == record.original_identity,
            "offline keygen rollback original identity changed");
        require_no_owner()?;
        let mut digest=Some(digest);
        let mut maintenance=resume_prelaunch_maintenance(&mut record,&mut digest)?;
        settle_marker_intent(&mut record,&mut digest,&mut maintenance)?;
        finish_initial_rollback(takeover,&mut record,&mut digest,&mut maintenance)?;
        return Ok(record.was_serving);
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
    if receipt.outcome == HostAuthOutcome::RolledBack {
        record_rollback(&mut record,&mut digest,&receipt)?;
        finish_initial_rollback(takeover,&mut record,&mut digest,&mut maintenance)?;
        return Ok(record.was_serving);
    }
    let session = committed_start_session(&record, &receipt, &control::identity(&profile)?)?;
    // Never retain the auth.result recovery code, including in the continuation file.
    drop(receipt.super_password);
    record.session_sha256=Some(session.clone()); record.stage=Stage::Starting;
    update_marker(&mut record,&mut maintenance)?; save(&record,&mut digest)?;
    maintenance.start_account_runtime()?;
    let actor=verify_target(&root,&profile,&record.operation_id,&session)?;
    let binding = maintenance.offline_keygen_start_binding(&profile, &record.token, &record.coordinator)?;
    let launch = launch::Evidence::capture(&record, &actor, &binding)?;
    maintenance.offline_keygen_target_verified(&profile,&record.operation_id,&session)?;
    record.stage=Stage::Verified; record.actor=Some(actor.clone()); save(&record,&mut digest)?;
    complete(takeover,&mut maintenance,&record,&actor,&launch)?;
    record.stage=Stage::Finished; save(&record,&mut digest)?;
    maintenance.finish_handoff()?;
    record.final_actor=finish_embedded_serving_handoff(takeover,&record,&HostAuthIdentity::Unbound {
        operation_id:record.operation_id.clone(),session_sha256:session.clone()},true)?;
    record.stage=Stage::HandedOff; save(&record,&mut digest)?;
    remove_finished(&record,digest.as_deref().context("offline keygen cleanup digest missing")?)?;
    Ok(true)
}

/// Only the successful in-process completion path calls this. Finished records
/// are deliberately not resumable: a lost drain/spawn result cannot be replayed.
fn finish_embedded_serving_handoff(takeover:&respire_client_host::lock::LibraryLock,record:&Original,identity:&HostAuthIdentity,ready:bool)
    -> Result<Option<RuntimeIdentity>> {
    let Some(selected)=crate::embedding::selection() else { return Ok(None); };
    anyhow::ensure!(matches!(record.stage,Stage::Finished|Stage::RollbackFinished),
        "offline keygen compatibility handoff precedes completion");
    anyhow::ensure!(takeover.protects(&record.root.join("runtime/takeover"))?, "offline keygen takeover mismatch");
    let expected_identity=if record.stage == Stage::Finished {
        HostAuthIdentity::Unbound { operation_id:record.operation_id.clone(),
            session_sha256:record.session_sha256.clone().context("offline keygen completed session missing")? }
    } else { record.original_identity.clone() };
    anyhow::ensure!(identity == &expected_identity, "offline keygen compatibility identity differs from original receipt");
    let (durable,_)=load(&record.root)?.context("offline keygen completion evidence missing")?;
    anyhow::ensure!(serde_json::to_value(&durable)? == serde_json::to_value(record)?,
        "offline keygen completion evidence changed before handoff");
    selected.verify_offline_keygen_handoff()?;
    verify_selection(record)?;
    lifecycle::verify_offline_keygen_finished(&record.root)?;
    let old=record.actor.as_ref().context("offline keygen completed actor missing")?;
    anyhow::ensure!(old == &verify_original_target(&record.root,&record.profile,identity,ready)?,
        "offline keygen strict actor changed before compatibility handoff");
    crate::embedding::account_host().context("embedded account host missing")?
        .finish_key_handoff(&record.profile,identity,true)?;
    verify_selection(record)?;
    let successor=verify_original_target(&record.root,&record.profile,identity,ready)?;
    anyhow::ensure!(successor.instance_id != old.instance_id,
        "offline keygen compatibility handoff did not replace strict actor");
    Ok(Some(successor))
}
fn completed_actor(record:&Original) -> Result<&RuntimeIdentity> {
    completed_actor_for_host(record,crate::embedding::selection().is_some())
}
fn completed_actor_for_host(record:&Original,embedded:bool) -> Result<&RuntimeIdentity> {
    if embedded {
        // Old records lacking a confirmed successor remain untouched, not
        // reinterpreted as permission to convert a grant into legacy authority.
        record.final_actor.as_ref().context("offline keygen compatibility actor unconfirmed")
    } else {
        anyhow::ensure!(record.final_actor.is_none(), "offline keygen successor requires its original embedded host");
        record.actor.as_ref().context("offline keygen completed actor missing")
    }
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
    std::thread_local! {
        static FORBID_ADMISSION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        static FAIL_JOURNAL_AFTER_PUBLISH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }
    pub(super) fn journal_publish_result() -> Result<()> {
        anyhow::ensure!(!FAIL_JOURNAL_AFTER_PUBLISH.with(|fail| fail.replace(false)),
            "synthetic unknown durability after journal publication");
        Ok(())
    }
    pub(super) fn assert_no_forbidden_admission() {
        FORBID_ADMISSION.with(|forbidden| assert!(!forbidden.get(), "unsupported keygen crossed the side-effect boundary"));
    }
    struct AdmissionTrap;
    impl AdmissionTrap {
        fn install() -> Self { FORBID_ADMISSION.with(|value| value.set(true)); Self }
    }
    impl Drop for AdmissionTrap {
        fn drop(&mut self) { FORBID_ADMISSION.with(|value| value.set(false)); }
    }
    fn snapshot_tree(root:&Path) -> Result<std::collections::BTreeMap<PathBuf,Option<Vec<u8>>>> {
        fn visit(root:&Path,at:&Path,out:&mut std::collections::BTreeMap<PathBuf,Option<Vec<u8>>>) -> Result<()> {
            for entry in std::fs::read_dir(at)? {
                let entry=entry?; let path=entry.path(); let kind=entry.file_type()?;
                anyhow::ensure!(!kind.is_symlink(), "unexpected test fixture link");
                let relative=path.strip_prefix(root)?.to_owned();
                if kind.is_dir() { out.insert(relative,None); visit(root,&path,out)?; }
                else { out.insert(relative,Some(std::fs::read(path)?)); }
            }
            Ok(())
        }
        let mut result=std::collections::BTreeMap::new(); visit(root,root,&mut result)?; Ok(result)
    }
    #[test]
    fn unsupported_metadata_keygen_never_enters_side_effects() -> Result<()> {
        let _env=crate::runtime_fetch::runtime_fetch_tests::env_scope(&[
            "RSRS_DATA_DIR","RSRS_BIN_DIR","RSRS_RUNTIME_BIN","RSRS_CLIENT_ONLY","RSRS_NO_AUTOSTART"])?;
        let temp=tempfile::tempdir()?; let root=temp.path().canonicalize()?;
        std::env::set_var("RSRS_DATA_DIR",&root);
        std::env::set_var("RSRS_BIN_DIR",root.join("bin"));
        for key in ["RSRS_RUNTIME_BIN","RSRS_CLIENT_ONLY","RSRS_NO_AUTOSTART"] { std::env::remove_var(key); }
        assert!(crate::embedding::selection().is_none());
        crate::runtime_fetch::runtime_fetch_tests::install_lifecycle_fixture()?;
        // This has authenticated schema-2 metadata and an intact file inventory,
        // but deliberately lacks offline_keygen_handoff. No installer is called.
        let before=snapshot_tree(&root)?;
        let _trap=AdmissionTrap::install();
        let error=keygen(None,false).err().context("unsupported Runtime accepted keygen")?;
        assert_eq!(error.to_string(),"offline_keygen_handoff_unsupported: upgrade Runtime before generating local keys");
        assert_eq!(snapshot_tree(&root)?,before);
        assert!(!path(&root).exists());
        assert!(!root.join("runtime/autostart/maintenance.json").exists());
        assert!(!root.join("runtime/endpoint.json").exists());
        assert!(!root.join("session.json").exists());
        Ok(())
    }

    #[test]
    fn unsupported_embedding_keygen_never_enters_side_effects() -> Result<()> {
        const CHILD: &str="RESP_ENV_KEYGEN_CAPABILITY_CHILD";
        if std::env::var(CHILD).as_deref() != Ok("1") {
            // OnceLock selection is process-local; never contaminate other tests.
            let thread=std::thread::current();
            let test_name=thread.name().context("test name missing")?;
            let output=std::process::Command::new(std::env::current_exe()?)
                .args(["--exact",test_name,"--nocapture"])
                .env(CHILD,"1").output()?;
            anyhow::ensure!(output.status.success(), "isolated unsupported embedding test failed: {}",
                String::from_utf8_lossy(&output.stderr));
            anyhow::ensure!(String::from_utf8_lossy(&output.stdout).contains("embedded-capability-rejection-checked"),
                "isolated capability test did not execute its assertions");
            return Ok(());
        }
        let _env=crate::runtime_fetch::runtime_fetch_tests::env_scope(&[
            "RSRS_DATA_DIR","RSRS_BIN_DIR","RSRS_RUNTIME_BIN","RSRS_CLIENT_ONLY","RSRS_NO_AUTOSTART"])?;
        let temp=tempfile::tempdir()?; let root=temp.path().canonicalize()?.join("untouched");
        std::env::set_var("RSRS_DATA_DIR",&root);
        std::env::set_var("RSRS_BIN_DIR",temp.path().join("bin"));
        for key in ["RSRS_RUNTIME_BIN","RSRS_CLIENT_ONLY","RSRS_NO_AUTOSTART"] { std::env::remove_var(key); }
        fn current_test_image() -> Result<respire_host_control::VerifiedRuntime> {
            let image=std::env::current_exe()?.canonicalize()?;
            let version=image.parent().and_then(|path| path.file_name()).and_then(|name| name.to_str())
                .context("test image directory missing")?;
            let digest=hash(&std::fs::read(&image)?);
            respire_host_control::VerifiedRuntime::verify_installed(&image,&digest,version,12345)
        }
        fn forbidden_account_host() -> std::sync::Arc<dyn respire_host_control::HostLifecycle> {
            panic!("unsupported embedding entered account host fallback")
        }
        crate::embedding::install_runtime_embedding(crate::embedding::RuntimeEmbedding {
            verify_runtime:current_test_image, account_host:forbidden_account_host,
            offline_keygen_handoff:None,
        })?;
        let _trap=AdmissionTrap::install();
        let error=keygen(None,false).err().context("unsupported embedding accepted keygen")?;
        assert_eq!(error.to_string(),"offline_keygen_handoff_unsupported: embedded Runtime lacks the implementation");
        assert!(!root.exists());
        assert_eq!(std::fs::read_dir(temp.path())?.count(),0);
        println!("embedded-capability-rejection-checked");
        Ok(())
    }
    fn original(root:&Path) -> Original {
        Original { schema:1,operation_id:uuid::Uuid::new_v4().to_string(),force:false,
            root:root.to_owned(),source:root.to_owned(),profile:root.to_owned(),binary:root.join("runtime-image"),
            image_sha256:"a".repeat(64),token:uuid::Uuid::new_v4().to_string(),coordinator:"synthetic-coordinator".into(),
            marker_sha256:"b".repeat(64),pending_marker_sha256:None,original_identity:HostAuthIdentity::Absent,session_sha256:None,stage:Stage::Prepared,actor:None,final_actor:None,was_serving:false,store_ready:false }
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
        record.stage=Stage::RollbackFinished;
        assert!(save(&record,&mut digest).is_err());
        record.stage=Stage::RolledBack; claim_rollback(&mut record,&mut digest)?;
        record.stage=Stage::RollbackFinished; save(&record,&mut digest)?;
        assert!(remove_rollback(&record,digest.as_deref().context("synthetic journal digest missing")?).is_err());
        record.stage=Stage::RollbackHandedOff; save(&record,&mut digest)?;
        assert!(remove_rollback(&record,"foreign-digest").is_err());
        remove_rollback(&record,digest.as_deref().context("synthetic journal digest missing")?)?;
        assert!(!path(&root).exists());
        Ok(())
    }
    #[test]
    fn prepared_retry_keeps_original_and_query_never_sends() -> Result<()> {
        let temp=tempfile::tempdir()?; let root=temp.path().canonicalize()?;
        let mut record=original(&root); let mut digest=None;
        record.force=true;
        save(&record,&mut digest)?;
        let original_id=record.operation_id.clone();
        let original_token=record.token.clone();
        // A successfully rebound Paused marker is persisted before retrying a
        // failed drain. Prepared proves that no keygen exchange has begun.
        record_marker_intent(&mut record,&mut digest,Some(&"b".repeat(64)),&"c".repeat(64))?;
        record.marker_sha256="c".repeat(64); record.pending_marker_sha256=None; save(&record,&mut digest)?;
        let (mut recovered,observed)=load(&root)?.context("prepared original missing")?;
        assert_eq!(recovered.operation_id,original_id);
        assert_eq!(recovered.token,original_token);
        assert!(recovered.force);
        assert_eq!(recovered.marker_sha256,record.marker_sha256);
        assert!(keygen_sends_original(recovered.stage,true).is_err());
        assert!(keygen_sends_original(recovered.stage,false)?);
        let mut changed=recovered.clone(); changed.force=false;
        assert!(save(&changed,&mut Some(observed.clone())).is_err());
        changed=recovered.clone(); changed.original_identity=HostAuthIdentity::Unbound {
            operation_id:original_id,session_sha256:"d".repeat(64) };
        assert!(save(&changed,&mut Some(observed.clone())).is_err());
        recovered.stage=Stage::Sent; save(&recovered,&mut digest)?;
        for query_only in [false,true] {
            assert!(!keygen_sends_original(Stage::Sent,query_only)?);
            assert!(!keygen_sends_original(Stage::Committed,query_only)?);
            for stage in [Stage::Starting,Stage::Verified,Stage::Finished,Stage::HandedOff,
                Stage::RolledBack,Stage::RollbackStarting,Stage::RollbackFinished,Stage::RollbackHandedOff] {
                assert!(keygen_sends_original(stage,query_only).is_err());
            }
        }
        recovered.stage=Stage::Prepared;
        assert!(save(&recovered,&mut digest).is_err());
        assert_eq!(load(&root)?.context("sent original missing")?.0.stage,Stage::Sent);
        Ok(())
    }
    #[test]
    fn reconciled_rollback_claim_is_durable_for_serving_and_idle_originals() -> Result<()> {
        for was_serving in [false,true] {
            let temp=tempfile::tempdir()?; let root=temp.path().canonicalize()?;
            let mut record=original(&root); let mut digest=None;
            record.was_serving=was_serving;
            save(&record,&mut digest)?;
            record.stage=Stage::Sent; save(&record,&mut digest)?;
            let receipt=HostAuthResult {operation_id:record.operation_id.clone(),
                outcome:HostAuthOutcome::RolledBack,path:root.join("session.json"),
                session_sha256:None,super_password:None};
            rollback_receipt(&record,&receipt,&HostAuthIdentity::Absent)?;
            record.stage=Stage::RolledBack; save(&record,&mut digest)?;
            let before=std::fs::read(path(&root))?;
            let mut stale=record.clone();
            assert!(claim_rollback(&mut stale,&mut Some("foreign-digest".into())).is_err());
            assert_eq!(std::fs::read(path(&root))?,before);
            let (mut recovered,observed)=load(&root)?.context("rollback original missing")?;
            claim_rollback(&mut recovered,&mut Some(observed))?;
            let (mut interrupted,observed)=load(&root)?.context("rollback claim missing")?;
            assert_eq!(interrupted.stage,Stage::RollbackStarting);
            assert_eq!(interrupted.was_serving,was_serving);
            assert!(claim_rollback(&mut interrupted,&mut Some(observed)).is_err());
            assert!(require_startable(interrupted.stage).is_err());
            assert!(keygen_sends_original(interrupted.stage,false).is_err());
            assert!(rollback_receipt(&interrupted,&receipt,&HostAuthIdentity::Absent).is_err());
        }
        Ok(())
    }
    #[test]
    fn rollback_reconciliation_rejects_unknown_foreign_and_committed_evidence() -> Result<()> {
        let temp=tempfile::tempdir()?; let root=temp.path().canonicalize()?;
        let mut record=original(&root); record.stage=Stage::Sent;
        let original_id=record.operation_id.clone();
        let fresh=|| HostAuthResult {operation_id:original_id.clone(),outcome:HostAuthOutcome::RolledBack,
            path:root.join("session.json"),session_sha256:None,super_password:None};
        let valid=fresh();
        rollback_receipt(&record,&valid,&HostAuthIdentity::Absent)?;
        let mut changed=fresh(); changed.operation_id=uuid::Uuid::new_v4().to_string();
        assert!(rollback_receipt(&record,&changed,&HostAuthIdentity::Absent).is_err());
        changed=fresh(); changed.path=root.join("other/session.json");
        assert!(rollback_receipt(&record,&changed,&HostAuthIdentity::Absent).is_err());
        changed=fresh(); changed.session_sha256=Some("a".repeat(64));
        assert!(rollback_receipt(&record,&changed,&HostAuthIdentity::Absent).is_err());
        changed=fresh(); changed.super_password=Some("synthetic-must-not-be-retained".into());
        assert!(rollback_receipt(&record,&changed,&HostAuthIdentity::Absent).is_err());
        for outcome in [HostAuthOutcome::Unknown,HostAuthOutcome::Committed] {
            changed=fresh(); changed.outcome=outcome;
            assert!(rollback_receipt(&record,&changed,&HostAuthIdentity::Absent).is_err());
        }
        assert!(rollback_receipt(&record,&valid,&HostAuthIdentity::Unbound {
            operation_id:record.operation_id.clone(),session_sha256:"a".repeat(64) }).is_err());
        for stage in [Stage::Prepared,Stage::Committed,Stage::Starting,Stage::Verified,Stage::Finished,
            Stage::HandedOff,Stage::RolledBack,Stage::RollbackStarting,Stage::RollbackFinished,Stage::RollbackHandedOff] {
            record.stage=stage;
            assert!(rollback_receipt(&record,&valid,&HostAuthIdentity::Absent).is_err());
        }
        Ok(())
    }
    #[test]
    fn marker_intent_cannot_escape_pre_effect_stages_or_authorize_foreign_hashes() -> Result<()> {
        let temp=tempfile::tempdir()?; let root=temp.path().canonicalize()?;
        for stage in [Stage::Prepared,Stage::RolledBack] {
            let mut record=original(&root); record.stage=stage;
            let mut pending=record.clone(); pending.pending_marker_sha256=Some("c".repeat(64));
            validate_record(&pending,&root)?; validate_transition(&record,&pending)?;
            let mut target=pending.clone(); target.marker_sha256="c".repeat(64); target.pending_marker_sha256=None;
            validate_transition(&pending,&target)?;
            let mut foreign=pending.clone(); foreign.marker_sha256="d".repeat(64);
            assert!(validate_transition(&pending,&foreign).is_err());
            let mut abandoned=pending.clone(); abandoned.pending_marker_sha256=None;
            assert!(validate_transition(&pending,&abandoned).is_err());
            let mut effect=target.clone(); effect.stage=if stage == Stage::Prepared {Stage::Sent} else {Stage::RollbackStarting};
            assert!(validate_transition(&pending,&effect).is_err());
            validate_transition(&target,&effect)?;
            record.pending_marker_sha256=Some("not-a-digest".into());
            assert!(validate_record(&record,&root).is_err());
        }
        for stage in [Stage::Sent,Stage::Committed,Stage::Starting,Stage::Verified,Stage::Finished,
            Stage::HandedOff,Stage::RollbackStarting,Stage::RollbackFinished,Stage::RollbackHandedOff] {
            let mut record=original(&root); record.stage=stage; record.pending_marker_sha256=Some("c".repeat(64));
            assert!(validate_record(&record,&root).is_err());
            assert!(resume_prelaunch_maintenance(&mut record,&mut None).is_err());
        }
        Ok(())
    }

    #[test]
    fn prelaunch_marker_rebind_recovers_process_and_publication_interruptions() -> Result<()> {
        const PHASE:&str="RSRS_TEST_KEYGEN_REBIND_PHASE";
        const STAGE:&str="RSRS_TEST_KEYGEN_REBIND_STAGE";
        fn child(phase:&str,stage:&str,root:&Path) -> Result<()> {
            let current=std::thread::current();
            let name=current.name().context("rebind test name missing")?;
            let output=std::process::Command::new(std::env::current_exe()?)
                .args(["--exact",name,"--nocapture"])
                .env(PHASE,phase).env(STAGE,stage).env("RSRS_DATA_DIR",root).output()?;
            anyhow::ensure!(output.status.success(),"rebind {stage}/{phase} failed: {} {}",
                String::from_utf8_lossy(&output.stdout),String::from_utf8_lossy(&output.stderr));
            anyhow::ensure!(String::from_utf8_lossy(&output.stdout).contains("keygen-rebind-cut-checked"),
                "rebind test child did not execute");
            Ok(())
        }
        let Ok(phase)=std::env::var(PHASE) else {
            for (stage,initial) in [("prepared","initial"),("prepared","initial_absent"),("rolled_back","initial")] {
                let temp=tempfile::tempdir()?; let root=temp.path().canonicalize()?;
                for phase in [initial,"intent_unknown","before_marker","after_marker","journal_failure","journal_unknown","recover"] {
                    child(phase,stage,&root)?;
                }
            }
            return Ok(());
        };
        let _env=crate::runtime_fetch::runtime_fetch_tests::env_scope(&["RSRS_DATA_DIR","RSRS_RUNTIME_BOOT_TOKEN"])?;
        std::env::remove_var("RSRS_RUNTIME_BOOT_TOKEN");
        let root=PathBuf::from(std::env::var_os("RSRS_DATA_DIR").context("rebind root missing")?).canonicalize()?;
        let stage=std::env::var(STAGE)?;
        let marker=root.join("runtime/autostart/maintenance.json");
        if phase == "initial" || phase == "initial_absent" {
            let mut record=original(&root); let mut digest=None;
            let result=lifecycle::begin_offline_keygen_maintenance(&root,&root,|token,coordinator,marker| {
                record.token=token.to_owned(); record.coordinator=coordinator.to_owned(); record.marker_sha256=marker.to_owned();
                save(&record,&mut digest)?;
                anyhow::ensure!(phase != "initial_absent", "synthetic interruption before initial marker");
                Ok(())
            });
            if phase == "initial_absent" {
                assert!(result.is_err() && !marker.exists());
            } else {
                let maintenance=result?;
                if stage == "rolled_back" {
                    record.stage=Stage::Sent; save(&record,&mut digest)?;
                    record.stage=Stage::RolledBack; save(&record,&mut digest)?;
                }
                // Another process cannot rebind while the exact original controller lives.
                child("live_controller",&stage,&root)?;
                drop(maintenance);
            }
        } else {
            let (mut record,observed)=load(&root)?.context("rebind original missing")?;
            let original=record.clone(); let mut digest=Some(observed);
            let before=match std::fs::read(&marker) {
                Ok(bytes) => Some(bytes),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(error.into()),
            };
            match phase.as_str() {
                "live_controller" => {
                    let journal=std::fs::read(path(&root))?;
                    assert!(resume_prelaunch_maintenance(&mut record,&mut digest).is_err());
                    assert_eq!(std::fs::read(path(&root))?,journal);
                    assert_eq!(std::fs::read(&marker).ok(),before);
                }
                "intent_unknown" => {
                    FAIL_JOURNAL_AFTER_PUBLISH.with(|fail| fail.set(true));
                    let error=resume_prelaunch_maintenance(&mut record,&mut digest).err().context("intent fault did not fire")?;
                    assert!(error.to_string().contains("offline_keygen_record_durability_unknown"));
                    assert_eq!(std::fs::read(&marker).ok(),before);
                    assert!(load(&root)?.context("published intent missing")?.0.pending_marker_sha256.is_some());
                }
                "before_marker" => {
                    let token=record.token.clone(); let coordinator=record.coordinator.clone();
                    let expected=record.marker_sha256.clone(); let pending=record.pending_marker_sha256.clone();
                    let result=lifecycle::resume_offline_keygen_prelaunch_maintenance(&root,&root,&token,&coordinator,
                        &expected,pending.as_deref(),record.stage == Stage::Prepared,|previous,target| {
                            record_marker_intent(&mut record,&mut digest,previous,target)?;
                            anyhow::bail!("synthetic error after intent but before marker publication")
                        });
                    assert!(result.is_err());
                    assert_eq!(std::fs::read(&marker).ok(),before);
                    assert!(load(&root)?.context("durable intent missing")?.0.pending_marker_sha256.is_some());
                }
                "after_marker" => {
                    lifecycle::fail_keygen_rebind_after_marker_for_test();
                    assert!(resume_prelaunch_maintenance(&mut record,&mut digest).is_err());
                    let actual=hash(&std::fs::read(&marker)?);
                    let saved=load(&root)?.context("durable target missing")?.0;
                    assert_ne!(actual,saved.marker_sha256);
                    assert_eq!(saved.pending_marker_sha256.as_deref(),Some(actual.as_str()));
                }
                "journal_failure" => {
                    let mut maintenance=resume_prelaunch_maintenance(&mut record,&mut digest)?;
                    assert!(settle_marker_intent(&mut record,&mut Some("foreign-digest".into()),&mut maintenance).is_err());
                    let actual=hash(&std::fs::read(&marker)?);
                    let saved=load(&root)?.context("failed journal lost intent")?.0;
                    assert_eq!(saved.pending_marker_sha256.as_deref(),Some(actual.as_str()));
                }
                "journal_unknown" => {
                    let mut maintenance=resume_prelaunch_maintenance(&mut record,&mut digest)?;
                    FAIL_JOURNAL_AFTER_PUBLISH.with(|fail| fail.set(true));
                    let error=settle_marker_intent(&mut record,&mut digest,&mut maintenance).err().context("journal fault did not fire")?;
                    assert!(error.to_string().contains("offline_keygen_record_durability_unknown"));
                    let saved=load(&root)?.context("published convergence missing")?.0;
                    assert!(saved.pending_marker_sha256.is_none());
                    assert_eq!(saved.marker_sha256,hash(&std::fs::read(&marker)?));
                }
                "recover" => {
                    let mut maintenance=resume_prelaunch_maintenance(&mut record,&mut digest)?;
                    settle_marker_intent(&mut record,&mut digest,&mut maintenance)?;
                    let (saved,_)=load(&root)?.context("settled original missing")?;
                    assert!(saved.pending_marker_sha256.is_none());
                    assert_eq!(saved.marker_sha256,hash(&std::fs::read(&marker)?));
                    assert_eq!(saved.stage,original.stage);
                    assert_eq!(saved.operation_id,original.operation_id);
                    assert_eq!(saved.original_identity,original.original_identity);
                    assert_eq!(saved.force,original.force); assert_eq!(saved.token,original.token);
                    drop(maintenance);
                    let journal=std::fs::read(path(&root))?;
                    let mut foreign:serde_json::Value=serde_json::from_slice(&std::fs::read(&marker)?)?;
                    foreign["owner_birth"]=serde_json::json!("foreign-controller");
                    std::fs::write(&marker,serde_json::to_vec(&foreign)?)?;
                    assert!(resume_prelaunch_maintenance(&mut record,&mut digest).is_err());
                    assert_eq!(std::fs::read(path(&root))?,journal);
                }
                _ => anyhow::bail!("unknown synthetic rebind phase"),
            }
        }
        assert!(!root.join("session.json").exists() && !root.join("runtime/endpoint.json").exists()
            && !root.join("runtime/autostart/launch").exists());
        println!("keygen-rebind-cut-checked");
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
        let mut premature=record.clone();
        premature.final_actor=record.actor.clone();
        assert!(validate_record(&premature,&root).is_err());
        let mut changed=record.clone();
        changed.stage=Stage::Finished;
        changed.actor.as_mut().context("synthetic actor missing")?.instance_id="changed".into();
        assert!(validate_transition(&record,&changed).is_err());
        record.stage=Stage::Finished; save(&record,&mut digest)?;
        assert!(require_startable(record.stage).is_err());
        let mut successor=record.actor.clone().context("synthetic actor missing")?;
        successor.instance_id="successor".into();
        let mut old_terminal=record.clone(); old_terminal.stage=Stage::HandedOff;
        assert!(completed_actor_for_host(&old_terminal,true).is_err());
        assert!(completed_actor_for_host(&old_terminal,false).is_ok());
        let mut rollback=record.clone(); rollback.stage=Stage::RollbackFinished;
        rollback.session_sha256=None; rollback.was_serving=true;
        validate_record(&rollback,&root)?;
        let mut rollback_terminal=rollback.clone(); rollback_terminal.stage=Stage::RollbackHandedOff;
        rollback_terminal.final_actor=Some(successor.clone());
        validate_record(&rollback_terminal,&root)?;
        validate_transition(&rollback,&rollback_terminal)?;
        assert!(require_startable(rollback.stage).is_err());
        let mut premature_rollback=rollback.clone(); premature_rollback.final_actor=Some(successor.clone());
        assert!(validate_record(&premature_rollback,&root).is_err());
        let mut foreign_rollback=rollback_terminal.clone(); foreign_rollback.operation_id=uuid::Uuid::new_v4().to_string();
        assert!(validate_transition(&rollback,&foreign_rollback).is_err());
        let mut terminal=record.clone();
        terminal.stage=Stage::HandedOff; terminal.final_actor=Some(successor);
        validate_transition(&record,&terminal)?;
        assert!(completed_actor_for_host(&terminal,false).is_err());
        assert!(completed_actor_for_host(&terminal,true).is_ok());
        let mut changed_terminal=terminal.clone();
        changed_terminal.final_actor.as_mut().context("synthetic successor missing")?.instance_id="foreign".into();
        assert!(validate_transition(&terminal,&changed_terminal).is_err());
        let mut changed_source=terminal.clone();
        changed_source.operation_id=uuid::Uuid::new_v4().to_string();
        assert!(validate_transition(&record,&changed_source).is_err());
        assert!(remove_finished(&record,digest.as_deref().context("synthetic journal digest missing")?).is_err());
        record.stage=Stage::HandedOff; save(&record,&mut digest)?;
        assert!(remove_finished(&record,"wrong-digest").is_err());
        assert!(path(&root).exists());
        remove_finished(&record,digest.as_deref().context("synthetic journal digest missing")?)?;
        assert!(!path(&root).exists());
        Ok(())
    }
    #[test]
    fn completed_actor_never_accepts_recovery_secret() {
        let value=serde_json::json!({"schema_version":1,"operation_id":uuid::Uuid::new_v4().to_string(),
            "session_sha256":"a".repeat(64),"path":"/synthetic/session.json","runtime":{
                "pid":12,"process_start_id":"synthetic","instance_id":"synthetic","generation":1,
                "image_path":"/synthetic/runtime","image_sha256":"a".repeat(64),
                "installation_root":"/synthetic","installation_id":"synthetic","profile":"/synthetic","account_id":"synthetic"},
            "super_password":"synthetic-only"});
        let mut actor = value["runtime"].clone();
        actor["super_password"] = serde_json::json!("synthetic-only");
        assert!(serde_json::from_value::<RuntimeIdentity>(actor).is_err());
    }
    fn fixture_actor(record: &Original) -> RuntimeIdentity {
        RuntimeIdentity { pid: 42, process_start_id: "fixture-birth".into(),
            instance_id: "fixture-instance".into(), generation: 1,
            image_path: record.binary.display().to_string(), image_sha256: record.image_sha256.clone(),
            installation_root: record.root.display().to_string(), installation_id: "fixture-root".into(),
            profile: record.profile.display().to_string(), account_id: "fixture-account".into() }
    }

    #[test]
    fn existing_result_never_turns_unknown_or_foreign_evidence_into_start() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().canonicalize()?;
        let mut record = original(&root);
        record.stage = Stage::Sent;
        let session = "c".repeat(64);
        let identity = HostAuthIdentity::Unbound {
            operation_id: record.operation_id.clone(), session_sha256: session.clone(),
        };
        let mut receipt = HostAuthResult { operation_id: record.operation_id.clone(),
            outcome: HostAuthOutcome::Committed, session_sha256: Some(session.clone()),
            path: root.join("session.json"), super_password: Some("synthetic-private-pipe-only".into()) };
        assert_eq!(committed_start_session(&record, &receipt, &identity)?, session);
        for outcome in [HostAuthOutcome::Unknown, HostAuthOutcome::RolledBack] {
            receipt.outcome = outcome;
            assert!(committed_start_session(&record, &receipt, &identity).is_err());
        }
        receipt.outcome = HostAuthOutcome::Committed;
        receipt.operation_id = uuid::Uuid::new_v4().to_string();
        assert!(committed_start_session(&record, &receipt, &identity).is_err());
        receipt.operation_id = record.operation_id.clone();
        receipt.path = root.join("other/session.json");
        assert!(committed_start_session(&record, &receipt, &identity).is_err());
        receipt.path = root.join("session.json");
        receipt.session_sha256 = None;
        assert!(committed_start_session(&record, &receipt, &identity).is_err());
        receipt.session_sha256 = Some("d".repeat(64));
        assert!(committed_start_session(&record, &receipt, &identity).is_err());
        receipt.session_sha256 = Some(session);
        assert!(committed_start_session(&record, &receipt, &HostAuthIdentity::Absent).is_err());
        record.session_sha256 = Some("e".repeat(64));
        assert!(committed_start_session(&record, &receipt, &identity).is_err());
        record.session_sha256 = None;
        for stage in [Stage::Starting, Stage::Verified, Stage::Finished, Stage::HandedOff] {
            record.stage = stage;
            assert!(committed_start_session(&record, &receipt, &identity).is_err());
        }
        Ok(())
    }

    #[test]
    fn local_completion_rejects_every_changed_actor_before_and_after_finish() -> Result<()> {
        use std::cell::Cell;
        let temp = tempfile::tempdir()?;
        let actor = fixture_actor(&original(&temp.path().canonicalize()?));
        let wire = serde_json::to_value(&actor)?;
        for (field, changed) in [
            ("pid", serde_json::json!(43)), ("process_start_id", serde_json::json!("other-birth")),
            ("instance_id", serde_json::json!("other-instance")), ("generation", serde_json::json!(2)),
            ("image_path", serde_json::json!("other-image")), ("image_sha256", serde_json::json!("f".repeat(64))),
            ("installation_root", serde_json::json!("other-root")), ("installation_id", serde_json::json!("other-root-id")),
            ("profile", serde_json::json!("other-profile")), ("account_id", serde_json::json!("other-account")),
        ] {
            let mut changed_wire = wire.clone(); changed_wire[field] = changed;
            let foreign: RuntimeIdentity = serde_json::from_value(changed_wire)?;
            for after_finish in [false, true] {
                let finished = Cell::new(false);
                let result = finish_checked(&actor, || {
                    Ok(if finished.get() || !after_finish { foreign.clone() } else { actor.clone() })
                }, || { finished.set(true); Ok(()) });
                assert!(result.is_err(), "changed {field} accepted");
                assert_eq!(finished.get(), after_finish, "changed actor advanced maintenance");
            }
        }
        Ok(())
    }

    #[test]
    fn local_completion_errors_are_not_success_and_never_retry_finish() -> Result<()> {
        use std::cell::Cell;
        let temp = tempfile::tempdir()?;
        let actor = fixture_actor(&original(&temp.path().canonicalize()?));
        for after_finish in [false, true] {
            let finishes = Cell::new(0);
            let result = finish_checked(&actor, || {
                if !after_finish || finishes.get() > 0 {
                    anyhow::bail!("synthetic dead process, changed session or unreadable original");
                }
                Ok(actor.clone())
            }, || { finishes.set(finishes.get() + 1); Ok(()) });
            assert!(result.is_err());
            assert_eq!(finishes.get(), usize::from(after_finish));
        }
        let observations = Cell::new(0);
        let finishes = Cell::new(0);
        assert!(finish_checked(&actor, || {
            observations.set(observations.get() + 1); Ok(actor.clone())
        }, || {
            finishes.set(finishes.get() + 1);
            anyhow::bail!("synthetic marker durability failure");
        }).is_err());
        assert_eq!(observations.get(), 1);
        assert_eq!(finishes.get(), 1);
        finish_checked(&actor, || { observations.set(observations.get() + 1); Ok(actor.clone()) }, || Ok(()))?;
        assert_eq!(observations.get(), 3);
        Ok(())
    }

    #[test]
    fn existing_auth_result_cannot_claim_a_finished_handoff() -> Result<()> {
        let wire = serde_json::json!({"operation_id": uuid::Uuid::new_v4().to_string(),
            "outcome": "finished", "session_sha256": "a".repeat(64),
            "path": "/fixture/session.json"});
        assert!(serde_json::from_value::<HostAuthResult>(wire).is_err());
        Ok(())
    }

    #[test]
    fn post_finish_failure_retains_verified_original_without_replay_or_cleanup() -> Result<()> {
        use std::cell::Cell;
        let temp = tempfile::tempdir()?; let root = temp.path().canonicalize()?;
        let mut record = original(&root); let mut digest = None;
        save(&record, &mut digest)?;
        record.stage = Stage::Sent; save(&record, &mut digest)?;
        record.session_sha256 = Some("c".repeat(64)); record.stage = Stage::Starting;
        save(&record, &mut digest)?;
        let actor = fixture_actor(&record);
        record.actor = Some(actor.clone()); record.stage = Stage::Verified;
        save(&record, &mut digest)?;
        let before = std::fs::read(path(&root))?;
        let finished = Cell::new(false);
        assert!(finish_checked(&actor, || {
            let (durable, _) = load(&root)?.context("fixture original missing")?;
            anyhow::ensure!(serde_json::to_value(&durable)? == serde_json::to_value(&record)?,
                "fixture original changed");
            anyhow::ensure!(!finished.get(), "synthetic actor exited after marker removal");
            Ok(actor.clone())
        }, || { finished.set(true); Ok(()) }).is_err());
        assert!(finished.get());
        assert_eq!(std::fs::read(path(&root))?, before);
        let (durable, observed) = load(&root)?.context("fixture original lost")?;
        assert!(durable.stage == Stage::Verified);
        assert!(require_startable(durable.stage).is_err());
        assert!(remove_finished(&durable, &observed).is_err());
        assert!(path(&root).is_file());
        Ok(())
    }

}
