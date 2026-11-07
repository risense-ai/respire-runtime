//! One space write; reconnects query its original Runtime journal admission.
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use respire_commands::output::{Item, ResultEnvelope, Status};
use respire_protocol::space_control::*;
use respire_protocol::{HostAuthIdentity, RpcRequest, RpcResponse};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Original {
    schema_version: u32,
    root: PathBuf,
    profile: PathBuf,
    operation_id: String,
    key: String,
    source_identity: HostAuthIdentity,
    operation: HostSpaceOperation,
    token: String,
    coordinator: String,
    was_serving: bool,
    store_ready: bool,
    sent: bool,
}

pub(crate) struct SpaceRecoveryRequired {
    pub operation_id: String,
    pub key: String,
    pub profile: PathBuf,
    pub operation: HostSpaceOperation,
    pub query_only: bool,
}
impl std::fmt::Debug for SpaceRecoveryRequired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { std::fmt::Display::fmt(self, f) }
}
impl std::fmt::Display for SpaceRecoveryRequired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "space_recovery_required operation_id={}; repeat the same space invite/join/kick command to query this operation; never replay the write", self.operation_id)
    }
}
impl std::error::Error for SpaceRecoveryRequired {}

impl Original {
    fn fingerprint(&self) -> Result<String> {
        Ok(super::hash(&serde_json::to_vec(&json!({"schema_version":HOST_SPACE_SCHEMA_V,
            "method":"control.space", "root":self.root, "profile":self.profile,
            "source_identity":self.source_identity, "operation":self.operation}))?))
    }
    fn recovery(&self) -> SpaceRecoveryRequired {
        SpaceRecoveryRequired { operation_id: self.operation_id.clone(), key: self.key.clone(),
            profile: self.profile.clone(), operation: self.operation.clone(), query_only: self.sent }
    }
}

fn read_original(path: &Path) -> Result<Option<(Original, String)>> {
    for ancestor in path.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                anyhow::ensure!(!metadata.file_type().is_symlink(), "identity recovery path is a symlink");
                #[cfg(windows)] {
                    use std::os::windows::fs::MetadataExt;
                    anyhow::ensure!(metadata.file_attributes() & 0x400 == 0, "identity recovery path is a reparse point");
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(metadata.is_file() && metadata.len() <= 16 * 1024, "identity recovery context is not a bounded file");
    let mut bytes = Vec::new();
    std::fs::File::open(path)?.take(16 * 1024 + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 16 * 1024, "identity recovery context exceeds its bound");
    let original = serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid identity recovery context"))?;
    Ok(Some((original, super::hash(&bytes))))
}

fn control_write(operation: HostSpaceOperation, invite_code: Option<&str>) -> Result<HostSpaceResult> {
    crate::runtime_policy::require_host("private space write")?;
    respire_client_host::settings::ensure_writable()?;
    anyhow::ensure!(super::lifecycle::current_boot_token().is_none(), "space write must own host maintenance");
    let takeover = crate::runtime_policy::takeover_lock()?;
    let (binary, manifest) = super::model_control::installed_model_runtime()?;
    let (root, profile) = respire_client_host::config::control_roots()?;
    std::fs::create_dir_all(&root)?;
    std::fs::create_dir_all(&profile)?;
    let root = root.canonicalize()?;
    let profile = profile.canonicalize()?;
    let path = root.join("runtime/autostart/space-write.json");
    let saved = read_original(&path)?;
    if saved.is_none() && matches!(&operation, HostSpaceOperation::Join { .. }) {
        // A retained operation may already own the target; only preflight new joins.
        respire::space::validate_join(invite_code.context("join invite input missing")?)?;
    }
    let expected = super::control::identity(&profile)?;
    let registration = super::read_registration(&root)?;
    let managed = registration.as_ref().filter(|config| config.enabled && !config.manually_stopped);
    let owner = crate::rpc::probe_runtime()?;
    anyhow::ensure!(owner.is_some() || !crate::rpc::endpoint_path().try_exists()?,
        "space write has a recorded owner without a verifiable drain identity");
    if let Some(config) = managed {
        super::lifecycle::owned(config)?;
        super::lifecycle::ensure_control_endpoint(config)?;
        anyhow::ensure!(owner.is_some() || !super::super::super::manager::inspect(config)?.running,
            "space write cannot identify the registered supervisor's owner");
    }
    if let Some(owner) = owner.as_ref() {
        super::model_control::verify_model_owner(owner, &root, &profile, managed, &binary, &manifest,
            Some(&account(&expected, &profile)))?;
    }
    let (mut original, mut digest, mut maintenance) = if let Some((original, digest)) = saved {
        let canonical = |value: &str| uuid::Uuid::parse_str(value)
            .is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == value);
        anyhow::ensure!(original.schema_version == HOST_SPACE_SCHEMA_V
            && canonical(&original.operation_id) && original.key == original.operation_id && canonical(&original.token),
            "invalid space recovery operation binding");
        if original.root != root || original.profile != profile || original.operation != operation {
            return Err(anyhow::anyhow!("another space operation owns recovery; do not replace its operation or source identity")
                .context(original.recovery()));
        }
        let maintenance = super::lifecycle::resume_identity_write_maintenance(&root, &profile,
            &original.token, &original.coordinator)?;
        (original, Some(digest), maintenance)
    } else {
        let mut maintenance = super::lifecycle::begin_maintenance_locked()?;
        let binding = maintenance.auth_launch_binding(&profile)?.context("space write requires persistent Paused maintenance")?;
        let id = uuid::Uuid::new_v4().to_string();
        let original = Original { schema_version: HOST_SPACE_SCHEMA_V, root: root.clone(), profile: profile.clone(),
            operation_id: id.clone(), key: id, source_identity: expected, operation,
            token: super::lifecycle::current_boot_token().context("identity maintenance token missing")?,
            coordinator: binding["coordinator_id"].as_str().context("identity coordinator missing")?.to_owned(),
            was_serving: owner.is_some(), store_ready: owner.as_ref().is_some_and(|owner| owner.store_ready), sent: false };
        let bytes = serde_json::to_vec(&original)?;
        super::private_write(&path, &bytes, None)?;
        (original, Some(super::hash(&bytes)), maintenance)
    };
    let mut finished = false;
    let result: Result<HostSpaceResult> = (|| {
        maintenance.check_account_runtime()?;
        if let Some(owner) = owner.as_ref() { maintenance.drain_runtime(owner)?; }
        anyhow::ensure!(!crate::net_rpc::port_is_open(), "space write requires the serving Runtime to be drained");
        let query_only = original.sent;
        if !query_only {
            anyhow::ensure!(super::control::identity(&profile)? == original.source_identity,
                "identity source changed before sending the operation");
            original.sent = true;
            let bytes = serde_json::to_vec(&original)?;
            if let Err(error) = super::private_write(&path, &bytes, digest.as_deref()) {
                // Publication can fail after replacement; recover from the actual durable state.
                if let Ok(Some((saved, _))) = read_original(&path) {
                    original.sent = saved.sent;
                }
                return Err(error);
            }
            digest = Some(super::hash(&bytes));
        }
        let mut received = None;
        for attempt in 0..2 {
        let query = query_only && attempt == 0;
        let envelope = super::control::auth_exchange(&takeover, &mut maintenance,
            Instant::now() + Duration::from_secs(180), None,
            |binding, identity| {
                anyhow::ensure!(binding.installation_root == original.root && binding.profile == original.profile,
                    "space write launch selection changed");
                let params = HostSpaceParams { schema_version: HOST_SPACE_SCHEMA_V, binding, identity,
                    source_identity: original.source_identity.clone(), operation: original.operation.clone(), invite_code: invite_code.map(str::to_owned) };
                let method = if query { HOST_SPACE_RESULT_METHOD } else { match &original.operation {
                    HostSpaceOperation::Invite { .. } => HOST_SPACE_INVITE_METHOD,
                    HostSpaceOperation::Join { .. } => HOST_SPACE_JOIN_METHOD, HostSpaceOperation::Kick { .. } => HOST_SPACE_KICK_METHOD,
                }};
                Ok(RpcRequest { v: respire_commands::rpc_client::PROTOCOL_V, id: uuid::Uuid::new_v4().to_string(),
                    method: method.to_owned(), args: vec![serde_json::to_string(&params)?], scope: None,
                    operation_id: Some(original.operation_id.clone()), idempotency_key: Some(original.key.clone()),
                    parent_operation_id: None, queue_wait_ms: None, lifecycle: None })
            }, |response, request, profile, pid| validate_response(response, request, profile, pid, &original), |error| error)?;
        let receipt: HostSpaceResult = serde_json::from_value(envelope.summary)
            .map_err(|_| anyhow::anyhow!("invalid space write receipt"))?;
        // Only a durable pre-POST Pending receipt permits this original O to continue.
        // Unknown never reaches this continuation, and no replacement O is generated.
        if query && receipt.outcome == HostSpaceOutcome::Pending { continue; }
        received = Some(receipt);
        break;
        }
        let receipt = received.context("space continuation did not return a receipt")?;
        if !matches!(receipt.outcome,HostSpaceOutcome::Committed | HostSpaceOutcome::Rejected) {
            maintenance.mark(super::lifecycle::Phase::Paused)?;
            return Ok(receipt);
        }
        match receipt.outcome {
            HostSpaceOutcome::Committed | HostSpaceOutcome::Rejected => {}
            HostSpaceOutcome::Pending => anyhow::bail!("space write pending; query the original operation"),
            HostSpaceOutcome::Unknown => anyhow::bail!("space write outcome unknown; query the original operation"),
        }
        unchanged(&original, &receipt.identity, &binary, &manifest)?;
        if original.was_serving {
            maintenance.start_account_runtime()?;
            let restored = crate::rpc::probe_runtime()?.context("identity owner did not resume")?;
            super::model_control::verify_model_owner(&restored, &root, &profile, managed, &binary, &manifest,
                Some(&account(&receipt.identity, &profile)))?;
            anyhow::ensure!(!original.store_ready || restored.store_ready, "identity owner store readiness was not restored");
        }
        unchanged(&original, &receipt.identity, &binary, &manifest)?;
        maintenance.finish()?;
        finished = true;
        anyhow::ensure!(read_original(&path)?.as_ref().map(|(_, hash)| hash.as_str()) == digest.as_deref(),
            "space recovery context changed before cleanup");
        std::fs::remove_file(&path)?;
        if respire_spawn::durable::sync_directory(path.parent().context("identity context parent missing")?).is_err() {
            eprintln!("Space operation committed; recovery namespace cleanup needs a later check.");
        }
        Ok(receipt)
    })();
    result.map_err(|error| {
        let error = if finished {
            error.context("space operation committed and maintenance finished; recovery context cleanup failed")
        } else {
            let pause = maintenance.mark(super::lifecycle::Phase::Paused);
            error.context(format!("space operation retained; Paused publication: {pause:?}"))
        };
        error.context(original.recovery())
    })
}

fn account(identity: &HostAuthIdentity, profile: &Path) -> String {
    match identity { HostAuthIdentity::Bound { account_id, .. } => account_id.clone(),
        _ => super::hash(profile.display().to_string().as_bytes()) }
}

fn unchanged(original: &Original, expected: &HostAuthIdentity, binary: &Path,
    manifest: &crate::runtime_fetch::ManagedManifest) -> Result<()> {
    let (root, profile) = respire_client_host::config::control_roots()?;
    let (current, release) = super::model_control::installed_model_runtime()?;
    anyhow::ensure!(root.canonicalize()? == original.root && profile.canonicalize()? == original.profile
        && current == binary && release.version == manifest.version && release.sha256.eq_ignore_ascii_case(&manifest.sha256)
        && super::control::identity(&original.profile)? == *expected,
        "space write installation, profile, image or resulting identity changed");
    Ok(())
}

fn validate_response(response: RpcResponse<ResultEnvelope>, request: &RpcRequest, profile: &Path,
    pid: u32, original: &Original) -> Result<ResultEnvelope> {
    anyhow::ensure!(response.v == request.v && response.id == request.id && response.pid == Some(pid)
        && response.bin == "rsrs-runtime" && response.scope.is_none() && response.web_url.is_none()
        && response.operation_id.as_deref() == Some(original.operation_id.as_str())
        && response.idempotency_key.as_deref() == Some(original.key.as_str()), "space response binding mismatch");
    if let Some(path) = response.data_dir.as_deref() { anyhow::ensure!(Path::new(path).canonicalize()? == profile, "space response profile mismatch"); }
    if response.error.is_some() {
        let code = match response.code.as_deref() {
            Some("unauthorized") => "unauthorized",
            Some("scope_mismatch") => "scope_mismatch",
            Some("auth_ownership_unavailable") => "auth_ownership_unavailable",
            Some("control_unavailable") => "control_unavailable",
            Some("space_outcome_unknown") => "space_outcome_unknown",
            Some("control_outcome_unknown") => "control_outcome_unknown",
            _ => anyhow::bail!("invalid space control rejection code"),
        };
        let deadline = code == "control_outcome_unknown";
        let envelope = response.envelope.as_ref().context("space control rejection envelope missing")?;
        anyhow::ensure!(!response.ok && response.exit == 2
            && response.error.as_deref().is_some_and(|error| !error.is_empty())
            && envelope.command == "space-control" && matches!(envelope.status, Status::Fail)
            && envelope.details.is_null() && envelope.actions.is_empty() && envelope.related.is_empty()
            && envelope.items.len() == 2
            && envelope.items[0].name == "control_ready"
            && envelope.items[0].value == (if deadline { "unknown" } else { "false" })
            && (if deadline { matches!(envelope.items[0].status, Status::Skip) }
                else { matches!(envelope.items[0].status, Status::Fail) })
            && envelope.items[1].name == "store_ready" && envelope.items[1].value == "false"
            && matches!(envelope.items[1].status, Status::Skip)
            && (if deadline { envelope.summary == json!({"outcome":"unknown"}) && envelope.errors.is_empty() }
                else { envelope.summary == json!({}) && envelope.errors.len() == 1
                    && response.error.as_ref() == envelope.errors.first() }),
            "invalid space control rejection envelope");
        // Keep the original operation Paused; never echo a possibly secret diagnostic.
        anyhow::bail!("Runtime rejected space control ({code}); query the original operation without replaying");
    }
    let envelope = response.envelope.context("space receipt missing")?;
    anyhow::ensure!(envelope.command == "space-control" && envelope.details.is_null() && envelope.errors.is_empty(), "invalid space envelope");
    for (name,value) in [("control_ready","true"),("store_ready","false")] {
        let mut items = envelope.items.iter().filter(|item| item.name == name);
        anyhow::ensure!(items.next().is_some_and(|item| item.value == value && if name == "control_ready" {
            matches!(item.status,Status::Ok) } else { matches!(item.status,Status::Skip) }) && items.next().is_none(), "space readiness mismatch");
    }
    let receipt: HostSpaceResult = serde_json::from_value(envelope.summary.clone()).map_err(|_| anyhow::anyhow!("invalid space receipt"))?;
    anyhow::ensure!(receipt.operation_id == original.operation_id && receipt.fingerprint == original.fingerprint()?
        && receipt.operation == original.operation && receipt.profile == profile && receipt.identity == original.source_identity
        && super::control::identity(profile)? == receipt.identity, "space receipt differs from its original identity or intent");
    match receipt.outcome {
        HostSpaceOutcome::Committed => anyhow::ensure!(response.ok && response.exit == 0 && response.code.is_none()
            && response.error.is_none() && matches!(envelope.status,Status::Ok), "invalid committed space outcome"),
        HostSpaceOutcome::Pending => anyhow::ensure!(response.ok && response.exit == 0 && response.code.is_none()
            && response.error.is_none() && matches!(envelope.status,Status::Pending), "invalid pending space outcome"),
        HostSpaceOutcome::Unknown => anyhow::ensure!(!response.ok && response.exit == 2
            && response.code.as_deref() == Some("space_outcome_unknown") && matches!(envelope.status,Status::Fail), "invalid unknown space outcome"),
        HostSpaceOutcome::Rejected => anyhow::ensure!(!response.ok && response.exit == 2
            && response.code.as_deref() == Some("space_rejected") && response.error.is_none()
            && matches!(envelope.status,Status::Fail), "invalid rejected space outcome"),
    }
    if receipt.outcome == HostSpaceOutcome::Rejected {
        anyhow::ensure!(receipt.invite_code.is_none() && receipt.session_id.is_none() && receipt.target_profile.is_none()
            && receipt.target_account_id.is_none() && receipt.target_session_sha256.is_none()
            && receipt.kick.is_empty() && receipt.remaining.is_none(), "rejected space receipt claims effects");
        return Ok(envelope);
    }
    match &original.operation {
        HostSpaceOperation::Join { space,user,readonly, .. } => {
            let target = original.root.join("accounts").join(space);
            anyhow::ensure!(receipt.target_profile.as_deref() == Some(target.as_path()) && receipt.invite_code.is_none()
                && receipt.session_id.is_none() && receipt.kick.is_empty() && receipt.remaining.is_none(), "join target receipt mismatch");
            if receipt.outcome == HostSpaceOutcome::Committed {
                anyhow::ensure!(receipt.target_account_id.as_deref() == Some(super::hash(user.as_bytes()).as_str()), "join account receipt mismatch");
                verify_target_path(&target)?;
                let bytes = std::fs::read(target.join("session.json"))?;
                anyhow::ensure!(receipt.target_session_sha256.as_deref() == Some(super::hash(&bytes).as_str()), "join session digest mismatch");
                // Host checks only the gate bytes and identity digest, never unwraps keys.
                let gate = target.join("agent.json");
                if *readonly { anyhow::ensure!(std::fs::read(gate)? == br#"{"readonly":true,"readonly_team":true}"#, "join readonly_team gate mismatch"); }
                else { anyhow::ensure!(!gate.try_exists()?, "join unexpectedly changed the agent gate"); }
            } else {
                anyhow::ensure!(receipt.target_account_id.is_none() && receipt.target_session_sha256.is_none(), "pending join claims completion");
            }
        }
        HostSpaceOperation::Invite { readonly, .. } => {
            anyhow::ensure!(receipt.target_profile.is_none() && receipt.target_account_id.is_none()
                && receipt.target_session_sha256.is_none() && receipt.kick.is_empty(), "invite receipt contains unrelated effects");
            if receipt.outcome == HostSpaceOutcome::Committed {
                let code = receipt.invite_code.as_deref().context("committed invite code missing")?;
                let value = respire::space::parse_invite(code)?;
                anyhow::ensure!(value["readonly"].as_bool() == Some(*readonly)
                    && value["session_id"].as_str() == receipt.session_id.as_deref()
                    && value["control_operation_id"].as_str() == Some(original.operation_id.as_str())
                    && value["control_fingerprint"].as_str() == Some(receipt.fingerprint.as_str()), "invite result binding mismatch");
                let user = value["user"].as_str().context("invite owner missing")?;
                anyhow::ensure!(matches!(&original.source_identity,HostAuthIdentity::Bound { account_id, .. }
                    if *account_id == super::hash(user.as_bytes())), "invite owner differs from the admitted source");
            } else { anyhow::ensure!(receipt.invite_code.is_none(), "pending invite exposed an uncommitted code"); }
        }
        HostSpaceOperation::Kick { session_id,all } => {
            anyhow::ensure!(receipt.invite_code.is_none() && receipt.session_id.is_none() && receipt.target_profile.is_none()
                && receipt.target_account_id.is_none() && receipt.target_session_sha256.is_none(), "kick receipt contains unrelated effects");
            let mut seen = std::collections::HashSet::new();
            for item in &receipt.kick {
                uuid::Uuid::parse_str(&item.session_id)?;
                anyhow::ensure!(seen.insert(&item.session_id) && (*all || session_id.as_deref() == Some(item.session_id.as_str())), "kick result target mismatch");
            }
            if receipt.outcome == HostSpaceOutcome::Committed {
                anyhow::ensure!(!receipt.kick.is_empty() && receipt.remaining.is_some() && receipt.kick.iter().all(|item|
                    matches!(item.state,HostSpaceKickState::Revoked | HostSpaceKickState::Absent | HostSpaceKickState::Rejected)), "committed kick has unresolved members");
            }
        }
    }
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PID: u32 = 5252;
    const DIAGNOSTIC: &str = "synthetic-private-space-diagnostic";

    struct Fixture {
        _directory: tempfile::TempDir,
        original: Original,
        request: RpcRequest,
        response: serde_json::Value,
    }

    impl Fixture {
        fn new() -> Result<Self> {
            let directory = tempfile::tempdir()?;
            let root = directory.path().canonicalize()?;
            let operation_id = uuid::Uuid::new_v4().to_string();
            let original = Original { schema_version: HOST_SPACE_SCHEMA_V, root: root.clone(), profile: root.clone(),
                operation_id: operation_id.clone(), key: operation_id.clone(), source_identity: HostAuthIdentity::Absent,
                operation: HostSpaceOperation::Kick { session_id: None, all: true }, token: "fixture-maintenance".into(),
                coordinator: uuid::Uuid::new_v4().to_string(), was_serving: false, store_ready: false, sent: true };
            let receipt = HostSpaceResult { operation_id: operation_id.clone(), fingerprint: original.fingerprint()?,
                profile: root.clone(), identity: original.source_identity.clone(), operation: original.operation.clone(),
                outcome: HostSpaceOutcome::Committed, invite_code: None, session_id: None, target_profile: None,
                target_account_id: None, target_session_sha256: None,
                kick: vec![HostSpaceKickItem { session_id: uuid::Uuid::new_v4().to_string(), state: HostSpaceKickState::Revoked }],
                remaining: Some(0) };
            let request: RpcRequest = serde_json::from_value(json!({"v":1,"id":uuid::Uuid::new_v4().to_string(),
                "method":HOST_SPACE_KICK_METHOD,"args":[],"operation_id":operation_id,"idempotency_key":operation_id}))?;
            let response = json!({"v":request.v,"id":request.id,"pid":PID,"bin":"rsrs-runtime",
                "operation_id":original.operation_id,"idempotency_key":original.key,"scope":null,"web_url":null,
                "data_dir":root,"ok":true,"exit":0,"code":null,"error":null,
                "envelope":ResultEnvelope::new("space-control",Status::Ok,serde_json::to_value(receipt)?,vec![
                    Item::new("control_ready",Status::Ok,"true"),Item::new("store_ready",Status::Skip,"false")])});
            Ok(Self { _directory: directory, original, request, response })
        }

        fn validate(&self, response: serde_json::Value) -> Result<ResultEnvelope> {
            validate_response(serde_json::from_value(response)?, &self.request, &self.original.profile, PID, &self.original)
        }

        fn rejection(&self, code: &str) -> serde_json::Value {
            let mut response = self.response.clone();
            response["ok"] = json!(false);
            response["exit"] = json!(2);
            response["code"] = json!(code);
            response["error"] = json!(DIAGNOSTIC);
            let deadline = code == "control_outcome_unknown";
            response["envelope"] = json!({"command":"space-control","status":"fail",
                "summary":if deadline { json!({"outcome":"unknown"}) } else { json!({}) },
                "details":null,"actions":[],"related":[],"errors":if deadline { json!([]) } else { json!([DIAGNOSTIC]) },
                "items":[Item::new("control_ready",if deadline { Status::Skip } else { Status::Fail },
                    if deadline { "unknown" } else { "false" }),Item::new("store_ready",Status::Skip,"false")]});
            response
        }

        fn reject_malformed(&self, response: serde_json::Value) -> Result<()> {
            let error = self.validate(response).err().context("malformed space response was accepted")?.to_string();
            assert!(!error.contains("Runtime rejected space control"), "malformed response was classified: {error}");
            assert!(!error.contains(DIAGNOSTIC));
            Ok(())
        }
    }

    #[test]
    fn stable_rejections_preserve_codes_without_exposing_diagnostics() -> Result<()> {
        let fixture = Fixture::new()?;
        for code in ["unauthorized", "scope_mismatch", "auth_ownership_unavailable", "control_unavailable",
            "space_outcome_unknown", "control_outcome_unknown"] {
            let error = fixture.validate(fixture.rejection(code)).err().context("rejection was accepted")?.to_string();
            assert_eq!(error, format!("Runtime rejected space control ({code}); query the original operation without replaying"));
            assert!(!error.contains(DIAGNOSTIC));
        }
        Ok(())
    }

    #[test]
    fn rejections_require_the_original_request_owner_and_scope() -> Result<()> {
        let fixture = Fixture::new()?;
        for (pointer, value) in [
            ("/v", json!(fixture.request.v + 1)), ("/id", json!("foreign-request")),
            ("/pid", json!(PID + 1)), ("/bin", json!("foreign-image")),
            ("/operation_id", json!(uuid::Uuid::new_v4().to_string())), ("/idempotency_key", json!("foreign-key")),
            ("/scope", json!({"account_id":"foreign-account","instance_id":"foreign-instance","generation":1})),
            ("/web_url", json!("https://fixture.invalid")), ("/data_dir", json!(fixture.original.profile.parent())),
        ] {
            let mut response = fixture.rejection("unauthorized");
            *response.pointer_mut(pointer).context("fixture binding field missing")? = value;
            fixture.reject_malformed(response).with_context(|| format!("binding field {pointer}"))?;
        }
        Ok(())
    }

    #[test]
    fn rejections_reject_unknown_codes_and_malformed_envelopes() -> Result<()> {
        let fixture = Fixture::new()?;
        for code in ["unauthorized", "control_outcome_unknown"] {
            for (pointer, value) in [
                ("/code", json!("unrecognized-private-code")), ("/ok", json!(true)), ("/exit", json!(0)),
                ("/error", json!(null)), ("/error", json!("")), ("/envelope", json!(null)),
                ("/envelope/command", json!("foreign-command")), ("/envelope/status", json!("ok")),
                ("/envelope/summary", json!({"outcome":"committed"})), ("/envelope/details", json!({})),
                ("/envelope/actions", json!(["untrusted-action"])),
                ("/envelope/related", json!([respire_protocol::RelatedMemory { id: "foreign-memory".into(),
                    title: "untrusted-related".into(), source_id: "foreign-source".into(),
                    relation: respire_protocol::RelationKind::SeeAlso }])),
                ("/envelope/errors", json!(["different-diagnostic"])), ("/envelope/items", json!([])),
                ("/envelope/items/0/name", json!("other-ready")), ("/envelope/items/0/value", json!("true")),
                ("/envelope/items/0/status", json!("ok")), ("/envelope/items/1/value", json!("true")),
                ("/envelope/items/1/status", json!("ok")),
            ] {
                let mut response = fixture.rejection(code);
                *response.pointer_mut(pointer).context("fixture envelope field missing")? = value;
                if pointer == "/envelope/related" {
                    let _: RpcResponse<ResultEnvelope> = serde_json::from_value(response.clone())?;
                }
                fixture.reject_malformed(response).with_context(|| format!("{code} field {pointer}"))?;
            }
            let mut response = fixture.rejection(code);
            let duplicate = response["envelope"]["items"][0].clone();
            response["envelope"]["items"].as_array_mut().context("fixture items missing")?.push(duplicate);
            fixture.reject_malformed(response)?;
        }
        Ok(())
    }

    #[test]
    fn typed_success_and_receipt_binding_remain_unchanged() -> Result<()> {
        let fixture = Fixture::new()?;
        let accepted = fixture.validate(fixture.response.clone())?;
        assert_eq!(serde_json::to_value(accepted)?, fixture.response["envelope"]);
        for (pointer, value) in [
            ("/envelope/summary/operation_id", json!(uuid::Uuid::new_v4().to_string())),
            ("/envelope/summary/fingerprint", json!("foreign-fingerprint")),
            ("/envelope/summary/identity", json!({"kind":"bound","account_id":"foreign-account","session_sha256":"foreign-session"})),
            ("/envelope/summary/profile", json!(fixture.original.profile.parent())),
            ("/envelope/summary/operation", json!({"kind":"kick","session_id":null,"all":false})),
            ("/envelope/summary/kick", json!([])), ("/envelope/summary/remaining", json!(null)),
            ("/envelope/summary/invite_code", json!("unrelated-secret")),
        ] {
            let mut response = fixture.response.clone();
            *response.pointer_mut(pointer).context("fixture receipt field missing")? = value;
            fixture.reject_malformed(response).with_context(|| format!("receipt field {pointer}"))?;
        }
        Ok(())
    }
}

fn verify_target_path(target: &Path) -> Result<()> {
    for path in target.join("session.json").ancestors() {
        let metadata = std::fs::symlink_metadata(path)?;
        anyhow::ensure!(!metadata.file_type().is_symlink(), "join target is a symlink");
        #[cfg(windows)] {
            use std::os::windows::fs::MetadataExt;
            anyhow::ensure!(metadata.file_attributes() & 0x400 == 0, "join target is a reparse point");
        }
    }
    let gate = target.join("agent.json");
    if gate.try_exists()? {
        let metadata = std::fs::symlink_metadata(gate)?;
        anyhow::ensure!(!metadata.file_type().is_symlink(), "join agent gate is a symlink");
        #[cfg(windows)] {
            use std::os::windows::fs::MetadataExt;
            anyhow::ensure!(metadata.file_attributes() & 0x400 == 0, "join agent gate is a reparse point");
        }
    }
    Ok(())
}

pub(crate) fn control_space_invite(note: Option<&str>, readonly: bool) -> Result<ResultEnvelope> {
    output(control_write(HostSpaceOperation::Invite { note: note.map(str::to_owned),readonly },None)?)
}

pub(crate) fn control_space_join(code: &str) -> Result<ResultEnvelope> {
    let value = respire::space::parse_invite(code)?;
    let space = value["space"].as_str().context("invite space missing")?.trim().to_owned();
    respire::space::validate_space_name(&space)?;
    let addr = value["addr"].as_str().context("invite address missing")?.trim().trim_end_matches('/').to_owned();
    let user = value["user"].as_str().context("invite user missing")?.trim().to_owned();
    let operation = HostSpaceOperation::Join { invite_sha256: super::hash(code.trim().as_bytes()),space,addr,user,
        readonly: value["readonly"].as_bool().unwrap_or(false) };
    output(control_write(operation,Some(code))?)
}

pub(crate) fn control_space_kick(session_id: Option<&str>, all: bool) -> Result<ResultEnvelope> {
    anyhow::ensure!(all || session_id.is_some_and(|id| !id.trim().is_empty()), "kick needs --session <id> or --all");
    output(control_write(HostSpaceOperation::Kick { session_id: session_id.map(|id| id.trim().to_owned()),all },None)?)
}

fn output(receipt: HostSpaceResult) -> Result<ResultEnvelope> {
    let complete = receipt.outcome == HostSpaceOutcome::Committed;
    let status = match receipt.outcome { HostSpaceOutcome::Committed => Status::Ok,
        HostSpaceOutcome::Pending => Status::Pending, HostSpaceOutcome::Unknown | HostSpaceOutcome::Rejected => Status::Fail };
    let mut envelope = ResultEnvelope::new("space",status,json!({"outcome":receipt.outcome,"operation_id":receipt.operation_id}),Vec::new());
    match &receipt.operation {
        HostSpaceOperation::Invite { readonly, .. } => {
            envelope.summary["action"] = json!("invite");
            envelope.details = json!({"session_id":receipt.session_id,"readonly":readonly,"code":receipt.invite_code});
            if let Some(code) = &receipt.invite_code {
                let value = respire::space::parse_invite(code)?;
                envelope.details["space"] = value["space"].clone();
                envelope.summary["space"] = value["space"].clone();
                envelope.items.push(Item::new("code",if *readonly { Status::Warn } else { Status::Ok },code));
                envelope.items.push(Item::new("session",Status::Ok,receipt.session_id.as_deref().unwrap_or("")));
                envelope.actions.push("space join <code>".to_owned());
                if *readonly { envelope.status = Status::Warn; }
            }
        }
        HostSpaceOperation::Join { space,addr,user,readonly, .. } => {
            envelope.summary["action"] = json!("join");
            envelope.summary["space"] = json!(space);
            envelope.details = json!({"space":space,"addr":addr,"user":user,"readonly":readonly,
                "dir":receipt.target_profile,"keyring":complete,"hint":if complete { Some(format!("space use {space}")) } else { None }});
            if complete {
                envelope.items.push(Item::new("space",if *readonly { Status::Warn } else { Status::Ok },space));
                envelope.actions.push(format!("space use {space}"));
                if *readonly { envelope.status = Status::Warn; }
            }
        }
        HostSpaceOperation::Kick { .. } => {
            let revoked: Vec<&str> = receipt.kick.iter().filter(|item| item.state == HostSpaceKickState::Revoked).map(|item| item.session_id.as_str()).collect();
            let failed: Vec<String> = receipt.kick.iter().filter(|item| item.state != HostSpaceKickState::Revoked).map(|item|
                format!("{} ({})",item.session_id,match item.state { HostSpaceKickState::Absent => "server has no such session",
                    HostSpaceKickState::Rejected => "rejected",HostSpaceKickState::Queued => "not sent",
                    _ => "outcome unknown; do not replay" })).collect();
            envelope.summary["action"] = json!("kick");
            envelope.summary["revoked"] = json!(revoked.len());
            envelope.summary["failed"] = json!(failed.len());
            envelope.summary["remaining"] = json!(receipt.remaining);
            for id in &revoked { envelope.items.push(Item::new("revoked",Status::Ok,*id)); }
            for error in &failed { envelope.items.push(Item::new("failed",Status::Warn,error)); }
            if complete && !failed.is_empty() { envelope.status = Status::Warn; }
            envelope.details = json!({"revoked":revoked,"failed":failed,"remaining":receipt.remaining,"items":receipt.kick});
        }
    }
    envelope.details["outcome"] = json!(receipt.outcome);
    envelope.details["operation_id"] = json!(receipt.operation_id);
    if receipt.outcome == HostSpaceOutcome::Rejected {
        envelope.details["error_type"] = json!("runtime");
        envelope.errors.push("space operation rejected; no change was committed".to_owned());
    }
    if !complete && receipt.outcome != HostSpaceOutcome::Rejected {
        envelope.actions.push("repeat exactly the same command to query the original operation; do not create a replacement".to_owned());
    }
    Ok(envelope)
}
