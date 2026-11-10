//! Bind a live handoff to the existing consumed launch claim, not just Health.
use super::*;
use respire_protocol::{HostControlLaunchGrant, HostControlMaintenanceBinding};
use serde_json::Value;

pub(super) struct Evidence {
    claim_path: PathBuf,
    claim_bytes: Vec<u8>,
    endpoint_path: PathBuf,
    endpoint_bytes: Vec<u8>,
    registration: Option<String>,
    root: PathBuf,
}

fn read_record(path: &Path) -> Result<Vec<u8>> {
    no_links(path)?;
    let file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    anyhow::ensure!(metadata.is_file() && metadata.len() <= 65536, "invalid keygen launch evidence");
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 65536, "keygen launch evidence exceeds 64 KiB");
    Ok(bytes)
}

impl Evidence {
    pub(super) fn capture(record: &Original, actor: &RuntimeIdentity,
        binding: &HostControlMaintenanceBinding,
    ) -> Result<Self> {
        anyhow::ensure!(canonical_id(&actor.instance_id), "keygen launch instance is not canonical");
        let claim_path = record.root.join("runtime/autostart/launch")
            .join(format!("launch-{}.claimed", actor.instance_id));
        let endpoint_path = crate::rpc::endpoint_path();
        let claim_bytes = read_record(&claim_path)?;
        let endpoint_bytes = read_record(&endpoint_path)?;
        let registration = validate(record, actor, binding, &claim_bytes, &endpoint_bytes)?;
        let proof = Self { claim_path, claim_bytes, endpoint_path, endpoint_bytes,
            registration, root: record.root.clone() };
        proof.verify()?;
        Ok(proof)
    }

    /// The Starting marker is intentionally gone after completion. Its original
    /// binding stays in the immutable consumed claim; only maintenance may clear.
    pub(super) fn verify(&self) -> Result<()> {
        anyhow::ensure!(read_record(&self.claim_path)? == self.claim_bytes
            && read_record(&self.endpoint_path)? == self.endpoint_bytes,
            "keygen consumed launch or endpoint changed");
        let current = crate::autostart::read_registration(&self.root)?;
        match (&self.registration, current) {
            (None, None) => Ok(()),
            (Some(original), Some(current)) => {
                crate::autostart::lifecycle::owned(&current)?;
                let recorded: crate::autostart::Registration = serde_json::from_str(original)?;
                verify_registration_transition(recorded, &current)?;
                Ok(())
            }
            _ => anyhow::bail!("keygen registration appeared or disappeared"),
        }
    }
}

fn verify_registration_transition(mut recorded: crate::autostart::Registration,
    current: &crate::autostart::Registration,
) -> Result<()> {
    anyhow::ensure!(recorded.maintenance || !current.maintenance,
        "keygen registration entered unrelated maintenance");
    recorded.maintenance = current.maintenance;
    anyhow::ensure!(serde_json::to_value(&recorded)? == serde_json::to_value(current)?,
        "keygen registration changed beyond maintenance completion");
    Ok(())
}

fn validate(record: &Original, actor: &RuntimeIdentity, binding: &HostControlMaintenanceBinding,
    claim_bytes: &[u8], endpoint_bytes: &[u8],
) -> Result<Option<String>> {
    let claim: Value = serde_json::from_slice(claim_bytes)?;
    let endpoint: Value = serde_json::from_slice(endpoint_bytes)?;
    let grant_json = claim["grant_json"].as_str().context("keygen consumed grant missing")?;
    let grant: HostControlLaunchGrant = serde_json::from_str(grant_json)?;
    let birth = claim["process_start_id"].as_str().filter(|value| !value.is_empty())
        .context("keygen claimant birth missing")?;
    let prefix = if cfg!(windows) { "windows-filetime-" }
        else if cfg!(target_os = "linux") { "linux-starttime-" } else { "darwin-lstart-" };
    anyhow::ensure!(claim["schema_version"] == 2 && claim["state"] == "consumed"
        && claim["protocol_version"] == crate::rpc::PROTOCOL_V
        && claim["grant_sha256"] == hash(grant_json.as_bytes())
        && claim["pid"] == actor.pid && actor.process_start_id == format!("{prefix}{birth}")
        && endpoint["schema_version"] == 2 && endpoint["server"] == "respire"
        && endpoint["v"] == crate::rpc::PROTOCOL_V
        && endpoint["launch_receipt_sha256"] == hash(claim_bytes)
        && endpoint.get("managed_id").is_some()
        && endpoint["managed_id"] == serde_json::to_value(&grant.managed_id)?,
        "keygen endpoint does not bind the consumed launch claimant");
    for (field, expected) in [
        ("pid", serde_json::json!(actor.pid)), ("process_start_id", serde_json::json!(actor.process_start_id)),
        ("instance_id", serde_json::json!(actor.instance_id)), ("generation", serde_json::json!(actor.generation)),
        ("image_path", serde_json::json!(actor.image_path)), ("image_sha256", serde_json::json!(actor.image_sha256)),
        ("installation_root", serde_json::json!(actor.installation_root)),
        ("installation_id", serde_json::json!(actor.installation_id)),
        ("data_dir", serde_json::json!(actor.profile)), ("account_id", serde_json::json!(actor.account_id)),
    ] {
        anyhow::ensure!(endpoint[field] == expected, "keygen endpoint differs from live actor");
    }
    anyhow::ensure!(grant.schema_version == 1 && grant.protocol_version == crate::rpc::PROTOCOL_V
        && grant.nonce == actor.instance_id && grant.instance_id == actor.instance_id
        && grant.installation_root == record.root && grant.profile == record.profile
        && grant.installation_id == actor.installation_id && grant.account_id == actor.account_id
        && grant.image_path == record.binary && grant.image_sha256.eq_ignore_ascii_case(&record.image_sha256)
        && grant.image_sha256.eq_ignore_ascii_case(&actor.image_sha256) && grant.port == crate::net_rpc::rpc_port()
        && grant.supervisor_pid > 0 && grant.supervisor_pid != actor.pid && !grant.supervisor_birth.is_empty()
        && grant.expires_at_ms > grant.issued_at_ms && grant.expires_at_ms - grant.issued_at_ms <= 60000
        && binding.coordinator_id == record.coordinator && binding.controller_pid == std::process::id()
        && serde_json::to_value(&grant.maintenance)? == serde_json::to_value(Some(binding))?,
        "keygen live actor was not launched by the original Starting controller");
    let registration = claim.get("registration_json").context("keygen launch registration missing")?;
    let registration: Option<String> = serde_json::from_value(registration.clone())?;
    anyhow::ensure!(grant.registration_sha256 == registration.as_deref().map(|value| hash(value.as_bytes()))
        && (registration.is_some() || grant.managed_id.is_none()),
        "keygen launch registration digest mismatch");
    Ok(registration)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture(root: &Path) -> Result<(Original, RuntimeIdentity, HostControlMaintenanceBinding, Value, Value)> {
        let record: Original = serde_json::from_value(json!({"schema":1,
            "operation_id":uuid::Uuid::new_v4().to_string(),"force":false,
            "root":root,"source":root,"profile":root,"binary":root.join("runtime-image"),
            "image_sha256":"a".repeat(64),"token":uuid::Uuid::new_v4().to_string(),
            "coordinator":"fixture-controller","marker_sha256":"b".repeat(64),
            "original_identity":{"kind":"absent"},"session_sha256":"c".repeat(64),
            "stage":"starting","actor":null,"was_serving":false,"store_ready":false}))?;
        let prefix = if cfg!(windows) { "windows-filetime-" }
            else if cfg!(target_os = "linux") { "linux-starttime-" } else { "darwin-lstart-" };
        let actor = RuntimeIdentity { pid:42, process_start_id:format!("{prefix}123"),
            instance_id:uuid::Uuid::new_v4().to_string(), generation:1,
            image_path:record.binary.display().to_string(),image_sha256:record.image_sha256.clone(),
            installation_root:root.display().to_string(),installation_id:hash(root.display().to_string().as_bytes()),
            profile:root.display().to_string(),account_id:hash(root.display().to_string().as_bytes()) };
        let binding = HostControlMaintenanceBinding {marker_sha256:"d".repeat(64),
            coordinator_id:record.coordinator.clone(),controller_pid:std::process::id(),
            controller_birth:"fixture-controller-birth".into(),issuer_cli_version:"fixture-version".into()};
        let grant = json!({"schema_version":1,"protocol_version":crate::rpc::PROTOCOL_V,
            "nonce":actor.instance_id,"instance_id":actor.instance_id,"installation_root":root,
            "installation_id":actor.installation_id,"profile":root,"account_id":actor.account_id,
            "sync_generation":0,"image_path":record.binary,"image_sha256":record.image_sha256,
            "supervisor_pid":std::process::id(),"supervisor_birth":"fixture-supervisor-birth",
            "managed_id":null,"registration_sha256":null,"maintenance":binding,
            "port":crate::net_rpc::rpc_port(),"issued_at_ms":1,"expires_at_ms":60001});
        let grant_json = serde_json::to_string(&grant)?;
        let claim = json!({"schema_version":2,"protocol_version":crate::rpc::PROTOCOL_V,"state":"consumed",
            "grant_sha256":hash(grant_json.as_bytes()),"grant_json":grant_json,"registration_json":null,
            "pid":actor.pid,"process_start_id":"123"});
        let endpoint = json!({"schema_version":2,"server":"respire","v":crate::rpc::PROTOCOL_V,
            "launch_receipt_sha256":hash(&serde_json::to_vec(&claim)?),"managed_id":null,
            "pid":actor.pid,"process_start_id":actor.process_start_id,"instance_id":actor.instance_id,
            "generation":actor.generation,"image_path":actor.image_path,"image_sha256":actor.image_sha256,
            "installation_root":actor.installation_root,"installation_id":actor.installation_id,
            "data_dir":actor.profile,"account_id":actor.account_id});
        Ok((record,actor,binding,claim,endpoint))
    }

    #[test]
    fn consumed_launch_rejects_foreign_controller_grant_and_endpoint() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let (record,actor,binding,claim,endpoint) = fixture(&temp.path().canonicalize()?)?;
        let check = |claim:&Value, endpoint:&Value| validate(&record,&actor,&binding,
            &serde_json::to_vec(claim)?,&serde_json::to_vec(endpoint)?);
        assert!(check(&claim,&endpoint)?.is_none());
        for pointer in ["/nonce","/instance_id","/installation_root","/profile","/account_id",
            "/image_path","/image_sha256","/installation_id","/registration_sha256",
            "/maintenance/coordinator_id","/maintenance/controller_pid","/maintenance/controller_birth",
            "/maintenance/marker_sha256","/maintenance/issuer_cli_version"] {
            let mut grant: Value = serde_json::from_str(claim["grant_json"].as_str().context("fixture grant missing")?)?;
            let slot = grant.pointer_mut(pointer).context("fixture grant field missing")?;
            *slot = if slot.is_number() { json!(0) } else { json!("foreign") };
            let mut changed = claim.clone();
            changed["grant_json"] = json!(serde_json::to_string(&grant)?);
            changed["grant_sha256"] = json!(hash(changed["grant_json"].as_str().context("fixture grant missing")?.as_bytes()));
            let mut linked = endpoint.clone();
            linked["launch_receipt_sha256"] = json!(hash(&serde_json::to_vec(&changed)?));
            assert!(check(&changed,&linked).is_err(), "foreign grant field {pointer} accepted");
        }
        for field in ["schema_version","protocol_version","state","grant_sha256","pid","process_start_id","registration_json"] {
            let mut changed = claim.clone(); changed[field] = json!("foreign");
            let mut linked = endpoint.clone(); linked["launch_receipt_sha256"] = json!(hash(&serde_json::to_vec(&changed)?));
            assert!(check(&changed,&linked).is_err(), "foreign claim field {field} accepted");
        }
        for field in ["schema_version","server","v","launch_receipt_sha256","managed_id","pid",
            "process_start_id","instance_id","generation","image_path","image_sha256",
            "installation_root","installation_id","data_dir","account_id"] {
            let mut changed = endpoint.clone(); changed[field] = json!("foreign");
            assert!(check(&claim,&changed).is_err(), "foreign endpoint field {field} accepted");
            changed.as_object_mut().context("fixture endpoint not object")?.remove(field);
            assert!(check(&claim,&changed).is_err(), "missing endpoint field {field} accepted");
        }
        Ok(())
    }

    #[test]
    fn retained_launch_evidence_rejects_missing_and_changed_real_files() -> Result<()> {
        let temp = tempfile::tempdir()?; let root = temp.path().canonicalize()?;
        let claim_path = root.join("claim"); let endpoint_path = root.join("endpoint");
        std::fs::write(&claim_path,b"original-claim")?;
        std::fs::write(&endpoint_path,b"original-endpoint")?;
        let proof = Evidence {claim_path:claim_path.clone(),claim_bytes:b"original-claim".to_vec(),
            endpoint_path:endpoint_path.clone(),endpoint_bytes:b"original-endpoint".to_vec(),
            registration:None,root};
        proof.verify()?;
        std::fs::write(&claim_path,b"changed-claim")?;
        assert!(proof.verify().is_err());
        std::fs::write(&claim_path,b"original-claim")?;
        std::fs::remove_file(&endpoint_path)?;
        assert!(proof.verify().is_err());
        std::fs::write(&endpoint_path,b"original-endpoint")?;
        proof.verify()?;
        std::fs::write(&claim_path,vec![b'x';65537])?;
        assert!(read_record(&claim_path).is_err());
        Ok(())
    }

    #[test]
    fn registration_allows_only_clearing_maintenance() -> Result<()> {
        let temp = tempfile::tempdir()?; let root = temp.path().canonicalize()?;
        let original: crate::autostart::Registration = serde_json::from_value(json!({"schema":1,
            "platform":"linux","installation":root,"executable":root.join("cli"),"user_home":root,
            "owner":"fixture","id":"fixture-registration","enabled":true,"manually_stopped":false,
            "maintenance":true,"environment":{},"artifact_hashes":{}}))?;
        let mut current = original.clone(); current.maintenance = false;
        verify_registration_transition(original.clone(), &current)?;
        current.id = "foreign".into();
        assert!(verify_registration_transition(original.clone(), &current).is_err());
        current = original.clone(); current.environment.insert("UNRELATED".into(),"changed".into());
        assert!(verify_registration_transition(original.clone(), &current).is_err());
        current = original.clone(); current.manually_stopped = true;
        assert!(verify_registration_transition(original.clone(), &current).is_err());
        let mut completed = original.clone(); completed.maintenance = false;
        assert!(verify_registration_transition(completed, &original).is_err());
        Ok(())
    }
}
