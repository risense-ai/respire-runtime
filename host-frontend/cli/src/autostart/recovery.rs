//! Explicit crash recovery consumes evidence, never revives a launch grant.
use super::{hash, lifecycle, manager, read_registration, Registration};
use anyhow::{Context, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub(crate) struct StaleOwner {
    endpoint: PathBuf,
    endpoint_bytes: Vec<u8>,
    receipt: PathBuf,
    receipt_bytes: Vec<u8>,
}

fn read_record(path: &Path) -> Result<Vec<u8>> {
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        anyhow::ensure!(
            !metadata.file_type().is_symlink(),
            "recovery path contains a symlink"
        );
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            anyhow::ensure!(
                metadata.file_attributes() & 0x400 == 0,
                "recovery path contains a reparse point"
            );
        }
    }
    let file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= 65536,
        "invalid recovery record"
    );
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 65536, "recovery record exceeds 64 KiB");
    Ok(bytes)
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .filter(|s| !s.is_empty())
        .with_context(|| format!("recovery identity missing {key}"))
}

pub(super) fn account_identity_source(profile: &Path) -> Result<String> {
    match respire_client_host::identity::host_session_user_of_dir(profile, super::hash)? {
        Some(user) => Ok(user),
        // Absent sessions and strict local claims share the profile identity.
        None => Ok(profile.display().to_string()),
    }
}

fn pid(value: &Value, key: &str) -> Result<u32> {
    value[key]
        .as_u64()
        .and_then(|id| u32::try_from(id).ok())
        .filter(|id| *id > 0 && *id != std::process::id())
        .with_context(|| format!("invalid recovery {key}"))
}

fn image_hash(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn refused() -> Result<()> {
    let address = SocketAddr::from(([127, 0, 0, 1], crate::net_rpc::rpc_port()));
    match TcpStream::connect_timeout(&address, Duration::from_secs(5)) {
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => Ok(()),
        Err(error) => Err(error).context("crash recovery requires an actual loopback refusal"),
        Ok(_) => anyhow::bail!("crash recovery blocked: loopback listener is alive"),
    }
}

impl StaleOwner {
    /// The caller must hold the installation takeover lock for this whole guard.
    pub(crate) fn prepare_locked() -> Result<Self> {
        let endpoint = crate::rpc::endpoint_path();
        let endpoint_bytes = read_record(&endpoint)?;
        let record: Value = serde_json::from_slice(&endpoint_bytes)?;
        anyhow::ensure!(record["schema_version"] == 2,
            "runtime restart blocked: endpoint and launch claim do not retain that evidence; legacy ownership requires repair, no replacement started");
        let instance = text(&record, "instance_id")?;
        let nonce = uuid::Uuid::parse_str(instance)?;
        anyhow::ensure!(
            nonce.get_version_num() == 4 && nonce.to_string() == instance,
            "invalid recovery instance"
        );
        let receipt = respire_client_host::paths::main_data_dir()
            .canonicalize()?
            .join("runtime/autostart/launch")
            .join(format!("launch-{instance}.claimed"));
        let receipt_bytes =
            read_record(&receipt).context("complete consumed launch receipt is missing")?;
        let guard = Self {
            endpoint,
            endpoint_bytes,
            receipt,
            receipt_bytes,
        };
        guard.verify()?;
        refused()?;
        Ok(guard)
    }

    fn verify(&self) -> Result<()> {
        let (runtime_pid, supervisor_pid) = self.verify_binding()?;
        // None is authoritative absence/exit; access errors and PID reuse stay closed.
        anyhow::ensure!(
            manager::process_birth(runtime_pid)
                .context("cannot prove recorded runtime exit")?
                .is_none()
                && manager::process_birth(supervisor_pid)
                    .context("cannot prove recorded supervisor exit")?
                    .is_none(),
            "old runtime or supervisor is still alive"
        );
        Ok(())
    }

    fn verify_binding(&self) -> Result<(u32, u32)> {
        anyhow::ensure!(
            read_record(&self.endpoint)? == self.endpoint_bytes
                && read_record(&self.receipt)? == self.receipt_bytes,
            "crash recovery evidence changed"
        );
        let endpoint: Value = serde_json::from_slice(&self.endpoint_bytes)?;
        let receipt: Value = serde_json::from_slice(&self.receipt_bytes)?;
        anyhow::ensure!(
            endpoint["schema_version"] == 2
                && receipt["schema_version"] == 2
                && receipt["state"] == "consumed"
                && receipt["protocol_version"] == crate::rpc::PROTOCOL_V
                && endpoint["launch_receipt_sha256"] == hash(&self.receipt_bytes),
            "endpoint does not bind a complete consumed launch receipt"
        );
        let grant_json = text(&receipt, "grant_json")?;
        anyhow::ensure!(
            receipt["grant_sha256"] == hash(grant_json.as_bytes()),
            "consumed grant digest mismatch"
        );
        let grant: Value = serde_json::from_str(grant_json)?;
        anyhow::ensure!(
            receipt.get("registration_json").is_some()
                && endpoint.get("managed_id").is_some()
                && ["registration_sha256", "managed_id", "maintenance"]
                    .iter()
                    .all(|key| grant.get(*key).is_some()),
            "incomplete nullable ownership bindings"
        );
        let health: crate::net_rpc::Health = serde_json::from_value(endpoint.clone())?;
        let roots = respire_client_host::roots::resolved_roots()?;
        let root = roots.installation_root.canonicalize()?;
        let profile = roots.account_data_root.canonicalize()?;
        let account_source = account_identity_source(&profile)?;
        let runtime_pid = pid(&endpoint, "pid")?;
        let supervisor_pid = pid(&grant, "supervisor_pid")?;
        let birth = text(&receipt, "process_start_id")?;
        let prefix = if cfg!(windows) {
            "windows-filetime-"
        } else if cfg!(target_os = "linux") {
            "linux-starttime-"
        } else {
            "darwin-lstart-"
        };
        let supervisor_birth = text(&grant, "supervisor_birth")?;
        if cfg!(any(windows, target_os = "linux")) {
            anyhow::ensure!(
                birth.parse::<u64>()? > 0 && supervisor_birth.parse::<u64>()? > 0,
                "invalid recorded process birth"
            );
        }
        anyhow::ensure!(
            grant["schema_version"] == 1
                && grant["protocol_version"] == crate::rpc::PROTOCOL_V
                && health.server == "respire"
                && health.v == crate::rpc::PROTOCOL_V
                && health.generation > 0
                && grant["nonce"] == health.instance_id
                && grant["instance_id"] == health.instance_id
                && grant["installation_root"] == serde_json::to_value(&root)?
                && grant["profile"] == serde_json::to_value(&profile)?
                && !health.installation_root.is_empty()
                && Path::new(&health.installation_root).canonicalize()? == root
                && !health.data_dir.is_empty()
                && Path::new(&health.data_dir).canonicalize()? == profile
                && grant["installation_id"] == hash(root.display().to_string().as_bytes())
                && grant["installation_id"] == health.installation_id
                && grant["account_id"] == hash(account_source.as_bytes())
                && grant["account_id"] == health.account_id
                && grant["managed_id"] == serde_json::to_value(&health.managed_id)?
                && grant["port"] == crate::net_rpc::rpc_port()
                && health.url == crate::net_rpc::rpc_base_url()
                && receipt["pid"] == runtime_pid
                && supervisor_pid != runtime_pid
                && health.process_start_id == format!("{prefix}{birth}")
                && crate::runtime_fetch::version_in_accept(&health.runtime_version)
                && health.bin == health.runtime_version,
            "crash recovery identity/root/account/version mismatch"
        );
        // sync_generation is a boot fence, not the process's actual wire scope.
        anyhow::ensure!(
            grant["sync_generation"].as_u64().is_some(),
            "missing launch generation fence"
        );
        let issued = grant["issued_at_ms"]
            .as_u64()
            .context("missing launch issuance")?;
        let expires = grant["expires_at_ms"]
            .as_u64()
            .context("missing launch expiry")?;
        anyhow::ensure!(
            expires > issued && expires - issued <= 60_000,
            "invalid recorded grant lifetime"
        );

        let current = read_registration(&root)?;
        if let Some(config) = current.as_ref() {
            lifecycle::owned(config)?;
            lifecycle::ensure_control_endpoint(config)?;
            let original = text(&receipt, "registration_json")?;
            anyhow::ensure!(
                grant["registration_sha256"] == hash(original.as_bytes()),
                "launch registration digest mismatch"
            );
            let mut recorded: Registration = serde_json::from_str(original)?;
            // Maintenance is the only field the existing successful launch changes.
            recorded.maintenance = config.maintenance;
            anyhow::ensure!(
                serde_json::to_value(&recorded)? == serde_json::to_value(config)?
                    && !config.manually_stopped
                    && health
                        .managed_id
                        .as_deref()
                        .is_none_or(|id| config.enabled && id == config.id),
                "registration changed since the consumed launch"
            );
            anyhow::ensure!(
                !manager::inspect(config)?.running,
                "registered supervisor still reports running"
            );
            let image = lifecycle::registered_runtime_image(config)?;
            anyhow::ensure!(
                Path::new(text(&grant, "image_path")?).canonicalize()? == image,
                "selected registered Runtime changed"
            );
        } else {
            anyhow::ensure!(
                receipt["registration_json"].is_null()
                    && grant["registration_sha256"].is_null()
                    && health.managed_id.is_none()
                    && grant["maintenance"].is_null()
                    && crate::rpc::runtime_acceptable(&health)?,
                "detached launch registration/selection mismatch"
            );
        }
        let image = Path::new(text(&grant, "image_path")?).canonicalize()?;
        anyhow::ensure!(
            image.is_file()
                && (crate::embedding::selection().is_some()
                    || image != std::env::current_exe()?.canonicalize()?)
                && Path::new(text(&endpoint, "exe")?).canonicalize()? == image
                && Path::new(text(&endpoint, "image_path")?).canonicalize()? == image
                && grant["image_sha256"] == health.image_sha256
                && health.image_sha256 == image_hash(&image)?,
            "crash recovery image identity changed"
        );
        anyhow::ensure!(
            !self
                .receipt
                .with_file_name(format!("launch-{}.json", health.instance_id))
                .try_exists()?,
            "consumed launch authorization is still present"
        );
        Ok((runtime_pid, supervisor_pid))
    }

    /// Called after existing maintenance fences new managed launches.
    pub(crate) fn remove_endpoint_locked(self) -> Result<()> {
        refused()?;
        self.verify()?;
        anyhow::ensure!(
            read_record(&self.endpoint)? == self.endpoint_bytes
                && read_record(&self.receipt)? == self.receipt_bytes,
            "stale records changed before cleanup"
        );
        // Keep the consumed claim as a permanent anti-replay tombstone.
        fs::remove_file(&self.endpoint)?;
        respire_spawn::durable::sync_directory(
            self.endpoint.parent().context("endpoint parent missing")?,
        )?;
        Ok(())
    }
}
