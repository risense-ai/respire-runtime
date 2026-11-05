//! One-shot launch grants. Public instance IDs cannot replay consumed grants.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

static STARTUP: OnceLock<Startup> = OnceLock::new();

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LaunchGrant {
    schema_version: u32,
    protocol_version: u32,
    nonce: String,
    instance_id: String,
    installation_root: PathBuf,
    installation_id: String,
    profile: PathBuf,
    account_id: String,
    sync_generation: usize,
    image_path: PathBuf,
    image_sha256: String,
    supervisor_pid: u32,
    supervisor_birth: String,
    managed_id: Option<String>,
    registration_sha256: Option<String>,
    maintenance: Option<MaintenanceBinding>,
    port: u16,
    issued_at_ms: u64,
    expires_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MaintenanceBinding {
    marker_sha256: String,
    coordinator_id: String,
    controller_pid: u32,
    controller_birth: String,
    issuer_cli_version: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LaunchContext {
    root: PathBuf,
    profile: PathBuf,
    account_id: String,
    sync_generation: usize,
    image_path: PathBuf,
    image_sha256: String,
    port: u16,
}

struct Startup {
    context: LaunchContext,
    grant: Option<LaunchGrant>,
}

pub(crate) fn authorize(supervised: bool, boot_token: Option<&str>, port: u16) -> Result<()> {
    anyhow::ensure!(
        STARTUP.get().is_none(),
        "runtime startup was authorized twice"
    );
    fs::create_dir_all(respire_app::service::main_data_dir())?;
    fs::create_dir_all(respire_app::service::data_dir())?;
    let context = current_context(port)?;
    let (grant, instance_id) = if let Some(token) = boot_token {
        let nonce = token
            .strip_prefix("launch-v1:")
            .context("unsupported runtime launch token")?;
        validate_nonce(nonce)?;
        let directory = context
            .root
            .join("runtime")
            .join("autostart")
            .join("launch");
        let path = directory.join(format!("launch-{nonce}.json"));
        let bytes =
            read_private_file(&path)?.context("runtime launch grant is missing or consumed")?;
        let grant: LaunchGrant = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid runtime launch grant JSON"))?;
        validate_grant(&grant, &context, supervised, nonce, now_ms()?)?;
        verify_authority(Some(&grant), &context)?;
        claim(&directory, nonce, &bytes)?;
        fs::remove_file(&path).context("consumed runtime launch grant could not be removed")?;
        sync_directory(&directory)?;
        let instance_id = grant.instance_id.clone();
        (Some(grant), instance_id)
    } else {
        anyhow::ensure!(
            !supervised,
            "supervised startup requires a one-time host launch grant"
        );
        verify_authority(None, &context)?;
        (None, uuid::Uuid::new_v4().to_string())
    };
    respire_commands::rpc_serve::set_launch_instance_id(&instance_id)?;
    STARTUP
        .set(Startup { context, grant })
        .map_err(|_| anyhow::anyhow!("runtime startup identity was installed twice"))?;
    Ok(())
}

pub(crate) fn managed_id() -> Option<&'static str> {
    STARTUP.get()?.grant.as_ref()?.managed_id.as_deref()
}

pub(crate) fn verify_managed_boot() -> Result<()> {
    let startup = STARTUP
        .get()
        .context("runtime startup authorization is missing")?;
    anyhow::ensure!(
        current_context(startup.context.port)? == startup.context,
        "runtime launch context changed before opening the store"
    );
    verify_authority(startup.grant.as_ref(), &startup.context)
}

fn current_context(port: u16) -> Result<LaunchContext> {
    let root = respire_app::service::main_data_dir().canonicalize()?;
    let profile = respire_app::service::data_dir().canonicalize()?;
    let account = respire_app::service::session_user_of_dir(&profile);
    let account_source = if account.is_empty() {
        profile.display().to_string()
    } else {
        account
    };
    let image_path = std::env::current_exe()?.canonicalize()?;
    Ok(LaunchContext {
        root,
        profile,
        account_id: hash(account_source.as_bytes()),
        sync_generation: respire_commands::rpc_worker::sync_generation(),
        image_sha256: hash_file(&image_path)?,
        image_path,
        port,
    })
}

fn validate_nonce(nonce: &str) -> Result<()> {
    let uuid = uuid::Uuid::parse_str(nonce)
        .map_err(|_| anyhow::anyhow!("invalid runtime launch nonce"))?;
    anyhow::ensure!(
        uuid.get_version_num() == 4 && uuid.to_string() == nonce,
        "runtime launch nonce must be a canonical random UUID"
    );
    Ok(())
}

fn validate_grant(
    grant: &LaunchGrant,
    context: &LaunchContext,
    supervised: bool,
    nonce: &str,
    now: u64,
) -> Result<()> {
    validate_nonce(nonce)?;
    anyhow::ensure!(
        grant.schema_version == 1
            && grant.protocol_version == respire_commands::rpc_worker::PROTOCOL_V
            && grant.nonce == nonce
            && grant.instance_id == nonce,
        "runtime launch grant schema, protocol or nonce mismatch"
    );
    anyhow::ensure!(
        grant.installation_root == context.root
            && grant.installation_id == hash(context.root.display().to_string().as_bytes())
            && grant.profile == context.profile
            && grant.account_id == context.account_id
            && grant.sync_generation == context.sync_generation
            && grant.image_path == context.image_path
            && grant.image_sha256 == context.image_sha256
            && grant.port != 0
            && grant.port == context.port,
        "runtime launch grant does not match this installation, account, generation or image"
    );
    anyhow::ensure!(
        grant.supervisor_pid > 0
            && grant.supervisor_pid != std::process::id()
            && !grant.supervisor_birth.is_empty()
            && supervised == grant.managed_id.is_some()
            && grant.managed_id.as_ref().is_none_or(|id| !id.is_empty())
            && grant.issued_at_ms <= now
            && now <= grant.expires_at_ms
            && grant.expires_at_ms > grant.issued_at_ms
            && grant.expires_at_ms - grant.issued_at_ms <= 60_000,
        "runtime launch grant owner, mode or expiry is invalid"
    );
    Ok(())
}

fn verify_authority(grant: Option<&LaunchGrant>, context: &LaunchContext) -> Result<()> {
    let control = context.root.join("runtime").join("autostart");
    let registration_bytes = read_private_file(&control.join("registration.json"))?;
    let maintenance_bytes = read_private_file(&control.join("maintenance.json"))?;
    let mut registration = registration_bytes
        .as_ref()
        .map(|bytes| parse_control(bytes))
        .transpose()?;
    if let Some(registration) = &mut registration {
        let raw_root = registration["environment"]["RSRS_DATA_DIR"]
            .as_str()
            .context("registered runtime root is missing")?;
        let registered_root = Path::new(raw_root).canonicalize()?;
        anyhow::ensure!(
            registered_root == context.root,
            "registered runtime root belongs to another installation"
        );
        registration["environment"]["RSRS_DATA_DIR"] = json!(registered_root);
    }
    let maintenance = maintenance_bytes
        .as_ref()
        .map(|bytes| parse_control(bytes))
        .transpose()?;
    validate_control(
        grant,
        context,
        registration.as_ref(),
        registration_bytes.as_deref(),
        maintenance.as_ref(),
        maintenance_bytes.as_deref(),
    )?;
    if let Some(grant) = grant {
        anyhow::ensure!(
            process_birth(grant.supervisor_pid)?.as_deref()
                == Some(grant.supervisor_birth.as_str()),
            "runtime launch supervisor exited or its PID was reused"
        );
        if let Some(binding) = &grant.maintenance {
            anyhow::ensure!(
                process_birth(binding.controller_pid)?.as_deref()
                    == Some(binding.controller_birth.as_str()),
                "runtime maintenance controller exited or its PID was reused"
            );
        }
    }
    Ok(())
}

fn validate_control(
    grant: Option<&LaunchGrant>,
    context: &LaunchContext,
    registration: Option<&Value>,
    registration_bytes: Option<&[u8]>,
    maintenance: Option<&Value>,
    maintenance_bytes: Option<&[u8]>,
) -> Result<()> {
    if let Some(grant) = grant {
        anyhow::ensure!(
            grant.registration_sha256 == registration_bytes.map(hash),
            "runtime registration changed after launch authorization"
        );
    }
    if let Some(registration) = registration {
        let owner = registration["owner"]
            .as_str()
            .filter(|v| !v.is_empty())
            .context("runtime registration owner is missing")?;
        let id =
            hash(format!("respire-runtime-v1\0{}\0{owner}", context.root.display()).as_bytes());
        anyhow::ensure!(
            registration["schema"] == 1
                && registration["platform"] == std::env::consts::OS
                && registration["installation"].as_str().map(Path::new)
                    == Some(context.root.as_path())
                && registration["id"].as_str() == Some(&id[..24])
                && registration["environment"]["RSRS_RPC_PORT"]
                    .as_str()
                    .and_then(|v| v.parse::<u16>().ok())
                    == Some(context.port)
                && registration["environment"]["RSRS_DATA_DIR"]
                    .as_str()
                    .map(Path::new)
                    == Some(context.root.as_path()),
            "runtime registration belongs to another installation, platform or port"
        );
        if let Some(managed) = grant.and_then(|grant| grant.managed_id.as_deref()) {
            anyhow::ensure!(
                registration["id"] == managed
                    && registration["enabled"] == true
                    && registration["manually_stopped"] == false,
                "managed runtime launch is disabled or belongs to another registration"
            );
        } else {
            anyhow::ensure!(
                (registration["enabled"] == false && registration["manually_stopped"] == false)
                    || grant.is_some_and(|grant| grant.maintenance.is_some()),
                "registered runtime requires its host lifecycle coordinator"
            );
        }
        anyhow::ensure!(
            registration["maintenance"] == false || maintenance.is_some(),
            "registration maintenance has no matching controller marker"
        );
    } else {
        anyhow::ensure!(
            grant.and_then(|grant| grant.managed_id.as_ref()).is_none(),
            "managed runtime registration disappeared"
        );
    }
    match (
        maintenance,
        grant.and_then(|grant| grant.maintenance.as_ref()),
    ) {
        (None, None) => Ok(()),
        (Some(marker), Some(binding)) => {
            anyhow::ensure!(
                maintenance_bytes.map(hash).as_deref() == Some(binding.marker_sha256.as_str())
                    && marker["schema"] == 1
                    && marker["id"] == binding.coordinator_id
                    && registration
                        .is_none_or(|registration| registration["id"] == binding.coordinator_id)
                    && marker["owner_pid"] == binding.controller_pid
                    && marker["owner_birth"] == binding.controller_birth
                    && marker["expected_version"] == binding.issuer_cli_version
                    && !binding.issuer_cli_version.is_empty()
                    && !binding.controller_birth.is_empty()
                    && binding.controller_pid > 0
                    && marker["expected_profile"].as_str().map(Path::new)
                        == Some(context.profile.as_path())
                    && matches!(marker["phase"].as_str(), Some("Starting" | "Verified")),
                "runtime maintenance does not authorize this launch"
            );
            Ok(())
        }
        _ => anyhow::bail!("runtime maintenance launch binding is missing or stale"),
    }
}

/// Match the CLI launch producer's birth format without inspecting command lines.
fn process_birth(pid: u32) -> Result<Option<String>> {
    anyhow::ensure!(pid > 0, "invalid launch owner PID");
    #[cfg(windows)]
    {
        return Ok(respire_spawn::process_birth(pid)?.map(|birth| birth.to_string()));
    }
    #[cfg(target_os = "linux")]
    {
        let raw = match fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        return linux_process_birth(&raw);
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        let output = std::process::Command::new("/bin/ps")
            .args(["-p", &pid.to_string(), "-o", "lstart="])
            .env("LC_ALL", "C")
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()?;
        if output.status.code() == Some(1) && output.stdout.is_empty() {
            return Ok(None);
        }
        anyhow::ensure!(output.status.success(), "launch owner birth lookup failed");
        let birth = String::from_utf8(output.stdout)?;
        let birth = birth.trim();
        anyhow::ensure!(!birth.is_empty(), "launch owner birth is empty");
        return Ok(Some(birth.to_owned()));
    }
    #[cfg(not(any(windows, unix)))]
    anyhow::bail!("launch owner identity is unsupported on this platform")
}

#[cfg(any(target_os = "linux", test))]
fn linux_process_birth(raw: &str) -> Result<Option<String>> {
    let fields = raw
        .rsplit_once(')')
        .context("invalid launch owner process identity")?
        .1;
    if matches!(fields.split_whitespace().next(), Some("Z" | "X")) {
        return Ok(None);
    }
    let birth = fields
        .split_whitespace()
        .nth(19)
        .context("launch owner birth is missing")?;
    let ticks = birth.parse::<u64>().context("invalid launch owner birth")?;
    anyhow::ensure!(ticks > 0, "launch owner birth cannot be zero");
    Ok(Some(ticks.to_string()))
}

fn claim(directory: &Path, nonce: &str, grant: &[u8]) -> Result<()> {
    let path = directory.join(format!("launch-{nonce}.claimed"));
    let birth = process_birth(std::process::id())?
        .context("runtime claimant process identity is unavailable")?;
    let verified: LaunchGrant = serde_json::from_slice(grant)?;
    let registration = read_private_file(
        &directory.parent().context("launch directory has no parent")?.join("registration.json"),
    )?;
    anyhow::ensure!(
        verified.registration_sha256 == registration.as_deref().map(hash),
        "registration changed before the launch claim was persisted"
    );
    let registration_json = registration.map(String::from_utf8).transpose()?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .context("runtime launch grant was already claimed")?;
    // Retain the claim on any later failure; a failed startup never revives a token.
    file.write_all(&serde_json::to_vec(&json!({
        "schema_version": 2,
        "protocol_version": respire_commands::rpc_worker::PROTOCOL_V,
        "state": "consumed",
        "grant_sha256": hash(grant),
        "grant_json": std::str::from_utf8(grant)?,
        "registration_json": registration_json,
        "pid": std::process::id(), "process_start_id": birth,
    }))?)?;
    file.sync_all()?;
    sync_directory(directory)
}

fn parse_control(bytes: &[u8]) -> Result<Value> {
    serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("invalid runtime startup authorization JSON"))
}

fn read_private_file(path: &Path) -> Result<Option<Vec<u8>>> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                anyhow::ensure!(
                    !metadata.file_type().is_symlink(),
                    "runtime authorization path contains a symlink"
                );
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    anyhow::ensure!(
                        metadata.file_attributes() & 0x400 == 0,
                        "runtime authorization path contains a reparse point"
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= 64 * 1024,
        "runtime startup authorization must be a bounded regular file"
    );
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(64 * 1024 + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= 64 * 1024,
        "runtime startup authorization is too large"
    );
    Ok(Some(bytes))
}

fn sync_directory(directory: &Path) -> Result<()> {
    #[cfg(unix)]
    fs::File::open(directory)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = directory;
    Ok(())
}

fn now_ms() -> Result<u64> {
    u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
        .context("runtime launch clock overflow")
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hash_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (LaunchContext, LaunchGrant) {
        let context = LaunchContext {
            root: PathBuf::from("fixture-root"),
            profile: PathBuf::from("fixture-profile"),
            account_id: "a".repeat(64),
            sync_generation: 0,
            image_path: PathBuf::from("fixture-runtime"),
            image_sha256: "b".repeat(64),
            port: 19169,
        };
        let grant = LaunchGrant {
            schema_version: 1,
            protocol_version: respire_commands::rpc_worker::PROTOCOL_V,
            nonce: "12345678-1234-4234-8234-123456789abc".to_owned(),
            instance_id: "12345678-1234-4234-8234-123456789abc".to_owned(),
            installation_root: context.root.clone(),
            installation_id: hash(context.root.display().to_string().as_bytes()),
            profile: context.profile.clone(),
            account_id: context.account_id.clone(),
            sync_generation: 0,
            image_path: context.image_path.clone(),
            image_sha256: context.image_sha256.clone(),
            supervisor_pid: if std::process::id() == 1 { 2 } else { 1 },
            supervisor_birth: "fixture-birth".to_owned(),
            managed_id: None,
            registration_sha256: None,
            maintenance: None,
            port: context.port,
            issued_at_ms: 1000,
            expires_at_ms: 61_000,
        };
        (context, grant)
    }

    #[test]
    fn detached_grant_accepts_only_its_exact_context() -> Result<()> {
        let (context, grant) = fixture();
        validate_grant(&grant, &context, false, &grant.nonce, 2000)?;
        validate_control(Some(&grant), &context, None, None, None, None)?;
        let value = serde_json::to_value(&grant)?;
        for (field, replacement) in [
            ("schema_version", json!(2)),
            ("protocol_version", json!(0)),
            ("nonce", json!("wrong")),
            ("instance_id", json!("wrong")),
            ("installation_root", json!("other-root")),
            ("installation_id", json!("other")),
            ("profile", json!("other-profile")),
            ("account_id", json!("other")),
            ("sync_generation", json!(1)),
            ("image_path", json!("other-image")),
            ("image_sha256", json!("c".repeat(64))),
            ("supervisor_pid", json!(0)),
            ("supervisor_birth", json!("")),
            ("managed_id", json!("unexpected")),
            ("port", json!(19170)),
            ("issued_at_ms", json!(3000)),
            ("expires_at_ms", json!(1999)),
            ("expires_at_ms", json!(62_000)),
        ] {
            let mut changed = value.clone();
            changed[field] = replacement;
            let changed: LaunchGrant = serde_json::from_value(changed)?;
            assert!(
                validate_grant(&changed, &context, false, &grant.nonce, 2000).is_err(),
                "accepted changed {field}"
            );
        }
        assert!(validate_grant(&grant, &context, true, &grant.nonce, 2000).is_err());
        assert!(validate_nonce("../../outside").is_err());
        assert!(validate_nonce("12345678-1234-1234-8234-123456789abc").is_err());
        Ok(())
    }

    #[test]
    fn managed_and_maintenance_grants_bind_exact_control_files() -> Result<()> {
        let (context, mut grant) = fixture();
        let id = hash(
            format!(
                "respire-runtime-v1\0{}\0fixture-owner",
                context.root.display()
            )
            .as_bytes(),
        );
        let mut registration = json!({
            "schema": 1, "platform": std::env::consts::OS,
            "installation": context.root, "owner": "fixture-owner", "id": &id[..24],
            "enabled": true, "manually_stopped": false, "maintenance": false,
            "environment": { "RSRS_DATA_DIR": context.root, "RSRS_RPC_PORT": "19169" }
        });
        let bytes = serde_json::to_vec(&registration)?;
        grant.managed_id = Some(id[..24].to_owned());
        grant.registration_sha256 = Some(hash(&bytes));
        validate_grant(&grant, &context, true, &grant.nonce, 2000)?;
        validate_control(
            Some(&grant),
            &context,
            Some(&registration),
            Some(&bytes),
            None,
            None,
        )?;
        assert!(validate_control(
            None,
            &context,
            Some(&registration),
            Some(&bytes),
            None,
            None
        )
        .is_err());
        registration["enabled"] = json!(false);
        let changed = serde_json::to_vec(&registration)?;
        assert!(validate_control(
            Some(&grant),
            &context,
            Some(&registration),
            Some(&changed),
            None,
            None
        )
        .is_err());
        grant.registration_sha256 = Some(hash(&changed));
        assert!(validate_control(
            Some(&grant),
            &context,
            Some(&registration),
            Some(&changed),
            None,
            None
        )
        .is_err());
        registration["enabled"] = json!(true);
        let bytes = serde_json::to_vec(&registration)?;
        grant.registration_sha256 = Some(hash(&bytes));
        let mut marker = json!({
            "schema": 1, "id": &id[..24], "owner_pid": grant.supervisor_pid,
            "owner_birth": "controller-birth", "expected_version": "fixture-cli-version",
            "expected_profile": context.profile, "phase": "Starting", "token": "maintenance-secret"
        });
        let marker_bytes = serde_json::to_vec(&marker)?;
        grant.maintenance = Some(MaintenanceBinding {
            marker_sha256: hash(&marker_bytes),
            coordinator_id: id[..24].to_owned(),
            controller_pid: grant.supervisor_pid,
            controller_birth: "controller-birth".to_owned(),
            issuer_cli_version: "fixture-cli-version".to_owned(),
        });
        validate_control(
            Some(&grant),
            &context,
            Some(&registration),
            Some(&bytes),
            Some(&marker),
            Some(&marker_bytes),
        )?;
        assert!(validate_control(
            Some(&grant),
            &context,
            Some(&registration),
            Some(&bytes),
            None,
            None
        )
        .is_err());
        marker["phase"] = json!("Paused");
        let changed = serde_json::to_vec(&marker)?;
        assert!(validate_control(
            Some(&grant),
            &context,
            Some(&registration),
            Some(&bytes),
            Some(&marker),
            Some(&changed)
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn linux_birth_parser_handles_parentheses_and_dead_or_invalid_processes() -> Result<()> {
        let fields = (1..=20)
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(
            linux_process_birth(&format!("123 (owner ) name) S {fields}"))?,
            Some("19".to_owned())
        );
        assert!(linux_process_birth(&format!("123 (owner) Z {fields}"))?.is_none());
        assert!(linux_process_birth("invalid").is_err());
        assert!(linux_process_birth("123 (owner) S 1 2").is_err());
        Ok(())
    }

    #[test]
    fn launch_claim_cannot_be_replayed() -> Result<()> {
        let root =
            std::env::temp_dir().join(format!("respire-launch-fixture-{}", uuid::Uuid::new_v4()));
        let directory = root.join("launch");
        fs::create_dir_all(&directory)?;
        let result = (|| -> Result<()> {
            let nonce = "12345678-1234-4234-8234-123456789abc";
            let (_, grant) = fixture();
            let bytes = serde_json::to_vec(&grant)?;
            claim(&directory, nonce, &bytes)?;
            let receipt_path = directory.join(format!("launch-{nonce}.claimed"));
            let receipt_bytes = fs::read(&receipt_path)?;
            let receipt: Value = serde_json::from_slice(&receipt_bytes)?;
            assert_eq!(receipt["schema_version"], 2);
            assert_eq!(receipt["state"], "consumed");
            assert_eq!(receipt["grant_sha256"], hash(&bytes));
            assert_eq!(receipt["grant_json"], std::str::from_utf8(&bytes)?);
            assert!(receipt["registration_json"].is_null());
            assert_eq!(receipt["pid"], std::process::id());
            assert_eq!(receipt["process_start_id"], process_birth(std::process::id())?.context("test process exited")?);
            assert!(claim(&directory, nonce, &bytes).is_err());
            assert_eq!(fs::read(&receipt_path)?, receipt_bytes);
            Ok(())
        })();
        fs::remove_dir_all(&root)?;
        result
    }
}
