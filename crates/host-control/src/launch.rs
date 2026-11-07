//! Typed launch grants minted only from coordinator-owned maintenance evidence.
//!
//! Grant fields originate in respire-cli 25ef33a23c87b0c00f1430c23d2c5b6c629ec13d,
//! `cli/src/autostart/launch_authorization.rs::{prepare_grant_for_identity,build_grant}`.
//! Identity rechecks originate in `cli/src/autostart/control.rs::auth_exchange`.
//! This is host orchestration, not business authorization: Runtime still consumes
//! the private channel and runs its unchanged grant, parent and request validators.
use anyhow::{Context, Result};
use respire_protocol::{HostAuthIdentity, HostControlLaunchGrant, HOST_CONTROL_SCHEMA_V};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::process::Child;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::maintenance::{LaunchContext, LaunchPurpose, OwnedMaintenanceBinding, Phase};
use crate::VerifiedRuntime;

/// No caller JSON or authorization flag can construct the maintenance evidence.
/// The coordinator holds takeover, drains the old owner and creates this binding.
/// No grant file is written here; private controls inherit exactly one grant and
/// request through the owned child's stdin, never argv, environment or public RPC.
pub(crate) fn prepare_grant(
    runtime: &VerifiedRuntime,
    binding: &OwnedMaintenanceBinding,
    expected_identity: &HostAuthIdentity,
) -> Result<HostControlLaunchGrant> {
    binding.revalidate()?;
    validate_purpose_phase(binding.purpose(), binding.phase())?;
    anyhow::ensure!(
        runtime.port != 0 && runtime.image_path.canonicalize()? == runtime.image_path,
        "host control Runtime path or port changed"
    );
    let image_sha256 = hash_file(&runtime.image_path)?;
    anyhow::ensure!(
        image_sha256.eq_ignore_ascii_case(&runtime.image_sha256),
        "host control Runtime image differs from the verified manifest"
    );
    let root = binding.installation_root();
    let profile = binding.profile();
    anyhow::ensure!(
        root.is_absolute()
            && root.canonicalize()? == root
            && profile.is_absolute()
            && profile.canonicalize()? == profile,
        "host control installation or profile is not canonical"
    );
    let supervisor_pid = std::process::id();
    let supervisor_birth = process_birth(supervisor_pid)?
        .context("launch supervisor process identity is unavailable")?;
    let maintenance = binding.maintenance();
    anyhow::ensure!(
        maintenance.controller_pid == supervisor_pid
            && maintenance.controller_birth == supervisor_birth,
        "launch maintenance is not owned by this parent process"
    );
    let nonce = uuid::Uuid::new_v4().to_string();
    let issued_at_ms = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
        .context("launch clock overflow")?;
    let grant = HostControlLaunchGrant {
        schema_version: HOST_CONTROL_SCHEMA_V,
        protocol_version: crate::PROTOCOL_V,
        nonce: nonce.clone(),
        instance_id: nonce,
        installation_root: root.to_path_buf(),
        installation_id: hash(root.display().to_string().as_bytes()),
        profile: profile.to_path_buf(),
        account_id: grant_account_id(profile, expected_identity),
        // A new worker, not a persistent owner generation.
        sync_generation: 0,
        image_path: runtime.image_path.clone(),
        image_sha256,
        supervisor_pid,
        supervisor_birth,
        managed_id: binding.managed_id().map(str::to_owned),
        registration_sha256: binding.registration_sha256().map(str::to_owned),
        maintenance: Some(maintenance.clone()),
        port: runtime.port,
        issued_at_ms,
        expires_at_ms: expires_at_ms(issued_at_ms)?,
    };
    // Re-read after hashing and grant construction. Scope is never widened if
    // the selected profile, its session or the coordinator's evidence changed.
    binding.revalidate()?;
    anyhow::ensure!(
        crate::identity(profile)? == *expected_identity,
        "auth control identity changed while preparing authorization"
    );
    Ok(grant)
}

/// Starts one candidate under the opaque, one-shot Starting context. Returning a
/// child is not proof of serving identity: the owner must verify health, native
/// birth, exact image, scope and account receipt before advancing maintenance.
pub fn spawn_serving(launch: &LaunchContext, runtime: &VerifiedRuntime) -> Result<(Child, String)> {
    let (binding, expected_identity) = launch.claim()?;
    anyhow::ensure!(
        binding.purpose() == LaunchPurpose::Serving && binding.phase() == Phase::Starting,
        "serving launch requires its one-shot Starting maintenance context"
    );
    let grant = prepare_grant(runtime, binding, expected_identity)?;
    let nonce = grant.nonce.clone();
    let directory = grant.installation_root.join("runtime/autostart/launch");
    let path = directory.join(format!("launch-{nonce}.json"));
    let bytes = serde_json::to_vec(&grant)?;
    let digest = hash(&bytes);
    publish_launch_grant(&path, &bytes)?;
    let arguments = serving_arguments(&grant);
    let token = format!("launch-v1:{nonce}");
    match respire_spawn::spawn_binary_with_boot_token(&runtime.image_path, &arguments, Some(&token))
    {
        Ok(child) => Ok((child, nonce)),
        Err(error) => {
            remove_unconsumed_grant(
                &path,
                &directory.join(format!("launch-{nonce}.claimed")),
                &digest,
            )
            .with_context(|| {
                format!("unused launch grant cleanup failed after spawn error: {error}")
            })?;
            Err(error)
                .context("authorized runtime could not be spawned; do not reuse its launch context")
        }
    }
}

fn serving_arguments(grant: &HostControlLaunchGrant) -> Vec<std::ffi::OsString> {
    let mut arguments = vec![
        "serve".into(),
        "--data-dir".into(),
        grant.installation_root.as_os_str().to_owned(),
        "--host".into(),
        "127.0.0.1".into(),
        "--port".into(),
        grant.port.to_string().into(),
    ];
    if grant.managed_id.is_some() {
        arguments.push("--supervised".into());
    }
    arguments
}

/// New-name-only variant of CLI autostart::private_write. No registration or
/// existing content is replaced; publication uses the shared durable primitive.
fn publish_launch_grant(path: &Path, bytes: &[u8]) -> Result<()> {
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= respire_protocol::HOST_CONTROL_MAX_FRAME_BYTES,
        "launch grant exceeds the protocol limit"
    );
    let parent = path.parent().context("launch grant has no parent")?;
    for ancestor in parent.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                reject_indirection(&metadata)?;
                anyhow::ensure!(
                    metadata.is_dir(),
                    "launch grant parent is not a regular directory"
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    require_absent(path, "launch grant already exists; refusing replacement")?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".respire-launch-{}", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        respire_spawn::durable::publish_new_file(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        match fs::symlink_metadata(&temporary) {
            Ok(metadata) => {
                reject_indirection(&metadata)?;
                anyhow::ensure!(
                    metadata.is_file(),
                    "launch temporary changed; cleanup outcome is unknown"
                );
                fs::remove_file(&temporary)?;
                respire_spawn::durable::sync_directory(parent)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    result
}

// Conservative preflight, not a kernel nofollow guarantee against a foreign
// rename. Cooperating host callers also retain installation takeover ownership.
fn reject_indirection(metadata: &fs::Metadata) -> Result<()> {
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "launch grant path is a symlink"
    );
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        anyhow::ensure!(
            metadata.file_attributes() & 0x400 == 0,
            "launch grant path is a reparse point"
        );
    }
    Ok(())
}

fn require_absent(path: &Path, message: &'static str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => anyhow::bail!(message),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Only called after spawn returned a definite error, never after a child was
/// created or its result became uncertain. A consumed or changed grant is kept.
fn remove_unconsumed_grant(path: &Path, claimed: &Path, digest: &str) -> Result<()> {
    require_absent(
        claimed,
        "launch grant was consumed; cleanup outcome is unknown",
    )?;
    let metadata = fs::symlink_metadata(path)
        .context("unused launch grant disappeared; cleanup outcome is unknown")?;
    reject_indirection(&metadata)?;
    anyhow::ensure!(
        metadata.is_file()
            && metadata.len() <= respire_protocol::HOST_CONTROL_MAX_FRAME_BYTES as u64,
        "unused launch grant changed; refusing cleanup"
    );
    anyhow::ensure!(
        hash_file(path)? == digest,
        "unused launch grant digest changed; refusing cleanup"
    );
    require_absent(
        claimed,
        "launch grant was consumed; cleanup outcome is unknown",
    )?;
    fs::remove_file(path)?;
    respire_spawn::durable::sync_directory(path.parent().context("launch grant has no parent")?)?;
    Ok(())
}

fn validate_purpose_phase(purpose: LaunchPurpose, phase: Phase) -> Result<()> {
    let matches = match purpose {
        LaunchPurpose::Account => phase == Phase::Paused,
        LaunchPurpose::AccountComplete => phase == Phase::Verified,
        LaunchPurpose::Serving => matches!(phase, Phase::Starting | Phase::Verified),
    };
    anyhow::ensure!(
        matches,
        "launch purpose does not match its owned maintenance phase"
    );
    Ok(())
}

fn expires_at_ms(issued_at_ms: u64) -> Result<u64> {
    issued_at_ms
        .checked_add(60_000)
        .context("launch expiry overflow")
}

fn grant_account_id(profile: &Path, identity: &HostAuthIdentity) -> String {
    match identity {
        HostAuthIdentity::Bound { account_id, .. } => account_id.clone(),
        HostAuthIdentity::Absent | HostAuthIdentity::Unbound { .. } => {
            hash(profile.display().to_string().as_bytes())
        }
    }
}

pub(crate) fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(crate) fn hash_file(path: &Path) -> Result<String> {
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

/// Native birth identity, matching Runtime's startup_identity.rs validator at
/// ea25213b0a58fe2f306104d95888c2f639cda374. Do not substitute a PID or timestamp.
pub(crate) fn process_birth(pid: u32) -> Result<Option<String>> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_purpose_rejects_a_foreign_phase() -> Result<()> {
        for (purpose, accepted) in [
            (LaunchPurpose::Account, vec![Phase::Paused]),
            (LaunchPurpose::AccountComplete, vec![Phase::Verified]),
            (
                LaunchPurpose::Serving,
                vec![Phase::Starting, Phase::Verified],
            ),
        ] {
            for phase in [Phase::Paused, Phase::Starting, Phase::Verified] {
                assert_eq!(
                    validate_purpose_phase(purpose, phase).is_ok(),
                    accepted.contains(&phase)
                );
            }
        }
        Ok(())
    }

    #[test]
    fn serving_arguments_cannot_carry_arbitrary_options_or_credentials() -> Result<()> {
        let mut grant: HostControlLaunchGrant = serde_json::from_value(serde_json::json!({
            "schema_version": 1, "protocol_version": crate::PROTOCOL_V,
            "nonce": "synthetic", "instance_id": "synthetic", "installation_root": "/synthetic/root",
            "installation_id": "synthetic", "profile": "/synthetic/profile", "account_id": "synthetic",
            "sync_generation": 0, "image_path": "/synthetic/runtime", "image_sha256": "synthetic",
            "supervisor_pid": 4242, "supervisor_birth": "19", "managed_id": null,
            "registration_sha256": null, "maintenance": null, "port": 9876,
            "issued_at_ms": 1, "expires_at_ms": 60001,
        }))?;
        let expected: Vec<std::ffi::OsString> = [
            "serve",
            "--data-dir",
            "/synthetic/root",
            "--host",
            "127.0.0.1",
            "--port",
            "9876",
        ]
        .into_iter()
        .map(Into::into)
        .collect();
        assert_eq!(serving_arguments(&grant), expected);
        grant.managed_id = Some("synthetic-registration".into());
        let mut supervised = expected;
        supervised.push("--supervised".into());
        assert_eq!(serving_arguments(&grant), supervised);
        Ok(())
    }

    #[test]
    fn grants_preserve_account_identity_or_explicit_profile_fallback() {
        let profile = Path::new("/synthetic/profile");
        let expected = hash(profile.display().to_string().as_bytes());
        assert_eq!(
            grant_account_id(profile, &HostAuthIdentity::Absent),
            expected
        );
        assert_eq!(
            grant_account_id(
                profile,
                &HostAuthIdentity::Unbound {
                    operation_id: "synthetic-operation".into(),
                    session_sha256: "synthetic-session".into(),
                }
            ),
            expected
        );
        assert_eq!(
            grant_account_id(
                profile,
                &HostAuthIdentity::Bound {
                    account_id: "synthetic-account".into(),
                    session_sha256: "synthetic-session".into(),
                }
            ),
            "synthetic-account"
        );
    }

    #[test]
    fn grant_expiry_is_exactly_one_minute_and_checked() -> Result<()> {
        assert_eq!(expires_at_ms(1)?, 60_001);
        assert_eq!(expires_at_ms(u64::MAX - 60_000)?, u64::MAX);
        assert!(expires_at_ms(u64::MAX - 59_999).is_err());
        Ok(())
    }

    #[test]
    fn linux_birth_is_native_numeric_nonzero_and_not_dead() -> Result<()> {
        let fields = (1..=20)
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(
            linux_process_birth(&format!("123 (owner ) name) S {fields}"))?,
            Some("19".into())
        );
        for state in ["Z", "X"] {
            assert!(linux_process_birth(&format!("123 (owner) {state} {fields}"))?.is_none());
        }
        for raw in ["invalid", "123 (owner) S 1 2"] {
            assert!(linux_process_birth(raw).is_err());
        }
        for birth in ["0", "nonnumeric", "-1", "18446744073709551616"] {
            let invalid = (1..=20)
                .map(|value| {
                    if value == 19 {
                        birth.to_owned()
                    } else {
                        value.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");
            assert!(linux_process_birth(&format!("123 (owner) S {invalid}")).is_err());
        }
        assert!(process_birth(0).is_err());
        Ok(())
    }

    #[test]
    fn hash_is_the_protocol_sha256_hex() {
        assert_eq!(
            hash(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
