//! Synthetic records only: no account, keyring, network or installed service use.
use super::*;
use std::time::Duration;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self> {
        let path =
            std::env::temp_dir().join(format!("respire-maintenance-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&path)?;
        Ok(Self(path.canonicalize()?))
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct NeverHost {
    root: PathBuf,
}
impl HostLifecycle for NeverHost {
    fn require_account_write(&self) -> Result<()> {
        anyhow::bail!("synthetic write gate denied")
    }
    fn verified_runtime(&self) -> Result<VerifiedRuntime> {
        anyhow::bail!("synthetic host has no executable")
    }
    fn issuer_version(&self) -> &str {
        "synthetic-1"
    }
    fn inspect_registration(&self, _root: &Path) -> Result<RegistrationMode> {
        anyhow::bail!("must not inspect registration")
    }
    fn set_maintenance(&self, _root: &Path, _enabled: bool) -> Result<()> {
        anyhow::bail!("must not mutate registration")
    }
    fn probe_runtime(&self) -> Result<Option<Health>> {
        anyhow::bail!("must not probe network")
    }
    fn endpoint_path(&self) -> PathBuf {
        self.root.join("endpoint.json")
    }
    fn drain_runtime(&self, _health: &Health) -> Result<()> {
        anyhow::bail!("must not drain")
    }
    fn start_account_runtime(&self, _launch: &LaunchContext) -> Result<()> {
        anyhow::bail!("must not launch")
    }
}

fn synthetic_marker() -> Result<Marker> {
    Ok(Marker {
        schema: 1,
        id: "synthetic-owner".into(),
        token: uuid::Uuid::new_v4().to_string(),
        phase: Phase::Paused,
        expected_profile: None,
        expected_version: "synthetic-1".into(),
        owner_pid: std::process::id(),
        owner_birth: process_birth(std::process::id())?.context("test process birth missing")?,
        snapshot: None,
        agent_config: None,
    })
}

struct ActiveReset;
impl Drop for ActiveReset {
    fn drop(&mut self) {
        ACTIVE.with(|value| *value.borrow_mut() = None);
    }
}
fn activate(marker: &Marker) -> ActiveReset {
    ACTIVE.with(|slot| *slot.borrow_mut() = Some(marker.token.clone()));
    ActiveReset
}

#[test]
fn marker_parser_rejects_unknown_or_invalid_ownership_fields() -> Result<()> {
    let marker = synthetic_marker()?;
    let mut value = serde_json::to_value(&marker)?;
    value["external_authorized"] = Value::Bool(true);
    assert!(parse_marker(&serde_json::to_vec(&value)?).is_err());
    for field in ["id", "token", "expected_version", "owner_birth"] {
        let mut value = serde_json::to_value(&marker)?;
        value[field] = Value::String(String::new());
        assert!(parse_marker(&serde_json::to_vec(&value)?).is_err());
    }
    let mut value = serde_json::to_value(&marker)?;
    value["owner_pid"] = Value::from(0);
    assert!(parse_marker(&serde_json::to_vec(&value)?).is_err());
    Ok(())
}

#[test]
fn exact_owner_rejects_equivalent_json_with_different_bytes() -> Result<()> {
    let marker = synthetic_marker()?;
    let _active = activate(&marker);
    let compact = serde_json::to_vec(&marker)?;
    ensure_exact_owner(&marker, &marker, &compact, &hash(&compact))?;
    let formatted = serde_json::to_vec_pretty(&marker)?;
    assert!(ensure_exact_owner(&marker, &marker, &formatted, &hash(&compact)).is_err());
    Ok(())
}

#[test]
fn exact_owner_rejects_phase_pid_birth_token_and_selection_changes() -> Result<()> {
    let marker = synthetic_marker()?;
    let _active = activate(&marker);
    let mut variants = Vec::new();
    let mut changed = marker.clone();
    changed.phase = Phase::Verified;
    variants.push(changed);
    let mut changed = marker.clone();
    changed.owner_pid = u32::MAX;
    variants.push(changed);
    let mut changed = marker.clone();
    changed.owner_birth.push_str("-changed");
    variants.push(changed);
    let mut changed = marker.clone();
    changed.token = uuid::Uuid::new_v4().to_string();
    variants.push(changed);
    let mut changed = marker.clone();
    changed.expected_profile = Some(PathBuf::from("/foreign"));
    variants.push(changed);
    for actual in variants {
        let bytes = serde_json::to_vec(&actual)?;
        assert!(ensure_exact_owner(&actual, &marker, &bytes, &hash(&bytes)).is_err());
    }
    ACTIVE.with(|slot| *slot.borrow_mut() = None);
    let bytes = serde_json::to_vec(&marker)?;
    assert!(ensure_exact_owner(&marker, &marker, &bytes, &hash(&bytes)).is_err());
    Ok(())
}

#[test]
fn exact_owner_rejects_recycled_process_birth_even_when_records_match() -> Result<()> {
    let mut marker = synthetic_marker()?;
    marker.owner_birth.push_str("-recycled");
    let _active = activate(&marker);
    let bytes = serde_json::to_vec(&marker)?;
    assert!(ensure_exact_owner(&marker, &marker, &bytes, &hash(&bytes)).is_err());
    Ok(())
}

#[test]
fn completion_role_never_promotes_paused_or_starting() -> Result<()> {
    for phase in [Phase::Paused, Phase::Starting, Phase::Verified] {
        assert_eq!(
            ensure_purpose(LaunchPurpose::Account, phase).is_ok(),
            phase == Phase::Paused
        );
        assert_eq!(
            ensure_purpose(LaunchPurpose::AccountComplete, phase).is_ok(),
            phase == Phase::Verified
        );
        assert_eq!(
            ensure_purpose(LaunchPurpose::Serving, phase).is_ok(),
            phase != Phase::Paused
        );
    }
    Ok(())
}

#[test]
fn publication_is_private_bounded_and_exact_compare_and_replace() -> Result<()> {
    let directory = Directory::new()?;
    let path = marker_path(directory.path());
    let initial = b"initial synthetic marker";
    private_write(&path, initial, None)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
    }
    assert!(private_write(&path, b"foreign", None).is_err());
    assert!(private_write(&path, b"foreign", Some("wrong-digest")).is_err());
    assert_eq!(fs::read(&path)?, initial);
    assert!(private_write(
        &path,
        &vec![b'x'; MAINTENANCE_MARKER_MAX_BYTES + 1],
        Some(&hash(initial))
    )
    .is_err());
    assert_eq!(fs::read(&path)?, initial);
    private_write(&path, b"next", Some(&hash(initial)))?;
    assert_eq!(fs::read(&path)?, b"next");
    fs::remove_file(&path)?;
    assert!(private_write(&path, b"unexpected recreation", Some(&hash(b"next"))).is_err());
    assert!(!path.try_exists()?);
    Ok(())
}

#[test]
fn bounded_marker_rejects_directory_and_oversized_file() -> Result<()> {
    let directory = Directory::new()?;
    let path = marker_path(directory.path());
    fs::create_dir_all(&path)?;
    assert!(marker_bytes(directory.path()).is_err());
    fs::remove_dir(&path)?;
    fs::write(&path, vec![b'x'; MAINTENANCE_MARKER_MAX_BYTES + 1])?;
    assert!(marker_bytes(directory.path()).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn marker_and_parent_symlinks_are_never_replaced() -> Result<()> {
    use std::os::unix::fs::symlink;
    let directory = Directory::new()?;
    let outside = Directory::new()?;
    let target = outside.path().join("sentinel");
    fs::write(&target, b"untouched")?;
    let path = marker_path(directory.path());
    fs::create_dir_all(path.parent().context("marker parent missing")?)?;
    symlink(&target, &path)?;
    assert!(marker_bytes(directory.path()).is_err());
    assert!(private_write(&path, b"foreign", Some(&hash(b"untouched"))).is_err());
    fs::remove_file(&path)?;
    let linked = directory.path().join("linked");
    symlink(outside.path(), &linked)?;
    assert!(private_write(&linked.join("new"), b"foreign", None).is_err());
    assert_eq!(fs::read(&target)?, b"untouched");
    assert!(!outside.path().join("new").try_exists()?);
    Ok(())
}

#[test]
fn failure_drop_retains_durable_marker_and_revokes_live_token() -> Result<()> {
    let directory = Directory::new()?;
    let marker = synthetic_marker()?;
    let bytes = serde_json::to_vec(&marker)?;
    private_write(&marker_path(directory.path()), &bytes, None)?;
    let _active = activate(&marker);
    let owner = Maintenance {
        root: directory.path().to_path_buf(),
        host: Arc::new(NeverHost {
            root: directory.path().to_path_buf(),
        }),
        registration: RegistrationMode::Unregistered,
        marker,
        marker_digest: hash(&bytes),
        drained: false,
        original_health: None,
        account_origin: None,
        account_record: None,
        completed: false,
    };
    drop(owner);
    assert_eq!(marker_bytes(directory.path())?, Some(bytes));
    assert!(current_boot_token().is_none());
    Ok(())
}

#[test]
fn denied_write_gate_precedes_any_marker_or_registration_action() -> Result<()> {
    let directory = Directory::new()?;
    let lock = LibraryLock::acquire(&directory.path().join("runtime/takeover"), Duration::ZERO)?;
    let host = Arc::new(NeverHost {
        root: directory.path().to_path_buf(),
    });
    let result = Maintenance::begin_locked(&lock, host, RecoveryMode::Fresh);
    assert!(result.is_err());
    assert!(!marker_path(directory.path()).try_exists()?);
    Ok(())
}

#[test]
fn registration_cannot_be_silently_treated_as_absent() -> Result<()> {
    let directory = Directory::new()?;
    validate_registration_mode(directory.path(), &RegistrationMode::Unregistered)?;
    let path = directory.path().join("runtime/autostart/registration.json");
    fs::create_dir_all(path.parent().context("registration parent missing")?)?;
    fs::write(&path, b"{}")?;
    assert!(validate_registration_mode(directory.path(), &RegistrationMode::Unregistered).is_err());
    #[cfg(unix)]
    {
        fs::remove_file(&path)?;
        std::os::unix::fs::symlink(directory.path().join("missing"), &path)?;
        assert!(
            validate_registration_mode(directory.path(), &RegistrationMode::Unregistered).is_err()
        );
    }
    Ok(())
}

#[test]
fn process_start_identity_requires_platform_prefix_and_exact_birth() {
    let prefix = if cfg!(windows) {
        "windows-filetime-"
    } else if cfg!(target_os = "linux") {
        "linux-starttime-"
    } else {
        "darwin-lstart-"
    };
    assert!(process_start_matches("123", &format!("{prefix}123")));
    assert!(!process_start_matches("123", &format!("{prefix}1234")));
    assert!(!process_start_matches("123", "123"));
    assert!(!process_start_matches("", prefix));
}

fn observed_fixture() -> Result<(
    Directory,
    Health,
    respire_commands::net_rpc::RuntimeProcessIdentity,
    String,
)> {
    let directory = Directory::new()?;
    let image = directory.path().join("old-rsrs-runtime");
    fs::write(&image, b"synthetic old Runtime image")?;
    let digest = crate::launch::hash_file(&image)?;
    let prefix = if cfg!(windows) {
        "windows-filetime-"
    } else if cfg!(target_os = "linux") {
        "linux-starttime-"
    } else {
        "darwin-lstart-"
    };
    let process = respire_commands::net_rpc::RuntimeProcessIdentity {
        executable: image.display().to_string(),
        started_at: "observed-birth".into(),
    };
    let health: Health = serde_json::from_value(serde_json::json!({
        "server":"respire", "bin":"synthetic-old", "runtime_version":"0.0.1-old",
        "pid":1234, "v":crate::PROTOCOL_V,
        "exe":image, "image_path":image, "image_sha256":digest,
        "process_start_id":format!("{prefix}observed-birth"),
        "installation_root":directory.path(), "data_dir":directory.path(),
        "installation_id":hash(directory.path().display().to_string().as_bytes()),
        "instance_id":"observed-instance", "account_id":"observed-account", "generation":7,
        "store_ready":true,
    }))?;
    Ok((directory, health, process, digest))
}

#[test]
fn observed_drain_matches_old_image_not_selected_replacement() -> Result<()> {
    let (directory, health, process, old_digest) = observed_fixture()?;
    let replacement = directory.path().join("new-rsrs-runtime");
    fs::write(&replacement, b"synthetic new Runtime image")?;
    let new_digest = crate::launch::hash_file(&replacement)?;
    assert_ne!(old_digest, new_digest);
    verify_observed_process(&health, &process, &old_digest)?;
    assert!(verify_observed_process(&health, &process, &new_digest).is_err());
    Ok(())
}

#[test]
fn observed_drain_rejects_recycled_birth_before_typed_stop() -> Result<()> {
    let (_directory, health, mut process, digest) = observed_fixture()?;
    process.started_at = "replacement-birth".into();
    let sent = Cell::new(false);
    let result = (|| -> Result<()> {
        verify_observed_process(&health, &process, &digest)?;
        sent.set(true);
        Ok(())
    })();
    assert!(result.is_err());
    assert!(!sent.get());
    Ok(())
}

#[test]
fn observed_drain_rejects_changed_image_and_executable() -> Result<()> {
    let (directory, mut health, process, digest) = observed_fixture()?;
    fs::write(&process.executable, b"replaced old Runtime bytes")?;
    let replaced = crate::launch::hash_file(Path::new(&process.executable))?;
    assert!(verify_observed_process(&health, &process, &replaced).is_err());
    let foreign = directory.path().join("foreign-executable");
    fs::write(&foreign, b"synthetic foreign image")?;
    health.exe = foreign.display().to_string();
    assert!(verify_observed_process(&health, &process, &digest).is_err());
    health.exe = process.executable.clone();
    health.image_path = foreign.display().to_string();
    assert!(verify_observed_process(&health, &process, &digest).is_err());
    Ok(())
}

#[test]
fn observed_drain_rejects_incomplete_or_incompatible_stop_scope() -> Result<()> {
    let (_directory, health, process, digest) = observed_fixture()?;
    let mut variants = Vec::new();
    let mut changed = health.clone();
    changed.pid = 0;
    variants.push(changed);
    let mut changed = health.clone();
    changed.v = crate::PROTOCOL_V.saturating_add(1);
    variants.push(changed);
    let mut changed = health.clone();
    changed.instance_id.clear();
    variants.push(changed);
    let mut changed = health.clone();
    changed.account_id.clear();
    variants.push(changed);
    let mut changed = health.clone();
    changed.generation = 0;
    variants.push(changed);
    let mut changed = health.clone();
    changed.runtime_version.clear();
    variants.push(changed);
    let mut changed = health.clone();
    changed.image_sha256 = "not-a-digest".into();
    variants.push(changed);
    for variant in variants {
        assert!(verify_observed_process(&variant, &process, &digest).is_err());
    }
    Ok(())
}

#[test]
fn observed_drain_rejects_foreign_root_and_selected_profile() -> Result<()> {
    let (directory, health, _process, _digest) = observed_fixture()?;
    let foreign = Directory::new()?;
    verify_health_roots(&health, directory.path(), directory.path())?;
    assert!(verify_health_roots(&health, foreign.path(), directory.path()).is_err());
    assert!(verify_health_roots(&health, directory.path(), foreign.path()).is_err());
    Ok(())
}
