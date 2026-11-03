//! Local snapshot inventory. Manifests describe files; they never grant access.
use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    pub id: String,
    pub created_at: String,
    pub note: String,
    pub database_sha256: String,
    pub bytes: u64,
    pub entries: u64,
    pub source_library: String,
    pub account_fingerprint: String,
    pub sqlite_user_version: i64,
    pub database_schema_sha256: String,
    pub sdk_version: String,
    pub sdk_abi: u32,
    pub model: String,
    #[serde(default)]
    pub witness_head: Option<String>,
    #[serde(default)]
    pub witness_count: Option<u64>,
    #[serde(default)]
    pub witness_intact: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_problem: Option<String>,
}

fn private_dir(path: &Path) -> Result<()> {
    if path.exists() {
        let meta = fs::symlink_metadata(path)?;
        anyhow::ensure!(
            meta.is_dir() && !meta.file_type().is_symlink(),
            "snapshot directory must be a real directory"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            anyhow::ensure!(
                meta.permissions().mode() & 0o077 == 0,
                "snapshot directory is not private; host operator must restrict it to mode 0700"
            );
        }
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(path)?;
        }
        #[cfg(not(unix))]
        fs::create_dir(path)?;
    }
    Ok(())
}

fn private_new(path: &Path) -> Result<fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

fn digest_file(path: &Path) -> Result<String> {
    let meta = fs::symlink_metadata(path)?;
    anyhow::ensure!(
        meta.is_file() && !meta.file_type().is_symlink(),
        "snapshot must be a regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        anyhow::ensure!(
            meta.permissions().mode() & 0o077 == 0,
            "snapshot file is not private"
        );
    }
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn inventory(path: &Path) -> Result<(u64, i64)> {
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    db.busy_timeout(std::time::Duration::from_secs(2))?;
    let check: String = db.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    anyhow::ensure!(check == "ok", "snapshot integrity check failed");
    let grants: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='access_grants')",
        [],
        |row| row.get(0),
    )?;
    if grants {
        let count: u64 =
            db.query_row("SELECT count(*) FROM access_grants", [], |row| row.get(0))?;
        anyhow::ensure!(count == 0, "snapshot must not contain access grants");
    }
    Ok((
        db.query_row("SELECT count(*) FROM memories", [], |row| row.get(0))?,
        db.query_row("PRAGMA user_version", [], |row| row.get(0))?,
    ))
}

fn schema_digest(path: &Path) -> Result<String> {
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut statement=db.prepare("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' AND name<>'snapshot_key_check' ORDER BY type,name")?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let version: i64 = db.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&(version, rows))?)
    ))
}

fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn sdk_target() -> Result<String> {
    let arch = std::env::consts::ARCH;
    if cfg!(target_os = "windows") { return Ok(format!("{arch}-pc-windows-msvc")); }
    if cfg!(target_os = "macos") { return Ok(format!("{arch}-apple-darwin")); }
    if cfg!(target_os = "linux") {
        let env = if cfg!(target_env = "musl") { "musl" } else { "gnu" };
        return Ok(format!("{arch}-unknown-linux-{env}"));
    }
    anyhow::bail!("snapshot SDK target is unsupported")
}

pub fn create(
    root: &Path,
    account: &str,
    note: &str,
    keys: &crate::SessionKeys,
) -> Result<Manifest> {
    anyhow::ensure!(
        note.chars().count() <= 1000,
        "snapshot note exceeds 1000 characters"
    );
    let source = crate::service::database_path(root)?;
    reject_live_symlink(&source)?;
    anyhow::ensure!(source.is_file(), "snapshot requires an existing library");
    let directory = root.join("snapshots");
    private_dir(&directory)?;
    let id = uuid::Uuid::new_v4().simple().to_string();
    let database = directory.join(format!("{id}.db"));
    let temporary = directory.join(format!(".{id}.json.tmp"));
    let published = directory.join(format!("{id}.json"));
    // backup_database owns cleanup if its exclusive creation fails; never
    // remove a file that was present before our successful backup operation.
    crate::service::backup_database(&source, &database)?;
    let result = (|| -> Result<Manifest> {
        let (entries, sqlite_user_version) = inventory(&database)?;
        let lock: serde_json::Value =
            serde_json::from_str(include_str!("../../core-sdk/core-sdk.lock.json"))?;
        let sdk_version = lock["targets"][sdk_target()?]["sdk_version"]
            .as_str().context("snapshot SDK target version missing")?.to_owned();
        let source_library = format!(
            "{:x}",
            Sha256::digest(fs::canonicalize(&source)?.to_string_lossy().as_bytes())
        );
        let account_fingerprint = format!("{:x}", Sha256::digest(account.as_bytes()));
        let database_schema_sha256 = schema_digest(&database)?;
        let challenge =
            format!("snapshot-key-check:v1:{id}:{source_library}:{account_fingerprint}");
        let (nonce, ciphertext) = keys.encrypt_content(&challenge)?;
        {
            let copy = Connection::open(&database)?;
            copy.execute_batch("DROP TABLE IF EXISTS snapshot_key_check; CREATE TABLE snapshot_key_check(singleton INTEGER PRIMARY KEY CHECK(singleton=1),nonce TEXT NOT NULL,ciphertext TEXT NOT NULL);")?;
            copy.execute(
                "INSERT INTO snapshot_key_check VALUES(1,?1,?2)",
                rusqlite::params![nonce, ciphertext],
            )?;
        }
        // A diagnostic pre-restore backup must preserve a damaged ledger too.
        // Restore targets remain fail-closed in read_manifest below.
        let (witness, witness_problem) =
            match crate::transport::local::witness_checkpoint_file(&database) {
                Ok(report) => (report, None),
                Err(_) => (
                    None,
                    Some("witness checkpoint is unverifiable; diagnostic copy only".to_owned()),
                ),
            };
        let manifest = Manifest {
            schema_version: 1,
            id,
            created_at: chrono::Utc::now().to_rfc3339(),
            note: note.to_owned(),
            database_sha256: digest_file(&database)?,
            bytes: fs::metadata(&database)?.len(),
            entries,
            source_library,
            account_fingerprint,
            database_schema_sha256,
            sqlite_user_version,
            sdk_version,
            sdk_abi: crate::core_sdk::ABI_VERSION,
            model: {
                let copy = Connection::open_with_flags(&database,OpenFlags::SQLITE_OPEN_READ_ONLY)?;
                let snapshot: Option<String> = copy.query_row("SELECT value FROM meta WHERE key=?1",[crate::core_sdk::profiles::ACTIVE_SELECTION_KEY],|r|r.get(0)).optional()?;
                snapshot.map(|v| serde_json::from_str::<crate::core_sdk::profiles::Selection>(&v).map(|s|s.model)).transpose()?.unwrap_or_else(||"m3".to_owned())
            },
            witness_head: witness.as_ref().map(|report| report.head.clone()),
            witness_count: witness.as_ref().map(|report| report.count),
            witness_intact: if witness_problem.is_some() {
                Some(false)
            } else {
                witness.as_ref().map(|report| report.intact)
            },
            witness_problem,
        };
        let mut file = private_new(&temporary)?;
        file.write_all(&serde_json::to_vec_pretty(&manifest)?)?;
        file.sync_all()?;
        drop(file);
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&database)?
            .sync_all()?;
        // An atomic, no-overwrite publication: a crash before this leaves no
        // visible manifest, and an existing manifest can never be overwritten.
        respire_spawn::durable::publish_new_file(&temporary, &published)?;
        respire_spawn::durable::sync_directory(root)?;
        Ok(manifest)
    })();
    if result.is_err() {
        // Only this invocation's UUID files are eligible for failure cleanup.
        let _ = fs::remove_file(&temporary);
        if !published.exists() {
            fs::remove_file(&database).context("failed to clean incomplete snapshot")?;
        }
    }
    result
}

#[derive(Debug, Serialize)]
pub struct SnapshotProblem {
    pub id: String,
    pub error: String,
}
#[derive(Debug, Serialize)]
pub struct SnapshotInventory {
    pub snapshots: Vec<Manifest>,
    pub problems: Vec<SnapshotProblem>,
}

fn read_manifest(root: &Path, id: &str) -> Result<Manifest> {
    anyhow::ensure!(valid_id(id), "snapshot requires a full snapshot ID");
    let directory = root.join("snapshots");
    private_dir(&directory)?;
    let path = directory.join(format!("{id}.json"));
    let metadata = fs::symlink_metadata(&path)?;
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= 1048576,
        "invalid snapshot manifest file"
    );
    let manifest: Manifest = serde_json::from_slice(&fs::read(&path)?)?;
    anyhow::ensure!(
        manifest.schema_version == 1 && manifest.id == id,
        "unsupported snapshot manifest or identity mismatch"
    );
    chrono::DateTime::parse_from_rfc3339(&manifest.created_at)
        .context("invalid snapshot timestamp")?;
    let database = directory.join(format!("{id}.db"));
    anyhow::ensure!(
        manifest.bytes == fs::metadata(&database)?.len()
            && manifest.database_sha256 == digest_file(&database)?,
        "snapshot digest mismatch"
    );
    anyhow::ensure!(
        schema_digest(&database)? == manifest.database_schema_sha256,
        "snapshot schema digest mismatch"
    );
    anyhow::ensure!(
        manifest.witness_problem.is_none(),
        "snapshot witness checkpoint is unverifiable; diagnostic copy cannot be a restore target"
    );
    match crate::transport::local::witness_checkpoint_file(&database)? {
        None => anyhow::ensure!(
            manifest.witness_head.is_none()
                && manifest.witness_count.is_none()
                && manifest.witness_intact.is_none(),
            "snapshot witness checkpoint exists without a witness schema"
        ),
        Some(report) => {
            anyhow::ensure!(
                manifest.witness_head.as_ref() == Some(&report.head)
                    && manifest.witness_count == Some(report.count)
                    && manifest.witness_intact == Some(report.intact),
                "snapshot witness checkpoint mismatch or missing checkpoint"
            );
            anyhow::ensure!(
                report.intact,
                "snapshot witness chain is invalid; preserve the copy for explicit recovery/repair"
            );
        }
    }
    let (entries, version) = inventory(&database)?;
    anyhow::ensure!(
        entries == manifest.entries && version == manifest.sqlite_user_version,
        "snapshot inventory mismatch"
    );
    Ok(manifest)
}

pub(crate) fn verify_backup(root: &Path, id: &str, keys: &crate::SessionKeys) -> Result<Manifest> {
    let manifest = read_manifest(root, id)?;
    verify_key(&root.join("snapshots").join(format!("{id}.db")), &manifest, keys)?;
    Ok(manifest)
}

pub fn list_report(root: &Path) -> Result<SnapshotInventory> {
    let directory = root.join("snapshots");
    if !directory.exists() {
        return Ok(SnapshotInventory {
            snapshots: Vec::new(),
            problems: Vec::new(),
        });
    }
    private_dir(&directory)?;
    let mut valid = Vec::new();
    let mut problems = Vec::new();
    for entry in fs::read_dir(&directory)? {
        let path = entry?.path();
        let Some(id) = path.file_stem().and_then(|v| v.to_str()) else {
            continue;
        };
        if path.extension().is_none_or(|v| v != "json") || !valid_id(id) {
            continue;
        }
        match read_manifest(root, id) {
            Ok(manifest) => valid.push((
                chrono::DateTime::parse_from_rfc3339(&manifest.created_at)?,
                manifest,
            )),
            Err(error) => problems.push(SnapshotProblem {
                id: id.to_owned(),
                error: error.to_string(),
            }),
        }
    }
    valid.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.id.cmp(&a.1.id)));
    problems.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(SnapshotInventory {
        snapshots: valid.into_iter().map(|(_, manifest)| manifest).collect(),
        problems,
    })
}

pub fn list(root: &Path) -> Result<Vec<Manifest>> {
    let report = list_report(root)?;
    anyhow::ensure!(
        report.problems.is_empty(),
        "snapshot inventory contains damaged entries; inspect snapshot list diagnostics"
    );
    Ok(report.snapshots)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreReceipt {
    pub restored: String,
    pub before_restore: String,
    pub sync_quarantined: bool,
    #[serde(skip_serializing)]
    rollback_file: String,
    #[serde(skip_serializing)]
    rollback_sha256: String,
    #[serde(skip_serializing)]
    account_fingerprint: String,
}

#[derive(Serialize, Deserialize)]
struct RecoveryJournal {
    schema_version: u32,
    phase: String,
    receipt: RecoveryReceipt,
}
#[derive(Serialize, Deserialize)]
struct RecoveryReceipt {
    restored: String,
    before_restore: String,
    rollback_file: String,
    rollback_sha256: String,
    account_fingerprint: String,
}
impl From<&RestoreReceipt> for RecoveryReceipt {
    fn from(value: &RestoreReceipt) -> Self {
        Self {
            restored: value.restored.clone(),
            before_restore: value.before_restore.clone(),
            rollback_file: value.rollback_file.clone(),
            rollback_sha256: value.rollback_sha256.clone(),
            account_fingerprint: value.account_fingerprint.clone(),
        }
    }
}
impl From<RecoveryReceipt> for RestoreReceipt {
    fn from(value: RecoveryReceipt) -> Self {
        Self {
            restored: value.restored,
            before_restore: value.before_restore,
            sync_quarantined: true,
            rollback_file: value.rollback_file,
            rollback_sha256: value.rollback_sha256,
            account_fingerprint: value.account_fingerprint,
        }
    }
}
const RECOVERY_FILE: &str = ".snapshot-recovery.json";
const MAINTENANCE_FILE: &str = ".snapshot-maintenance.json";

fn reject_live_symlink(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "live database symbolic links and non-regular files are not supported for snapshots"
    );
    Ok(())
}
fn write_journal(root: &Path, receipt: &RestoreReceipt, phase: &str) -> Result<()> {
    write_record(root, receipt, phase, RECOVERY_FILE)
}
fn write_record(root: &Path, receipt: &RestoreReceipt, phase: &str, name: &str) -> Result<()> {
    let temporary = root.join(format!(
        ".snapshot-journal-{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    let mut file = private_new(&temporary)?;
    file.write_all(&serde_json::to_vec(&RecoveryJournal {
        schema_version: 1,
        phase: phase.to_owned(),
        receipt: receipt.into(),
    })?)?;
    file.sync_all()?;
    drop(file);
    respire_spawn::durable::replace_file(&temporary, &root.join(name))?;
    Ok(())
}
fn read_journal(root: &Path) -> Result<Option<RecoveryJournal>> {
    let mut found = None;
    for name in [RECOVERY_FILE, MAINTENANCE_FILE] {
        let path = root.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                found = Some((path, metadata));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let Some((path, meta)) = found else {
        return Ok(None);
    };
    anyhow::ensure!(
        meta.is_file() && !meta.file_type().is_symlink() && meta.len() < 65536,
        "invalid snapshot recovery journal file"
    );
    let journal: RecoveryJournal = serde_json::from_slice(&fs::read(path)?)?;
    anyhow::ensure!(
        journal.schema_version == 1
            && matches!(
                journal.phase.as_str(),
                "prepared" | "installed" | "verified"
            ),
        "unsupported snapshot recovery journal"
    );
    let name = &journal.receipt.rollback_file;
    let id = name
        .strip_prefix(".snapshot-rollback-")
        .and_then(|name| name.strip_suffix(".db"))
        .context("invalid snapshot rollback filename")?;
    anyhow::ensure!(valid_id(id), "invalid snapshot rollback identity");
    Ok(Some(journal))
}

fn maintenance_present(root: &Path) -> Result<bool> {
    match fs::symlink_metadata(root.join(MAINTENANCE_FILE)) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub fn ensure_no_incomplete_restore(root: &Path) -> Result<()> {
    anyhow::ensure!(
        !maintenance_present(root)?,
        "snapshot maintenance blocks normal library access; host recovery/commit is required"
    );
    if let Some(journal) = read_journal(root)? {
        anyhow::ensure!(journal.phase=="verified","interrupted snapshot restore; host must run snapshot recover --confirm before opening the library");
    }
    Ok(())
}

/// Only the runtime holding library ownership can bootstrap the staged store.
/// This does not release the maintenance gate for any business request.
pub fn runtime_bootstrap_target(root: &Path) -> Result<Option<String>> {
    let Some(journal) = read_journal(root)? else {
        return Ok(None);
    };
    anyhow::ensure!(
        matches!(journal.phase.as_str(), "installed" | "verified"),
        "snapshot restore preparation is incomplete; recover before startup"
    );
    Ok(Some(journal.receipt.restored))
}

fn checkpoint_closed(live: &Path) -> Result<()> {
    reject_live_symlink(live)?;
    let connection = Connection::open_with_flags(live, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    connection.busy_timeout(std::time::Duration::from_millis(300))?;
    let (busy, log, checkpointed): (i64, i64, i64) =
        connection.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
    anyhow::ensure!(
        busy == 0 && (log == checkpointed || log < 0),
        "snapshot restore checkpoint is busy; original library retained"
    );
    connection.execute_batch("PRAGMA locking_mode=EXCLUSIVE; BEGIN EXCLUSIVE; COMMIT;")?;
    drop(connection);
    for suffix in ["-wal", "-shm"] {
        let sidecar = std::path::PathBuf::from(format!("{}{suffix}", live.to_string_lossy()));
        anyhow::ensure!(
            !sidecar.exists(),
            "snapshot restore found an active SQLite sidecar; library was not replaced"
        );
    }
    Ok(())
}
fn copy_private(source: &Path, destination: &Path) -> Result<()> {
    let mut target = private_new(destination)?;
    let mut input = fs::File::open(source)?;
    std::io::copy(&mut input, &mut target)?;
    target.sync_all()?;
    Ok(())
}

/// Hold the matching library ownership guard throughout prepare and commit.
/// The private rollback image retains grants and is never a portable snapshot.
pub fn restore_locked(
    root: &Path,
    account: &str,
    keys: &crate::SessionKeys,
    id: &str,
    ownership: &crate::lock::LibraryLock,
) -> Result<RestoreReceipt> {
    restore_with_hook(root, account, keys, id, ownership, &|_| Ok(()))
}
fn restore_with_hook(
    root: &Path,
    account: &str,
    keys: &crate::SessionKeys,
    id: &str,
    ownership: &crate::lock::LibraryLock,
    hook: &dyn Fn(&str) -> Result<()>,
) -> Result<RestoreReceipt> {
    anyhow::ensure!(
        ownership.protects(root)?,
        "snapshot restore requires ownership of this library"
    );
    anyhow::ensure!(
        read_journal(root)?.is_none(),
        "an earlier snapshot recovery is pending; run snapshot recover --confirm"
    );
    let live = crate::service::database_path(root)?;
    reject_live_symlink(&live)?;
    let selected = read_manifest(root, id)?;
    let source_library = format!(
        "{:x}",
        Sha256::digest(fs::canonicalize(&live)?.to_string_lossy().as_bytes())
    );
    let account_fingerprint = format!("{:x}", Sha256::digest(account.as_bytes()));
    anyhow::ensure!(
        selected.source_library == source_library
            && selected.account_fingerprint == account_fingerprint,
        "snapshot belongs to another account or library"
    );
    anyhow::ensure!(
        schema_digest(&live)? == selected.database_schema_sha256,
        "snapshot schema differs from the initialized library; explicit migration is required"
    );
    let source = root.join("snapshots").join(format!("{id}.db"));
    crate::metadata_gate::ensure_restore_allowed(&live, &source)?;
    verify_key(&source, &selected, keys)?;
    let before = create(root, account, &format!("before restore {id}"), keys)?;
    let rollback_file = format!(".snapshot-rollback-{}.db", uuid::Uuid::new_v4().simple());
    let rollback = root.join(&rollback_file);
    let rollback_build = root.join(format!(
        ".snapshot-rollback-build-{}.db",
        uuid::Uuid::new_v4().simple()
    ));
    crate::service::backup_database_policy(&live, &rollback_build, false)?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(&rollback_build)?
        .sync_all()?;
    respire_spawn::durable::publish_new_file(&rollback_build, &rollback)?;
    let receipt = RestoreReceipt {
        restored: id.to_owned(),
        before_restore: before.id,
        sync_quarantined: true,
        rollback_sha256: digest_file(&rollback)?,
        rollback_file,
        account_fingerprint,
    };
    // Durable receipt exists before the first operation that can replace live.
    write_record(root, &receipt, "prepared", MAINTENANCE_FILE)?;
    write_journal(root, &receipt, "prepared")?;
    let temporary = root.join(format!(
        ".snapshot-restore-{}.db",
        uuid::Uuid::new_v4().simple()
    ));
    let mut replacement_attempted = false;
    let result = (|| -> Result<()> {
        hook("after_backups")?;
        checkpoint_closed(&live)?;
        copy_private(&source, &temporary)?;
        anyhow::ensure!(
            digest_file(&temporary)? == selected.database_sha256,
            "snapshot changed during restore preparation"
        );
        verify_key(&temporary, &selected, keys)?;
        let staged = Connection::open(&temporary)?;
        staged.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA secure_delete=ON;")?;
        staged.execute("INSERT INTO meta(key,value) VALUES('snapshot_sync_quarantine_v1',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [serde_json::json!({"snapshot":id,"before_restore":receipt.before_restore}).to_string()])?;
        drop(staged);
        inventory(&temporary)?;
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&temporary)?
            .sync_all()?;
        hook("before_replace")?;
        // A durable replacement can report an fsync error after rename, so mark
        // the attempt before calling it. Either outcome rolls back from image.
        replacement_attempted = true;
        respire_spawn::durable::replace_file(&temporary, &live)?;
        hook("after_replace")?;
        crate::resident::clear()?;
        hook("after_cache_clear")?;
        write_journal(root, &receipt, "installed")?;
        hook("after_installed")?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        let rollback_result = if replacement_attempted {
            rollback_locked(root, &receipt, ownership)
        } else {
            clear_recovery(root, &receipt)
        };
        return match rollback_result {
            Ok(())=>Err(error.context(format!("restore aborted; original state retained/restored; pre-restore snapshot {}",receipt.before_restore))),
            Err(rollback_error)=>Err(error.context(format!("restore recovery required: {rollback_error:#}; journal {RECOVERY_FILE}; pre-restore snapshot {}",receipt.before_restore))),
        };
    }
    Ok(receipt)
}

/// Restore only this operation's original local image, including grants/outbox.
pub fn rollback_locked(
    root: &Path,
    receipt: &RestoreReceipt,
    ownership: &crate::lock::LibraryLock,
) -> Result<()> {
    anyhow::ensure!(
        ownership.protects(root)?,
        "rollback requires this library's ownership lock"
    );
    let journal = read_journal(root)?.context("snapshot recovery journal missing")?;
    anyhow::ensure!(
        journal.phase != "verified" || maintenance_present(root)?,
        "snapshot restore is committed; rollback would discard accepted writes"
    );
    anyhow::ensure!(
        journal.receipt.rollback_file == receipt.rollback_file
            && journal.receipt.rollback_sha256 == receipt.rollback_sha256,
        "rollback receipt differs from durable journal"
    );
    let original = root.join(&receipt.rollback_file);
    anyhow::ensure!(
        digest_file(&original)? == receipt.rollback_sha256,
        "local rollback image digest mismatch"
    );
    let live = crate::service::database_path(root)?;
    if let Err(error) = checkpoint_closed(&live) {
        let corrupt = error
            .chain()
            .filter_map(|cause| cause.downcast_ref::<rusqlite::Error>())
            .any(|error| {
                matches!(
                    error.sqlite_error_code(),
                    Some(rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase)
                )
            });
        let has_sidecars = ["-wal", "-shm"].iter().any(|suffix| {
            std::path::PathBuf::from(format!("{}{suffix}", live.to_string_lossy())).exists()
        });
        anyhow::ensure!(
            corrupt && !has_sidecars,
            "rollback checkpoint failed; original recovery image retained: {error}"
        );
    }
    let temporary = root.join(format!(
        ".snapshot-rollback-install-{}.db",
        uuid::Uuid::new_v4().simple()
    ));
    copy_private(&original, &temporary)?;
    if let Err(error) = respire_spawn::durable::replace_file(&temporary, &live) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    crate::resident::clear()?;
    clear_recovery(root, receipt)
}
fn remove_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
fn clear_recovery(root: &Path, receipt: &RestoreReceipt) -> Result<()> {
    clear_with_hook(root, receipt, &|_| Ok(()))
}
fn clear_with_hook(
    root: &Path,
    receipt: &RestoreReceipt,
    hook: &dyn Fn(&str) -> Result<()>,
) -> Result<()> {
    // Once verified is durable, gate removal is a one-way commit release. Any
    // later cleanup failure must retain the selected state, never roll it back.
    remove_if_present(&root.join(MAINTENANCE_FILE))?;
    hook("after_gate_removed")?;
    respire_spawn::durable::sync_directory(root)?;
    remove_if_present(&root.join(RECOVERY_FILE))?;
    respire_spawn::durable::sync_directory(root)?;
    remove_if_present(&root.join(&receipt.rollback_file))?;
    respire_spawn::durable::sync_directory(root)?;
    Ok(())
}

/// Persist commit while maintenance still blocks all normal requests. Failure
/// here is fatal and the caller must roll back before releasing its lifecycle lock.
pub fn commit_restore(root: &Path, receipt: &RestoreReceipt) -> Result<()> {
    commit_with_hook(root, receipt, &|_| Ok(()))
}
fn commit_with_hook(
    root: &Path,
    receipt: &RestoreReceipt,
    hook: &dyn Fn(&str) -> Result<()>,
) -> Result<()> {
    anyhow::ensure!(
        maintenance_present(root)?,
        "snapshot commit requires active maintenance gate"
    );
    let journal = read_journal(root)?.context("snapshot completion journal missing")?;
    anyhow::ensure!(
        journal.receipt.rollback_file == receipt.rollback_file
            && journal.receipt.rollback_sha256 == receipt.rollback_sha256,
        "snapshot completion receipt differs from durable journal"
    );
    hook("before_verified_write")?;
    write_journal(root, receipt, "verified")?;
    hook("after_verified_write")?;
    Ok(())
}

/// Only call after commit_restore returned success. Cleanup errors are warnings
/// about an already committed state and must never trigger original-state rollback.
pub fn release_restore(root: &Path, receipt: &RestoreReceipt) -> Result<()> {
    let journal = read_journal(root)?.context("snapshot release journal missing")?;
    anyhow::ensure!(
        journal.phase == "verified"
            && journal.receipt.rollback_file == receipt.rollback_file
            && journal.receipt.rollback_sha256 == receipt.rollback_sha256,
        "snapshot release is not the committed operation"
    );
    clear_recovery(root, receipt)
}

pub fn complete_restore(root: &Path, receipt: &RestoreReceipt) -> Result<()> {
    commit_restore(root, receipt)?;
    release_restore(root, receipt)
}

pub fn recover_locked(
    root: &Path,
    account: &str,
    ownership: &crate::lock::LibraryLock,
) -> Result<()> {
    anyhow::ensure!(
        ownership.protects(root)?,
        "recovery requires this library's ownership lock"
    );
    let journal = read_journal(root)?.context("no interrupted snapshot operation exists")?;
    let verified = journal.phase == "verified";
    let receipt: RestoreReceipt = journal.receipt.into();
    anyhow::ensure!(
        receipt.account_fingerprint == format!("{:x}", Sha256::digest(account.as_bytes())),
        "snapshot recovery belongs to another account"
    );
    if verified {
        clear_recovery(root, &receipt)
    } else {
        rollback_locked(root, &receipt, ownership)
    }
}

fn verify_key(path: &Path, manifest: &Manifest, keys: &crate::SessionKeys) -> Result<()> {
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let (nonce, ciphertext): (String, String) = db.query_row(
        "SELECT nonce,ciphertext FROM snapshot_key_check WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let challenge = format!(
        "snapshot-key-check:v1:{}:{}:{}",
        manifest.id, manifest.source_library, manifest.account_fingerprint
    );
    anyhow::ensure!(
        keys.decrypt_content(&ciphertext, &nonce)
            .context("snapshot key validation failed")?
            == challenge,
        "snapshot key identity mismatch"
    );
    let mut statement = db.prepare("SELECT ciphertext,nonce FROM memories WHERE ciphertext<>''")?;
    for row in statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })? {
        let (ciphertext, nonce) = row?;
        keys.decrypt_content(&ciphertext, &nonce)
            .context("snapshot contains content that cannot be opened by this account key")?;
    }
    Ok(())
}

pub fn ensure_sync_allowed(root: &Path) -> Result<()> {
    let path = crate::service::database_path(root)?;
    if !path.exists() {
        return Ok(());
    }
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let has_meta: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta')",
        [],
        |r| r.get(0),
    )?;
    if has_meta {
        crate::metadata_gate::ensure_connection_sync_allowed(&connection)?;
        let quarantined: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM meta WHERE key='snapshot_sync_quarantine_v1')",
            [],
            |r| r.get(0),
        )?;
        anyhow::ensure!(
            !quarantined,
            "snapshot restore quarantined sync; compare differences before snapshot resume-sync"
        );
    }
    Ok(())
}

pub fn resume_sync(root: &Path, reviewed_revision: &str) -> Result<()> {
    let database = crate::service::database_path(root)?;
    let connection = Connection::open_with_flags(&database, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    connection.execute_batch("BEGIN IMMEDIATE")?;
    ensure_no_incomplete_restore(root)?;
    crate::metadata_gate::ensure_connection_sync_allowed(&connection)?;
    let revision: String = connection.query_row(
        "SELECT value FROM meta WHERE key='memory_revision_v1'",
        [],
        |row| row.get(0),
    )?;
    anyhow::ensure!(
        revision == reviewed_revision,
        "library changed since the reviewed revision; sync remains quarantined"
    );
    connection.execute(
        "DELETE FROM meta WHERE key='snapshot_sync_quarantine_v1'",
        [],
    )?;
    connection.execute_batch("COMMIT")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Result<(tempfile::TempDir, Connection)> {
        let directory = tempfile::tempdir()?;
        let db = Connection::open(directory.path().join("rsrs.db"))?;
        db.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE memories(id TEXT PRIMARY KEY,ciphertext TEXT,nonce TEXT,user TEXT NOT NULL DEFAULT 'account',created_at TEXT NOT NULL DEFAULT '2026-01-01T00:00:00Z',updated_at TEXT NOT NULL DEFAULT '2026-01-01T00:00:00Z'); CREATE TABLE access_grants(id TEXT PRIMARY KEY,label TEXT,root_id TEXT,token_hash TEXT,created_at TEXT,revoked INTEGER DEFAULT 0); CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT); INSERT INTO meta VALUES('memory_revision_v1','0123456789abcdef0123456789abcdef'); INSERT INTO access_grants(id,label,root_id,token_hash,created_at) VALUES('synthetic-grant','fixture','synthetic','synthetic-private-grant-marker','2026-01-01');")?;
        let (nonce, ciphertext) =
            crate::SessionKeys::from_urk([7; 32])?.encrypt_content("encrypted-fixture")?;
        db.execute(
            "INSERT INTO memories(id,ciphertext,nonce) VALUES('synthetic',?1,?2)",
            rusqlite::params![ciphertext, nonce],
        )?;
        Ok((directory, db))
    }
    #[test]
    fn snapshot_captures_committed_wal_excludes_grants_and_preserves_source() -> Result<()> {
        let (directory, db) = fixture()?;
        let manifest = create(
            directory.path(),
            "synthetic-account",
            "first",
            &crate::SessionKeys::from_urk([7; 32])?,
        )?;
        assert_eq!(manifest.entries, 1);
        let pinned:serde_json::Value=serde_json::from_str(include_str!("../../core-sdk/core-sdk.lock.json"))?;
        let targets=pinned["targets"].as_object().context("pinned SDK targets")?;
        assert_eq!(targets.len(),7);
        assert_eq!(targets.get(&sdk_target()?).context("current SDK target")?["sdk_version"].as_str(), Some(manifest.sdk_version.as_str()));
        assert_eq!(list(directory.path())?.len(), 1);
        let copied = directory
            .path()
            .join("snapshots")
            .join(format!("{}.db", manifest.id));
        assert!(!fs::read(&copied)?
            .windows(b"synthetic-private-grant-marker".len())
            .any(|w| w == b"synthetic-private-grant-marker"));
        assert_eq!(
            db.query_row("SELECT count(*) FROM access_grants", [], |r| r
                .get::<_, u64>(0))?,
            1
        );
        let ciphertext: String =
            db.query_row("SELECT ciphertext FROM memories", [], |r| r.get(0))?;
        let nonce: String = db.query_row("SELECT nonce FROM memories", [], |r| r.get(0))?;
        assert_eq!(
            crate::SessionKeys::from_urk([7; 32])?.decrypt_content(&ciphertext, &nonce)?,
            "encrypted-fixture"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&copied)?.permissions().mode() & 0o777, 0o600);
            assert_eq!(
                fs::metadata(copied.with_extension("json"))?
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let (nonce, ciphertext) =
            crate::SessionKeys::from_urk([7; 32])?.encrypt_content("second")?;
        db.execute(
            "INSERT INTO memories(id,ciphertext,nonce) VALUES('second',?1,?2)",
            rusqlite::params![ciphertext, nonce],
        )?;
        let second = create(
            directory.path(),
            "synthetic-account",
            "second",
            &crate::SessionKeys::from_urk([7; 32])?,
        )?;
        assert_ne!(second.id, manifest.id);
        assert_eq!(second.entries, 2);
        assert_eq!(list(directory.path())?.len(), 2);
        Ok(())
    }
    #[test]
    fn restore_checks_keys_accounts_schema_and_quarantines_sync() -> Result<()> {
        let (directory, db) = fixture()?;
        let root = directory.path();
        let keys = crate::SessionKeys::from_urk([7; 32])?;
        let manifest = create(root, "account", "baseline", &keys)?;
        db.execute("DELETE FROM memories", [])?;
        drop(db);
        let ownership = crate::lock::LibraryLock::acquire(root, std::time::Duration::from_secs(1))?;
        assert!(restore_locked(root, "wrong-account", &keys, &manifest.id, &ownership).is_err());
        assert!(restore_locked(
            root,
            "account",
            &crate::SessionKeys::from_urk([8; 32])?,
            &manifest.id,
            &ownership
        )
        .is_err());
        let receipt = restore_locked(root, "account", &keys, &manifest.id, &ownership)?;
        assert!(receipt.sync_quarantined);
        assert_ne!(receipt.before_restore, manifest.id);
        assert!(ensure_sync_allowed(root).is_err());
        let restored = Connection::open(root.join("rsrs.db"))?;
        assert_eq!(
            restored.query_row("SELECT count(*) FROM memories", [], |r| r.get::<_, u64>(0))?,
            1
        );
        assert_eq!(
            restored.query_row("SELECT count(*) FROM access_grants", [], |r| r
                .get::<_, u64>(0))?,
            0
        );
        complete_restore(root, &receipt)?;
        assert!(resume_sync(root, "stale-review").is_err());
        assert!(ensure_sync_allowed(root).is_err());
        resume_sync(root, "0123456789abcdef0123456789abcdef")?;
        assert!(ensure_sync_allowed(root).is_ok());
        drop(restored);
        assert!(restore_locked(root, "account", &keys, &manifest.id, &ownership)?.sync_quarantined);
        Ok(())
    }

    #[test]
    fn restore_rejects_schema_changes_without_touching_live_rows() -> Result<()> {
        for statement in [
            "ALTER TABLE memories ADD COLUMN future_schema TEXT",
            "PRAGMA user_version=42",
        ] {
            let (directory, db) = fixture()?;
            let keys = crate::SessionKeys::from_urk([7; 32])?;
            let manifest = create(directory.path(), "account", "baseline", &keys)?;
            db.execute_batch(statement)?;
            let ownership = crate::lock::LibraryLock::acquire(
                directory.path(),
                std::time::Duration::from_secs(1),
            )?;
            assert!(
                restore_locked(directory.path(), "account", &keys, &manifest.id, &ownership)
                    .is_err()
            );
            assert_eq!(
                db.query_row("SELECT count(*) FROM memories", [], |row| row
                    .get::<_, u64>(0))?,
                1
            );
            assert_eq!(
                list(directory.path())?.len(),
                1,
                "schema mismatch should not begin restore"
            );
        }
        Ok(())
    }

    #[test]
    fn injected_failures_restore_original_grants_outbox_and_state() -> Result<()> {
        for stage in [
            "after_backups",
            "before_replace",
            "after_replace",
            "after_cache_clear",
            "after_installed",
        ] {
            let (directory, db) = fixture()?;
            let root = directory.path();
            let keys = crate::SessionKeys::from_urk([7; 32])?;
            let snapshot = create(root, "account", "baseline", &keys)?;
            db.execute(
                "INSERT INTO memories(id,ciphertext,nonce) VALUES('later','','')",
                [],
            )?;
            db.execute(
                "INSERT INTO meta VALUES('synthetic_outbox','original-pending-write')",
                [],
            )?;
            drop(db);
            let ownership =
                crate::lock::LibraryLock::acquire(root, std::time::Duration::from_secs(1))?;
            let result =
                restore_with_hook(root, "account", &keys, &snapshot.id, &ownership, &|at| {
                    anyhow::ensure!(at != stage, "injected restore failure at {stage}");
                    Ok(())
                });
            assert!(result.is_err(), "fault did not run: {stage}");
            let original = Connection::open(root.join("rsrs.db"))?;
            assert_eq!(
                original.query_row("SELECT count(*) FROM memories", [], |r| r.get::<_, u64>(0))?,
                2,
                "{stage}"
            );
            assert_eq!(
                original.query_row("SELECT count(*) FROM access_grants", [], |r| r
                    .get::<_, u64>(0))?,
                1,
                "{stage}"
            );
            assert_eq!(
                original.query_row(
                    "SELECT value FROM meta WHERE key='synthetic_outbox'",
                    [],
                    |r| r.get::<_, String>(0)
                )?,
                "original-pending-write",
                "{stage}"
            );
            assert!(
                ensure_sync_allowed(root).is_ok(),
                "rollback changed original quarantine: {stage}"
            );
            assert!(
                !root.join(RECOVERY_FILE).exists(),
                "recovery journal retained after successful rollback: {stage}"
            );
            assert!(
                list(root)?.len() >= 2,
                "portable prebackup missing: {stage}"
            );
        }
        Ok(())
    }

    #[test]
    fn runtime_startup_rollback_uses_private_original_not_portable_backup() -> Result<()> {
        let (directory, db) = fixture()?;
        let root = directory.path();
        let keys = crate::SessionKeys::from_urk([7; 32])?;
        let selected = create(root, "account", "baseline", &keys)?;
        db.execute(
            "INSERT INTO memories(id,ciphertext,nonce) VALUES('later','','')",
            [],
        )?;
        drop(db);
        let ownership = crate::lock::LibraryLock::acquire(root, std::time::Duration::from_secs(1))?;
        let receipt = restore_locked(root, "account", &keys, &selected.id, &ownership)?;
        rollback_locked(root, &receipt, &ownership)?;
        let original = Connection::open(root.join("rsrs.db"))?;
        assert_eq!(
            original.query_row("SELECT count(*) FROM memories", [], |r| r.get::<_, u64>(0))?,
            2
        );
        assert_eq!(
            original.query_row("SELECT count(*) FROM access_grants", [], |r| r
                .get::<_, u64>(0))?,
            1
        );
        assert!(ensure_sync_allowed(root).is_ok());
        Ok(())
    }

    #[test]
    fn damaged_unrelated_snapshot_does_not_block_healthy_recovery() -> Result<()> {
        let (directory, db) = fixture()?;
        let root = directory.path();
        let keys = crate::SessionKeys::from_urk([7; 32])?;
        let healthy = create(root, "account", "healthy", &keys)?;
        let damaged = create(root, "account", "damaged", &keys)?;
        fs::write(
            root.join("snapshots").join(format!("{}.db", damaged.id)),
            "corrupt",
        )?;
        drop(db);
        let report = list_report(root)?;
        assert_eq!(report.snapshots.len(), 1);
        assert_eq!(report.problems.len(), 1);
        assert_eq!(report.problems[0].id, damaged.id);
        let ownership = crate::lock::LibraryLock::acquire(root, std::time::Duration::from_secs(1))?;
        let receipt = restore_locked(root, "account", &keys, &healthy.id, &ownership)?;
        complete_restore(root, &receipt)?;
        assert_eq!(list_report(root)?.problems.len(), 1);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn live_database_symlinks_are_rejected_for_creation_restore_and_rollback() -> Result<()> {
        use std::os::unix::fs::symlink;
        let (directory, db) = fixture()?;
        let root = directory.path();
        let keys = crate::SessionKeys::from_urk([7; 32])?;
        let snapshot = create(root, "account", "baseline", &keys)?;
        drop(db);
        let live = root.join("rsrs.db");
        let external = root.join("original-target.db");
        fs::rename(&live, &external)?;
        symlink(&external, &live)?;
        let before = fs::read(&external)?;
        assert!(create(root, "account", "reject link", &keys).is_err());
        let ownership = crate::lock::LibraryLock::acquire(root, std::time::Duration::from_secs(1))?;
        assert!(restore_locked(root, "account", &keys, &snapshot.id, &ownership).is_err());
        assert_eq!(fs::read(&external)?, before);
        assert!(fs::symlink_metadata(&live)?.file_type().is_symlink());
        fs::remove_file(&live)?;
        fs::rename(&external, &live)?;
        let receipt = restore_locked(root, "account", &keys, &snapshot.id, &ownership)?;
        fs::rename(&live, &external)?;
        symlink(&external, &live)?;
        assert!(rollback_locked(root, &receipt, &ownership).is_err());
        assert!(root.join(&receipt.rollback_file).is_file());
        assert!(fs::symlink_metadata(&live)?.file_type().is_symlink());
        fs::remove_file(&live)?;
        fs::rename(&external, &live)?;
        rollback_locked(root, &receipt, &ownership)?;
        Ok(())
    }

    fn assert_normal_open_is_blocked_in_fresh_process(root: &Path) -> Result<()> {
        let output = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "snapshot::tests::interrupted_restore_has_recoverable_original_image",
                "--test-threads=1",
            ])
            .env("RSRS_SNAPSHOT_FAULT_CHILD_ROOT", root)
            .env("RSRS_SNAPSHOT_FAULT_MODE", "probe")
            .output()?;
        anyhow::ensure!(
            output.status.success(),
            "normal entry probe failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }

    #[test]
    fn corrupt_staged_database_cannot_be_marked_ready_and_original_is_recoverable() -> Result<()> {
        let (directory, db) = fixture()?;
        let root = directory.path();
        let keys = crate::SessionKeys::from_urk([7; 32])?;
        let snapshot = create(root, "account", "baseline", &keys)?;
        drop(db);
        let ownership = crate::lock::LibraryLock::acquire(root, std::time::Duration::from_secs(1))?;
        let receipt = restore_locked(root, "account", &keys, &snapshot.id, &ownership)?;
        fs::write(root.join("rsrs.db"), b"damaged database after replacement")?;
        assert!(ensure_no_incomplete_restore(root).is_err());
        // SQLite itself rejects the staged file; no readiness can be based on it.
        assert!(Connection::open(root.join("rsrs.db"))?
            .query_row("PRAGMA quick_check", [], |r| r.get::<_, String>(0))
            .is_err());
        rollback_locked(root, &receipt, &ownership)?;
        let original = Connection::open(root.join("rsrs.db"))?;
        assert_eq!(
            original.query_row("SELECT count(*) FROM access_grants", [], |r| r
                .get::<_, u64>(0))?,
            1
        );
        Ok(())
    }

    #[test]
    fn verified_write_failure_keeps_all_normal_entries_closed_until_rollback() -> Result<()> {
        for failure in ["before_verified_write", "after_verified_write"] {
            let (directory, db) = fixture()?;
            let root = directory.path();
            let keys = crate::SessionKeys::from_urk([7; 32])?;
            let snapshot = create(root, "account", "baseline", &keys)?;
            db.execute(
                "INSERT INTO memories(id,ciphertext,nonce) VALUES('later','','')",
                [],
            )?;
            drop(db);
            let ownership =
                crate::lock::LibraryLock::acquire(root, std::time::Duration::from_secs(1))?;
            let receipt = restore_locked(root, "account", &keys, &snapshot.id, &ownership)?;
            assert!(commit_with_hook(root, &receipt, &|phase| {
                anyhow::ensure!(
                    phase != failure,
                    "injected verified persistence I/O failure"
                );
                Ok(())
            })
            .is_err());
            assert_normal_open_is_blocked_in_fresh_process(root)?;
            rollback_locked(root, &receipt, &ownership)?;
            let original = Connection::open(root.join("rsrs.db"))?;
            assert_eq!(
                original.query_row("SELECT count(*) FROM memories", [], |row| row
                    .get::<_, u64>(0))?,
                2
            );
            assert_eq!(
                original.query_row("SELECT count(*) FROM access_grants", [], |row| row
                    .get::<_, u64>(0))?,
                1
            );
        }
        Ok(())
    }

    #[test]
    fn interrupted_restore_has_recoverable_original_image() -> Result<()> {
        const CHILD: &str = "RSRS_SNAPSHOT_FAULT_CHILD_ROOT";
        if let Some(root) = std::env::var_os(CHILD) {
            let root = std::path::PathBuf::from(root);
            std::env::set_var("RSRS_DATA_DIR", &root);
            let mode = std::env::var("RSRS_SNAPSHOT_FAULT_MODE")?;
            if mode == "probe" {
                for result in [
                    crate::service::open_store().map(|_| ()),
                    crate::service::open_store_with_profile().map(|_| ()),
                    crate::service::initialize_runtime_store().map(|_| ()),
                ] {
                    let error = result
                        .err()
                        .context("normal library entry accepted pending restore")?;
                    anyhow::ensure!(
                        error.to_string().contains("snapshot"),
                        "unexpected open failure: {error}"
                    );
                }
                return Ok(());
            }
            if mode == "write" {
                use crate::transport::MemoryTransport;
                let store = crate::service::open_store()?;
                let pending =
                    crate::StoredMemory::new_pending("new-after-commit".into(), "account".into());
                anyhow::ensure!(store.put(&pending)?, "post-commit write was not accepted");
                return Ok(());
            }
            let id = std::env::var("RSRS_SNAPSHOT_FAULT_ID")?;
            let ownership =
                crate::lock::LibraryLock::acquire(&root, std::time::Duration::from_secs(1))?;
            let receipt = restore_with_hook(
                &root,
                "account",
                &crate::SessionKeys::from_urk([7; 32])?,
                &id,
                &ownership,
                &|stage| {
                    if stage == mode {
                        std::process::exit(77);
                    }
                    Ok(())
                },
            )?;
            commit_restore(&root, &receipt)?;
            if mode == "after_commit" {
                std::process::exit(77);
            }
            clear_with_hook(&root, &receipt, &|stage| {
                if stage == mode {
                    std::process::exit(77);
                }
                Ok(())
            })?;
            anyhow::bail!("interruption hook was not reached");
        }
        for phase in [
            "after_replace",
            "after_installed",
            "after_commit",
            "after_gate_removed",
        ] {
            let (directory, db) = fixture()?;
            let root = directory.path();
            let keys = crate::SessionKeys::from_urk([7; 32])?;
            let snapshot = create(root, "account", "baseline", &keys)?;
            db.execute(
                "INSERT INTO memories(id,ciphertext,nonce) VALUES('later','','')",
                [],
            )?;
            drop(db);
            let output = std::process::Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "snapshot::tests::interrupted_restore_has_recoverable_original_image",
                    "--test-threads=1",
                ])
                .env(CHILD, root)
                .env("RSRS_SNAPSHOT_FAULT_ID", &snapshot.id)
                .env("RSRS_SNAPSHOT_FAULT_MODE", phase)
                .output()?;
            assert_eq!(
                output.status.code(),
                Some(77),
                "child did not reach {phase}: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            if phase != "after_gate_removed" {
                assert_normal_open_is_blocked_in_fresh_process(root)?;
            } else {
                assert!(ensure_no_incomplete_restore(root).is_ok());
                let output = std::process::Command::new(std::env::current_exe()?)
                    .args([
                        "--exact",
                        "snapshot::tests::interrupted_restore_has_recoverable_original_image",
                        "--test-threads=1",
                    ])
                    .env(CHILD, root)
                    .env("RSRS_SNAPSHOT_FAULT_MODE", "write")
                    .output()?;
                anyhow::ensure!(
                    output.status.success(),
                    "normal post-commit write failed: {} {}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            let ownership =
                crate::lock::LibraryLock::acquire(root, std::time::Duration::from_secs(1))?;
            recover_locked(root, "account", &ownership)?;
            let current = Connection::open(root.join("rsrs.db"))?;
            let rolled_back = matches!(phase, "after_replace" | "after_installed");
            assert_eq!(
                current.query_row("SELECT count(*) FROM access_grants", [], |row| row
                    .get::<_, u64>(0))?,
                if rolled_back { 1 } else { 0 },
                "{phase}"
            );
            assert_eq!(
                current.query_row(
                    "SELECT count(*) FROM memories WHERE id='later'",
                    [],
                    |row| row.get::<_, u64>(0)
                )?,
                if rolled_back { 1 } else { 0 },
                "{phase}"
            );
            if phase == "after_gate_removed" {
                assert_eq!(
                    current.query_row(
                        "SELECT count(*) FROM memories WHERE id='new-after-commit'",
                        [],
                        |row| row.get::<_, u64>(0)
                    )?,
                    1,
                    "recovery discarded accepted post-commit write"
                );
            }
            assert!(ensure_no_incomplete_restore(root).is_ok());
        }
        Ok(())
    }

    #[test]
    fn busy_restore_preserves_live_database_and_prebackup() -> Result<()> {
        let (directory, db) = fixture()?;
        let root = directory.path();
        let keys = crate::SessionKeys::from_urk([7; 32])?;
        let manifest = create(root, "account", "baseline", &keys)?;
        db.execute(
            "INSERT INTO memories(id,ciphertext,nonce) VALUES('pending','','')",
            [],
        )?;
        let reader = Connection::open(root.join("rsrs.db"))?;
        reader.execute_batch("BEGIN; SELECT * FROM memories;")?;
        db.execute(
            "INSERT INTO memories(id,ciphertext,nonce) VALUES('later','','')",
            [],
        )?;
        let ownership = crate::lock::LibraryLock::acquire(root, std::time::Duration::from_secs(1))?;
        assert!(restore_locked(root, "account", &keys, &manifest.id, &ownership).is_err());
        assert_eq!(
            db.query_row("SELECT count(*) FROM memories", [], |r| r.get::<_, u64>(0))?,
            3
        );
        assert!(
            list(root)?.len() >= 2,
            "mandatory pre-restore backup missing"
        );
        assert!(root.join("rsrs.db-wal").exists(), "live WAL removed");
        reader.execute_batch("ROLLBACK")?;
        Ok(())
    }

    #[test]
    fn legacy_manifest_without_witness_fields_remains_valid_for_pre_witness_database() -> Result<()>
    {
        let (directory, _db) = fixture()?;
        let snapshot = create(
            directory.path(),
            "account",
            "legacy",
            &crate::SessionKeys::from_urk([7; 32])?,
        )?;
        assert!(snapshot.witness_head.is_none());
        let path = directory
            .path()
            .join("snapshots")
            .join(format!("{}.json", snapshot.id));
        let mut old: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
        let fields = old.as_object_mut().context("manifest object")?;
        for name in ["witness_head", "witness_count", "witness_intact"] {
            fields.remove(name);
        }
        fs::write(&path, serde_json::to_vec(&old)?)?;
        assert_eq!(list(directory.path())?.len(), 1);
        Ok(())
    }

    #[test]
    fn corrupted_or_mismatched_snapshot_fails_closed() -> Result<()> {
        let (directory, _db) = fixture()?;
        let manifest = create(
            directory.path(),
            "synthetic-account",
            "",
            &crate::SessionKeys::from_urk([7; 32])?,
        )?;
        let database = directory
            .path()
            .join("snapshots")
            .join(format!("{}.db", manifest.id));
        fs::write(database, b"damaged")?;
        assert!(list(directory.path()).is_err());
        Ok(())
    }
    #[test]
    fn invalid_source_and_destination_do_not_publish_partial_snapshot() -> Result<()> {
        let directory = tempfile::tempdir()?;
        assert!(create(
            directory.path(),
            "account",
            "",
            &crate::SessionKeys::from_urk([7; 32])?
        )
        .is_err());
        assert!(!directory.path().join("rsrs.db").exists());
        let (directory, _db) = fixture()?;
        fs::write(directory.path().join("snapshots"), "user-owned")?;
        assert!(create(
            directory.path(),
            "account",
            "",
            &crate::SessionKeys::from_urk([7; 32])?
        )
        .is_err());
        assert_eq!(
            fs::read_to_string(directory.path().join("snapshots"))?,
            "user-owned"
        );
        Ok(())
    }
    #[test]
    fn failed_integrity_cleans_only_its_own_files() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let source = Connection::open(directory.path().join("rsrs.db"))?;
        source.execute_batch("CREATE TABLE unrelated(id TEXT);")?;
        assert!(create(
            directory.path(),
            "account",
            "",
            &crate::SessionKeys::from_urk([7; 32])?
        )
        .is_err());
        assert_eq!(fs::read_dir(directory.path().join("snapshots"))?.count(), 0);
        assert_eq!(
            source.query_row("SELECT count(*) FROM unrelated", [], |r| r.get::<_, u64>(0))?,
            0
        );
        Ok(())
    }
}
