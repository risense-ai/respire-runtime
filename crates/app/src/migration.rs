//! Copy legacy default homes without modifying the original libraries or credentials.

#[cfg(test)]
#[path = "migration_readiness_tests.rs"]
mod readiness_tests;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use rusqlite::{
    backup::{Backup, StepResult},
    Connection, OpenFlags,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

// WP-2c: internally_configured_root sank into the domain service module; the
// engine side must classify the internally configured default home.
use crate::service::internally_configured_root;

const RECEIPT: &str = ".rsrs-migration.json";
const SOURCE_RECEIPT: &str = ".rsrs-migrated.json";
const DEFAULT_ENV: &str = "RSRS_DEFAULT_DATA_DIR";

struct Profile {
    source: PathBuf,
    destination: PathBuf,
    identity: String,
    services: [&'static str; 3],
}

/// Configure the current home before parsing. Legacy import is always explicit.
pub fn ensure_default_home() -> Result<()> {
    if ["RSRS_CLIENT_ONLY", "RSRS_NO_AUTOSTART"]
        .iter()
        .any(|name| {
            crate::env::var(name).ok().is_some_and(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "on" | "yes"
                )
            })
        })
    {
        return Ok(());
    }
    if let Ok(value) = crate::env::var("RSRS_DATA_DIR") {
        if !value.trim().is_empty() && !internally_configured_root(value.trim()) {
            return Ok(());
        }
    }
    let home = crate::service::home_dir().context("cannot locate the user home")?;
    let root = home.join(".rsrs");
    // This occurs at single-threaded startup, before Core or runtime workers exist.
    std::env::set_var("RSRS_DATA_DIR", &root);
    std::env::set_var(DEFAULT_ENV, &root);
    Ok(())
}

fn legacy_profiles(home: &Path) -> Result<Vec<Profile>> {
    let mut result = Vec::new();
    for (label, services) in [
        ("respire", ["respire", "memocap", "1memory"]),
        ("onememory", ["1memory", "memocap", "respire"]),
        ("rsrs", ["rsrs", "respire", "1memory"]),
    ] {
        let root = home.join(format!(".{label}"));
        if root.exists() { meaningful(&root)?; }
        let mut candidates = vec![("main".to_owned(), root.clone())];
        if root.join("accounts").is_dir() {
            meaningful(&root.join("accounts"))?;
            for entry in std::fs::read_dir(root.join("accounts"))? {
                let entry = entry?;
                candidates.push((entry.file_name().to_string_lossy().into_owned(), entry.path()));
            }
        }
        candidates.sort_by(|left, right| left.0.cmp(&right.0));
        for (name, source) in candidates {
            if !source.join("onememory.db").is_file() && !source.join("session.json").is_file() {
                continue;
            }
            // Reject symlinks before reading identity or any credential material.
            meaningful(&source)?;
            // Current vaults remain current even when an older filename or home is retained.
            let session_path = source.join("session.json");
            if session_path.is_file() {
                let value: Value = serde_json::from_slice(&std::fs::read(&session_path)?)?;
                if value["crypto_namespace"].as_str() == Some(crate::memory::crypto::RSRS_PREFIX)
                    || value["wrapped_urk"].as_str().is_some_and(|wrapped| wrapped.starts_with(crate::memory::crypto::RSRS_PREFIX)) {
                    continue;
                }
            }
            if label == "rsrs" {
                let session = source.join("session.json");
                let legacy_vault = if session.is_file() {
                    let value: Value = serde_json::from_slice(&std::fs::read(&session)?)?;
                    value["wrapped_urk"].as_str().is_some_and(|wrapped|
                        !wrapped.is_empty() && !wrapped.starts_with(crate::memory::crypto::RSRS_PREFIX))
                } else { false };
                if !source.join("onememory.db").is_file() && !legacy_vault { continue; }
            }
            let source_id = identity(&source)?;
            result.push(Profile {
                identity: source_id.clone(), source,
                destination: crate::service::accounts_root().join(format!("imported-{}-{}", &source_id[..8], safe_name(&name))),
                services,
            });
        }
    }
    Ok(result)
}

fn migrated_destination(source_id: &str) -> Result<Option<PathBuf>> {
    let mut destinations = vec![crate::service::main_data_dir()];
    let accounts = crate::service::accounts_root();
    if accounts.is_dir() {
        for entry in std::fs::read_dir(accounts)? {
            destinations.push(entry?.path());
        }
    }
    for destination in destinations {
        if destination.is_dir() {
            meaningful(&destination)?;
            if receipt_matches(&destination, source_id)? { return Ok(Some(destination)); }
        }
    }
    Ok(None)
}

/// Enumerate actual legacy profiles; backup-only roots do not constitute a library.
pub fn list_legacy_profiles() -> Result<Value> {
    let home = crate::service::home_dir()?;
    let mut rows = Vec::new();
    for profile in legacy_profiles(&home)? {
        let source_receipt = profile.source.join(SOURCE_RECEIPT);
        let marked = if source_receipt.is_file() {
            meaningful(&profile.source)?;
            let receipt: Value = serde_json::from_slice(&std::fs::read(source_receipt)?)?;
            if receipt["complete"] == true && receipt["source_identity"] == profile.identity {
                receipt["destination"].as_str().map(PathBuf::from)
            } else { None }
        } else { None };
        rows.push(json!({"source_id":profile.identity,"source":profile.source,
            "user":crate::service::session_user_of_dir(&profile.source),
            "account":profile.destination.file_name().map(|name| name.to_string_lossy().into_owned()),
            "migrated_to":marked.or(migrated_destination(&profile.identity)?)}));
    }
    Ok(json!({"profiles":rows}))
}

/// Discovery is read-only. A completed receipt suppresses repeated suggestions.
pub fn pending_legacy_profiles() -> Result<Vec<Value>> {
    let report = list_legacy_profiles()?;
    let profiles = report["profiles"].as_array()
        .ok_or_else(|| anyhow!("migration discovery did not return profiles"))?;
    Ok(profiles.iter().filter(|profile| profile["migrated_to"].is_null()).cloned().collect())
}

/// Copy only the selected profile into a new account, keeping current selection intact.
pub fn migrate_profile(source_id: &str, account: &str) -> Result<Value> {
    crate::service::require_profile_change_host()?;
    anyhow::ensure!(!account.is_empty() && account != "main" && safe_name(account) == account,
        "migration needs a new account name containing letters, digits, '-' or '_'");
    let home = crate::service::home_dir()?;
    let lock_root = home.join(".rsrs-migration-lock");
    private_directory(&lock_root)?;
    let _lock = crate::lock::LibraryLock::acquire(&lock_root, Duration::from_secs(30))?;
    let mut profiles = legacy_profiles(&home)?;
    let selected = profiles.iter().position(|profile| profile.identity == source_id)
        .ok_or_else(|| anyhow!("legacy source is no longer available; list sources again"))?;
    let source_receipt = profiles[selected].source.join(SOURCE_RECEIPT);
    if let Ok(metadata) = std::fs::symlink_metadata(&source_receipt) {
        anyhow::ensure!(!metadata.file_type().is_symlink(), "source migration marker is a symbolic link; nothing was migrated");
        let receipt: Value = serde_json::from_slice(&std::fs::read(&source_receipt)?)?;
        if receipt["complete"] == true && receipt["source_identity"].as_str() == Some(source_id) {
            return Ok(json!({"state":"already_migrated","dir":receipt["destination"]}));
        }
    }
    if let Some(destination) = migrated_destination(source_id)? {
        return Ok(json!({"state":"already_migrated","dir":destination}));
    }
    let accounts = crate::service::accounts_root();
    if accounts.exists() {
        anyhow::ensure!(!std::fs::symlink_metadata(&accounts)?.file_type().is_symlink(),
            "account root is a symbolic link; no external data was written");
    }
    profiles[selected].destination = accounts.join(account);
    anyhow::ensure!(!profiles[selected].destination.exists(), "migration account already exists; nothing was overwritten");
    let staging_root = home.join(".rsrs-migration-staging");
    private_directory(&staging_root)?;
    let stage = staging_root.join(uuid::Uuid::new_v4().to_string());
    snapshot_profile(&profiles[selected], &stage, &profiles, true)?;
    private_directory(&accounts)?;
    // rename must never replace an existing empty directory either.
    std::fs::create_dir(&profiles[selected].destination)
        .context("migration destination changed; nothing was overwritten")?;
    std::fs::remove_dir(&profiles[selected].destination)?;
    std::fs::rename(&stage, &profiles[selected].destination)?;
    write_json(&source_receipt,
        &json!({"schema":1,"complete":true,"source_identity":source_id,
            "destination":profiles[selected].destination,"original_preserved":true,
            "snapshot_at":chrono::Utc::now().to_rfc3339()}))?;
    Ok(json!({"state":"migrated","account":account,"dir":profiles[selected].destination,
        "source":profiles[selected].source,"original_preserved":true}))
}

fn meaningful(path: &Path) -> Result<bool> {
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            bail!("migration root is a symbolic link; no external data was copied");
        }
    }
    if !path.is_dir() {
        return Ok(false);
    }
    for entry in std::fs::read_dir(path)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if !excluded(&name) && name != RECEIPT {
            return Ok(true);
        }
    }
    Ok(false)
}

fn excluded(name: &str) -> bool {
    matches!(
        name,
        "runtime" | "bin" | "bak" | ".rsrs-migrated.json" | "lock.db" | "lock.db-wal" | "lock.db-shm"
    ) || name.ends_with("-wal")
        || name.ends_with("-shm")
        || name.ends_with(".pid")
        || name.starts_with("runtime.")
        || name.starts_with(".rsrs-metadata-")
        || name == "runtime.json"
        || name == "runtime-token"
}

fn identity(path: &Path) -> Result<String> {
    let canonical = path.canonicalize()?;
    let mut value = canonical.to_string_lossy().replace('\\', "/");
    if cfg!(windows) {
        value.make_ascii_lowercase();
    }
    Ok(hex::encode(Sha256::digest(value.as_bytes())))
}

fn receipt_matches(destination: &Path, source_id: &str) -> Result<bool> {
    let path = destination.join(RECEIPT);
    if !path.is_file() {
        return Ok(false);
    }
    let receipt: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    Ok(receipt["source_identity"].as_str() == Some(source_id) && receipt["complete"] == true)
}

fn safe_name(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

#[cfg(test)]
fn destination_for(base: PathBuf, id: &str, reserved: &mut BTreeSet<PathBuf>) -> Result<PathBuf> {
    if (!base.exists() || !meaningful(&base)? || receipt_matches(&base, id)?)
        && reserved.insert(base.clone())
    {
        return Ok(base);
    }
    let name = base
        .file_name()
        .ok_or_else(|| anyhow!("invalid migration destination"))?
        .to_string_lossy();
    let alternate = base.with_file_name(format!("{name}-{}", &id[..16]));
    if alternate.exists() && !receipt_matches(&alternate, id)? {
        bail!("legacy migration destination conflict; original libraries were preserved");
    }
    if !reserved.insert(alternate.clone()) {
        bail!("duplicate legacy migration destination");
    }
    Ok(alternate)
}

/// Also used by fixture-only tests; it does not replace HOME or access runtime services.
#[cfg(test)]
fn migrate_home(home: &Path) -> Result<()> {
    let target = home.join(".rsrs");
    if let Ok(metadata) = std::fs::symlink_metadata(target.join("accounts")) {
        if metadata.file_type().is_symlink() {
            bail!("new account root is a symbolic link; no external data was written");
        }
    }
    let sources = [
        ("respire", ["respire", "memocap", "1memory"]),
        ("onememory", ["1memory", "memocap", "respire"]),
    ];
    let mut roots = Vec::new();
    for (label, services) in sources {
        let path = home.join(format!(".{label}"));
        if meaningful(&path)? {
            roots.push((label, path, services));
        }
    }
    if roots.is_empty() {
        return Ok(());
    }
    let lock_root = home.join(".rsrs-migration-lock");
    private_directory(&lock_root)?;
    let _lock = crate::lock::LibraryLock::acquire(&lock_root, Duration::from_secs(30))?;
    let fresh = !meaningful(&target)?;
    let mut reserved = BTreeSet::new();
    let mut profiles = Vec::new();
    for (index, (label, source, services)) in roots.iter().enumerate() {
        let id = identity(source)?;
        let main = if fresh && index == 0 || receipt_matches(&target, &id)? {
            reserved.insert(target.clone());
            target.clone()
        } else {
            destination_for(
                target.join("accounts").join(format!("legacy-{label}")),
                &id,
                &mut reserved,
            )?
        };
        profiles.push(Profile {
            source: source.clone(),
            destination: main,
            identity: id,
            services: *services,
        });
        let accounts = source.join("accounts");
        if accounts.is_dir() {
            let mut entries = std::fs::read_dir(accounts)?.collect::<std::io::Result<Vec<_>>>()?;
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                if !meaningful(&entry.path())? {
                    continue;
                }
                let id = identity(&entry.path())?;
                let original = safe_name(&entry.file_name().to_string_lossy());
                let name = if index == 0 && (fresh || profiles[0].destination == target) {
                    original
                } else {
                    format!("legacy-{label}-{original}")
                };
                let destination =
                    destination_for(target.join("accounts").join(name), &id, &mut reserved)?;
                profiles.push(Profile {
                    source: entry.path(),
                    destination,
                    identity: id,
                    services: *services,
                });
            }
        }
    }
    let pending = profiles
        .iter()
        .filter_map(
            |profile| match receipt_matches(&profile.destination, &profile.identity) {
                Ok(true) => None,
                result => Some(result.map(|_| profile)),
            },
        )
        .collect::<Result<Vec<_>>>()?;
    if pending.is_empty() {
        return Ok(());
    }
    let staging_root = home.join(".rsrs-migration-staging");
    private_directory(&staging_root)?;
    let staging = staging_root.join(uuid::Uuid::new_v4().to_string());
    private_directory(&staging)?;
    let mut completed = Vec::new();
    // Provider settings belong to the user's selected global source, not to
    // every account. Existing new provider entries always retain precedence.
    crate::keystore::import_classification(&roots[0].2)?;
    for (index, profile) in pending.iter().enumerate() {
        let stage = staging.join(format!("profile-{index}"));
        snapshot_profile(profile, &stage, &profiles, false)?;
        completed.push((profile, stage));
    }
    // A new default home is published in one rename, including every account.
    if fresh {
        let (_, main_stage) = completed
            .iter()
            .find(|(profile, _)| profile.destination == target)
            .ok_or_else(|| anyhow!("missing main migration snapshot"))?;
        for (profile, stage) in &completed {
            if profile.destination == target {
                continue;
            }
            let relative = profile.destination.strip_prefix(&target)?;
            let destination = main_stage.join(relative);
            if let Some(parent) = destination.parent() {
                private_directory(parent)?;
            }
            std::fs::rename(stage, destination)?;
        }
        if target.exists() {
            // Only an empty directory may be replaced; never remove existing state.
            std::fs::remove_dir(&target)
                .context("new home is no longer empty; migration was not published")?;
        }
        std::fs::rename(main_stage, &target)?;
    } else {
        for (profile, stage) in completed {
            if profile.destination.exists() {
                std::fs::remove_dir(&profile.destination)
                    .context("migration destination changed; no state was overwritten")?;
            }
            if let Some(parent) = profile.destination.parent() {
                private_directory(&target)?;
                private_directory(parent)?;
            }
            std::fs::rename(stage, &profile.destination)?;
        }
    }
    eprintln!("legacy library copied safely to ~/.rsrs; original directories and credentials were retained");
    Ok(())
}

fn snapshot_profile(profile: &Profile, stage: &Path, profiles: &[Profile], current_namespace: bool) -> Result<()> {
    // Reading a held SQLite library lock detects an active original writer without
    // stopping it or modifying its lock file.
    let old_lock = profile.source.join("lock.db");
    let mut legacy_active = false;
    if old_lock.is_file() {
        let connection = Connection::open_with_flags(old_lock, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        connection.busy_timeout(Duration::from_millis(100))?;
        match connection.query_row("PRAGMA schema_version", [], |row| row.get::<_, i64>(0)) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(error, _))
                if matches!(
                    error.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                ) =>
            {
                legacy_active = true;
                eprintln!("legacy runtime is active: migration captures committed data at the snapshot; use rsrs after upgrading; later unsynced old writes remain in the original library");
            }
            Err(error) => return Err(error.into()),
        }
    }
    let session_path = profile.source.join("session.json");
    let original_session = if session_path.is_file() {
        Some(std::fs::read(&session_path)?)
    } else {
        None
    };
    copy_tree(&profile.source, stage, true)?;
    let database = crate::service::database_path(stage)?;
    validate_schema(&database)?;
    if database.is_file() {
        private_file(&database)?;
    }
    let mut keyring_backend = None;
    if let Some(bytes) = original_session.as_ref() {
        let mut session: Value = serde_json::from_slice(bytes)
            .context("legacy session is invalid; source was preserved")?;
        let recovered = migrate_credentials(profile, &database, &mut session)?;
        if current_namespace {
            if let Some(keys) = recovered.as_ref() {
                migrate_namespace_database(&database, keys)?;
                let alias = session["keyring_account"].as_str().context("migrated credential alias is missing")?;
                let (salt, wrapped, nonce) = rewrap_namespace(&session, alias, keys)?;
                session["kdf_salt"] = json!(salt);
                session["wrapped_urk"] = json!(wrapped);
                session["urk_nonce"] = json!(nonce);
                let version = session["vault_version"].as_i64().unwrap_or(1);
                if let Some(fields) = session.as_object_mut() {
                    for field in ["super", "pass"] { fields.remove(field); }
                    if version >= 4 { fields.remove("secret_key"); fields.remove("secret"); }
                }
            }
            session["crypto_namespace"] = json!(crate::memory::crypto::RSRS_PREFIX);
        }
        keyring_backend = session.get("keyring_backend").cloned();
        rewrite_address(&mut session);
        write_json(&stage.join("session.json"), &session)?;
    } else if encrypted_count(&database)? > 0 {
        bail!("legacy library has ciphertext but no session; recover the original keys before migration");
    } else {
        validate_live_memories(&database, None)?;
    }
    for name in ["client.json", "agent.json"] {
        let path = stage.join(name);
        if path.is_file() {
            let mut config: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
            rewrite_address(&mut config);
            if let Some(value) = config["data_dir"]
                .as_str()
                .filter(|value| !value.is_empty())
            {
                let old = crate::service::expand_tilde(value);
                if old
                    .components()
                    .any(|component| matches!(component, std::path::Component::ParentDir))
                {
                    bail!("legacy configuration contains a parent-directory path; originals were preserved");
                }
                if let Some(found) = profiles
                    .iter()
                    .filter(|candidate| old.starts_with(&candidate.source))
                    .max_by_key(|candidate| candidate.source.components().count())
                {
                    let suffix = old.strip_prefix(&found.source)?;
                    let destination = if suffix.as_os_str().is_empty() {
                        found.destination.clone()
                    } else {
                        found.destination.join(suffix)
                    };
                    config["data_dir"] = json!(destination);
                } else {
                    bail!("legacy configuration uses an external data directory; originals were preserved; set RSRS_DATA_DIR explicitly to open it");
                }
            }
            write_json(&path, &config)?;
        }
    }
    if let Some(bytes) = original_session {
        if std::fs::read(session_path)? != bytes {
            bail!("legacy identity changed during migration; retry after closing the old runtime");
        }
    }
    if current_namespace && database.is_file() && database.file_name().is_some_and(|name| name != "rsrs.db") {
        std::fs::rename(&database, stage.join("rsrs.db"))?;
    }
    write_json(
        &stage.join(RECEIPT),
        &json!({"schema":2,"complete":true,"source_identity":profile.identity,
        "source":profile.source,"destination":profile.destination,
            "api_default":crate::service::DEFAULT_SERVER_ADDR,"original_preserved":true,
            "keyring_backend":keyring_backend,
        "snapshot_at":chrono::Utc::now().to_rfc3339(),"legacy_runtime_active":legacy_active,
        "snapshot_only":true,"namespace_migrated":current_namespace}),
    )?;
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path, root: bool) -> Result<()> {
    private_directory(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        let text = name.to_string_lossy();
        if excluded(&text) || text == RECEIPT || root && text == "accounts" {
            continue;
        }
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            bail!("legacy library contains a symbolic link; no external data was copied");
        }
        let target = destination.join(&name);
        if kind.is_dir() {
            copy_tree(&entry.path(), &target, false)?;
        } else if kind.is_file() {
            if text.ends_with(".db") || text.ends_with(".sqlite") || text.ends_with(".sqlite3") {
                snapshot_database(&entry.path(), &target)?;
            } else {
                std::fs::copy(entry.path(), &target)?;
                private_file(&target)?;
            }
        }
    }
    Ok(())
}

fn snapshot_database(source: &Path, destination: &Path) -> Result<()> {
    let source = Connection::open_with_flags(source, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    source.busy_timeout(Duration::from_millis(200))?;
    let mut destination = Connection::open(destination)?;
    let backup = Backup::new(&source, &mut destination)?;
    let began = Instant::now();
    loop {
        match backup.step(256)? {
            StepResult::Done => break,
            _ if began.elapsed() >= Duration::from_secs(60) => {
                bail!("legacy SQLite snapshot remained busy; migration was not published")
            }
            _ => std::thread::sleep(Duration::from_millis(10)),
        }
    }
    drop(backup);
    let result: String = destination.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if result != "ok" {
        bail!("legacy SQLite snapshot failed integrity validation");
    }
    if let Some(path) = destination.path() {
        private_file(Path::new(path))?;
    }
    Ok(())
}

fn encrypted_count(path: &Path) -> Result<usize> {
    if !path.is_file() {
        return Ok(0);
    }
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let has_table: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='memories')",
        [],
        |row| row.get(0),
    )?;
    if !has_table {
        return Ok(0);
    }
    let count: i64 = db.query_row(
        "SELECT count(*) FROM memories WHERE ciphertext <> ''",
        [],
        |row| row.get(0),
    )?;
    Ok(usize::try_from(count)?)
}

/// Verify live payloads before credential import or a completion receipt. This
/// reads the snapshot without upgrading it; deleted rows remain opaque bytes.
fn validate_live_memories(path: &Path, keys: Option<&crate::memory::SessionKeys>) -> Result<()> {
    if !path.is_file() {
        return Ok(());
    }
    let database = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let columns = database
        .prepare("PRAGMA table_info(memories)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if columns.is_empty() {
        return Ok(());
    }
    // Older compatible schemas acquire deleted=0 only on normal store open.
    // A NULL marker is not evidence that a memory was deleted.
    let query = if columns.iter().any(|column| column == "deleted") {
        "SELECT ciphertext, nonce FROM memories WHERE COALESCE(deleted, 0) = 0"
    } else {
        "SELECT ciphertext, nonce FROM memories"
    };
    let mut statement = database.prepare(query)?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let keys = keys.ok_or_else(|| anyhow!(
            "legacy live ciphertext requires usable session keys; migration was not published"
        ))?;
        let mut stored = crate::memory::model::StoredMemory::new_pending(String::new(), String::new());
        stored.ciphertext = row.get(0).context("legacy live ciphertext is missing or invalid; migration was not published")?;
        stored.nonce = row.get(1).context("legacy live ciphertext nonce is missing or invalid; migration was not published")?;
        // Reuse normal supported payload decoding, including legacy defaults.
        // Do not include decrypted content or identifiers in a failure report.
        crate::memory::MemoryEngine::open(keys, &stored).map_err(|_| anyhow!(
            "legacy live ciphertext is unreadable with the recovered account key; migration was not published; original rows were preserved"
        ))?;
    }
    Ok(())
}

fn validate_schema(path: &Path) -> Result<()> {
    if !path.is_file() {
        return Ok(());
    }
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let columns = db
        .prepare("PRAGMA table_info(memories)")?
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(5)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if columns.is_empty() {
        return Ok(());
    }
    let compatible_id = columns.iter().any(|(name, kind, primary)| {
        name == "id" && kind.eq_ignore_ascii_case("TEXT") && *primary == 1
    }) && columns
        .iter()
        .filter(|(_, _, primary)| *primary > 0)
        .count()
        == 1;
    let required = ["user", "ciphertext", "nonce", "created_at", "updated_at"];
    if !compatible_id
        || columns.iter().any(|(name, _, _)| name == "tag_hashes")
        || required
            .iter()
            .any(|field| !columns.iter().any(|(name, _, _)| name == field))
    {
        bail!("legacy database uses an incompatible pre-encrypted demo format; export with its original version and import into rsrs; original rows were preserved");
    }
    Ok(())
}

fn candidate_values(
    profile: &Profile,
    user: &str,
    slot: &str,
    fields: &[&str],
    session: &Value,
) -> Vec<String> {
    let mut values = Vec::new();
    for field in fields {
        if let Some(value) = session[field].as_str().filter(|value| !value.is_empty()) {
            values.push(value.to_owned());
        }
    }
    let account = if let Some(alias) = session["keyring_account"].as_str().filter(|value| !value.is_empty()) {
        alias
    } else if user.trim().is_empty() {
        "local"
    } else {
        user.trim()
    };
    for service in profile.services {
        values.extend(crate::keystore::read_credentials(
            service,
            &format!("{slot}:{account}"),
        ));
    }
    if slot == "super" {
        if let Ok(value) = crate::env::var("RSRS_SUPER") {
            if !value.is_empty() {
                values.push(value);
            }
        }
    }
    let mut seen = BTreeSet::new();
    values.retain(|value| seen.insert(value.clone()));
    values
}

fn migrate_credentials(profile: &Profile, database: &Path, session: &mut Value) -> Result<Option<crate::memory::SessionKeys>> {
    if session["wrapped_urk"].as_str().filter(|value| !value.is_empty()).is_none() {
        if encrypted_count(database)? > 0 {
            bail!("legacy session has no wrapped key; recover the original keys before migration");
        }
        validate_live_memories(database, None)?;
        return Ok(None);
    }
    let user = session["user"].as_str().unwrap_or("").to_owned();
    let passes = candidate_values(profile, &user, "pass", &["pass"], session);
    let supers = candidate_values(
        profile,
        &user,
        "super",
        if session["vault_version"].as_i64().unwrap_or(1) >= 4 {
            &["secret_key", "super"]
        } else {
            &["super"]
        },
        session,
    );
    let version = session["vault_version"].as_i64().unwrap_or(1);
    let mut unlocked = None;
    if version >= 2 {
        for super_pass in &supers {
            if let Ok(keys) = crate::auth::unlock_session_keys(session, "", Some(super_pass), &user)
            {
                unlocked = Some((keys, Some(super_pass.clone()), None));
                break;
            }
        }
    } else {
        for pass in &passes {
            if let Ok(keys) = crate::auth::unlock_session_keys(session, pass, None, &user) {
                unlocked = Some((keys, None, Some(pass.clone())));
                break;
            }
        }
    }
    let (keys, super_pass, legacy_pass) = unlocked.ok_or_else(|| anyhow!("legacy vault could not be unlocked; supply its original recovery key/password; no new vault was created"))?;
    validate_live_memories(database, Some(&keys))?;
    let alias = format!("legacy-{}", &profile.identity[..16]);
    if let Some(value) = super_pass {
        let backend = crate::keystore::import_credential(&alias, "super", &value)?;
        session["keyring_backend"] = json!(backend);
    }
    if let Some(value) = legacy_pass.as_ref().or_else(|| passes.first()) {
        let backend = crate::keystore::import_credential(&alias, "pass", value)?;
        if legacy_pass.is_some() {
            session["keyring_backend"] = json!(backend);
        }
    }
    session["keyring_account"] = json!(alias);
    Ok(Some(keys))
}

/// Recalculate internal keys while retaining every original user factor. Older
/// two-factor vaults keep their version and factors; migration is not a reset.
fn rewrap_namespace(session: &Value, alias: &str, keys: &crate::memory::SessionKeys) -> Result<(String, String, String)> {
    use crate::memory::crypto;
    let version = session["vault_version"].as_i64().unwrap_or(1);
    let salt = crypto::random_hex(16);
    let credential = |slot: &str| -> Result<String> {
        crate::keystore::read_credentials("rsrs", &format!("{slot}:{alias}"))
            .into_iter().next().ok_or_else(|| anyhow!("the original migration credential is missing; no replacement Key was generated"))
    };
    let kek = match version {
        1 => crypto::derive_rsrs_password_kek(&credential("pass")?,
            session["secret"].as_str().context("original Account Secret is missing")?, &salt)?,
        2 => crypto::derive_super_kek(&credential("super")?, &salt)?,
        3 => crypto::derive_rsrs_vault_kek(&credential("super")?,
            session["secret_key"].as_str().context("original Secret Key is missing")?, &salt)?,
        4 => crypto::derive_rsrs_kek(&credential("super")?, &salt)?,
        _ => bail!("unsupported vault version; original credentials were preserved"),
    };
    let (nonce, wrapped) = crypto::wrap_key(&keys.urk, &kek)?;
    anyhow::ensure!(crypto::unwrap_key(&wrapped, &nonce, &kek)? == keys.urk,
        "new key wrap did not round-trip; migration was not completed");
    Ok((salt, format!("{}{wrapped}", crypto::RSRS_PREFIX), nonce))
}

/// A new library is a new encrypted projection. The original immutable sync
/// journal remains in the old library; changing its operation bodies would
/// invalidate retries. The new projection queues fresh operations on normal open.
fn migrate_namespace_database(path: &Path, source: &crate::memory::SessionKeys) -> Result<()> {
    if !path.is_file() { return Ok(()); }
    let mut database = Connection::open(path)?;
    crate::transport::local::register_witness_functions(&database)?;
    let tables = database.prepare("SELECT name FROM sqlite_master WHERE type='table'")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<BTreeSet<_>>>()?;
    if !tables.contains("memories") { return Ok(()); }
    let columns = database.prepare("PRAGMA table_info(memories)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<BTreeSet<_>>>()?;
    let query = if columns.contains("embedding_enc") {
        "SELECT id,ciphertext,nonce,embedding_enc FROM memories ORDER BY id"
    } else { "SELECT id,ciphertext,nonce,'' FROM memories ORDER BY id" };
    let rows = database.prepare(query)?.query_map([], |row| Ok((
        row.get::<_, String>(0)?, row.get::<_, String>(1)?,
        row.get::<_, String>(2)?, row.get::<_, String>(3)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let target = crate::memory::SessionKeys::from_urk(source.urk)?;
    let mut converted = Vec::with_capacity(rows.len());
    for (id, ciphertext, nonce, embedding) in rows {
        let plaintext = source.decrypt_content(&ciphertext, &nonce)
            .map_err(|_| anyhow!("a source record cannot be decrypted; full migration was not published; original library and keys were preserved"))?;
        let (new_nonce, new_ciphertext) = target.encrypt_content(&plaintext)?;
        anyhow::ensure!(target.decrypt_content(&new_ciphertext, &new_nonce)? == plaintext,
            "migrated ciphertext did not round-trip; no completion marker was written");
        let embedding = source.migrate_embedding(&embedding)?;
        converted.push((id, ciphertext, new_ciphertext, new_nonce, embedding));
    }
    let transaction = database.transaction()?;
    transaction.execute_batch("DROP TRIGGER IF EXISTS sync_capture_insert; DROP TRIGGER IF EXISTS sync_capture_update;")?;
    for table in ["sync_outbox", "sync_inbox", "sync_remote_heads", "sync_conflict_analysis", "sync_resolution_outbox"] {
        if tables.contains(table) { transaction.execute(&format!("DELETE FROM {table}"), [])?; }
    }
    if tables.contains("meta") {
        transaction.execute("DELETE FROM meta WHERE key IN ('sync_v2_cursor','sync_v2_snapshot_done','sync_v2_snapshot_until','sync_cursor')", [])?;
    }
    for (id, old, ciphertext, nonce, embedding) in converted {
        let sql = format!("UPDATE memories SET ciphertext=?1,nonce=?2{}{} WHERE id=?3",
            if columns.contains("dirty") { ",dirty=1" } else { "" },
            if columns.contains("embedding_enc") { ",embedding_enc=?4" } else { "" });
        if columns.contains("embedding_enc") {
            transaction.execute(&sql, rusqlite::params![ciphertext, nonce, id, embedding])?;
        } else {
            transaction.execute(&sql, rusqlite::params![ciphertext, nonce, id])?;
        }
        if tables.contains("core_artifacts") {
            transaction.execute("UPDATE core_artifacts SET source=?1 WHERE memory_id=?2 AND source=?3",
                rusqlite::params![ciphertext, id, old])?;
        }
    }
    if tables.contains("sync_outbox") && tables.contains("sync_base") {
        // Preserve acknowledged base revisions. Assign new operation IDs to the
        // newly encrypted projection rather than changing immutable old bodies.
        transaction.execute_batch("INSERT INTO sync_outbox (op_id,id,base_rev,user,ciphertext,nonce,updated_at,deleted)
            SELECT lower(hex(randomblob(16))),m.id,b.rev,m.user,m.ciphertext,m.nonce,m.updated_at,m.deleted
            FROM memories m LEFT JOIN sync_base b ON b.id=m.id WHERE m.dirty=1;")?;
    }
    transaction.commit()?;
    database.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;")?;
    let integrity: String = database.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    anyhow::ensure!(integrity == "ok", "migrated database failed integrity validation");
    Ok(())
}

fn rewrite_address(value: &mut Value) {
    let Some(address) = value["addr"].as_str() else {
        return;
    };
    let host = address
        .strip_prefix("https://")
        .or_else(|| address.strip_prefix("http://"))
        .and_then(|value| value.split('/').next())
        .unwrap_or("")
        .to_ascii_lowercase();
    if matches!(
        host.as_str(),
        "1memory.ai"
            | "api.1memory.ai"
            | "memocap.ai"
            | "api.memocap.ai"
            | "respire.ai"
            | "api.respire.ai"
    ) {
        value["addr"] = json!(crate::service::DEFAULT_SERVER_ADDR);
    }
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    use std::io::Write;
    anyhow::ensure!(!std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()),
        "migration metadata must not be a symbolic link");
    let parent = path.parent().context("migration metadata has no parent directory")?;
    let temporary = parent.join(format!(".rsrs-metadata-{}.tmp", uuid::Uuid::new_v4()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> Result<()> {
        let mut file = options.open(&temporary)?;
        file.write_all(&serde_json::to_vec_pretty(value)?)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)?;
        #[cfg(unix)] std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() && temporary.is_file() { let _ = std::fs::remove_file(&temporary); }
    result
}

fn private_directory(path: &Path) -> Result<()> {
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            bail!("migration destination is a symbolic link; no external data was written");
        }
    }
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn private_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        std::fs::set_permissions(
            path,
            std::fs::Permissions::from_mode(0o600 | (mode & 0o100)),
        )?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_conversion_registers_witness_functions_and_preserves_original()->Result<()> {
        use crate::transport::MemoryTransport;
        let root=tempfile::tempdir()?;let original=root.path().join("original.db");let staged=root.path().join("staged.db");
        let keys=crate::SessionKeys::from_legacy_urk([7;32])?;
        let (nonce,ciphertext)=keys.encrypt_content("synthetic namespace content")?;
        let mut memory=crate::StoredMemory::new_pending("synthetic-entry".into(),"account".into());
        memory.ciphertext=ciphertext.clone();memory.nonce=nonce;memory.updated_at="2026-01-01T00:00:00Z".into();
        {let store=crate::transport::local::LocalStore::open(&original)?;assert!(store.put(&memory)?);assert_eq!(store.witness_verify()?.count,1);}
        std::fs::copy(&original,&staged)?;
        migrate_namespace_database(&staged,&keys)?;
        let converted=crate::transport::local::LocalStore::open_read_only(&staged)?;
        let rows=converted.all(false)?;assert_eq!(rows.len(),1);
        assert!(rows[0].ciphertext.starts_with(crate::memory::crypto::RSRS_PREFIX));
        assert_eq!(crate::SessionKeys::from_urk([7;32])?.decrypt_content(&rows[0].ciphertext,&rows[0].nonce)?,"synthetic namespace content");
        let proof=converted.witness_verify()?;assert!(proof.intact);assert_eq!(proof.count,2);
        let retained=crate::transport::local::LocalStore::open_read_only(&original)?;
        assert_eq!(retained.all(false)?[0].ciphertext,ciphertext);assert_eq!(retained.witness_verify()?.count,1);
        Ok(())
    }

    #[test]
    fn client_only_never_creates_a_migration_home() -> Result<()> {
        let _isolate = crate::test_lock::Isolate::new()?;
        let home = tempfile::tempdir()?;
        plaintext_profile(&home.path().join(".onememory"), "client-fixture")?;
        let variables = [
            "HOME",
            "RSRS_DATA_DIR",
            "RSRS_CLIENT_ONLY",
            DEFAULT_ENV,
        ];
        let saved = variables.map(|name| (name, crate::env::var_os(name)));
        std::env::set_var("HOME", home.path());
        std::env::remove_var("RSRS_DATA_DIR");
        std::env::remove_var(DEFAULT_ENV);
        std::env::set_var("RSRS_CLIENT_ONLY", "yes");
        let result = ensure_default_home();
        let root_changed = crate::env::var_os("RSRS_DATA_DIR").is_some();
        for (name, value) in saved {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
        result?;
        assert!(!root_changed);
        assert!(!home.path().join(".rsrs").exists());
        assert!(!home.path().join(".rsrs-migration-lock").exists());
        assert!(!home.path().join(".rsrs-migration-staging").exists());
        Ok(())
    }

    fn plaintext_profile(path: &Path, user: &str) -> Result<()> {
        std::fs::create_dir_all(path)?;
        write_json(
            &path.join("session.json"),
            &json!({"user":user,"addr":"https://1memory.ai","token":"fixture-token"}),
        )?;
        Ok(())
    }

    #[test]
    fn committed_wal_and_original_files_survive() -> Result<()> {
        let _isolate = crate::test_lock::Isolate::new()?;
        let _keyring = super::readiness_tests::memory_keyring();
        let home = tempfile::tempdir()?;
        let source = home.path().join(".onememory");
        plaintext_profile(&source, "wal-owner")?;
        let urk = crate::memory::crypto::generate_key();
        let db = Connection::open(source.join("onememory.db"))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;
                        CREATE TABLE memories (id TEXT PRIMARY KEY,user TEXT,ciphertext TEXT,nonce TEXT,created_at TEXT,updated_at TEXT,deleted INTEGER NOT NULL DEFAULT 0);
                        INSERT INTO memories VALUES ('committed','wal-owner','','','created','updated',0);")?;
        let data_key = crate::memory::crypto::derive_subkey(&urk, b"onememory:data:v1")?;
        let payload = json!({"kind":"context","tags":"","title":"committed",
                "content":"committed fixture","user":"wal-owner","computer":"fixture",
                "project":"","created_at":"2026-10-04T00:00:00Z","updated_at":"2026-10-04T00:00:00Z"});
        let (nonce, ciphertext) = crate::memory::crypto::encrypt_item(&data_key, &payload.to_string())?;
        db.execute(
            "UPDATE memories SET ciphertext=?1,nonce=?2 WHERE id='committed'",
            rusqlite::params![ciphertext, nonce],
        )?;
        let foreign_key = crate::memory::crypto::generate_key();
        let (foreign_nonce, foreign_ciphertext) =
            crate::memory::crypto::encrypt_item(&foreign_key, "old local fixture")?;
        db.execute(
            "INSERT INTO memories VALUES ('old-local','local',?1,?2,'created','updated',0)",
            rusqlite::params![foreign_ciphertext, foreign_nonce],
        )?;
        db.execute("UPDATE memories SET deleted=1 WHERE id='old-local'", [])?;
        for index in 1..5 {
            db.execute(
                "INSERT INTO memories VALUES (?1,'local',?2,?3,'created','updated',1)",
                rusqlite::params![
                    format!("old-local-{index}"),
                    foreign_ciphertext,
                    foreign_nonce
                ],
            )?;
        }
        // Exercise the copied database through the normal store/index path.
        let encrypted_snapshot = home.path().join("encrypted-snapshot.db");
        snapshot_database(&source.join("onememory.db"), &encrypted_snapshot)?;
        validate_schema(&encrypted_snapshot)?;
        let keys = crate::memory::SessionKeys::from_urk(urk)?;
        let store = crate::transport::local::LocalStore::open(&encrypted_snapshot)?;
        use crate::transport::MemoryTransport;
        let rows = store.all(true)?;
        assert_eq!(rows.len(), 6);
        let tombstone = rows
            .iter()
            .find(|row| row.id == "old-local")
            .ok_or_else(|| anyhow!("copied tombstone missing"))?;
        assert!(crate::memory::MemoryEngine::open(&keys, tombstone).is_err());
        let embedder = crate::memory::search::HashingEmbedder::default();
        assert_eq!(store.rebuild_index(&keys, &embedder, "m3")?, 1);
        assert!(!store.index_pending("m3")?);
        assert_eq!(store.all(false)?.len(), 1);
        assert_eq!(
            (tombstone.ciphertext.clone(), tombstone.nonce.clone()),
            (foreign_ciphertext.clone(), foreign_nonce.clone())
        );
        // An encrypted profile without usable session material must remain
        // retryable instead of being published with a completion receipt.
        assert!(migrate_home(home.path()).is_err());
        assert!(!home.path().join(".rsrs").exists());
        std::fs::remove_file(source.join("session.json"))?;
        assert!(migrate_home(home.path()).is_err());
        assert!(!home.path().join(".rsrs").exists());
        let secret = crate::memory::crypto::generate_secret_key();
        let salt = crate::memory::crypto::random_hex(16);
        let kek = crate::memory::crypto::derive_kek_v4(&secret, &salt)?;
        let (urk_nonce, wrapped_urk) = crate::memory::crypto::wrap_key(&urk, &kek)?;
        write_json(&source.join("session.json"), &json!({
            "user":"wal-owner","addr":"https://1memory.ai","token":"fixture-token",
            "vault_version":4,"secret_key":secret,"kdf_salt":salt,
            "urk_nonce":urk_nonce,"wrapped_urk":wrapped_urk
        }))?;
        std::fs::create_dir_all(source.join("runtime"))?;
        std::fs::write(source.join("runtime/token"), "must-not-copy")?;
        std::fs::create_dir_all(source.join("models"))?;
        std::fs::write(source.join("models/model.fixture"), "model")?;
        let original_session = std::fs::read(source.join("session.json"))?;
        migrate_home(home.path())?;
        let target = home.path().join(".rsrs");
        let snapshot = Connection::open(target.join("onememory.db"))?;
        assert_eq!(
            snapshot.query_row("SELECT id FROM memories WHERE id='committed'", [], |row| {
                row.get::<_, String>(0)
            })?,
            "committed"
        );
        assert_eq!(
            snapshot.query_row(
                "SELECT ciphertext,nonce,deleted FROM memories WHERE id='old-local'",
                [],
                |row| Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?
                ))
            )?,
            (foreign_ciphertext, foreign_nonce, 1)
        );
        assert_eq!(
            std::fs::read(source.join("session.json"))?,
            original_session
        );
        assert!(source.join("runtime/token").is_file());
        assert!(!target.join("runtime").exists());
        assert_eq!(
            std::fs::read_to_string(target.join("models/model.fixture"))?,
            "model"
        );
        let session: Value = serde_json::from_slice(&std::fs::read(target.join("session.json"))?)?;
        assert_eq!(session["addr"], crate::service::DEFAULT_SERVER_ADDR);
        assert_eq!(session["token"], "fixture-token");
        migrate_home(home.path())?;
        assert!(!target.join("accounts/legacy-onememory").exists());
        Ok(())
    }

    #[test]
    fn both_homes_and_conflicting_profiles_are_retained() -> Result<()> {
        let _isolate = crate::test_lock::Isolate::new()?;
        let home = tempfile::tempdir()?;
        let recent = home.path().join(".respire");
        let old = home.path().join(".onememory");
        plaintext_profile(&recent, "recent")?;
        plaintext_profile(&old, "old")?;
        plaintext_profile(&recent.join("accounts/work"), "recent-work")?;
        plaintext_profile(&old.join("accounts/work"), "old-work")?;
        write_json(
            &recent.join("client.json"),
            &json!({"data_dir":recent.join("accounts/work"),"addr":"https://dev.rsrs.rs"}),
        )?;
        migrate_home(home.path())?;
        let target = home.path().join(".rsrs");
        assert!(target.join("session.json").is_file());
        assert!(target.join("accounts/work/session.json").is_file());
        assert!(target
            .join("accounts/legacy-onememory/session.json")
            .is_file());
        assert!(target
            .join("accounts/legacy-onememory-work/session.json")
            .is_file());
        let config: Value = serde_json::from_slice(&std::fs::read(target.join("client.json"))?)?;
        let active_profile = config["data_dir"]
            .as_str()
            .ok_or_else(|| anyhow!("migrated active profile path is missing"))?;
        assert_eq!(Path::new(active_profile), target.join("accounts/work"));
        assert_eq!(config["addr"], "https://dev.rsrs.rs");
        let session_before = std::fs::read(target.join("session.json"))?;
        migrate_home(home.path())?;
        assert_eq!(std::fs::read(target.join("session.json"))?, session_before);
        assert!(old.join("accounts/work/session.json").is_file());
        let fresh_home = tempfile::tempdir()?;
        for label in [".rsrs", ".respire"] {
            let current = fresh_home.path().join(label);
            std::fs::create_dir_all(&current)?;
            std::fs::write(current.join("onememory.db"), b"")?;
            write_json(&current.join("session.json"), &json!({"wrapped_urk":format!("{}fixture",crate::memory::crypto::RSRS_PREFIX),"vault_version":4}))?;
        }
        assert!(legacy_profiles(fresh_home.path())?.is_empty(), "current vaults were reported as legacy");
        Ok(())
    }

    #[test]
    fn incompatible_ciphertext_schema_never_publishes() -> Result<()> {
        let _isolate = crate::test_lock::Isolate::new()?;
        let home = tempfile::tempdir()?;
        let source = home.path().join(".onememory");
        plaintext_profile(&source, "old-demo")?;
        let db = Connection::open(source.join("onememory.db"))?;
        db.execute_batch(
            "CREATE TABLE memories (id INTEGER PRIMARY KEY,tag_hashes TEXT,content TEXT);
            INSERT INTO memories VALUES (1,'legacy','preserved');",
        )?;
        assert!(migrate_home(home.path()).is_err());
        assert!(!home.path().join(".rsrs").exists());
        assert_eq!(
            db.query_row("SELECT content FROM memories", [], |row| row
                .get::<_, String>(0))?,
            "preserved"
        );
        assert!(home.path().join(".rsrs-migration-staging").is_dir());
        Ok(())
    }
}
