//! Read-only profile and legacy discovery. Never open a database or a key backend.
use anyhow::{Context, Result};
use respire_client_host::{config, identity, paths};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Component, Path, PathBuf};

const RECEIPT: &str = ".rsrs-migration.json";
const SOURCE_RECEIPT: &str = ".rsrs-migrated.json";
// A session-format discriminator, not a crypto operation or a credential lookup.
const CURRENT_NAMESPACE: &str = "rsrs:v1:";

fn absolute(path: &Path) -> Result<PathBuf> {
    anyhow::ensure!(
        !path.components().any(|part| part == Component::ParentDir),
        "discovery path contains parent traversal"
    );
    Ok(std::path::absolute(path)?)
}

fn metadata(path: &Path) -> Result<Option<fs::Metadata>> {
    let path = absolute(path)?;
    let mut result = None;
    for (index, ancestor) in path.ancestors().enumerate() {
        match fs::symlink_metadata(ancestor) {
            Ok(value) => {
                anyhow::ensure!(
                    !value.file_type().is_symlink(),
                    "discovery path contains a symlink: {}",
                    ancestor.display()
                );
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    anyhow::ensure!(
                        value.file_attributes() & 0x400 == 0,
                        "discovery path contains a reparse point: {}",
                        ancestor.display()
                    );
                }
                anyhow::ensure!(
                    index == 0 || value.is_dir(),
                    "discovery ancestor is not a directory"
                );
                if index == 0 {
                    result = Some(value);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("cannot inspect {}", ancestor.display()))
            }
        }
    }
    Ok(result)
}

fn is_file(path: &Path) -> Result<bool> {
    Ok(metadata(path)?.is_some_and(|value| value.is_file()))
}

fn directories(root: &Path, sorted: bool) -> Result<Vec<PathBuf>> {
    let Some(value) = metadata(root)? else {
        return Ok(Vec::new());
    };
    anyhow::ensure!(value.is_dir(), "profile root is not a directory");
    let mut result = Vec::new();
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if metadata(&path)?.is_some_and(|value| value.is_dir()) {
            result.push(path);
        }
    }
    if sorted {
        result.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    }
    Ok(result)
}

fn roots() -> Result<(PathBuf, PathBuf)> {
    // Do not fall back to HOME on malformed config or an invalid isolation override.
    metadata(&paths::client_config_path())?;
    let (root, current) = config::control_roots()?;
    metadata(&root)?;
    metadata(&current)?;
    Ok((root, current))
}

fn session(directory: &Path) -> Result<Option<Value>> {
    let path = directory.join("session.json");
    let Some(value) = metadata(&path)? else {
        return Ok(None);
    };
    anyhow::ensure!(value.is_file(), "invalid session metadata file");
    // Legacy discovery retains its original JSON shape handling, before auth schemas existed.
    Ok(Some(serde_json::from_slice(&fs::read(path)?)?))
}

fn display_user(directory: &Path) -> Result<String> {
    // Lists historically display an empty user for malformed/absent session JSON.
    // Path redirects are not part of that permissive display contract.
    let path = directory.join("session.json");
    metadata(&path)?;
    Ok(identity::read_session_json(&path)
        .ok()
        .flatten()
        .and_then(|value| value["user"].as_str().map(str::to_owned))
        .unwrap_or_default())
}

pub(crate) fn account_list() -> Result<Value> {
    let (root, current) = roots()?;
    let mut rows = vec![
        json!({"name":"main","dir":root.to_string_lossy(),"user":display_user(&root)?,"current":current == root}),
    ];
    for directory in directories(&root.join("accounts"), true)? {
        // Preserve the old short circuit: a session lists the account without resolving DB ambiguity.
        if !is_file(&directory.join("session.json"))? {
            let current_db = is_file(&directory.join("rsrs.db"))?;
            let legacy_db = is_file(&directory.join("onememory.db"))?;
            anyhow::ensure!(!current_db || !legacy_db, "both rsrs.db and the legacy database exist; select the intended library explicitly");
            if !current_db && !legacy_db {
                continue;
            }
        }
        rows.push(
            json!({"name":directory.file_name().map(|name| name.to_string_lossy()),
            "dir":directory.to_string_lossy(),"user":display_user(&directory)?,"current":current == directory}),
        );
    }
    Ok(json!({"accounts":rows,"current_dir":current.to_string_lossy()}))
}

pub(crate) fn space_list() -> Result<Value> {
    let (root, current) = roots()?;
    let mut rows = vec![space_row("main", &root, &current)?];
    for directory in directories(&root.join("accounts"), true)? {
        let name = directory
            .file_name()
            .context("space directory has no name")?
            .to_string_lossy();
        rows.push(space_row(&name, &directory, &current)?);
    }
    Ok(json!({"spaces":rows,"current_dir":current.to_string_lossy()}))
}

fn space_row(name: &str, directory: &Path, current: &Path) -> Result<Value> {
    let issued = directory.join("space_sessions.json");
    metadata(&issued)?;
    // Invalid membership metadata has always displayed zero members; it is not authorization.
    let members = if is_file(&issued)? {
        fs::read(&issued)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .and_then(|value| value.as_array().map(Vec::len))
            .unwrap_or(0)
    } else {
        0
    };
    Ok(
        json!({"name":name,"dir":directory.to_string_lossy(),"user":display_user(directory)?,"current":directory == current,
        "owner":metadata(&directory.join("space_owner.json"))?.is_some(),"is_main":name == "main","members":members}),
    )
}

fn source_identity(path: &Path) -> Result<String> {
    // Keep byte-for-byte compatibility with app migration::identity and Runtime source IDs.
    let mut normalized = path.canonicalize()?.to_string_lossy().replace('\\', "/");
    if cfg!(windows) {
        normalized.make_ascii_lowercase();
    }
    Ok(format!("{:x}", Sha256::digest(normalized.as_bytes())))
}

fn safe_name(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

fn read_receipt(path: &Path) -> Result<Option<Value>> {
    if !is_file(path)? {
        return Ok(None);
    }
    Ok(Some(serde_json::from_slice(&fs::read(path)?)?))
}

fn migrated_destination(root: &Path, source_id: &str) -> Result<Option<PathBuf>> {
    let mut destinations = vec![root.to_path_buf()];
    // Keep the original receipt lookup order rather than selecting a different duplicate receipt.
    destinations.extend(directories(&root.join("accounts"), false)?);
    for destination in destinations {
        if metadata(&destination)?.is_some_and(|value| value.is_dir()) {
            if let Some(receipt) = read_receipt(&destination.join(RECEIPT))? {
                if receipt["source_identity"].as_str() == Some(source_id)
                    && receipt["complete"] == true
                {
                    return Ok(Some(destination));
                }
            }
        }
    }
    Ok(None)
}

pub(crate) fn list_legacy_profiles() -> Result<Value> {
    let (installation, _) = roots()?;
    // Explicit migration discovery retains the fixed HOME roots; active profile selection
    // never becomes a scan root. RSRS_DATA_DIR still scopes destinations and receipt search.
    let home = absolute(&paths::home_dir()?)?;
    metadata(&home)?;
    let mut rows = Vec::new();
    for label in ["respire", "onememory", "rsrs"] {
        let root = home.join(format!(".{label}"));
        metadata(&root)?;
        let mut candidates = vec![("main".to_owned(), root.clone())];
        for directory in directories(&root.join("accounts"), false)? {
            candidates.push((
                directory
                    .file_name()
                    .context("legacy profile has no name")?
                    .to_string_lossy()
                    .into_owned(),
                directory,
            ));
        }
        candidates.sort_by(|left, right| left.0.cmp(&right.0));
        for (name, source) in candidates {
            let legacy_db = is_file(&source.join("onememory.db"))?;
            if !legacy_db && !is_file(&source.join("session.json"))? {
                continue;
            }
            metadata(&source)?;
            let session = session(&source)?.unwrap_or(Value::Null);
            if session["crypto_namespace"].as_str() == Some(CURRENT_NAMESPACE)
                || session["wrapped_urk"]
                    .as_str()
                    .is_some_and(|value| value.starts_with(CURRENT_NAMESPACE))
            {
                continue;
            }
            if label == "rsrs"
                && !legacy_db
                && !session["wrapped_urk"]
                    .as_str()
                    .is_some_and(|value| !value.is_empty() && !value.starts_with(CURRENT_NAMESPACE))
            {
                continue;
            }
            let source_id = source_identity(&source)?;
            let account = format!("imported-{}-{}", &source_id[..8], safe_name(&name));
            let marked = read_receipt(&source.join(SOURCE_RECEIPT))?
                .filter(|receipt| {
                    receipt["complete"] == true && receipt["source_identity"] == source_id
                })
                .and_then(|receipt| receipt["destination"].as_str().map(PathBuf::from));
            let migrated_to = marked.or(migrated_destination(&installation, &source_id)?);
            rows.push(json!({"source_id":source_id,"source":source,"user":session["user"].as_str().unwrap_or(""),
                "account":account,"migrated_to":migrated_to}));
        }
    }
    Ok(json!({"profiles":rows}))
}

pub(crate) fn pending_legacy_profiles() -> Result<Vec<Value>> {
    let report = list_legacy_profiles()?;
    let rows = report["profiles"]
        .as_array()
        .context("migration discovery did not return profiles")?;
    Ok(rows
        .iter()
        .filter(|row| row["migrated_to"].is_null())
        .cloned()
        .collect())
}
