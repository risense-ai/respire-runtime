use super::*;

fn validate_candidate_backup(record: &AuthRecord, backup: &OriginalBackup) -> Result<()> {
    canonical_operation_id(&record.operation_id)?;
    ensure!(record.alias.starts_with("login-")
        && record.alias.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-'),
        "invalid candidate credential alias");
    ensure!(!backup.pending && backup.sha256.len() == 64
        && backup.sha256.bytes().all(|ch| ch.is_ascii_hexdigit())
        && backup.slot == format!("login-candidate-{}-{}", record.operation_id, backup.sha256)
        && record.candidate_sha256.as_deref() == Some(backup.sha256.as_str()),
        "invalid candidate backup binding");
    require_persistent_auth_backend(&backup.backend)
}

pub(super) fn prepare_candidates(journal: &mut Journal) -> Result<()> {
    for record in &mut journal.operations {
        let Some(bytes) = record.candidate.as_deref() else { continue; };
        let session: Value = serde_json::from_slice(bytes).context("invalid historical candidate; retain recovery")?;
        if ["pass", "super", "secret", "secret_key"].iter().all(|field| session.get(*field).is_none()) {
            continue;
        }
        let sha256 = digest(bytes);
        ensure!(record.candidate_sha256.as_deref() == Some(sha256.as_str()), "historical candidate digest mismatch");
        if let Some(backup) = record.candidate_backup.as_ref() {
            validate_candidate_backup(record, backup)?;
            continue;
        }
        ensure!(record.alias.starts_with("login-")
            && record.alias.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-'),
            "invalid candidate credential alias");
        canonical_operation_id(&record.operation_id)?;
        let slot = format!("login-candidate-{}-{sha256}", record.operation_id);
        // The previous journal retains these exact bytes until the host confirms readback.
        let backend = crate::keystore::import_credential_checkpoint(&record.alias, &slot, &hex::encode(bytes),
            require_persistent_auth_backend)?;
        let backup = OriginalBackup { slot, backend: backend.to_owned(), sha256, pending: false };
        validate_candidate_backup(record, &backup)?;
        record.candidate_backup = Some(backup);
    }
    Ok(())
}

fn hydrate_candidates(journal: &mut Journal) -> Result<()> {
    for record in &mut journal.operations {
        let Some(backup) = record.candidate_backup.as_ref() else { continue; };
        validate_candidate_backup(record, backup)?;
        ensure!(record.candidate.is_none(), "candidate contains both inline and host snapshots");
        let bytes = hex::decode(crate::keystore::read_imported(&record.alias, &backup.slot, &backup.backend)?)
            .context("invalid candidate backup encoding")?;
        ensure!(digest(&bytes) == backup.sha256, "candidate backup digest mismatch; retain recovery");
        record.candidate = Some(bytes);
    }
    Ok(())
}

pub(super) fn write(journal: &Journal) -> Result<()> {
    let path = recovery_path();
    std::fs::create_dir_all(path.parent().context("recovery root is missing")?)?;
    let mut value = serde_json::to_value(journal)?;
    if journal.active.as_ref().is_some_and(|active| active.original_backup.is_some() || active.retired) {
        value["active"]["original"] = Value::Null;
    }
    for (index, record) in journal.operations.iter().enumerate() {
        if record.candidate_backup.is_some() { value["operations"][index]["candidate"] = Value::Null; }
    }
    private_write(&path, &serde_json::to_vec(&value)?)
}

fn validate(active: &Recovery, backup: &OriginalBackup) -> Result<()> {
    ensure!(active.alias.starts_with("login-")
        && active.alias.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-'),
        "invalid recovery credential alias");
    ensure!(backup.sha256.len() == 64 && backup.sha256.bytes().all(|ch| ch.is_ascii_hexdigit())
        && backup.slot == format!("login-original-{}", backup.sha256), "invalid original backup slot");
    require_persistent_auth_backend(&backup.backend)
}

pub(super) fn original_digest(active: &Recovery) -> Result<Option<String>> {
    if let Some(backup) = active.original_backup.as_ref() {
        validate(active, backup)?;
        ensure!(active.original.as_deref().is_none_or(|bytes| digest(bytes) == backup.sha256),
            "original backup digest mismatch");
        Ok(Some(backup.sha256.clone()))
    } else { Ok(active.original.as_deref().map(digest)) }
}

pub(super) fn prepare(journal: &mut Journal) -> Result<()> {
    let Some(active) = journal.active.as_ref() else { return Ok(()); };
    if active.retired { return Ok(()); }
    let Some(original) = active.original.clone() else {
        journal.active.as_mut().context("recovery is missing")?.original_backup = None;
        return Ok(());
    };
    // Old inline factors remain readable, but never enter another journal revision.
    let contains_factors = serde_json::from_slice::<Value>(&original).map(|session|
        ["pass", "super", "secret", "secret_key"].iter().any(|field| session.get(*field).is_some()))
        .unwrap_or(true);
    if !contains_factors {
        journal.active.as_mut().context("recovery is missing")?.original_backup = None;
        return Ok(());
    }
    let sha256 = digest(&original);
    if active.original_backup.as_ref().is_some_and(|backup| backup.sha256 == sha256 && !backup.pending) {
        return Ok(());
    }
    let alias = active.alias.clone();
    let slot = format!("login-original-{sha256}");
    let encoded = hex::encode(&original);
    let backend = crate::keystore::import_credential_checkpoint(&alias, &slot, &encoded, |backend| {
        let backup = OriginalBackup { slot: slot.clone(), backend: backend.to_owned(), sha256: sha256.clone(), pending: true };
        let active = journal.active.as_mut().context("recovery is missing")?;
        validate(active, &backup)?;
        if !active.original_backups.iter().any(|entry| entry.slot == slot && entry.backend == backend) {
            active.original_backups.push(backup.clone());
        }
        active.original_backup = Some(backup);
        // The source is still untouched if the process stops before the host write.
        write(journal)
    })?;
    let backup = OriginalBackup { slot, backend: backend.to_owned(), sha256, pending: false };
    let active = journal.active.as_mut().context("recovery is missing")?;
    validate(active, &backup)?;
    if !active.original_backups.iter().any(|entry| entry.slot == backup.slot && entry.backend == backup.backend) {
        active.original_backups.push(backup.clone());
    }
    active.original_backup = Some(backup);
    Ok(())
}

pub(super) fn hydrate(journal: &mut Journal) -> Result<()> {
    hydrate_candidates(journal)?;
    let Some(active) = journal.active.as_mut() else { return Ok(()); };
    if active.retired { return Ok(()); }
    let Some(backup) = active.original_backup.as_ref() else { return Ok(()); };
    validate(active, backup)?;
    ensure!(active.original.is_none(), "recovery contains both inline and host original snapshots");
    let original = match crate::keystore::read_imported(&active.alias, &backup.slot, &backup.backend) {
        Ok(value) => hex::decode(value).context("invalid original backup encoding")?,
        Err(error) if backup.pending && matches!(error.downcast_ref::<respire_protocol::credentials::CredentialError>(),
            Some(respire_protocol::credentials::CredentialError::NoEntry)) => {
            // This is the explicit pre-write checkpoint, not a replacement snapshot.
            read_original(&active.directory)?.context("pending original backup source is missing")?
        }
        Err(error) => return Err(error.context("original backup is unavailable; retain the recovery record")),
    };
    ensure!(digest(&original) == backup.sha256, "original backup digest mismatch; retain the recovery record");
    active.original = Some(original);
    Ok(())
}

pub(super) fn remove(active: &Recovery) -> Result<()> {
    ensure!(active.retired, "original backups cannot be removed before durable retirement");
    for backup in &active.original_backups {
        validate(active, backup)?;
        crate::keystore::remove_imported(&active.alias, &backup.slot, &backup.backend)?;
    }
    Ok(())
}

pub(super) fn rollback_snapshot(journal: &mut Journal, record: &Recovery) -> Result<Option<Vec<u8>>> {
    let Some(original) = record.original.as_deref() else { return Ok(None); };
    let source: Value = serde_json::from_slice(original).context("original session is invalid; retain recovery")?;
    if ["pass", "super", "secret", "secret_key"].iter().all(|field| source.get(*field).is_none()) {
        return Ok(Some(original.to_vec()));
    }
    let version = source["vault_version"].as_i64().unwrap_or(1);
    ensure!((1..=4).contains(&version), "unsupported original vault; retain recovery");
    let old_alias = source["keyring_account"].as_str().or_else(|| source["user"].as_str()).unwrap_or("local");
    let primary_slot = if version == 1 { "pass" } else { "super" };
    let primary = if let Some(value) = source[primary_slot].as_str() {
        value.to_owned()
    } else if version == 4 && source["secret_key"].as_str().is_some() {
        source["secret_key"].as_str().context("original v4 factor is missing")?.to_owned()
    } else if let Some(backend) = source["keyring_backend"].as_str() {
        if version == 1 { crate::keystore::read_imported_v1_password(old_alias, backend)? }
        else { crate::keystore::read_imported(old_alias, "super", backend)? }
    } else if version == 1 {
        crate::keystore::load_login_pass(old_alias).context("original login credential is required for recovery")?
    } else {
        crate::keystore::load_super(old_alias).context("original super credential is required for recovery")?
    };
    let legacy = session_legacy_secret(&source, old_alias)?;
    let mut material = source.clone();
    if let Some(secret) = &legacy { material[if version == 1 { "secret" } else { "secret_key" }] = json!(secret); }
    let original_keys = crate::auth::unlock_session_keys(&material,
        if version == 1 { &primary } else { "" }, Some(if version == 1 { "" } else { &primary }), old_alias)?;
    let alias = format!("{}-restore-{}", record.alias, &digest(original)[..16]);
    let active = journal.active.as_mut().context("rollback recovery is missing")?;
    ensure!(!active.retired && active.alias == record.alias && active.directory == record.directory
        && active.original.as_deref() == Some(original), "rollback snapshot owner changed");
    ensure!(active.restore_alias.as_deref().is_none_or(|existing| existing == alias), "rollback credential alias changed");
    active.restore_alias = Some(alias.clone());
    save_journal(journal)?;
    let backend = crate::keystore::import_credential_checkpoint(&alias, primary_slot, &primary, |backend| {
        require_persistent_auth_backend(backend)?;
        save_journal(journal)
    })?;
    require_persistent_auth_backend(backend)?;
    if version != 1 {
        if let Some(password) = source["pass"].as_str().map(str::to_owned).or_else(|| crate::keystore::load_login_pass(old_alias)) {
            crate::keystore::import_credential_checkpoint(&alias, "pass", &password, |backend| {
                require_persistent_auth_backend(backend)?;
                save_journal(journal)
            })?;
        }
    }
    let mut restored = source.clone();
    for field in ["pass", "super", "secret", "secret_key", "legacy_secret_backend"] {
        restored.as_object_mut().context("original session must be an object")?.remove(field);
    }
    restored["vault_version"] = json!(version);
    restored["keyring_account"] = json!(alias);
    restored["keyring_backend"] = json!(backend);
    if let Some(secret) = legacy {
        let backend = crate::keystore::import_credential_checkpoint(&alias, "legacy-secret", &secret, |backend| {
            require_persistent_auth_backend(backend)?;
            save_journal(journal)
        })?;
        require_persistent_auth_backend(backend)?;
        restored["legacy_secret_backend"] = json!(backend);
    }
    let restored_keys = session_material_keys(&restored, &alias, backend)?;
    ensure!(original_keys.urk == restored_keys.urk, "rollback changed the original data key");
    let bytes = serde_json::to_vec_pretty(&restored)?;
    let active = journal.active.as_mut().context("rollback recovery is missing")?;
    ensure!(active.restored.as_ref().is_none_or(|previous| previous == &bytes), "rollback candidate changed");
    active.restored = Some(bytes.clone());
    save_journal(journal)?;
    Ok(Some(bytes))
}

pub(super) fn matches_original(record: &Recovery, current: &Option<Vec<u8>>) -> bool {
    current == &record.original || record.restored.as_ref().is_some_and(|restored| current.as_ref() == Some(restored))
}

pub(super) fn matches_restored(record: &AuthRecord, profile: &Path, current: &Option<Vec<u8>>) -> bool {
    matches!(record.phase, AuthPhase::RollingBack | AuthPhase::RolledBack)
        && record.restored.as_ref().is_some_and(|restored| restored.profile == profile
            && current.as_deref().map(digest).as_deref() == Some(restored.sha256.as_str()))
}
