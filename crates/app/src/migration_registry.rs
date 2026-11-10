//! Windows durable admission fence. The file journal remains the full record;
//! this compact HKCU value prevents a lost file/name from becoming a new O.
//!
//! RegFlushKey returns after the containing hive reaches the registry store on
//! disk. It is intentionally used only at migration phase boundaries, because
//! it blocks other writers to the hive. No elevated access or raw-volume I/O.
//! Contract: https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regflushkey
use super::*;
use winsafe::{co, guard::RegCloseKeyGuard, HKEY, RegistryValue};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fence {
    schema: u32,
    operation: String,
    source: String,
    account: String,
    frame_sha256: String,
}

fn key_path(home: &Path) -> Result<String> {
    let canonical = home.canonicalize()?;
    let canonical = canonical.to_str().context("migration home is not Unicode")?.to_lowercase();
    #[cfg(not(test))]
    let namespace = "Software\\Risense\\Respire\\MigrationIntentsV1";
    #[cfg(test)]
    let namespace = "Software\\Risense\\Respire\\Tests\\MigrationIntentsV1";
    Ok(format!("{namespace}\\{}",
        hex::encode(Sha256::digest(canonical.as_bytes()))))
}

fn open(home: &Path) -> Result<Option<RegCloseKeyGuard>> {
    let user = HKEY::RegOpenCurrentUser(co::KEY::READ)
        .map_err(|error| anyhow!("open migration registry user: {error}"))?;
    match user.RegOpenKeyEx(Some(&key_path(home)?), co::REG_OPTION::default(), co::KEY::QUERY_VALUE | co::KEY::WOW64_64KEY) {
        Ok(key) => Ok(Some(key)),
        Err(error) if error == co::ERROR::FILE_NOT_FOUND => Ok(None),
        Err(error) => Err(anyhow!("open migration registry fence: {error}")),
    }
}

fn check_size(key: &HKEY) -> Result<()> {
    let (mut count, mut name_size, mut data_size) = (0, 0, 0);
    key.RegQueryInfoKey(None, None, None, None, Some(&mut count), Some(&mut name_size),
        Some(&mut data_size), None, None)
        .map_err(|error| anyhow!("query migration registry bounds: {error}"))?;
    anyhow::ensure!(count <= 4096 && name_size <= 36 && data_size <= 2048,
        "migration registry exceeds its safety bounds");
    Ok(())
}

fn read(key: &HKEY, name: &str) -> Result<Option<Fence>> {
    check_size(key)?;
    let value = match key.RegQueryValueEx(Some(name)) {
        Ok(value) => value,
        Err(error) if error == co::ERROR::FILE_NOT_FOUND => return Ok(None),
        Err(error) => return Err(anyhow!("read migration registry fence: {error}")),
    };
    let RegistryValue::Binary(bytes) = value else { bail!("invalid migration registry value type"); };
    anyhow::ensure!(bytes.len() <= 2048, "migration registry value exceeds its bound");
    let fence: Fence = serde_json::from_slice(&bytes)?;
    let id = uuid::Uuid::parse_str(name)?;
    anyhow::ensure!(id.get_version_num() == 4 && id.to_string() == name
        && fence.schema == 1 && fence.operation == name && fence.frame_sha256.len() == 64,
        "invalid migration registry binding");
    Ok(Some(fence))
}

fn frame_digest(record: &Intent) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(record)?)))
}

pub(super) fn verify(home: &Path, original: &HostMigrationOperation, record: Option<&Intent>) -> Result<()> {
    let fence = match open(home)? {
        Some(key) => read(&key, &original.operation_id)?,
        None => None,
    };
    match (record, fence) {
        (None, None) => Ok(()),
        (Some(record), Some(fence)) => {
            anyhow::ensure!(fence.source == original.source_id
                && fence.account == original.account.to_ascii_lowercase()
                && fence.frame_sha256 == frame_digest(record)?,
                "migration registry and file evidence disagree; no operation was replayed");
            Ok(())
        }
        _ => bail!("migration admission evidence is incomplete; retain the original operation"),
    }
}

pub(super) fn persist(home: &Path, record: &Intent) -> Result<()> {
    let user = HKEY::RegOpenCurrentUser(co::KEY::CREATE_SUB_KEY)
        .map_err(|error| anyhow!("open migration registry user for admission: {error}"))?;
    let (key, _) = user.RegCreateKeyEx(&key_path(home)?, None, co::REG_OPTION::NON_VOLATILE,
        co::KEY::QUERY_VALUE | co::KEY::SET_VALUE | co::KEY::WOW64_64KEY, None)
        .map_err(|error| anyhow!("create migration registry fence: {error}"))?;
    check_size(&key)?;
    let fence = Fence { schema: 1, operation: record.original.operation_id.clone(),
        source: record.original.source_id.clone(), account: record.original.account.to_ascii_lowercase(),
        frame_sha256: frame_digest(record)? };
    let bytes = serde_json::to_vec(&fence)?;
    anyhow::ensure!(bytes.len() <= 2048, "migration registry fence exceeds its bound");
    key.RegSetValueEx(Some(&record.original.operation_id), RegistryValue::Binary(bytes))
        .map_err(|error| anyhow!("write migration registry fence: {error}"))?;
    key.RegFlushKey().map_err(|error| anyhow!("flush migration registry fence before side effects: {error}"))?;
    verify(home, &record.original, Some(record))
}

pub(super) fn reject_conflicts(home: &Path, original: Option<&HostMigrationOperation>, source: &str, account: &str) -> Result<()> {
    let Some(key) = open(home)? else { return Ok(()); };
    check_size(&key)?;
    for item in key.RegEnumValue().map_err(|error| anyhow!("enumerate migration registry: {error}"))? {
        let (name, _) = item.map_err(|error| anyhow!("read migration registry entry: {error}"))?;
        let fence = read(&key, &name)?.context("migration registry fence disappeared")?;
        if original.is_some_and(|original| original.operation_id == fence.operation) { continue; }
        if fence.source == source || fence.account.eq_ignore_ascii_case(account) {
            let candidate = read_frames(home, &home.join(".rsrs-migration-intents").join(format!("{name}.json")))?
                .context("an unfinished migration has lost its file evidence; no new operation was admitted")?;
            verify(home, &candidate.original, Some(&candidate))?;
            anyhow::ensure!(candidate.phase == Phase::RejectedSchema || migration_control_result(&candidate.original)?.is_some(),
                "another unfinished migration owns this source or account");
        }
    }
    Ok(())
}


#[cfg(test)]
pub(super) struct TestScope(PathBuf);
#[cfg(test)]
impl TestScope {
    pub(super) fn new(home: &Path) -> Self { Self(home.to_owned()) }
}
#[cfg(test)]
impl Drop for TestScope {
    fn drop(&mut self) {
        // Only this test's canonical temporary-home hash beneath Tests is removed.
        if let Ok(path) = key_path(&self.0) {
            let _ = HKEY::CURRENT_USER.RegDeleteTree(Some(&path));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_fence_detects_lost_file_and_retains_cross_operation_exclusion() -> Result<()> {
        let _isolate = crate::test_lock::Isolate::new()?;
        let temp = tempfile::tempdir()?;
        let home = temp.path().canonicalize()?;
        let _scope = TestScope::new(&home);
        let (original, profile) = super::super::tests::fixture(&home)?;
        let record = admit_or_load(&home, &original, &profile)?;
        verify(&home, &original, Some(&record))?;
        let journal = path(&home, &original)?;
        std::fs::rename(&journal, home.join("retained-journal"))?;
        assert!(load(&home, &original).is_err());
        let mut other = original.clone();
        other.operation_id = uuid::Uuid::new_v4().to_string();
        other.key = other.operation_id.clone();
        assert!(admit_or_load(&home, &other, &profile).is_err());
        assert!(!path(&home, &other)?.exists());
        Ok(())
    }

    #[test]
    fn registry_old_frame_cannot_authorize_new_file_phase() -> Result<()> {
        let _isolate = crate::test_lock::Isolate::new()?;
        let temp = tempfile::tempdir()?;
        let home = temp.path().canonicalize()?;
        let _scope = TestScope::new(&home);
        let (original, profile) = super::super::tests::fixture(&home)?;
        let mut record = admit_or_load(&home, &original, &profile)?;
        // Model a file append whose registry flush was never acknowledged.
        // This is not a physical power-loss test.
        record.phase = Phase::Transforming;
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new().append(true).open(path(&home, &original)?)?;
        let mut frame = serde_json::to_vec(&record)?;
        frame.push(b'\n');
        file.write_all(&frame)?;
        file.sync_all()?;
        assert!(load(&home, &original).is_err());
        assert!(!profile.destination.exists());
        Ok(())
    }

    #[test]
    fn registry_transforming_rejects_rolled_back_copying_file_and_new_operation() -> Result<()> {
        let _isolate = crate::test_lock::Isolate::new()?;
        let temp = tempfile::tempdir()?;
        let home = temp.path().canonicalize()?;
        let _scope = TestScope::new(&home);
        let (original, profile) = super::super::tests::fixture(&home)?;
        let mut record = admit_or_load(&home, &original, &profile)?;
        let journal = path(&home, &original)?;
        let old_file = std::fs::read(&journal)?;
        record.phase = Phase::Transforming;
        save(&home, &record)?;
        // Model old file state while the authoritative fence is already newer.
        std::fs::write(&journal, old_file)?;
        assert!(load(&home, &original).is_err());
        let mut other = original.clone();
        other.operation_id = uuid::Uuid::new_v4().to_string();
        other.key = other.operation_id.clone();
        assert!(admit_or_load(&home, &other, &profile).is_err());
        assert!(!profile.destination.exists());
        Ok(())
    }

    #[test]
    fn registry_missing_or_wrong_type_is_not_a_fresh_admission() -> Result<()> {
        let _isolate = crate::test_lock::Isolate::new()?;
        let temp = tempfile::tempdir()?;
        let home = temp.path().canonicalize()?;
        let _scope = TestScope::new(&home);
        let (original, profile) = super::super::tests::fixture(&home)?;
        admit_or_load(&home, &original, &profile)?;
        let key = HKEY::CURRENT_USER.RegOpenKeyEx(Some(&key_path(&home)?), co::REG_OPTION::default(),
            co::KEY::QUERY_VALUE | co::KEY::SET_VALUE | co::KEY::WOW64_64KEY)
            .map_err(|error| anyhow!("open isolated test key: {error}"))?;
        key.RegSetValueEx(Some(&original.operation_id), RegistryValue::Dword(1))
            .map_err(|error| anyhow!("set isolated test type: {error}"))?;
        assert!(load(&home, &original).is_err());
        key.RegDeleteValue(Some(&original.operation_id))
            .map_err(|error| anyhow!("remove isolated test value: {error}"))?;
        assert!(load(&home, &original).is_err());
        assert!(admit_or_load(&home, &original, &profile).is_err());
        Ok(())
    }

}
