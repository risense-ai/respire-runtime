use anyhow::{ensure, Result};
use crate::MemoryEntry;
use crate::transport::local::LocalStore;
use crate::transport::MemoryTransport;

pub const MODE_KEY: &str = "memory_metadata_v1_mode";

/// This local declaration does not exclude old or offline writers.
pub fn mode(store: &LocalStore) -> Result<String> {
    let value = store.meta_get(MODE_KEY)?.unwrap_or_else(|| "isolated".to_owned());
    ensure!(matches!(value.as_str(), "isolated" | "controlled_writers"), "invalid memory_metadata_v1_mode");
    Ok(value)
}

pub fn require_support() -> Result<()> {
    let capabilities: serde_json::Value = crate::core_sdk::execute("capabilities", serde_json::Value::Null)?;
    ensure!(capabilities["memory_metadata_contract"].as_u64() == Some(1),
        "memory_metadata_v1_unsupported: install the paired Core SDK/CLI with memory_metadata_contract 1");
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum Deployment {
    Isolated,
    ControlledWriters {
        all_writers_upgraded: bool,
        old_clients_disconnected: bool,
        offline_writes_reconciled: bool,
    },
}

#[derive(Debug, serde::Serialize)]
pub struct EnableReceipt {
    pub enabled: bool,
    pub deployment: Deployment,
    pub backup: crate::snapshot::Manifest,
}

/// Deployment conditions are an operator attestation, not an old-client access barrier.
pub fn enable(
    root: &std::path::Path, lock: &crate::lock::LibraryLock,
    account: &str, keys: &crate::SessionKeys, deployment: Deployment,
) -> Result<EnableReceipt> {
    ensure!(lock.protects(root)?, "metadata gate requires the library ownership lock");
    require_support()?;
    if let Deployment::ControlledWriters { all_writers_upgraded, old_clients_disconnected, offline_writes_reconciled } = &deployment {
        ensure!(*all_writers_upgraded && *old_clients_disconnected && *offline_writes_reconciled,
            "controlled_writers requires upgraded writers, disconnected old clients and reconciled offline writes");
    }
    crate::snapshot::ensure_no_incomplete_restore(root)?;
    let store = LocalStore::open_existing(&crate::service::database_path(root)?)?;
    let revision = store.memory_revision()?;
    let backup = crate::snapshot::create(root, account, "before enabling memory metadata v1", keys)?;
    let backup = crate::snapshot::verify_backup(root, &backup.id, keys)?;
    let mode = match deployment { Deployment::Isolated => "isolated", Deployment::ControlledWriters { .. } => "controlled_writers" };
    store.write_transaction(|| {
        ensure!(store.memory_revision()? == revision, "library changed while creating metadata backup; gate remains unchanged");
        store.meta_set(MODE_KEY, mode)?;
        store.meta_set("memory_metadata_v1_deployment", &serde_json::to_string(&deployment)?)?;
        store.meta_set("memory_metadata_v1_backup", &serde_json::to_string(&backup)?)?;
        store.meta_set("memory_metadata_v1_enabled", "1")
    })?;
    Ok(EnableReceipt { enabled: true, deployment, backup })
}

pub fn ensure_write(store: &LocalStore, entry: &MemoryEntry) -> Result<()> {
    entry.metadata.validate()?;
    ensure!(entry.metadata.memory_contract != 0 || !matches!(entry.kind,
        crate::memory::Kind::Hypothesis | crate::memory::Kind::Reflection | crate::memory::Kind::SelfNote),
        "invalid_metadata: new kind requires memory contract 1");
    crate::memory::model::metadata::validate_extra_fields(&entry.unknown_fields)?;
    if entry.metadata.memory_contract != 0 {
        ensure!(store.memory_metadata_v1_enabled()?, "memory_metadata_v1_disabled");
        mode(store)?;
        require_support()?;
    }
    Ok(())
}

pub fn ensure_sync_allowed(store: &LocalStore) -> Result<()> {
    let enabled = store.memory_metadata_v1_enabled()?;
    let isolated = mode(store)? == "isolated";
    if !isolated { require_support()?; }
    if isolated {
        ensure!(!enabled
            && !store.has_memory_metadata()?,
            "memory_metadata_v1_isolated: this library cannot sync");
    }
    Ok(())
}

/// Read-only check for snapshot and remote-configuration entry points.
pub(crate) fn ensure_connection_sync_allowed(connection: &rusqlite::Connection) -> Result<()> {
    use rusqlite::OptionalExtension;
    let mode: Option<String> = connection.query_row("SELECT value FROM meta WHERE key=?1", [MODE_KEY], |row| row.get(0)).optional()?;
    let mode = mode.as_deref().unwrap_or("isolated");
    ensure!(matches!(mode, "isolated" | "controlled_writers"), "invalid memory_metadata_v1_mode");
    let enabled: Option<String> = connection.query_row("SELECT value FROM meta WHERE key='memory_metadata_v1_enabled'", [], |row| row.get(0)).optional()?;
    ensure!(matches!(enabled.as_deref(), None | Some("0") | Some("1")), "invalid memory_metadata_v1_enabled");
    if mode == "controlled_writers" { require_support()?; }
    if mode == "isolated" {
        let has_column: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM pragma_table_info('memories') WHERE name='memory_contract')", [], |row| row.get(0))?;
        let has_metadata = has_column && crate::transport::local::has_memory_metadata(connection)?;
        ensure!(enabled.as_deref() != Some("1") && !has_metadata, "memory_metadata_v1_isolated: this library cannot sync");
    }
    Ok(())
}

pub(crate) fn ensure_restore_allowed(live: &std::path::Path, source: &std::path::Path) -> Result<()> {
    use rusqlite::OptionalExtension;
    let live = rusqlite::Connection::open_with_flags(live, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let controlled: bool = live.query_row("SELECT EXISTS(SELECT 1 FROM meta WHERE key=?1 AND value='controlled_writers')", [MODE_KEY], |row| row.get(0))?;
    if !controlled { return Ok(()); }
    let source = rusqlite::Connection::open_with_flags(source, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let enabled: Option<String> = source.query_row("SELECT value FROM meta WHERE key='memory_metadata_v1_enabled'", [], |row| row.get(0)).optional()?;
    ensure!(enabled.as_deref() == Some("1"), "old backup cannot replace a controlled-writers library; isolate the library and stop remote writes first");
    Ok(())
}

/// Reject known required dependency cycles before writing a new head.
pub fn ensure_sources(keys: &crate::SessionKeys, store: &LocalStore, entry: &MemoryEntry) -> Result<()> {
    if entry.metadata.source_refs.is_empty() { return Ok(()); }
    let mut graph = std::collections::HashMap::new();
    for row in store.all(false)? {
        if row.id == entry.id { continue; }
        let old = crate::MemoryEngine::open(keys, &row)?;
        graph.insert(old.id, old.metadata.source_refs);
    }
    graph.insert(entry.id.clone(), entry.metadata.source_refs.clone());
    let mut complete = std::collections::HashSet::new();
    let mut active = std::collections::HashSet::new();
    let mut stack = vec![(entry.id.clone(), false)];
    while let Some((id, exiting)) = stack.pop() {
        if exiting { active.remove(&id); complete.insert(id); continue; }
        if complete.contains(&id) { continue; }
        ensure!(active.insert(id.clone()), "invalid_metadata: required source cycle");
        stack.push((id.clone(), true));
        if let Some(sources) = graph.get(&id) {
            for source in sources.iter().filter(|source| source.required) {
                stack.push((source.id.clone(), false));
            }
        }
    }
    Ok(())
}
