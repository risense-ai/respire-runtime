//! Explicit, bounded diary retrieval. Diary matches never enter normal recall.
//! Only derived opaque Core artifacts are persisted; original encrypted records stay intact.
use crate::core_sdk::{self, search::Embedder, Snapshot};
use crate::transport::local::LocalStore;
use crate::{MemoryEngine, MemoryEntry, MemoryQuery, MemoryTransport, SessionKeys, StoredMemory};
use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

#[cfg(test)]
#[path = "diary_tests.rs"]
mod tests;

#[path = "diary_fragments.rs"]
mod fragments;
const LIMIT_MAX: usize = 20;
const BUDGET_MAX: usize = 12000;
const CACHE_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS diary_sources(id TEXT PRIMARY KEY, source TEXT NOT NULL); CREATE TABLE IF NOT EXISTS diary_artifacts(id TEXT PRIMARY KEY, source_id TEXT NOT NULL, generation TEXT NOT NULL, artifact BLOB NOT NULL)";

#[derive(Clone, Serialize)]
pub struct Fragment {
    pub source_kind: &'static str,
    pub evidence_state: &'static str,
    pub source_id: String,
    pub fragment_id: String,
    pub source_version: String,
    pub date: String,
    pub title: String,
    pub project: String,
    pub start: usize,
    pub end: usize,
    pub text: String,
    /// Ranking only, not credibility or factual confidence.
    pub score: f32,
    pub truncated: bool,
    #[serde(skip)]
    anchor: usize,
    #[serde(skip)]
    index_id: String,
}

#[derive(Serialize)]
pub struct FragmentResult {
    pub items: Vec<Fragment>,
    pub semantic_ready: bool,
    pub pending_fragments: usize,
    pub truncated: bool,
    pub max_chars: usize,
    pub offset_unit: &'static str,
}

fn digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}
fn cache_path() -> std::path::PathBuf {
    let root = crate::service::data_dir();
    // Existing library directories may have legitimate aliases (macOS /var).
    // Resolve only the directory; SQLite NOFOLLOW still protects the cache file.
    root.canonicalize()
        .unwrap_or(root)
        .join("diary-fragments-v1.db")
}

fn model_cache_path(model: &str) -> Result<std::path::PathBuf> {
    if core_sdk::profiles::current()?.is_none() { return Ok(cache_path()); }
    let generation = core_sdk::generation_key(model)?;
    Ok(cache_path().with_file_name(format!("diary-fragments-{}.db", digest(&generation))))
}
fn model_cache(model: &str, readonly: bool) -> Result<Option<Connection>> {
    cache_at(&model_cache_path(model)?, readonly)
}
#[derive(Debug)]
struct DamagedCache;
impl std::fmt::Display for DamagedCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("derived diary cache needs reconstruction")
    }
}
impl std::error::Error for DamagedCache {}
fn schema_error(error: rusqlite::Error) -> anyhow::Error {
    match &error {
        rusqlite::Error::SqliteFailure(code, _) if code.extended_code == 1 => DamagedCache.into(),
        _ => error.into(),
    }
}
fn cache_at(path: &std::path::Path, readonly: bool) -> Result<Option<Connection>> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "unsafe diary cache path"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                anyhow::ensure!(
                    metadata.nlink() == 1,
                    "linked diary cache is not writable derived state"
                );
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if readonly {
                return Ok(None);
            }
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(path)?;
        }
        Err(error) => return Err(error.into()),
    }
    let db = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_NOFOLLOW
            | if readonly {
                OpenFlags::SQLITE_OPEN_READ_ONLY
            } else {
                OpenFlags::SQLITE_OPEN_READ_WRITE
            },
    )?;
    db.busy_timeout(std::time::Duration::from_millis(200))?;
    // Refuse an unrelated database before any schema write, even at this name.
    let unknown:i64=db.query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT IN ('diary_sources','diary_artifacts')",[],|r|r.get(0))?;
    anyhow::ensure!(
        unknown == 0,
        "unexpected database at diary cache path; refusing mutation"
    );
    if !readonly {
        db.execute_batch(CACHE_SCHEMA)?;
    }
    db.prepare("SELECT id,source FROM diary_sources LIMIT 0")
        .map_err(schema_error)?;
    db.prepare("SELECT id,source_id,generation,artifact FROM diary_artifacts LIMIT 0")
        .map_err(schema_error)?;
    let invalid:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM diary_sources WHERE typeof(id)!='text' OR typeof(source)!='text') OR EXISTS(SELECT 1 FROM diary_artifacts WHERE typeof(id)!='text' OR typeof(source_id)!='text' OR typeof(generation)!='text' OR typeof(artifact)!='blob')",[],|r|r.get(0))?;
    if invalid {
        return Err(DamagedCache.into());
    }
    Ok(Some(db))
}
#[cfg(test)]
fn cache(readonly: bool) -> Result<Option<Connection>> {
    cache_at(&cache_path(), readonly)
}
fn writable_cache(path: &std::path::Path) -> Result<Connection> {
    match cache_at(path, false) {
        Ok(Some(db)) => Ok(db),
        Ok(None) => bail!("derived diary cache unavailable"),
        Err(error) => {
            let damaged=error.is::<DamagedCache>() || error.downcast_ref::<rusqlite::Error>().is_some_and(|error|
                matches!(error,rusqlite::Error::SqliteFailure(code,_) if matches!(code.code,rusqlite::ErrorCode::DatabaseCorrupt|rusqlite::ErrorCode::NotADatabase)));
            if !damaged {
                return Err(error);
            }
            // Only discardable derived state is moved; original bytes remain for diagnosis.
            let quarantine = path.with_file_name(format!(
                "diary-fragments-corrupt-{}.db",
                uuid::Uuid::new_v4()
            ));
            std::fs::rename(path, quarantine)?;
            cache_at(path, false)?.context("cannot reconstruct diary cache")
        }
    }
}

fn diaries(store: &LocalStore) -> Result<Vec<StoredMemory>> {
    Ok(store
        .all(false)?
        .into_iter()
        .filter(|m| m.local_importance == "trivial")
        .collect())
}
fn version(m: &StoredMemory) -> String {
    digest(&format!("{}:{}", m.nonce, m.ciphertext))
}
fn day(entry: &MemoryEntry) -> String {
    chrono::DateTime::parse_from_rfc3339(&entry.created_at)
        .map(|date| {
            date.with_timezone(&chrono::Local)
                .format("%Y-%m-%d")
                .to_string()
        })
        .unwrap_or_else(|_| entry.created_at.chars().take(10).collect())
}
fn piece(
    entry: &MemoryEntry,
    source_version: &str,
    chars: &[char],
    start: usize,
    end: usize,
) -> Fragment {
    let text: String = chars[start..end].iter().collect();
    // Embedding identity is stable for unchanged text/metadata after an append.
    let key = digest(&format!(
        "{}:{start}:{text}:{}:{}:{:?}:{}:{:?}",
        entry.id, entry.title, entry.project, entry.tags, entry.computer, entry.kind
    ));
    // A public locator additionally binds the exact source revision and range.
    let locator = digest(&format!("{key}:{source_version}:{end}"));
    Fragment {
        source_kind: "diary",
        evidence_state: "reference",
        source_id: entry.id.clone(),
        fragment_id: format!("d1.{start}.{end}.{}", &locator[..32]),
        index_id: key[..32].into(),
        source_version: source_version.into(),
        date: day(entry),
        title: entry.title.chars().take(80).collect(),
        project: entry.project.chars().take(80).collect(),
        start,
        end,
        text,
        score: 0.0,
        truncated: false,
        anchor: 0,
    }
}
fn split(entry: &MemoryEntry, source_version: &str) -> Vec<Fragment> {
    let chars: Vec<char> = entry.content.chars().collect();
    fragments::ranges(&entry.content)
        .into_iter()
        .map(|(start, end)| piece(entry, source_version, &chars, start, end))
        .collect()
}
fn indexed_entry(source: &MemoryEntry, fragment: &Fragment) -> MemoryEntry {
    // Never clone a whole day's plaintext to immediately replace its content.
    MemoryEntry {
        metadata: source.metadata.clone(),
        unknown_fields: source.unknown_fields.clone(),
        id: format!("diary-fragment:{}", fragment.index_id),
        content: fragment.text.clone(),
        kind: source.kind,
        tags: source.tags.clone(),
        title: source.title.clone(),
        user: source.user.clone(),
        computer: source.computer.clone(),
        project: source.project.clone(),
        created_at: source.created_at.clone(),
        updated_at: source.updated_at.clone(),
        emotion: source.emotion,
        importance: source.importance.clone(),
        device: source.device.clone(),
        modified_by: source.modified_by.clone(),
        parent_id: String::new(),
        supersedes: String::new(),
        superseded_by: String::new(),
        see_also: Vec::new(),
    }
}

/// Match the authoritative full text, not the lossy indexing windows. Map folded
/// UTF-8 positions back to original Unicode scalars, including expanded casing.
fn lexical(entry: &MemoryEntry, revision: &str, terms: &[String]) -> (Vec<Fragment>, bool) {
    let folded = entry.content.to_lowercase();
    let title = entry.title.to_lowercase();
    let project = entry.project.to_lowercase();
    if !terms
        .iter()
        .all(|term| title.contains(term) || project.contains(term) || folded.contains(term))
    {
        return (Vec::new(), false);
    }
    let mut omitted = false;
    let spans: Vec<_> = terms
        .iter()
        .flat_map(|term| {
            let mut positions: Vec<_> = folded
                .match_indices(term.as_str())
                .take(LIMIT_MAX + 1)
                .map(|(at, _)| (at, at + term.len()))
                .collect();
            omitted |= positions.len() > LIMIT_MAX;
            positions.truncate(LIMIT_MAX);
            positions
        })
        .collect();
    let mut mapped = vec![(0, 0); spans.len()];
    let mut points: Vec<_> = spans
        .iter()
        .enumerate()
        .flat_map(|(i, &(a, b))| [(a, i, false), (b - 1, i, true)])
        .collect();
    points.sort_unstable();
    let chars: Vec<char> = entry.content.chars().collect();
    let (mut cursor, mut next) = (0, 0);
    for (original, ch) in chars.iter().enumerate() {
        cursor += ch.to_lowercase().map(char::len_utf8).sum::<usize>();
        while next < points.len() && points[next].0 < cursor {
            let (_, i, end) = points[next];
            if end {
                mapped[i].1 = original + 1;
            } else {
                mapped[i].0 = original;
            }
            next += 1;
        }
    }
    mapped.sort_unstable();
    mapped.dedup();
    if mapped.is_empty() {
        mapped.push((0, 0));
    }
    let mut groups: Vec<(usize, usize)> = Vec::new();
    for (start, end) in mapped {
        if let Some(last) = groups
            .last_mut()
            .filter(|last| end.max(last.1) - last.0 <= fragments::CHUNK_CHARS)
        {
            last.1 = last.1.max(end);
        } else {
            groups.push((start, end));
        }
    }
    omitted |= groups.len() > LIMIT_MAX;
    let hits = groups
        .into_iter()
        .take(LIMIT_MAX)
        .map(|(at, end)| {
            let start = at.saturating_sub((fragments::CHUNK_CHARS - (end - at)) / 3);
            let stop = (start + fragments::CHUNK_CHARS).min(chars.len());
            let mut hit = piece(entry, revision, &chars, start, stop);
            hit.anchor = at - start;
            hit.score = 2.0;
            hit
        })
        .collect();
    (hits, omitted)
}

fn select(mut hits: Vec<Fragment>, limit: usize) -> Vec<Fragment> {
    hits.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| b.date.cmp(&a.date))
            .then_with(|| a.source_id.cmp(&b.source_id))
            .then_with(|| a.start.cmp(&b.start))
    });
    let mut selected: Vec<Fragment> = Vec::new();
    for hit in hits {
        if !selected.iter().any(|other| {
            other.source_id == hit.source_id && hit.start < other.end && other.start < hit.end
        }) {
            selected.push(hit);
            if selected.len() == limit {
                break;
            }
        }
    }
    selected
}

pub fn needs_rebuild(store: &LocalStore) -> Result<bool> {
    let sources = diaries(store)?;
    let result = (|| -> Result<bool> {
        let model = core_sdk::profiles::current()?.map(|s| s.model).unwrap_or(store.retrieval_model()?);
        let Some(db) = model_cache(&model, true)? else {
            return Ok(!sources.is_empty());
        };
        if sources.is_empty() {
            return Ok(db.query_row("SELECT EXISTS(SELECT 1 FROM diary_sources) OR EXISTS(SELECT 1 FROM diary_artifacts)",[],|r|r.get::<_,bool>(0))?);
        }
        if db.query_row("SELECT count(*) FROM diary_sources", [], |r| {
            r.get::<_, usize>(0)
        })? != sources.len()
        {
            return Ok(true);
        }
        let generation = core_sdk::generation_key(&model)?;
        let mut stmt = db.prepare("SELECT generation,artifact FROM diary_artifacts")?;
        let artifacts = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if artifacts.iter().any(|(key, _)| key != &generation) {
            return Ok(true);
        }
        if !artifacts.is_empty()
            && !core_sdk::index_ready(&artifacts.into_iter().map(|(_, a)| a).collect::<Vec<_>>())?
        {
            return Ok(true);
        }
        for source in sources {
            let old: Option<String> = db
                .query_row(
                    "SELECT source FROM diary_sources WHERE id=?1",
                    [&source.id],
                    |r| r.get(0),
                )
                .optional()?;
            if old.as_deref() != Some(version(&source).as_str()) {
                return Ok(true);
            }
        }
        Ok(false)
    })();
    // Broken or incompatible derived state requests rebuild, never blocks original text.
    Ok(result.unwrap_or(true))
}

/// Remove obsolete derived rows after the final diary is removed/promoted,
/// without preparing or downloading an otherwise unused model.
pub fn clear_if_empty(
    store: &LocalStore,
    mut commit: impl FnMut(&mut dyn FnMut() -> Result<()>) -> Result<()>,
) -> Result<bool> {
    let revision = store
        .meta_get("memory_revision_v1")?
        .context("memory snapshot token unavailable")?;
    if !diaries(store)?.is_empty() {
        return Ok(false);
    }
    let path = model_cache_path(&store.retrieval_model()?)?;
    guarded(store, &revision, &mut commit, || {
        let mut db = writable_cache(&path)?;
        let tx = db.transaction()?;
        tx.execute("DELETE FROM diary_artifacts", [])?;
        tx.execute("DELETE FROM diary_sources", [])?;
        tx.commit()?;
        Ok(())
    })?;
    Ok(true)
}

/// Core preparation stays outside locks. Every durable cache mutation must be
/// executed exactly once by the runtime's short context/cancellation commit guard.
pub fn rebuild<E: Embedder>(
    store: &LocalStore,
    keys: &SessionKeys,
    provider: &E,
    check: impl FnMut() -> Result<()>,
    commit: impl FnMut(&mut dyn FnMut() -> Result<()>) -> Result<()>,
) -> Result<()> {
    rebuild_with_progress(store, keys, provider, check, commit, |_| Ok(()))
}

/// Report completed fragment work so cancellation/idle accounting reflects actual progress.
pub fn rebuild_with_progress<E: Embedder>(
    store: &LocalStore,
    keys: &SessionKeys,
    provider: &E,
    mut check: impl FnMut() -> Result<()>,
    mut commit: impl FnMut(&mut dyn FnMut() -> Result<()>) -> Result<()>,
    mut progress: impl FnMut(usize) -> Result<()>,
) -> Result<()> {
    let mut completed = 0;
    progress(completed)?;
    let revision = store
        .meta_get("memory_revision_v1")?
        .context("memory snapshot token unavailable")?;
    let sources = diaries(store)?;
    let path = model_cache_path(provider.model_name())?;
    let mut db = None;
    check()?;
    guarded(store, &revision, &mut commit, || {
        db = Some(writable_cache(&path)?);
        Ok(())
    })?;
    let mut db = db.context("diary commit guard did not initialize cache")?;
    let generation = core_sdk::generation_key(provider.model_name())?;
    let mut live_sources = HashSet::new();
    for source in sources {
        check()?;
        live_sources.insert(source.id.clone());
        let current_version = version(&source);
        let entry = MemoryEngine::open(keys, &source)
            .with_context(|| format!("cannot decode diary {}", source.id))?;
        let cached = {
            let mut stmt = db.prepare(
                "SELECT id,artifact FROM diary_artifacts WHERE source_id=?1 AND generation=?2",
            )?;
            let rows = stmt
                .query_map(params![source.id, generation], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
                })?
                .collect::<rusqlite::Result<HashMap<_, _>>>()?;
            rows
        };
        let ready = cached.is_empty()
            || core_sdk::index_ready(&cached.values().cloned().collect::<Vec<_>>())
                .unwrap_or(false);
        let mut live = HashSet::new();
        for fragment in split(&entry, &current_version) {
            check()?;
            live.insert(fragment.index_id.clone());
            if !(ready && cached.contains_key(&fragment.index_id)) {
                let prepared = provider.prepare(&indexed_entry(&entry, &fragment))?;
                guarded(store, &revision, &mut commit, || {
                    db.execute("INSERT OR REPLACE INTO diary_artifacts(id,source_id,generation,artifact) VALUES(?1,?2,?3,?4)",params![fragment.index_id,source.id,generation,prepared.artifact])?;
                    Ok(())
                })?;
            }
            completed += 1;
            progress(completed)?;
        }
        check()?;
        guarded(store, &revision, &mut commit, || {
            let tx = db.transaction()?;
            let ids = {
                let mut stmt = tx.prepare("SELECT id FROM diary_artifacts WHERE source_id=?1")?;
                let rows = stmt
                    .query_map([&source.id], |r| r.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                rows
            };
            for id in ids {
                if !live.contains(&id) {
                    tx.execute("DELETE FROM diary_artifacts WHERE id=?1", [id])?;
                }
            }
            tx.execute(
                "INSERT OR REPLACE INTO diary_sources(id,source) VALUES(?1,?2)",
                params![source.id, current_version],
            )?;
            tx.commit()?;
            Ok(())
        })?;
    }
    check()?;
    guarded(store, &revision, &mut commit, || {
        let tx = db.transaction()?;
        let ids = {
            let mut stmt = tx.prepare(
                "SELECT id FROM diary_sources UNION SELECT source_id FROM diary_artifacts",
            )?;
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        for id in ids {
            if !live_sources.contains(&id) {
                tx.execute("DELETE FROM diary_artifacts WHERE source_id=?1", [&id])?;
                tx.execute("DELETE FROM diary_sources WHERE id=?1", [&id])?;
            }
        }
        tx.commit()?;
        Ok(())
    })
}
fn guarded(
    store: &LocalStore,
    revision: &str,
    commit: &mut impl FnMut(&mut dyn FnMut() -> Result<()>) -> Result<()>,
    action: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let mut action = Some(action);
    commit(&mut || {
        let action = action
            .take()
            .context("diary commit executed more than once")?;
        // Existing SQLite writer reservation serializes source changes with the
        // derived commit. O(1) revision check replaces per-source full-catalog reads.
        store.write_transaction(|| {
            anyhow::ensure!(
                store.meta_get("memory_revision_v1")?.as_deref() == Some(revision),
                "diary source changed while indexing; retry"
            );
            action()
        })
    })?;
    anyhow::ensure!(
        action.is_none(),
        "diary commit guard did not execute its action"
    );
    Ok(())
}

fn budget(
    mut matches: Vec<Fragment>,
    limit: usize,
    max_chars: usize,
    ready: bool,
    pending: usize,
) -> Result<FragmentResult> {
    anyhow::ensure!((1..=LIMIT_MAX).contains(&limit), "limit must be 1..=20");
    anyhow::ensure!(
        (512..=BUDGET_MAX).contains(&max_chars),
        "max-chars must be 512..=12000 (Unicode characters, not tokens)"
    );
    let mut out = FragmentResult {
        items: Vec::new(),
        semantic_ready: ready,
        pending_fragments: pending,
        truncated: matches.len() > limit,
        max_chars,
        offset_unit: "unicode_scalar",
    };
    matches.truncate(limit);
    for mut hit in matches {
        let used = serde_json::to_string(&out)?.chars().count();
        let overhead = {
            let mut empty = hit.clone();
            empty.text.clear();
            serde_json::to_string(&empty)?.chars().count() + 2
        };
        if used + overhead >= max_chars {
            out.truncated = true;
            break;
        }
        let remaining = max_chars - used - overhead;
        if hit.text.chars().count() > remaining {
            let window = hit.anchor.saturating_sub(remaining / 3);
            hit.text = hit.text.chars().skip(window).take(remaining).collect();
            hit.start += window;
            hit.end = hit.start + hit.text.chars().count();
            hit.truncated = true;
            out.truncated = true;
        }
        // JSON escaping can require more space than the raw text.
        out.items.push(hit);
        while serde_json::to_string(&out)?.chars().count() > max_chars {
            let last = out.items.last_mut().unwrap();
            if last.text.pop().is_none() {
                out.items.pop();
                break;
            }
            last.end = last.start + last.text.chars().count();
            last.truncated = true;
            out.truncated = true;
        }
    }
    Ok(out)
}

/// Explicit diary search. Queries never prepare a whole year's embeddings on the foreground path.
pub fn search(
    store: &LocalStore,
    keys: &SessionKeys,
    query: &str,
    limit: usize,
    max_chars: usize,
    hybrid: bool,
) -> Result<FragmentResult> {
    anyhow::ensure!(
        !query.trim().is_empty() && query.chars().count() <= 500,
        "query must contain 1..=500 characters"
    );
    anyhow::ensure!((1..=LIMIT_MAX).contains(&limit), "limit must be 1..=20");
    anyhow::ensure!(
        (512..=BUDGET_MAX).contains(&max_chars),
        "max-chars must be 512..=12000"
    );
    let terms: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
    // Lexical mode does not even open the disposable semantic cache.
    let db = if hybrid {
        model_cache(&store.retrieval_model()?, true).ok().flatten()
    } else {
        None
    };
    let mut all = HashMap::new();
    let mut snapshots = Vec::new();
    let mut hits = Vec::new();
    let mut pending = 0;
    let mut omitted = false;
    let generation = if hybrid && db.is_some() {
        Some(core_sdk::generation_key(&store.retrieval_model()?)?)
    } else {
        None
    };
    for source in diaries(store)? {
        let entry = MemoryEngine::open(keys, &source)
            .with_context(|| format!("cannot decode diary {}", source.id))?;
        let revision = version(&source);
        let (lexical_hits, more) = lexical(&entry, &revision, &terms);
        omitted |= more;
        hits.extend(lexical_hits);
        hits = select(hits, LIMIT_MAX + 1);
        if hits.len() > LIMIT_MAX {
            omitted = true;
            hits.truncate(LIMIT_MAX);
        }
        if !hybrid {
            continue;
        }
        for hit in split(&entry, &revision) {
            let artifact = if let (Some(db), Some(generation)) = (&db, &generation) {
                db.query_row(
                    "SELECT artifact FROM diary_artifacts WHERE id=?1 AND generation=?2",
                    params![hit.index_id, generation],
                    |r| r.get::<_, Vec<u8>>(0),
                )
                .optional()
                .unwrap_or(None)
            } else {
                None
            };
            if let Some(artifact) = artifact.filter(|value| !value.is_empty()) {
                let indexed = indexed_entry(&entry, &hit);
                snapshots.push(Snapshot {
                    id: indexed.id.clone(),
                    deleted: false,
                    updated_at: indexed.updated_at.clone(),
                    kind: source.local_kind.clone(),
                    tags: source.local_tags.clone(),
                    title: indexed.title.clone(),
                    project: indexed.project.clone(),
                    computer: indexed.computer.clone(),
                    parent_id: String::new(),
                    created_at: indexed.created_at.clone(),
                    content_head: indexed.content.clone(),
                    recall_count: 0,
                    importance: indexed.importance.clone(),
                    entry: Some(indexed.clone()),
                    features: Some(core_sdk::Prepared { artifact }),
                });
                all.insert(indexed.id, hit);
            } else {
                pending += 1;
            }
        }
    }
    if !snapshots.is_empty()
        && !core_sdk::index_ready(
            &snapshots
                .iter()
                .filter_map(|s| s.features.as_ref().map(|f| f.artifact.clone()))
                .collect::<Vec<_>>(),
        )
        .unwrap_or(false)
    {
        pending += snapshots.len();
        snapshots.clear();
    }
    let mut ready = false;
    if hybrid && !snapshots.is_empty() {
        let semantic = (|| -> Result<Vec<(f32, MemoryEntry)>> {
            let provider = crate::memory::bge::BgeEmbedder::load_model(&store.retrieval_model()?)?;
            core_sdk::query(
                &provider,
                &snapshots,
                &MemoryQuery::new(query).limit(LIMIT_MAX),
                "scored",
            )
        })();
        match semantic {
            Ok(results) => {
                ready = pending == 0;
                for (score, entry) in results {
                    if score.is_finite() && score > 0.0 {
                        if let Some(mut hit) = all.remove(&entry.id) {
                            hit.score = score.min(1.0);
                            hits.push(hit);
                        }
                    }
                }
            }
            Err(_) => pending += snapshots.len(),
        }
    }
    let mut result = budget(select(hits, limit + 1), limit, max_chars, ready, pending)?;
    result.truncated |= omitted;
    Ok(result)
}

pub fn read_fragment(
    store: &LocalStore,
    keys: &SessionKeys,
    source_id: &str,
    fragment_id: &str,
    neighbors: usize,
    max_chars: usize,
) -> Result<FragmentResult> {
    anyhow::ensure!(neighbors <= 1, "neighbors must be 0 or 1");
    let source = diaries(store)?
        .into_iter()
        .find(|m| m.id == source_id)
        .context("diary source not found or no longer active")?;
    let entry = MemoryEngine::open(keys, &source)?;
    let revision = version(&source);
    let mut locator = fragment_id.split('.');
    anyhow::ensure!(
        locator.next() == Some("d1"),
        "stale or unknown fragment; search again before reading"
    );
    let start = locator
        .next()
        .and_then(|v| v.parse::<usize>().ok())
        .context("invalid fragment start")?;
    let end = locator
        .next()
        .and_then(|v| v.parse::<usize>().ok())
        .context("invalid fragment end")?;
    let chars: Vec<char> = entry.content.chars().collect();
    anyhow::ensure!(
        start < end && end <= chars.len() && end - start <= fragments::CHUNK_CHARS,
        "stale or unknown fragment; search again before reading"
    );
    let target = piece(&entry, &revision, &chars, start, end);
    anyhow::ensure!(
        target.fragment_id == fragment_id,
        "stale or unknown fragment; search again before reading"
    );
    let mut selected = vec![target];
    if neighbors == 1 {
        let pieces = split(&entry, &revision);
        if let Some(previous) = pieces
            .iter()
            .filter(|f| f.start < start)
            .max_by_key(|f| f.start)
        {
            selected.push(previous.clone());
        }
        if let Some(next) = pieces.iter().filter(|f| f.end > end).min_by_key(|f| f.end) {
            selected.push(next.clone());
        }
    }
    let mut result = budget(selected, 3, max_chars, false, 0)?;
    // Restore source order only after allocating the target's text budget.
    result.items.sort_by_key(|item| item.start);
    Ok(result)
}
