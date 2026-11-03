//! Seal converted entries and import them through the runtime store.
//!
//! Extract is a raw ingester: it does not judge or place memories. Entries land
//! exactly as the converter wrote them (roots unless `--parent` was given), and a
//! later AI-driven tidy attaches them. Mirrors `service::import_json`'s write
//! path (seal each entry with BGE, batch import, one auto-sync) with a per-entry
//! progress callback.

use std::collections::HashMap;

use anyhow::Result;

use crate::memory::model::{MemoryEntry, StoredMemory};
use crate::memory::MemoryEngine;
use crate::service::App;
use crate::transport::MemoryTransport;

/// Entries written per committed chunk, so a long import yields the SQLite write
/// lock periodically instead of holding it for the whole batch.
const IMPORT_CHUNK: usize = 25;

/// Import result: rows written, and per input entry whether it is done (written,
/// or intentionally skipped because the stored row is deleted).
pub struct ImportOutcome {
    pub imported: usize,
    pub completed: Vec<bool>,
}

/// Seal every entry, then import them in committed chunks, then auto-sync once.
///
/// `parent_spec` (id / 8-char prefix / tree or anchor title) is an optional
/// pre-attach: when non-empty it is resolved and applied to entries that have no
/// parent. When empty, entries stay as-is (roots) for a later tidy.
///
/// `progress(done, total)` runs as each entry is sealed (the slow embedding step,
/// performed with no database lock held) and the count is reused for the writes.
/// `on_commit(start, completed)` runs after each chunk commits, so the caller can
/// persist its import cursor between chunks — a failure then resumes from the last
/// committed chunk instead of re-importing from the start.
///
/// Re-import never clobbers user work: a session whose row was deleted is skipped
/// (never resurrected), and an existing row keeps its tidy parent and any edited
/// title. The last-write-wins path also refuses to overwrite a row with unpushed
/// local edits, and that entry is reported as not completed.
pub fn import_entries<F, G>(
    entries: &mut [MemoryEntry],
    parent_spec: &str,
    progress: F,
    on_commit: G,
) -> Result<ImportOutcome>
where
    F: FnMut(usize, usize),
    G: FnMut(usize, &[bool]) -> Result<()>,
{
    if entries.is_empty() {
        return Ok(ImportOutcome {
            imported: 0,
            completed: Vec::new(),
        });
    }
    let app = App::open()?;
    import_entries_with_app(&app, entries, parent_spec, progress, on_commit, || {
        app.auto_sync()
    })
}

fn import_entries_with_app<F, G, H>(
    app: &App,
    entries: &mut [MemoryEntry],
    parent_spec: &str,
    mut progress: F,
    mut on_commit: G,
    auto_sync: H,
) -> Result<ImportOutcome>
where
    F: FnMut(usize, usize),
    G: FnMut(usize, &[bool]) -> Result<()>,
    H: FnOnce(),
{
    let spec = parent_spec.trim();
    if !spec.is_empty() {
        let all = app.store.all(false)?;
        let parent = crate::service::resolve_prefix(&all, spec)?;
        for entry in entries.iter_mut() {
            if entry.parent_id.is_empty() {
                entry.parent_id = parent.clone();
            }
        }
    }
    // Phase 1: seal every entry with no database write, so the slow embedding does
    // not hold the SQLite write lock.
    let existing: HashMap<String, StoredMemory> = app
        .store
        .all(true)?
        .into_iter()
        .map(|memory| (memory.id.clone(), memory))
        .collect();
    let total = entries.len();
    let mut completed = vec![false; total];
    let mut sealed: Vec<Option<StoredMemory>> = Vec::with_capacity(total);
    for (index, entry) in entries.iter_mut().enumerate() {
        if let Some(previous) = existing.get(&entry.id) {
            if previous.deleted {
                completed[index] = true;
                sealed.push(None);
                progress(index + 1, total);
                continue;
            }
            if entry.parent_id.is_empty() {
                entry.parent_id = previous.local_parent_id.clone();
            }
            entry.title = previous.local_title.clone();
        }
        let stored = MemoryEngine::seal(&app.keys, &app.embedder, entry, &entry.user)?;
        sealed.push(Some(stored));
        progress(index + 1, total);
    }
    // Phase 2: write in committed chunks, so the write lock is held only briefly
    // per chunk and other writers can interleave between chunks.
    let mut committed = false;
    let result = (|| {
        let mut imported = 0usize;
        let mut start = 0usize;
        while start < total {
            let end = (start + IMPORT_CHUNK).min(total);
            let flags = app.store.write_transaction(|| {
                let mut flags = vec![false; end - start];
                for (offset, plan) in sealed[start..end].iter().enumerate() {
                    if let Some(stored) = plan {
                        flags[offset] = app.store.put_session_import(stored)?;
                    }
                }
                Ok(flags)
            })?;
            committed = true;
            for (offset, wrote) in flags.iter().enumerate() {
                if *wrote {
                    completed[start + offset] = true;
                    imported += 1;
                }
            }
            on_commit(start, &completed[start..end])?;
            start = end;
        }
        Ok(ImportOutcome {
            imported,
            completed,
        })
    })();
    // A later transaction or cursor error must not suppress notifications for
    // earlier commits. Preserve the original Result after this single cleanup.
    if committed {
        auto_sync();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_import::{session_entry, ConvertOptions, Session};
    use std::cell::Cell;

    fn fixture(count: usize) -> Result<(crate::test_lock::Isolate, App, Vec<MemoryEntry>)> {
        let isolate = crate::test_lock::Isolate::new()?;
        let app = App {
            keys: crate::memory::SessionKeys::from_urk([7; 32])?,
            store: crate::transport::local::LocalStore::open(&isolate.path().join("fixture.db"))?,
            embedder: Box::new(crate::memory::search::HashingEmbedder::default()),
        };
        let entries = (0..count)
            .map(|index| {
                let mut entry = session_entry(
                    &Session {
                        platform: "fixture".into(),
                        id: index.to_string(),
                        first_user_message: "synthetic import regression".into(),
                        updated_at: Some("2026-10-11T00:00:00.000Z".into()),
                        ..Default::default()
                    },
                    &ConvertOptions::default(),
                );
                entry.id = format!("fixture-{index:03}");
                entry
            })
            .collect();
        Ok((isolate, app, entries))
    }

    fn inject_failure(isolate: &crate::test_lock::Isolate, index: usize) -> Result<()> {
        let connection = rusqlite::Connection::open(isolate.path().join("fixture.db"))?;
        connection.execute_batch(&format!(
            "CREATE TRIGGER fail_import BEFORE INSERT ON memories \
             WHEN NEW.id = 'fixture-{index:03}' \
             BEGIN SELECT RAISE(ABORT, 'synthetic chunk failure'); END;"
        ))?;
        Ok(())
    }

    #[test]
    fn later_transaction_failure_syncs_only_committed_chunk() -> Result<()> {
        let (isolate, app, mut entries) = fixture(51)?;
        inject_failure(&isolate, 26)?;
        let syncs = Cell::new(0);
        let mut cursor = Vec::new();
        let result = import_entries_with_app(
            &app,
            &mut entries,
            "",
            |_, _| {},
            |start, flags| {
                cursor.push((start, flags.to_vec()));
                Ok(())
            },
            || syncs.set(syncs.get() + 1),
        );
        let error = match result {
            Err(error) => error,
            Ok(_) => anyhow::bail!("second chunk should fail"),
        };
        assert!(
            error.downcast_ref::<rusqlite::Error>().is_some(),
            "original SQLite error retained"
        );
        assert!(error.to_string().contains("synthetic chunk failure"));
        let rows = app.store.all(true)?;
        assert_eq!(rows.len(), 25);
        assert!(rows.iter().all(|row| row.id.as_str() < "fixture-025"));
        assert_eq!(cursor, vec![(0, vec![true; 25])]);
        assert_eq!(syncs.get(), 1);
        Ok(())
    }

    #[test]
    fn first_transaction_failure_neither_advances_cursor_nor_syncs() -> Result<()> {
        let (isolate, app, mut entries) = fixture(51)?;
        inject_failure(&isolate, 1)?;
        let syncs = Cell::new(0);
        let callbacks = Cell::new(0);
        let result = import_entries_with_app(
            &app,
            &mut entries,
            "",
            |_, _| {},
            |_, _| {
                callbacks.set(callbacks.get() + 1);
                Ok(())
            },
            || syncs.set(syncs.get() + 1),
        );
        assert!(result.is_err());
        assert!(app.store.all(true)?.is_empty());
        assert_eq!(callbacks.get(), 0);
        assert_eq!(syncs.get(), 0);
        Ok(())
    }

    #[test]
    fn successful_import_syncs_once_and_retry_creates_no_duplicates() -> Result<()> {
        let (_isolate, app, mut entries) = fixture(51)?;
        let syncs = Cell::new(0);
        let mut starts = Vec::new();
        let outcome = import_entries_with_app(
            &app,
            &mut entries,
            "",
            |_, _| {},
            |start, flags| {
                assert!(flags.iter().all(|flag| *flag));
                starts.push(start);
                Ok(())
            },
            || syncs.set(syncs.get() + 1),
        )?;
        assert_eq!(outcome.imported, 51);
        assert_eq!(outcome.completed, vec![true; 51]);
        assert_eq!(starts, vec![0, 25, 50]);
        assert_eq!(syncs.get(), 1);
        let retry =
            import_entries_with_app(&app, &mut entries, "", |_, _| {}, |_, _| Ok(()), || {})?;
        assert_eq!(retry.imported, 0);
        assert_eq!(app.store.all(true)?.len(), 51);
        Ok(())
    }

    #[test]
    fn callback_failure_stops_after_commit_and_keeps_original_error() -> Result<()> {
        let (_isolate, app, mut entries) = fixture(51)?;
        let syncs = Cell::new(0);
        let callbacks = Cell::new(0);
        let result = import_entries_with_app(
            &app,
            &mut entries,
            "",
            |_, _| {},
            |_, flags| {
                assert!(flags.iter().all(|flag| *flag));
                callbacks.set(callbacks.get() + 1);
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "synthetic cursor failure",
                )
                .into())
            },
            || syncs.set(syncs.get() + 1),
        );
        let error = match result {
            Err(error) => error,
            Ok(_) => anyhow::bail!("callback should fail"),
        };
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::PermissionDenied)
        );
        assert_eq!(callbacks.get(), 1);
        assert_eq!(app.store.all(true)?.len(), 25);
        assert_eq!(syncs.get(), 1);
        Ok(())
    }

    #[test]
    fn empty_input_does_not_open_app_or_call_callbacks() -> Result<()> {
        let progress_calls = Cell::new(0);
        let commit_calls = Cell::new(0);
        let outcome = import_entries(
            &mut [],
            "",
            |_, _| progress_calls.set(progress_calls.get() + 1),
            |_, _| {
                commit_calls.set(commit_calls.get() + 1);
                Ok(())
            },
        )?;
        assert_eq!(progress_calls.get(), 0);
        assert_eq!(commit_calls.get(), 0);
        assert_eq!(outcome.imported, 0);
        assert!(outcome.completed.is_empty());
        Ok(())
    }

    #[test]
    fn concurrent_delete_is_not_overwritten_by_content_versioned_refresh() -> Result<()> {
        let (_isolate, app, mut entries) = fixture(1)?;
        import_entries_with_app(&app, &mut entries, "", |_, _| {}, |_, _| Ok(()), || {})?;
        let id = entries[0].id.clone();
        let mut refresh = session_entry(
            &Session {
                platform: "hermes".into(),
                id: "refresh".into(),
                first_user_message: "changed source summary".into(),
                ..Default::default()
            },
            &ConvertOptions::default(),
        );
        refresh.id = id.clone();
        let mut deletion_result = Ok(());
        let outcome = import_entries_with_app(
            &app,
            &mut [refresh],
            "",
            |_, _| {
                deletion_result = app.store.forget(&id).map(|_| ());
            },
            |_, _| Ok(()),
            || {},
        )?;
        deletion_result?;
        assert_eq!(outcome.imported, 0);
        assert_eq!(
            outcome.completed,
            vec![false],
            "rejected refresh stays retryable"
        );
        assert!(app.store.all(true)?[0].deleted);
        Ok(())
    }

    fn edit_fixture_body(app: &App, id: &str) -> Result<String> {
        let stored = app
            .store
            .all(true)?
            .into_iter()
            .find(|row| row.id == id)
            .ok_or_else(|| anyhow::anyhow!("fixture row missing"))?;
        let mut entry = MemoryEngine::open(&app.keys, &stored)?;
        entry.content = "synthetic unsynced user edit".into();
        entry.updated_at = app.store.edit_stamp(id)?;
        let edited = MemoryEngine::seal(&app.keys, &app.embedder, &entry, &entry.user)?;
        assert!(app.store.put(&edited)?);
        Ok(entry.updated_at)
    }

    #[test]
    fn sqlite_refresh_preserves_existing_unsynced_body_for_force_and_source_change() -> Result<()> {
        for changed in [false, true] {
            let (_isolate, app, mut entries) = fixture(1)?;
            import_entries_with_app(&app, &mut entries, "", |_, _| {}, |_, _| Ok(()), || {})?;
            let id = entries[0].id.clone();
            app.store.clear_dirty(&id)?;
            let edited_stamp = edit_fixture_body(&app, &id)?;
            let mut refresh = session_entry(
                &Session {
                    platform: "hermes".into(),
                    id: "fixture".into(),
                    first_user_message: if changed {
                        "changed source"
                    } else {
                        "synthetic import regression"
                    }
                    .into(),
                    ..Default::default()
                },
                &ConvertOptions::default(),
            );
            refresh.id = id.clone();
            refresh.updated_at = crate::transport::timestamp_after(Some(&edited_stamp))?;
            let mut flags = Vec::new();
            let outcome = import_entries_with_app(
                &app,
                &mut [refresh],
                "",
                |_, _| {},
                |_, completed| {
                    flags.extend_from_slice(completed);
                    Ok(())
                },
                || {},
            )?;
            assert_eq!(outcome.imported, 0);
            assert_eq!(flags, vec![false]);
            let stored = app.store.all(true)?;
            assert_eq!(
                MemoryEngine::open(&app.keys, &stored[0])?.content,
                "synthetic unsynced user edit"
            );
            // After synchronization clears the pending edit, explicit/source
            // refresh can replace the body while keeping edited title/parent.
            app.store.clear_dirty(&id)?;
            let mut retry = entries[0].clone();
            retry.updated_at = crate::transport::timestamp_after(Some(&edited_stamp))?;
            retry.content = "synthetic refreshed source body".into();
            let accepted =
                import_entries_with_app(&app, &mut [retry], "", |_, _| {}, |_, _| Ok(()), || {})?;
            assert_eq!(accepted.imported, 1);
            assert_eq!(accepted.completed, vec![true]);
            let stored = app.store.all(true)?;
            assert_eq!(
                MemoryEngine::open(&app.keys, &stored[0])?.content,
                "synthetic refreshed source body"
            );
        }
        Ok(())
    }

    #[test]
    fn sqlite_refresh_rechecks_dirty_edit_inside_write_transaction() -> Result<()> {
        let (_isolate, app, mut entries) = fixture(1)?;
        import_entries_with_app(&app, &mut entries, "", |_, _| {}, |_, _| Ok(()), || {})?;
        let id = entries[0].id.clone();
        app.store.clear_dirty(&id)?;
        let mut refresh = entries[0].clone();
        refresh.updated_at = "2099-01-01T00:00:00.000Z".into();
        let mut edit_result = Ok(String::new());
        let outcome = import_entries_with_app(
            &app,
            &mut [refresh],
            "",
            |_, _| {
                edit_result = edit_fixture_body(&app, &id);
            },
            |_, _| Ok(()),
            || {},
        )?;
        edit_result?;
        assert_eq!(outcome.imported, 0);
        assert_eq!(outcome.completed, vec![false]);
        let stored = app.store.all(true)?;
        assert_eq!(
            MemoryEngine::open(&app.keys, &stored[0])?.content,
            "synthetic unsynced user edit"
        );
        Ok(())
    }
}
