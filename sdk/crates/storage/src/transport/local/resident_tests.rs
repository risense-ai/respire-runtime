use super::*;
use crate::transport::MemoryTransport;

#[test]
fn compound_edit_keeps_its_snapshot_while_another_writer_waits() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("compound.db");
    let store = LocalStore::open(&path)?;
    let original = super::super::tests::sample("one");
    store.put(&original)?;
    let (started, ready) = std::sync::mpsc::channel();
    let (completed, done) = std::sync::mpsc::channel();
    let mut writer = None;
    store.write_transaction(|| {
        let mut latest = store.all(false)?[0].clone();
        let other_path = path.clone();
        writer = Some(std::thread::spawn(move || -> anyhow::Result<()> {
            let other = LocalStore::open_existing(&other_path)?;
            started.send(())?;
            other.meta_set("background-checkpoint", "ready")?;
            completed.send(())?;
            Ok(())
        }));
        ready.recv_timeout(std::time::Duration::from_secs(2))?;
        assert!(matches!(done.recv_timeout(std::time::Duration::from_millis(50)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)));
        latest.ciphertext = "compound-source".to_owned();
        latest.updated_at = store.edit_stamp(&latest.id)?;
        anyhow::ensure!(store.put(&latest)?, "compound source was not saved");
        Ok(())
    })?;
    writer.ok_or_else(|| anyhow::anyhow!("writer was not started"))?.join()
        .map_err(|_| anyhow::anyhow!("background writer panicked"))??;
    done.recv_timeout(std::time::Duration::from_secs(2))?;
    assert_eq!(store.all(false)?[0].ciphertext, "compound-source");
    assert_eq!(store.meta_get("background-checkpoint")?.as_deref(), Some("ready"));
    Ok(())
}

#[test]
fn stale_preparation_cannot_replace_a_concurrent_write() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("source-check.db");
    let first = LocalStore::open(&path)?;
    let second = LocalStore::open_existing(&path)?;
    let original = super::super::tests::sample("one");
    assert!(first.put_checked(&original, None)?);
    let mut latest = original.clone();
    latest.ciphertext = "new-source".to_owned();
    latest.updated_at = second.edit_stamp(&original.id)?;
    assert!(second.put_checked(&latest, Some(&original.ciphertext))?);
    let mut stale = original.clone();
    stale.updated_at = first.edit_stamp(&original.id)?;
    let error = first.put_checked(&stale, Some(&original.ciphertext)).err()
        .ok_or_else(|| anyhow::anyhow!("stale write unexpectedly succeeded"))?;
    assert!(error.downcast_ref::<MemorySourceChanged>().is_some());
    assert_eq!(first.all(false)?[0].ciphertext, latest.ciphertext);
    assert!(first.put_checked(&super::super::tests::sample("two"), None)?);
    Ok(())
}

#[test]
fn revision_delta_contains_changed_sources_and_tombstones() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = LocalStore::open(&dir.path().join("revision.db"))?;
    let initial = store.retrieval_revision()?;
    store.put_checked(&super::super::tests::sample("one"), None)?;
    store.put_checked(&super::super::tests::sample("two"), None)?;
    let (revision, changed, removed) = store.retrieval_delta(Some(initial))?;
    assert_eq!(changed.len(), 2);
    assert!(removed.is_empty());
    assert!(revision > initial);
    store.forget("one")?;
    let (next, changed, removed) = store.retrieval_delta(Some(revision))?;
    assert!(next > revision);
    assert!(changed.is_empty());
    assert_eq!(removed, vec!["one"]);
    let (_, changed, removed) = store.retrieval_delta(Some(next))?;
    assert!(changed.is_empty() && removed.is_empty());
    Ok(())
}

#[test]
fn diary_conflict_rolls_back_without_deleting_duplicates() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = LocalStore::open(&dir.path().join("diary.db"))?;
    let original = super::super::tests::sample("main");
    let duplicate = super::super::tests::sample("duplicate");
    store.put_checked(&original, None)?;
    store.put_checked(&duplicate, None)?;
    let mut newer = original.clone();
    newer.ciphertext = "concurrent-diary".to_owned();
    newer.updated_at = store.edit_stamp(&original.id)?;
    store.put_checked(&newer, Some(&original.ciphertext))?;
    let error = store.put_diary_checked(&original, &original.ciphertext, &[&duplicate]).err()
        .ok_or_else(|| anyhow::anyhow!("conflicting diary unexpectedly succeeded"))?;
    assert!(error.downcast_ref::<MemorySourceChanged>().is_some());
    let rows = store.all(false)?;
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().any(|row| row.id == "main" && row.ciphertext == newer.ciphertext));
    assert!(rows.iter().any(|row| row.id == "duplicate" && !row.deleted));
    Ok(())
}
