use anyhow::Result;
use crate::engine::select_diary_tracks;

/// Construct selection-only metadata without opening a vault.
fn track(id: &str, user: &str, title: &str, created: &str) -> respire_app::StoredMemory {
    let mut memory = respire_app::StoredMemory::new_pending(id.into(), user.into());
    memory.local_title = title.into();
    memory.local_created_at = created.into();
    memory
}

/// Stable identity wins over older same-title legacy rows.
#[test]
fn stable_id_precedes_legacy_titles_and_preserves_importance_compatibility() -> Result<()> {
    let mut legacy = track(
        "legacy",
        "alice",
        "\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} 2026-10-13",
        "2026-10-13T00:00:00Z",
    );
    legacy.local_importance = "normal".into();
    let canonical = track(
        "stable",
        "server-routing-owner",
        "User's renamed day",
        "2026-10-13T01:00:00Z",
    );
    let rows = vec![legacy, canonical];
    let tracks = select_diary_tracks(
        &rows,
        "stable",
        "\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} 2026-10-13",
        |row| Ok(row.id == "stable" || row.user == "alice"),
    )?;
    assert_eq!(
        tracks.iter().map(|row| row.id.as_str()).collect::<Vec<_>>(),
        ["stable", "legacy"]
    );
    Ok(())
}

/// An unrelated canonical payload must fail before legacy candidates can be merged.
#[test]
fn canonical_author_mismatch_is_not_a_legacy_fallback() -> Result<()> {
    let rows = vec![
        track("stable", "wire-owner", "renamed", "1"),
        track(
            "legacy",
            "alice",
            "\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} 2026-10-13",
            "0",
        ),
    ];
    let result = select_diary_tracks(
        &rows,
        "stable",
        "\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} 2026-10-13",
        |row| Ok(row.id != "stable"),
    );
    assert!(result.is_err());
    Ok(())
}

/// Blank titles remain valid while deleted and unrelated tracks stay separate.
#[test]
fn blank_title_deleted_rows_other_users_and_days_are_handled_separately() -> Result<()> {
    let mut deleted = track(
        "deleted",
        "alice",
        "\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} 2026-10-13",
        "0",
    );
    deleted.deleted = true;
    let rows = vec![
        track("stable", "alice", "", "1"),
        deleted,
        track(
            "other-user",
            "bob",
            "\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} 2026-10-13",
            "0",
        ),
        track(
            "other-day",
            "alice",
            "\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} 2026-10-12",
            "0",
        ),
    ];
    let tracks = select_diary_tracks(
        &rows,
        "stable",
        "\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} 2026-10-13",
        |row| Ok(row.user == "alice"),
    )?;
    assert_eq!(tracks.len(), 1);
    assert_eq!(tracks[0].id, "stable");
    assert!(select_diary_tracks(
        &rows,
        "charlie-stable",
        "\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} 2026-10-14",
        |row| Ok(row.user == "charlie")
    )?
    .is_empty());
    Ok(())
}

/// Live legacy tracks retain their deterministic earliest-created ordering.
#[test]
fn missing_or_deleted_stable_id_keeps_earliest_legacy_track() -> Result<()> {
    let mut deleted = track("stable", "alice", "renamed", "0");
    deleted.deleted = true;
    let rows = vec![
        track(
            "later",
            "alice",
            "\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} 2026-10-13",
            "2",
        ),
        track(
            "earlier",
            "alice",
            "\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} 2026-10-13",
            "1",
        ),
        deleted,
    ];
    let tracks = select_diary_tracks(
        &rows,
        "stable",
        "\u{6d3b}\u{52a8}\u{8f68}\u{8ff9} 2026-10-13",
        |row| Ok(row.user == "alice"),
    )?;
    assert_eq!(
        tracks.iter().map(|row| row.id.as_str()).collect::<Vec<_>>(),
        ["earlier", "later"]
    );
    Ok(())
}
