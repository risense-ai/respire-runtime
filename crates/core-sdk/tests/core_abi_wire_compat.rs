use anyhow::{Context, Result};
use respire_core_sdk::{query, search::Embedder, Core, ResidentLease, Snapshot};
use respire_protocol::{MemoryEntry, MemoryQuery, StoredMemory};
use serde_json::{json, Value};

// Frozen copy of contracts/core-abi/fixtures/wire-v1-compat.json at
// respire-core d725aa1b86fd913cf15fb2a6865f72c572d0b196. No fetch or shared
// crate is required to test the pinned SDK's schema-v1 bytes.
const WIRE_FIXTURE: &str = include_str!("fixtures/core-abi-wire-v1.json");
const MODEL: &str = "abi-wire-fixture";

struct LexicalFixture;
impl Embedder for LexicalFixture {
    fn model_name(&self) -> &str {
        MODEL
    }

    fn dims(&self) -> usize {
        1024
    }
}

fn assert_entry(entry: &MemoryEntry) {
    assert_eq!(entry.id, "fixture-entry");
    assert_eq!(entry.title, "old entry");
    assert_eq!(entry.content, "fixture text");
    assert_eq!(entry.importance, "normal");
    assert!(entry.device.is_empty());
    assert!(entry.modified_by.is_empty());
    assert_eq!(entry.see_also, ["older-a", "older-b"]);
    assert_eq!(
        entry.unknown_fields.get("future_field"),
        Some(&json!({"revision": 2}))
    );
}

#[test]
fn historical_query_fixture_round_trips_through_pinned_core_abi() -> Result<()> {
    let mut fixture: Value = serde_json::from_str(WIRE_FIXTURE)?;
    fixture["query"]["text"] = json!("fixture text");
    let mut core = Core::new()?;

    // Raw legacy request: omit fields as written in the frozen fixture, not
    // the defaults a current typed writer would materialize before Core.
    let mut raw_row = fixture["snapshot"].clone();
    raw_row["entry"] = fixture["entry"].clone();
    let mut raw_request = json!({
        "model": MODEL, "lexical_only": true, "mode": "plain",
        "snapshots": [raw_row], "query": fixture["query"]
    });
    let raw_result = core.call("query", raw_request.clone())?;
    let raw_entries: Vec<MemoryEntry> = serde_json::from_value(raw_result.clone())?;
    assert_eq!(raw_entries.len(), 1);
    assert_entry(&raw_entries[0]);

    let query_fields = raw_request["query"]
        .as_object_mut()
        .context("fixture query is not an object")?;
    assert_eq!(query_fields.remove("future_hint"), Some(json!(true)));
    assert_eq!(core.call("query", raw_request.clone())?, raw_result);

    // A snapshot is an explicit ABI DTO, unlike the tolerant entry/query
    // inside it. Change only the outer row and leave known-good input intact.
    let mut invalid = raw_request.clone();
    invalid["snapshots"][0]["future_snapshot"] = json!(true);
    let error = core
        .call("query", invalid)
        .err()
        .context("unknown snapshot field accepted")?;
    assert!(
        error
            .to_string()
            .contains("unknown field `future_snapshot`"),
        "{error}"
    );
    assert_eq!(core.call("query", raw_request)?, raw_result);

    let entry: MemoryEntry = serde_json::from_value(fixture["entry"].clone())?;
    let typed_query: MemoryQuery = serde_json::from_value(fixture["query"].clone())?;
    assert!(serde_json::to_value(&typed_query)?
        .get("future_hint")
        .is_none());
    let mut stored = StoredMemory::new_pending(entry.id.clone(), entry.user.clone());
    stored.local_kind = entry.kind.as_str().to_owned();
    stored.local_title = entry.title.clone();
    stored.local_content_head = entry.content.clone();
    stored.local_importance = entry.importance.clone();

    // No derived artifact: resident publication selects the lexical path.
    // Use the same host wrappers that build and query authorized views.
    let snapshot = Snapshot::new(&stored, Some(entry));
    let lease =
        ResidentLease::publish("core-abi-wire-v1".to_owned(), None, MODEL, &[snapshot], &[])?;
    let _scope = lease.enter();
    let typed_result: Vec<MemoryEntry> = query(&LexicalFixture, &[], &typed_query, "plain")?;
    assert_eq!(typed_result.len(), 1);
    assert_entry(&typed_result[0]);
    assert_eq!(serde_json::to_value(typed_result)?, raw_result);
    Ok(())
}
