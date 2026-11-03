//! Read-only reuse of review's trusted proof resolver for recall.
use super::*;

/// Created from the local authorized read transaction, never public JSON.
pub struct AuthorizedRecallSource {
    view: View,
    has_metadata: bool,
}

impl AuthorizedRecallSource {
    pub fn has_metadata(&self) -> bool {
        self.has_metadata
    }
    pub fn memories(&self) -> &[StoredMemory] {
        &self.view.rows
    }
    pub fn snapshots(&self) -> &[crate::core_sdk::Snapshot] {
        &self.view.snapshots
    }
    pub fn entries(&self) -> impl Iterator<Item = &MemoryEntry> {
        self.view.entries.values()
    }
    pub fn memory_revision(&self) -> &str {
        &self.view.revision
    }
}

impl ReviewService<'_> {
    /// Inspect plaintext even when a stale projection claims the legacy format.
    /// No Core/model/network operation runs before detecting required semantics.
    pub fn recall_source(&self) -> Result<AuthorizedRecallSource> {
        let snapshot = self.store.review_snapshot()?;
        let mut rows = Vec::new();
        let mut entries = HashMap::new();
        let mut snapshots = Vec::new();
        let mut has_metadata = false;
        for row in snapshot.memories {
            if row.deleted {
                if row.user == self.owner {
                    snapshots.push(crate::core_sdk::Snapshot::new(&row, None));
                    rows.push(row);
                }
                continue;
            }
            let entry = MemoryEngine::open(self.keys, &row)
                .with_context(|| format!("decode recall source {}", row.id))?;
            ensure!(
                row.local_meta == entry.metadata,
                "invalid_metadata: recall projection differs from encrypted payload"
            );
            has_metadata |= entry.metadata != respire_protocol::MemoryMeta::default()
                || matches!(
                    entry.kind,
                    respire_protocol::Kind::Hypothesis
                        | respire_protocol::Kind::Reflection
                        | respire_protocol::Kind::SelfNote
                );
            if row.user != self.owner {
                continue;
            }
            entries.insert(entry.id.clone(), entry.clone());
            snapshots.push(crate::core_sdk::Snapshot::new(&row, Some(entry)));
            rows.push(row);
        }
        Ok(AuthorizedRecallSource {
            view: View {
                revision: snapshot.memory_revision,
                rows,
                entries,
                snapshots,
                unavailable: snapshot.unavailable_ids,
            },
            has_metadata,
        })
    }

    /// The caller supplies the exact query_settings.now and actual request scope.
    /// Only this resolver can create proofs; caller JSON never supplies checks.
    pub fn recall_evidence(
        &self,
        source: &AuthorizedRecallSource,
        scope: &Scope,
        now: &str,
    ) -> Result<(Value, Vec<Evaluation>, Vec<Value>)> {
        respire_protocol::metadata::validate_timestamp(now)?;
        let (checks, errors) = self.checks(&source.view, None)?;
        let context = json!({"now":now,"request_scope":{"project":scope.project,"device":scope.device,"version":scope.version,"at":now},
            "authority_checks":checks,"unavailable_ids":source.view.unavailable});
        let snapshots: Vec<_> = source.snapshots().iter().cloned().map(|mut snapshot| {
            snapshot.features = None;
            snapshot
        }).collect();
        let evaluations = crate::core_sdk::execute(
            "memory_evidence_evaluate",
            json!({
                "model":self.store.retrieval_model()?,"snapshots":snapshots,"evidence_context":context,
            }),
        )?;
        Ok((context, evaluations, errors))
    }
}
