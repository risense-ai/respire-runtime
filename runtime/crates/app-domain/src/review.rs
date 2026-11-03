//! Review candidates and CAS commits. Authority/root inputs never come from CLI JSON.
#[path = "review_recall.rs"]
mod recall;
pub use recall::AuthorizedRecallSource;
use anyhow::{ensure, Context, Result};
use respire_protocol::{Evidence, MemoryEntry, Scope, Verification};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::review_approval::{OpaqueApproval, ReviewAuthority, ReviewBinding};
use crate::transport::{
    local::{LocalStore, ReviewHistoryRow},
    MemoryTransport,
};
use crate::{MemoryEngine, SessionKeys, StoredMemory};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewInput {
    #[serde(default)]
    pub expected_memory_revision: Option<String>,
    #[serde(default)]
    pub expected_record_revision: Option<String>,
    pub claim: String,
    pub scope: Scope,
    pub evidence: Vec<Evidence>,
    pub method: String,
    // Value distinguishes an explicitly requested null from an omitted field.
    pub next_review_at: Value,
}

impl ReviewInput {
    pub fn validate_shape(&self) -> Result<()> {
        ensure!(
            !self.claim.trim().is_empty() && !self.method.trim().is_empty(),
            "invalid_metadata: claim and method are required"
        );
        self.scope.validate()?;
        for evidence in &self.evidence {
            evidence.validate()?;
        }
        if let Some(revision) = &self.expected_record_revision {
            respire_protocol::metadata::validate_revision(revision)?;
        }
        if let Some(revision) = &self.expected_memory_revision {
            ensure!(
                revision.len() == 32
                    && revision
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
                "invalid_metadata: invalid memory revision"
            );
        }
        if !self.next_review_at.is_null() {
            respire_protocol::metadata::validate_timestamp(
                self.next_review_at
                    .as_str()
                    .context("invalid_metadata: next_review_at must be timestamp or null")?,
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Evaluation {
    pub id: String,
    pub record_revision: Option<String>,
    pub evidence_state: String,
    pub fact_eligible: bool,
    pub due_reasons: Vec<String>,
    pub reason_codes: Vec<String>,
}

#[derive(Deserialize)]
struct Validation {
    record_revision: String,
    claim_digest: Option<String>,
    intent_digest: Option<String>,
}

#[derive(Debug)]
pub struct ReviewCommittedError(anyhow::Error);
impl std::fmt::Display for ReviewCommittedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "review write committed, but post-commit verification failed: {}",
            self.0
        )
    }
}
impl std::error::Error for ReviewCommittedError {}

pub fn require_support() -> Result<()> {
    let caps: Value = crate::core_sdk::execute("capabilities", Value::Null)?;
    ensure!(
        caps["memory_metadata_contract"].as_u64() == Some(1),
        "Core SDK does not support memory_metadata_contract 1; install the paired metadata SDK/CLI"
    );
    ensure!(
        caps["superseded_status_contract"].as_u64() == Some(1),
        "Core SDK does not support superseded_status_contract 1"
    );
    Ok(())
}

pub fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub struct ReviewService<'a> {
    keys: &'a SessionKeys,
    store: &'a LocalStore,
    owner: &'a str,
}

struct View {
    revision: String,
    rows: Vec<StoredMemory>,
    entries: HashMap<String, MemoryEntry>,
    snapshots: Vec<crate::core_sdk::Snapshot>,
    unavailable: Vec<String>,
}

impl<'a> ReviewService<'a> {
    pub fn new(keys: &'a SessionKeys, store: &'a LocalStore, owner: &'a str) -> Result<Self> {
        ensure!(
            !owner.trim().is_empty(),
            "verification_authority_unavailable: no current library owner"
        );
        Ok(Self { keys, store, owner })
    }

    fn view(&self) -> Result<View> {
        let snapshot = self.store.review_snapshot()?;
        let rows: Vec<_> = snapshot
            .memories
            .into_iter()
            .filter(|row| row.user == self.owner)
            .collect();
        let mut entries = HashMap::new();
        let mut snapshots = Vec::with_capacity(rows.len());
        for row in &rows {
            let entry = MemoryEngine::open(self.keys, row)
                .with_context(|| format!("decode review snapshot {}", row.id))?;
            ensure!(
                row.local_meta == entry.metadata,
                "invalid_metadata: review projection differs from encrypted payload"
            );
            entries.insert(row.id.clone(), entry.clone());
            let mut snapshot = crate::core_sdk::Snapshot::new(row, Some(entry));
            // This operation is pure metadata; no semantic artifact/model is needed.
            snapshot.features = None;
            snapshots.push(snapshot);
        }
        let query = respire_protocol::MemoryQuery::default();
        let relation: Value = crate::core_sdk::execute(
            "related_business",
            json!({
                "model":self.store.retrieval_model()?,"snapshots":snapshots,"query":query,
                "ids":[],"pairs":[],"related_settings":{"enabled":false},"all_superseded":true,
            }),
        )?;
        let superseded = relation["superseded"]
            .as_object()
            .context("missing authoritative supersession map")?;
        for snapshot in &mut snapshots {
            if let Some(entry) = snapshot.entry.as_mut() {
                entry.superseded_by = superseded
                    .get(&entry.id)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
            }
        }
        Ok(View {
            revision: snapshot.memory_revision,
            rows,
            entries,
            snapshots,
            unavailable: snapshot.unavailable_ids,
        })
    }

    fn target<'v>(&self, view: &'v View, id: &str) -> Result<(&'v StoredMemory, &'v MemoryEntry)> {
        respire_protocol::metadata::validate_full_id(id)?;
        let row = view
            .rows
            .iter()
            .find(|row| row.id == id && !row.deleted)
            .context("evidence_unavailable: no authorized live review target")?;
        let entry = view
            .entries
            .get(id)
            .context("evidence_unavailable: target body unavailable")?;
        ensure!(
            !view.unavailable.iter().any(|value| value == id),
            "evidence_unavailable: unmaterialized target head"
        );
        Ok((row, entry))
    }

    fn validate(
        &self,
        entry: &MemoryEntry,
        review: Option<Value>,
        intent: Option<Value>,
    ) -> Result<Validation> {
        let mut payload = json!({"entry":entry});
        if let Some(review) = review {
            payload["review"] = review;
        }
        if let Some(intent) = intent {
            payload["intent"] = intent;
        }
        crate::core_sdk::execute("memory_metadata_validate", payload)
    }

    fn claim(input: &ReviewInput) -> Value {
        json!({"claim":input.claim,"scope":input.scope,"evidence":input.evidence,"method":input.method})
    }

    fn next_date(input: &ReviewInput, now: &str) -> Result<Option<String>> {
        if input.next_review_at.is_null() {
            return Ok(None);
        }
        let date = input.next_review_at.as_str().context(
            "invalid_metadata: next_review_at must be an explicit UTC timestamp or null",
        )?;
        respire_protocol::metadata::validate_timestamp(date)?;
        ensure!(
            date > now,
            "invalid_metadata: review_at must be in the future"
        );
        Ok(Some(date.to_owned()))
    }

    fn binding(
        &self,
        view: &View,
        entry: &MemoryEntry,
        input: &ReviewInput,
        now: &str,
    ) -> Result<ReviewBinding> {
        let next = Self::next_date(input, now)?;
        let library = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(self.store.library_identity()?.as_bytes()))
        );
        let intent = json!({"owner":self.owner,"local_library_id":library,
            "expected_memory_revision":view.revision,"next_review_at":next});
        let validation = self.validate(entry, Some(Self::claim(input)), Some(intent))?;
        if let Some(expected) = &input.expected_memory_revision {
            ensure!(
                expected == &view.revision,
                "review_conflict: library revision changed"
            );
        }
        if let Some(expected) = &input.expected_record_revision {
            ensure!(
                expected == &validation.record_revision,
                "review_conflict: target revision changed"
            );
        }
        let binding = ReviewBinding {
            owner: self.owner.to_owned(),
            local_library_id: library,
            id: entry.id.clone(),
            record_revision: validation.record_revision,
            expected_memory_revision: view.revision.clone(),
            claim_digest: validation
                .claim_digest
                .context("missing Core claim digest")?,
            intent_digest: validation
                .intent_digest
                .context("missing Core intent digest")?,
        };
        binding.validate()?;
        Ok(binding)
    }

    fn checks(
        &self,
        view: &View,
        replacement: Option<(&str, Value)>,
    ) -> Result<(Vec<Value>, Vec<Value>)> {
        let authority = ReviewAuthority::configured();
        let mut checks = Vec::new();
        let mut errors = Vec::new();
        for entry in view.entries.values() {
            if let Some((id, proof)) = &replacement {
                if entry.id == *id {
                    checks.push(proof.clone());
                    continue;
                }
            }
            let Some(verification) = &entry.metadata.verification else {
                continue;
            };
            let revision = self.validate(entry, None, None)?.record_revision;
            if verification.record_revision != revision {
                continue;
            }
            let review = json!({"claim":verification.claim,"scope":verification.scope,"evidence":verification.evidence,"method":verification.method});
            let validated = self.validate(entry, Some(review), None)?;
            let claim_digest = validated
                .claim_digest
                .context("missing Core historical claim digest")?;
            let resolved = match &authority {
                Ok(authority) => authority.resolve_confirmation(
                    self.owner,
                    &entry.id,
                    &revision,
                    &verification.confirmed_by.event_id,
                    &claim_digest,
                ),
                Err(_) => {
                    errors.push(json!({"id":entry.id,"code":"verification_authority_unavailable"}));
                    continue;
                }
            };
            match resolved {
                Ok(resolved) => {
                    checks.push(serde_json::to_value(resolved.user_claim_authority_check())?)
                }
                Err(error) => {
                    let code = error
                        .downcast_ref::<crate::review_approval::ApprovalError>()
                        .map(|error| error.code)
                        .unwrap_or("verification_authority_unavailable");
                    errors.push(json!({"id":entry.id,"code":code}));
                    // No verified event means no host proof. In particular never
                    // copy the candidate's claimed actor/time into AuthorityCheck.
                }
            }
        }
        Ok((checks, errors))
    }

    fn evaluate(
        &self,
        view: &View,
        now: &str,
        scope: &Scope,
        checks: Vec<Value>,
    ) -> Result<Vec<Evaluation>> {
        let request_scope = json!({"project":scope.project.as_ref().filter(|value| value.as_str()!="*"),
            "device":scope.device.as_ref().filter(|value| value.as_str()!="*"),
            "version":scope.version.as_ref().filter(|value| value.as_str()!="*"),"at":now});
        crate::core_sdk::execute(
            "memory_evidence_evaluate",
            json!({"model":self.store.retrieval_model()?,
            "snapshots":view.snapshots,"evidence_context":{"now":now,"request_scope":request_scope,
            "authority_checks":checks,"unavailable_ids":view.unavailable}}),
        )
    }

    pub fn due(&self, scope: &Scope, now: &str) -> Result<Value> {
        let view = self.view()?;
        let (checks, errors) = self.checks(&view, None)?;
        let evaluations = self.evaluate(&view, now, scope, checks)?;
        let due: Vec<_> = evaluations.into_iter().filter(|item| !item.due_reasons.is_empty())
            .map(|item| json!({"id":item.id,"revision":item.record_revision,"due_reasons":item.due_reasons,"reason_codes":item.reason_codes})).collect();
        Ok(json!({"due":due,"now":now,"memory_revision":view.revision,"authority_errors":errors}))
    }

    pub fn prepare(&self, id: &str, input: &ReviewInput, now: &str) -> Result<Value> {
        input.validate_shape()?;
        let view = self.view()?;
        let (_, entry) = self.target(&view, id)?;
        let binding = self.binding(&view, entry, input, now)?;
        let mut confirm_input = serde_json::to_value(input)?;
        confirm_input["expected_memory_revision"] = json!(binding.expected_memory_revision);
        confirm_input["expected_record_revision"] = json!(binding.record_revision);
        let (checks, errors) = self.checks(&view, None)?;
        let evaluations = self.evaluate(&view, now, &input.scope, checks)?;
        let authority = ReviewAuthority::configured()
            .map(|authority| authority.handoff())
            .unwrap_or_else(
                |_| json!({"available":false,"code":"verification_authority_unavailable"}),
            );
        Ok(
            json!({"binding":binding,"authority":authority,"purpose":"review-confirm","entry":entry,"claim":input.claim,"scope":input.scope,"evidence":input.evidence,
            "method":input.method,"next_review_at":input.next_review_at,"confirm_input":confirm_input,"source_checks":evaluations,
            "authority_errors":errors,"root_rules":{"user":{"locator":format!("respire:user-claim:{id}"),"revision":binding.record_revision,
            "requires":"fresh Passkey factual confirmation of this exact claim and scope"},"primary":"provider_unavailable","run":"provider_unavailable"},"saved":false,"now":now}),
        )
    }

    pub fn draft_input(&self, id: &str) -> Result<ReviewInput> {
        let view = self.view()?;
        let (_, entry) = self.target(&view, id)?;
        let revision = self.validate(entry, None, None)?.record_revision;
        let mut evidence: Vec<_> = entry
            .metadata
            .source_refs
            .iter()
            .filter(|source| source.required)
            .map(|source| Evidence::Memory {
                id: source.id.clone(),
                revision: source.revision.clone(),
                unknown_fields: Default::default(),
            })
            .collect();
        evidence.push(Evidence::User {
            locator: format!("respire:user-claim:{id}"),
            revision: revision.clone(),
            unknown_fields: Default::default(),
        });
        Ok(ReviewInput {
            expected_memory_revision: Some(view.revision.clone()),
            expected_record_revision: Some(revision.clone()),
            claim: entry.content.clone(),
            scope: Scope {
                project: Some(if entry.project.is_empty() {
                    "*".to_owned()
                } else {
                    entry.project.clone()
                }),
                device: Some("*".to_owned()),
                version: Some("*".to_owned()),
                from: None,
                until: None,
                unknown_fields: Default::default(),
            },
            evidence,
            method: "passkey_explicit_fact_confirmation".to_owned(),
            next_review_at: Value::Null,
        })
    }

    fn writable(&self) -> Result<()> {
        crate::service::ensure_writable()?;
        ensure!(
            !crate::service::off_mode(),
            "feature_disabled: memory service is off"
        );
        ensure!(
            self.store.memory_metadata_v1_enabled()?,
            "feature_disabled: memory metadata v1 is off"
        );
        crate::metadata_gate::mode(self.store)?;
        Ok(())
    }

    pub fn confirm(
        &self,
        id: &str,
        input: &ReviewInput,
        approval: &OpaqueApproval,
        now: &str,
    ) -> Result<Value> {
        input.validate_shape()?;
        self.writable()?;
        ensure!(
            input.expected_memory_revision.is_some() && input.expected_record_revision.is_some(),
            "invalid_metadata: confirmation requires both expected revisions from prepare"
        );
        let mut view = self.view()?;
        let (row, entry) = self.target(&view, id)?;
        let row = row.clone();
        let mut updated = entry.clone();
        let binding = self.binding(&view, &updated, input, now)?;
        ensure!(updated.metadata.memory_contract == 1, "invalid_metadata: upgrade the record through the ordinary metadata path before confirmation");
        let authority = ReviewAuthority::configured()?;
        let trusted = authority.verify_review_approval(&binding, approval)?;
        updated.metadata.verification = Some(Verification {
            record_revision: binding.record_revision.clone(),
            claim: input.claim.clone(),
            scope: input.scope.clone(),
            evidence: input.evidence.clone(),
            method: input.method.clone(),
            confirmed_by: trusted.confirmed_by(),
            confirmed_at: trusted.confirmed_at().to_owned(),
            unknown_fields: Default::default(),
        });
        updated.metadata.review_at = Self::next_date(input, now)?;
        self.validate(&updated, Some(Self::claim(input)), None)?;
        for snapshot in &mut view.snapshots {
            if snapshot.id == id {
                if let Some(entry) = snapshot.entry.as_mut() {
                    entry.metadata = updated.metadata.clone();
                }
            }
        }
        let proof = serde_json::to_value(trusted.user_claim_authority_check())?;
        let (checks, _) = self.checks(&view, Some((id, proof)))?;
        let evaluation = self.evaluate(&view, now, &input.scope, checks)?;
        let target = evaluation
            .iter()
            .find(|item| item.id == id)
            .context("evidence_unavailable: missing target evaluation")?;
        ensure!(
            target.fact_eligible,
            "evidence_unavailable: {}",
            target.reason_codes.join(",")
        );
        trusted.commit_once(|_| {
            authority.ensure_current()?;
            self.commit(
                &view,
                &row,
                &updated,
                "confirm",
                None,
                now,
                &binding.record_revision,
            )
        })
    }

    fn commit(
        &self,
        view: &View,
        previous: &StoredMemory,
        entry: &MemoryEntry,
        action: &str,
        reason: Option<String>,
        now: &str,
        revision: &str,
    ) -> Result<Value> {
        self.writable()?;
        crate::metadata_gate::ensure_write(self.store, entry)?;
        let mut updated = entry.clone();
        updated.updated_at = self.store.edit_stamp(&entry.id)?;
        updated.modified_by = self.owner.to_owned();
        let _deferred = crate::core_sdk::defer_indexing();
        let embedder = crate::memory::bge::BgeEmbedder::load_model(&self.store.retrieval_model()?)?;
        let sealed = MemoryEngine::seal(self.keys, &embedder, &updated, self.owner)?;
        let encode =
            |value: &Option<Verification>| value.as_ref().map(serde_json::to_string).transpose();
        let actor = if action == "confirm" {
            serde_json::to_value(
                &entry
                    .metadata
                    .verification
                    .as_ref()
                    .context("missing new verification")?
                    .confirmed_by,
            )?
        } else {
            json!({"kind":"owner_client","id":self.owner})
        };
        let history = ReviewHistoryRow {
            seq: None,
            entry_id: entry.id.clone(),
            record_revision: revision.to_owned(),
            action: action.to_owned(),
            actor: actor.to_string(),
            happened_at: now.to_owned(),
            previous_verification: encode(&previous.local_meta.verification)?,
            next_verification: encode(&entry.metadata.verification)?,
            previous_review_at: previous.local_meta.review_at.clone(),
            next_review_at: entry.metadata.review_at.clone(),
            reason,
        };
        self.store
            .commit_review(&view.revision, &sealed, &history)?;
        let verify = || -> Result<Value> {
            crate::resident::clear()?;
            crate::service::notify_index();
            let readback = self
                .store
                .all(true)?
                .into_iter()
                .find(|row| row.id == entry.id)
                .context("review read-back missing target")?;
            let reopened = MemoryEngine::open(self.keys, &readback)?;
            ensure!(
                reopened.metadata == updated.metadata,
                "review read-back metadata mismatch"
            );
            let rows = self.store.review_history(&entry.id, 1)?;
            let saved_history = rows.first().context("review read-back missing history")?;
            ensure!(
                saved_history.action == action
                    && saved_history.next_verification == history.next_verification
                    && saved_history.next_review_at == history.next_review_at
                    && saved_history.record_revision == revision,
                "review read-back history mismatch"
            );
            crate::service::notify_autosync();
            Ok(
                json!({"saved":true,"id":entry.id,"record_revision":revision,"memory_revision":self.store.memory_revision()?,
            "verification":reopened.metadata.verification,"review_at":reopened.metadata.review_at,"history_seq":saved_history.seq}),
            )
        };
        verify().map_err(|error| ReviewCommittedError(error).into())
    }

    pub fn change(
        &self,
        id: &str,
        expected: &str,
        review_at: Option<Option<String>>,
        reason: Option<&str>,
        now: &str,
    ) -> Result<Value> {
        self.writable()?;
        let view = self.view()?;
        ensure!(
            view.revision == expected,
            "review_conflict: library revision changed"
        );
        let (row, entry) = self.target(&view, id)?;
        let mut updated = entry.clone();
        let validation = self.validate(entry, None, None)?;
        let action;
        if let Some(date) = review_at {
            if let Some(value) = &date {
                respire_protocol::metadata::validate_timestamp(value)?;
                ensure!(
                    value.as_str() > now,
                    "invalid_metadata: review_at must be in the future"
                );
            }
            action = if date.is_some() {
                "reschedule"
            } else {
                "clear_review_at"
            };
            updated.metadata.review_at = date;
        } else {
            let reason = reason
                .filter(|value| !value.trim().is_empty())
                .context("invalid_metadata: revoke requires reason")?;
            if let Some(verification) = &entry.metadata.verification {
                ReviewAuthority::configured()?.revoke(
                    &OpaqueApproval {
                        event_id: verification.confirmed_by.event_id.clone(),
                    },
                    reason,
                )?;
            }
            action = "revoke";
            updated.metadata.verification = None;
        }
        ensure!(
            updated.metadata.memory_contract == 1,
            "invalid_metadata: review writes require a contract 1 record"
        );
        self.commit(
            &view,
            row,
            &updated,
            action,
            reason.map(str::to_owned),
            now,
            &validation.record_revision,
        )
    }

    pub fn history(&self, id: &str, limit: usize) -> Result<Value> {
        let view = self.view()?;
        respire_protocol::metadata::validate_full_id(id)?;
        ensure!(
            view.rows.iter().any(|row| row.id == id),
            "evidence_unavailable: no authorized target"
        );
        Ok(json!({"id":id,"local_only":true,"history":self.store.review_history(id,limit)?}))
    }
}
