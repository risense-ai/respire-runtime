use anyhow::{Context, Result};
use respire_app::memory::model::{Artifact, MemoryMeta, SourceRef};
use respire_app::{Kind, MemoryEntry, SessionKeys};
use respire_app::transport::local::LocalStore;
use serde_json::{json, Value};

// A JSON array is one clap value; Option<Vec<T>> would mean repeated T values.
#[derive(Clone)]
pub struct SourceRefs(Vec<SourceRef>);

#[derive(clap::Args, Clone, Default)]
pub struct Flags {
    /// Candidate summary, at most 120 Unicode scalars; does not confirm a fact.
    #[arg(long, value_parser = summary)]
    pub summary: Option<String>,
    #[arg(long, conflicts_with = "summary")]
    pub clear_summary: bool,
    /// JSON array of {id: full UUID, revision: sha256:<hex>, required: bool}.
    #[arg(long, value_parser = sources)]
    pub source_refs: Option<SourceRefs>,
    #[arg(long, conflicts_with = "source_refs")]
    pub clear_source_refs: bool,
    /// UTC expiration, exactly YYYY-MM-DDTHH:MM:SS.SSSZ.
    #[arg(long, value_parser = timestamp)]
    pub valid_until: Option<String>,
    #[arg(long, conflicts_with = "valid_until")]
    pub clear_valid_until: bool,
    /// UTC review date; changing it does not change the semantic revision.
    #[arg(long, value_parser = timestamp)]
    pub review_at: Option<String>,
    #[arg(long, conflicts_with = "review_at")]
    pub clear_review_at: bool,
    /// Artifact JSON object with path, repo, commit and purpose; no local-file execution.
    #[arg(long, value_parser = artifact)]
    pub artifact: Option<Artifact>,
    #[arg(long, conflicts_with = "artifact")]
    pub clear_artifact: bool,
}

fn summary(value: &str) -> std::result::Result<String, String> {
    if value.chars().count() > 120 { return Err("summary exceeds 120 Unicode scalars".into()); }
    Ok(value.to_owned())
}

pub fn kind(value: &str) -> std::result::Result<String, String> {
    let value = value.trim().to_lowercase();
    Kind::try_from_str(&value).ok_or_else(|| "unsupported_metadata: unknown memory kind".to_owned())?;
    Ok(value)
}
fn timestamp(value: &str) -> std::result::Result<String, String> {
    respire_app::memory::model::metadata::validate_timestamp(value).map_err(|e| e.to_string())?;
    Ok(value.to_owned())
}
fn sources(value: &str) -> std::result::Result<SourceRefs, String> {
    let refs = serde_json::from_str(value).map_err(|e| format!("source-refs JSON: {e}"))?;
    let metadata = MemoryMeta { memory_contract: 1, source_refs: refs, ..Default::default() };
    metadata.validate().map_err(|e| e.to_string())?;
    Ok(SourceRefs(metadata.source_refs))
}
fn artifact(value: &str) -> std::result::Result<Artifact, String> {
    let artifact = serde_json::from_str(value).map_err(|e| format!("artifact JSON: {e}"))?;
    let metadata = MemoryMeta { memory_contract: 1, artifact: Some(artifact), ..Default::default() };
    metadata.validate().map_err(|e| e.to_string())?;
    metadata.artifact.ok_or_else(|| "artifact must be an object; use --clear-artifact to clear it".into())
}

impl Flags {
    pub fn patch(&self) -> Option<respire_app::service::MetadataPatch> {
        let patch = respire_app::service::MetadataPatch {
            summary: self.summary.clone().map(Some).or_else(|| self.clear_summary.then_some(None)),
            source_refs: self.source_refs.as_ref().map(|refs| refs.0.clone()).or_else(|| self.clear_source_refs.then(Vec::new)),
            valid_until: self.valid_until.clone().map(Some).or_else(|| self.clear_valid_until.then_some(None)),
            review_at: self.review_at.clone().map(Some).or_else(|| self.clear_review_at.then_some(None)),
            artifact: self.artifact.clone().map(Some).or_else(|| self.clear_artifact.then_some(None)),
        };
        (patch.summary.is_some() || patch.source_refs.is_some() || patch.valid_until.is_some()
            || patch.review_at.is_some() || patch.artifact.is_some()).then_some(patch)
    }
    pub fn apply(&self, entry: &mut MemoryEntry) {
        if let Some(patch) = self.patch() { patch.apply(&mut entry.metadata); }
        if matches!(entry.kind, Kind::Hypothesis | Kind::Reflection | Kind::SelfNote) {
            entry.metadata.memory_contract = 1;
        }
    }
}

/// Compute the receipt before committing, so a Core rejection cannot follow a save.
pub fn prepare(keys: &SessionKeys, store: &LocalStore, entry: &MemoryEntry) -> Result<Value> {
    respire_app::metadata_gate::ensure_write(store, entry)?;
    respire_app::metadata_gate::ensure_sources(keys, store, entry)?;
    if entry.metadata.memory_contract == 0 { return Ok(json!({})); }
    let validation: Value = respire_app::core_sdk::execute("memory_metadata_validate", json!({"entry": entry}))?;
    let revision = validation["record_revision"].as_str().context("Core omitted record_revision")?;
    respire_app::memory::model::metadata::validate_revision(revision)?;
    Ok(receipt(entry, revision))
}

pub fn receipt(entry: &MemoryEntry, revision: &str) -> Value {
    json!({"saved":true,"memory_contract":entry.metadata.memory_contract,
        "record_revision":revision,"metadata":entry.metadata,
        "evidence_state":if entry.metadata.verification.is_none(){"unverified"}else{"unavailable"},
        "evidence_evaluated":false})
}

pub fn add_receipt(result: &mut crate::output::ResultEnvelope, receipt: Value) {
    if let Value::Object(fields) = receipt {
        for (key, value) in fields { result.summary[key] = value; }
    }
}

#[derive(clap::Subcommand)]
pub enum Command {
    /// Inspect the gate; no enablement or deployment claim is made.
    Status,
    /// Enable only after a validated local backup and explicit deployment review.
    Enable {
        #[arg(long, value_parser = ["isolated", "controlled_writers"], default_value = "isolated")]
        mode: String,
        /// Operator JSON file explaining upgraded writers, disconnected old clients and reconciled offline writes.
        #[arg(long)]
        deployment_review: Option<std::path::PathBuf>,
    },
    /// Stop new-format writes; retained metadata and sync isolation remain in force.
    Disable,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentReview {
    pub operator: String,
    pub upgraded_writers: String,
    pub disconnected_old_clients: String,
    pub reconciled_offline_writes: String,
}

pub fn deployment(mode: &str, file: Option<&std::path::Path>) -> Result<(respire_app::metadata_gate::Deployment, Option<DeploymentReview>)> {
    if mode == "isolated" {
        anyhow::ensure!(file.is_none(), "isolated mode does not accept --deployment-review");
        return Ok((respire_app::metadata_gate::Deployment::Isolated, None));
    }
    let file = file.context("controlled_writers requires --deployment-review with an operator's written review; a flag cannot exclude old clients")?;
    let review: DeploymentReview = serde_json::from_slice(&std::fs::read(file)?)?;
    anyhow::ensure!([&review.operator, &review.upgraded_writers, &review.disconnected_old_clients,
        &review.reconciled_offline_writes].iter().all(|value| !value.trim().is_empty()),
        "deployment review requires an operator and an explanation for each of the three conditions");
    Ok((respire_app::metadata_gate::Deployment::ControlledWriters {
        all_writers_upgraded: true, old_clients_disconnected: true, offline_writes_reconciled: true,
    }, Some(review)))
}
