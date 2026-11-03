//! Review command inputs (the clap surface), shared with the runtime engine.
//! Dispatch, service calls and result emission stay in the CLI's review
//! shell, which re-imports these types.

use anyhow::{ensure, Context, Result};
use clap::{ArgGroup, Args};

#[derive(Args)]
#[command(group(ArgGroup::new("action").required(true).multiple(false)
    .args(["due","draft","confirm","revoke","history","review_at","clear"])))]
pub struct ReviewArgs {
    pub id: Option<String>,
    #[arg(long)]
    pub due: bool,
    #[arg(long, visible_aliases=["prepare","check"])]
    pub draft: bool,
    #[arg(long)]
    pub confirm: bool,
    #[arg(long)]
    pub revoke: bool,
    #[arg(long)]
    pub history: bool,
    #[arg(long)]
    pub review_at: Option<String>,
    #[arg(long,value_parser=["review_at"])]
    pub clear: Option<String>,
    #[arg(long)]
    pub reason: Option<String>,
    /// Candidate JSON; --draft without input creates a candidate for explicit review.
    #[arg(long)]
    pub input: Option<String>,
    /// Event UUID from the configured Server's fresh review-confirm ceremony.
    #[arg(long)]
    pub approval: Option<String>,
    /// Required CAS token for revoke or date changes.
    #[arg(long)]
    pub expected_memory_revision: Option<String>,
    #[arg(long,default_value_t=20,value_parser=clap::value_parser!(u16).range(1..=200))]
    pub limit: u16,
    #[arg(long)]
    pub project: Option<String>,
    #[arg(long)]
    pub device: Option<String>,
    /// Fact target version; omitted means unknown, never the CLI version.
    #[arg(long)]
    pub target_version: Option<String>,
}

impl ReviewArgs {
    pub fn writes(&self) -> bool {
        self.confirm || self.revoke || self.review_at.is_some() || self.clear.is_some()
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            ![&self.project, &self.device, &self.target_version]
                .into_iter()
                .flatten()
                .any(|value| value == "*"),
            "invalid_metadata: due request scope cannot contain wildcards"
        );
        if let Some(date) = &self.review_at {
            respire_app::memory::model::metadata::validate_timestamp(date)?;
        }
        ensure!(
            self.due == self.id.is_none(),
            "invalid_metadata: --due takes no id; other review actions require a full id"
        );
        if let Some(id) = &self.id {
            respire_app::memory::model::metadata::validate_full_id(id)?;
        }
        ensure!(
            self.input.is_none() || self.draft || self.confirm,
            "invalid_metadata: --input is only for draft/confirm"
        );
        ensure!(
            self.approval.is_none() || self.confirm,
            "invalid_metadata: --approval is only for confirm"
        );
        ensure!(
            self.reason.is_none() || self.revoke,
            "invalid_metadata: --reason is only for revoke"
        );
        ensure!(self.expected_memory_revision.is_none() || self.revoke || self.review_at.is_some() || self.clear.is_some(),
            "invalid_metadata: --expected-memory-revision is only for revoke/date changes; confirm uses its prepared input");
        ensure!(self.due || (self.project.is_none() && self.device.is_none() && self.target_version.is_none()),
            "invalid_metadata: scope flags are only for --due; draft/confirm use the candidate scope");
        if self.confirm {
            ensure!(
                self.input.is_some() && self.approval.is_some(),
                "invalid_metadata: confirm requires --input and --approval"
            );
            respire_app::memory::model::metadata::validate_full_id(
                self.approval.as_deref().context("missing approval")?,
            )?;
        }
        if self.revoke {
            ensure!(
                self.reason
                    .as_ref()
                    .is_some_and(|value| !value.trim().is_empty()),
                "invalid_metadata: revoke requires --reason"
            );
        }
        if self.revoke || self.review_at.is_some() || self.clear.is_some() {
            ensure!(
                self.expected_memory_revision.is_some(),
                "invalid_metadata: revoke/date changes require --expected-memory-revision"
            );
        }
        Ok(())
    }
}
// CLI review shell (migrated): dispatch and emission for the shared inputs.

use anyhow::{Context, Result};
use respire_app::review::{ReviewInput, ReviewService};
use serde_json::{json, Value};



fn invoke(args: &ReviewArgs) -> Result<Value> {
    args.validate()?;
    let candidate = args
        .input
        .as_deref()
        .map(serde_json::from_str::<ReviewInput>)
        .transpose()?;
    if let Some(input) = &candidate {
        input.validate_shape()?;
    }
    // Reject an old SDK before reading keys, opening/migrating a store or loading a model.
    respire_app::review::require_support()?;
    let (keys, owner) = crate::engine::build_session_with_owner()?;
    let owner = owner.unwrap_or_else(|| "local".to_owned());
    let store = crate::engine::build_local()?;
    let service = ReviewService::new(&keys, &store, &owner)?;
    let now = respire_app::review::now();
    let scope = respire_app::memory::model::Scope {
        project: args.project.clone(),
        device: args.device.clone(),
        version: args.target_version.clone(),
        from: None,
        until: None,
        unknown_fields: Default::default(),
    };
    if args.due {
        return service.due(&scope, &now);
    }
    let id = args.id.as_deref().context("missing review id")?;
    if args.history {
        return service.history(id, usize::from(args.limit));
    }
    if args.draft || args.confirm {
        let input = match candidate {
            Some(input) => input,
            None => service.draft_input(id)?,
        };
        if args.draft {
            return service.prepare(id, &input, &now);
        }
        let event = args.approval.clone().context("missing approval event")?;
        return service.confirm(
            id,
            &input,
            &respire_app::review_approval::OpaqueApproval { event_id: event },
            &now,
        );
    }
    let date = if args.clear.is_some() {
        Some(None)
    } else {
        args.review_at.clone().map(Some)
    };
    service.change(
        id,
        args.expected_memory_revision
            .as_deref()
            .context("missing review CAS token")?,
        date,
        args.reason.as_deref(),
        &now,
    )
}

fn error_code(error: &anyhow::Error) -> &str {
    if error.is::<serde_json::Error>() {
        return "invalid_metadata";
    }
    if let Some(error) = error.downcast_ref::<respire_app::review_approval::ApprovalError>() {
        return error.code;
    }
    if let Some(error) = error.downcast_ref::<respire_app::memory::model::metadata::MetadataError>() {
        return error.code;
    }
    let message = error.to_string();
    for code in [
        "feature_disabled",
        "unsupported_metadata",
        "invalid_metadata",
        "verification_authority_unavailable",
        "verification_rejected",
        "evidence_unavailable",
        "review_conflict",
    ] {
        if message.contains(code) {
            return code;
        }
    }
    if message.contains("Core SDK") || message.contains("memory_metadata_contract") {
        return "unsupported_core_capability";
    }
    "review_failed"
}

pub fn run(args: &ReviewArgs) -> Result<()> {
    use crate::output::{ResultEnvelope, Status};
    let result = invoke(args);
    let mut envelope = match result {
        Ok(details) => {
            let pending = args.draft;
            let count = details["due"].as_array().map(Vec::len);
            let mut result = ResultEnvelope::new(
                "review",
                if pending { Status::Pending } else { Status::Ok },
                json!({"saved":details.get("saved").cloned().unwrap_or(Value::Bool(false)),"due_count":count}),
                Vec::new(),
            );
            result.details = details;
            result
        }
        Err(error) => {
            crate::output_state::set_exit_code(1);
            let mut result =
                ResultEnvelope::new("review", Status::Fail, json!({"saved":false}), Vec::new());
            result.details = json!({"code":error_code(&error),"saved":false});
            if error
                .downcast_ref::<respire_app::review::ReviewCommittedError>()
                .is_some()
            {
                result.details["write_committed"] = json!(true);
                result.details["readback_verified"] = json!(false);
            }
            result.errors.push(format!("{error:#}"));
            result
        }
    };
    envelope.ensure_failure_diagnostics();
    crate::output_emit::emit_result(envelope)
}

#[cfg(test)]
mod review_coverage {
    use super::*;
    use anyhow::Context;

    #[test]
    fn error_codes_preserve_typed_and_wrapped_failures() -> Result<()> {
        let malformed = serde_json::from_str::<Value>("{")
            .err()
            .context("invalid JSON accepted")?;
        assert_eq!(error_code(&malformed.into()), "invalid_metadata");
        let metadata = respire_app::memory::model::metadata::MetadataError {
            code: "unsupported_metadata",
            message: "fixture metadata version",
        };
        assert_eq!(
            error_code(&anyhow::Error::new(metadata).context("outer context")),
            "unsupported_metadata"
        );
        for code in [
            "feature_disabled",
            "unsupported_metadata",
            "invalid_metadata",
            "verification_authority_unavailable",
            "verification_rejected",
            "evidence_unavailable",
            "review_conflict",
        ] {
            assert_eq!(error_code(&anyhow::anyhow!("fixture: {code}: detail")), code);
        }
        for diagnostic in ["Core SDK lacks review support", "missing memory_metadata_contract"] {
            assert_eq!(
                error_code(&anyhow::anyhow!("{diagnostic}")),
                "unsupported_core_capability"
            );
        }
        assert_eq!(
            error_code(&anyhow::anyhow!("fixture storage read failed")),
            "review_failed"
        );
        // Isolated environment (the CLI's capture fixture is bin-local), with
        // the same save/restore contract around the unchanged assertions.
        let isolation = (|| -> anyhow::Result<()> {
            let _lock = crate::TEST_ENV_LOCK.lock().map_err(|error| anyhow::anyhow!("{error}"))?;
            let dir = tempfile::tempdir()?;
            let previous = std::env::var_os("RSRS_DATA_DIR");
            std::env::set_var("RSRS_DATA_DIR", dir.path());
            let checked = (|| -> anyhow::Result<()> {
                let error = respire_app::review_approval::ReviewAuthority::configured()
                    .err()
                    .context("fixture unexpectedly has authority")?;
                assert!(error
                    .downcast_ref::<respire_app::review_approval::ApprovalError>()
                    .is_some());
                assert_eq!(
                    error_code(&error.context("outer authority context")),
                    "verification_authority_unavailable"
                );
                Ok(())
            })();
            match previous {
                Some(value) => std::env::set_var("RSRS_DATA_DIR", value),
                None => std::env::remove_var("RSRS_DATA_DIR"),
            }
            checked
        })();
        isolation
    }
}
