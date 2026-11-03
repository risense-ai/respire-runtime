//! Review command inputs (the clap surface), shared with the runtime engine.
//! Dispatch, service calls and result emission stay in the CLI's review
//! shell, which re-imports these types.

use anyhow::{ensure, Result};
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
