//! Fixed-account Server approvals. Receipt JSON alone never establishes trust.
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Debug)]
pub struct ApprovalError {
    pub code: &'static str,
    message: &'static str,
}

impl std::fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for ApprovalError {}

fn unavailable() -> anyhow::Error {
    ApprovalError {
        code: "verification_authority_unavailable",
        message: "configure the fixed HTTPS review authority and log in to its account",
    }
    .into()
}
fn rejected() -> anyhow::Error {
    ApprovalError {
        code: "verification_rejected",
        message: "approval is invalid, stale, revoked, consumed, or bound to a different review",
    }
    .into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewBinding {
    pub owner: String,
    pub local_library_id: String,
    pub id: String,
    pub record_revision: String,
    pub expected_memory_revision: String,
    pub claim_digest: String,
    pub intent_digest: String,
}

fn full_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value)
}
fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|value| hex(value, 64))
}

impl ReviewBinding {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.owner.trim().is_empty()
                && !self.local_library_id.is_empty()
                && self.local_library_id.len() <= 256
                && full_id(&self.id)
                && digest(&self.record_revision)
                && digest(&self.claim_digest)
                && digest(&self.intent_digest)
                && hex(&self.expected_memory_revision, 32),
            rejected()
        );
        Ok(())
    }
}

/// The only public approval input; no actor, issuer, signature or trusted flag.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpaqueApproval {
    pub event_id: String,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AuthorityConfig {
    issuer: String,
    account_id: String,
    owner: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Actor {
    kind: String,
    id: String,
    event_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    event_id: String,
    purpose: String,
    account_id: String,
    binding: ReviewBinding,
    confirmed_by: Actor,
    confirmed_at: String,
    expires_at: i64,
    // Missing fields must not be confused with explicit null.
    consumed_at: Value,
    revoked_at: Value,
    valid: bool,
    submission_available: bool,
}

/// Internal Core input created only from a verified receipt, without inferred
/// root availability. Evidence resolvers must supply their own checked roots.
#[derive(Serialize)]
pub struct VerifiedAuthorityProof {
    id: String,
    record_revision: String,
    event_id: String,
    claim_digest: String,
    confirmed_by: respire_protocol::ConfirmedBy,
    confirmed_at: String,
    outcome: &'static str,
    roots: Vec<Value>,
}

impl Receipt {
    fn confirmed_by(&self) -> respire_protocol::ConfirmedBy {
        respire_protocol::ConfirmedBy {
            kind: respire_protocol::ConfirmerKind::Human,
            id: self.confirmed_by.id.clone(),
            event_id: self.event_id.clone(),
            unknown_fields: Default::default(),
        }
    }

    fn authority_check(&self) -> VerifiedAuthorityProof {
        VerifiedAuthorityProof {
            id: self.binding.id.clone(),
            record_revision: self.binding.record_revision.clone(),
            event_id: self.event_id.clone(),
            claim_digest: self.binding.claim_digest.clone(),
            confirmed_by: self.confirmed_by(),
            confirmed_at: self.confirmed_at.clone(),
            outcome: "trusted",
            roots: Vec::new(),
        }
    }

    fn user_claim_authority_check(&self) -> VerifiedAuthorityProof {
        let mut proof = self.authority_check();
        proof.roots.push(json!({
            "kind":"user", "locator":format!("respire:user-claim:{}", self.binding.id),
            "revision":self.binding.record_revision, "outcome":"available",
        }));
        proof
    }
}

/// No Deserialize, Clone or public constructor. Consume this value for one local CAS attempt.
pub struct TrustedApproval {
    receipt: Receipt,
}

impl TrustedApproval {
    pub fn binding(&self) -> &ReviewBinding {
        &self.receipt.binding
    }
    pub fn confirmed_by(&self) -> respire_protocol::ConfirmedBy {
        self.receipt.confirmed_by()
    }
    pub fn authority_check(&self) -> VerifiedAuthorityProof {
        self.receipt.authority_check()
    }
    pub(crate) fn user_claim_authority_check(&self) -> VerifiedAuthorityProof {
        self.receipt.user_claim_authority_check()
    }
    pub fn confirmed_at(&self) -> &str {
        &self.receipt.confirmed_at
    }
    pub fn expires_at(&self) -> i64 {
        self.receipt.expires_at
    }

    /// No retry on failure: the Server event has already been consumed.
    pub fn commit_once<T>(self, commit: impl FnOnce(&Self) -> Result<T>) -> Result<T> {
        ensure!(
            self.receipt.expires_at > chrono::Utc::now().timestamp(),
            rejected()
        );
        commit(&self)
    }
}

/// Historical authority is separate from a fresh, single-use submission approval.
pub struct HistoricalConfirmation {
    receipt: Receipt,
}

impl HistoricalConfirmation {
    pub(crate) fn user_claim_authority_check(&self) -> VerifiedAuthorityProof {
        self.receipt.user_claim_authority_check()
    }
    pub fn confirmed_by(&self) -> respire_protocol::ConfirmedBy {
        self.receipt.confirmed_by()
    }
    pub fn authority_check(&self) -> VerifiedAuthorityProof {
        self.receipt.authority_check()
    }
    pub fn event_id(&self) -> &str {
        &self.receipt.event_id
    }
    pub fn binding(&self) -> &ReviewBinding {
        &self.receipt.binding
    }
    pub fn confirmed_at(&self) -> &str {
        &self.receipt.confirmed_at
    }
}

pub struct ReviewAuthority {
    config: AuthorityConfig,
    token: String,
    agent: ureq::Agent,
    profile: std::path::PathBuf,
}

// Accept only an explicit HTTPS DNS origin. Redirects, URL credentials, paths,
// IP/loopback endpoints and alternate tokenless local authorities are excluded.
fn https_origin(value: &str) -> bool {
    // Use the HTTP client's parser, including IPv4 alias normalization.
    let Ok(request_url) = ureq::get(value).request_url() else {
        return false;
    };
    let url = request_url.as_url();
    // domain() excludes IPv4/IPv6 host variants after normalization.
    let Some(domain) = url.domain() else {
        return false;
    };
    url.scheme() == "https" && url.port().is_none() && domain.contains('.')
        && !domain.ends_with('.') && !domain.ends_with(".localhost") && domain != "localhost"
        // Exact canonical origin also excludes credentials, paths, ports,
        // queries, fragments and parser-normalized alternative spellings.
        && value == url.origin().ascii_serialization()
}

impl ReviewAuthority {
    /// Read one existing profile snapshot; never unlock keys or change credentials.
    pub fn configured() -> Result<Self> {
        Self::from_session(&crate::auth::read_session_json().map_err(|_| unavailable())?)
    }

    fn from_session(session: &Value) -> Result<Self> {
        let config: AuthorityConfig = serde_json::from_value(
            session
                .get("review_authority")
                .cloned()
                .ok_or_else(unavailable)?,
        )
        .map_err(|_| unavailable())?;
        ensure!(
            https_origin(&config.issuer)
                && full_id(&config.account_id)
                && !config.owner.trim().is_empty(),
            unavailable()
        );
        ensure!(
            session["addr"]
                .as_str()
                .map(|addr| addr.trim_end_matches('/'))
                == Some(config.issuer.as_str())
                && session["user"].as_str() == Some(config.owner.as_str()),
            unavailable()
        );
        let token = session["token"]
            .as_str()
            .filter(|token| !token.is_empty())
            .ok_or_else(unavailable)?
            .to_owned();
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .timeout(Duration::from_secs(30))
            .build();
        Ok(Self {
            config,
            token,
            agent,
            profile: crate::service::data_dir(),
        })
    }

    pub fn handoff(&self) -> Value {
        json!({"issuer":self.config.issuer,"account_id":self.config.account_id,"owner":self.config.owner})
    }

    pub(crate) fn ensure_current(&self) -> Result<()> {
        ensure!(self.profile == crate::service::data_dir(), unavailable());
        let current = Self::configured()?;
        ensure!(
            self.config == current.config && self.token == current.token,
            unavailable()
        );
        Ok(())
    }

    fn request(&self, path: &str, body: Option<Value>) -> Result<Value> {
        self.ensure_current()?;
        let url = format!("{}/api/self/passkeys/review/{path}", self.config.issuer);
        let request = if body.is_some() {
            self.agent.post(&url)
        } else {
            self.agent.get(&url)
        }
        .set("Authorization", &format!("Bearer {}", self.token));
        let response = match body {
            Some(body) => request.send_json(body),
            None => request.call(),
        };
        match response {
            Ok(response) => response.into_json().map_err(|_| rejected()),
            Err(ureq::Error::Status(400 | 404 | 409, _)) => Err(rejected()),
            Err(_) => Err(unavailable()),
        }
    }

    fn receipt(&self, event_id: &str) -> Result<Receipt> {
        ensure!(full_id(event_id), rejected());
        let receipt: Receipt =
            serde_json::from_value(self.request(&format!("events/{event_id}"), None)?)
                .map_err(|_| rejected())?;
        self.check_receipt(&receipt, event_id)?;
        Ok(receipt)
    }

    fn check_receipt(&self, receipt: &Receipt, event_id: &str) -> Result<()> {
        receipt.binding.validate()?;
        ensure!(
            receipt.event_id == event_id
                && receipt.purpose == "review-confirm"
                && receipt.account_id == self.config.account_id
                && receipt.binding.owner == self.config.owner
                && receipt.confirmed_by.kind == "human"
                && receipt.confirmed_by.id == self.config.owner
                && receipt.confirmed_by.event_id == event_id
                && receipt.valid
                && receipt.revoked_at.is_null(),
            rejected()
        );
        let confirmed =
            chrono::DateTime::parse_from_rfc3339(&receipt.confirmed_at).map_err(|_| rejected())?;
        ensure!(
            confirmed.timestamp() <= chrono::Utc::now().timestamp()
                && confirmed.timestamp() < receipt.expires_at,
            rejected()
        );
        if !receipt.consumed_at.is_null() {
            let consumed = receipt.consumed_at.as_str().ok_or_else(rejected)?;
            let consumed =
                chrono::DateTime::parse_from_rfc3339(consumed).map_err(|_| rejected())?;
            ensure!(
                consumed >= confirmed && consumed.timestamp() < receipt.expires_at,
                rejected()
            );
        }
        Ok(())
    }

    /// Verify first, then perform the Server's atomic single-use consume. Never retry.
    pub fn verify_review_approval(
        &self,
        binding: &ReviewBinding,
        approval: &OpaqueApproval,
    ) -> Result<TrustedApproval> {
        binding.validate()?;
        ensure!(binding.owner == self.config.owner, rejected());
        let receipt = self.receipt(&approval.event_id)?;
        ensure!(
            receipt.binding == *binding
                && receipt.submission_available
                && receipt.consumed_at.is_null()
                && receipt.expires_at > chrono::Utc::now().timestamp(),
            rejected()
        );
        let consumed: Receipt = serde_json::from_value(self.request(
            "consume",
            Some(json!({
                "event_id": approval.event_id, "binding": binding,
            })),
        )?)
        .map_err(|_| rejected())?;
        self.check_receipt(&consumed, &approval.event_id)?;
        ensure!(
            consumed.binding == *binding
                && !consumed.submission_available
                && !consumed.consumed_at.is_null()
                && consumed.confirmed_at == receipt.confirmed_at
                && consumed.expires_at == receipt.expires_at
                && consumed.expires_at > chrono::Utc::now().timestamp(),
            rejected()
        );
        Ok(TrustedApproval { receipt: consumed })
    }

    /// Revalidate a durable event for another device; no original library/CAS/intent match.
    pub fn resolve_confirmation(
        &self,
        owner: &str,
        id: &str,
        record_revision: &str,
        event_id: &str,
        claim_digest: &str,
    ) -> Result<HistoricalConfirmation> {
        ensure!(
            owner == self.config.owner
                && full_id(id)
                && digest(record_revision)
                && digest(claim_digest),
            rejected()
        );
        let receipt = self.receipt(event_id)?;
        ensure!(
            receipt.binding.owner == owner
                && receipt.binding.id == id
                && receipt.binding.record_revision == record_revision
                && receipt.binding.claim_digest == claim_digest
                && !receipt.consumed_at.is_null(),
            rejected()
        );
        Ok(HistoricalConfirmation { receipt })
    }

    pub fn revoke(&self, approval: &OpaqueApproval, reason: &str) -> Result<()> {
        ensure!(
            full_id(&approval.event_id) && !reason.trim().is_empty() && reason.len() <= 1024,
            rejected()
        );
        let response = self.request(
            "revoke",
            Some(json!({"event_id": approval.event_id,"reason": reason})),
        )?;
        ensure!(
            response["event_id"] == approval.event_id
                && response["revoked"].as_bool() == Some(true),
            rejected()
        );
        Ok(())
    }
}
