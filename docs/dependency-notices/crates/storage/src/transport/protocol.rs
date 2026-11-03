//! Versioned sync envelopes. Ciphertext payloads remain compatible with v1 clients.
use serde::{Deserialize, Serialize};

use crate::memory::model::StoredMemory;

pub const PUSH_ITEMS: usize = 100;
pub const PAGE_ITEMS: usize = 200;
pub const BATCH_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capabilities {
    pub protocols: Vec<u32>,
    pub epoch: String,
    pub push_items: usize,
    pub push_bytes: usize,
    #[serde(default)]
    pub conflict_resolution: bool,
}

/// A terminal disposition of one retained version. Content history is immutable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resolution {
    pub seq: i64,
    pub conflict_rev: i64,
    pub id: String,
    pub action: String,
    pub head_rev: i64,
    pub restore_op_id: Option<String>,
    pub processed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionDecision {
    pub conflict_rev: i64,
    pub expected_head_rev: i64,
    pub action: String,
    pub restore_op_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveRequest {
    pub epoch: String,
    pub items: Vec<ResolutionDecision>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionResult {
    pub conflict_rev: i64,
    pub outcome: String,
    pub resolution: Option<Resolution>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveReply {
    pub results: Vec<ResolutionResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionPage {
    pub epoch: String,
    pub cursor: i64,
    pub until: i64,
    pub has_more: bool,
    pub resolutions: Vec<Resolution>,
}

/// An immutable local save. Retrying an op_id must send the identical envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    pub op_id: String,
    pub base_rev: Option<i64>,
    pub parent_op_id: Option<String>,
    pub blob: StoredMemory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushRequest {
    pub epoch: String,
    pub items: Vec<Operation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub op_id: String,
    pub status: String,
    pub stored_rev: i64,
    pub head_rev: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushReply {
    pub results: Vec<Receipt>,
}

/// Immutable server event, including versions that lost a legacy LWW comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Change {
    pub rev: i64,
    pub status: String,
    pub op_id: Option<String>,
    pub blob: StoredMemory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page {
    pub epoch: String,
    pub until: i64,
    pub cursor: i64,
    pub has_more: bool,
    pub changes: Vec<Change>,
    pub total: u64,
    pub alive: u64,
}
