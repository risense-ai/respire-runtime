use serde::{Serialize, Deserialize};
use respire_protocol::MemoryEntry;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoredEntry {
    pub score: f32,
    pub entry: MemoryEntry,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRef {
    pub id: String,
    pub title: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateReport {
    pub merge: Vec<ScoredEntry>,
    pub parent: Vec<ScoredEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootStat {
    pub id: String,
    pub title: String,
    pub descendants: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CureSuggest {
    pub orphan: NodeRef,
    pub target: NodeRef,
    pub target_tree: NodeRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeCureReport {
    pub roots: Vec<RootStat>,
    pub lone_roots: usize,
    pub suggests: Vec<CureSuggest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepenPlan {
    /// Proposed sub-outlines under the selected root.
    pub sub_roots: Vec<DeepenSubRoot>,
    /// Leaves that did not cluster (stay put, not under a sub-outline)
    pub leftovers: Vec<NodeRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepenSubRoot {
    pub title: String,
    pub member_ids: Vec<String>,
    pub member_titles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    pub id: String,
    pub title: String,
    pub date: String,
    pub depth: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cluster {
    /// Members (created_at early→late)
    pub members: Vec<Member>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub total: usize,
    pub roots: usize,
    /// Orphan leaf: no parent, no children
    pub orphans: usize,
    pub max_depth: usize,
    /// Groups suggested by Core.
    pub clusters: Vec<Cluster>,
    /// Already-placed cluster count (all members share a parent — already under an outline, not fragments)
    pub settled: usize,
}
