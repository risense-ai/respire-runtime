//! bench - retrieval quality benchmark suite (added 2026-09-19).
//!
//! Why: retrieval changes need repeatable A/B measurement; gains
//! could not be quantified and regressions were invisible. This module is the
//! **pure logic layer** (parse / score / aggregate / compare / mine) - retrieval
//! itself is assembled in main.rs. Benefit: unit-testable; the run never touches
//! the store (no query_log writes, no hit-count bump).
//!
//! Evalset JSONL, one case per line:
//! `{"query":"...","expect":["8-char prefix or full id",...],"project":"...","note":"..."}`
//! Empty expect = negative sample (retrieval should not mislead). Hit rule: id
//! prefix match either way; any expected id counts as a hit.
//! Usage: `rsrs bench run <file> [--topk 5] [--save out.json] [--baseline prev.json]`
//!        `rsrs bench mine --out file.jsonl [--limit 100] [--strict]`

use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// One eval case (one JSONL line).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvalCase {
    pub query: String,
    /// Expected hit ids (8-char prefix or full id; any match counts).
    #[serde(default)]
    pub expect: Vec<String>,
    /// Restrict to this project (default: whole store).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Parse evalset JSONL: skip blank lines and `#` comments; bad lines report the line number.
pub fn parse_evalset(text: &str) -> Result<Vec<EvalCase>> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let case: EvalCase = serde_json::from_str(line)
            .with_context(|| format!("evalset line {} failed to parse: {}", i + 1, line))?;
        anyhow::ensure!(
            !case.query.trim().is_empty(),
            "evalset line {} has empty query",
            i + 1
        );
        out.push(case);
    }
    Ok(out)
}

/// Id prefix match either way: expect may be an 8-char short id or a full id; empty never matches.
pub fn id_match(result_id: &str, expect: &str) -> bool {
    let e = expect.trim();
    !e.is_empty() && (result_id.starts_with(e) || e.starts_with(result_id))
}

/// Rank of the first hit (0-based); None if none hit.
pub fn rank_of(ids: &[String], expect: &[String]) -> Option<usize> {
    ids.iter()
        .position(|id| expect.iter().any(|e| id_match(id, e)))
}

/// Result for one case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseResult {
    pub query: String,
    #[serde(default)]
    pub expect: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// Rank of the first hit (0-based); None = miss.
    pub rank: Option<usize>,
    /// Retrieved entry ids in rank order (full ids).
    pub ids: Vec<String>,
    /// Top-1 score.
    pub top1_score: Option<f32>,
    /// Top-1 title (human-readable).
    #[serde(default)]
    pub top1_title: String,
}

/// Aggregate metrics. Hit-rate denominator is positive cases (n_pos);
/// negative samples are counted separately as noise.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Metrics {
    /// Total cases (including negatives).
    pub n: usize,
    /// Cases with a non-empty expect list.
    pub n_pos: usize,
    /// Negative samples (empty expect).
    pub n_neg: usize,
    /// Share of positives whose hit landed in top-1.
    pub hit1: f64,
    /// Share that landed in top-3.
    pub hit3: f64,
    /// Share that landed in top-k.
    pub hitk: f64,
    /// Mean reciprocal rank (MRR).
    pub mrr: f64,
    /// Positive cases that returned no results.
    pub empty_results: usize,
    /// Negative cases that still returned results (noise; lower is better).
    pub neg_noise: usize,
    /// Mean top-1 score (positives).
    pub avg_top1_score: f64,
}

/// Summarize per-case results into metrics.
pub fn summarize(results: &[CaseResult], topk: usize) -> Metrics {
    let mut m = Metrics {
        n: results.len(),
        ..Default::default()
    };
    let mut rr = 0.0f64;
    let mut score_sum = 0.0f64;
    let mut score_n = 0usize;
    for r in results {
        if r.expect.is_empty() {
            m.n_neg += 1;
            if !r.ids.is_empty() {
                m.neg_noise += 1;
            }
            continue;
        }
        m.n_pos += 1;
        if r.ids.is_empty() {
            m.empty_results += 1;
        }
        if let Some(rank) = r.rank {
            rr += 1.0 / (rank as f64 + 1.0);
            if rank == 0 {
                m.hit1 += 1.0;
            }
            if rank < 3 {
                m.hit3 += 1.0;
            }
            if rank < topk {
                m.hitk += 1.0;
            }
        }
        if let Some(s) = r.top1_score {
            score_sum += s as f64;
            score_n += 1;
        }
    }
    if m.n_pos > 0 {
        let n = m.n_pos as f64;
        m.hit1 /= n;
        m.hit3 /= n;
        m.hitk /= n;
        m.mrr = rr / n;
        if score_n > 0 {
            m.avg_top1_score = score_sum / score_n as f64;
        }
    }
    m
}

/// Per-query rank change.
#[derive(Debug, Clone, Serialize)]
pub struct Delta {
    pub query: String,
    pub base: Option<usize>,
    pub now: Option<usize>,
}

/// Compare report (this run vs baseline).
#[derive(Debug, Clone, Serialize)]
pub struct CompareReport {
    pub improved: Vec<Delta>,
    pub regressed: Vec<Delta>,
    pub same: usize,
    pub only_in_base: usize,
    pub only_in_now: usize,
}

/// Per-case compare: smaller rank or miss->hit = improved; hit->miss or larger rank = regressed.
/// Match key = query + project.
pub fn compare(base: &[CaseResult], now: &[CaseResult]) -> CompareReport {
    let key = |r: &CaseResult| format!("{}|{}", r.query, r.project.clone().unwrap_or_default());
    let base_map: HashMap<String, Option<usize>> = base.iter().map(|r| (key(r), r.rank)).collect();
    let mut rep = CompareReport {
        improved: Vec::new(),
        regressed: Vec::new(),
        same: 0,
        only_in_base: 0,
        only_in_now: 0,
    };
    let mut matched = 0usize;
    for r in now {
        let k = key(r);
        match base_map.get(&k) {
            None => rep.only_in_now += 1,
            Some(&b) => {
                matched += 1;
                let improved = match (b, r.rank) {
                    (None, Some(_)) => true,
                    (Some(bi), Some(ni)) => ni < bi,
                    _ => false,
                };
                let regressed = match (b, r.rank) {
                    (Some(_), None) => true,
                    (Some(bi), Some(ni)) => ni > bi,
                    _ => false,
                };
                if improved {
                    rep.improved.push(Delta {
                        query: r.query.clone(),
                        base: b,
                        now: r.rank,
                    });
                } else if regressed {
                    rep.regressed.push(Delta {
                        query: r.query.clone(),
                        base: b,
                        now: r.rank,
                    });
                } else {
                    rep.same += 1;
                }
            }
        }
    }
    rep.only_in_base = base_map.len().saturating_sub(matched);
    rep
}

/// Mine an evalset draft from query-log.
///
/// expect = good (strict uses only this) ∪ adopted (weak signal); keep only ids
/// still active in the store; merge same query (newest first, unique); shorten
/// ids to 8 chars (readable; matching still uses prefix either way).
pub fn mine_from_rows(
    rows: &[respire_app::transport::local::QueryLogRow],
    strict: bool,
    limit: usize,
    active: &HashSet<String>,
) -> Vec<EvalCase> {
    let mut seen_queries = HashSet::new();
    let mut out: Vec<EvalCase> = Vec::new();
    for r in rows {
        if out.len() >= limit {
            break;
        }
        let q = r.query.trim();
        if q.is_empty() || !seen_queries.insert(q.to_owned()) {
            continue;
        }
        let mut pool: Vec<&String> = r.good.iter().collect();
        if !strict {
            pool.extend(r.adopted.iter());
        }
        let mut ids: Vec<String> = Vec::new();
        for id in pool {
            if active.contains(id) && !ids.iter().any(|x| x == id) {
                ids.push(id.clone());
            }
        }
        if ids.is_empty() {
            continue;
        }
        let expect: Vec<String> = ids.iter().map(|id| id.chars().take(8).collect()).collect();
        out.push(EvalCase {
            query: q.to_owned(),
            expect,
            project: if r.project.is_empty() {
                None
            } else {
                Some(r.project.clone())
            },
            note: Some(format!("query-log#{} {}", r.id, r.ts)),
        });
    }
    out
}

/// Archived report (carrier for --save / --baseline).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchReport {
    pub version: u32,
    pub ts: String,
    pub evalset: String,
    pub topk: usize,
    /// Active entries in the store at eval time.
    pub n_entries: usize,
    /// Snapshot of env vars that affect retrieval (to replay a tuning session).
    #[serde(default)]
    pub params: BTreeMap<String, String>,
    pub metrics: Metrics,
    pub results: Vec<CaseResult>,
}

/// Env vars that affect retrieval (recorded in the report).
pub const PARAM_KEYS: &[&str] = &[
    "RSRS_FEEDBACK",
    "RSRS_MARK_SIM",
    "RSRS_BAD_PENALTY",
    "RSRS_ABLATE",
    "RSRS_ROUTE",
    "RSRS_RECALL_MIN_SCORE",
    "RSRS_RECALL_PROFILE",
    "RSRS_RECALL_COS_MIN",
    "RSRS_RECALL_SIM_MIN",
    "RSRS_RECALL_COS_RELATIVE_RATIO",
    "RSRS_RECALL_COS_MARGIN",
    "RSRS_RECALL_LEXICAL_WEIGHT",
    "RSRS_RECALL_SEMANTIC_POWER",
    "RSRS_RECALL_BM25",
    "RSRS_RECALL_MAX_FUSION",
    "RSRS_RECALL_NORMALIZE_ABLATION",
    "RSRS_RECALL_AUX_CAP_RATIO",
    "RSRS_RECALL_RRF_CAP",
    "RSRS_RECALL_FUSION",
    "RSRS_RECALL_FUSION_ALPHA",
    "RSRS_RECALL_FUSION_BETA",
    "RSRS_RECALL_FUSION_TEMPERATURE",
    "RSRS_RECALL_FUSION_GATE_RECENCY",
    "RSRS_RECALL_FUSION_GATE_RECENCY_TEMPORAL",
    "RSRS_RECALL_FUSION_GATE_HOT",
    "RSRS_RECALL_FUSION_GATE_TREE",
    "RSRS_RECALL_FUSION_TEMPORAL_ALPHA",
    "RSRS_RECALL_HEAT_CAP",
    "RSRS_MMR_LAMBDA",
    "RSRS_ANCESTOR_BUDGET",
    "RSRS_ANCESTOR_ROOT_FLOOR",
    "RSRS_M3_DIR",
    "RSRS_DEBUG_SCORE",
];

/// Environment snapshot plus effective persistent fusion settings.
pub fn snapshot_params() -> anyhow::Result<BTreeMap<String, String>> {
    let mut m = BTreeMap::new();
    for k in PARAM_KEYS {
        if let Ok(v) = respire_app::env::var(k) {
            if !v.trim().is_empty() {
                m.insert((*k).to_owned(), v);
            }
        }
    }
    for (name,default) in [("RSRS_FEEDBACK","0"),("RSRS_MARK_SIM","0.5"),("RSRS_BAD_PENALTY","1")] {
        m.entry(name.into()).or_insert_with(||default.into());
    }
    m.entry("RSRS_RECALL_PROFILE".into()).or_insert_with(||"calibrated".into());
    m.insert("recall_calibration_contract".into(),"1".into());
    m.insert("recall_fusion_contract".into(),"1".into());
    for (key, value) in respire_app::recall_fusion::query_settings()? {
        if key == "fusion" || key.starts_with("fusion_") {
            m.insert(format!("RSRS_RECALL_{}", key.to_uppercase()),
                value.as_str().map(str::to_owned).unwrap_or_else(|| value.to_string()));
        }
    }
    m.insert("feedback_contract".into(),respire_app::core_sdk::FEEDBACK_CONTRACT.to_string());
    {
        use sha2::{Digest,Sha256};
        m.insert("sdk_lock_sha256".into(),format!("{:x}",Sha256::digest(include_bytes!("../../../sdk/core-sdk.lock.json"))));
    }
    m.insert("cli_version".into(),env!("CARGO_PKG_VERSION").into());
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{anyhow, Result};

    fn result(q: &str, rank: Option<usize>, n_ids: usize) -> CaseResult {
        CaseResult {
            query: q.to_owned(),
            expect: vec!["a".to_owned()],
            project: None,
            rank,
            ids: (0..n_ids).map(|i| format!("id{i}")).collect(),
            top1_score: Some(0.8),
            top1_title: "t".to_owned(),
        }
    }

    #[test]
    fn parse_ok_and_skip() -> Result<()> {
        let text = "# comment\n\n{\"query\":\"alpha\",\"expect\":[\"abcd1234\"]}\n{\"query\":\"beta\",\"expect\":[]}\n";
        let cases = parse_evalset(text)?;
        assert_eq!(cases.len(), 2);
        assert_eq!(cases[0].query, "alpha");
        assert_eq!(cases[1].expect.len(), 0);
        Ok(())
    }

    #[test]
    fn parse_bad_line_reports_lineno() -> Result<()> {
        let text = "{\"query\":\"alpha\"}\n{\"query\":\"beta\",broken}\n";
        let err = match parse_evalset(text) {
            Err(e) => e.to_string(),
            Ok(_) => return Err(anyhow!("expected parse error")),
        };
        assert!(err.contains("line 2"), "err={err}");
        Ok(())
    }

    #[test]
    fn parse_empty_query_rejected() -> Result<()> {
        let err = match parse_evalset("{\"query\":\"  \"}\n") {
            Err(e) => e.to_string(),
            Ok(_) => return Err(anyhow!("expected empty-query error")),
        };
        assert!(err.contains("empty query"), "err={err}");
        Ok(())
    }

    #[test]
    fn id_match_prefix_both_ways() {
        assert!(id_match("abcd1234-ffff-0000", "abcd1234"));
        assert!(id_match("abcd1234-ffff-0000", "abcd1234-ffff-0000"));
        assert!(!id_match("abcd1234-ffff-0000", "ffff"));
        assert!(!id_match("abcd1234", ""));
    }

    #[test]
    fn rank_first_hit() {
        let ids: Vec<String> = ["x1", "x2", "abcd1234-0"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(rank_of(&ids, &["abcd1234".to_owned()]), Some(2));
        assert_eq!(rank_of(&ids, &["nope".to_owned()]), None);
        // any of several expected ids counts as a hit
        assert_eq!(
            rank_of(&ids, &["nope".to_owned(), "x2".to_owned()]),
            Some(1)
        );
    }

    #[test]
    fn summarize_metrics() {
        let results = vec![
            result("a", Some(0), 3), // hit@1
            result("b", Some(2), 5), // hit@3, hit@5
            result("c", None, 5),    // miss
        ];
        let m = summarize(&results, 5);
        assert_eq!(m.n, 3);
        assert_eq!(m.n_pos, 3);
        assert!((m.hit1 - 1.0 / 3.0).abs() < 1e-9);
        assert!((m.hit3 - 2.0 / 3.0).abs() < 1e-9);
        assert!((m.hitk - 2.0 / 3.0).abs() < 1e-9);
        let mrr = (1.0 + 1.0 / 3.0) / 3.0;
        assert!((m.mrr - mrr).abs() < 1e-9);
    }

    #[test]
    fn summarize_negative_and_empty() {
        let mut neg = result("n", None, 2);
        neg.expect.clear();
        let mut pos_empty = result("p", None, 0);
        pos_empty.expect = vec!["a".to_owned()];
        let m = summarize(&[neg, pos_empty], 5);
        assert_eq!(m.n_neg, 1);
        assert_eq!(m.neg_noise, 1);
        assert_eq!(m.empty_results, 1);
        assert_eq!(m.n_pos, 1);
    }

    #[test]
    fn compare_improve_regress_same() {
        let base = vec![
            result("up", None, 1),
            result("down", Some(0), 3),
            result("same", Some(2), 3),
        ];
        let now = vec![
            result("up", Some(1), 3),
            result("down", None, 1),
            result("same", Some(2), 3),
            result("new", Some(0), 1),
        ];
        let rep = compare(&base, &now);
        assert_eq!(rep.improved.len(), 1);
        assert_eq!(rep.improved[0].query, "up");
        assert_eq!(rep.regressed.len(), 1);
        assert_eq!(rep.regressed[0].query, "down");
        assert_eq!(rep.same, 1);
        assert_eq!(rep.only_in_now, 1);
        assert_eq!(rep.only_in_base, 0);
    }

    #[test]
    fn compare_rank_smaller_is_better() {
        let base = vec![result("q", Some(3), 5)];
        let now = vec![result("q", Some(1), 5)];
        let rep = compare(&base, &now);
        assert_eq!(rep.improved.len(), 1);
        assert!(rep.regressed.is_empty());
    }

    #[test]
    fn mine_filters_inactive_and_merges() {
        use respire_app::transport::local::QueryLogRow;
        let row = |id: i64, q: &str, good: &[&str], adopted: &[&str]| QueryLogRow {
            request_id:None,
            id,
            ts: "2026-09-19".to_owned(),
            query: q.to_owned(),
            project: String::new(),
            scope: String::new(),
            candidates: vec![],
            adopted: adopted.iter().map(|s| (*s).to_owned()).collect(),
            good: good.iter().map(|s| (*s).to_owned()).collect(),
            bad: vec![],
        };
        let active: HashSet<String> = ["aaaaaaaa-1".to_owned(), "bbbbbbbb-2".to_owned()]
            .into_iter()
            .collect();
        let rows = vec![
            row(1, "alpha", &["aaaaaaaa-1"], &["bbbbbbbb-2", "deadbeef-x"]),
            row(2, "beta", &[], &["deadbeef-x"]), // all expect inactive -> drop
            row(3, "gamma", &["bbbbbbbb-2"], &[]),
        ];
        let got = mine_from_rows(&rows, false, 10, &active);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].query, "alpha");
        assert_eq!(got[0].expect, vec!["aaaaaaaa", "bbbbbbbb"]);
        // strict: good only, alpha keeps aaaaaaaa
        let got_strict = mine_from_rows(&rows, true, 10, &active);
        assert_eq!(got_strict[0].expect, vec!["aaaaaaaa"]);
    }

    #[test]
    fn report_roundtrip() -> Result<()> {
        let rep = BenchReport {
            version: 1,
            ts: "2026-09-19T00:00:00Z".to_owned(),
            evalset: "x.jsonl".to_owned(),
            topk: 5,
            n_entries: 10,
            params: BTreeMap::new(),
            metrics: summarize(&[result("a", Some(0), 1)], 5),
            results: vec![result("a", Some(0), 1)],
        };
        let s = serde_json::to_string(&rep)?;
        let back: BenchReport = serde_json::from_str(&s)?;
        assert_eq!(back.metrics.n, 1);
        assert_eq!(back.results[0].rank, Some(0));
        Ok(())
    }
}
