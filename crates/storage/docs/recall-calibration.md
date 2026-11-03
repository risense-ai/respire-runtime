# Recall calibration

This CLI requires the paired Core SDK with `recall_calibration_contract=1`.
The 2026-10-31 repair includes cosine admission, mailbox floor alignment,
remaining-weight ablation normalization, plain document embeddings, BM25/IDF
lexical coverage, Latin token boundaries, diagnostic receipts and read-heat caps.
Core performs all scoring; the host only supplies controls and persists opaque
indexes. No extra model inference or remote selector request is introduced.

Five-axis fusion settings additionally require `recall_fusion_contract=1` in the
paired SDK. The TUI model page provides a persistent editor; `agent-config`
reports saved and effective settings under `recall_fusion_runtime`. Environment
overrides take priority and saved changes apply to the next recall without
reindexing. See [client2gui integration](client2gui-recall-fusion.md) for the
shared settings contract and GUI implementation steps.

## Controls

Set variables in the process that runs retrieval. Restart an existing runtime to
change its environment; setting variables only on a thin client does not change
the already running runtime. `RSRS_*` names retain the standard legacy aliases.

| Environment variable | Default | Meaning |
| --- | --- | --- |
| RSRS_RECALL_PROFILE | calibrated | `legacy` restores the historical scoring controls together |
| RSRS_RECALL_COS_MIN | model default | Raw document/chunk cosine floor: M3 0.42; 768 dimensions 0.38; other dimensions 0.40; 0 disables it |
| RSRS_RECALL_SIM_MIN | 0.10 | Composite score floor after admission and feedback |
| RSRS_RECALL_MIN_SCORE | 0.10 | Mailbox tier score floor |
| RSRS_RECALL_BM25 | 1 | BM25/IDF coverage; 0 selects the boundary-corrected historical keyword score |
| RSRS_RECALL_NORMALIZE_ABLATION | 1 | Normalize remaining active weights and vector-only fusion |
| RSRS_RECALL_LEXICAL_WEIGHT | 0.30 | Lexical share of weighted semantic fusion |
| RSRS_RECALL_SEMANTIC_POWER | 1.3 | Set to 1 for the report's linear alternative |
| RSRS_RECALL_MAX_FUSION | 0 | Select strongest-axis fusion instead of weighted fusion |
| RSRS_RECALL_AUX_CAP_RATIO | 0.85 | Limit auxiliary contributions relative to semantic strength |
| RSRS_RECALL_RRF_CAP | 0 | Optional consensus contribution; report comparison value 0.05 |
| RSRS_RECALL_FUSION | legacy | `attention` re-ranks admitted candidates with per-head softmax distributions and independent gates; `attention_anchor` keeps the legacy relevance blend and attends only priors; `auto` selects by a fitted pool-size gate |
| RSRS_RECALL_FUSION_ALPHA | 0.20 | Auxiliary prior share in attention fusion; semantic keeps the residual |
| RSRS_RECALL_FUSION_BETA | 0.25 | Lexical head share in attention fusion |
| RSRS_RECALL_FUSION_TEMPERATURE | 1.0 | Softmax temperature after per-head standardization |
| RSRS_RECALL_FUSION_GATE_RECENCY | 0.02 | Non-temporal recency gate in attention fusion |
| RSRS_RECALL_FUSION_GATE_RECENCY_TEMPORAL | 1.0 | Temporal recency gate in attention fusion |
| RSRS_RECALL_FUSION_GATE_HOT | 0.10 | Heat gate in attention fusion |
| RSRS_RECALL_FUSION_GATE_TREE | 0.02 | Tree gate in attention fusion |
| RSRS_RECALL_FUSION_TEMPORAL_ALPHA | 0.15 | Extra prior share for temporal questions |
| RSRS_RECALL_HEAT_CAP | 8 | Cap read frequency for ranking; raw counters remain intact |
| RSRS_RECALL_COS_RELATIVE_RATIO | unset | Optional additional cosine floor, e.g. 0.85 of this query's top cosine |
| RSRS_RECALL_COS_MARGIN | unset | Optional top-minus-median semantic admission margin, e.g. 0.15 |
| RSRS_DEBUG_SCORE | 0 | Include per-record ID/score components and print the receipt to stderr |

Boolean controls accept only 0 or 1. Numeric ranges are checked by Core. Individual
variables override the selected profile. The relative gates and 768-dimensional
default are implemented initial values, not validated quality guarantees.

The legacy profile sets cosine 0, composite 0.30, mailbox 0.25, keyword weight
0.30, power 1.3, historical keyword scoring, no normalization/auxiliary cap/RRF,
and read-heat cap 15. It does not restore the substring bug or undo vector
migration. A full binary rollback uses the previous CLI/SDK and index generation.

## Index migration

Document embedding no longer inserts Chinese field-name labels. It uses plain
title plus the first 400 Unicode scalars of content; an already repeated title is
not duplicated. Tags remain lexical fields and full-body chunking is unchanged.
The Core generation changes, so existing resumable background indexing rebuilds
derived vectors. During rebuilding, source-checked pending entries retain lexical
retrieval. No user memory, encryption key, sync metadata or raw usage count is
rewritten by this migration. `rsrs reembed` remains the explicit repair command.

## Diagnostics and checks

Recall JSON summaries add `retrieval`, including empty results and selector
fallback: actual cosine/composite floors, best cosine and pre-floor score,
examined/dropped counts, pending admissions and mailbox tiers visited. Explicit
debug mode adds IDs and numeric components; it does not return vectors or bodies.
Benchmark snapshots record all controls, CLI version and SDK lock hash. Standalone
ablation per-case output also includes the Core receipt. Benchmarks remain
read-only with respect to query logs and usage counts.

Existing native feedback/model probes check both calibrated admission/diagnostics
and semantic-only ablation, then verify historical feedback semantics under the
explicit legacy profile. Existing source, model, migration and upgrade checks
remain release gates. No external corpus replication is claimed: the user asked
to implement the supplied algorithms without requiring the original evaluation
archive. Lower admission floors may return candidates for questions with no
answer; titles remain reference material, not evidence that an answer exists.
