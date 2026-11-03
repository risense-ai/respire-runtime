# Explicit feedback experiment

This implements the 2026-10-24 scientist proposal. It is **off by default**.
`RSRS_FEEDBACK=1` opts in (the existing ONEMEMORY_/RESPIRE_ environment aliases
remain supported); it requires the paired SDK with `feedback_contract=1`.
Missing support fails explicitly instead of silently retaining read frequency.

The existing Core heat weight remains 0.10. Its input becomes explicit good
counts, `min(log2(n+1)/4,1)`. Bad counts multiply the real ranking score by
`1-0.4*min(n,5)/5` before candidate filtering, pooling and selection. When this
experiment is enabled, bad penalties default on; `RSRS_BAD_PENALTY=0` disables
them. `RSRS_ABLATE=hot` retains the existing heat ablation. No wrapper rearranges
a truncated top twenty list to imitate the scoring change.

The host rebuilds immutable counts before CLI recall, service search, remember
candidate selection and each benchmark case. Other SDK ranking requests receive
neutral feedback counts when enabled, so they do not retain read-frequency heat.
There are no process-global good/bad maps. The store, exact project/scope and
currently authorized candidate IDs constrain aggregation. Observations come from
the last 180 days and must pass character-bigram Jaccard similarity (default
`RSRS_MARK_SIM=0.5`). Unicode scalar pairs are deduplicated; text is lowercased
and trimmed, with one-character queries represented by a singleton. Empty text
has no similarity. This is the proposed lexical filter, not semantic negation
detection: similar opposing queries can still match and must be evaluated.

A recall in normal mode returns `summary.query_log_id`, an explicit UUID. To
attribute a verdict:

```sh
rsrs query-log mark FULL_MEMORY_ID --good --query-log-id REQUEST_UUID --source human --json
rsrs query-log mark FULL_MEMORY_ID --bad --query-log-id REQUEST_UUID --source model --json
```

Sources are `human`, `model` (the default), or `task_outcome`. Only complete IDs
in that exact request's candidate list are accepted. Timestamp/source/revision
and verdict commit in one transaction. Repeating an identical verdict/source is
idempotent. Regrading wins, including regrading an older request after a newer
one. Repeated identical query/entry contexts contribute at most once; distinct
similar query contexts can contribute separately. Opposite old grades are removed.
A request still awaiting statistics persistence gives an explicit retryable
not-found diagnostic; no different recent request is silently selected.

Legacy good_ids/bad_ids remain readable for existing marks and benchmark data.
New legacy-prefix marks assign old query rows a UUID if needed and use the same
attributed event/mirror transaction. Turning the experiment off to regrade does
not leave an older explicit event authoritative when it is re-enabled.
Idempotent explicit retries also repair an inconsistent report mirror without
creating extra heat or a new revision.
With feedback disabled, the existing recent-candidate prefix grading command is
retained with source `model` only; other sources require explicit request identity
and are rejected instead of being mislabeled. With feedback enabled, request identity is required. Read-only/off
mode cannot create marks; read-only benchmark aggregation does not write marks,
query logs or read counters. Existing read counters remain diagnostic data but
are not used as heat while the experiment is enabled.

Run the existing JSONL `bench run` or `ablation_bench` against a frozen isolated
library/model/SDK and topk 20; retain per-case results and the parameter snapshot.
The original 200-case/250-entry/40-mark dataset has not been supplied here, so
synthetic contract/isolation tests do **not** reproduce its reported gains.
Holdout splits by time/query family and paired hit@20/MRR/per-case regressions,
false penalties, latency and coverage remain required before assessing benefit.

Suggested matched ablations on that same isolated dataset (all topk 20):

| Variant | FEEDBACK | BAD_PENALTY | ABLATE | MARK_SIM |
|---|---|---|---|---|
| Current legacy | 0 | ignored | empty | ignored |
| Remove read heat | 1 | 0 | hot | 0.5 |
| Good heat only | 1 | 0 | empty | 0.5 |
| Conditional bad only | 1 | 1 | hot | 0.5 |
| Combined | 1 | 1 | empty | 0.5 |
| Global bad negative control | 1 | 1 | empty | 0 |

Names in the table omit the `RSRS_` prefix. Bad-only also removes good heat;
the global negative control intentionally admits all query contexts and is not
a recommended production setting. Save each report. The shared parameter
snapshot records explicit feedback defaults, SDK lock hash and CLI version.
`python3 scripts/compare-feedback-bench.py baseline.json variant.json` verifies
paired case order/identity and model/SDK/count compatibility, reports per-case
degradation indices and paired hit@20/MRR deltas with seeded bootstrap intervals.
These are case-bootstrap exploratory intervals, not proof of a frozen dataset,
query-family independence, holdout generalization or a production benefit.

For a running CLI daemon, environment switches are captured at startup. Apply
changed FEEDBACK/BAD_PENALTY/MARK_SIM settings by stopping and restarting the
owned runtime from its host terminal. Explicit grades are refreshed on the next
request without restarting; they are not a one-time process cache. The four-platform
manual research CI mode uses only exact dependency caches prepared by the existing
trusted main workflow, carries no private download token and retains the ordinary
GNU full-suite/90% coverage gate plus native lifecycle and real-model checks.
