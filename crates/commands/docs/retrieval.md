# Retrieval and local index migration

Core owns retrieval, ranking, feature preparation and context selection. CLI-side code
manages user settings, encrypted data and local index locators.

## Opt-in complete brief and metadata-aware recall

`recall QUERY --brief --json` uses a 1500 Unicode-scalar dynamic block. An
optional `--render-budget-base64` supplies the same strict wrappers as the title
interface; public `items` must remain empty. The CLI never accepts a caller's
rendered_text, completeness, revision, authority checks or root proofs. Default
brief layouts support limits up to 200. Brief is opt-in; no preference is enabled.

Before loading the provider, the host checks `brief_render_contract=1`,
`memory_metadata_contract=1`, the existing budget/intent/supersession contracts,
and `read_heat_contract=1` when read heat is explicitly configured. Missing
capabilities fail visibly. It reads one authorized `review_snapshot`, decrypts
the real source fields, and uses review's existing trusted event resolver.
Unconfigured authority is unavailable; stored human strings never establish
trust. The same immutable source view is published as a resident lease, keeping
pending-index lexical recall available without loading a model.

The SDK's query_settings.now is copied exactly to evidence_context.now and
request_scope.at. The current device tag and requested project are explicit;
the fact target version remains null. One pure metadata evaluation supplies
current record revisions. One query_business call then owns evidence filtering,
how-to union, ranking, score filtering and final representation selection.
Proofs are request-local and are not accepted from CLI/runtime JSON.

The host provides original full/summary/title variants from that snapshot. Full
includes the complete body and its original title, source identity, stored
summary, source references and artifact fields; Core adds status, scope and
expiry labels before budgeting. Summary and title are always complete=false
until a trusted source review qualifies them. Their existence is not evidence
of semantic completeness. Core tries full/summary/title/drop in its own rank
order, with no truncation or first-item exception. Manual qualification samples
and production rollout remain required; this path does not summarize content.

The host emits Core's rendered_text unchanged and checks the final Unicode
scalar count, actual wrappers, selected IDs/order and same-view evidence again.
Tokens/tokenizer_id stay null and estimated stays true. JSON carries actual
representation, revision, evidence, scope, expiry and source references.

New-format records require evidence-aware recall even when the library write
gate is off. Their budgeted output uses complete brief selection, including when
the caller requested titles. An older consumer must refuse an unsupported new
receipt rather than treating it as the old title receipt. Non-budgeted new-format
details include the authoritative evidence and restrictions. Legacy-only recalls
without --brief preserve the original no-context/title path and title bytes.

## Dynamic title budget (WP3a)

`recall --titles --no-related --render-budget-base64 <BASE64> --json`
accepts UTF-8 JSON encoded with standard Base64 so Windows npm command shims
receive one argument without interpreting JSON quotes or shell metacharacters.
The decoded object is `{budget_chars,prefix_by_count,separator,suffix,items:[]}`.
Prefixes cover zero through `--limit` and include their own newlines. The CLI validates Base64, the strict layout schema, empty input items and prefix
coverage, then negotiates Core capabilities before loading the catalog, scheduling
index work or evaluating the embedder. For rendering, it reads full stored records
whose IDs belong to the authorized catalog; resident directory entries deliberately
contain no ciphertext and are never decrypted. The host supplies complete title,
full ID and authoritative superseded status; it does not truncate or select them. The format is
`- title（full-id） →superseded`, with the status marker omitted when absent.
Before rendering, one pure `related_business` metadata call uses the same query
and authorized view, `all_superseded=true`, empty `ids/pairs`, and
`related_settings.enabled=false`. It requires `superseded_status_contract=1`
and returns the complete in-scope map computed by Core from authoritative
`supersedes` edges. Stored reverse hints are ignored. The host reuses this map
after recall; budgeted requests perform no second relationship call or kNN pass.

The same option travels through the existing runtime argv/JSON request. Before
its single `query_business` call, the host requires
`capabilities.render_budget_contract=1`. It passes the complete `render_budget`
to Core, which owns ordering, deduplication and hard Unicode scalar counting.
Budgeted calls pass the actual `auto|fact|howto` intent and authorized
`skill_runs` counts, requiring `howto_recall_contract=1`. One `query_business`
call performs the original ordinary and skill-only passes, their existing merge,
then the final-score filter and budget inside Core. The host returns Core's
`intent`, `procedure_pass` and `procedure_promoted` diagnostics and performs no
second merge. Core payloads without this option omit `intent` and `skill_runs`,
keeping the existing CLI procedure branch.

Both successful and empty recall envelopes include `summary.budget`. Its
`rendered_text` is the exact dynamic block; `items`, `chars`, `budget_chars`,
`selected_count`, `candidate_count`, drop counts and `status` explain the result.
The host verifies the selected IDs, complete rendering and scalar count before
returning the envelope. Missing capability, a missing receipt or a mismatch is
an explicit error, never an unbudgeted fallback. The caller must send that text
unchanged and refuse overflow. The Qoder adapter further limits the maximum to
1500 scalars and checks the receipt before emission.

`--render-min-score <f32>` passes a finite final-score threshold to Core; negative
values are allowed. It requires `render_min_score_contract=1` before any catalog
or model work. Core applies `score >= threshold` after its existing gates, ranking
and quality selection, before budgeting, without replenishing removed candidates.
This is separate from retrieval admission controls such as `sim_min`. The recall
summary exposes `filtered_by_score`, including zero when the filter is requested.
Qoder forwards nonzero `recall_threshold` through this option and does no local
score filtering.

This phase supports complete `title` representations only. Without a target
generation tokenizer, Core returns `tokens=null`, `tokenizer_id=null` and
`estimated=true`; character counts remain exact. Notifications and later slots
must be part of the supplied wrappers before selection. Independent `show`
responses are outside this automatic block.

## Research routing and ablation

The Core applies the research query routing by default: recency is enabled only
for temporal queries, and the tree contribution is scaled to one quarter.
`RSRS_ROUTE=0` restores the previous always-on scoring. `RSRS_ABLATE` accepts
comma-separated `semantic`, `kw`, `recency`, `hot`, `emo`, and `tree`; named axes
are zeroed and the remaining active weights are normalized. Set
`RSRS_RECALL_NORMALIZE_ABLATION=0` for historical scores. The complete
[recall calibration controls and migration](recall-calibration.md) describe the
paired Core SDK update. The host reads the variables and supplies
explicit controls to the memory-only Core. `ONEMEMORY_ROUTE` and
`ONEMEMORY_ABLATE` remain supported compatibility names.

Every recall JSON summary, including empty results and quality-selection failures,
contains `routing` with `temporal`, `route_on`, and normalized `ablate` from the
actual Core call. Benchmark parameter snapshots include both controls. Environment
changes apply to the executing process; a running runtime must receive its controls
in its own environment. Changing a thin client's environment does not change it.

Candidate receipts append five numbered judgments: duplicate, contradiction,
obsolete, linkable, and representation. The same actions are included in pending
remember receipts. Consumers answer each question before choosing update, merge,
parent, or force; a candidate receipt is not a successful write.

Both plaintext record and encrypted-payload parsing accept historical string and
array `see_also` values. Serialization writes arrays only, omitting empty lists.

The current Core uses a zero-valued emotion contribution; `emo` ablation therefore
does not change scores. This control does not add an emotion signal to the index.

For local ablation measurements, set `RSRS_DATA_DIR` to an initialized isolated
library copy, with its session and opaque index artifacts. Copy SQLite WAL state
consistently with the database. The example opens SQLite read-only, does not migrate,
does not prepare missing indexes, and does not update recall counts or query logs.
Fast mode performs no selector request. Optional report files contain memory titles
and must stay in a suitable local output directory.

```powershell
$env:RSRS_DATA_DIR = 'D:\isolated-library'
$env:RSRS_ROUTE = '0' # baseline; remove this variable for research routing
$env:RSRS_ABLATE = 'recency,tree' # empty value enables all axes
cargo run --locked -p respire --example ablation_bench -- daily_evalset.jsonl --topk 5 --per-case --save baseline.json
```

`--per-case` writes one case and its actual routing receipt per stdout line, with
aggregate metrics on stderr. `--save` uses the existing benchmark report format,
including the environment-control snapshot. Both canonical `RSRS_*` names and
historical `ONEMEMORY_*` aliases use the same host resolution as normal retrieval.

```mermaid
flowchart LR
  Query[Query] --> Core[Local retrieval]
  Core -->|explicit quality mode: query and titles| API[Configured endpoint]
  API --> Core
  Core --> Results[Validated results]
```

| Mode | Data flow |
| --- | --- |
| Fast, default | Local retrieval, no selector request |
| High quality | Query and bounded candidate titles sent to the configured endpoint |
| Selector failure | Local results with fallback diagnostics |

Memory and ancestor bodies are not sent to the selector. The TUI explains this flow;
high quality requires the user's explicit choice.

```sh
rsrs recall "query" --mode fast --titles --json
rsrs recall "query" --mode quality --titles --json
rsrs agent-config --set recall_mode=fast
```

Configure URL/model/key on the Models page. Keys use the OS keyring, not `agent.json`.
`RSRS_RECALL_API_KEY` overrides the running process key. File settings apply on the
next query; changed process environment requires runtime restart. TUI recall checks
use the same data flow and diagnostics.

| Migration step | Behavior |
| --- | --- |
| Runtime automatic preparation | Detect pending work, prepare the active profile's resources and rebuild in the background |
| `model install-m3` | Explicitly verify pinned files; pending index work is handled by the runtime |
| `model activate m3` | Rebuild/resume locally, then activate after source checks |
| Interrupted rebuild | Keep completed checkpoints; explicitly resume a pending profile switch |
| Concurrent content edit | Reject stale derived data |
| Legacy index | Rebuild from decrypted source with M3; retired inference never runs |
| `reembed` | Repair missing/outdated data for the current model |

When a usable account has an invalid or incomplete index, the runtime prepares
the active embedding profile and rebuilds derived data in the background. M3
remains the default when no library profile has been selected. Recall uses current, source-checked
index artifacts and full-body lexical retrieval for pending entries. A library
with no indexed entries can perform lexical retrieval without loading the model.
Its JSON summary reports `index_pending`, `indexed_candidates` and
`lexical_candidates`; pending entries gain semantic retrieval after background
indexing completes. No manual rebuild confirmation is needed.
The TUI displays progress and download errors through the model-operation channel.
Rebuilding checkpoints completed entries and resumes pending work after restart.
Encrypted memories, account keys and sync state are preserved. Explicit invalid
model paths or failed downloads remain visible errors.

`RSRS_M3_DIR` selects the legacy M3 directory; custom resource paths belong to
their immutable profile snapshots. See [embedding profiles](model-profiles.md).
Index work does not alter memory content
or synced dirty flags. Core artifacts are opaque, versioned local derived data, not
account keys or an encryption mechanism. Writes and changed sync inputs maintain the
active index; deleted content is excluded from retrieval.

`--titles --json` requests IDs, titles and final scores; `show <id> --json` reads selected
memories. Binary updates do not rewrite agent files; run `rsrs inject` after prompt changes.

New profiles use M3. Existing legacy metadata does not select the retired model.
Incomplete generations remain resumable; semantic retrieval uses only valid,
source-checked artifacts for the active selection. The runtime continues long migrations in the background;
`rsrs reembed` remains available for an explicit repair. The plain-document calibration update advances the M3 generation identity;
existing source-checked checkpoints for that generation are reused. Content, timestamps and sync flags
are unchanged; retired weight files are not deleted automatically.

## Resident retrieval and concurrency

The runtime keeps one foreground and one background ONNX session. Each session
runs one inference call at a time; the two sessions have independent admission
queues. Foreground query embedding does not wait for a background indexing batch.
The tokenizer and immutable model input bytes are shared; native session weights
and work buffers may be allocated separately.

Explicit lexical-only requests use a per-request vector-free metadata copy,
including mixed indexed/pending data; the resident vectors remain unchanged.

Core holds an immutable parsed retrieval view. Unchanged queries retain that view;
source/artifact revisions publish an incremental replacement. Existing readers
retain their previous view until their query ends. An account/key change invalidates
the host cache and old-context replies. Refreshes decrypt changed records outside
the cache publication lock. Publication still copies unchanged Core view data once
per refresh; it is not a zero-copy persistent tree.

Normal runtime remember/update prepare outside the SQLite write transaction.
Only the commit phase takes the host write gate to coordinate with account changes
and complex edits. The short SQLite transaction validates the source ciphertext, commits the source and
local artifact state, and rejects a concurrent conflicting preparation. One
source conflict is re-evaluated from the latest record. The write receipt reports
`index_state` as pending or ready; successful durable storage does not wait for
background embeddings. Background artifact publication also checks the source
ciphertext, so concurrent edits cannot receive an obsolete artifact. Complex
multi-record operations retain the existing exclusive host gate.

The runtime follows the operating system's available CPU parallelism for ordinary jobs and reserves two additional show/list/status
slots. Reads use WAL snapshots without an application writer gate. Healthy host
clients reuse the validated runtime before taking the lifecycle gate; only startup,
replacement and recovery serialize through that gate. SQLite still permits one writer.
Health and CLI progress report foreground/background activity and queues separately.

`RSRS_RPC_PARALLELISM` or `config --rpc-parallelism` may reduce ordinary concurrency;
values above available CPU parallelism are clamped. `/api/health` reports both
`rpc.available_parallelism` and `rpc.effective_parallelism`. This does not create
additional model sessions: foreground and background inference each remain serial.

Queued HTTP and pipe commands await their result in asynchronous connection
tasks. Completion callbacks only hand off in-memory results; neither command
workers nor the dispatcher write sockets or wait for preceding HTTP responses.
Incomplete bodies and stalled writes have transport deadlines independent of
command execution. Ordinary queue length does
not reject a command. Execution slots still follow available CPUs; model sessions
and serialized write transactions remain unchanged.
`RSRS_RPC_QUEUE_WAIT_SECS` bounds queue waiting (default 120, range 1–3600).
RPC callers can shorten this wait using the optional `queue_wait_ms` field.
Expired commands that have not started are removed and cannot later commit a write.
Once execution starts, the server keeps its actual result; a queue deadline is
not reported as cancellation of an executing write. The HTTP client's existing
120-second deadline can still precede that result. Such transport failures return
`request_outcome_unknown` with the original request ID, and never replay the write.
Inspect it with an RPC request such as
`{"v":1,"id":"inspection-id","method":"runtime.result","args":["original-request-id"]}`.
`pending` means the request is queued or executing; `completed` includes its
original response. `unknown` is not proof that the write did not commit: receipts
cover the last 64 completed requests in the current runtime and do not survive
restart. Concurrent reuse of an in-flight request ID is rejected rather than
executed again; this is not durable exactly-once execution.
Health and stop HTTP endpoints remain outside ordinary command admission.
Manual sync captures its outgoing boundary in the existing sync worker under the
write gate, with a generation check; waiting for this snapshot never occupies the
shared dispatcher or a network executor. An expired sync cannot execute when the
gate later becomes available.
The health response includes the last
1024 queue/command timing samples in microseconds; command time ends at the
in-memory result handoff and excludes asynchronous socket delivery. It does not
separately measure native inference or storage.

The resident host holds the LibraryLock and owns SQLite commits. It sends Core
business requests over private inherited pipes to one shared worker process;
the worker reuses the foreground and background native sessions. Transport
credentials remain in host callbacks, and the child receives only OS loader
paths and local inference settings. It opens no network listener or memory
database. `--client-only` and `--no-autostart` do not own or recover workers.

The host observes native watchdog status independently of command execution.
If a cancelled native call remains unresponsive for five more seconds, or worker
heartbeats stop for ten seconds, it fails pending Core calls without replay,
terminates the owned child and confirms exit before permitting a replacement.
Each complete Core call also has a 365-second ceiling, covering the existing
load, native queue and execution budgets plus grace, even when an abnormal call
never reaches Run. Running SQLite writes remain owned by the host and return
their actual commit result.
The next request rebuilds its authorized resident view from the host store and
loads the model once in the replacement process. Old generation replies and
leases cannot be used by the replacement. The native execution watchdog retains
its SDK timeout; this is recovery after cancellation, not a faster native model.
If termination cannot be confirmed, replacement is prohibited; health/control
remain available and the host retains its library lock during shutdown.

`native-fault-tests` is a non-default fixture feature. Its explicitly marked SDK
can inject holds at the real Run boundary with a two-second watchdog. The fixture
also shortens the complete Core call ceiling to ten seconds. SDK promotion,
release staging and the exact binary version gate reject fixture
packages. Fault injection validates containment and recovery; it does not prove
that a real ORT call has the same defect.

```mermaid
flowchart TD
  Client[CLI / API / MCP] --> Owner[Validate resident owner]
  Owner --> Reads[Recall / show / list]
  Owner --> Write[Remember / update preparation]
  Reads --> View[Retain immutable Core view]
  View --> FG[Foreground Session: serial Run]
  Write --> Commit[Short SQLite source check and commit]
  Commit --> Receipt[Durable write receipt: pending or ready]
  Commit --> BG[Background Session: serial Run]
  BG --> Publish[Source-checked artifact commit]
  Publish --> Refresh[Changed records refresh Core view]
  Refresh --> View
```

Recall associations are documented in [associations](associations.md). Use `--no-related` for a per-request original-results comparison.

## How-to routing and procedure run history (CLI)

When a recall query reads like a procedural question (the built-in CJK how-to, error,
step and command markers, or an English `how to ...`) the CLI sets `intent=howto` and runs a second Core query filtered to
`kind=skill`. The two result sets are unioned by id, ordered with Core's scores,
and the best-scored procedure is moved into the third slot when no procedure is
already in the top three. Facts keep their Core order and Core scores; only
procedure ordering is nudged by the local run history. `--intent fact` skips the
second pass, `--intent howto` forces it, and passing `--type` disables auto-detection.

`rsrs run-log <id> --status ok|fail|confounded|no_effect --note "..."` appends to
the local `skill_runs` table (SQLite, never encrypted into the payload, never
synced — same contract as `query_log`). Raise/lower rankings are bounded to ±0.03
so a handful of runs cannot outvote semantics; only `ok`/`fail` take part. A
`confounded` run (something else changed too, so the outcome cannot be attributed)
or a `no_effect` run is recorded but attributes nothing: it neither feeds the
ordering nor breaks or counts toward the audit's "last three runs all failed"
streak, which an `ok` does break.

The summary of every recall now carries `intent`, `procedure_pass` and
`procedure_promoted`, so a consumer can tell whether a how-to pass ran and whether
the order departs from Core's scores.

`rsrs audit` also reports `hot_untyped`: live entries recalled at least five
times, not typed as `skill`, whose body still reads like a manual. The list is
advisory — the injected policy asks the AI to judge during tidy whether the entry
is a procedure worth an explicit `update --kind skill` (with the six sections) or
should stay a fact. Declining to upgrade is a first-class outcome, not a skip:
with no `run-log` ok, no user sign-off, or a body that does not read as a
procedure, the AI must name the missing evidence and leave the entry as-is
rather than promote to fill a quota. `show` and `list` expose `recall_count` for
that judgement; the count is cumulative and never feeds ranking.

The judgement is not silent: the injected policy requires the AI to state its
decision in the reply (which entry was upgraded and why, or why nothing was), so
the user can veto an upgrade.
