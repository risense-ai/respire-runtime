# Runtime control contract

## Scope

This contract freezes the minimum cross-repository agreement needed by Stage 1.
It covers release metadata, health identity, stop draining, request identity and
result retention, root resolution, bootstrap routing, and channels. It does not
migrate the existing disk layout and does not authorize a stable release.

The canonical machine-readable inputs are under `contracts/runtime-control/`.
Rust and Go tests must consume the same fixture files. A protocol change updates
the fixtures and this document in one contract commit.

## Release metadata

`schema_version` identifies release metadata semantics.

- Schema 1 is the legacy compatibility shape.
- Schema 2 is the canonical Stage 1 shape.
- Unknown required semantics reject the file.

### Canonical schema 2 fields

| Field | Meaning |
| --- | --- |
| `schema_version` | Must be `2`. |
| `runtime_version` | Runtime version without the leading `v`. |
| `tag` | Exact release tag and must equal `v` plus `runtime_version`. |
| `target_triple` | Real OS, CPU, and ABI target. |
| `archive_file` | Exact release archive file name. |
| `archive_sha256` | SHA-256 of the archive bytes. |
| `binary_file` | Exact archive-relative path of the primary executable. |
| `binary_sha256` | SHA-256 of the extracted primary executable. |
| `source_commit` | Full Git commit SHA used to build the release. |
| `compat` | Minimum and maximum supported CLI versions. |
| `protocol_range` | Minimum and maximum supported wire protocol versions. |
| `capabilities` | Required capability keys with versions. |
| `files` | Archive-relative path, byte size, and SHA-256 for every required file. |

The archive and binary hashes describe different byte sequences and never have
to be equal. Both are mandatory.

### Legacy schema 1 mapping

| Schema 1 field | Canonical field |
| --- | --- |
| `sha256` | `archive_sha256` |
| `triple` | `target_triple` |
| `binary_sha256` | `binary_sha256` |
| `binary_file` | `binary_file` |
| `runtime_version` | `runtime_version` |
| `tag` | `tag` |
| `compat` | `compat` |

When legacy and canonical aliases both exist, equal values are accepted and
different values reject the metadata. Published releases are never edited in
place. Missing safe-install data may be supplied only by separately trusted
metadata; otherwise the combination is unsupported.

## Installation

1. Resolve a pinned compatible release from an approved source.
2. Download the archive to private staging.
3. Verify the downloaded bytes against `archive_sha256`.
4. Reject absolute paths, parent traversal, symlinks, devices, FIFOs, duplicate
   conflicting entries, unsupported file types, and size/count violations.
5. Extract into staging without following pre-existing symlinks out of staging.
6. Verify the primary executable against `binary_sha256` and every required
   file against `files`.
7. Verify target, SDK inventory, version, source commit, and protocol range.
8. Promote verified bytes to an immutable version directory.
9. On any failure, remove this staging attempt and preserve the active version.

Mirror retries may change transport only when the pinned digest and asset
identity remain the same. A mirror cannot become the sole trust root.

## Health and instance identity

Minimum identity fields:

- `installation_root`
- `installation_id`
- `instance_id`, newly generated for each business Runtime start
- `pid`
- `process_start_id` or an equivalent stable OS process start identity
- `image_path`
- `image_sha256`
- `runtime_version`
- `account_id`
- `generation`
- `managed_id` when supervised
- `protocol_range`
- `capabilities`
- `store_ready`
- `state`

PID alone is not identity. Managers cross-check the launch record, health reply,
and OS process identity. A health path is evidence, never an executable command.
Readiness requires identity, store readiness, capability, and root agreement.
HTTP success alone is not business readiness.

Health failure, timeout, permission denial, or a busy port never authorizes
quiet takeover, killing, port selection, or starting another instance.

## Stop and drain

```text
running -> maintenance_requested -> draining -> resources_closing
    -> stopped(drained)
draining -> timeout/blocked -> explicit force -> stopped(forced_timeout)
draining -> failed/unknown
```

`stop` first returns `accepted`, a new `request_id`, and a stable
`operation_id`. It must not claim `drained` immediately.

The stop request body carries the previously verified `installation_id`,
`instance_id`, `account_id`, and `generation`. Runtime checks them while holding
the admission fence before entering maintenance. Missing or stale identities
return `stop_identity_mismatch` without stopping the current instance. The
legacy `runtime.stop` RPC method cannot bypass this check.

`drained` means all admitted RPC, writes, synchronization, indexing,
classification, profile changes, and started MCP calls completed or received an
explicit outcome; database work committed or flushed as required; workers
stopped; and ports, child processes, and handles reached the contracted state.
The final proof is a supervisor exit handshake or a private durable stop receipt,
followed by confirmation that the exact process exited and ownership released.

The Stage 1 durable receipt is
`<installation_root>/runtime/stop-<instance_id>.json`. Managers construct this
path from their trusted installation root and accept only instance IDs matching
`[A-Za-z0-9_-]{1,128}`. Runtime writes a private temporary file, flushes it,
renames it in the same directory, and flushes the directory on Unix before exit.
A write failure is a failed stop, never proof of `drained`.

The receipt has `schema_version: 1`, `protocol_version`, `operation_id`,
`installation_id`, `instance_id`, `pid`, `process_start_id`, `image_path`,
`image_sha256`, `runtime_version`, `account_id`, `generation`, `state`, and
`unfinished`. Every identity field must match the stopped instance, and the
operation must match its accepted stop. `drained` requires an explicitly empty
`unfinished` array. Missing, malformed, stale, or mismatched receipts fail
closed. The CLI returns the verified receipt in `runtime.stop`'s `summary`;
Client2 verifies that operation against the persisted receipt after its own
OS-bound exit wait. A normal drain timeout never implicitly authorizes a kill.

Client disconnects do not cancel admitted writes. Idle MCP connections do not
block drain; new calls are rejected and started calls finish. About four seconds
is only a compatibility or forced-path deadline. That outcome is
`forced_timeout` or `compatibility_timeout`; unfinished operations are `aborted`
or `unknown`, never a normal successful drain.

Force is allowed only for an exact instance identity. A timeout alone does not
prove that the lock holder died.

## Request identity and results

| Field | Lifetime |
| --- | --- |
| `request_id` | One transport RPC or polling call; never reused. |
| `operation_id` | One logical operation across retries and status queries. |
| `idempotency_key` | Logical submission inside an explicit idempotency scope. |
| `parent_operation_id` | Parent of independent child operations. |
| `expected_generation` / `expected_revision` | Compare-and-swap precondition. |

Business submissions carry a top-level `scope` beside `v`, `id`, `method`, and
`args`. Its only fields are `account_id`, `instance_id`, and `generation`.
CLI and Client2 capture these values from one verified health identity and keep
them for the whole logical operation, including every `runtime.result` query.
The wire generation is the health value: raw Runtime generation plus one.
Callers must not subtract one or refresh scope while retrying or polling.

Missing or null scope returns `scope_required`. Empty identities, generation
zero, and an account, instance, or generation mismatch return `scope_mismatch`.
Missing members, wrong JSON types, or unknown scope members fail RPC body
parsing (HTTP 400); they are not a successful RPC with an invented error code.
The shared schema requires a complete, nonempty scope on accepted requests.
Public health, `runtime.status`, asset status, and model catalog/progress remain
queryable without business scope. Internal MCP submission captures the current
scope once before enqueueing.

Runtime verifies scope at the admission/stop fence before inserting a new
idempotency identity. Queue entries keep the admitted scope and revalidate it
before execution. Stale queued work receives an explicit failure; it never
rebinds to the new identity. Result cache keys use the verified request scope,
including instance ID, rather than rereading a new current scope. Result queries
remain available during drain; they do not admit new business.

The request fingerprint contains protocol semantic version, method, normalized
arguments, the complete scope, and parent operation ID. The normalization rule
is fixed by shared fixtures. Unknown execution-affecting fields do not disappear.
The `operation_result` fixture records this binding in its `scope` object;
legacy flattened account/generation fields cannot replace request scope.
The `business_rpc_request` fixtures are actual request envelopes checked against
the scope in `positive/health-identity.json`. A result query has its own request
ID and carries the original operation ID in `args[0]`.

Responses echo the current transport `id` and supported `v`, plus the original
`operation_id`, `scope`, and `idempotency_key`. Success, pending, and failure
constructors preserve the same binding. A cached replay changes only its outer
`id` to the retry request ID; it never rewrites the cached receipt or operation.
A `runtime.result` reply uses the polling request ID both outside and in
`envelope.summary.request_id`; its summary retains the original operation,
scope, and key, while a nested cached response retains its submission request ID.
Explicit scope rejection may omit scope or report the current scope, but must
remain a failure and never changes the caller's original operation context.

The `business_rpc_response` fixtures contain `request` and `response`, plus
`cached_response` for replay cases. The shared Node verifier and existing Rust
and Go fixture consumers check these relational invariants; schema validation
alone cannot prove cross-field equality. Fixture `error_code` names a checker
violation, not a new Runtime wire error. These are static contract checks, not
compiled Runtime/CLI execution or G1 acceptance.

Same key plus same fingerprint has one admitted execution. Same key plus a
different fingerprint returns `idempotency_conflict`. Result states are
`pending`, `completed`, `failed`, `aborted`, and `unknown`. `unknown` is not
proof that work did not run.

Stage 1 may use bounded in-memory retention. After eviction or restart, the
result is `unknown`; non-idempotent writes are never replayed automatically.
Stage 2 must commit a durable receipt atomically with the business submission
before promising cross-restart exactly-once. External non-database side effects
need their own recovery state machine.

Model setup, probe, and rollback use separate child operation IDs under one
parent operation. Compensation checks the expected revision or generation. A
later successful change rejects an older rollback instead of being overwritten.

## Root resolution

`RSRS_DATA_DIR` is the legacy whole-isolation root. It can affect
`client.json`, the primary account root, named accounts, and the installation
root. Existing tests and multi-store workflows depend on that behavior.

Stage 1 keeps this contract. It does not create a config directory or introduce
Stage 2 split-root variables. For a controlled inspection, use the existing
`--data-dir PATH` ahead of the inherited `RSRS_DATA_DIR`; both map the whole
installation. `RSRS_DEFAULT_DATA_DIR` is only an SDK default-home marker, not
an explicit legacy isolation request. A controlled parameter overrides it.

The read-only summary has `schema_version: 1`, `layout: "phase1"`,
`legacy_whole_isolation`, and an exact `sources` entry for each path:

| Field | Existing source and Stage 1 meaning |
| --- | --- |
| installation_root | Rust main_data_dir(); Client2 Manager.DataRoot |
| device_config_root | Parent of client_config_path, not a /config subdirectory |
| client_config_path | installation_root/client.json |
| account_data_root | Strict client.json snapshot and existing data_dir selection; isolated profiles must be in-tree |
| accounts_root | Existing accounts_root(); installation_root/accounts |
| asset_root | BGE-M3 installation target, normally models/bge-m3; not loaded/discovered inference assets |
| runtime_state_root | Existing rpc_worker runtime directory; installation_root/runtime |

Sources are `RSRS_DATA_DIR`, `default_data_dir`, `client.json:data_dir`,
or `RSRS_M3_DIR`, as applicable. The summary contains no account identity,
credentials, config contents, new shared log root, or synthetic summary hash.
The existing optional `log_root` extension remains for existing consumers. It
now names the real Client2 Manager.Root (installation_root/client2), which
contains managed runtime.log; it is optional and is not emitted by ResolvedRoots.

Compare the CLI `--roots --data-dir PATH --json` envelope's `summary`,
Runtime health's `resolved_roots`, Client2 `--roots --data-dir PATH --json`
output, or desktop `GET /api/roots` response's `result`. Inspection does not
create directories or locks, migrate, start a Runtime, load Core, or invoke
business RPC. The Runtime must already be running to inspect its health.
Runtime itself already accepts `--data-dir`; no new Runtime flag is added.

Only a missing client.json permits an empty in-memory config; inspection never
writes it. Other read, JSON, field-type, or path errors propagate. CLI reports
its existing failure envelope, Client2 exits nonzero or returns ok=false, and
Runtime health returns state=error with code=roots_resolution_failed (without
config text). Roots containing parent traversal are rejected rather than cleaned:
filesystem links can change what '..' actually selects. Relative paths are
reported absolute without probing the filesystem. In legacy isolation, account
selection preserves Rust's component-prefix, relative/absolute, and case rules.

Existing home/tilde helpers are not changed. Rust's model helper expands only
'~/' using the OS home, while its service home can honor HOME first. Use the
same absolute controlled root for cross-client comparisons. Rust rejects an
implicit model root that escapes legacy isolation. Client2's live API rejects
a Manager root that differs from the current environment; its standalone probe
does not construct a running Manager. Since Client2 downloads through ModelDir(),
a conflicting RSRS_M3_DIR is reported as an error, not falsely labeled as its
actual installation target. Rust can report an explicitly split RSRS_M3_DIR.
No installation, release, or trust behavior is changed by this inspection.

`client.json` is an object. Missing and malformed are different states. A JSON
array, scalar, bad JSON, wrong field type, or permission failure returns a
structured error and does not panic, reset to `{}`, or continue as default.
Writes preserve unknown fields, serialize across processes, use an expected
revision, and replace through a same-directory temporary file plus atomic
rename or the platform equivalent.

## Bootstrap and routing

Client2 contains a minimal bootstrap for a clean machine. It does not require
npm, PATH CLI, or an existing Runtime. It uses the same pinned compatibility
contract as normal installation, verifies every executable before running it,
and returns `components_ready` only after identity, real write/read, and MCP
verification. Any failure leaves a repair state and never marks onboarding
complete.

Routing:

| Operation | Executor |
| --- | --- |
| Memory write/read, MCP | Runtime |
| Login, register, account identity, keygen, keys-export | CLI |
| Device configuration | Shared configuration entry |
| Runtime lifecycle | Runtime management protocol |

`runtimeChannel`, `cliChannel`, and `clientChannel` are independent. A resolver
turns channel preferences into one exact compatible combination. Stable rejects
prereleases. If no compatible stable exists, current dev remains dev; the UI
must not call it stable.

## Platform commitment

Stage 1 requires all eight targets:

| Platform | Target |
| --- | --- |
| Linux x64 glibc | `x86_64-unknown-linux-gnu` |
| Linux x64 musl | `x86_64-unknown-linux-musl` |
| Linux ARM64 glibc | `aarch64-unknown-linux-gnu` |
| Linux ARM64 musl | `aarch64-unknown-linux-musl` |
| macOS ARM64 | `aarch64-apple-darwin` |
| macOS Intel | `x86_64-apple-darwin` |
| Windows x64 | `x86_64-pc-windows-msvc` |
| Windows ARM64 | `aarch64-pc-windows-msvc` |

Each target needs its archive, build metadata, and integrity evidence. A missing
native runner is a release blocker; emulation cannot replace it.

### Timeout receipt fixtures

The shared `stop-final-forced-timeout.json` and
`stop-final-compatibility-timeout.json` fixtures retain the stopped scope and
unfinished operation IDs. Unfinished results may be `aborted` or `unknown`,
never fabricated `completed`. Neither timeout state is a normal `drained`
receipt. `stop-final-fabricated-completion.json` is rejected. These are wire
fixtures, not proof of process exit, child cleanup, lock release or a working
force executor; dedicated native acceptance remains mandatory.

### Backend load evidence in assets.status

The current unfrozen contract adds optional `backend_load` to `AssetsStatus`.
Its `state` is `not_run`, `loaded`, or `failed`; `reason` is an optional
stable lowercase code, never raw errors, JSON, addresses or paths. A loaded
status carries `evidence` and omits reason; other states omit evidence.
Missing optional fields remain readable by protocol serde, including internal
file-only checks with `complete=true` and no backend result. This does not
constitute wire readiness. No version is bumped or published by this change.

On the wire, `complete` equals an empty `missing` inventory AND loaded
evidence proving `ready`, `fresh_session`, and `inference_completed`.
A failed probe leaves `complete=false` even when all files are verified.
`missing` contains only real file inventory failures, never a synthetic probe
file. Pre-initialization file checks do not invoke the probe.

`BackendLoadEvidence` matches the public sanitized SDK success result:
`contract/status/ready/backend/engine/selected/provider/fresh_session/
inference_completed/model/index_identity/dimensions/node_assignment/
cpu_node_fallback/runtime/sdk_pin/modules/module_identity_source`.
`runtime` contains `kind/api_version/version/build_info_sha256`; `sdk_pin`
contains `target/sdk_version/manifest_sha256`; each module has `id/sha256`.
Native addresses, symbol maps, build text and paths are excluded. Current
evidence describes ONNX Runtime; `node_assignment=not_measured` is explicit
and does not claim every node used an accelerator. CPU fallback policy is
`allowed/disabled/host_managed/not_applicable`, according to selection.

The shared assets fixtures and Node verifier enforce wire integrity without
starting Runtime or claiming actual native SDK acceptance.

### Private auth, installation plan/verify and snapshot maintenance

`schema/private-host-control.schema.json` freezes the DTOs in
`protocol::host_control` and `protocol::maintenance_control`. The existing Node
verifier decodes the single JSON-string RPC argument before checking its schema.
The existing Rust suites include the shared fixture consumer and deserialize
positive cases with the producer DTOs. Client2 consumes the same cases in its
existing Go fixture suite. No additional runner or application implementation is
introduced. The original 73 fixtures and two schemas remain byte-bound unchanged.
The legacy `bootstrap_route` fixture retains its historical CLI entry/coordinator
assertion. It is not evidence that the new CLI executes authentication business
logic locally; the inherited request is executed by Runtime.

The `private_host_control` case container is not a wire DTO. Its `channel`,
`maintenance_phase`, `finish_maintenance`, original-operation anchors and history
are declared test inputs. They do not authorize anything. `request` is the real
RPC request, `args[0]` is the real serialized parameter DTO, and `result`, when
present, is the typed receipt or ModelPreparation. Model cases also contain
`public_response`, the ResultEnvelope (not RpcResponse), checked against the
strict modelEnvelope schema. Other command/status/error wrapping remains outside
these fixtures; no values are guessed.

All methods use a one-shot inherited pipe, never a privileged loopback HTTP
route. Auth and snapshot operations require canonical lowercase UUIDv4 request
and operation IDs, the original operation ID, and an ASCII idempotency key of
1..128 letters, digits, underscore, period or hyphen. Business scope, lifecycle,
queue and parent-operation fields cannot grant this access. Binding constrains
installation root, profile, launch ID and optional expected account; it is not
a credential. Bad JSON and arbitrary fields are rejected, including fields in
the auth identity/authorization variants. No argv or arbitrary exec is accepted.

Passwords, browser tokens and recovery codes exist only in the private auth
request/receipt. They must not appear in public model-plan DTO fields. Fixtures
contain synthetic strings, not credentials. Schema key allowlists cannot detect
a secret hidden in arbitrary text, nor prove absence from logs, argv or storage.
The public model plan has `complete=false`, equal `assets`/`missing` inventories
and no backend evidence; it proves neither installed files nor backend readiness.

`control.model_install_plan` and `control.model_install_verify` accept only
HostModelParams (schema_version, binding, intent and selection_sha256), with no
operation/key or argv. Intent preserves model, for_engine and mirror; paths and
mirror authority still come from local host policy. Plan accepts no selection
digest; verify requires the exact lowercase SHA-256 returned by plan. Runtime
binds that digest to the authoritative selection, intent and pinned inventory,
and rechecks the selection before and after the fresh probe.
Both require Paused maintenance. Their response commands are `model-install-plan`
and `model-install-verify`; details are strict ModelPreparation containing
selection_sha256 and AssetsStatus assets. Summary contains only complete, equal
to details.assets.complete (always false for plan). Both report
control_ready=true and store_ready=false, with no related-memory payload. Verify
accepts a failed/incomplete probe as incomplete; complete requires fresh-session,
completed-inference evidence and the existing assets/provider/module invariants.
The loaded fixture is synthetic evidence, not an actual probe result.

Runtime must invalidate CPU ORT and run a fresh probe inside Paused maintenance.
The outer deadline is 180 seconds, the internal probe limit is 150 seconds, and
parent-pipe revocation must remain active. Schema and fixtures cannot establish
any of these execution properties. Neither source code presence nor a passing
fixture verifier counts as fresh-probe acceptance.

Auth `awaiting_verification` is not `committed`. It retains maintenance ownership
until the receipt target has started and has been independently verified.
`unknown` never authorizes registration replay or automatic compensation.
Committed keygen still has an unbound identity and must retain Paused maintenance;
it is not an account-login commit. Account operations use Paused authorization,
except `account_complete`, which needs the narrow Verified+receipt role. A local
`rolled_back` receipt does not claim remote account deletion. Runtime must bind
the original admission fingerprint and credential backend before effects; these
fixtures do not establish journal durability or keyring recovery.

Snapshot offline actions use Paused authorization. `commit` and `release` require
Verified authorization and the receipt-bound live Runtime. A result query may use
a fresh request/launch ID, but retains the original O, key and fingerprint. The
fingerprint is SHA-256 of the exact JSON tuple
`["snapshot-restore-v1", installation_root, profile, expected_account_id,
sync_generation, snapshot_id]`; action and request/launch IDs are excluded.
Node and Go recompute the tuple; Rust binds the frozen fingerprint anchor.
Terminal history retains O/fingerprint/snapshot identity and cannot regress from
released/rolled_back, or from verified to an uncommitted state. Cleanup warnings
do not erase terminal history. These assertions do not prove a restore was not
executed twice, process exit, lock ownership, file replacement or cleanup.

Actual grant consumption, marker digest/token/controller birth, parent-pipe
revocation, secret handling, source/target locks, strict credential identity,
live Runtime verification and crash recovery require native acceptance. A green
fixture verifier is not evidence that any of those runtime properties passed.

### Fixed identity read and reviewed config validation

`control.identity.session_list` accepts only HostIdentitySessionListParams:
schema_version, binding and identity. It requires Paused maintenance, has no
operation/key/business scope/argv, and returns HostIdentitySessionListResult.
Its private ResultEnvelope uses command=session, summary={"action":"list"},
and details={"details": remoteJson}. Session details may leave the coordinator
only after the original owner is restored and verified. The GET limit is 30s;
the CLI exchange limit is 35s. Fixtures do not prove deadlines or restoration.

`control.config_validate` accepts the frozen ConfigValidateParams and returns
ConfigValidationReceipt in the config-validate envelope summary; details is null.
Both private methods report control_ready=true, store_ready=false. Neither a
receipt, off_mode=true nor a successful private read proves serving store readiness
or authorizes maintenance completion. Config validation has no O/key/scope/argv.

Config cases bind the reviewed original UTF-8 bytes/revision, staged candidate
bytes/revision, all five allowed intent fields, source and target profile, and
both strict session identities. Unrelated original fields must survive. Receipt
revision/intent/profile/identity values must match the request, not another edit.
The fixture-only config_context declares observed files and identities; it is not
a grant or filesystem proof. Node and Go independently recompute byte hashes;
Rust binds the declared original/candidate byte and digest anchors and calls the
actual ConfigChangeIntent::apply. The candidate-whitespace case fails the byte
anchor in every consumer; only Node/Go claim independent hash recomputation. Native admission, symlink/canonicalization, locks,
CAS publication, sync validation, parent watching, rollback and restored Runtime
health remain outside these fixture checks. Private config/session values must
not be copied to public HTTP, progress, logs or operation ledgers.

### Fixed identity writes, super-reset and model maintenance

The existing schema, manifest and consumers also freeze these private methods:

- control.identity.logout, control.identity.session_revoke and control.identity.write_result
  use HostIdentityWriteParams / HostIdentityWriteResult. Full logout may yield
  Absent; soft logout and revoke cannot remove a previously present identity.
  The owned session path, digest, same-account identity and revoke UUID are bound.
- control.key.super_reset, control.key.result and control.key.rollback use
  HostKeyParams / HostKeyResult. Only super_reset is in this frozen cohort.
  Later key operations are not admitted by this schema. Supplemental password
  inputs are not part of the immutable operation fingerprint. A new super password
  is synthetic in fixtures and permitted only in the private committed result,
  never in public_response, progress or ledger fields. Existing native recovery
  session snapshots are not claimed to be credential-free.
- control.model_maintenance uses ModelMaintenanceParams / ModelMaintenanceReceipt.
  Plan has no expected review; apply is reset_cpu-only; verify excludes reset_cpu.
  Non-plan receipts must match both selection and revision digests. Catalog
  package source/hash/version/member are fixed; DLL metadata in the fixture is
  synthetic, not installed-byte or hardware evidence. npu_ready remains false.

All seven methods use Paused maintenance and inherited_pipe. Identity/key writes
require the original O and key, even on a fresh request/launch result query. The
fixture-only write_context pins root/profile/source identity/complete operation,
O/key and fingerprint. Node and Go independently hash the sorted JSON object used
by the producer; Rust binds the declared complete intent/digest anchor and parses
actual respire_protocol DTOs. None of those declarations supplies a capability.

Private ResultEnvelope summaries carry identity/key receipts; model maintenance
uses envelope.details. Readiness must be control_ready=true/store_ready=false.
Pending/unknown results cannot masquerade as success. Even a committed receipt
alone does not authorize finish_maintenance or prove a restored serving owner.
The 180s long-control limit budgets four 30s key network calls or the model probe;
fixtures do not execute or prove those timeouts, keyring durability, CAS, rollback,
parent revocation, native model loading or full required/G1 acceptance.

## Frozen fivekeys and local-migration fixture extension

The 281-file baseline retains all 277 existing fixture bytes and assertions.
This extension adds 17 positive and 82 negative cases: 380 digest-bound files,
89 positive / 287 negative fixtures, including 303 private-host cases.
Only frozen control.key.fivekeys/complete and control.migration.profile/result
are added. Metadata-control drafts are not part of this contract.

Fivekeys uses the original O/key and intent fingerprint across private input/TOTP
continuations. An applied candidate stays Pending with verification_required=true;
only the exact target identity and a declared verified completion may be Committed.
Explicit v1 password="" is present; a missing/null password requests input.
The key_context/write_context fields are synthetic anchors, not grants or proof
that a live Runtime was verified. Private responses never authorize public progress
or ledger copies of inputs, TOTP or issued super passwords.

Migration binds its fixed tuple fingerprint, discovered source ID, safe account name,
final accounts path, namespace conversion and complete O/key marker before publication.
A legacy unbound marker may return AlreadyMigrated on the first profile request;
a result query stays Unknown and must not claim that marker for the original O.
This does not exercise or replace CLI handling of an acknowledged terminal response.

Node and Go recompute frozen fingerprints. Rust uses the real protocol DTOs and
checks the actual migration fingerprint preimage plus declared digest anchors;
it adds no hash/native dependency to the serde-only protocol crate. All source
paths and identities are synthetic anchors, not filesystem discovery evidence.
No fixture executes keyring, network, TOTP, native launch, CAS, rollback, owner
restoration or timeout behavior. These checks are not G1/native acceptance.

## Frozen private space-control extension

All original 380 bound files, fixture bytes and assertions remain unchanged.
The additive space extension binds 31 fixtures (7 positive / 24 negative), one
schema and one shared Rust consumer: 413 bound files in total. The original
89/287 fixture lists are retained; new lists live under extensions.space.

The closed methods are control.space.invite, control.space.join,
control.space.kick and control.space.result. Strict DTOs reject extra fields,
invalid UUID/O/key, business scope and mismatched method/intent. Private input
and result material must stay on the inherited channel. Invite codes must not
appear in public responses, ledger or progress; all fixture secrets are synthetic.
Unknown remains Unknown (a Fail envelope), never Committed. Pending uses Pending.
Only a terminal receipt may finish the declared maintenance phase; control_ready
is true and store_ready is false throughout this private operation.

The original O/key, source identity, installation root, source profile, intent
and fingerprint remain fixed on result queries. Join preserves the selected
source profile, binds the exact target account/session digest, and retains the
readonly invitation intent in readonly_team. Kick keeps every ordered partial
result. A result query declares no remote POST; confirmed revocations cannot be
rewritten and remote-pending/unknown rows cannot become success on recovery.
The all-members kick fixture accounts for remaining members, including unknown,
queued, absent and rejected rows; it does not generalize that count to single kick.

Node and Go recompute SHA-256 fingerprints, invitation digests and account IDs.
Rust deserializes the real protocol DTOs, checks the fingerprint preimage and
digest anchors, and rejects unknown fields without adding a hashing dependency.
Context, previous_kick and remote_posts are synthetic assertions, not runtime
observations. Schema/consumer success does not prove a consumed grant, parent
revocation, credential durability, remote idempotency, filesystem publication,
no network replay or native execution. Those still need exact-source CI and
private-control integration evidence. No localaccount/profile draft is included.
