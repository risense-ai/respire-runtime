# Process-local core configuration

Runtime dev.24 adds `core_config.validate`, `core_config.apply` and
`core_config.read`. The DTO source is `crates/protocol/src/core_config.rs`,
published as `respire_protocol` **2.0.0-dev.17**. Publish that crate before
merging hosts that consume its new types. Wire protocol remains **1**. Existing
host-control contracts keep their dev.16 shapes and semantics.

All methods use the authenticated existing `/api/rpc` transport. Supply the
current `scope` (`account_id`, `instance_id`, `generation`), an operation ID and
an idempotency key. `args` contains exactly one JSON string. Neither credentials
nor an open database nor model assets are required.

```json
{
  "schema_version": 1,
  "maintenance": null,
  "candidate": {
    "read_heat": false,
    "recall_fusion": {"fusion": "attention", "fusion_alpha": 0.3}
  },
  "expected_revision": 0
}
```

`apply` requires `candidate` and `expected_revision`. `validate` requires the
candidate and forbids an expected revision. `read` accepts neither field.
Both candidate keys are required. `read_heat: null` removes the explicit
per-query override; the paired Core default is true. `recall_fusion: null`
removes persistent overrides; its effective values are the existing defaults
plus this Runtime process's environment overrides. Objects use only the
existing fusion mode and numeric fields and their existing validation rules.
Validation and application use the same parameter resolution.

While host maintenance is Paused, supply the existing
`HostControlMaintenanceBinding` in `maintenance`. Runtime verifies the exact
marker digest, phase, coordinator, selected profile, CLI version and live
controller PID/birth. Without a marker, omit the binding or use null. The
binding is an additional constraint on authenticated HTTP, not a launch grant.
Stopping Runtime instances reject new configuration operations.

Successful `envelope.summary` has this shape; the outer response carries scope,
operation ID and idempotency key:

```json
{
  "state": "applied",
  "revision": 1,
  "candidate": {"read_heat": false, "recall_fusion": {"fusion": "attention", "fusion_alpha": 0.3}},
  "effective": {
    "read_heat": false,
    "recall_fusion": {
      "fusion": "attention", "fusion_alpha": 0.3, "fusion_beta": 0.25,
      "fusion_temperature": 1.0, "fusion_gate_recency": 0.02,
      "fusion_gate_recency_temporal": 1.0, "fusion_gate_hot": 0.1,
      "fusion_gate_tree": 0.02, "fusion_temporal_alpha": 0.15
    }
  },
  "capabilities": {"read_heat_contract": 1, "recall_fusion_contract": 1},
  "applies": "next_query"
}
```

States are `validated`, `applied` and `current` respectively. Revision starts at
zero for a profile in this process and increments on each successful apply.
An expected-revision mismatch leaves the current settings unchanged. Apply
replaces both settings together under the existing identity and exclusive
execution fences. Recall obtains a single snapshot and passes those resolved
parameters to Core. The receipt proves selection for subsequent queries; it
does not claim that a query or a model inference has already run.

The pinned SDK remains **2.0.0-dev.4**, unchanged. All three operations query
the actual linked Core's capabilities and require both contract versions to
equal 1. An unsupported SDK is an explicit error, never a default success.

`core_config_rejected` is a definite pre-application rejection. Malformed
payloads, invalid values, unsupported capabilities, stale maintenance binding
and revision conflicts all fail before the in-memory replacement.
`core_config_outcome_unknown` is not proof of non-application. Existing scope,
admission and idempotency error codes retain their meanings.

After a transport failure, call `runtime.result` with `args: [operation_id]`
and the original scope. Its summary state is `completed`, `failed`, `pending`
or `unknown`, and `response` contains the original response when retained.
Only a retained successful original response proves that operation applied;
only a retained `core_config_rejected` response proves it did not. Never replay
an unknown write or manufacture its receipt from a matching `read` result.
After restart the old instance scope is invalid and its in-memory receipts are
lost; the host must retain Unknown for the old transaction.

## Persistence and startup boundary

These methods never save agent.json, touch the database, access a keychain,
install assets or supervise processes. The host owns file validation, CAS,
maintenance and rollback. Saved, pending and applied are separate host states.
With no running owner, a host may save a strictly validated candidate as pending
without downloading or starting Runtime.

For compatibility, the pre-existing agent.json read/reload paths and private
setters remain in this release. Before the first explicit apply, reads and
queries use those existing paths. Therefore dev.24 does not remove all Runtime
access to host configuration. An explicit apply takes precedence for the current
profile until exit. Restart discards that state; hosts must supply their effective
candidate again and wait for an applied receipt before reporting it as applied.
Removing legacy paths is a separate audit, not part of this change.

## Verification

The existing feedback unit test exercises candidate validation, real linked SDK
capabilities, application, recall parameter selection, readback, revision
conflicts, invalid candidate rejection and null reset without Core test mode:

```text
cargo test --locked -p respire_app_domain --lib feedback::tests::defaults_are_off_and_old_sdk_cannot_silently_accept_enabled_feedback -- --exact --test-threads=1
cargo test --locked -p respire_commands --lib rpc_serve::tests:: -- --test-threads=1
cargo test --locked -p respire_protocol
```

These run in CI against the exact pinned SDK. They supplement, and do not replace,
native API checks on a candidate binary before publication or the full release
matrix against published bytes.

The same CI step builds the candidate binary and runs
`node scripts/smoke-runtime-release.mjs --core-config-candidate` without Core test
mode. This checks real HTTP validation/application/readback while keyless and
Paused, the SDK capability response, revision conflicts, exact-operation replay
and result lookup, and the absence of host configuration, database or asset writes.
Its report records the exact source commit and candidate binary hash. This is
pre-publication evidence, separate from the eight-platform public-asset checks.
