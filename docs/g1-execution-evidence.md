# G1 execution evidence v2

This format is a contract, not a frozen candidate or an execution result.
Candidate schema 1 and required-execution/v1 reports are rejected. The registry
itself stays schema 1; every entry uses `report_schema: required-execution/v2`.
Changing that label does not implement a missing test or pass a gate.

## Frozen candidate

A candidate has `schema: 2`, `frozen: true`, `gate: G1`, and
`components.runtime`, `components.cli`, and `components.client2`.
Each component retains its exact `source_sha`, `version`, and nonempty
`artifacts.<target>` map. Each artifact retains the product
`archive_sha256` and `binary_sha256` and adds `native_sdk`.

For Runtime and CLI, `native_sdk` is an object with exactly these fields:

| Field | Meaning |
|---|---|
| `version` | Native Core SDK version, nonempty text |
| `manifest_sha256` | SHA-256 of the exact native SDK manifest bytes |
| `archive_sha256` | SHA-256 of the exact compressed native SDK archive bytes |

SDK digests are 64 lowercase hexadecimal characters. The component and target
are supplied by the enclosing map; they must not be inferred from another row.
Current Runtime dev.21 and CLI dev.20 identities can coexist. Archives and
manifests can differ across targets even when the SDK version is equal.

Client2 currently builds directly with Go and does not consume the native Core
SDK. Every Client2 artifact must contain `native_sdk: null`. Omitting the key
is invalid. This null says nothing about the Runtime that Client2 controls.

There is no global `sdk` field in v2; its presence is rejected. The Rust wrapper
crate (currently `respire_core_sdk` 2.0.0-dev.4) is a different dependency.
Its source/version and lock files are bound by the component source SHA.
A wrapper crate archive or version must not replace a native SDK identity.

## required-execution/v2 report

The report has numeric `schema: 2`. Existing bindings remain required:
`test_id`, `target`, `coverage`, `status: passed`, nonempty passed `cases`,
`source_sha`, `repository`, `run_id`, `run_attempt`, `candidate_sha256`,
`job_name`, `artifact_id`, and `artifact_name`.

The report adds `actual_native_sdk`. For Runtime and CLI it must have the same
three fields as the candidate and match
`components.<registry owner>.artifacts.<report target>.native_sdk` exactly.
Client2 must explicitly report null. A report-level `sdk` field is rejected.

The producer must derive the actual identity from the SDK used for that run:
read and hash the manifest and archive bytes, validate manifest version/target,
and bind the installed payload to the manifest and checked-out lock.
Copying candidate fields into `actual_native_sdk` is not verification.
The verifier compares identities; that comparison alone cannot prove that a
producer read or loaded the actual bytes.

Keep the exact candidate bytes. Hash those bytes, not reserialized JSON.
Upload raw evidence in its producing test job before creating the report bundle.
The verifier still requires the current source/run/attempt, a successful mapped
job, non-expired raw artifact identity and creation time inside that job,
all mapped cases including mandatory children, and every required target.
No frozen candidate means no passing execution report.

## Scope and current producer state

The two implemented CLI entries remain source tests. They do not satisfy
published-asset or eight-target native acceptance. Runtime 8, Client2 4, and
CLI 1 missing entries remain missing. No status, target, case, or reason is
changed by this format migration.

Raw source logs use a separate `evidence_class: source-raw` context with
`gate: not-evaluated`; their schema 1 is not an execution-report schema.
They must never be accepted as v1 or v2 passing reports.

The CLI producer and workflow now support candidate-bound source reports when
explicit manual inputs select the exact same-repository artifact/run and candidate
digest. The input artifact supplies candidate.json and the original sdk.tar.gz;
the producer verifies those bytes and the extracted SDK before source execution.
Existing SDK preparation still removes temporary archives, and cache hits alone
do not prove a fresh archive read/hash. Ordinary raw output cannot be promoted
after execution. This wiring has only synthetic local checks, not actual CI/G1
evidence; no final candidate report has been produced.

The downstream native aggregator source now accepts this v2 contract. Its pure
synthetic self-checks do not prove actual SDK byte use, a complete eight-target
producer, or real CI/native execution. No final candidate has passed G1.
