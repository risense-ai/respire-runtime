# App metadata lifecycle

The library gate defaults to off. `metadata_gate::enable(root, lock, account,
keys, deployment)` requires the matching library lock and the actual binary
capability `memory_metadata_contract=1`. It creates and validates a portable
snapshot before changing any gate keys. The receipt includes the real snapshot
manifest. A changed library revision leaves the gate unchanged.

`Deployment::Isolated` prohibits sync while enabled, and also after disabling
if contract 1 records remain. `ControlledWriters` requires explicit operator
attestation that every writer is upgraded, old clients are disconnected, and
offline writes are reconciled. These attestations and the local gate are not a
barrier against old clients. Deployment checks must establish those conditions
before using this mode. The App does not claim to establish them remotely.

New-format writes and controlled-writer sync reject an old Core binary.
Snapshot resume-sync, remote address changes and auto-sync enable use the same
isolation checks. Deletion remains possible with the gate off; restoring,
updating or reparenting a contract 1 record requires the gate and paired SDK.

`CreateReq.metadata` accepts candidate metadata and rejects verification.
`App::update_with_metadata` accepts `MetadataPatch`: outer `None` preserves a
field, `Some(None)` clears a nullable field, and `Some(value)` sets a value.
Source references use `Some(vec![])` to clear. The CLI must reject simultaneous
set and clear options before constructing this patch. Existing `App::update`
preserves all metadata. Updates retain the old verification; Core compares its
record revision with the current content. The App does not compute a second
canonical revision, so review_at changes do not enter any App digest.

`merge_entries_with_metadata` and `CreateReq.merge_metadata` carry explicit
final metadata overrides, including an explicit null artifact. Without an
override, a new-format merge requires one kind, clears summary and verification,
unions source references with matching revisions, combines required flags, and
keeps the earliest non-null expiration and review dates. Different artifacts
require an explicit final choice. The replacement never redirects source_refs
on external dependents. Ordinary relationship changes continue to use the
existing atomic merge transaction.

JSON and share import preserve candidate fields but discard incoming
verification. Unknown semantics reject rewrite instead of silently losing
fields. A content duplicate with different new metadata rejects the import.
Imported IDs are new IDs; source_refs keep their original full IDs and revisions
instead of guessing a new version. Unavailable original sources remain
unavailable. Known required source cycles reject writes.

Snapshots preserve the database, metadata projections, gate keys and existing
review history. Restore keeps the existing ownership, validation, rollback and
sync quarantine workflow. An old backup with the gate off cannot replace a
controlled-writer library; isolate the library and stop remote writes first.
Restoring a backup does not manufacture a new verification.

## CLI

`remember` and `update` accept `--summary`, `--source-refs`, `--valid-until`,
`--review-at` and `--artifact`. Each has a corresponding `--clear-*` option.
Setting and clearing the same field is a parse error. Omitted update fields
remain unchanged. Source references are a JSON array of full UUIDs, lowercase
SHA-256 revisions and explicit required booleans. Artifact is a JSON object;
`--clear-artifact` explicitly chooses null. Unknown fields reject input.

```text
rsrs metadata status --json
rsrs metadata enable
rsrs remember "candidate" --importance important --summary "short clue" --force
rsrs update <id> --clear-summary --review-at 2026-12-01T00:00:00.000Z
rsrs remember "combined" --merge-ids <id1,id2> --clear-artifact
rsrs metadata disable
```

Enabling defaults to isolated mode and requires the actual paired Core
capability, the library ownership lock and a verified recoverable snapshot.
The output contains the real backup manifest. Disabling preserves metadata,
history and the mode; it does not permit isolated sync or old-SDK rewrites.
Explicit `--direct` configuration does not start or stop a runtime and refuses
while a runtime is already active. Normal host configuration uses the existing
profile-change lifecycle. Client-only runtime requests cannot enable or disable
the gate.

For a synchronized deployment, an operator must first establish all controlled
writer conditions outside the CLI. Then use `metadata enable --mode
controlled_writers --deployment-review <file>`. The UTF-8 JSON file must have
exactly these non-empty string fields:

```json
{
  "operator": "person or team responsible for the deployment review",
  "upgraded_writers": "writer inventory and how paired versions were checked",
  "disconnected_old_clients": "how old clients and copies lost access",
  "reconciled_offline_writes": "how pending offline branches were reconciled"
}
```

This file is an operator declaration, not authentication or a server-side access
barrier. The response labels it operator_attestation_only and explicitly states
old_client_access_enforced=false. A plain enable flag cannot prove that old
writers have stopped. Keep the review and returned backup receipt with the
deployment evidence.

Existing writes without new metadata remain contract 0. Explicit metadata or a
new kind creates contract 1, with no verification. New kinds are hypothesis,
reflection and self. Explicit candidate metadata creates a separate entry in
concise diary mode; it does not silently replace the daily track's metadata.
For merge, omitted type inherits the first source's kind and sources must share
that kind. The actual final metadata is returned in the result, including any
explicit override or clear.

New-format successful write summaries contain saved, memory_contract,
record_revision and metadata. Core computes the revision before commit; a
merge uses the existing transaction for its final validation. A candidate with
no verification reports unverified. A preserved verification reports
unavailable with evidence_evaluated=false until a host evidence evaluation;
the write receipt does not upgrade it to a fact. CLI update retains its existing
source CAS and deferred-index reuse, applying the same App MetadataPatch rules.

The gate is off by default in development builds too. CLI capabilities advertise
the existence of flags separately from the binary SDK's actual capability.
An old SDK explicitly refuses new-format requests; it is not a positive
metadata integration result. Review approval remains a separate command flow.
Queries need the Core evidence context. The target fact's version belongs in
request_scope.version; unknown is null, not the CLI/Core package version.
