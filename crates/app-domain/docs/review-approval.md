# Trusted review approval adapter

Source integration only. The Server bridge is not deployed or verified with real
WebAuthn here. The CLI command and local transaction path are implemented; new
metadata SDK and Dashboard integration are still unverified. No configured
authority returns `verification_authority_unavailable`.

The existing profile's `session.json` supplies `addr`, `user` and its existing
Server `token`. Explicit host configuration adds:

```json
{"review_authority":{"issuer":"https://memory.example.com","account_id":"00000000-0000-4000-8000-000000000001","owner":"alice"}}
```

This configuration is trusted host configuration, never a candidate/RPC field.
The issuer must exactly match the session endpoint (apart from a trailing slash)
and owner must match its user. This first adapter accepts a lowercase HTTPS DNS
origin without a port or path. It uses ureq's own URL parser and requires a
domain host after IPv4/IPv6 normalization, so numeric/octal/hex IP aliases are
also rejected. The original value must equal the parsed canonical origin;
credentials, explicit ports, paths, queries and fragments are rejected.
Redirects remain disabled.
It reuses the existing Bearer session and ureq transport; it does not create a
token, sign an assertion, unlock keys or transmit plaintext evidence/URK.
RP/origin, current account generation and active credential checks remain in the
Server's existing Passkey implementation. The receipt does not expose RP/origin
or credential material, so this adapter does not pretend to check those locally.

`ReviewAuthority::configured()` reads one profile snapshot. Approval input is only
`OpaqueApproval { event_id }` with unknown fields rejected. The host builds
`ReviewBinding { owner, local_library_id, id, record_revision,
expected_memory_revision, claim_digest, intent_digest }` from the authorized
candidate/Core preview. IDs are complete canonical UUIDs, revisions/digests use
`sha256:` plus 64 lowercase hex digits, and memory revision is 32 lowercase hex.
Dashboard must display that exact candidate's claim, scope, evidence and next
review date, then use this binding for Server `review/start` and fresh WebAuthn
`review/finish`. A prior unlock ceremony is not review approval. Only the returned
event ID is handed back; it must not replace the host's expected binding.

`verify_review_approval` first GETs the event at the configured issuer. It checks
purpose, configured account/owner, actor/event, all binding fields, expiry and
unconsumed/unrevoked status. It then POSTs the same binding to `review/consume`.
Only a matching, newly consumed receipt creates `TrustedApproval`. This type has
private fields, no public constructor, no Deserialize and no Clone. Ordinary CLI
JSON, TTY, loopback access, `source=human` and a local session token cannot create
it. HTTP/session/transport errors fail closed; there are no automatic retries.

The command owner must perform one CAS attempt with `TrustedApproval::commit_once`
and the original expected memory revision, after Core validates the candidate.
Any CAS/write/read-back failure must return saved=false and require a new user
confirmation. Consumption cannot be rolled back with the local transaction.
This adapter does not claim distributed atomicity. Do not cache or serialize a
TrustedApproval for later use, or run network/UI operations inside a SQLite write
transaction.

`resolve_confirmation(owner,id,record_revision,event_id,claim_digest)` GETs the
durable event and returns historical authority only for the matching current
account, owner, record and claim. It requires a consumed, unrevoked event. It does
not require the original library ID/CAS/intent or an unexpired submission window,
so other devices can revalidate a saved confirmation. It cannot produce a fresh
TrustedApproval. Map success to the internal Core trusted authority check, a
typed `verification_rejected` error to rejected, and
`verification_authority_unavailable` to unavailable. Root evidence checks remain
separate; do not manufacture available roots from this event.

`revoke` uses the existing authenticated `review/revoke` endpoint with an explicit
reason. Never manufacture a local revocation success after a failed request.
Network receipt lookup remains necessary on later fact reads; a synchronized
confirmed_by string alone supplies no authority.

Both trusted result types expose `authority_check()` as a Serialize-only,
privately constructed `VerifiedAuthorityProof`. Its exact Core input shape is
`{id,record_revision,event_id,claim_digest,confirmed_by,confirmed_at,outcome,roots}`.
The actor and timestamp come from the verified Server receipt, never the review
candidate or synchronized verification. Core must compare them exactly with the
verification being evaluated. `outcome` is trusted and `roots` is empty: the
Passkey event does not establish external evidence availability. The root
resolver must independently check authorized evidence before fact eligibility.
These proof values are internal request inputs, not public RPC parameters or
permanent authority caches. Each network request and the final confirm CAS check
the current profile, issuer/account/owner and session token again. Logout or a
profile/account change invalidates a cached adapter. Protected configuration and
real Server/WebAuthn integration remain unverified requirements.

## Review command and local transaction

```
rsrs review --due --json
rsrs review ID --draft --json
rsrs review ID --prepare --input JSON --json
rsrs review ID --confirm --input PREPARED_JSON --approval EVENT_UUID --json
rsrs review ID --revoke --reason TEXT --expected-memory-revision TOKEN --json
rsrs review ID --review-at UTC --expected-memory-revision TOKEN --json
rsrs review ID --clear review_at --expected-memory-revision TOKEN --json
rsrs review ID --history --limit 20 --json
```

All IDs are full canonical UUIDs. The paired metadata and supersession Core
capabilities are required before keys/store/model access. The pre-metadata SDK
fails explicitly. Read-only due/history do not require the new-format write gate.
Due returns `details.due=[{id,revision,due_reasons,reason_codes}]`. Core/network
failures cannot masquerade as an empty successful list. A missing/rejected
historical authority appears as an explicit authority diagnostic and unavailable
proof, allowing Core to report unverified due entries without trusting JSON.

Prepare reads the authorized owner's complete rows, tombstones, unavailable
heads and memory revision from `review_snapshot` in one SQLite read transaction.
It sends no model/kNN recall. Core supplies revisions, digests, authoritative
supersession and evidence evaluation. One UTC millisecond timestamp is reused
as evaluate now and request_scope.at. Fact version is unknown unless explicitly
provided, never the CLI version. Preview does not write verification or dates.

The default draft is only a proposed explicit user confirmation. It contains
the complete target entry, claim, scope, evidence, method, proposed date, binding
and prepared confirm input. Dashboard **must recompute the record revision and
display all semantic fields**: kind/title/content/summary/source_refs/valid_until/
artifact. Approval must explicitly cover the complete record and all compound
claims, not only an independently supplied claim string. Carrying entry in JSON
alone does not prove that display or semantic review occurred. That Dashboard
binding is a remaining release requirement; this adapter does not use substring
or model judgments to pretend it is satisfied. Plaintext stays local; Server
start/consume receive only the frozen binding.
The bridge and UI prototype have never been deployed/released. Complete-record
display is therefore a requirement of the initial review-confirm contract, not
a new version framework. Existing record/claim/intent digest encodings and the
seven binding fields are unchanged.

The concrete user root locator is `respire:user-claim:<target-full-id>`, with
revision equal to the target Core record_revision. Only an independently verified
Passkey event bound to the **same complete claim digest** can supply its available
root. Historical reads revalidate that Server event; the locator alone or stored
verification cannot supply availability. `user_claim_authority_check` creates
this deterministic root internally from the checked receipt. Memory dependencies
are evaluated by Core. Primary/run have no genuine host receipt/byte provider
yet and remain unavailable; those missing providers are unfinished requirements.

Confirm requires both expected revisions from prepare. It reopens the current
authorized snapshot and recomputes the Core binding, verifies/consumes approval,
then uses receipt actor/time in the candidate verification. Core reevaluates the
same view and now with checked history/root proofs and must return fact_eligible.
The host then seals the complete payload with deferred indexing and calls the
existing `commit_review` CAS transaction for payload/projection/history/outbox.
Any conflict requires a new prepare and approval, with no automatic retry.
The resident cache is cleared and the stored payload/history are read back
before saved=true. A post-commit verification failure reports fail, saved=false,
write_committed=true and readback_verified=false rather than claiming rollback.

Revoke checks the configured Server revocation response for an existing event
before clearing its local verification under CAS. A later local CAS failure does
not undo remote revocation. Date changes preserve verification. History is local
only and includes deleted targets within the current owner's authorized view.
Gate-off refuses new-format writes. Successful writes notify the existing index
and sync workers; this module does not start a runtime or load a model.
