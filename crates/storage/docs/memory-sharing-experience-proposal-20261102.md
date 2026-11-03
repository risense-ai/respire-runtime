# Memory sharing and experience exchange -- design proposal (2026-11-02)

English summary: This proposal maps GitSwarm (arXiv:2610.04862) onto Respire's existing
`share` / `share-import` surface. The transferable idea is not "share text and agents get
stronger"; it is a provenance-carrying, status-aware import: keep the origin entry, separate
the structural parent from declared semantic dependencies, keep declared / observed / outcome
evidence apart, retain failed paths as scoped negative knowledge, and gate publication without
treating publication as correctness. Current v1 exports plaintext content plus metadata,
unknown fields and internal supersession/cross-reference links. Import validates metadata,
strips sender verification and applies existing write/source/sync gates, but does not establish
an authenticated cross-library origin or share-specific trust/revocation protocol. Successful
imports mint fresh local IDs; semantic conflict refusal is not origin-based idempotence.
Status: design proposal, not implemented. Facts below are pinned to `respire-cli` main
`0f6bf9ac30f8e93a12f669c7495f0ada6689ca25` (published CLI DEV6, Core SDK dev.16).
This PR changes documentation only: no v2 importer, commands, quarantine, trust upgrade,
revocation or read-heat behavior is implemented, and no section-10 experiment has been run.

> Verdict: worth borrowing, but borrow only "origin, edges, layered evidence, negative
> knowledge, publication gate" -- not the Git repository, multi-agent scheduling, voting or
> "ancestor coverage equals improvement". Today `share/share-import` is closer to "export a text
> bundle" than to "share experience". The MVP must fix correctness and safety first, and only
> then talk about experience cards and effect measurements.

## 0. One-line conclusion

What is genuinely valuable in GitSwarm is not "shared memory makes an agent stronger" but that it
turns the reasoning process into a **durable, branchable, attributable contribution graph** and
splits "what was declared as used / what was actually used / what the final result inherited" into
three evidence layers. respire should upgrade "sharing" from **copying text** to a **controlled
import that carries origin and status**, without turning itself into Git or a multi-agent runtime.

## 1. Paper mechanism and evidence boundary

Paper: [GitSwarm: Decentralized Compounding Inference, v1](https://arxiv.org/html/2610.04862v1)
(arXiv:2610.04862v1). The paper's results are not a capability, schedule or policy authorization
for this product.

Borrowable mechanisms:

1. **Memory = contribution ledger**: a memory is not just a body; it carries a revision, parent,
   branch, author and "who it referenced".
2. **Structural parent vs cross-branch semantic dependency are separate**: `parent` records the
   starting state and `informed_by` records a cross-branch borrow; the latter is a declaration,
   not causation.
3. **The three reuse-evidence layers are not interchangeable**:
   - declared dependency (what was claimed to be referenced)
   - trajectory observation (what was actually opened/executed/adapted)
   - final-result ancestry (what the final answer inherited)
4. **Failures and rejected paths are persisted too**: failed results flow back and can later be
   cited, compared and rejected.
5. **Three states: committed/nominated/abandoned**: only a contribution that passes the
   publication check is published; a nomination is a preference signal, not proof of correctness.
6. **Distributed exploration plus centralized publication arbitration**: contribution and
   exploration can be distributed, while scheduling, isolation, the publication check and the
   final choice stay centralized.
7. **Cost accounting**: the larger the history, the greater the check tokens, duplicated work and
   abandonment cost; an agent only selectively checks part of the history.
8. **Independent verification boundary**: passing the publication check is not correctness; another
   agent having said it is not a fact; the authors admit no causal ablation was done.

Evidence boundary (must not become a respire promise):

- ProgramBench 79.4% and IMOProofBench 30/30 are for a specific subset, budget, model and single
  run, and some comparisons are not compute-equal.
- The 82-93% ancestor coverage applies to ProgramBench only; IMOProofBench is 21.3-33.0%.
- The hand-built tasks only prove "less duplicated discovery/traversal/investigation cost", not a
  higher score on the main evaluation.
- The scheduling comparison covers only 9 tasks and 3 seeds, and the authors explicitly do not
  establish statistical equivalence.
- The conclusions are correlational observations, not causal proof that "persisted memory causes
  improvement".

## 2. Mapping onto respire

| Paper mechanism | respire today | Borrowing approach | Verdict |
| --- | --- | --- | --- |
| Contribution ledger | Causal tree, internal supersession/`see_also`, share also carries full metadata and unknown extensions; no authenticated cross-library origin | A share bundle carries origin, edges, status and an evidence summary | Borrow, reduced |
| parent vs informed_by | `parent` is causal; `see_also` is symmetric; `source_refs` are verification references | Keep the existing symmetric `see_also` and the source-reference semantics; if `informed_by` is genuinely needed, define a separate versioned directed relation and never silently reinterpret old edges | Revise |
| Three evidence layers | `query-log`, `run-log` and `history` each exist | Produce audit reports only; never synthesize heat and never use it for ranking | Borrow the principle |
| Failure trails | `run-log` has fail/no_effect/confounded | Negative knowledge carries a scope, stays out of positive recall by default and acts as a warning on a matching scenario | Borrow, change semantics |
| Three-state gate | `share-import` has a candidate bill and `--go` | Persist attach/merge/reject as three states, with reject keeping a reason | Borrow, implement first |
| Publication arbitration | `share` emits a plaintext prompt containing body and metadata; import already has metadata gates | Propose an extra review; space encryption is not identity authentication and does not retract plaintext | Borrow |
| Cost accounting | No share cost statistics | Record bundle size, import duplication rate, recall tokens and revocation rate | Borrow |
| Independent verification | Import strips verification; there is no share-specific origin/trust isolation protocol | Add a local origin marker; never upgrade trust merely by importing | Must borrow |

Not borrowed:

- Do not turn respire into a Git repository: single writer, ciphertext storage, and diff/merge
  cannot see plaintext; borrow the edge semantics only.
- Do not introduce multi-agent scheduling, concurrent working copies or nomination voting: personal
  memory has no swarm.
- Do not adjust `read_heat` because usage was observed: observation is not causation; the code
  currently defaults to true. This proposal has no verifiable "off by default" product decision and
  makes no behaviour change on that basis.
- Do not treat ancestor coverage as a capability improvement and do not market "sharing makes the
  agent stronger".
- Do not treat `--go` as a security boundary: imported content is recalled and injected into
  context and must be isolated.

## 3. Unit of sharing: memory vs experience

- **Memory (facts)**: facts about a user/project/environment, suited to small, on-demand sharing;
  high privacy risk, not shared by default.
- **Experience (a reusable practice)**: a conditional proposition, `unverified` by default, never
  treated as a fact; better suited to cross-project reuse.

Experience card MVP fields (only 4 required):

- `trigger`: under what conditions it applies
- `action`: what was done
- `boundary`: where it does not apply / version / environment
- `outcome`: `ok | fail | confounded | no_effect` (reusing the four run-log values)

Later additions: `evidence` (run-log / source_refs), `counter` (known failure paths),
`task_signature`, `valid_until`, `authored_by/at`. A card should hang as its own node on the causal
tree, not be stuffed into tags.

## 4. Share bundle manifest v2 (proposed format, unsupported by the current CLI)

```json
{
  "v": 2,
  "bundle_id": "uuidv7",
  "created_at": "ISO-8601",
  "author": {"user": "...", "device": "..."},
  "scope": "project",
  "root": "source-root-id",
  "origin_namespace": {"issuer": "claimed-issuer", "library": "source-library"},
  "digest_scheme": "rfc8785-jcs-sha256-v2",
  "items_digest": "<canonical-manifest-sha256>",
  "enc": "none",
  "items": [
    {
      "origin_entry_id": "...",
      "origin_revision": "...",
      "parent_id": "...",
      "title": "...",
      "content": "...",
      "kind": "...",
      "tags": ["..."],
      "importance": "important",
      "declared_status": "unverified",
      "edges": [
        {"kind": "informed_by", "to": "origin-entry-id", "confidence": "declared"}
      ]
    }
  ],
  "evidence": {"run_logs": [], "source_refs": []},
  "cost": {"items": 0, "tokens_est": 0, "read_before_write": 0}
}
```

Principles:

- The bundle carries only what a decision needs: title, boundary, status, evidence summary and
  cost; the body can be expanded on demand and is not stuffed into the prompt in full by default.
- A new local UUID can be generated independently, but the origin key must be
  `(issuer, library, entry_id, revision)`: a cross-library-collidable entry UUID is not enough, and a
  local new ID must never overwrite the original declaration.
- The proposed digest uses [RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785) UTF-8 canonical
  serialization. It covers the decrypted logical manifest (version, namespace, root, items/revisions,
  edges) minus `items_digest` itself; the transport envelope's nonce/ciphertext is not part of that
  logical digest. Duplicate object keys and invalid Unicode/numbers are rejected; array order is
  preserved and participates in the hash, with no extra Unicode normalization. A versioned scheme
  must be frozen with cross-language vectors before implementation.
- A different digest for the same origin revision is an explicit conflict and must not be
  overwritten or silently deduplicated; same-name IDs from different issuers/libraries are not
  merged. A digest provides content integrity/equality, not source authenticity; `author`, `device`
  and the issuer string are all just declarations. Authenticating an issuer needs a separate key
  binding, signing/verification, authorization and revocation protocol, and an unauthenticated
  origin stays unverified.
- `enc=none` still exposes the body and metadata; a space shared key is only part of
  confidentiality/access control, proves no author identity and cannot retract plaintext already
  obtained. The `space-v1` envelope is an ability still to be designed and must not be presented as
  the existing share encryption format.
- The in-bundle `declared_status`, `evidence`, `verification` and procedural instructions are all
  external declarations and must never become local verification, execution authorization or a
  higher instruction. Keep the current principle of stripping sender verification on import; local
  review must produce independent evidence bound to the record revision/scope.
- The current prefix `1MEMSHARE1:` accepts payload `v=1` and rejects an unsupported version. A
  future v2 needs its own version negotiation and v1 compatibility/degradation rules; a legacy v1
  without an authenticated origin must not have an origin fabricated or v2 trust granted secretly.
- A future importer must bound encoding, compressed/decompressed bytes, item count, body/field size
  and graph complexity before allocating/unpacking and writing; it must validate duplicate IDs,
  root/parent chains, cycles, dangling edges, cross-namespace references and content conflicts
  before mutating. The current decoder's `read_to_end` is not an implementation of those bounds.

## 5. Import decision and the trust state machine

Three states:

1. **attach**: hang it on an existing same-topic node as evidence/a sub-experience; keep the origin.
2. **merge**: only for the same kind with a high trigger overlap; after merging both origins are
   kept and it remains revertible.
3. **reject**: write no body, only an import receipt and the reason (duplicate/not applicable/
   privacy/low quality).

State machine:

```
import -> external_untrusted + unverified + active
  |- attach -> attached (still external_untrusted)
  |- local reproduction (same task/env, >=2 ok, 0 fail) -> corroborated
  |- explicit, auditable local review by the user -> local_reviewed (scope-limited, grants no execution permission)
  |- expired -> needs_review
  |- source revoked -> source_revoked (stop recalling, do not delete the row)
```

Constraints:

- None of the state machine above is implemented. Trust never rises because the author is a
  colleague, the entry is widely cited, it is recalled often, the bundle claims its own
  status/evidence, or it was imported once. Import must not silently raise local trust or
  auto-execute commands in an entry.
- "corroborated" needs local run-log evidence; without task_id/env_hash only the count and the most
  recent status are shown, no trusted label is granted automatically, and a reproduction count never
  becomes an authorization.
- External content does not take part in ranking weights by default; it is only labelled and
  filtered.

## 6. Negative knowledge

- `fail/no_effect/confounded` does not mean "this experience is false" but "unusable/undecided
  within this boundary".
- Store `outcome + scope + evidence`, keep it out of positive recall by default, and return it as a
  warning when a query matches the same task/env.
- Do not mix it into `kind`; expressing it as `status=refuted` is not recommended, to avoid breaking
  the existing kind/status filters.
- The proposed `share-revoke` first defines receiver-side local suppression: mark a namespaced
  origin, mark downstream entries as needing review and suppress recall under an explicit policy.
  Propagating a revocation needs an authenticated issuer/receipt/offline rule; it can never delete
  another party's offline copy, screenshot, backup or already decrypted history, and must not claim
  to retract knowledge already obtained. The command does not exist yet.

## 7. Three evidence layers and metrics

Audit only, never ranking:

1. **Declaration layer**: how many imported items carry an origin / informed_by.
2. **Observation layer**: how often and how recently they were actually used by `recall`, `show` and
   `run-log`.
3. **Outcome layer**: whether a final `run-log ok` or a later memory's `informed_by` traces back to
   that bundle.

Supporting metrics: bundle size, import duplication rate, mis-attachment rate, revocation rate,
recall tokens, expiry rate.
It is forbidden to write "was recalled" as "was useful" or "ancestor relation" as "caused success".

## 8. Current capability and confirmed gaps (pinned source facts)

All CLI files below point at main `0f6bf9ac30f8e93a12f669c7495f0ada6689ca25`; symbols/fields are
authoritative and proposed fields must not be read as the current protocol.

- **v1 export scope**: [`ShareItem` / `items_from`](https://github.com/risense-ai/respire-cli/blob/0f6bf9ac30f8e93a12f669c7495f0ada6689ca25/crates/app/src/share.rs) contain the body, title, kind/tags, timestamps and the string `importance`, and flatten the full `MemoryMeta` plus `unknown_fields`. The metadata may carry `source_refs`, `artifact`, validity/review periods and `verification`; the export also carries the subtree-internal `supersedes`, `superseded_by` and `see_also`, while external structural parents/relations are truncated. `source_user`/`device` are only unauthenticated declarations, not a durable cross-library origin identity. `1MEMSHARE1:` plus base64(gzip(JSON)) is a plaintext encoding, not encryption; there is no share-specific redaction review. A privacy check must cover the body and every metadata/unknown field/evidence reference/repo path, not just the text.
- **Existing import protection**: [`import_share_payload`](https://github.com/risense-ai/respire-cli/blob/0f6bf9ac30f8e93a12f669c7495f0ada6689ca25/crates/app/src/service.rs) parses kind/importance, validates metadata, mints a new local ID, rebuilds the parent chain and remaps supersession/`see_also`, and explicitly clears the sender's `verification`; before committing it goes through `metadata_gate::ensure_write` / `ensure_sources`, then uses a batch import after sealing. It must not be described as "no validation at all". These checks are not authentication of the sharer, idempotent import or a share-specific quarantine.
- **Confirmed gaps**: without `--parent` and without `--force` it runs a semantic conflict check and can refuse, while an explicit `--parent` skips that check; it is therefore wrong to claim every repeated import must succeed. A successful repeated import still mints a new local ID, and `duplicates: 0` does not mean origin/digest deduplication happened. The share-import merge path only prints a hint for a later manual merge and implements no automatic merge; `--title` changes `payload.root_title`/the candidate bill rather than the per-item stored title. There is no share-specific origin list or revocation protocol.
- **Metadata and sync**: [`MemoryMeta`](https://github.com/risense-ai/respire-cli/blob/0f6bf9ac30f8e93a12f669c7495f0ada6689ca25/crates/protocol/src/metadata.rs) already has validity, source references, artifact and verification, so it must not be lumped together with the proposed share-specific trust/revocation state as "completely stateless". [`MemoryEngine::seal` / `hydrate_local`](https://github.com/risense-ai/respire-cli/blob/0f6bf9ac30f8e93a12f669c7495f0ada6689ca25/crates/crypto/src/engine.rs) keep the record/metadata/unknown extensions in the encrypted payload, and plaintext local columns are not the sync content. A successful import can sync **sealed ciphertext** when autosync/remote configuration allows; [`metadata_gate`](https://github.com/risense-ai/respire-cli/blob/0f6bf9ac30f8e93a12f669c7495f0ada6689ca25/crates/app/src/metadata_gate.rs) in an isolated deployment can block a store carrying that metadata from syncing. The decryption-capable receiver scope still has to be reviewed; a local origin column alone is lost after a machine change/hydration/LWW and cannot replace a versioned encrypted origin protocol.
- **space boundary**: the existing space account/key/data-dir isolation does not amount to sharer signature authentication; removing a member cannot retract keys already obtained, offline copies or decrypted history. The cross-library origin revocation/propagation proposed here is not implemented.
- **Recall and read heat**: metadata verification/validity semantics already exist, but the share origin/quarantine/trust filter protocol proposed here is not implemented. `read_heat` is true in Core's `QuerySettings::default()` and the CLI uses it when the query settings do not specify otherwise. There is no verifiable "off by default" decision, so this PR does not adjust read counting, heat, ranking or origin trust. An effect experiment must record the actual settings, and changing a default needs separate authorization and regression.

## 9. Candidate implementation path (none implemented; not a commitment for this release)

### P0: correctness and safety (needs separate review, authorization and scheduling)

1. Fix `share-import`: a real merge or remove the merge hint; idempotent dedup by
   `items_digest`/origin; `--parent` must go through the conflict check; `--title` actually takes
   effect; reject writes an import receipt; define an auditable local compensation/rollback
   boundary and never promise to retract data another party already copied.
2. Isolate external content: while keeping the existing metadata gates/verification clearing, design
   an explicit local quarantine/review and sync policy; the proposed `external_untrusted` is not an
   existing import label. A default sync policy change needs separate confirmation; never execute
   procedural content automatically.
3. `share-list` + `share-revoke`: list bundle/entry/status; revocation marks the origin and marks
   `informed_by` descendants `source_revoked`; never physically delete rows, keep the audit.
4. Put the origin into the encrypted payload, not only into a local plaintext column, so it stays
   traceable after sync.

### P1: experience sharing (candidate design, effort not estimated)

5. manifest v2: bundle_id, author, scope, items_digest, edges, evidence, cost; keep v1 decode
   compatibility.
6. The four experience-card fields in the share-import candidate bill; the attach/merge/reject three
   states.
7. Proposed `share-review`: a privacy/conflict review and size check over the body, metadata/unknown
   fields, source_refs, artifact and verification; define false-positive/false-negative rates and the
   available scanning ability first, and do not claim automatic credential scanning exists today.
   Report only by default, never write.

### P2: measurement (candidate design, effort not estimated)

8. `share-report`: declaration/observation/outcome counts plus cost; read-only.
9. The E1/E2/E3 gates (below).

### Change surface and dependencies (the whole protocol cannot ship as "three files, one table, two commands")

- share.rs/service.rs/main.rs are only entry points, not a sufficient change surface for encrypted
  provenance, authentication, revocation, quarantine and recall isolation.
- Before implementing, inventory protocol/schema, encryption seal/hydrate and legacy writer
  retention, storage migration and atomic commit/receipt, sync compatibility, CLI/MCP/HTTP exposure
  and permissions, origin and relation validation, recall filtering and acceptance. Core/SDK changes
  only where the contract genuinely needs them; a documentation fact correction needs no new Core.
- If a local index such as `share_origins` is used, the authoritative origin must still live in the
  encrypted payload under version/compatibility constraints; adding a plaintext table alone is not
  enough.
- All of `share-list`, `share-revoke`, `share-review`, `share-report`, manifest v2 and the new trust
  states are unimplemented. This PR is not a product authorization to build the whole platform and
  changes no existing API, storage, default sync or read_heat.

## 10. Acceptance experiments (none executed; these are gate conditions)

- **E1 idempotence and migration**: import the same bundle twice, plus a machine-change sync. Pass:
  0 duplicate rows, 100% origin retention, revertible, 0 `--parent` bypasses.
- **E2 import decision**: 20 blind bundles (10 true duplicates, 10 new topics). Pass: merge precision
  >= 0.9, mis-attachment <= 5%; the sample source and labelling scheme must be defined first. Until
  merge is implemented this metric cannot be verified.
- **E3 sharing effect**: 30 tasks (15 answerable, 15 expired), comparing "no share / with markers /
  without markers" and crossing `read_heat`. Metrics: accuracy, harmful adoption, injection success,
  tokens. Without a causal ablation only differences can be reported, never an improvement claim.

## 11. Risk list

1. **LWW washes away the origin**: keeping the origin only in a local column loses it on sync or a
   machine change; it must go into the encrypted payload.
2. **Sync receiver scope**: an existing import is sealed into ciphertext first, and autosync/remote
   settings plus the metadata isolated gate decide whether it syncs; it is not a direct upload of the
   share plaintext bundle. Origin/sensitive metadata can still be seen by a receiver that can
   decrypt, so a later quarantine/sync policy needs explicit authorization.
3. **Origin declarations are not namespace-persisted**: import normalizes
   `user/computer/project/emotion` and has no durable issuer/library/entry/revision attribution
   protocol; however, existing metadata, unknown fields and internal relations are not all lost. The
   origin should be separated from local identity and must never claim to be authenticated.
4. **prompt injection / memory poisoning**: external bodies are recalled and injected; `--go` is not
   a security boundary; `external_untrusted` isolation, delimiter markers and human confirmation are
   needed.
5. **`--parent` bypasses the conflict check**: a new bundle can be hard-attached to a wrong parent;
   the conflict check must be unified.
6. **Repeated import**: a successful import mints a new ID and there is no origin/digest idempotent
   receipt yet; a semantic conflict without an explicit parent/force can block a repeat, but that
   refusal layer is not a substitute for an idempotency protocol.
7. **Trust label illusion**: without a task_id/baseline in run-log, `trusted` is
   not trustworthy; the MVP only shows counts and the latest status.
8. **read_heat experiment control**: the code defaults to true and this proposal has no decision to
   change the default. An experiment should record/control that setting explicitly and must not
   invent an "off by default" promise or use this proposal to change ranking behaviour.
9. **Over-designing the experience card**: the MVP keeps only trigger/action/boundary/outcome; the
   rest comes later.

## 12. If only three things get done

1. **Fix share-import correctness and safety first**: idempotence, a real merge or remove the hint,
   the `--parent` check, external isolation, revocation.
2. **Namespaced origin into ciphertext plus the proposed list/local revocation**: make sharing and
   receiver-side suppression inspectable, without promising deletion of offline copies or that the
   author identity is authenticated.
3. **Four experience-card fields plus three-state import**: turn "share text" into "share a reusable
   practice", `unverified` by default.

## 13. Open items

- Whether to change the `read_heat` default is an independent product decision; it currently defaults
  to true and this proposal keeps the status quo, defining experiment control rather than assuming a
  change.
- Is there a genuine independent need for `informed_by`? The existing symmetric `see_also` semantics
  stay unchanged; a new directed edge needs an explicit contract and writer compatibility, never a
  silent reuse of an old field.
- Must `share_origins` sync across devices? Recommended: yes, otherwise the origin and revocation
  chain break on a machine change.
- Does the trust level need `trusted`? Before independent reproduction exists, keep only
  `unverified/corroborated/source_revoked`.
- Identity/issuer authentication, namespace and revision lifecycle, JCS cross-language
  vectors/collision conflicts, v1 compatibility and revocation propagation all await detailed
  review. Nothing is scheduled and no delivery is committed on the earlier person-day estimate.
