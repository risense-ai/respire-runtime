# Memory associations

Recall keeps its original ranked `details` array and appends bounded title-only
associations in a separate `related` array. Each association contains `id`,
`title`, `source_id` and `relation`: `new_version`, `old_version`, `see_also`,
`co_recall` or `neighbor`. Read bodies with `show`; titles are untrusted data.
The summary counts original hits and associations separately. An active
replacement is indicated by `superseded_by` on the recall detail row and a
`[superseded]` text marker. Replacement chains resolve to the newest live endpoint.

```sh
rsrs remember "Revised conclusion" --title "Current decision" --importance important --supersedes OLD_ID
rsrs remember "Related evidence" --title "Supporting evidence" --importance important --see-also ID_A,ID_B
rsrs recall "query" --titles --json
rsrs recall "query" --no-related --titles --json
```

Explicit relation flags imply an intentional new write, bypassing duplicate
proposals. Both flags reject diary memories and cannot be combined with
`--merge-ids`. IDs must resolve to live important entries. Targets are validated
before embedding or saving; the new entry and all reverse links commit together
or roll back together. Metadata-only reverse edits preserve Core index locators;
SQLite rebinds their source to the new ciphertext.

Fast and quality modes expand only final selected hits. Model selection still
receives only its existing query/title material. Core owns relation priority,
neighbor inference, exclusions, scope filtering and budgets. No vector,
intermediate cosine value, strategy threshold or selector plan is returned.
The main hit IDs and scores are unchanged by associations.

`--no-related` disables expansion and superseded hints for this request. The
Core compatibility environment switch `RSRS_RELATED=0` disables expansion
while retaining replacement warnings; process-environment changes require a
runtime restart by the host owner. Association settings are Core-owned.

Co-recall evidence is a local `recall_pairs` SQLite table, not synced content.
The first five final hit IDs form distinct unordered pairs; each pair increments
once per recall. Association IDs do not feed the statistics. CLI reuses the
existing bounded asynchronous statistics queue and its failure diagnostics.
An immediately repeated query may run before the queued statistics are saved.

## Data compatibility

Encrypted payloads add default-empty `supersedes`, `superseded_by` and array
`see_also` fields. Empty fields are omitted on serialization. Legacy ciphertext
remains readable; the server's ciphertext transport contract is unchanged.
The forward `supersedes` edge is authoritative. Reverse fields are hints:
cross-device LWW sync can temporarily split a multi-entry transaction. Core
derives active replacements from forward edges, resolves competing live writers
deterministically by timestamp and ID, and suppresses cyclic replacement claims.
Deleted and out-of-scope targets are not injected or used for warnings.

Import/share mint new IDs and remap only included relation targets. Sharing
omits external targets. Imports reject self-links, competing replacements and
cycles. Merge carries surviving links and rewrites references to the replacement
in the same transaction as child moves and tombstones; distinct external
replacement chains cannot be merged implicitly. Deletion retains encrypted
relations for restoration; inactive endpoints remain excluded from recall.

New relation writes require a Core SDK advertising `related_business`.
C ABI and request envelope version remain unchanged because symbols and calling
conventions are unchanged; the new operation is additive. Rust callers constructing
MemoryEntry/PayloadV2 literals must supply the three new fields.
The Rust protocol and binding use 2.0 development crate versions for this
struct-literal API change; their versions are independent of the binary SDK.
**Older writers may strip unknown payload fields when resealing. Upgrade every
writer before enabling relations on a shared library.** The opaque sync server
cannot enforce encrypted-payload field preservation. Automatic legacy-tailnote
backfill is not performed because prose references need review.

## SDK compatibility and validation

CLI requires association contract 1 in every target SDK. Use the exact manifest
and archive pins from the paired seven-platform SDK release. Preserve its
runtime libraries, license and third-party notices when packaging the CLI.

Use existing workspace tests and SDK native-caller checks. Compare retrieval
benchmarks with the same library/model and compare end-to-end answer quality
with associations enabled/disabled. A stable hit@5 measures the original ranking,
not the correctness or usefulness of added associations. Paid selector/provider
quality needs an explicitly authorized provider and evaluation corpus.
