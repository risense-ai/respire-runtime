# Release validation

Job inventories are read in complete ten-job pages to keep GitHub API responses
bounded. Publication readers retry a transient HTTP 5xx job-list read once;
artifact waiters allow at most two consecutive failed status reads. Authentication
errors, incomplete validation and failed producers still stop publication.
The reviewed API route inventory is pinned to Server 1.0.1 source
`fb370b2a49193db64d2530c9af9a2a3895fd231c`; all 66 baseline routes and existing
vault assertions remain required. Migration fixtures require legacy tombstones
and live records to be re-encrypted before cloud synchronization. After an
accepted deletion synchronizes, the same tombstone IDs and deletion flags must
remain with empty ciphertext, nonce and encrypted embedding, matching Server
1.0.1. Active records still require independent decryption after a fresh login.

New releases target Windows x64 and ARM64, Linux x64 and ARM64 (GNU and musl), and macOS ARM64 and Intel x64.
Windows ARM64 builds and migration checks require native ARM64 runners. Historical
published assets remain available. Intel macOS uses ORT API 20 and bundled ORT 1.20.1, with macOS 13.4 as the minimum supported version. Intel releases before 1.0.20 have no upgrade baseline; first-platform reports identify that absence explicitly while real CPU inference remains mandatory.
The paired Core SDK still validates its own eight-target compatibility contract.
All eight CLI SDK pins bind the same reviewed SDK version and its per-target digests in
`sdk/core-sdk.lock.json`.

Normal DEV and stable publication use the `critical` validation profile. It
requires exact-source workspace tests, CLI 90% coverage and packaging/workflow/
fixture contracts across all three source CI lanes, eight Release builds, and
eight native startup/real CPU inference/latest applicable formal-stable upgrade
checks. API regression, pinned SDK digests, and consistent artifacts for all
nine npm packages remain required: eight scoped platform packages and the
`rsrs-cli` launcher. The parent Release submits only the eight platform packages;
`npm-alias.yml` submits the exact launcher tarball validated by the parent using
its existing package-specific Trusted Publisher. Parent acceptance binds the
launcher digest separately, without claiming its npm acceptance. Byte, source, dependency, receipt and immutable-version fence
checks still apply before submission.

The `full` profile additionally requires all historical upgrades, long resident
stress, six cloud sweeps, three native migration fixtures and three migration
join gates. It retains the API gate and all critical build/source protections.
Full regression runs on the scheduled/manual path; an ordinary critical release
does not claim those checks ran. `full_regression_before_publish=true` explicitly
forces the full profile for compatibility with older callers.
Manual Release exposes `validation_profile=critical|full`, defaulting to
`critical`; the legacy full flag overrides that selection. The daily
`release-full-regression.yml` entry dispatches Release with `publish=false`,
`validation_profile=full` and the legacy full flag. Its dispatch success is not
regression success; use the dispatched run's actual full results and receipts.

`rsrs-cli` is the primary public npm install entry. Protocol 2 separates two
states; neither state can substitute for the other:

- **accepted**: all eight platform packages and the direct `rsrs-cli` launcher
  have explicit successful npm submission acknowledgements, or their existing
  exact public bytes have been confirmed. Local pack SHA-512/SHA-1, package
  versions and exact dependencies remain mandatory. The launcher follows the
  platform acknowledgements and their parent receipt. The Release
  becomes public only after the exact alias publisher job succeeds, all required
  acknowledgements exist, and the source attempt, tag and twenty-one assets match.
- **verified**: the separate `Verify public npm publication` workflow confirms
  public metadata, install-index resolution and tarball digests, then performs
  isolated Linux x64 GNU and native Linux ARM64 GNU/musl public installs. They check launcher/native
  versions, the native binary hash, `--version` and `--help`. This proves the
  three Linux routes only; it does not claim public installation on other systems.

`scoped-accepted-RUN-ATTEMPT` and `alias-accepted-RUN-ATTEMPT-CHILD-ATTEMPT`
receipts bind the repository, workflow, selected source SHA (which may differ
from the dispatch workflow SHA), exact attempts, version, channel, release ID,
local package digests, assets and actual npm acknowledgements. An accepted
receipt never contains fabricated registry metadata or installation evidence.
The parent `publication-accepted` report explicitly leaves public verification
pending. The independent `publication-verified` report records actual content
and installation proof with its completion time.

`npm-alias.yml` retains its Trusted Publishing identity and permissions and
starts on Release `in_progress`. Its read-only early wait holds no publication
lock or OIDC permission. Its writer checks out the receipt's selected source,
uses the existing alias lock and never waits for the parent to complete. The
parent observes the exact successful publisher job and durable accepted receipt,
not the whole child workflow or background verifier. Background verification
starts after parent completion, including a failure after publication, has read-only permissions, holds no
publication lock and can validate an immutable completed source attempt. All
write operations still require the active current source attempt. A failed parent can only produce a verified report if its exact public Release, complete accepted receipts and public content/install all validate; it still cannot authorize artifact cleanup. Protocol 1
and its integrated installation barrier remain for historical recovery.

A successful npm process must have exit code zero, no spawn error and no signal.
Only that explicit acceptance avoids propagation waiting. Failed or uncertain
submissions are reconciled by bounded read-only content verification; they are
never blindly repeated. Submission journals preserve intent before the write
and each acknowledgement afterward. A rerun must reconcile interrupted earlier
attempts; missing evidence fails closed. Public read failures cannot be reported
as acceptance. Existing matching immutable versions are skipped without tag
changes. DEV uses `dev`, stable uses `latest`, and tag rollback remains forbidden.
A failed required package prevents overall publication success; partial accepted
versions remain immutable and the Release remains draft.

The user-confirmed target is **five minutes from commit/CI trigger or an explicit
release trigger to successful npm submission of every required package**. Count
the applicable source CI, runner queues, build, validation, packaging and npm
submission work. Do not start the clock at publication-ready or hide preparation
and validation before it. Report those earlier stages separately when they ran
before a manual release trigger; a promotion-only result does not prove this
end-to-end target.

Normal direct-launcher success requires all eight exact-package npm acknowledgements: exit code
zero, no spawn error and no signal. It does not wait for the npm web page, search,
registry/install-index propagation or public installation. GitHub Release
finalization and the independent public verifier retain their own results and
timings; they do not extend the npm-ACK SLA. A failed or unknown submission remains
an exception, not a successful ACK. Source, local bytes, dependencies, active
attempts, journals, immutable-version ownership and fences remain mandatory.

Use checkable service events for timing bounds and retain each raw ACK timestamp.
If clocks disagree, report the affected duration as unavailable rather than
compensating timestamps or claiming a five-minute result. Only exact merged
source/version/platform/toolchain/SDK-lock/content-bound validation may be reused;
different or untrusted PR artifacts cannot authorize publication.

Baseline `41292330463/1` took **2060.115 seconds** from trigger to nine ACKs and
**248.115 seconds** from validation-ready to nine ACKs. Its later public install
verification is outside the success boundary. Five-minute end-to-end performance
is a target, **not an achieved result**; code changes and simulated concurrency
tests alone do not establish it.

To resume that same version, rerun the failed publication job only while its
original plan, build artifacts and required receipts remain available within the
one-day retention window. A fresh run attempt requires fresh ready/alias receipts;
stale attempts cannot finish publication. Once the evidence expires, stop and
diagnose the remaining draft and npm state before separately authorized recovery;
never substitute a version string or successful run status for missing evidence.
Do not use a full workflow rerun as same-version recovery: rerunning `plan` can allocate a different DEV version.
Waits are bounded (four hours for initial scoped readiness, fifteen minutes for
a set of public tarball checks, forty-five minutes for matching alias success).
A failed or timed-out barrier never makes a draft public. The workflow-run event
and OIDC handoff require a real release after deployment to validate end to end;
local tests simulate the registry and validate workflow/receipt contracts without
publishing test versions.

Validation-only runs, failed/skipped publication and explicitly scoped historical
ARM64 repairs do not emit ready receipts. Old source refs without the publication
protocol are refused before any scoped npm write. To recover a missing alias for
an already-public historical release, explicitly dispatch `npm-alias.yml` with
`version` and `release_run`; its legacy recovery path requires successful source
publication and a public release. It is not an automatic bypass of this barrier.

## Client sync payload retention

The client retains current memories, one current remote snapshot per memory, and
unconfirmed operations or unresolved incoming data. Completed transport payloads
are reclaimed; processed conflicts retain only their small resolution receipts.
The server sync protocol, operation identities and cursor commit rules are unchanged.

Opening an existing library migrates remote snapshots from the old inbox before
reclaiming history. The same cleanup runs before and after sync, including before
a network failure can leave the previous round's completed payloads behind.
When free SQLite pages total at least 16 MiB and one quarter of the database,
automatic VACUUM and WAL truncation return that space to the filesystem.
An active reader or writer can defer compaction until a later maintenance pass.
Disk-full and I/O compaction failures log a warning and defer compaction rather
than preventing library access; reclamation errors still fail explicitly.
An explicit snapshot reset saves the previous current heads for recovery after
a server backup restore. Matching heads or explicit restoration reclaim these
recovery payloads; the completed edit history is not retained.
Current content, pending operations, undecodable data and unresolved conflicts
must survive migration; sync and memory revision tokens must remain unchanged.

Remote history queries return a bounded in-memory view without caching the
account's history in the inbox. Restoring a reclaimed version fetches the
requested operation or revision through the existing remote history protocol.

## Actions artifact retention and recovery

All workflows explicitly retain Actions artifacts for one day after upload,
including accepted and verified publication receipts and legacy `scoped-ready` / `alias-ready` receipts.
Build inputs, cross-job transfers, and publication receipts are still uploaded;
consumers, validation gates, publication locks, and digest checks are unchanged.
This policy does not change GitHub Release assets, published npm packages, or
Actions cache and workflow-log retention.

After an artifact expires or is deleted, failed-job reruns that need original
build inputs, the integrated publication handshake that needs its matching
`scoped-ready` / `alias-ready` receipts, and historical short-package repair that
needs the original `npm-release-validation` receipt are not guaranteed to work.
Supplying a version does not replace those receipts. Long publication queues can
also outlive the one-day window. Missing or expired evidence must fail closed: never skip digest,
source, regression, receipt, or publication checks to work around retention.
A full workflow rerun can allocate a different DEV version and is not guaranteed
to recover the same version. Diagnose the remaining draft and public package
state before a separately authorized recovery or new release.

The targeted `migration-keyring-check.yml` workflow also downloads
`cli-release-${{ matrix.target }}` from its `release_run_id`; expiry prevents
that diagnostic from verifying the original binary. For a new candidate,
separately authorize a fresh, non-publishing `release-validation.yml` run. Its
dispatch workflow ref and `ref` input must resolve to the same source commit,
because the targeted consumer checks the producer's `head_sha`. Wait for all
required platform builds and `npm-dry-run` to succeed, then use the new run ID
for targeted migration before its artifacts expire. This validates a freshly
built candidate, not the deleted original bytes. Preserve all source, version,
and digest checks; if the original artifact identity is required, stop and
report that evidence as unavailable rather than substituting a newer binary.

Deletion or expiry also removes downloadable diagnostic reports and publication
receipts; run status and logs are not a substitute for those files. An artifact
cleanup is not permission to delete Release assets or npm versions.

Only version allocation and publication share a serial lock. Allocation reserves the DEV number in an unpublished draft. The existing version script counts drafts to prevent collisions. Failed drafts remain available for diagnosis. Full regression does not hold this lock. Workflow or documentation changes alone do not publish a DEV.

Seven-target Release builds produce a native binary, runtime bundle and build
metadata per target: twenty-one assets. The separate optional source compile
matrix remains manual. CLI coverage checks and other workspace tests retain
their existing cases. musl builds reuse the existing cache; model caches still
require file validation and actual inference. No profile permits replacing the
candidate's real tests with cached success from another source or binary.
Release compilation caches contain dependency outputs only. Keys are collected
before ephemeral version rewriting and bind the workspace profiles, dependency
lock, target, actual toolchain/container, SDK and compiler flags. Cache misses
still build and validate the candidate. Hot hits skip cache archive preparation;
cold archive preparation and the independent post-run writer are best effort.
Their failure cannot substitute for or invalidate a product check. Cold-cache
preparation can still add time before the producer job ends; its cost and actual
cross-platform hits remain part of hosted performance measurement.

`scripts/test-published-upgrades.py --profile critical` selects the latest
applicable formal stable by numeric version for the current target. Only the
explicit historical platform gaps permit selecting an older version; a missing
or partial asset set outside that policy fails closed. No applicable formal
stable also fails. The selected case still exercises real model inference,
owned-runtime/worker isolation, hash checks, old HTTP RPC compatibility and the
complete main -> alternate -> main sequence. It never reuses cached profiles,
sessions, tokens or keyring material.

`--profile full` is the upgrade script's backward-compatible default. It
discovers every stable release from 1.0.6 onward and verifies the npm/GitHub
inventory. There is no formal stable 1.0.6 artifact, so its actual historical DEV
baseline remains required, as does the explicit 1.0.10 draft baseline. The
recorded baseline had 77 platform/version inventory rows: 71 applicable real
upgrade cases and six documented platform gaps. These are observed counts,
not a fixed future cap. Newly published stable sources automatically join the
full inventory; missing artifacts are not a general skip rule.

Upgrade reports explicitly record `profile`, `selected_sources`, `full_coverage`
and `all_published_sources_covered`. A successful critical report leaves both
coverage flags false. Full coverage requires all applicable sources and valid
not-applicable reasons to pass. A failed, cancelled, skipped, missing or duplicate
required result cannot authorize the selected profile's publication gate.

Scheduled/manual full runs retain historical upgrades on all seven native
targets, resident pressure, all six cloud sweeps, all three native migration
fixtures, their three joins and API regression. Reports bind the source, version
and hashes of the verified original artifacts. A critical publication can be
successful while its later scheduled full result remains pending or fails;
report those states separately and never label critical success as full
validation. Independent public installation verification also remains separate.

When a DEV must pass full acceptance before publication, first merge the
reviewed source while keeping push CLI CI enabled. Then manually dispatch
Release for the exact merged source with
`publish=true`, `full_regression_before_publish=true` and the requested unused
`dev_version`. All required full gates must succeed before npm writes; no
historical or pressure case is dropped. Normal critical stable and DEV releases
still wait for their complete critical gates before publishing.

For an explicitly requested DEV number, manual Release accepts `dev_version`
in `X.Y.Z-dev.N` format. Its base can differ from the source manifest. The
version must have no Git tag or published version on any platform package,
`rsrs-cli`, or the historical `@rsrsai/cli` package. Only an empty unpublished DEV draft can be resumed after
its previous owner run finishes; preserve the failed run and reports. Draft
notes record the owner, and an active owner blocks resumption. Legacy drafts
without an owner marker require all other Release runs to finish first. The
corrected source still passes the selected profile's complete gates. Omit the
input for automatic allocation. Stable releases reject this input.

## Independent source and migration checks

Normal CLI CI runs other workspace tests, CLI 90% coverage and packaging/workflow/fixture
contracts on three independent runners. `check-complete` fails unless all three lanes
succeed, including unexpected skips. Release's exact-source push-CI check still
requires the entire CLI CI run to succeed; adding a job does not automatically
configure a GitHub required branch check.

Windows and macOS migration fixtures run independently of base cloud sweeps,
with separate runners, profile roots and owned random native keyring entries.
Their join jobs wait for both successful producer groups. On each native
platform, the existing migration gate checks both reports against the original
verified build metadata's exact SHA/version/target/binary digest. Fixture success
alone cannot replace the base report, and base success cannot replace migration.
Linux supplements and their model/outbox dependencies keep their ordering.

New accepted/prepared receipts bind the selected validation profile and its
exact required inventory. Critical requires eight native startup/CPU/latest
upgrade lanes and API; full requires seven historical/resident lanes, six cloud
sweeps, three native migration fixtures, three joins and API. Both retain all
seven builds and exact-source CI. Publication and cleanup validate every
declared lane; failure, cancellation, skip, missing or duplicate targets cannot
authorize success. A legacy proof without a profile is interpreted only as its
original full contract, never as a critical shortcut. Older platform inventories
retain their committed requirements rather than inventing jobs that did not
exist. No critical receipt or imported proof can authorize a requested full
gate. The receipt contract uses `validation_profile`; an absent legacy field
means full, while an unknown value fails closed. The five-minute end-to-end ACK
target still needs an actual measurement.


The read-only `publication-ready` job waits for exact-source push CI and the
selected critical/full contract without holding the publication transaction
lock. The writer requires that job's success. Accepted reports distinguish
source commit to selected-profile validation, workflow creation to acceptance, and the ready
job's completion to acceptance (including publication-runner queue time).
These are actual timestamps; the ready-to-acceptance interval is not relabelled
as the complete source workflow duration. Every gate in the selected profile
must complete before the write transaction. Full-only work runs on its explicit
scheduled/manual path and cannot be reported as executed by critical.


For a dependency PR whose base is not `main`, normal PR branch filters do not
start CLI CI. Explicit `workflow_dispatch` with `source_checks_only=true` runs
all three source lanes and their aggregate without the separate optional native
compile matrix. This is source CI only: it cannot substitute for Release's
required exact-source **push** CI or any native/model/release acceptance.
The default manual matrix remains unchanged when the input is false.

## Cross-run immutable-version fence

Before npm can start, the normal publisher binds the repository, version,
selected source SHA, owning Release run and complete scoped/alias package names
in an encoded `rsrs-npm-write-fence` comment in the Release notes. Immediately
before the first possible submission it persists `phase: fenced` with every
validated package digest and confirms the write. Direct-launcher sources use
fence schema 2 for all eight packages, including the launcher. Historical schema
1 still binds only its scoped-package digests and retains its original meaning. This is durable intent,
not an npm acceptance or installation receipt. It survives Actions artifact
expiry and is retained when descriptions are regenerated or the Release becomes
public. No new credential, service or permission is used.

A different Release run cannot take over that version, even for stable tags or
when every public registry read returns 404. Version allocation checks the old
marker before changing a DEV reservation owner. The publisher checks ownership
before npm/asset preparation and again before replacing draft notes or assets.
An existing unbound stable draft cannot prove that no previous submission
occurred and therefore fails closed. A freshly allocated empty DEV reservation
owned by the current run can acquire its first marker.

After an uncertain submission, inspect public content read-only and resume the
original run's failed publisher only while its exact source/build/journal
proofs remain available. Same-run attempts retain the original fence and
reconcile their per-package unknown outcomes. Matching previous acceptances are
carried forward without another npm submission. Do not remove/downgrade the
marker, overwrite accepted versions, or create a replacement run to work around
an unresolved intent. Expired or missing proofs require separately audited
recovery or a new unused version; this change does not add automatic cross-run
recovery. Temporary artifact cleanup never removes this Release metadata.

Draft body updates explicitly preserve the canonical tag and then re-read the
Release identity and fence. Discovery and DEV allocation also reserve versions
claimed by a draft title or a durable fence when its tag is unexpectedly
`untagged-*`; these claims never authorize publication with a mismatched tag.
The first prepared DEV13 attempt persisted its fence and then failed the tag
read-back before npm ran. The observed object shape is covered by PATCH/GET
regression tests; the available logs do not establish why GitHub changed it.
That draft and its original owner remain reserved, including when npm returns
404 or another canonical-tag draft exists.


The payload-lifetime ownership fixture runs after workspace tests on that same
runner: its offline Cargo project intentionally reuses the workspace's locked
cached dependencies. It is not independent packaging work. Its two expected
negative controls and seven actual-wrapper/feedback tests remain unchanged.


Source workspace/coverage jobs use Cargo `line-tables-only` debug metadata to
retain file/line backtraces while omitting full type/variable DWARF. They keep
optimization at zero, debug assertions and overflow checks explicitly enabled,
all original tests and the same coverage threshold/exclusions. This is a source
CI setting, not a release/native profile change. See the [Cargo profile
reference](https://doc.rust-lang.org/cargo/reference/profiles.html#debug).
A local instrumented three-case probe confirmed normal results, retained debug
assertion panics and retained overflow panics under these settings; project
coverage and any timing effect still require the hosted run.

Selected-profile validation timing uses the latest valid completion time among
every required regression and `publication-ready`. A readiness clock cannot
stand in for a later required completion. Missing, malformed, impossible or
reversed required clocks leave that duration unavailable, even when all success
conclusions are present. Critical timing is not full-validation timing.
Source/publication bounds are checked so clock inconsistencies cannot become
negative or shortened performance claims.

## Unpublished preparation evidence

A manual Release from the exact current main commit with `publish=false` and
`full_regression_before_publish=true` can emit `release-prepared-RUN-ATTEMPT`.
Its read-only producer waits for all existing build/package, native, sweep,
migration, join and API jobs, then checks the latest exact-source main push CI.
Other refs, forks, stale attempts and failed or incomplete gates cannot attest.

The proof binds the source and version, validation profile, committed Cargo/toolchain/SDK/workflow
inputs, every platform SDK pin, original Actions artifact IDs/digests, actual
binary/runtime/metadata hashes, and the exact local validated npm tarballs.
For this explicitly full preparation it records full validation completion
independently of publication. A critical proof cannot be relabelled or imported
as full, and a legacy proof without a profile retains only its original full
meaning. Required
jobs and timestamps are rechecked when validating the proof; missing or changed
evidence fails closed. The artifact retains the existing one-day lifetime.

This is evidence from a run that did not publish. It is neither npm acceptance
nor public installation proof, and does not promise the version is still free.

For prepared DEV publication, dispatch Release from main with `ref` set to that
same exact source SHA, `dev_version` set to the prepared version, `prepared_run`
set to the completed preparation run ID, and both `publish=true` and
`full_regression_before_publish=true`. The preparation must have completed
before this new publication trigger. Historical repair/recovery inputs cannot
be combined with prepared mode. Normal publication retains its existing gates.

The plan pins the original receipt artifact ID, ZIP digest, canonical JSON
digest and source attempt, then registers a consumer before reading any binary
artifact. A read-only import job checks the original main run, complete gates,
source inputs and actual binary/runtime/metadata bytes. It independently packs
with the same pinned npm tool and requires equality with every prepared npm
tarball. It uploads verified platform copies and an import receipt into the new
run. Failed or skipped import jobs cannot authorize publication. Readiness pins
this new receipt, and the actual publisher checks both local byte inventories
and original/current proof pins before npm submissions. Existing immutable
version fences and active-attempt write checks remain in effect.

The accepted report records preparation run/attempt/duration and import time
separately from source-to-complete-validation and publication-trigger-to-acceptance.
Original preparation archives retain their one-day fallback. Once imported,
verified current copies can outlive those original archives, but their exact
source/gate history and current receipts remain mandatory. Cleanup deletes only
the current publication's copies after all parent, alias, background public
verification and potential manual artifact readers are terminal, installation
is verified, and an hour has passed since the last consumer/report. It never
deletes the original preparation's archives as current-run artifacts.
The five-minute end-to-end ACK target still requires a real measured publication;
prepared promotion alone cannot establish it.

DEV allocation reads every scoped package and `rsrs-cli`, including a version
visible only on the short entry. Registry metadata is an observation, not proof
that an earlier write never happened: Release reservations and the durable
cross-run submission fence remain mandatory even when metadata returns 404.
An accepted version is immutable, and unknown submissions are never replayed.


## Native Linux ARM64 delivery

Both Linux ARM64 targets build and run on `ubuntu-24.04-arm`. Their exact SDK
cache entries stay pinned to SDK `1.0.2-dev.14` in `sdk/core-sdk.lock.json`; source consumers have
read-only exact-hit caches and no private SDK token. Both targets participate
in model/runtime/diary feedback, native upgrades and full-profile cloud sweeps. Full gates
require eight native jobs, seven cloud jobs, three native migration jobs, three joins
and the API job. An ARM failure or missing result prevents full validation.

Eight targets produce 24 Release assets and nine npm packages for a direct
launcher source: eight platform packages and `rsrs-cli`. Historical source
manifests retain their scoped umbrella and separate alias. The npm launcher defaults ARM64 Linux to static musl;
`RSRS_LIBC=glibc` explicitly selects GNU. Independent background verification
runs native ARM public installations for both routes, checks their exact binary
hashes, version and executable startup, and records a separate ARM proof.
Cleanup requires this proof for current eight-target sources as well as the existing
GNU x64 proof; neither npm acceptance nor another architecture's installation
substitutes for it. Historical sources retain their own committed platform
inventory.
