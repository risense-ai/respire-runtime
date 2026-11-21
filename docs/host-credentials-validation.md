# Host-owned credentials: draft acceptance record

This record preserves the November 15 acceptance scope. See
[Runtime test ownership and execution](testing.md) for current acceptance.

This is a validation plan and partial evidence record, not a passing acceptance
report. The coordinated drafts are Runtime #84, CLI #290 and Client2 #42 in
`risense-ai`. They must remain drafts until the other in-flight work is complete,
the branches are synchronized with main, and implementation review is finished.

## Current evidence and CI scope (2026-11-15)

The user's clarified acceptance target is a coordinated upgrade to the new
protocol-compatible CLI, Runtime and Client2. Historical stacks are migration
sources, not mixed-version compatibility targets. Database compatibility and
integrity are the upgrade gate; obsolete host commands and old client/runtime
combinations are outside this release's acceptance scope. Candidate source and
artifact hashes identify evidence, not runtime component coupling.

The sections below preserve the original draft checklist and historical baseline;
its pending rows and original SDK/protocol/conflict notes are not a current status
report. The current SDK lock selects Core SDK `2.0.0-dev.4`, and
`respire_protocol 2.0.0-dev.8` is published. Product PRs remain unmerged.

Runtime `ebf1c3c554dedc5529c9247e60192f295b12b648`, CLI
`ab7a25078c0d2dfcde4b30d4f1a27382ae3b778d`, and Client2
`1734322b6c6dd543441a753f07a3517bee5e1231` passed the paired Linux/macOS
native lifecycle workflow `43660791467`. Its Linux controlled-service account
suite and macOS original-path issue #285 upgrade also passed. These are source
candidate results, not published-product acceptance. Windows UI, frozen G1 and
published-product acceptance must be evaluated separately.

CLI run `43660517611` passed its core integration but failed the account case in
`runtime_smoke`: full logout with the published Runtime `2.0.0-dev.17` reopened
the store without a session. Keep that assertion for the new supported stack;
this mixed old-Runtime/new-CLI run is not a coordinated upgrade acceptance
result. The paired native suite tests the new Runtime source. A historical
Runtime result must not substitute for new-stack or release acceptance.
The CLI pin must not name an unpublished release.

Measured warm-run times show runner allocation around two seconds, Runtime
builds of 46–54 seconds and CLI builds around 35 seconds. Linux account execution
took about five minutes, and the macOS upgrade about three minutes. The two
Windows jobs each repeated 5–6 minutes of shared source tests. Shared source and
PowerShell policy tests now run once in `windows-source`; both jobs retain their
separate native product scenarios and both must pass. New PR revisions cancel
obsolete runs of the two native workflows. No product assertion is removed.

Old business assertions for database integrity, login, synchronization, memory
operations and migration remain relevant. Startup fixtures must supply synthetic
credentials through the host. A separate direct-Runtime case must prove locked
startup without host input. Old Client2 binaries that require removed host RPCs
are historical fixtures, not supported consumers of the pure Runtime.

## Follow-up packaging failure and migration scope

Frozen G1 run `43662361394` passed source tests, both native smoke targets and
its original business subset. Its launcher cases failed before credential setup:
the frozen Runtime sidecar omitted `offline_keygen_handoff`, although the actual
Runtime and published-release producer support it. The freeze producer now
retains that capability, and the existing contract check verifies both producers.
The CLI fixture also completes keygen's paused handoff through public Runtime
start before stopping its setup owner. CLI source is now
`51afe9a4adeac7ea3e79610dadd82013db508df3`. New exact-source G1 is required.

Runtime source `c389bd369bf3a55529ccd1c472ee61eff8d208fa` passed all eight
builds and eight native regression jobs in nonpublishing run `43662682478`.
This is evidence for that source only; it is not a published DEV acceptance.

Migration coverage follows database formats: formal release upgrades remain
required, and a DEV that changes persistent schema or encoding becomes an
additional mandatory source. Unknown historical DEV formats remain covered.
Runtime DEV 1 through 17 have identical storage and crypto trees
(`ed03246f14b2dc6af68b2b4c13fdf87789e06829` and
`ecdb99048c9532c44654b3660ee8b9f9915493d3`). Core SDK DEV 1 through 4 have
identical transport and crypto sources. The current Runtime crypto change only
adds Clone to in-memory SessionKeys. Consequently, the issue #285 DEV-to-DEV
upgrade remains available with `legacy_dev_upgrade=true` on the manual native
workflow, and is no longer repeated on every PR. This does not remove stable
release migration or independent credential/lifecycle/business regressions.

That comparison predates the current uncommitted storage migration: it installs
revision triggers for retained `when_to_use` and `superseded_by` columns in
upgraded databases. If included in the released DEV, that DEV becomes a
persistent-schema checkpoint for subsequent upgrades. Do not register a
nonexistent release as a mandatory download. CLI's historical checkpoint list
already retains `v1.0.15-dev.10` and the unclassified older DEV format; those
sources remain required while validating the current new stack.

## Dependency evidence (historical draft baseline)

The original working baseline pins Core SDK `1.0.2-dev.23`. For
`x86_64-pc-windows-msvc`, the downloaded private release matches the lock:

- Manifest SHA-256: `6a65af1a8c95a2380895b03f988e1aab02debcbdbfa93fa0751856425364f1ee`
- Archive SHA-256: `c08c1b89052948c5e225ce80fff23988b9207257fab3868f867a3fd167524029`

After fixing stale references left by host-command extraction, the Runtime
host-target `cargo check -p respire_runtime --locked --offline` passed. This
checks types only. It does not execute any of the scenarios below.

Client2's existing PR CI passed lint, Windows amd64 and Linux amd64. Those jobs
do not by themselves prove startup key delivery against these paired drafts.
The new protocol version is not published and the official Runtime download pin
has not been moved to an unpublished build.

## Required native scenarios

Use fresh synthetic profiles, a dedicated test credential store, a controlled
sync service and verified installed model files. Never use the developer's
account, native credential entries, database or an unrelated running Runtime.
Bind evidence to the exact three source commits, executable hashes, SDK lock,
runner platform and execution command.

| Scenario | Required observation | Status |
| --- | --- | --- |
| Restart without host input | Directly start the new Runtime with the encrypted profile. It reports `store_ready=false` and `credential_state=required`; memory RPC returns `runtime_locked`; sync and indexing remain paused. Repeat after a successful unlock and process restart. | Pending |
| No implicit key source | Existing native credentials, inherited password variables and legacy session secret fields must not unlock the serving Runtime by themselves. | Pending |
| Unlock rejection | Missing bearer token, wrong key, wrong profile, changed session revision, wrong instance or generation must fail without opening or replacing the database. | Pending |
| Explicit host unlock | Submit correct host material to the verified owner; the library becomes ready. The request must not appear in normal operation journals, argv, health or replies. | Pending |
| CLI startup | With no key embedded in the session and no password environment override, store a synthetic key in the isolated native store. Exercise managed startup, foreground `runtime run`, an existing locked owner and supervisor restart; CLI must deliver the key. | Pending |
| Client2 startup | Start through the actual Manager with the paired CLI. Test a fresh child and an existing locked owner, verify the same PID/profile, then verify readiness after host key delivery. | Pending |
| Missing host credential | CLI and Client2 keep the Runtime locked and do not generate a replacement key or overwrite existing encrypted data. | Pending |
| Login and sync | Use the paired CLI and Runtime with the controlled service. Login preserves the expected identity and keys. Synchronize a synthetic memory to a second fresh profile, unlock there and verify decrypted content. | Pending |
| Remember and recall | After host unlock, execute the real public `remember` and `recall` paths with verified installed model files. Verify the expected memory and content before and after restart plus host unlock. | Pending |

The existing `cli_business_tests` account and diary suites provide reusable
fixtures for login, sync and memory operations. Audit their startup helpers:
direct Runtime startup with `RSRS_SUPER` is intentionally no longer sufficient.
Do not weaken the locked-state requirement to preserve an old fixture.

Unit tests built with `test-support` retain their synthetic keyring adapter.
Passing those tests is not evidence that a production Runtime avoids native
credential access. Production-process scenarios above are required separately.

## Current coordination limits

The Runtime and CLI drafts originate from a baseline older than current main and
GitHub reports merge conflicts. Do not resolve those conflicts by overwriting
new version, logging, migration or startup changes. Synchronize and audit after
the other tasks finish, as requested.

The original Runtime CI also requires frozen native execution reports even for
a manual source-only invocation. A missing report keeps that gate red; this
draft does not remove or relax the gate. A source-only run cannot be reported as
native acceptance.
