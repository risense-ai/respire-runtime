# Host-owned credentials: draft acceptance record

This is a validation plan and partial evidence record, not a passing acceptance
report. The coordinated drafts are Runtime #84, CLI #290 and Client2 #42 in
`risense-ai`. They must remain drafts until the other in-flight work is complete,
the branches are synchronized with main, and implementation review is finished.

## Dependency evidence

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
