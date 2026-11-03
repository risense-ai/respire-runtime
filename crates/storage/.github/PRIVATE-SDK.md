# Private Core SDK reader transition

This preparatory change adds the reader but does not activate private pins or
reference a secret in any CI job. Existing public SDK10 inputs keep working.
Native thread repair/pins in PR125 are still a separate unfinished delivery.

The eventual credential is `CORE_SDK_READ_TOKEN` in respire-cli Actions settings,
owned by risense-ai and limited to respire-core Contents:read. This permission
also reads private source, so it must remain isolated from build/PR code. User
configuration is pending; no value is requested in chat, read by this change,
created, transferred or persisted by the agent.

## Request boundary

`private-sdk-download.mjs` accepts only Core, the seven approved targets, exact
SDK DEV tag and canonical asset names/URLs with pinned SHA256. It resolves the
released asset's integer ID through authenticated api.github.com metadata, then
uses the canonical same-repository asset API. No arbitrary metadata URL is used.
Redirects are manual: only HTTPS official asset CDN hosts and expected paths are
accepted. The CDN request is newly constructed with no Authorization, cookie or
referrer; another redirect is rejected. Response size and actual bytes must match
the metadata and pinned hash before existing prepare-sdk archive/path/file
verification and atomic staging can run. API/body/redirect errors do not echo
credential contents, response bodies or signed URLs; mutations/retries are absent.
There is no GH_TOKEN/GITHUB_TOKEN fallback.

The reader rejects pull_request and pull_request_target contexts before reading
the dedicated token. Under Actions it accepts only CLI main-branch push/manual
context; ordinary fork/PR native builds and automatic tag jobs are not implicitly
authorized. Local authenticated developers can use an approved binding explicitly.
A prevalidated local SDK directory still verifies hashes without network/token.

## Required isolation before pin activation

Do NOT put CORE_SDK_READ_TOKEN in a job-wide environment, Cargo/build-script
process, untrusted checkout, fork/PR job or a PR-target workflow. The next workflow
change must use a trusted default-branch download job, with no untrusted code
execution before/during credential use. All downloaded data must be hash-checked
against the reviewed lock. Any native validation of a reviewed source revision
must execute in a separate token-free job/runner after the trusted reader ends.
Only distributable compiled SDK files may cross that boundary, never the token,
credential config, private implementation source or signed URL logs. Temporary
artifact transfer, if selected, needs explicit consumed-run cleanup; it is not
silently enabled here. This isolation design requires review before activation.

PR-safe verification in this change uses synthetic metadata/body/redirect fixtures
and no private credential. Full native SDK/CLI tests must still use verified local
SDKs or the reviewed isolated workflow; a fixture result is not native acceptance.
Do not change private pins just to make an unauthenticated PR build green, expose
secrets to PR code, or skip necessary native/runtime/regression checks.

Core's private Release must exist first. Then generate/review actual new manifest
and archive hashes, update BOTH CLI SDK locks, and integrate the trusted workflow.
Plain npm installation already carries platform executables, runtime libraries
and notices; it never needs the private SDK read credential. Do not publish a new
DEV until the full paired fix, private delivery, CI, npm/alias and install gates
are complete. Long-term direct native crates remain pending registry support.

## Verified scope

16 private-reader tests cover API/redirect/header boundaries, all rejection paths,
SHA256/size, PR context denial and secret-shaped response data. The combined100
publication/cleanup/reader tests pass locally. No live private download or upload
was performed. Helper packaging includes the module; no credential is written or
logged. This maintenance-only merge is ignored by native Release push triggers;
the separate SDK pin/native repair change will trigger the real validated DEV.
