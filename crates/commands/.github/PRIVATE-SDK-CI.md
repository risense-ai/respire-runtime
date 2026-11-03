# Private SDK credentials and native CI isolation

The existing CLI repository binding is CORE_SDK_READ_TOKEN, limited to Core
Contents:read. It also grants private Core source access, so builds must never
receive it. No new credential, secret copy or permission expansion is added.

## Data flow

1. A maintainer manually dispatches private-sdk-cache.yml on main, with the exact
   independently reviewed CLI source commit containing BOTH private SDK locks.
2. Trusted main code reads those two files as bounded JSON through CLI's normal
   read token, validates the seven targets/Core-only URLs/version/license/hashes
   and emits canonical data only. It never checks out or executes that source in
   the privileged job. Unknown fields are not forwarded.
3. Separate trusted-main download jobs never restore any dependency cache. Their
   cache-mode is write-only, setup-node package-manager caching is disabled, and
   preparation rejects a pre-existing SDK directory. They freshly download and use CORE_SDK_READ_TOKEN only in the SDK
   preparation step. The existing private reader pins API destinations, strips
   authentication on the single allowed CDN hop, and checks actual size/SHA256.
   Preparation verifies archive paths, manifest equality and every file hash.
   A final directory audit rejects unlisted/corrupt/linked/source/model/credential
   files before dependency caching. No Rust build script or selected-source code
   executes in this job. The cache action does not receive the read-token env.
4. A separate reusable native workflow receives only source SHA, target, cache key
   and runner OS. No secrets are declared/passed/inherited. Its automatic token
   has CLI contents/actions read only and cannot access private Core. Both the
   caller and reusable native job declare cache-mode: read; the plan job uses
   cache-mode: none. These explicit GitHub controls fail workflow validation on
   unsupported systems rather than falling back to writable cache tokens. The source
   checkout/build/model execution occurs here; an environment check requires the
   Core read token to be absent. GNU retains the full source-test and90% coverage
   gate; four native targets build and run a real model installation/probe, with
   unit-test Core mode scoped only to the GNU test step.
5. Normal CI/Release-validation/hardware workflows restore only exact per-target
   cache keys derived from the reviewed pins, with cross-OS archives and no
   fallback prefixes, and require cache-matched-key to equal the expected key
   before running the next source command. All source-running consumer workflows
   use read-only cache tokens and restore-only actions. Missing private SDK cache fails rather than injecting a
   credential into source code. Existing public SDK inputs continue their
   existing no-secret path. No hardware workflow is triggered by this change.

## Cache scope and lifetime

This uses GitHub dependency caches instead of Actions-artifact storage. Keys bind
target plus both pinned SDK hashes and canonical identity. Only the audited SDK
folder is saved: compiled libraries, public ABI header, manifests and notices.
SDK binary data may be restored by fork workflows in this public CLI repository;
that is the same approved compiled-native distribution scope as the existing
public SDK/native-crate design. Private implementation source, model weights,
chat/account data, credentials, checkout history and signed URLs are excluded.

SDK dependency caches retain GitHub's existing cache lifetime/capacity/eviction
rules (including eviction after7days without use). No existing cache is deleted
or retention setting changed. Release temporary Actions artifacts keep their
separately approved one-hour-after-consumers cleanup/one-day fallback. This PR
creates no Actions artifacts or Release assets and avoids adding another SDK
artifact-storage requirement. It does not promise one-hour dependency-cache
expiry. Consumers verify cache hits again. Only the trusted fresh-download
producer can save SDK caches; selected-source jobs cannot write dependency
caches even during a main workflow_dispatch run. Other source build/model
caches are restored read-only too; these workflows no longer populate them.

Rust compilation caching keeps these source jobs read-only. They restore separate
ordinary/instrumented dependency caches and stage a new snapshot only on a miss,
after successful tests. Workspace builds and old LLVM counters are excluded.
The separate `rust-build-save` job has write-only cache access: it never checks
out or executes source, validates the `rust-ci-v1-` key, extracts only dependency
data, and saves that compilation cache. It cannot restore SDK caches and never
receives the private SDK credential. Existing SDK key and producer rules stay in
effect.

Official permission semantics: https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching#controlling-cache-access-with-cache-mode

## Activation sequence and evidence

The workflow is manual-only and main-only. First merge this exact-head reviewed,
CI-passing infrastructure change with public SDK pins intact. Then review the
actual private Core Release/source/15asset hashes, update both locks in the native
repair PR and dispatch the trusted workflow for that exact reviewed commit.
Successful real private download plus audited caches must precede normal PR CI
and token-free native validation. No private lock or secret use is activated by
this PR's merge alone. Publication/install gates remain separate and mandatory.

No live credential request is claimed by fixture tests. Local tests cover exact
keys/canonical fields, both lock copies, directory integrity, credential/source
exclusion and the no-secret reusable-workflow boundary. Existing source/coverage,
release regressions, package integrity and installation tests remain required.
Native source code is selected only by a40-character SHA; changing a reviewed
head requires review again. Do not use pull_request_target or put the Core read
binding in native-job env, source scripts, lock files, runtime binaries or npm.
