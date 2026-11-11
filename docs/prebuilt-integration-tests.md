# Prebuilt integration test bundles

`prebuilt-integration-tests.yml` is a trusted `main` manual producer. Dispatch it
with the independently reviewed, exact 40-character `reviewed_source_sha`.
The source must belong to the workflow commit's main history. Tools come from
that workflow commit; source is checked out separately. No private SDK token
is passed to either job. Exact SDK directory and archive caches must already
exist, prepared by the existing trusted SDK cache workflow.

The six native targets match the existing CLI feedback matrix: Linux x64 and
ARM64 GNU/musl, Windows x64, and macOS ARM64. GNU x64 runs independently of the
other matrix legs. Musl uses the existing Alpine/Rust toolchain and release
profile; other targets use debug with assertions and overflow checks.
This producer builds no Runtime executable and publishes no product release.

Each `runtime-test-bundle-${target}` artifact contains `manifest.json` and a flat
`bin/` directory holding five executable roles plus the existing staged Core
runtime dependencies and notices:

| Role | Existing build target / consumer selection |
| --- | --- |
| `business_tests` | `respire_commands` example `cli_business_tests`; all 31 exact cases |
| `app_tests` | `respire_app_domain` libtest; `snapshot::tests` |
| `storage_tests` | `respire_storage` libtest; `transport::local::sync::diary_tests` |
| `feedback_contract_probe` | Matching existing commands example |
| `ablation_bench` | Matching existing commands example, adjacent to the feedback probe |

The app facade re-exports snapshot code; snapshot unit tests belong to
`respire_app_domain`, not the facade's own libtest. The producer copies the
complete payload to an independent temporary directory, clears SDK/library-path
overrides, lists all 31 exact business names, and requires nonempty original
app/storage filters. From that relocated directory it executes the existing
model-free `snapshot_captures_committed_wal_excludes_grants_and_preserves_source`
and `conflict_receipt_does_not_replace_a_confirmed_diary_append` assertions,
requiring one actual passed test each. Payload hashes must remain unchanged.
It does not execute the 31 business tests, install models, or start a product.

Schema 1 binds `repository`, `source_sha`, `target`, `sdk_lock_sha256` (SHA-256 of
the identical Git blob bytes of both locks), `features`, `roles` (relative paths),
`tests` (`business`, `app`, `storage` exact names), and `files`
(`path`, `size`, `sha256`). `features` preserves `cpu-owned-ort-experiment`;
Cargo selects the corresponding owning-crate feature for each role.
Before building and after relocation checks, both checkout files must match
their reviewed-source Git blobs byte for byte. Line-ending conversion fails
explicitly; it never changes the identity used in the manifest.
`files` covers all payload files; the manifest is covered by the API artifact
digest, rather than a recursive self-hash.

Consumers pin the repository, producer workflow commit, artifact ID, API digest,
source SHA, run ID/attempt, target and SDK lock digest. They must authenticate
these against GitHub's API before executing a role, validate the manifest and
all payload files, and retain the existing test assignment, identity, model,
ownership, stop, and cleanup assertions. Producer success and `--list` are not
execution acceptance. Use the separately verified, already published Runtime
release as the product fixture.

Artifacts request 90 days of retention (repository policy must permit it).
CLI runs reuse a fixed pin; they never dispatch this producer. An expired or
missing artifact fails closed. A reviewed rebuild requires a new explicit
run/artifact/digest pin; there is no latest or source-build fallback.
