# Diary sync conflicts and the local working copy

## Problem and fix scope

v2 sync uses server-side revision/CAS. A local diary append can be written successfully and read back independently, and then receive `conflict_saved` because another device advanced the server head. That receipt means the revision was stored as a conflict, not that the current body was accepted by the server.

Previously the client cleared pending after the receipt and then wrote the canonical head as authoritative into the current record, bypassing timestamp LWW. That could replace a just-confirmed diary body with another branch carrying an earlier timestamp. The original append stayed in conflict history, but later show/diary-search saw only the body swapped back in. The derived diary index is not a precondition for reproducing this.

The fix protects only a diary that is **still the current working copy, not deleted, importance=trivial, and exactly matches an unprocessed conflict revision**. When another active diary head arrives, the client keeps the current body, timestamp and device metadata; the server head, the original conflict ciphertext and the real conflict count are still stored. After the outbox is cleared the branch is still recognisable from the unprocessed inbox, so a restart and later pulls do not lift the protection. The existing sync policy for ordinary important records is unchanged; remote deletion and promotion still follow the original rules.

There is no automatic resend, no body concatenation, no change to the remote-wins rule and no marking of a conflict as resolved. `pending=0` only means the transport queue is acknowledged; it does not mean `conflicts=0` or that both sides have the same body.

## Explicit handling boundary

`sync-conflicts.current` is the **server-side canonical head**, and the output gains the marker `current_scope=remote_canonical`. While protection is active it can differ from the local working copy shown by `show`.

- `keep-current` keeps the reviewed server-side canonical head and may discard events in the local conflict branch. The protection is released only after a processed resolution arrives.
- `take-incoming` takes the whole conflict candidate and may overwrite events the other remote branch added; never treat it as a lossless append.
- `merge` uses only the body the user explicitly reviewed and supplied; it never computes a text union automatically.
- For an explicit take/merge on a protected diary only a newly created, not yet sent op uses the reviewed head revision for CAS; it never fakes an applied sync_base and never relaxes the epoch, head, pending or idempotency checks.
- Once the resolution receipt is processed, the same sync re-materialises so the explicit choice takes effect promptly; a later local pending write still falls under the original protection.

This fix does not automatically restore a diary already replaced by the canonical head before the upgrade, nor does it modify existing conflict history. An existing conflict must be handled separately on this machine after comparing both full records, taking a backup and confirming authorization; re-running remember once, sync-reset or replacing the store are not acceptance steps for this fix.

## Isolated verification

Every fixture uses only synthetic accounts, keys and diaries; no real memory is read or uploaded.

```sh
cargo test --locked -p respire_storage transport::local::sync::diary_tests
cargo test --locked -p respire_app sync::
```

The storage cases use an explicit test provider and cover the working copy after a receipt, outbox cleanup, restart, a later head, stale index artifacts, explicit take/merge/keep-current, and the delete/promote boundary; they are not real model or real service acceptance.

A real service/model probe needs the pinned SDK, a verified CPU M3 model and a **disposable local API/PostgreSQL service**. The probe only accepts a standalone `http://127.0.0.1:<port>`, refuses the host memory Runtime's default port, registers a new random synthetic account and uses a temporary client store; the service and database must be created and cleaned up by the test runner independently.

```sh
cargo build --locked -p respire --example diary_sync_probe
# If the SDK runtime is not yet staged into the examples directory, prepare it with the existing stage-core-runtime.mjs first.
RSRS_ENGINE=cpu RSRS_M3_DIR=/path/to/verified/model \
RSRS_CPU_OWNED_ORT_FILE=/path/to/verified/model/onnx/model_quantized.cpu-v1.ort \
  target/debug/examples/diary_sync_probe http://127.0.0.1:<disposable-port> \
  --confirm-disposable-server
```

The probe refuses `RSRS_CORE_TEST_MODE`, uses a real M3 prepare, and coordinates one real two-client HTTP sync conflict after background artifact preparation and before the commit. It then repeats four rounds of sync, cleanup, database reopen and real re-index, checking that the body and revision are preserved; finally it performs a merge with an explicitly supplied body and checks that both sides converge. The coordination point exists to trigger the race window reliably; it does not replace real inference and is not a year-long store performance or semantic retrieval quality benchmark.

The local integration used an isolated copy of the existing server source `d8bb056423a6ff1c0452601467af1cf30ce2beef` with PostgreSQL 17; only that test copy's public app dependency was pointed at the current CLI workspace and the pinned SDK, and the server repo and its HTTP/CAS implementation were not modified. This result does not mean the fix is deployed on user devices or production databases.

Maintainer isolated acceptance was actually executed: the DEV9 baseline `5a0c086afb67b250956bcbb02616585f6f2381d7` failed the same real service/M3 probe with "confirmed diary regressed after sync/restart"; the fixed build passes, including the four-round persistence check and the final explicit merge convergence. Under the repo CI's serial setting the whole workspace (excluding the CLI package) passed 258 tests with 1 pre-existing ignored, of which app was 166 and storage 59. A first default-parallel full app run showed process-level environment interference in a login-transaction fixture; that test was not modified and passed on a serial rerun.

The new diary storage regression was added to the native/musl steps of the existing token-free four-platform source acceptance; the existing real-model and snapshot/runtime/MCP gates are kept.

GNU's full source test and the 90% CLI coverage check moved to a separate `source-coverage` job running in parallel with `native-source`'s native build, real-model and Runtime/MCP acceptance. Both read-only restore the same exact SDK cache key, re-verify the pinned SDK and accept no private download credential; the producer is unchanged. The full results of the four-platform reusable workflow all feed into `research-feedback-complete`, and any failure, cancellation or skip cannot count as a passing merge or release. The existing test commands, coverage thresholds and exclusions are unchanged; only the dependency graph changed, and no performance benefit is claimed from comparing timings across build profiles.

In the first four-platform round, macOS's background fence probe timed out while still verifying two model containers of about 569 MB each, before any real diary work started. The probe now treats model preparation as a separate precondition of at most 300 seconds; the actual diary work observation after preparation is still limited to 120 seconds, must still observe `diary-fragments`, and must verify the two-table summary, data_version and that drain no longer writes after the read-only receipt. A later macOS round passed that fence but timed out waiting for semantic_ready after switching to another key account; account switching uses the same model preparation path, so both waits share the same bounded preparation rule and keep model_operation/retrieval_index diagnostics when not ready. The other account must still become genuinely semantically ready, return its own body and exclude the previous account's body. No model verification was skipped and a prepared state was never treated as real diary inference passing.

## Release status

This fix is not released. The official `1.0.17-dev.9` is the affected version. Source and isolated test passes cannot replace normal CI, cross-platform and release gates on the final SHA; the plugin's native new-session cross-sync persistence acceptance still has to run separately after the fixed build is deployed.
