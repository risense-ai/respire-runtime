# dev.10 ownership and transient allocation audit

Base CLI: 4549184ecdd7520b623a5c091a4f75d608a2d467.
SDK: 1.0.2-dev.9; pinned GNU manifest source 3be310e92610a5d063c7d8aad570a88652930e66. No SDK changes.
Branch: perf/dev10-memory-copies, isolated worktree /workspace/shared/cli-dev10-memory-copies. No push, merge, release, permissions changes, real memories, credentials, or user computer access.

## Two isolated changes

1. Storage artifact attachment: previously all matching IDs, source ciphertexts, and opaque artifact vectors were materialized in a HashMap. Each output lookup cloned both ID and full source ciphertext, then cloned the artifact again. Now keep only an ID→output-position map; step the same SQL join; compare the SQLite-borrowed source against the requested snapshot; copy the artifact directly from SQLite to its final output Vec. This removes the full-library source copy, per-lookup source temporary, and second artifact allocation. Final returned memories and their artifact ownership are unchanged. This path is used by LocalStore::all and initial retrieval_delta(None); not every hot resident query.
2. CLI freshness SHA-256: read each native executable in a reused 64KiB stack buffer instead of fs::read's native-sized heap Vec. Still hash both complete files every time. No inode/path/mtime shortcut, cache, weaker integrity test, or altered retirement logic. Retries Interrupted and propagates other read errors. Like the previous read-to-end implementation, this does not promise an atomic snapshot if another process modifies the open file; deterministic grow/truncate/error readers test that boundary.

## Byte attribution

Storage N=10,000, ciphertext=16,384 bytes implies 163,840,000 bytes = 156.25MiB of full-library source payload removed. The old map also retained IDs, artifacts, and buckets. New ID keys are 13 bytes each (fixture-00000) plus String/bucket overhead. Opaque artifact fixture is 29 bytes per ID; two distinct IDs can share ciphertext/artifact bytes without sharing identity. One SQLite row source remains live at a time; requested output ciphertext remains owned and is not counted as a leak. All fixtures have the same 16KiB repeated ASCII ciphertext, so they specifically exercise repeated-content/different-ID mapping; no actual decryption, model inference, or vector retrieval is performed.

Hash fixture is exactly 48MiB. Baseline has an executable-sized 50,331,648-byte Vec per hash, sequentially twice; candidate has a 65,536-byte reused stack buffer and a small hasher. Do not claim 96MiB simultaneous savings, since the hashes are sequential.

## Measurement contract and limits

Linux x86_64, rustc 1.95.0. Storage crate opt-level=3; dependencies and example harness remain dev/debug. This is a locally optimized storage-only microbenchmark, NOT an all-release build and NOT whole-CLI or M3 measurements. Historical no-model 1068→388MiB and real M3 ~1GiB are not the baseline here. The 500–600MiB model target remains unproven.

Identical pre-created synthetic SQLite fixture for each A/B pair. Counts 1k,2k,...,10k; 3 rounds with alternating A/B ordering; 20 reads each. No other agent build/benchmark ran during the isolated matrix. Every read verifies count, ID order, user, timestamp, deletion flag, exact artifact-to-ID association, and ciphertext length. Unit oracle additionally compares complete Debug output including serde-skipped metadata against the original attachment algorithm.

PSS and RSS are sampled every 2ms from /proc/PID/smaps_rollup; each case has exactly one process, no model worker, so there is no shared-page/process double count. Sampled peak may miss shorter transients. CPU time is child user+system time and includes common assertions; QPS and latency only time LocalStore::all. Reported peak and idle values are medians across three processes. Idle means after all 20 returned vectors were dropped; allocator retention is included. It is neither live output size nor long-lived M3 worker steady state. P95/P99 describe 60 observations, include initial reads and scheduling outliers, and are not a robust production tail SLO.

Hash harness directly extracts base and candidate functions, uses identical SHA-256 dependency built with sha2 opt-level=3 and rustc -O harness (other dependencies remain debug). Three rounds, 30 sequential double-hash operations each. No user binary is read. Full release CLI end-to-end audit is a separate acceptance gate.

## Remaining ownership hotspots (not changed)

- Core FFI Buffer::bytes creates a full response Vec from Core-owned bytes before serde parsing. Potential response-sized transient; a lifetime-bounded borrow while RAII Buffer remains alive could remove it, but ABI/error ownership needs dedicated testing.
- Resident publication builds owned Snapshot metadata/entry, json Value, and framed serialized bytes. Existing borrowed request structs, payload.take, response removal, and drop(payload) already avoid some duplication. A typed serialization/streaming design could cut cold-publish overlap but overlaps broader framing work; PR109 is untouched and not counted as accepted.
- Host refresh clones unchanged StoredMemory metadata into a new catalog. These are deep String/Vec clones (typically metadata/locator-sized after existing ciphertext-capacity release), unlike the lightweight cache Arc::clone. Changing catalog to per-record Arc would require API and retained-reader tests.
- candidates_index_ready clones opaque artifact Vecs before base64 serialization, and rebuild_index clones each stored row before replacing its artifact. Typically locators/single-row transients; lower priority than whole ciphertext map.
- Process::send holds input Mutex during serialize+write+flush. Moving encode before lock may improve contention but needs generation/retirement ordering proof and can increase concurrent live serialized buffers. Not a free memory win.
- Worker channel send moves Value ownership; it does not deep-copy JSON. Unbounded channels can retain queued payloads, so bounding queues is a behavioral/backpressure change, not a clone cleanup.
- Core historical resident source at 3be310e already uses Arc<View>, per-record Arc, and borrowed fully-pending lexical views. Arc cloning increments a reference count, not body/vector copying. Mixed/indexed lexical projection still intentionally deep-copies a vector-free full-body view; investigate separately with genuine indexed fixtures.

## Reproduction

Use SDK/source pins above and an isolated writable directory. Build the same crates/storage/examples/catalog_copy_profile.rs against baseline and candidate with:
 cargo build --offline --config 'profile.dev.package.respire_storage.opt-level=3' -p respire_storage --example catalog_copy_profile
Copy outputs to OUTPUT/storage-baseline and OUTPUT/storage-candidate before switching source. Set RSRS_CORE_SDK_DIR, CARGO_HOME, RUSTUP_HOME, CARGO_TARGET_DIR to the verified toolchain/SDK; RSRS_CORE_TEST_MODE=1. SDK lock hashes must pass normally; no lock bypass.

Generate hash harnesses with scripts/perf/prepare_hash_copy_profile.py OUTPUT BASE_COMMIT, compile both with rustc --edition=2021 -O and the same sha2 rlib/dependency directory to OUTPUT/hash-baseline and OUTPUT/hash-candidate.
Run scripts/perf/profile_memory_copies.py OUTPUT, scripts/perf/profile_memory_copy_boundaries.py OUTPUT, then scripts/perf/summarize_memory_copies.py OUTPUT. Raw JSON includes commands, all latency observations, CPU, peak PSS/RSS, full final /proc counters, stderr, and sampling counts. Fixture directories are disposable synthetic data; preserve JSON/logs/source hashes.

## Verified commits and tests

- 4d215de870b9cf8c0dc8593353176fc4a3b709e2: bounded executable hash.
- 35d8fcc032b6b540b2ab093deded20b77490ccce: streamed artifact attachment.
- Author is local assistant dot <dot@localhost>. No remote changes.
- Final cargo test --offline -p respire_storage --lib -- --test-threads=1: 31 passed, including full original-algorithm metadata/order oracle, differing IDs with equal source/artifact, stale source, missing artifact, alternate model, deleted memory, empty subset, and SQL failure.
- Final cargo test --offline -p respire --bin rsrs mcp::tests -- --test-threads=1: 13 passed. Covers exact digest for empty and chunk-edge inputs, same-sized last-byte replacement, missing target, missing source, directory read error, Interrupted retry, injected mid-read failure, deterministic source growth and truncation versus read_to_end.
- Existing test commands use RUST_MIN_STACK=16777216 as shared Linux debug-test convention. All required SDK manifest/toolchain checks remained enabled.
- Python scripts compile; git diff --check passes. Full workspace/release E2E acceptance remains separate.

## Storage 16KiB results (three rounds per row)

| Count | Variant | Median ms | P95 ms | P99 ms | all QPS | CPU s / 20 reads | Peak PSS MiB | Peak RSS MiB | Post-drop idle PSS MiB |
|---:|:---|---:|---:|---:|---:|---:|---:|---:|---:|
| 1000 | baseline | 47.77 | 55.56 | 61.88 | 20.65 | 1.00 | 43.91 | 45.40 | 37.38 |
| 1000 | candidate | 28.51 | 30.83 | 32.34 | 35.03 | 0.59 | 28.07 | 29.56 | 14.13 |
| 2000 | baseline | 91.55 | 116.17 | 122.66 | 10.71 | 1.87 | 75.84 | 77.33 | 74.87 |
| 2000 | candidate | 49.71 | 56.29 | 60.77 | 19.85 | 1.04 | 44.42 | 45.91 | 44.42 |
| 3000 | baseline | 125.96 | 144.01 | 178.57 | 7.79 | 2.54 | 108.54 | 110.03 | 98.55 |
| 3000 | candidate | 72.34 | 78.57 | 92.51 | 13.67 | 1.51 | 61.22 | 62.71 | 61.22 |
| 4000 | baseline | 194.05 | 232.66 | 297.95 | 5.06 | 4.03 | 140.18 | 141.68 | 140.18 |
| 4000 | candidate | 105.10 | 124.11 | 145.42 | 9.28 | 2.24 | 77.15 | 78.64 | 77.15 |
| 5000 | baseline | 229.29 | 303.75 | 514.85 | 4.18 | 4.73 | 173.87 | 175.36 | 162.67 |
| 5000 | candidate | 119.58 | 150.04 | 182.05 | 8.19 | 2.51 | 94.99 | 96.48 | 94.99 |
| 6000 | baseline | 259.23 | 301.74 | 439.08 | 3.76 | 5.41 | 205.24 | 206.73 | 205.24 |
| 6000 | candidate | 142.38 | 160.42 | 222.04 | 6.85 | 3.02 | 110.87 | 112.36 | 110.87 |
| 7000 | baseline | 298.86 | 386.93 | 885.58 | 3.13 | 6.27 | 236.73 | 238.22 | 236.58 |
| 7000 | candidate | 175.92 | 205.58 | 243.12 | 5.58 | 3.74 | 126.70 | 128.20 | 126.70 |
| 8000 | baseline | 371.97 | 507.45 | 908.12 | 2.53 | 7.80 | 268.99 | 270.48 | 267.87 |
| 8000 | candidate | 209.85 | 277.30 | 329.01 | 4.59 | 4.59 | 142.74 | 144.23 | 142.74 |
| 9000 | baseline | 421.86 | 782.49 | 2525.36 | 2.02 | 8.80 | 304.29 | 305.78 | 282.36 |
| 9000 | candidate | 220.58 | 243.24 | 327.37 | 4.45 | 4.65 | 162.39 | 163.88 | 162.39 |
| 10000 | baseline | 466.35 | 713.14 | 1009.88 | 2.04 | 9.60 | 335.90 | 337.39 | 335.90 |
| 10000 | candidate | 258.31 | 296.25 | 355.27 | 3.81 | 5.43 | 178.26 | 179.75 | 178.26 |

## Smaller source boundary cases

Three rounds × ten reads. Same artifact/ID distribution. Savings scale with source bytes; 16KiB results must not be generalized to shorter real records.

| Count | Bytes/source | Variant | Median ms | Peak PSS MiB |
|---:|---:|:---|---:|---:|
| 1000 | 1024 | baseline | 6.26 | 14.36 |
| 1000 | 1024 | candidate | 5.44 | 13.37 |
| 1000 | 4096 | baseline | 16.50 | 20.37 |
| 1000 | 4096 | candidate | 10.75 | 16.31 |
| 10000 | 1024 | baseline | 79.00 | 42.67 |
| 10000 | 1024 | candidate | 65.73 | 30.36 |
| 10000 | 4096 | baseline | 181.27 | 101.43 |
| 10000 | 4096 | candidate | 125.42 | 61.12 |

## 48MiB synthetic executable double-hash

| Variant | Median ms | P95 ms | P99 ms | QPS | CPU s / 30 pairs | Peak PSS MiB | Peak RSS MiB | Post-drop idle PSS MiB |
|:---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 99.54 | 107.50 | 114.05 | 10.04 | 2.96 | 48.49 | 49.11 | 0.49 |
| candidate | 66.12 | 74.40 | 81.00 | 14.91 | 2.04 | 0.55 | 1.17 | 0.55 |

The initial exploratory unoptimized-storage results and an aborted unoptimized-SHA dependency run are excluded from all final tables. Raw storage-matrix.json, storage-boundaries.json and hash-matrix.json are the final datasets.

## Root review follow-up: internal caller contract

The attachment helper's sole production caller is LocalStore::all (local.rs), whose input comes from memories.id PRIMARY KEY; duplicate IDs cannot appear in its output. Debug assertion and tests make that invariant explicit. Arbitrary duplicate-ID slices are not supported by this private helper. Original collect staged all decoding before modification; the new cursor may have modified earlier local rows when a later row fails. LocalStore::all propagates the error with `?` and drops its local output Vec without returning it, so no partial catalog is externally published. No claim is made that this private helper is transactionally atomic for arbitrary supplied slices.

A root-reviewed follow-up decodes all three selected columns on every row before matching the snapshot. Thus malformed artifact data still causes an error even for absent/stale snapshot rows; skipping unrelated artifact decoding would have weakened previous failure behavior. Source checks, ordering, missing-artifact behavior, and output ownership remain unchanged. This follow-up's tests and precise commit are appended after the exclusive release benchmark slot is available.

## Full production-release CLI freshness acceptance

Candidate code through 2ffba0149d1876105040c1f1644ea774828b5f2f; real `cargo build --release --offline -p respire --bin rsrs -j4`, default features and pinned SDK. Reviewed storage decoding/caller test still 31/31 passed. Baseline binary SHA256 030d91b704b8b1b9782cf6152a6775de0a69d7ea52d0570b7d1fe17a1a664b95; candidate b125aa90801532347e93e0ebaf65bc9f5160306f584c5f734c93cff3a5633321. Baseline 48,435,232B, candidate 48,437,504B.

Real CLI `status --json`, normal host mode, explicitly installed matching runtime binary, no lifecycle replacement, independent empty profiles, no model. Three alternating rounds × 20 commands. Unique-PID union of runtime family plus current client sampled every 2ms; no RSS of a parent added twice. All 120 commands succeeded and runtime PID remained unchanged.

- Family sampled peak PSS: 76.88 → 31.44MiB; RSS 88.02 → 42.26MiB.
- Median 108.14 → 74.69ms; P95 119.68 → 85.45ms; P99 148.93 → 102.99ms.
- Client CPU per 20 calls: 2.076 → 1.415s.
- Runtime idle PSS after clients exit: 18.25 → 18.64MiB. No claimed steady runtime/model gain from streaming executable hashes.

`memory-revision` was separately run as a negative control: its intentional read-only path bypasses ensure_daemon, so its ~6–7ms/30MiB family result is not evidence of the hash change. Preserved as full-cli-revision-control-results.json. The actual freshness data are full-cli-hash-results.json with every result/latency.

Real-M3 acceptance is detailed below. All three model hashes were revalidated: ONNX 0826f8c1ab9edf1801db86c61919d4d108e8bfc0b809ec823ad366882ff0b77d, owned CPU ORT 7ff152e912bc234f5c90e4012f99897a7b2ce180f016db2321304057756b64ff, tokenizer 6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790. No downloads or new accounts. Generated 1,000 unique fixed-seed plaintext bodies with 50%192B/30%384B/15%768B/5%1536B distribution; ciphertext total 1,503,220B (min1080/max3770); all IDs/owners synthetic, zero initial artifacts. Real runtime creates every artifact. SQLite backup, not copying only a WAL-backed .db, is used for snapshots.

## Real M3 1k rebuilt A/B (completed)

Each run starts from the same pending-only synthetic SQLite snapshot and really embeds all 1,000 distinct bodies. Both ended with 1,000 distinct artifacts; 31 decoded recall JSON values match exactly (including entry fields, ordering, and scores), and reembed validation reports zero new rows. CLI release binaries/SDK/model hashes remain those above. Warm queries are 3 rounds of 10; one process per variant, so small timing differences are not a demonstrated model optimization.

| Variant | Phase | Host PSS/RSS MiB | Worker PSS/RSS MiB | Family PSS/RSS MiB |
|:---|:---|---:|---:|---:|
| baseline | post_index_idle | 16.98 / 21.93 | 911.27 / 916.30 | 928.25 / 938.23 |
| baseline | warm_idle | 25.30 / 30.25 | 944.22 / 949.27 | 969.52 / 979.52 |
| baseline | index_readiness_validation_complete | 27.75 / 32.70 | 962.27 / 967.32 | 990.03 / 1000.02 |
| candidate | post_index_idle | 17.24 / 22.12 | 911.05 / 916.00 | 928.29 / 938.12 |
| candidate | warm_idle | 25.00 / 29.91 | 943.78 / 948.78 | 968.77 / 978.69 |
| candidate | index_readiness_validation_complete | 27.45 / 32.36 | 961.81 / 966.82 | 989.26 / 999.18 |

| Variant | Actual indexing s | Index family peak PSS/RSS MiB | Warm median/P95/P99 ms |
|:---|---:|---:|---:|
| baseline | 328.76 | 1450.45 / 1460.41 | 122.16 / 144.38 / 151.49 |
| candidate | 332.46 | 1450.78 / 1460.59 | 117.92 / 133.78 / 139.10 |

Conclusion: worker steady memory is essentially unchanged (~944MiB PSS, ~949MiB RSS) and the 500–600MiB target is not met. The measured CLI/transient savings must not be presented as model-resident savings. Health confirms real m3, 1,000 indexed candidates, zero lexical-only candidates/pending, one Core-owned immutable model owner (569,654,128B), two native lanes. The difference between model-file length and process PSS is not by itself an allocation attribution; full smaps were collected in a separate clearly labeled candidate-only indexed-start diagnostic for independent VMA analysis.

10k generation and indexed-start comparisons are complete, as detailed below.

## Real M3 10k indexed-start A/B, three process rounds

Generation once took 3319.63 seconds (55m20s), creating 10,000 actual distinct artifacts from the unique synthetic bodies. All subsequent processes used WAL-aware SQLite backups of that same completed snapshot. This is cold startup, recall, and readiness validation of a real indexed catalog, **not** a 10k full-rebuild A/B. Generation-history memory is not mixed into these comparisons. Process order was baseline, candidate, candidate, baseline, baseline, candidate; each ran one cold and 30 warm recalls. All 186 decoded recall responses match exactly, and every reembed validation returns zero new rows. All processes exited with status 0.

| Version | Warm host PSS/RSS MiB | Warm worker PSS/RSS MiB | Median/P95/P99 ms | QPS | Host/worker CPU s per 30 warm queries |
|:---|---:|---:|---:|---:|---:|
| baseline | 80.73 / 85.71 | 1160.78 / 1165.78 | 446.89 / 654.84 / 698.84 | 2.164 | 1.69 / 13.13 |
| original combined candidate | 80.61 / 85.52 | 1160.19 / 1165.20 | 438.70 / 676.52 / 814.46 | 2.162 | 1.78 / 13.10 |

Memory and CPU are medians across three processes; latency is pooled 90 warm queries/version, nearest-rank percentiles. CPU is user+system process delta between cold-complete and warm-complete; this excludes already-exited CLI clients. Same-time unique-family cold-recall peak PSS median is 1805.42 → 1804.97 MiB. These data do not establish improvement in model memory, QPS, or tail latency. The 500–600 MiB goal remains unmet.

### Post-readiness retention and split controls

An additional condition must not be concealed: immediately after reembed readiness validation, baseline worker PSS was 1160.49/1159.25/1159.58 MiB; candidate was 1249.38/1248.34/1158.95 MiB. Thus the original combined binary retained ~90 MiB extra in two of three processes, but not the third. A single pair's readiness peak difference did not reproduce: repeated baseline/candidate median family peak was 1446.23/1443.05 MiB.

We preserved every run, then split the changes and added fixed observations at command return, +2s and +10s. The clock starts after the reembed response, with absolute monotonic deadlines, not cumulative sleeps. Full process smaps are saved at warm idle and +10s. Neither model nor allocator settings changed. Each run repeats the exact same 31-query history and snapshot; all 217 further decoded responses match. Every runtime cleanup exited 0.

| Binary / run | Warm worker PSS/RSS MiB | Worker PSS/RSS at +10s MiB |
|:---|---:|---:|
| original baseline | 1160.85 / 1165.82 | 1159.34 / 1164.31 |
| hash-only, first | 1160.96 / 1166.55 | 1249.14 / 1254.73 |
| storage-only | 1160.94 / 1166.90 | 1159.78 / 1165.74 |
| combined, current source rebuild | 1161.98 / 1167.85 | 1183.39 / 1189.26 |
| original combined | 1160.18 / 1165.25 | 1158.67 / 1163.73 |
| same-worktree baseline rebuild | 1160.88 / 1165.82 | 1159.41 / 1164.35 |
| same hash-only SHA, second | 1159.75 / 1165.34 | 1159.27 / 1164.86 |

The high-retention hash-only case stayed high at +2s and +10s. The same hash-only executable did not reproduce this in a second process. All model commands use --client-only and bypass the freshness-hashing path; therefore this does not demonstrate that executing the hash patch causes the worker allocations. Nor is the observation specific to the storage patch. At this stage there is no established allocation-site causal attribution or proof of absence of regression. Do not treat non-reproduction as acceptance or infer a guaranteed ~90 MiB saving from a particular split. VMA comparison is read-only and separate from these measurements.

### Build and reproduction provenance

All split builds used the same worktree, SDK, default features and `cargo build --release --offline -p respire --bin rsrs -j4`. Only the two production source files were swapped against exact baseline commit 4549184; a shell EXIT trap restores both files. Pure-baseline production Rust sources had zero diff from the original baseline while building. That build reproduced the original baseline SHA byte-for-byte, despite the different worktree. Current combined source was retained unchanged after all builds.

- Baseline, original and rebuilt: 030d91b704b8b1b9782cf6152a6775de0a69d7ea52d0570b7d1fe17a1a664b95
- Original combined: b125aa90801532347e93e0ebaf65bc9f5160306f584c5f734c93cff3a5633321
- Current combined rebuild: 29cd4917cfb65edaeb1af85b495bd3ce863e481547f85a21f16e2248e2152206
- Hash-only: 70204731854e0a1c19967cd0a0a068b9241a8c57c2ad72198be6131b42ae4f63
- Storage-only: edaed3b4dd2a593043925074610d873a8f32a98d71594ec3ebe7cc087d50e326

The original and current combined binaries differ by 32 bytes in file length and SHA. Their equivalence is not assumed; the report names both separately. Split source hashes, build logs, binaries and restoration scripts are preserved with the raw evidence. No compiler/model/allocator settings were altered to erase the retention result.

Reproduce a fixed-window case with `python3 scripts/perf/profile_cli_m3.py OUTPUT 10000 UNIQUE_VARIANT BINARY MODEL_DIR INDEXED_SYNTHETIC_PROFILE`. The script refuses an existing result directory, backs up SQLite including WAL, and cleans up its own runtime. `python3 scripts/perf/summarize_cli_m3.py OUTPUT` checks all completed reports, compares entire decoded query outputs and emits separated PSS/RSS, latency, CPU and fixed-window data. Raw evidence includes m3-run-10000-indexed-*/report.json, m3-run-10000-fixed-*/report.json and corresponding smaps; model files and synthetic session material are not committed.

### Read-only VMA attribution of the retained pages

The high-retention hash-only worker grows by exactly 90,296 KiB (88.18 MiB) RSS and PSS from warm idle to +10s. The added pages are anonymous/private-dirty: an existing 64MiB-aligned VMA grows from 3,452 to 65,532 KiB resident (+62,080 KiB), a new similarly aligned VMA holds 28,184 KiB, and a small area adds 32 KiB. The largest 580,720 KiB resident VMA stays unchanged. In the same-SHA low-retention control, the worker instead changes by −496 KiB; baseline changes by −1,548 KiB. This supports system-heap allocation/release-history variation, not additional model-file residency. smaps cannot tell whether these heap pages hold live objects or allocator-retained free blocks; it proves neither recoverable bytes nor a leak. Core CPU-owned configuration already disables ORT arenas, prepacking and memory patterns; none was changed for this experiment. Allocation-site instrumentation would be required to close the remaining live-versus-free question.
