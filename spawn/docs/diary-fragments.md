# Standalone diary fragment retrieval

A diary can hold proposals, failed attempts and unconfirmed conclusions. This entry point only offers locatable historical references: it does not change normal `recall`, never promotes a diary automatically, never rewrites main memory, and never treats wording such as "verified" in the body as proof that a fact is trustworthy.

## Command and response

```text
rsrs --client-only --json diary-search "IoT integration" --mode hybrid --limit 5 --max-chars 4000
rsrs --client-only --json diary-search "bridge" --mode lexical --limit 5 --max-chars 4000
rsrs --client-only --json diary-fragment <source-id> <fragment-id> --neighbors 1 --max-chars 4000
```

The MCP equivalents are `memory_diary_search` (query, mode, limit, max_chars) and `memory_diary_fragment` (source_id, fragment_id, neighbors, max_chars). Read-only mode allows reading while paused mode still refuses it; the existing authorization policy is unchanged. An older Runtime that does not know the new commands errors out, and the caller should state plainly that the capability is not installed rather than wrapping the old whole-day output as fragment-level semantic retrieval.

`details.items` in the JSON envelope is the result. Each item carries:

- `source_kind=diary`, `evidence_state=reference`: the origin and the conservative reference state, not a verification credential.
- `source_id`, `fragment_id`, `source_version`: the original memory ID, the fragment locator ID and the SHA-256 version fingerprint of the current encrypted record.
- `date`, `title`, `project`: the local date and bounded-length provenance.
- `start`, `end`: a half-open range of original-text Unicode scalars, not UTF-8 bytes or JavaScript UTF-16 indices.
- `text`, `truncated`, `score`: the bounded body, whether it was truncated, and the ranking score. A score means relevance only, never trustworthiness.

`details.semantic_ready` and `pending_fragments` distinguish a complete semantic index from one still to be built; when the index is missing, lexical hits are still returned and the existing background indexer is notified. Queries never generate all vectors for a whole year of diaries in the foreground. A fragment read includes at most one neighbour on each side: the target fragment gets its budget first and neighbours take the remainder; output restores original order, and an omitted or truncated neighbour sets `truncated=true`. A public locator ID is bound to the source version and the Unicode range; any change to the original text or metadata (including an append at the tail) invalidates the old locator and requires a new search. Internal index keys are bound separately to fragment content and retrieval metadata so unchanged fragments can reuse derived artifacts. Neighbours are the immediately adjacent earlier start position and later end position in the source, including the 80-character overlap; the dynamic lexical window also extends left and right by the same rule and never skips an adjacent overlap fragment.

`limit` is 1-20 and `max_chars` is 512-12000, defaulting to 5 and 4000. The budget bounds the character count of the compact-serialised `details`, including fragment metadata and JSON escaping; the outer standard envelope has its own fixed overhead. This is a character budget, not an exact token count. With too small a budget there may be no result that fits, and `truncated=true`. Non-JSON mode prints the same compact bounded result directly.

## Retrieval and the derived index

Standalone retrieval scans only the valid `trivial` diaries of the current account and never reads deleted records. Lexical retrieval first matches every query word against the authoritative full text, then maps hit positions to original-text Unicode scalars and selects a bounded window; it never misses a long keyword at an index shard boundary and never checks only the first 500 characters. Multiple words may match in the title, project or body of the same source, and fragments within budget do not guarantee every hit of the full text. A long record is split at most every 800 Unicode scalars, preferring line breaks, keeping an 80-character overlap. A lexical query still scans every diary locally, so disk and local compute cost grows with the data; the full diary is never returned to the chat model.

The semantic path calls the public Core SDK's BGE-M3 `prepare`, `query` and index-status interfaces. The background indexer updates the derived cache under the existing cancellation, account-switch and foreground-yield mechanisms. `diary-fragments-v1.db` in the current account's data directory stores only source versions and opaque Core index locators, never extra diary plaintext. Core derived artifacts stay managed by its existing local index mechanism. Add/modify/delete, model generation changes and invalidated artifacts trigger a rebuild; after the last diary is deleted or promoted the empty source cache can be cleared without loading the model. Lexical mode never opens the derived cache; hybrid mode returns `semantic_ready=false` and the pending count when the cache is missing or corrupt. A corrupt recognised derived database is moved to a diagnostic copy and rebuilt in a controlled background commit; symlinks, hard links and unrelated databases are refused. Model preparation happens outside the lock, and the durable commit is validated by the runtime write gate, lifecycle ownership, cancellation-confirmation lock and main-database revision transaction together, without touching original memory, sync history or diary parents.

The existing `diary --contains` is a whole-store time chain (main memory plus diaries) and differs from the diary-only entry above. It now decrypts and filters the full text and returns up to 500 characters of summary around a hit; the existing date, ordering and count semantics are unchanged.

## Current verification boundary

Open source can change segmentation, CLI/MCP, response bounds, caching and SDK call orchestration; it cannot edit the closed Core's internal vector algorithms or model implementation. A build must provide the matching SDK pinned by the repo and cannot bypass manifest validation.

`crates/app/src/diary_tests.rs`, the MCP tool tests and the runtime routing tests cover full-text matching, Unicode positions, the JSON budget, source invalidation, cache corruption/rebuild and the cancellation-commit boundary. Lexical and commit-failure tests use explicit test providers and cannot stand in for real semantic retrieval results. The matching SDK's real BGE-M3, CLI/Runtime/MCP round trips, background concurrency/restart and cross-account isolation must be run separately; a full release also keeps the existing autostart, real-model, upgrade and migration gates. Scale measurements use sanitised synthetic diaries and describe only the timing and memory of that fixture, not a real user's year-long store or retrieval benefit.

## Re-runnable acceptance

In an isolated test environment with the matching SDK prepared per the lock file and a verified CPU model, build the current `rsrs` and the probes and run the real-model cases (without setting `RSRS_CORE_TEST_MODE`):

```sh
cargo build --locked -p respire --bin rsrs --example feedback_contract_probe --example ablation_bench
RSRS_ENGINE=cpu RSRS_M3_DIR=/path/to/verified/model \
  target/debug/examples/feedback_contract_probe --diary-only
```

The probe refuses test providers, reuses the CPU model size and SHA-256 verification, and uses a temporary store, synthetic sessions and synthetic diaries to cover the missing-index lexical fallback, a semantic query with no lexical hit, CLI/runtime/MCP stdio round trips, restart, read-only reads, refusal in off mode, locator invalidation after an append and cleanup after deletion. The full `feedback_contract_probe` also runs these diary checks after the existing feedback and both benchmark paths, so the existing four-platform token-free model acceptance covers the new entry points. A single paraphrase hit is a functional check only and says nothing about diary retrieval set benefit; the broader `cycling equipment maintenance` returned no candidate under the current synthetic fixture and existing Core thresholds, and that result was not hidden by lowering a threshold.

`diary_scale_probe <chars-per-diary> <count>` uses an explicit synthetic test provider and measures lexical scanning only, not modelling quality. The 2026-10-27 cloud debug build measurements below are one run each: the time is the sum of three consecutive searches after the store was built and RSS is the peak of the whole fixture process.

| Synthetic scale | Original PR `611b4da`: time / RSS | Fixed build: time / RSS |
| --- | --- | --- |
| One 100k-character diary | 194.7 ms / 15,120 KiB | 195.6 ms / 15,300 KiB |
| One 1M-character diary | 2,078.7 ms / 31,212 KiB | 1,881.9 ms / 31,084 KiB |
| 365 diaries of 5,000 characters | 4,028.2 ms / 21,196 KiB | 3,748.5 ms / 19,212 KiB |

The test machine had parallel work, so there is no multi-run confidence interval; the two builds also differ in boundary/dedup/budget results (the multi-day fixture returned 4 items originally and 5 in the fixed build). These numbers only show that the given scale really ran; they do not claim a stable speed-up and certainly are not a reproduction of the original research set. The fixed build still decrypts the full text and scans linearly; avoiding per-fragment cloning of a whole year's bodies and repeated whole-store reads is not the same as eliminating all large-store cost.
