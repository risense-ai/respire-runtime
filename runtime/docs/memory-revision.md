# Client memory refresh contract

`rsrs memory-revision --json` probes an **already running local loopback runtime**.
It never starts/restarts a runtime, initializes a profile, unlocks a session, loads
an inference model, schedules background indexing, or scans memory rows. `RSRS_JSON=1` produces the same JSON.

```json
{"command":"memory-revision","status":"ok","summary":{"profile":"/resolved/profile","revision":"0123456789abcdef0123456789abcdef"},"items":[],"actions":[],"errors":[],"details":null}
```

- `summary.profile` is the CLI-resolved `data_dir` used for this exact database.
  Existing `rsrs.db` and legacy `onememory.db` follow the normal database resolver;
  ambiguous directories containing both are rejected, never migrated by the probe.
  Clients must not guess `~/.rsrs`, cache a profile path, or derive it from the
  active account name. Runtime profile ownership checks still apply.
- `summary.revision` is an opaque 128-bit random token, encoded as 32 lowercase
  hex characters. Compare it for equality only. It is **not** a timestamp, count,
  sync cursor, cloud version, content hash, or durable event identifier.
- Capability detection requires a successful, valid response, not the CLI version.
  Missing runtime/schema, old binaries, invalid tokens, and transport failures
  are errors. Do not replace an existing snapshot with empty data on errors.
- `--direct memory-revision` is a host-only, SQLite READ_ONLY probe of an initialized
  local database. It works without a runtime and does not acquire its writer lock.
  It does not initialize a missing/legacy schema. Client-only/sandbox mode refuses
  `--direct`; use the existing loopback runtime instead. GUI snapshots using RPC
  status/list should use ordinary `memory-revision` to keep all reads on one path.

## Refresh sequence

1. Read and validate `{profile, revision}`. Poll only this cheap probe.
2. When changed, obtain normal `status` and `list` snapshots.
3. Validate `status.summary.data_dir` and `list.summary.profile` against the
   revision's profile. The list identity is captured for its exact store connection;
   checking it prevents a profile switch A → B → A from accepting B's rows.
   Memory entries remain in `list.details`; the profile field is additive.
4. Probe again; publish the fetched snapshot only when both token and profile
   still match. Otherwise discard and retry with bounded backoff/coalescing.

A deliberate initial/manual status/list can perform the normal CLI initialization.
If the revision probe is unavailable, retain prior data, explain limited automatic
refresh, and permit manual refresh. Do not silently poll full memory dumps as a
fallback. An old running runtime may need a normal host-managed restart after a CLI
upgrade; this polling command will not take it over.

## Persistence semantics

Normal storage migration installs the token and triggers atomically, preserving an
existing token on subsequent opens. INSERT, actual content/identity/metadata/tree
changes, tombstones/restores, imported/synchronized historical rows (even at an
older timestamp), and physical DELETE/clear change it in the same transaction as
the mutation. Rollbacks restore both memory data and token. A newly created or
replaced database receives an independent token.

No-op updates, SELECTs, dirty acknowledgements, recall counters, query logs,
synchronization bookkeeping, and derived embeddings do not change the token.
The triggers update only the dedicated metadata value. They never rewrite memory
payload/ciphertext, `updated_at`, outbox rows, or synchronization revisions.

The token covers persisted memory content, not session credentials, workspace
settings, transient synchronization progress, or derived retrieval statistics.
Those UI surfaces need explicit refreshes for their own actions. As with every
optimistic snapshot, a later commit can occur after the final probe; the next poll
will detect it.

## Focused checks

With the pinned Rust/Core SDK prepared as in CI:

```sh
RSRS_CORE_TEST_MODE=1 RUST_TEST_THREADS=1 cargo test --locked -p respire_storage revision
RSRS_CORE_TEST_MODE=1 RUST_TEST_THREADS=1 cargo test --locked -p respire --test memory_revision
RSRS_CORE_TEST_MODE=1 RUST_TEST_THREADS=1 cargo test --locked -p respire --test net_rpc_http rpc_memory_revision
```

Fixtures use only temporary synthetic databases/profiles. The workspace's normal
`cargo test --workspace --locked` also discovers these tests.
