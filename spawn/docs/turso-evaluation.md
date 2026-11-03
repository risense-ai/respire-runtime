# Turso storage assessment

Reviewed 2026-10-18. Decision: evaluate separately; keep SQLite and the existing encrypted sync protocol for this DEV release. No Turso dependency or production database migration is included.

## What changes, and what does not

The client already embeds SQLite through `rusqlite` (`crates/storage/Cargo.toml`) and stores separate account libraries. It does not require a separate SQLite server. The cloud service currently depends on PostgreSQL (`respire-server/service/Cargo.toml`); replacing the CLI storage engine would not replace the cloud database, account authorization or sync service.

Turso Database is the newer Rust engine; libSQL is the older SQLite fork. Turso Cloud and Turso Sync are additional products. Evaluate a pinned combination, rather than assuming every feature exists in every engine/SDK version. The [engine README](https://github.com/tursodatabase/turso/blob/main/README.md) describes current SQLite compatibility gaps, experimental features and the remaining path to 1.0.

| Requirement | Assessment |
| --- | --- |
| Embedded account files | Feasible, but SQLite already provides this architecture. File isolation still needs account ownership checks, backups and lifecycle management. |
| Concurrent local writers | `BEGIN CONCURRENT` provides optimistic concurrency with conflicts/retries. It does not eliminate application transaction design. |
| Several processes opening one file | [Multi-process WAL](https://docs.turso.tech/sql-reference/multiprocess-access) is experimental. Windows currently ignores the flag. Writers remain serialized; this mode cannot currently be combined with MVCC. Shared network filesystems are not a cross-device sync mechanism. |
| Offline multi-device sync | [Turso Sync](https://docs.turso.tech/sync/usage) supports local writes and explicit push/pull through an authenticated remote service. It is not unlimited synchronization. Database provisioning, authorization, bandwidth, storage and conflict policy remain necessary. |
| Conflict safety | [Conflict resolution](https://docs.turso.tech/sync/conflict-resolution) uses last push wins. An old offline edit pushed later may win; this differs from ordering by the original edit time. Test edits, deletes, parent changes and retries before adopting it. |
| Native vector search | The new engine documents exact vector search; approximate vector indexing remains on its roadmap. libSQL vector indexing is a different implementation. Benchmark against the existing Core SDK before choosing a backend. |
| Branches | [Cloud branches](https://docs.turso.tech/features/branching) are separate database instances. Data/schema merging remains an application/migration responsibility, and branches consume database quota. |

## Security and compatibility gates

The local store intentionally contains plaintext search projections, audit previews and private retrieval artifacts which the current encrypted transport never uploads (`crates/storage/src/transport/local.rs`). Replicating the entire local database would change that security boundary. At-rest encryption is not a substitute for end-to-end encryption. A sync candidate must separate encrypted, portable records from local indexes, diagnostics and device state. Do not upload the current database wholesale.

Inventory the actual SQL and `rusqlite` surface first: schema migrations, WAL/busy handling, transaction/savepoint behavior, backup API, triggers, conflict/revision tables and crash recovery. A compatible file format alone does not make the Rust APIs interchangeable. Retain the private Core SDK boundary and measure its integration; native SQL vector support alone is not evidence of equivalent retrieval quality.

## Proposed sequence

1. Finish the account/server migration and idempotent import fixes on SQLite. These are application identity and import bugs, independent of the engine.
2. In a separate experiment, pin Turso Database/SDK and use disposable database copies. Run the existing storage checks on Windows, macOS and Linux. Compare correctness, latency, memory, file size, startup and recovery; record actual measurements.
3. Independently evaluate two offline clients plus a disposable remote. Cover same-record edits, delete/edit conflicts, parent cycles, repeat uploads, token revocation, schema upgrades, interrupted push/pull and backup restoration. Require an explicit acceptable conflict policy and a cost/operations model.
4. Only after both gates pass, propose a reversible storage migration: retain the original SQLite file, copy into a new engine file, verify decrypted records/relationships/counts, then switch selection. Keep engine replacement and sync-protocol replacement as separately reviewable changes.

No prototype benchmark, production compatibility certification or cost estimate has been performed in this assessment. The simplest current option is to retain SQLite while fixing the user-facing workflow.
