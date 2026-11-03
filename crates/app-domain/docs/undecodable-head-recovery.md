# Controlled recovery from an undecodable current revision (pending acceptance)

## Problem and scope

When the current remote revision is already applied but its payload cannot be decoded, pull records the remote head without advancing the local sync_base; the original take-incoming then required the two to be equal, so "finish the sync first" could not clear the block.

This branch only fixes the client-side recovery exit. It is based on official main at d5001f8 and lives on `fix/undecodable-head-recovery`. It is submitted as a draft pending acceptance; nothing has been deployed, and sync-resolve / sync-restore have not been run against real memory. The Rust and real-service acceptance gaps are described below, and committing the source must not be read as a successful recovery.

## Behaviour

- The epoch check, the head check and op creation happen in one SQLite Immediate transaction.
- Only when the persisted head carries a decode error, is still unreadable, and the user explicitly chose take-incoming may the undecodable head be replaced; merge keeps rejecting it.
- The overwrite is refused when local dirty state, pending ops or a recovery op that can still be sent exist.
- A candidate must still pass the existing decryption and field parsing; a valid deletion candidate keeps its delete intent. An invalid candidate rolls the whole thing back.
- Only before the op's first committed transaction is the new op's base_rev set to the head the user reviewed; sync_base keeps the last genuinely applied revision. The existing server-side revision comparison and the restore_op_id protocol are then used, with no new server endpoint.
- The original memory ID, the bad revision and the candidate history are preserved. The new table sync_recovery_intents stores only the epoch, the candidate revision, the reviewed head and the op_id as a cross-retry idempotency key -- never the body or keys.
- Repeated calls for the same recovery request reuse the original op; a server rejection never mints a new op_id automatically. A retried take-incoming that was already processed creates no further revision.
- sync-reset invalidates old ops: an old recovery request fails explicitly, and after the new head is reviewed a stale association no longer blocks a new recovery. Do not treat sync-reset as the fix for this problem.
- Local queueing or an applied upload is not a resolved conflict; processed still waits for the existing server-side resolution receipt.

## Verification status

Done:

- Rust syntax/format checks on the changed files and a whitespace check on the git patch.
- Validated with the SQL from the source and an in-memory SQLite: initialisation is repeatable; dirty protection; a new op changes the baseline while keeping sync_base and history; transaction rollback; the idempotency key survives failure; a duplicate key is rejected; a reset old op is not reused.
- An independent code review, which fixed a false success report from the idempotent early return after reset.

The Rust regression cases the original commit added (actually executed during maintainer acceptance):

1. Bad head plus a good candidate recovers, and a repeat of the same request queues idempotently.
2. Content applied but still awaiting the resolution receipt, then an idempotent retry after the full receipt.
3. Head and epoch changes, and merge rejection.
4. Protection of pending and dirty-only local changes.
5. A readable but not yet applied head still requires a sync first.
6. A bad candidate rolls the transaction back.
7. A simulated server-side concurrent conflict keeps the unresolved state and does not add a conflict on a repeated request.
8. After a same-epoch reset an old recovery retry is explicitly invalidated and creates no extra op; covers pending, applied and already conflict_saved content receipts. The old incomplete resolution association is invalidated, the op history is kept, and the new head can start a new explicit recovery.
9. A new client with no applied baseline can still recover explicitly.

Entry points (requires a matching Core SDK and the Windows build tools configured per the repo docs):

```text
cargo test --locked -p respire_storage transport::local::conflicts::tests -- --test-threads=1
cargo test --locked -p respire_storage transport::local::sync::tests -- --test-threads=1
```

At the original commit stage there was no matching SDK and no complete dependency cache, so the Rust tests could not run then. Maintainer acceptance used the verified official SDK `1.0.2-dev.12` (source `77fc566e47c6c283c0bde9192528debad23d6248`) with offline dependencies and ran the whole storage suite in an isolated HOME/db directory with no credentials: 53 passed, including the 9 recovery regressions above. The extended negative reset case really failed before the fix and passes after it.

The reset fix only cancels incomplete resolution outbox associations bound to a recovery intent; it deletes no ops, candidates, bad revisions or already processed resolution history. Neither the receipt simulation here nor a local Rust pass is acceptance of real server-side concurrency.

## Follow-up acceptance and open items

- Complete the Rust tests above in an environment with the official matching SDK, then verify real server-side CAS, receipt-loss retries and concurrent updates on an isolated account.
- Do not replace the current Runtime before that passes; an actual recovery needs an independent backup and user confirmation. The current old Runtime does not acquire this fix merely because the source branch exists.
- The root cause of the initial head decode failure is still unknown. This change read no original ciphertext and changed no payload compatibility rule.
- Staged parsing diagnostics (stage, type, field location) belong to a later crypto-layer improvement; this branch only distinguishes recovery precondition errors and adds no low-level error output that could leak bodies or keys.
