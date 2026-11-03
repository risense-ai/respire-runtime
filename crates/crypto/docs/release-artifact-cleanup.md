# Temporary release artifact cleanup

GitHub's official [upload-artifact retention input](https://github.com/actions/upload-artifact#retention-period) accepts whole days, with a minimum of **one day**. This repository already sets `retention-days: 1` on artifact uploads. A fraction such as `1/24` is not a supported one-hour setting.

The dedicated cleanup workflow adds best-effort deletion **at least one hour after publication and all consumers have finished**, with one-day native expiry as the fallback. It scans every 15 minutes, away from the top of the hour. GitHub documents that [scheduled workflows can be delayed or dropped](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule); this is not a strict wall-clock one-hour expiry. Queue contention, incomplete evidence or an API failure can delay cleanup until native expiry.

## Scope and authorization

The workflow uses the existing ephemeral `GITHUB_TOKEN`. Only its dedicated job requests `actions: write`, needed for `DELETE /repos/risense-ai/respire-cli/actions/artifacts/{artifact_id}`. Repository contents remain read-only. There is no new secret, `write-all`, Release edit/delete, npm mutation, tag operation, cache cleanup or cross-repository operation. Merging the reviewed workflow activates this permission and schedule; creating a draft PR does not deploy it.

Only **new** `scoped-ready` or protocol-2 `scoped-accepted` receipts containing `cleanup_policy: {schema: 1, after_consumers_seconds: 3600}` opt in. Historical receipts without this marker are not retroactively authorized. Manually approved historical batches remain separate, frozen ID lists: new artifacts are never appended to those approvals.

The cleanup workflow checks out the reviewed default branch with credentials persistence disabled. It never checks out a release event's potentially different source ref or executes downloaded artifact code. Receipt ZIPs must match the GitHub SHA256 digest, contain exactly the expected single JSON member, fit the compressed bound and produce at most 1 MiB of uncompressed JSON. No artifact is extracted into the checkout.

## Completion barrier

Before selecting anything for deletion, the policy requires:

1. The exact source Release workflow/repository/attempt is completed successfully. A completed alias child is insufficient while the parent is still in `awaitAlias`.
2. Every lane in the receipt's declared regression inventory and the selected publisher succeeded; all parent jobs are terminal. New inventories require four native upgrades, three system sweeps, two native migration fixtures, two migration joins and API success. Historical receipts without the declaration retain the original four-native/three-system/API inventory. Recovery paths without these proofs keep the native one-day fallback.
3. The exact tagged Release is public, its commit matches the scoped source, and every public asset name, size and digest matches the publication receipt.
4. All alias consumers created since that parent started are terminal, including duplicates and manual publishers. This deliberately conservative fence can postpone an older cleanup while an unrelated later alias is active.
5. For protocol 1, at least one matching alias run has the exact bindings, successful publisher and native public-install digest. For protocol 2, an alias acceptance is insufficient: all independent `Verify public npm publication` consumers must be terminal and at least one matching successful verifier job must provide exact public content and isolated-install proof. Missing, failed or invalid proof stops cleanup.
6. An hour has passed since the latest parent completion, public publication, alias/background consumer completion, verified report time or selected artifact creation. An early accepted artifact timestamp cannot start the grace period while background readers remain active.

The cleanup job shares the existing `npm-rsrs-cli-publication` concurrency group with both alias publisher jobs. Before **each** deletion it rechecks the entire parent/alias/background consumer snapshot, current attempt, public Release/tag and exact artifact ID/name/digest/size/run identity. A new consumer, rerun or metadata change stops the batch. A historical attempt whose temporary artifacts have already expired cannot be assumed to support a later rerun: rebuild in a new validated run instead. GitHub offers no transactional lock across a human starting a rerun and an artifact DELETE; the shared consumer lock, grace interval and per-item fence reduce that race, rather than claiming an atomic server-side guarantee.

## What is deleted

For an opted-in source run, the explicit allowlist covers its source manifest's platform build packages, temporary npm packages (including
`npm-publication-packages-RUN-ATTEMPT`, the parent's validated launcher handoff), npm validation, API/upgrade/sweep/migration/concurrency evidence, and exact source-attempt scoped receipt. Matching alias and background verification receipts are selected only after validating their source and final installation proof. Protocol-2 accepted summaries and scoped submission journals are also allowlisted. Unknown alias submission journals retain the one-day fallback. Unknown names, unrelated CI workflows, other source runs and SDK delivery files are preserved.

Payloads/evidence are removed first, alias receipts next, and the parent scoped receipt last. This preserves proof during partial progress where possible. The policy does not delete workflow runs or their logs. Detailed artifact-only test evidence and old download inputs are lost after cleanup; the Release, npm versions, run conclusions, audit logs and job summary remain. Historical manual alias recovery may need a new validated run after its temporary receipts expire.

An ambiguous DELETE is not automatically retried. Each subsequent invocation inventories again; already absent IDs are not deleted again. Every attempted deletion records source run/attempt/version, artifact ID/name/size/digest in workflow logs and the job summary, then verifies HTTP404. An API or verification failure stops the workflow. If cleanup stops after the final alias receipt but before the parent receipt, the remaining small receipt may need to reach its native expiry rather than bypassing proof checks.

## Operation and validation

Manual dispatch defaults to dry-run. The command is:

```sh
GITHUB_REPOSITORY=risense-ai/respire-cli node npm/scripts/cleanup-release-artifacts.mjs --dry-run
```

Only the approved scheduled workflow or an explicitly selected apply dispatch uses `--apply`. No live apply run was used to test this policy before review. Policy tests use simulated APIs; ZIP tests run the real bounded archive reader. A live read-only dry-run confirmed that the historical DEV1/DEV2 receipts are not opted in and selected no deletions.

The new policy and test paths are excluded from the native Release push trigger, alongside the already excluded publication helper, workflows and docs. Merging this storage-policy-only change does not allocate a DEV or trigger a native Release. Normal CLI CI still runs the cleanup and publication tests.

## Existing PR125 publication gate audit

At exact commit `2bc4906c80016f42e4e905a0db28d54dd3e3d81c`, `publish` still has `needs: [plan, validate]`. Its separate step at lines 541–568 blocks before publication until four native, three system and one API regression succeed, for push/latest or explicit `full_regression_before_publish`. Manual DEV dispatch without that input is not an unconditional full-regression path. Cleanup does **not** equate entering or finishing that publish job with finishing the whole Release: the full parent-run and cross-run consumer fence above is independently required. This change does not alter that gate.

Actions storage reclamation can be delayed by accounting recalculation. It does not repair the separate `uploads.github.com` HTTP401 authentication failure and does not retry that upload.
