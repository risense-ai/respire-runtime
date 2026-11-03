# Repository instructions

## Preserve mandatory prompt constraints

The mandatory workflow in `docs/respire-lite.md` is the default injected policy. `docs/respire.md` is the complete policy. `crates/app/src/inject.rs` also contains the size-limited WorkBuddy reference block. All three are release behavior, not disposable documentation.

- Do not remove, weaken, defer, or replace mandatory rules with vague summaries to save tokens. Preserve the trigger, required action, prohibition, exception, and completion check. Loading `rsrs prompt` later does not compensate for a missing default rule.
- Keep the three anchors: recall before answering/acting, archive each round's findings before finishing, and recall immediately after errors. The first tool action of each round is recall, subject to mode/authorization. Each new user message resets the recall gate. Do not require reading the full policy every round; consult its details when needed.
- Preserve title-first JSON retrieval, selected-record full reads, device checks, alternate keyword searches, evidence in the answer, and honest reporting of failed recall or unverified facts.
- Preserve error-time recall as the next tool action, hypothesis-based investigation, bounded retries, repeat recall after two attempts without progress, and a concrete blocker report.
- Preserve update > merge > attach > new record; full candidate reads, no unresolved candidate output, no duplicate sibling records, taxonomy/tree search and `--parent` for new important records. Diary entries remain exempt from parent/taxonomy requirements.
- Preserve event-based titles and simultaneous `--title` for body updates, the canonical English body markers with legacy Chinese read compatibility, one fact per record, persistent nonempty backups before long rewrites/merges, descendant checks and read-back verification.
- Preserve important/trivial classification, the prohibition on downgrading reusable findings to avoid tree placement, credential inspection, confirmed task trigger conditions and due-condition checks. Do not claim numeric importance, automatic credential scanning/redaction, or automatic reminders unless implemented and verified.
- Preserve the twelve work rules, anti-shortcut rules, scope/authorization boundaries, dependency ordering, actual validation including relevant failure paths, and the final recall/storage/error gates, with one bounded archival pass and explicit refused/pending/unknown outcomes; never replay an uncertain write or recurse on recall failure. Read-only and off modes must retain their explicit no-write/no-memory exceptions; mandatory storage never grants extra authority.
- WorkBuddy's size limit permits a reference plus explicit mandatory gates, not deletion of those gates. Its mode-specific block must preserve the essential boundaries without forcing a full policy read each turn. Keep JSON examples and update-first deduplication consistent with the default policy.
- Keep current runtime security semantics, relationship compatibility checks, injection markers, taxonomy names, and existing user-owned content. Never import stale ports, product markers, or unsupported features from a reference prompt.
- Prompt changes require a before/after semantic comparison and existing injection tests, including stale replacement, preservation, idempotence and removal. Validate the actual packaged `prompt` and injection preview in an isolated workspace. Do not add tests unless the user requests them.
- A future reduction in these constraints requires explicit user authorization for the named rules. Record the reason and behavior impact in the change description. Routine refactoring, translation, formatting, or token reduction is not authorization.

## Prompt-strength contract

The default injection must stay a standing hard constraint. No one may delete or soften, on the grounds of trimming, translation, token saving or "the full text still exists elsewhere", the first-tool recall rule, the per-turn reset, recall-before-fix on a non-recall fault, the two-retry rule, the bounded per-turn archive in normal writable mode, update/merge/attach-then-create, deep search from the attach point, the title rule, backup re-verification, the twelve diligent-and-complete items, the anti-laziness general rule or the three gates around recall and store. Rule strength changes only with an explicit user authorization for that specific rule. Read-only/paused modes and the user-authorized boundary take precedence, and inventing product capabilities is forbidden.

## Reviewed prompt update

The English prompt revision removes compulsory full-policy reads every turn, not the normal-mode per-turn archival obligation. Preserve actual findings/process records, one bounded wrap-up pass, candidate-vs-saved and unknown-outcome distinctions, and read-only/off exceptions. A pure-Q&A storage exemption requires a separate explicit product decision; a third-party PR description does not authorize it.
