# Session import (`rsrs extract`)

Extract the process data local coding agents already save on disk and convert it
into encrypted rsrs memories. Discovery mirrors the cross-platform
`coding-agent-sessions` finder: each platform scanner normalizes its own store
into one common session shape, which is then turned into a memory and sealed
through the runtime store.

## Supported platforms

`codex`, `opencode`, `claude`, `senpi`, `oh-my-pi`, `gajae-code`, `openclaw`,
`droid`, `amp`, `gemini`, `kimi`, `qwen`, `codebuff`, `roo-code`, `kilo-code`,
`cline`, `kodu`, `cursor-cli`, `aider`, `kilo-cli`, `hermes`, `goose`, `crush`,
`zed`, `kiro`, `aside`.

Data sources per platform:

| Platform | Store |
| --- | --- |
| codex | `$CODEX_HOME/state_*.sqlite` (`threads`, `thread_spawn_edges`) + `sessions/**/rollout-*.jsonl` |
| opencode | `opencode.db` `session` table, else `storage/session/**/ses_*.json` + `messages/*/parts` |
| claude | `~/.claude/projects/**/*.jsonl`, `transcripts/*.jsonl`, `subagents/**/agent-*.jsonl` |
| openclaw / droid / amp / gemini / kimi / qwen / codebuff / roo-code / kilo-code / cline / aider | per-platform JSON/JSONL/VS Code `globalStorage` stores |
| cursor-cli / kodu / kilo-cli / hermes / goose / crush / zed | per-platform SQLite stores |
| senpi / oh-my-pi / gajae-code | `~/.*/agent/sessions/**/*.jsonl` (+ profile dirs) |
| kiro / aside | per-platform JSON/JSONL + SQLite index |

## Usage

```sh
rsrs extract --targets                 # list sources and whether a local store exists
rsrs extract --all --dry-run           # preview what would be imported
rsrs extract --id codex                # extract one source
rsrs extract --all                     # extract every detected source
rsrs extract --all --since 7d --limit 50
rsrs extract --tui                     # interactive picker with a progress bar
rsrs extract --all --importance trivial --kind context --parent <id>
```

Filters: `--cwd`, `--model`, `--session`, `--since`, `--limit`,
`--include-subagents`. Conversion: `--kind` (default `context`),
`--importance` (`important` default, or `trivial`), `--parent`.

`--force` only re-imports sessions already recorded in the cursor; it never
overrides the store's protection of user edits. `--tui` runs the interactive
picker and is mutually exclusive with every option above and with `--json`
(combining them is an error). `--limit 0` imports nothing.

## What gets stored

One memory per session by default:

- title: `<Platform> session <first request>`
- body: the mandatory cause/action/result three-marker form, carrying the
  working directory, model/provider, first and last user requests, token usage
  and any subagent linkage
- `importance`/`kind` from the flags; `device`/`user` auto-filled
- **extract is a raw ingester**: entries land as roots (or under `--parent` if
  given). Organizing is a separate, AI-driven tidy pass — after extracting, have
  an agent run the §3.8 tidy (`rsrs list --since-resort --json` → diagnose →
  `resort` / `remember --merge-ids`).

Re-running skips unchanged sessions through a cursor at
`<data-dir>/extract-state.json` (keyed by `platform:id` + `updated_at`). `--limit`
caps **new** imports per source per run (newest first; `0` imports none): when a
source exceeds the limit, the overflow is deferred, so repeating the run (or
raising `--limit`) pulls the older history next.

For `kilo-cli`, `hermes`, `goose`, `crush` and `cursor-cli`, the cursor records a
SHA-256 fingerprint of the imported summary (prompts, usage and metadata), since
SQLite WAL commits can leave the main database's modification time unchanged.
Legacy timestamp-only marks receive one refresh. Checkpoints and unrelated
sessions do not cause repeat imports; changed summaries receive a fresh memory
write timestamp while retaining source timestamps in the body.

Each session maps to a stable id (UUIDv5-shaped from `platform:id`), so a
re-import updates that same row instead of creating a duplicate. A re-import only
refreshes the body and timestamp: an existing row keeps its tidy parent and any
edited title, and a row the user deleted is skipped rather than resurrected.

An existing row with pending local changes is protected from all import refreshes,
including `--force` and SQLite content changes. The check runs inside the chunk
write transaction; rejected refreshes do not advance the session cursor. After
synchronization clears the pending changes, a refresh may replace the body with
the source summary while continuing to preserve its edited title and parent.

Import embeds every session first (that step holds no database lock), then writes
in small committed chunks and persists the cursor after each chunk, so the write
lock is never held across embedding and a failure resumes near where it stopped.
Bodies, titles and the `--json` preview are scrubbed best-effort for PEM private
keys, `key[:=]value` (including quoted/JSON) secrets, `--flag value` secrets and
known token prefixes before storage; this is a safety net, not a guarantee.

## Boundaries

- Reads are best-effort and never panic on malformed stores.
- Writes go through the runtime write path (`MemoryEngine::seal` + batch import
  + one auto-sync), so `extract` is a write command: refused in read-only mode
  and while memory is off.
- Progress is a determinate stderr line (`done/total (pct%)`); `--json` keeps
  progress silent. The TUI shows a `Gauge` and runs extraction on a worker thread.
- `extract --tui` needs a real TTY and rejects any extraction option (and
  `--json`); bare `rsrs extract` opens it only on a TTY.
- Deviation from the reference finder: `opencode` is read from its documented
  default database/file paths rather than by invoking the `opencode` CLI.

MCP exposes the same capability as the `memory_extract` tool: a batch write that
imports up to `limit` newest sessions per source and auto-syncs, so it requires
`confirm: true` (or `dry_run: true` to preview), and `limit` must be a
non-negative integer.
