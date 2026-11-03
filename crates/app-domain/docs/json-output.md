# CLI JSON output contract

Use `rsrs --json <command>` and parse stdout as one JSON envelope. Check both
the process exit code and `status`; a pending decision or warning is not a
completed write. Human progress is never part of the stdout JSON document.

The envelope fields have distinct purposes:

| Field | Contract |
| --- | --- |
| `command`, `status` | Command identity and `ok`, `warn`, `fail`, `skip`, or `pending` state. |
| `summary` | Command-specific machine data. Preserve JSON boolean, number, array and object types. |
| `details` | Command-specific public payload, described below; `null` when no payload is returned. |
| `items` | Human display rows. `items[].value` is a **display string**, not a typed machine field; do not use its truthiness for configuration. |
| `actions` | Suggested next actions; these are not automatically executed. |
| `errors` | Diagnostics. Check the status as well, since warnings can also carry diagnostics. |
| `related` | Related memory records, when the command supplies them. |

For `status: "fail"`, `errors` always contains a nonblank diagnostic. Read it
from stdout's envelope even when stderr is empty. Argument parsing errors keep
a concise first-line diagnostic in `errors` and the full diagnostic and usage in
`details.usage`. Existing exit codes remain intact: a warning or pending result
can exit with code 2 without being a failed command.

Payload locations are intentionally command-specific for compatibility:

| Command | Machine payload |
| --- | --- |
| `list`, `recall`, `tree`, `inject --targets` | `details` is an array of result rows. Recall rows include ranking metadata. |
| `show` | `details.entry` is the decrypted public entry; `details.ancestors` and `details.children` provide context. |
| `remember` with `summary.action` equal to `created`, `diary_appended`, or `merged` | `details` is the decrypted public entry actually written, with `details.id == summary.id`. |
| `remember` pending or vetoed | No completed-write entry is promised. Follow `summary`, status and actions. |
| `update` | `details` is the updated decrypted public entry. |
| `config`, `agent-config` | Typed configuration lives in `summary`; `details` may be `null`. |
| `space list` | `details` is an object containing `current_dir` and `spaces`. |
| `defrag` | `details` contains the command's cluster results. |
| `capabilities` | `summary.schema_version`, `summary.cli_version` and typed `summary.capabilities`. |

For example, `agent-config` may report `summary.memory_off: false` and
`summary.purge_days: 30`; the corresponding display strings in `items` must not
replace these typed values. Read and write payloads are public entries, never
sealed storage rows, ciphertext, nonces, encrypted embeddings or key material.

## Diary identity and explicit titles

In concise diary mode, an untitled `remember --importance trivial` creates or
appends to the daily activity track. A title consisting only of whitespace is
untitled. The returned ID and full payload refer to that daily track, including
previous events when appending.

A nonblank explicit `--title` creates an independent entry in both concise and
verbose modes, including for trivial memories. It preserves the supplied title
and does not append to or rename an existing daily track. `show <summary.id>`
returns the same public entry as the successful write receipt's `details`.

## Feature discovery

`rsrs capabilities --json` works before login and with no initialized profile,
runtime, model files or downloads. It describes this CLI's supported interfaces,
not the selected account's permissions or the model's readiness. Schema version
1 reports `summary.capabilities.rerank: false` and
`summary.capabilities.model.install_rerank: false`: the cross-encoder reranker
and its installation command are retired. Clients should hide that installer
instead of parsing help text or attempting the removed command. Retrieval uses
the current Core SDK's retrieval pipeline; this probe does not claim an
equivalent replacement cross-encoder or a measured retrieval-quality gain.
