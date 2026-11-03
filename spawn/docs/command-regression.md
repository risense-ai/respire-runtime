# Existing command checks

`--json` keeps command errors in the result envelope. Invalid IDs, malformed or
inapplicable split/resort/deepen input, unknown restore IDs, diary association
targets, self/cyclic attachment, invalid grant roots, missing kick targets and
missing user-selected import/benchmark/share files use `reason: invalid_input`,
`details.error_type: user` and exit 2. Storage, transport and engine failures keep
`reason: runtime_error`, `error_type: runtime` and exit 1. Pending or warning
results also use exit 2; automation must read `status` and `reason`.

Host `space create`, `space use`, `space join` and confirmed `space remove --yes` coordinate
runtime shutdown and restart, preserve configuration and verify the resulting
profile. The active space cannot be removed. Sandbox clients cannot manage this
lifecycle. `update-check` uses an arrow only for an available upgrade; equal or
ahead builds report their state without offering a downgrade.

Current parser behavior and `rsrs --help` define the command contract.

| Scenario | Command |
| --- | --- |
| Version | `--version`, `-v`, `v`; JSON command `version` |
| Plugins | `plugin list`; `plugin test <EVENT> --payload <JSON>` |
| Causal chain | `chain <ID> --depth <N>` |
| Importance | `--importance important|trivial` |
| Isolated data | `RSRS_DATA_DIR=<path>` |
| Split | `split <ID>` preview; `split <ID> --go --spec <JSON>` apply |
| Tree maintenance | `tree-cure` report; explicit `--id` and `--parent` apply |
| Procedures | `run-log <ID> --status ok|fail|confounded|no_effect` (skill/knowledge only; other kinds return `status: skip`); `recall --intent auto|howto|fact` |

Plugins use the platform shell and do not inherit account-key variables. Explicit and
background sync share one persistent outbox. Foreground mutations wait for local
storage; the runtime performs network synchronization in the background. Explicit
`sync` waits for its captured queue boundary. Timing reports
must describe version, mode, sample and network conditions.

| Check | Scope |
| --- | --- |
| Existing tests | Commands, encryption, storage, sync, runtime and MCP contracts |
| `scripts/dev-release-sweep.ps1` | CLI contracts on Linux, macOS and Windows |
| `scripts/dev-api-smoke.py` | Positive and negative contracts for all 61 cloud routes |
| `scripts/dev-local-api-smoke.py` | All 72 local web actions on an ephemeral Linux runner |
| `scripts/dev-outbox-smoke.py` | Delayed network writes, independent decryption, finite sync, reset and retry |
| AI and legacy-vault supplements | Real CPU inference, deterministic provider contracts, injection and v1/v2/v3 recovery |
| `scripts/dev-smoke-gate.py` | Exact artifact identity, required observations and confirmed account cleanup |
| SDK | Exact target, Rust, ABI and file hashes |

Runtime checks must not bypass sandbox confinement. Release sweeps must not use real
user libraries or the production server.

Release smoke uses only `https://api-dev.rsrs.rs`. The manual `Dev server sweep` requires
the original successful build run and its exact source SHA; it never selects a
floating npm version. Reports contain no session files, credentials or raw payloads.

Main pushes publish a development version and stable tags publish a formal version
only after build, API and CLI gates pass. Development versions use consecutive
numbers, such as `1.0.8-dev.1`, `1.0.8-dev.2`, and `1.0.8-dev.3`, rather than Actions
run IDs. Publishing is serialized; existing tags, draft releases and all eight npm
packages reserve numbers. A partially published version is never reused. The next
unreleased base starts at `dev.1`; existing published versions remain unchanged.
CLI releases do not fetch or build Web UI source and do not depend on frontend
revision pins or browser smoke tests. Homepage, Dashboard and Admin build and
browser acceptance belong to `risense-ai/respire-site`. The CLI's cloud API
checks and mailbox helper remain part of API acceptance.
Development bases must exceed the current stable version: `1.0.8` ->
`1.0.9-dev.1` -> `1.0.9` -> `1.0.10-dev.1`.
Release notes include features, fixes, other changes, every commit, installation
instructions, source identity and a comparison link. Stable releases summarize
changes since the previous published stable release; development releases use the
previous published release. Drafts do not establish a comparison baseline.
Use `feat:` and `fix:` commit subjects with clear English descriptions for reliable
classification; unclassified changes retain their original descriptions. Missing
baseline history fails publication rather than silently omitting changes.
Publishing a development ref requires its source to be in `main` history;
unmerged candidate refs remain available for validation with publication disabled.
Interactive UI, real GPU/NPU hardware and
paid provider quality require separate validation; a deterministic provider fixture
does not measure model quality.

The manual `CLI CI` input `native_published_only` compares the exact published
DEV5 and DEV7 binaries on Windows, macOS and Linux with pinned, real M3 weights.
It verifies CPU inference after main → alternate → main, global engine settings,
distinct vault keys and unchanged source rows, queues and complete index artifacts.
This diagnostic run does not replace the release gate or claim that a reported
inference failure is fixed. Its reports retain failures; unexecuted platforms
must not be reported as passed.
