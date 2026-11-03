# Host runtime and sandbox clients

Embedding profiles use `model.catalog`, `model.configure`, `model.switch`,
`model.resume` and `model.progress` on the existing runtime RPC transport.
See [embedding profiles](model-profiles.md) for CLI/JSON and failure semantics.
SQLite library metadata owns active selections. A switch pauses new semantic
requests and writes, checkpoints a candidate generation, validates both main
and diary indexes, and only then activates it. Pending snapshots survive restart
for an explicit `model resume`; no uncertain operation is automatically replayed.

```mermaid
flowchart LR
  Host[Host terminal] -->|owns lifecycle| Runtime[Loopback HTTP runtime]
  Sandbox[Sandbox CLI / TUI / MCP] -->|client-only| Runtime
  Runtime -->|anonymous stdin/stdout| Worker[Supervised Core worker]
  Worker --> Inference[Shared native model session]
```

| Context | Behavior |
| --- | --- |
| Host | Starts, stops, updates and recovers the runtime |
| Sandbox | Connects to the host loopback runtime without a token |
| Restricted Windows token | Automatically selects client-only mode |
| Other sandboxes | Integration explicitly selects client-only mode |

```sh
# Hosted dashboard (does not start the local runtime)
rsrs web
# Host lifecycle diagnostics
rsrs --runtime-internal
rsrs --runtime-internal --stop
# Sandbox
rsrs --client-only recall "query" --titles --json
```

Client-only mode forbids lifecycle changes, binary copies, upgrades, CPU recovery and
`--direct` execution. MCP stdio does not copy the executable. A failed request never
triggers sandbox takeover. An idle runtime stays running until the host stops it.

## Opt-in current-user supervision

Startup is **off by default**. Installing or updating the CLI never registers a
service. A host user can opt in explicitly:

```sh
rsrs runtime autostart status --json
rsrs runtime autostart enable          # future sign-ins; does not start a stopped runtime
rsrs runtime autostart enable --now    # also start now
rsrs runtime stop                     # stays stopped until explicit start/restart
rsrs runtime start
rsrs runtime restart
rsrs runtime autostart disable --stop
rsrs runtime autostart remove --stop   # remove registration, retain libraries and keys
```

`runtime run` serves in the foreground. The adapters supervise that process:
Linux uses the existing systemd **user** session, macOS uses the current user's
LaunchAgent, and Windows uses a Limited, interactive current-user logon task.
The Windows task keeps a native foreground supervisor alive; it retries a failed
foreground runtime child after 60 seconds, with at most three consecutive failed
children before explicit start/restart is needed. A child that ran for two minutes
resets that consecutive-failure budget. Maintenance or manual stop prevents retry.
A non-inheritable, process-owned Windows job also removes the child tree if the
supervisor itself exits unexpectedly; automatic parent recovery is not promised,
and an explicit host restart may be needed. Normal CLI stop drains the runtime
before stopping the supervisor or replacing its executable.
They do not install a system service, enable linger, elevate privileges, store a
Windows password, or start before anyone signs in. Missing user service-manager
support is an error, without an automatic system-wide fallback.
Systemd itself rejects quotes/backslashes in an executable pathname. Such a data
root remains usable with a separate safe absolute `RSRS_BIN_DIR`; enable rejects
an unsupported native path before creating lifecycle/registration state.

Status is read-only and does not create a profile, download a model, start a
runtime or change a registration. It reports configuration separately from the
actual OS registration and runtime/store readiness. Store readiness does not
prove that the OS keyring is unlocked, a model is installed or the network is
available. Unlock/login and model preparation remain host operations; a service
must not generate replacement recovery material to bypass an unavailable keyring.

The registration belongs to one installation root and OS user. Its native path,
arguments, owner and service-file hash must match before changing it. Unknown
units, task actions and loaded systemd drop-ins are refused, including removal.
Existing manually created startup tasks are not adopted or deleted automatically;
remove an old task yourself after checking its ownership to avoid competing owners.

Host binary/profile changes use the same installation coordinator as normal
runtime lifecycle operations. A durable maintenance marker blocks queued/direct
access and background indexing/sync until the replacement store is verified.
An interrupted change stays paused; explicit `runtime restart` recovers the
lifecycle marker, while a snapshot/login interruption still requires its own
indicated recovery command. The control marker is not proof that a snapshot or
login transaction completed.

Startup settings are captured when registering. To change the saved port/native
location or environment, first `remove --stop` using the old registered settings,
then explicitly enable again with the new settings. A mismatched caller port is
refused before stopping a service, so an unreachable old endpoint cannot silently
turn into a forced shutdown. Status reports `configured_rpc_port`.

Only non-secret allowlisted runtime settings are saved, including explicit
`RSRS_NO_AUTOSYNC` and `RSRS_UPDATE_CHECK` opt-outs (legacy prefixes are read and
saved under their canonical names). Credentials and recovery
material are never stored in a service command line or registration. Managed
launches have a persistent limit of three attempts per 120 seconds, plus the OS
restart delay. Explicit start/restart resets the owned unit's launch budget.
Fixed-field lifecycle events are kept under `runtime/autostart/events.jsonl`,
with a 64 KiB limit and one previous file; they contain no raw errors, command
arguments or account content. Disabling/removing startup preserves data and keys.

The platform acceptance workflow uses disposable GitHub-hosted runner profiles;
passing it does not establish physical reboot, logout/login, real-account keyring
or model readiness on every machine.

## Existing manual Windows sign-in setup

For client-only tools after a restart, configure one host-owned Windows Task
Scheduler task. It runs after the same Windows user signs in, so the user's
selected profile and OS keyring remain available. This is a sign-in task, not a
SYSTEM service before login. The CLI does not install it automatically.

1. In an ordinary host terminal, run `rsrs status --json`, followed by
   `rsrs --runtime-internal --status --json`. Verify the selected account and
   running host. The first command installs/updates the managed native executable
   and its verified runtime files in the installation's `bin` directory.
2. Open **Task Scheduler → Create Task**. Name it **Respire host runtime**, select
   your current Windows user, choose **Run only when user is logged on**, and
   leave **Run with highest privileges** unchecked. No stored password is needed.
3. Add **At log on** for that specific user. Add **Start a program** using the
   absolute managed executable path (normally
   `C:\Users\<your-user>\.rsrs\bin\rsrs.exe`) and arguments `status --json`.
   Use the actual installation `bin` path if you configured another location.
   Use your user home as **Start in**. Do not select an account subdirectory's
   copy, a temporary build directory or a sandbox/client-only launcher.
4. In **Settings**, allow on-demand execution and choose **Do not start a new
   instance**. Disable the task's maximum-running-time stop condition: the
   resident child must remain available. Power/battery conditions can delay a
   task; choose these according to your own power policy.
5. Run the task once. `status` performs normal host startup and then returns;
   the owned runtime keeps running. Check **Last Run Result** and verify
   `rsrs --runtime-internal --status --json` again before relying on a sandbox
   connection. Repeat this check after your next sign-in.

After a CLI update, run the new host `rsrs status --json` once to update the
managed executable used by the task. Custom `RSRS_DATA_DIR`, `RSRS_BIN_DIR` or
port settings must also be present in the task's user environment; terminal-only
variables are not inherited by Task Scheduler. The task uses the profile selected
in the installation's `client.json`; it does not log in, generate keys or choose
another account.

To remove startup, disable/delete only your **Respire host runtime** task. Stop
the existing owned runtime separately from a host terminal with
`rsrs --runtime-internal --stop`. Client-only tools continue to leave lifecycle
management to the host. `rsrs --runtime-internal --help` lists lifecycle flags
without creating a profile or starting a runtime.

The doctor injection count measures detected installed hosts, rather than every
catalog target. Absent hosts are not failed injections; stale installed-host
instructions can be refreshed with an explicitly requested `rsrs inject --all`.

`rsrs doctor` includes a `Runtime version` check. Its JSON summary exposes
`runtime_version`, which is `null` when no runtime is connected. The TUI home
and version pages show the connected runtime's version separately from the CLI
version. A disconnected TUI shows `Runtime not connected` instead of a cached
version. Reading this version does not start or replace a runtime.

The TUI Models/inference page includes **Inference / Recall Benchmark**. Enter a
query to measure one initial call and eight repeated rounds against the existing
local runtime. The report separates the SDK's reported inference-probe time,
full probe-request time, and full fast-Recall request
time. It shows mean, P50, P95 and estimated sequential operations per second.
Full request times include RPC and any scheduling waits; they do not isolate
queue time. The first call is not necessarily a cold start, and repeated Recall
can reuse query caches. Indexed-candidate ranges and pending-index counts identify
an empty or changing library. These are current-load measurements, not retrieval
quality scores or hardware guarantees. The benchmark never calls the quality
selector API or changes the saved engine/mode; normal Recall logs and hit counts
are still updated. Esc finishes the in-flight request and stops further rounds.

Command progress labels inference activity and its waiting-task count as **global
inference service** state. A zero count means no pending inference tasks, not that
the displayed CLI command is waiting for inference. Read commands such as `show`
do not perform inference; a multi-command script may be busy in a later write.

Host `account <name>`, `account use <name>`, `space use <name>` and
`config --data-dir <path>` coordinate shutdown, profile selection and restart.
An invalid target keeps the original profile and restarts its service.
Client-only tools cannot switch the host profile. `--direct` still requires a
stopped runtime and does not perform an automatic takeover.

`space join` also runs on the host coordinator. Invalid invites and existing
targets are rejected before stopping the runtime. Joining creates the invited
profile and restarts the original selected profile; `space use <name>` switches
to the joined profile explicitly. Read-only joins and keyring warnings count as
successful joins. Failed server requests restore the original configuration and
runtime.

Human CLI requests use a hidden request ID and the additive `cli.progress` RPC
to read their current stage outside the worker queue. `--json` does not start a
human progress display. `model.prepare` schedules preparation from the selected
mirror on the existing background model worker; `model.control` cancels only the
matching active task. Cancellation must release its model slot before restart.

| Setting | Purpose |
| --- | --- |
| `RSRS_CLIENT_ONLY=1` | Host runtime client mode |
| `RSRS_NO_AUTOSTART=1` | Compatibility synonym |
| `RSRS_RPC_PORT` | Override the default port `15169` |

Runtime RPC uses HTTP over loopback TCP only. Startup does not create or probe
Unix-domain sockets or Windows named-pipe listeners, and there is no legacy
pipe fallback. A process-lifetime installation lock prevents a second host on
another port; library ownership is acquired before health/endpoint readiness.
Core worker stdin/stdout and MCP stdio are anonymous inherited
process streams, not runtime RPC listeners; their protocols are unchanged.

CLI / TUI / MCP stdio connect to `127.0.0.1` without reading a token file or
requiring token injection. Loopback listeners do not create a token. The runtime
currently rejects non-loopback bind addresses, so cross-machine runtime access
is not supported. Non-loopback peers are never exempt from authentication.
The server checks the actual peer address, not Host or forwarded headers.
Every request must use the bound loopback authority or `localhost` with the
bound port as its Host; when bound to HTTP port 80, Host may omit `:80`.
Origin checks apply to GET and POST alike. MCP endpoints
use the actual bound address.

Keep tokens out of prompts and reports. Remote containers do not automatically
share host loopback addresses.

| Error | Meaning | Action |
| --- | --- | --- |
| `runtime_unavailable` | Runtime unavailable | Host starts the service |
| `runtime_unauthorized` | Authentication rejected | Non-loopback client supplies a valid token; a loopback client requires an updated host runtime |
| `runtime_transport` | Connection failed | Host checks endpoint/network |

## Server deployment

| Service | Address |
| --- | --- |
| Main site | `https://rsrs.rs` |
| User dashboard | `https://dash.rsrs.rs` |
| Administration | `https://admin.rsrs.rs` |
| Default API | `https://api.rsrs.rs` |

The default API can be changed through the server settings. Respire uses `~/.rsrs` and port `15169`; startup preserves the selected account and does not import old profiles automatically. Use the TUI's Migrate old version action or `rsrs migrate` to select a source and target account. Original directories remain intact and existing accounts are not overwritten. Explicit
`ONEMEMORY_*` overrides remain supported, and the database filename and wire format
remain compatible.

## Hosted dashboard and local transport

`rsrs web` opens `https://dash.rsrs.rs`. `rsrs web --no-open --json` reports that URL without opening a browser. It does not start, stop, or bind the runtime. Former `web --host`, `--port`, `--status`, `--stop`, and `--internal` flags are no longer supported.

The hidden `--runtime-internal` entry is reserved for host lifecycle and automated diagnostics. Commands that require the runtime automatically start it when allowed; restricted clients only connect. Local `/api/health`, `/api/rpc`, `/api/runtime/stop`, `/mcp`, and `/sse` accept actual loopback peers without a token. Non-loopback peers are not exempt from token checks, and non-loopback listening is currently unsupported. Browser pages, static assets, `/api/invoke`, and `/api/task` are removed. The non-loopback authentication gate accepts tokens in headers, never dashboard URLs.

## Upgrading an older runtime

The host command `rsrs --runtime-internal --stop` supports runtimes that still
require a loopback token, including 1.0.9. The client sends the existing
`RSRS_RPC_TOKEN` or runtime token file on the initial request. It does not
create or replace credentials, and it never replays a failed request. Current
loopback runtimes ignore the header and also work without a token file.
Health checks and normal RPC use the same compatibility rule, so host upgrades
can gracefully stop the old runtime before starting the new executable.

Run lifecycle commands from the host terminal; client-only mode does not permit
shutdown. Client-only requests also preserve existing authentication headers.
A missing or rejected legacy token requires the old runtime's existing
authentication material, rather than bypassing authentication or killing an
unverified process. HTTP redirects are disabled for the local runtime client.

## Model downloads and account switches

Model weights and inference engine selection are global to the installation
root (`RSRS_DATA_DIR` for isolated installations); the selected account's
library directory does not select another engine or require another model copy.
Account switching must preserve the global configuration and reuse compatible,
complete M3 artifacts. Only missing, changed or corrupt artifacts need indexing.

Large ONNX downloads use at most four HTTP ranges when the source honors range
requests. Sources without range support use one connection. Pinned-revision
temporary files and segment checkpoints survive interruption and mirror changes;
completed files are published only after their SHA256 matches the pinned model.
Progressing downloads do not expire merely because 30 minutes elapsed. The
existing bounded network-read timeout still applies. Parallel connections do not
guarantee faster transfers when the server or network limits total bandwidth.

## Background inference thread policy

The SDK must advertise `inference_thread_contract: 1`. Foreground sessions use
one intra-op thread. Background indexing uses the host's available CPU count
minus one, bounded to 1–16. `RSRS_INTRA_THREADS` explicitly selects the background
count; numeric values are clamped to 1–16 and invalid values fail clearly. It
does not change the foreground session. Set it before starting the runtime and
restart that owned runtime when changing it; the supervised worker receives a
startup snapshot. Core receives explicit configuration, never environment access.
The policy participates in model reuse identity for both ONNX and owned ORT.

For an isolated synthetic measurement using verified model files, run
`cargo run --locked -p respire_core_sdk --example index-thread-probe -- /path/to/model`.
Add `--legacy` to exercise borrowed ONNX instead of streamed owned ORT. The probe
reports background prepare and concurrent foreground latency for background
counts 1 and 4; it also checks cache-policy rejection and native pool creation.
These fixture timings are measurements, not a production speedup guarantee.
