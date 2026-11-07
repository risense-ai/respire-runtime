# Existing Client2 compatibility during the Runtime split

The standalone Runtime retains the existing Client2 host interface. Client2 does
not need a source change, a new local credential, or a new request field.

- The existing platform transports and loopback listener are retained. Legacy
  requests use the existing Runtime dispatch and bounded in-memory result cache.
- `--json runtime start` starts the same selected Runtime image in the background;
  stop/status, concurrent startup, restart and interrupted-owner recovery retain
  their original host behavior.
- Host commands and `--json --host-rpc-stdio` reuse the CLI frontend. The v1 stdio
  parser, parameter mapping, response formatting and secret scrubber are the
  original CLI implementation, not another protocol implementation.
- Account and key maintenance share one coordinator with the CLI. Pausing,
  draining, original-operation queries, verified completion, rollback and host
  restoration are retained. Offline fivekeys recovery accepts the original empty
  server/account fields for supported v1/v2/v4 kits.
- The embedded frontend uses the Runtime image already selected by Client2. It
  cannot replace, download, clean or materialize a different Runtime or host CLI.
  Explicit host asset commands retain the original CLI behavior; the serving
  Runtime does not gain an automatic downloader.

## Source ownership

`host-frontend/cli` and `crates/host-commands` reuse the canonical CLI source.
Their Rust source is identical to the companion CLI checkout; only Cargo package
names and dependency paths differ. `crates/client-host` and `crates/host-control`
are shared with the CLI consumer. Change these implementations in the canonical
CLI consumer and synchronize the copies together, rather than independently
forking authentication or host command behavior.

The integration includes Runtime PR #51 and CLI PRs #219 and #220. The latter's
legacy-install preservation still applies to the ordinary CLI. A Client2-embedded
command revalidates its already selected image instead of treating an unrelated
stable CLI image as a request to migrate it. All embedded installer entry points
remain disabled.

## Acceptance boundaries

Local Linux checks cover compilation, focused shared-coordinator and frontend
unit tests, process identity, and the unchanged Client2 host/lifecycle package
against the integrated executable. The local environment refuses the disposable
Secret Service D-Bus socket before daemon startup, so these results are not a
native account/OAuth acceptance claim. Native account, Windows/macOS and release
acceptance remain the existing CI gates. Windows process-role tests are compiled
for the Windows target locally, not claimed as natively executed.

Runtime dev.16 is a new candidate version. No previous release or tag is replaced
or removed. The CLI's formal Runtime pin is updated only after the corresponding
Runtime release exists.
