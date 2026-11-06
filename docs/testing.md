# Runtime test ownership and execution

`workspace-tests` in `.github/workflows/ci.yml` executes the Runtime workspace
source tests on every PR, main/release push and manual run. This includes the
Runtime business implementation and snapshot/store unit tests. The separate
`cli_business_tests --no-run` step checks compilation only; it is not execution
evidence.

All five modules in `crates/commands/examples/cli_business_tests` invoke the real
CLI: memory revision, diary identity, snapshot lifecycle, account, and
capture/parser behavior. The current inventory is 30 cases; this is a dated
inventory, not a fixed execution limit. These are cross-repository integration
fixtures owned by Runtime, not Runtime-only unit tests.

## External joint execution: CLI is the authoritative entry point

The single source-integration coverage entry point for these fixtures is
`risense-ai/respire-cli`, `.github/workflows/ci.yml`, job `runtime-integration`.
Runtime owns their source and assertions; CLI owns this external joint execution
and its CLI coverage counters. Runtime CI only compiles the harness. It does not
execute these business fixtures, call a second runner, or claim their acceptance.

The CLI job checks out the exact Runtime harness commit in its
`runtime-tests-source.json`, verifies checkout HEAD and matching SDK locks, and
uses the instrumented CLI from that same run's `coverage-core` or
`coverage-runtime_smoke` artifact. Its integration record binds the CLI source,
run/attempt, source archive digest, CLI executable digest and Runtime harness SHA.
The official installer supplies the version in the CLI's `runtime-pin.json`;
the real CPU model and private account credential fixture remain required.

Keep the official Runtime product source SHA, harness source SHA and CLI source
SHA distinct. For the current dev.15 product, the expected official source is
`9338a6654cf395525668dd9faaea3f401abe2d5a`; a harness revision does not replace that
product identity. The integration job's raw result and exact asset bindings are
needed before reporting an external joint pass. Merely finding a workflow,
compiling a harness, or listing test names is not execution evidence.

The current CLI job splits memory revision, diary identity, snapshot lifecycle
and capture/parser cases into `core`, and account cases into `runtime_smoke`.
The witness failure assertion remains unchanged. No Runtime-local execution
report is produced for these fixtures. The CLI Linux integration also does not
replace native Windows/macOS, release-asset or three-repository candidate gates.

### Outstanding execution evidence

- The CLI wiring now compares the installed metadata's `source_commit` with
  the independent expected dev.15 product SHA and records metadata/binary
  digests. Cloud execution must still prove these checks ran successfully.
- The CLI wiring retains the required per-module counts and also checks that
  every listed harness case has an execution assignment. New cases require
  updating this inventory without dropping existing assertions.
- The CLI job stages SDK libraries beside its Cargo example harness. Successful
  dynamic loading and case execution still require evidence from the exact
  built executable; static wiring checks cannot establish that result.
- A normal CLI candidate with official dev.15 passed an isolated Windows batch
  of 31 cases: HTTP 14, memory 6, snapshot 8 and account 3. Report SHA-256:
  `0ed0d390eda6f87c9a93bc22fc4c6fe2a31a0a482b7b6bc742be6498b088fbf1`.
  The frozen seven harness source files match `9338` after CRLF normalization.
  This batch did not execute diary/capture or the new cloud coverage wiring;
  the earlier intermittent OS5 snapshot failure remains unexplained.

`scripts/required-tests.json` and its candidate/run/attempt-bound report gate are
unchanged. Missing required tests remain missing. These integration logs are not
`required-execution/v2` reports and cannot satisfy G1/G2 by themselves.

## Same-name `net_rpc` cases are not additive coverage

The Runtime and CLI each compile their own `crates/commands/src/net_rpc.rs`.
The Windows inventories overlap by 11 test names; Linux additionally includes
the two same-name procfs/exited-child cases. Report execution counts per binary,
but do not sum these names as independent behavior coverage.

The comparison below used Runtime `cebfca8` and the frozen CLI worktree
`release-cli-dev5-final-20261106`. Source-file SHA-256 values were
`e43e65fac60a776139010f811e5cfb3603ed9429c6cd57bcb0f514434ecb7159`
(Runtime) and
`ac1a48cad2b16cbefe50c99414ea6591e1edb15cbd137a8e4e3de8cd88444ff7`
(CLI). Recheck the comparison if either implementation changes.

| Same-name case(s) | Actual overlap and owner |
| --- | --- |
| `rpc_timeout_recognizes_commands_after_global_values_and_equals_forms`, `rpc_timeout_does_not_treat_tracking_values_or_other_methods_as_commands` | Identical assertions; timeout implementation differs only in command-parser module reference. Client request-budget behavior belongs to CLI. Runtime still has its separate implementation, so these tests are retained pending an implementation ownership change. |
| `port_is_open_sees_local_listener`, `default_port_is_15169` | Identical assertions. Listener probing is client behavior; the default port is also used by Runtime startup. Keep protection for both compiled copies while they exist. |
| `origin_empty_is_cli` | Identical assertions and implementation. Runtime `runtime_http.rs` actually calls `origin_ok` for HTTP requests and upgrades. This is server access-control coverage and must remain in Runtime despite the test name. |
| `version_newer_dev` | Identical assertions. A common version-utility check, not two independently covered behaviors. |
| `rpc_port_reads_env`, `token_env_beats_file` | Only the environment-module namespace differs. Port selection is used by the server; host token precedence belongs primarily to the client. These are tests of separate compiled copies, not proof of additional behavior. |
| `health_shape` | CLI adds `Health.rpc` default/payload assertions absent in Runtime. Shared baseline coverage, different total assertions. |
| `persist_and_load_token_file` | CLI additionally rejects empty, whitespace, invalid UTF-8 and directory token inputs. The Runtime case is not a substitute for those client assertions. |
| `response_after_client_deadline_reports_unknown_and_can_be_inspected_without_replay` | Different implementations and assertions. Runtime uses delayed loopback transport and an operation-result query; CLI additionally exercises strict response/operation/scope binding and malformed receipt rejection. Same name does not establish a replacement. |

For the 11 Windows names, six function bodies are identical, two differ only in
environment namespace, and three have substantive assertion differences. No case
was deleted on the basis of its name. Moving the duplicated client implementation
is a product change outside this test/CI-only task; the Runtime server checks and
all current assertions remain in place. The VM's `commands37/app3` inventory is
an execution inventory pending its own frozen executable digests, not 40 new
non-overlapping behaviors or a claim of successful execution.
