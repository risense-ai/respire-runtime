# Source CI profiles and the CLI test-stack exception

Source CI keeps the dev/test defaults at opt-level=0, with debug assertions,
overflow checks, line-table debug information and the existing 90% coverage
gate. The existing sha2 dev-package optimization remains unchanged.

Only `[profile.test.package.respire] opt-level=1` is an approved exception.
On Windows x86_64 with Rust 1.95.0, the actual baseline Clap declarations
generate a 2,148,200-byte `Command::augment_subcommands` stack frame. Current
declarations generate 2,188,856 bytes. Both exceed the measured 2,097,152-byte
default test-thread stack before argument values or business code run.
Boxing the returned enum does not remove these builder temporaries.

Compiling the same current declarations at opt-level=1 reduces that frame to
415,208 bytes. Command construction and parsing then pass on the same default
stack. The actual CLI's existing help/parser and injected-chain parser tests
also pass with this package override and no RUST_MIN_STACK environment value.
This does not claim that the reduced frame is the full CLI binary's exact frame,
or that all capture tests have been rerun.

The contract test permits exactly this test-only package setting. It rejects
other package overrides, changed global profiles, weakened debug settings and
changes to the release profile. It also preserves the two existing CI stack
settings; this exception does not introduce or raise a stack override.

Production release compilation remains unchanged: strip=debuginfo, lto=false,
codegen-units=1 and panic=unwind. The compile matrix receives no source-test
profile environment override. Credential-writing tests still require their
own explicit isolation; this optimization does not authorize running them.
