# Extra embedded source-native regression

Not a release candidate or GUI acceptance replacement. Inject the Go test only
into a clean checkout of Client2 `03f27c519d23877e7dfe82ef764ef2fbe1a2bfe0`.
It drives that revision's actual managed host manager, not an external CLI or
mock Runtime. The selected Runtime is the source build from this CI commit.

Run after producing the strict Runtime payload directory (including SDK DLLs
and `core-runtime.json`) and downloading the three pinned public model inputs:

```sh
python scripts/fixtures/embedded-keygen/run.py \
  --client2 .client2-source \
  --payload "$RUNNER_TEMP/offline-keygen-source-payload" \
  --models "$RUNNER_TEMP/offline-keygen-models" \
  --version "$RUNTIME_VERSION" \
  --binary-file "rsrs-runtime-$RUNTIME_TARGET.exe"
```

Use `actions/setup-go@v5` with `go-version-file:
.client2-source/go.mod`. Checkout with `persist-credentials: false`. No token or
external account credentials are used. Do not upload the temporary profile,
command output, keygen envelope, sessions or journal. Only the Go test's fixed
stage failure labels/success line are intended diagnostics.

Coverage: managed image selection; original-O keygen persistence; refused
foreign operation lookup without mutation; explicit Start completion/cleanup;
PID, executable, version, profile and strong actor identity unchanged across
repeated Client2 Start. Start success exercises the Runtime completion receipt
inside the coordinator; the test does not invent a receipt or extract recovery
material. Models are genuine pinned public CPU inputs, not a test embedder.

The foreign-O rejection is not a simulated lost server response. Real transport
Unknown recovery, interrupted processes, account write/transfer and the original
GUI fixture remain separate gates. No claim of those outcomes follows from this
test. The runner has been syntax-checked only until the exact native CI runs.
