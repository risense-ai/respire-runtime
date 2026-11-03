# Linux builds

CLI-side builds link a validated binary Core SDK. They do not compile Core
or ONNX Runtime sources.

| Item | Contract |
| --- | --- |
| Linux x64, glibc | `x86_64-unknown-linux-gnu` |
| Linux x64, static musl | `x86_64-unknown-linux-musl` |
| Linux ARM64, glibc | `aarch64-unknown-linux-gnu`, native `ubuntu-24.04-arm` |
| Linux ARM64, static musl | `aarch64-unknown-linux-musl`, native `ubuntu-24.04-arm` |
| musl container | `rust:1.95.0-alpine3.23`, same CPU architecture |
| SDK | Pinned binary SDK for the exact target |
| Output | `target/ci/<target>/release/rsrs` and staged notices |
| musl verification | No ELF `INTERP`/`NEEDED`; version checks on Ubuntu and Alpine |

On a glibc Linux host, prepare the SDK and compile the native GNU target:

```sh
target="$(uname -m)-unknown-linux-gnu"
node scripts/fetch-core-sdk.mjs "$target"
export RSRS_CORE_SDK_DIR="$PWD/.sdk/$target"
cargo build --release --locked -p respire --bin rsrs --target "$target" --target-dir target/ci
node scripts/stage-core-runtime.mjs "target/ci/$target/release"
```

The GNU build requires compatible glibc and the staged shared libraries. Choose
musl for a static libc build; neither architecture can be substituted for the other.
The npm launcher keeps musl as its default. Set `RSRS_LIBC=glibc` to select a GNU
platform package; see [npm platform selection](../npm/README.md).

For musl, use the existing Alpine container build:

```sh
bash scripts/build-linux-musl.sh "$(uname -m)-unknown-linux-musl"
```

The container fetches the SDK, compiles CLI/application crates and stages runtime/third-party
notices. Configure the SDK URL first. Caches stay in `target/musl-cache/<target>`.
Static libc does not establish support for every kernel, CPU or sandbox. Host
permissions still govern Linux keyring access.

Linux ARM64 builds and acceptance require `uname -m=aarch64` on a native Linux
runner. No QEMU or cross build substitutes for model/runtime acceptance. GNU
artifacts require an AArch64 ELF with its interpreter and resolved dynamic
runtime dependencies. Musl artifacts require no ELF interpreter or shared
library imports and also run in native ARM Alpine.
The Alpine inference probe uses the already prepared model files, a separate
owned profile and no container network or forwarded credentials. It executes
actual CPU model inference as well as the native executable startup check.

Historical upgrades keep every actual ARM source. Only `v1.0.15`, `v1.0.16` and
`v1.0.17-dev.12` have an explicit ARM distribution gap. Their complete absence
is reported as not applicable; partial assets or any other missing version
still fail. Existing ARM releases, including the 1.0.6 DEV baseline and 1.0.10
compatibility draft, remain strict upgrade sources.
