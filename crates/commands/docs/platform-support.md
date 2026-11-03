# Platform support

The desktop client needs an exact-target CLI and native Core package.
This matrix describes the release configuration for issue [#163](https://github.com/risense-ai/respire-cli/issues/163).
A configured target is a candidate until its native release gates pass; a Rust
compiler target alone does not establish product support.

| OS / CPU | Rust target | CLI build and native acceptance | Core / inference SDK |
| --- | --- | --- | --- |
| Windows x64 | `x86_64-pc-windows-msvc` | Existing; `windows-latest` | Pinned SDK and DirectML |
| Windows ARM64 | `aarch64-pc-windows-msvc` | Added; native `windows-11-arm`, DEV first | Pinned SDK and ARM64 DirectML |
| macOS Intel | `x86_64-apple-darwin` | Native `macos-15-intel`; macOS 13.4+ | ORT API 20; bundled ORT 1.20.1 |
| macOS ARM64 | `aarch64-apple-darwin` | Existing; native `macos-latest` | Pinned CPU SDK |
| Linux x64 GNU | `x86_64-unknown-linux-gnu` | Existing; `ubuntu-latest` | Pinned CPU SDK |
| Linux x64 musl | `x86_64-unknown-linux-musl` | Existing; Ubuntu and native Alpine | Pinned static CPU SDK |
| Linux ARM64 GNU | `aarch64-unknown-linux-gnu` | Existing; native `ubuntu-24.04-arm` | Pinned CPU SDK |
| Linux ARM64 musl | `aarch64-unknown-linux-musl` | Existing; native Ubuntu and Alpine | Pinned static CPU SDK |

Both SDK locks pin the same eight SDKs, including
manifest and archive SHA-256. CPU inference is linked into Core; an empty list
of shared runtime files on Unix does not mean inference is missing. Windows
ships the matching DirectML DLL. Redistribution notices remain mandatory.

## Requirements and limits

All shipped targets are 64-bit, little-endian, with the CPU ISA selected by
their Rust target (x86-64 or AArch64). Windows uses the dynamic MSVC CRT;
GNU Linux needs compatible glibc; musl Linux has static libc and uses the
native `rust:1.95.0-alpine3.23` build. See [Linux builds](linux-build.md).
The pinned SDKs do not record a minimum OS, kernel/libc version or a complete
inference ISA floor. Those minimum product requirements remain unverified;
the runner and Alpine versions above are qualification environments, not
promises that older hosts work. Rust's own platform minimum is only a lower
bound and does not certify the linked inference SDK.

Windows ARM64 acceptance requires an ARM64 runner and ARM64 PE headers.
Running an x64 executable under Windows emulation is not ARM64 acceptance.
All release executables are checked for matching PE, ELF or Mach-O headers;
staged SDK shared libraries receive the same architecture check.

## Targets excluded from this release

These targets are deliberately absent from the artifact manifest and release
matrix. No different-architecture binary or stub library is substituted.

| Target | CLI/toolchain audit | Core and inference blocker |
| --- | --- | --- |
| `i686-pc-windows-msvc` | Rust target exists; host WinML build explicitly accepts only x64/ARM64 | No pinned x86 SDK; WinML and inference need a separate validated x86 build |
| `i686-unknown-linux-gnu` | Rust target exists; 32-bit application/dependencies not compiled here | No pinned 32-bit Core/inference SDK |
| `mipsel-unknown-linux-gnu` | Rust Tier 3; requires a custom Rust/std and GNU cross toolchain | No pinned Core/inference SDK or runtime validation |
| `mips64el-unknown-linux-gnuabi64` | Rust Tier 3; custom toolchain/stdlib required | No pinned Core/inference SDK or runtime validation |
| `loongarch64-unknown-linux-gnu` | Rust target exists; upstream specifies Linux 5.19+, glibc 2.36+, LP64D and LSX | No pinned Core/inference SDK or runtime validation |

MIPS candidates mean little-endian MIPS32 O32 hard-float and little-endian
MIPS64 N64 hard-float respectively. Neither is supported by this release.
Big-endian MIPS is also excluded. MIPS and LoongArch were considered only
for Linux; there is no Windows/macOS support claim. The missing SDK is a
concrete packaging blocker, not proof that upstream inference cannot be ported.
See the upstream [Rust matrix](https://doc.rust-lang.org/rustc/platform-support.html),
[MIPS32 toolchain requirements](https://doc.rust-lang.org/rustc/platform-support/mipsel-unknown-linux-gnu.html)
and [LoongArch requirements](https://doc.rust-lang.org/rustc/platform-support/loongarch-linux.html).

## Delivery and verification

Every released target must provide `cli-build-<target>.json`,
`rsrs-<target>[.exe]` and `rsrs-<target>-runtime.tar.gz`. Metadata binds the
version, source commit, target, filenames and SHA-256. The runtime archive
contains `core-runtime.json` and all runtime libraries and notices.
The build checks version and headers before staging; package verification
checks source/target identity, headers and both archive/binary hashes.

Release gates run real CPU model inference, isolated account/runtime lifecycle,
health/RPC, concurrent access and historical upgrades on native runners.
Windows ARM64 also participates in cloud and profile-migration gates.
Historical Windows ARM64 assets remain required, including the 1.0.6 DEV
and 1.0.10 draft baselines; only its exact, completely absent 1.0.15/1.0.16
packages are inapplicable. Partial packages still fail verification.

Windows ARM64 must pass DEV before any stable promotion. Stable 1.0.15/1.0.16
omit Windows ARM64 and Linux ARM64; changing this matrix does not change those
immutable releases. A client with no matching channel package should report
the missing target and may attach to an existing compatible local Runtime.
`RSRS_BIN_DIR`, `RSRS_DATA_DIR`, `RSRS_RPC_PORT` and loopback lifecycle
semantics are unchanged.
