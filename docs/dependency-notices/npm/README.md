# rsrs-cli

The launcher selects the platform binary package and forwards arguments to `rsrs`. Packages include the executable, runtime libraries and notices.

```sh
npm i -g rsrs-cli
# Or: pnpm add -g rsrs-cli
# DEV: npm i -g rsrs-cli@dev
rsrs doctor
rsrs --help
```

`rsrs-cli` is the primary install entry. For releases built from a manifest whose
`npmScope` is `rsrs-cli`, it contains the launcher and declares every supported
`@rsrsai/` platform package as an optional dependency at the exact same version.
It does not depend on `@rsrsai/cli`. Stable releases use `latest`; development
releases use `dev`.

This is a source-layout change for future publications. For example, published `1.0.19` and
`1.0.20-dev.8` still use `rsrs-cli` → `@rsrsai/cli` → platform package. Historical
source manifests with `npmScope: "@rsrsai/cli"` and their receipts retain that
layout; the split is determined by the source manifest, not a version threshold.
The historical packer under `npm/alias` stays unchanged for exact-byte recovery.

## Migrating a global install

Check `npm prefix -g`, `npm ls -g --depth=0`, and the executable selected by
`command -v rsrs` (PowerShell: `Get-Command rsrs -All`; cmd: `where rsrs`). Use the
same package manager, user and global prefix that own that entry. Resolve
multiple prefixes or uncertain ownership before changing anything.

- If the top-level package is already `rsrs-cli` (including its historical alias
  layout), upgrade that same package to the exact reviewed release. npm replaces
  its own entry; do not separately uninstall its nested `@rsrsai/cli` dependency.
- If only top-level `@rsrsai/cli` was installed, both package names claim the
  `rsrs` command. Installing `rsrs-cli` alongside it can fail with `EEXIST` while
  retaining the old entry. Do not use `--force` or manually delete an unknown
  executable/shim. Switching this installation requires an explicit user choice;
  the launcher never uninstalls another package automatically.

Before switching, record the old package's exact version and prefix. In a
separate disposable prefix, install and run `--version` for both the exact new
`rsrs-cli` release and the recorded old `@rsrsai/cli` release using the same npm
cache. Confirm the selected platform dependency exists at its exact matching
version; an optional-dependency warning alone is not a successful CLI install.
Keep the old package and its platform dependencies available for offline rollback
before removing the working global entry. Do not start a switch during a network
outage without a tested local recovery path.

For a scoped-only install, the user can then uninstall just the old **npm
launcher package** and install the new exact package in that same prefix. In the
commands below, replace `EXACT_NEW_VERSION` and `EXACT_OLD_VERSION` with the
recorded exact release versions before executing; these are placeholders, not tags.
`@dev` is useful for discovery but is not an exact migration/rollback pin.

```sh
npm uninstall -g @rsrsai/cli
npm install -g "rsrs-cli@EXACT_NEW_VERSION"
rsrs --version
```

If uninstall fails, stop and inspect the existing package/entry. If installation
fails after uninstall, do not force a link or retry an unverified package: restore
the recorded old launcher from the tested cache, for example
`npm install --offline -g "@rsrsai/cli@EXACT_OLD_VERSION"`, then verify its version
and executable path. If a partial new `rsrs-cli` package owns the entry, inspect
it and explicitly remove only that failed npm package before restoring the old
one. Keep the failure diagnostic; if rollback also fails, report the exact state
and stop rather than deleting unrelated files.

The built-in runtime registration normally points to the materialized executable
under the profile’s stable `bin` directory, rather than the npm dependency tree.
Still inspect custom `RSRS_BIN_DIR` settings and third-party service definitions
before removing a package: a custom service pointing into the old npm tree is
not covered by that default path and needs its operator’s migration plan.

These package-manager commands do not authorize deleting Respire profiles,
credentials, model files, runtime registrations or databases, or restarting
services. Preserve those separately managed resources. pnpm users must use the
same pnpm prefix/cache and equivalent reviewed operations; do not mix managers
or assume npm's offline flags apply to pnpm. Existing binaries and old releases
retain their original layout and behavior.

| Platform | Package |
| --- | --- |
| Linux x64, musl (default) | `@rsrsai/linux-x64` |
| Linux x64, glibc | `@rsrsai/linux-x64-gnu` |
| Linux ARM64, musl (default) | `@rsrsai/linux-arm64` |
| Linux ARM64, glibc | `@rsrsai/linux-arm64-gnu` |
| Apple Silicon | `@rsrsai/macos-arm64` |
| Windows x64 | `@rsrsai/win-x64` |
| Windows ARM64 | `@rsrsai/win-arm64` |

Linux ARM64 returns in the DEV channel first. Use `rsrs-cli@dev` for a release
whose manifest includes ARM64; stable versions 1.0.15 and 1.0.16 have no ARM64
packages. A newer stable install becomes applicable only when its release
actually includes those platform packages.

Windows ARM64 is a DEV-first release candidate and requires a version that
actually includes its complete package. Stable 1.0.15 and 1.0.16 omit it.
See the [support matrix](../docs/platform-support.md) for validation status and blockers.

`artifact-manifest.json` defines targets and names. Intel Mac uses `@rsrsai/macos-x64` and requires macOS 13.4 or later.
Linux keeps the static musl package as its default. On a glibc distribution,
select the GNU build explicitly; the same choice applies to npm and pnpm:

```sh
RSRS_LIBC=glibc rsrs doctor
RSRS_LIBC=musl rsrs doctor
# Persist the selection for this shell:
export RSRS_LIBC=glibc
```

The glibc packages require a compatible glibc host; they do not run on Alpine.
If optional packages were omitted during installation, install the selected
platform package at the same version as the installed launcher.
See [CLI source](https://github.com/risense-ai/respire-cli) for builds and runtime guides.

| Boundary | Behavior |
| --- | --- |
| Models | Separately installed with upstream licenses and source records |
| Runtime | Host manages lifecycle; sandbox uses authenticated client requests |
| Sync | Host-side login; encrypted server storage |
| Core binary | Separately licensed proprietary binary and public binding |

## License

First-party material uses the [Respire Noncommercial License 1.0](https://github.com/risense-ai/respire-cli/blob/main/LICENSE).
Personal noncommercial use and self-hosting are permitted. Commercial use,
including internal business deployment, requires prior written authorization.
See [commercial licensing](https://github.com/risense-ai/respire-cli/blob/main/COMMERCIAL-LICENSE.md).
