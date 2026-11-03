# Linux credential storage dependencies

The Linux CLI uses Secret Service before the kernel keyring. The vendored build
links the libdbus library; it does not distribute the upstream standalone tools.
These consumer notices accompany CLI binaries and npm platform packages under
`core-notices/consumer/`. They do not change the closed Core SDK license.

| Dependency | Selected license | Original notice | Exact source archive |
| --- | --- | --- | --- |
| libdbus 1.14.4, vendored by libdbus-sys 0.2.7 | Academic Free License 2.1, from the upstream dual-license choice | libdbus-COPYING.txt | [libdbus-sys 0.2.7](https://crates.io/api/v1/crates/libdbus-sys/0.2.7/download), including `vendor/dbus` and its build recipe |
| libdbus-sys 0.2.7 Rust bindings | MIT | libdbus-sys-MIT.txt | [libdbus-sys 0.2.7](https://crates.io/api/v1/crates/libdbus-sys/0.2.7/download) |
| dbus 0.9.12 Rust bindings | MIT | dbus-MIT.txt | [dbus 0.9.12](https://crates.io/api/v1/crates/dbus/0.9.12/download) |
| dbus-secret-service 4.1.0 | MIT | dbus-secret-service-MIT.txt | [dbus-secret-service 4.1.0](https://crates.io/api/v1/crates/dbus-secret-service/4.1.0/download) |

The original notices are copied unchanged. `Cargo.lock` pins the source archive
SHA-256 checksums:

| Archive | SHA-256 |
| --- | --- |
| libdbus-sys 0.2.7 | `328c4789d42200f1eeec05bd86c9c13c7f091d2ba9a6ea35acdf51f31bc0f043` |
| dbus 0.9.12 | `3ab69f03cc8c4340c9c8e315114e1658e6775a9b16a04357973aa21cec22b32e` |
| dbus-secret-service 4.1.0 | `708b509edf7889e53d7efb0ffadd994cc6c2345ccb62f55cfd6b0682165e4fa6` |
