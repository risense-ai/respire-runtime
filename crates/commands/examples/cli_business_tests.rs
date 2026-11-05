//! Runtime-owned business fixtures exercising the exact independently built CLI.
//! Run with `cargo test -p respire_commands --example cli_business_tests`.
#![forbid(unsafe_code)]

#[cfg(test)]
#[path = "cli_business_tests/support.rs"]
mod support;
#[cfg(test)]
#[path = "cli_business_tests/memory_revision.rs"]
mod memory_revision;
#[cfg(test)]
#[path = "cli_business_tests/diary_identity.rs"]
mod diary_identity;
#[cfg(test)]
#[path = "cli_business_tests/snapshot_lifecycle.rs"]
mod snapshot_lifecycle;
#[cfg(test)]
#[path = "cli_business_tests/account.rs"]
mod account;
#[cfg(test)]
#[path = "cli_business_tests/capture_main.rs"]
mod capture_main;

fn main() {}
