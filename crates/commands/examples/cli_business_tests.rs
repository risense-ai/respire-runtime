//! Cross-repository integration fixtures owned by Runtime, invoking a real CLI.
//! See docs/testing.md for exact CLI/official Runtime/model binding and CI execution.
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
