#![forbid(unsafe_code)]

//! Runtime host identity and low-level helpers without app or Core dependencies.
//! Account and installation root resolution is owned by app-domain service.

pub mod config;
pub mod credential;
pub mod identity;
pub mod input_error;
#[cfg(feature = "locks")]
pub mod lock;
mod version;

pub use version::version_cmp;
