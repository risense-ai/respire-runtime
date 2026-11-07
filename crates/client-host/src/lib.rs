#![forbid(unsafe_code)]

//! Client host helpers shared without app or Core dependencies.

pub mod classification;
pub mod config;
pub mod credential;
pub mod env;
pub mod identity;
pub mod input_error;
#[cfg(feature = "locks")]
pub mod lock;
pub mod paths;
pub mod roots;
pub mod settings;
mod version;

pub use version::version_cmp;
