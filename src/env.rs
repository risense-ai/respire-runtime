//! Canonical environment names with read-only compatibility for previous clients.
use std::{env::VarError, ffi::OsString};

pub fn var_os(name: &str) -> Option<OsString> {
    std::env::var_os(name).or_else(|| {
        let suffix = name.strip_prefix("RSRS_")?;
        std::env::var_os(format!("ONEMEMORY_{suffix}"))
            .or_else(|| std::env::var_os(format!("RESPIRE_{suffix}")))
    })
}

pub fn var(name: &str) -> Result<String, VarError> {
    match var_os(name) {
        Some(value) => value.into_string().map_err(VarError::NotUnicode),
        None => Err(VarError::NotPresent),
    }
}
