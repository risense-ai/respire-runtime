//! Embedded CLI version. Printed by `--version`, `-v`, and `rsrs v`.
//!
//! The version is the rsrs CLI release version, supplied at build time by this
//! crate's build script as `RSRS_CLI_VERSION` (read from the workspace manifest),
//! because this crate keeps its own independent package version.

use crate::output::{Item as OutputItem, ResultEnvelope, Status};

pub fn embedded() -> &'static str {
    env!("RSRS_CLI_VERSION")
}

pub fn clap_version() -> &'static str {
    #[cfg(feature = "native-fault-tests")]
    { concat!(env!("RSRS_CLI_VERSION"), " (native fault fixture; not releasable)") }
    #[cfg(not(feature = "native-fault-tests"))]
    { embedded() }
}

pub fn line() -> String {
    let line = format!("rsrs {}", embedded());
    #[cfg(feature = "native-fault-tests")]
    let line = format!("{line} (native fault fixture; not releasable)");
    line
}

pub fn emit(json: bool) -> anyhow::Result<()> {
    if json {
        let mut envelope = ResultEnvelope::new(
            "version",
            Status::Ok,
            serde_json::json!({"version": embedded()}),
            vec![OutputItem::new(
                "version",
                Status::Ok,
                embedded().to_owned(),
            )],
        );
        envelope.details = serde_json::json!({"bin": embedded()});
        #[cfg(feature = "native-fault-tests")]
        { envelope.summary["test_only"] = serde_json::json!("native-fault-tests"); }
        println!("{}", envelope.render(true)?);
    } else {
        println!("{}", line());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn embedded_is_nonempty_semverish() -> Result<(), String> {
        let v = super::embedded();
        if v.is_empty() {
            return Err("empty version".into());
        }
        if !v.chars().next().unwrap_or('x').is_ascii_digit() {
            return Err(format!("version should start with a digit: {v}"));
        }
        if !super::line().starts_with("rsrs ") {
            return Err(super::line());
        }
        Ok(())
    }
}
