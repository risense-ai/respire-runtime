//! Feedback feature configuration and immutable request plumbing owned by Host.
use crate::{transport::local::LocalStore, MemoryQuery, StoredMemory};
use anyhow::{Context, Result};
use serde_json::Value;

fn switch(name: &str, default: bool) -> Result<bool> {
    match crate::env::var(name) {
        Ok(value) => match value.trim() {
            "1" => Ok(true),
            "0" => Ok(false),
            _ => anyhow::bail!("{name} must be 0 or 1"),
        },
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error.into()),
    }
}
pub fn enabled() -> Result<bool> {
    crate::core_sdk::feedback_enabled()
}

/// Refresh before every query, including each benchmark case. No global counts,
/// thread-local feedback or mutation of source memory/read statistics is used.
pub fn query_settings(
    store: &LocalStore,
    query: &MemoryQuery,
    candidates: &[StoredMemory],
) -> Result<Value> {
    let mut settings = crate::recall_fusion::query_settings()?;
    if let Some(read_heat) = crate::read_heat::effective()? {
        settings.insert("read_heat".into(), Value::Bool(read_heat));
    }
    if enabled()? {
        anyhow::ensure!(crate::core_sdk::FEEDBACK_CONTRACT==1,"enabled feedback requires Core SDK feedback contract 1; install the paired SDK/CLI version");
        let threshold = match crate::env::var("RSRS_MARK_SIM") {
            Ok(value) => value
                .parse::<f64>()
                .context("RSRS_MARK_SIM must be between 0 and 1")?,
            Err(std::env::VarError::NotPresent) => 0.5,
            Err(error) => return Err(error.into()),
        };
        let ids = candidates
            .iter()
            .filter(|row| !row.deleted)
            .map(|row| row.id.clone())
            .collect();
        let counts = store.feedback_counts(
            &query.text,
            query.project.as_deref().unwrap_or(""),
            "",
            &ids,
            threshold,
            chrono::Utc::now().timestamp(),
        )?;
        settings.insert("feedback".into(),serde_json::json!({"enabled":true,"good":counts.good,"bad":counts.bad,"bad_penalty":switch("RSRS_BAD_PENALTY",true)?}));
    }
    Ok(Value::Object(settings))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_are_off_and_old_sdk_cannot_silently_accept_enabled_feedback() -> Result<()> {
        let isolate = crate::test_lock::Isolate::new()?;
        struct Restore(Vec<(String, Option<std::ffi::OsString>)>);
        impl Drop for Restore {
            fn drop(&mut self) {
                for (name, value) in &self.0 {
                    match value {
                        Some(value) => std::env::set_var(name, value),
                        None => std::env::remove_var(name),
                    }
                }
            }
        }
        let keys = [
            "RSRS_FEEDBACK",
            "ONEMEMORY_FEEDBACK",
            "RESPIRE_FEEDBACK",
            "RSRS_BAD_PENALTY",
            "RSRS_MARK_SIM",
        ];
        let _restore = Restore(
            keys.iter()
                .map(|name| (name.to_string(), std::env::var_os(name)))
                .collect(),
        );
        for name in keys {
            std::env::remove_var(name);
        }
        let store = LocalStore::open(&isolate.path().join("test.db"))?;
        let query = MemoryQuery::new("synthetic");
        assert!(!enabled()?);
        assert!(query_settings(&store, &query, &[])?
            .get("feedback")
            .is_none());
        std::env::set_var("RSRS_FEEDBACK", "invalid");
        assert!(enabled().is_err());
        std::env::set_var("RSRS_FEEDBACK", "1");
        assert!(enabled()?);
        if crate::core_sdk::FEEDBACK_CONTRACT != 1 {
            let error = query_settings(&store, &query, &[])
                .err()
                .context("old SDK must reject opt-in")?;
            assert!(error.to_string().contains("feedback contract 1"));
        } else {
            let context = query_settings(&store, &query, &[])?;
            assert_eq!(context["feedback"]["enabled"], true);
            assert_eq!(context["feedback"]["bad_penalty"], true);
            std::env::set_var("RSRS_BAD_PENALTY", "0");
            assert_eq!(
                query_settings(&store, &query, &[])?["feedback"]["bad_penalty"],
                false
            );
            std::env::set_var("RSRS_MARK_SIM", "2");
            assert!(query_settings(&store, &query, &[]).is_err());
        }
        std::env::set_var("RSRS_FEEDBACK", "0");
        std::env::set_var("ONEMEMORY_FEEDBACK", "1");
        assert!(!enabled()?);
        std::env::remove_var("RSRS_FEEDBACK");
        assert!(enabled()?);
        Ok(())
    }
}
