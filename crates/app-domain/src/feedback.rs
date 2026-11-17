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
    let mut settings = crate::core_config::query_settings()?;
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
        std::env::set_var("RSRS_FEEDBACK", "0");
        let candidate = respire_protocol::core_config::CoreConfigCandidate {
            read_heat: serde_json::json!(false),
            recall_fusion: serde_json::json!({"fusion":"attention", "fusion_alpha":0.3}),
        };
        let before = crate::core_config::revision()?;
        let validated = crate::core_config::validate(candidate.clone())?;
        assert_eq!(validated.state, "validated");
        assert_eq!(crate::core_config::revision()?, before);
        let applied = crate::core_config::apply(candidate.clone(), before)?;
        assert_eq!(applied.state, "applied");
        assert_eq!(applied.applies, "next_query");
        assert_eq!(applied.revision, before + 1);
        let context = query_settings(&store, &query, &[])?;
        assert_eq!(context["read_heat"], false);
        assert_eq!(context["fusion"], "attention");
        assert_eq!(context["fusion_alpha"], 0.3);
        assert_eq!(crate::core_config::read()?.effective, applied.effective);
        assert!(crate::core_config::apply(candidate, before).is_err());
        assert_eq!(crate::core_config::revision()?, applied.revision);
        let invalid = respire_protocol::core_config::CoreConfigCandidate {
            read_heat: serde_json::json!("false"), recall_fusion: serde_json::Value::Null,
        };
        assert!(crate::core_config::validate(invalid.clone()).is_err());
        assert!(crate::core_config::apply(invalid, applied.revision).is_err());
        assert_eq!(crate::core_config::revision()?, applied.revision);
        let defaults = respire_protocol::core_config::CoreConfigCandidate {
            read_heat: serde_json::Value::Null, recall_fusion: serde_json::Value::Null,
        };
        let reset = crate::core_config::apply(defaults, applied.revision)?;
        assert_eq!(reset.effective["read_heat"], true);
        assert!(query_settings(&store, &query, &[])?.get("read_heat").is_none());
        Ok(())
    }
}
