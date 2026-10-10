//! Host leases keep an immutable Core view alive across concurrent requests.
use anyhow::Result;
use serde_json::{json, Value};
use std::cell::RefCell;
use std::sync::Arc;

thread_local! {
    static CURRENT: RefCell<Option<(String, bool)>> = const { RefCell::new(None) };
    static DEFER_INDEX: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub struct ResidentLease { key: String, lexical_only: bool }

impl ResidentLease {
    pub fn publish(key: String, base: Option<&Self>, model: &str,
        snapshots: &[crate::Snapshot], removed: &[String]) -> Result<Arc<Self>> {
        let mut payload = json!({"key":key,"model":model,"snapshots":snapshots,"removed":removed});
        if let Some(base) = base { payload["base_key"] = json!(base.key); }
        let result: Value = crate::execute("resident_publish", payload)?;
        Ok(Arc::new(Self { key, lexical_only:result["indexed"].as_u64() == Some(0) }))
    }

    pub fn enter(&self) -> ResidentScope {
        ResidentScope(CURRENT.with(|slot| slot.replace(Some((self.key.clone(), self.lexical_only)))))
    }
}

impl Drop for ResidentLease {
    fn drop(&mut self) {
        if let Err(error) = crate::execute::<Value>("resident_release", json!({"key":self.key})) {
            eprintln!("resident view release failed: {error:#}");
        }
    }
}

pub struct ResidentScope(Option<(String, bool)>);
impl Drop for ResidentScope {
    fn drop(&mut self) { CURRENT.with(|slot| { slot.replace(self.0.take()); }); }
}

pub fn resident_scope_active() -> bool { CURRENT.with(|slot| slot.borrow().is_some()) }
pub(crate) fn resident_lexical_only() -> bool {
    CURRENT.with(|slot| slot.borrow().as_ref().is_some_and(|(_, lexical_only)| *lexical_only))
}
pub(crate) fn apply_scope(operation: &str, payload: &mut Value) {
    if matches!(operation, "query" | "query_business" | "related_business" | "remember_candidates" | "candidate_report") {
        CURRENT.with(|slot| {
            if let Some((key, lexical_only)) = slot.borrow().as_ref() {
                payload.as_object_mut().map(|fields| fields.remove("snapshots"));
                payload["resident_key"] = json!(key);
                payload["lexical_only"] = json!(lexical_only);
            }
        });
    }
}

pub struct BackgroundIndexScope(bool);
pub fn defer_indexing() -> BackgroundIndexScope {
    BackgroundIndexScope(DEFER_INDEX.with(|flag| flag.replace(true)))
}
pub fn indexing_deferred() -> bool { DEFER_INDEX.with(std::cell::Cell::get) }
impl Drop for BackgroundIndexScope {
    fn drop(&mut self) { DEFER_INDEX.with(|flag| flag.set(self.0)); }
}
