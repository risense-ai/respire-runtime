//! Business event receipts for the calling host. Runtime never reads plugins.json
//! or starts plugin processes; hosts own hook configuration and execution.

use std::cell::RefCell;

#[derive(Debug, Clone, Copy)]
pub enum HookEvent {
    PostRemember,
    PostRecall,
    PostForget,
    PostSync,
}

impl HookEvent {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PostRemember => "post-remember",
            Self::PostRecall => "post-recall",
            Self::PostForget => "post-forget",
            Self::PostSync => "post-sync",
        }
    }
}

thread_local! {
    static EVENTS: RefCell<Option<Vec<serde_json::Value>>> = const { RefCell::new(None) };
}

/// Capture only the current command. Background work has no calling host.
pub struct EventScope;

impl EventScope {
    pub fn begin() -> Self {
        EVENTS.with(|events| *events.borrow_mut() = Some(Vec::new()));
        Self
    }

    pub fn finish(self) -> Vec<serde_json::Value> {
        EVENTS.with(|events| match events.borrow_mut().take() {
            Some(events) => events,
            None => unreachable!("host event scope must be active until finish"),
        })
    }
}

impl Drop for EventScope {
    fn drop(&mut self) {
        EVENTS.with(|events| *events.borrow_mut() = None);
    }
}

pub fn record(event: HookEvent, data: serde_json::Value) {
    EVENTS.with(|events| {
        if let Some(events) = events.borrow_mut().as_mut() {
            events.push(serde_json::json!({"event": event.as_str(), "data": data}));
        }
    });
}

pub fn remember_done_payload(id: &str, title: &str, importance: &str) -> serde_json::Value {
    serde_json::json!({"id": id, "title": title, "importance": importance})
}

pub fn recall_payload(query: &str, project: &str, hits: &[(String, f32)]) -> serde_json::Value {
    serde_json::json!({
        "query": query,
        "project": project,
        "hits": hits.iter().map(|(id, score)| serde_json::json!({"id": id, "score": score})).collect::<Vec<_>>(),
    })
}

pub fn forget_payload(id: &str) -> serde_json::Value {
    serde_json::json!({"id": id})
}

pub fn sync_payload(pulled: usize, pushed: usize) -> serde_json::Value {
    serde_json::json!({"pulled": pulled, "pushed": pushed})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_builders_and_event_names() {
        let scope = EventScope::begin();
        record(HookEvent::PostRemember, remember_done_payload("id", "title", "important"));
        record(HookEvent::PostRecall, recall_payload("query", "project", &[("id".into(), 0.9)]));
        record(HookEvent::PostForget, forget_payload("id"));
        record(HookEvent::PostSync, sync_payload(1, 2));
        let events = scope.finish();
        assert_eq!(events.len(), 4);
        assert_eq!(events[0]["event"], "post-remember");
        assert_eq!(events[0]["data"]["importance"], "important");
        assert_eq!(events[1]["data"]["hits"][0]["id"], "id");
        assert_eq!(events[2]["data"]["id"], "id");
        assert_eq!(events[3]["data"]["pushed"], 2);
        record(HookEvent::PostSync, sync_payload(3, 4));
        assert!(EventScope::begin().finish().is_empty());
        {
            let _scope = EventScope::begin();
            record(HookEvent::PostForget, forget_payload("discarded"));
        }
        assert!(EventScope::begin().finish().is_empty());
    }
}
