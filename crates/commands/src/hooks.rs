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

/// Capture only the current command. Autosync uses the acknowledged private host channel.
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
    fn payload_builders_and_event_names() -> anyhow::Result<()> {
        use respire_protocol::host_plugin::*;
        use crate::rpc_serve::HostPluginChannel;
        // A standalone host has not opted into the private plugin extension.
        crate::rpc_serve::deliver_post_sync(3, 4)?;
        let plugin_timeout: anyhow::Error = crate::rpc_serve::HostPluginFailure(anyhow::anyhow!("configured hook timeout")).into();
        assert!(!crate::rpc_serve::background_sync_retryable(&plugin_timeout));
        assert!(crate::rpc_serve::background_sync_retryable(&anyhow::anyhow!("network timeout")));
        let channel = HostPluginChannel::default();
        for result in [
            HostPluginEventResult::Completed { warnings: Vec::new() },
            HostPluginEventResult::Completed { warnings: vec!["observer warning".into()] },
            HostPluginEventResult::Failed { error: "configured plugin exited unsuccessfully".into() },
        ] {
            let failed = matches!(&result, HostPluginEventResult::Failed { .. });
            let observed = channel.exchange(|bytes| {
                let request: HostPluginEventRequest = serde_json::from_slice(bytes)?;
                assert_eq!(request.plugin_event, HOST_PLUGIN_SCHEMA_V);
                assert!(matches!(request.event, HostPluginEvent::PostSync));
                assert_eq!((request.data.pulled, request.data.pushed), (3, 4));
                assert!(channel.acknowledge(HostPluginEventAck { plugin_event_ack: HOST_PLUGIN_SCHEMA_V,
                    id: "another-event".into(), result: HostPluginEventResult::Completed { warnings: Vec::new() } }).is_err());
                assert!(channel.acknowledge(HostPluginEventAck { plugin_event_ack: HOST_PLUGIN_SCHEMA_V + 1,
                    id: request.id.clone(), result: HostPluginEventResult::Completed { warnings: Vec::new() } }).is_err());
                channel.acknowledge(HostPluginEventAck { plugin_event_ack: HOST_PLUGIN_SCHEMA_V, id: request.id, result })
            }, 3, 4);
            if failed {
                let failure: anyhow::Error = crate::rpc_serve::HostPluginFailure(
                    observed.err().ok_or_else(|| anyhow::anyhow!("failed plugin was accepted"))?).into();
                assert!(failure.to_string().contains("configured plugin exited unsuccessfully"));
                assert!(!crate::rpc_serve::background_sync_retryable(&failure));
            } else {
                let warnings = observed?;
                assert!(warnings.is_empty() || warnings == ["observer warning"]);
            }
        }
        let disconnected = HostPluginChannel::default();
        let disconnected_error: anyhow::Error = crate::rpc_serve::HostPluginFailure(
            disconnected.exchange(|_| disconnected.close("parent disconnected".into()), 0, 0)
                .err().ok_or_else(|| anyhow::anyhow!("disconnect was accepted"))?).into();
        assert!(disconnected_error.to_string().contains("parent disconnected"));
        assert!(!crate::rpc_serve::background_sync_retryable(&disconnected_error));
        assert!(disconnected.exchange(|_| anyhow::bail!("closed channel must not write again"), 0, 0).is_err());
        let broken_output = HostPluginChannel::default();
        assert!(broken_output.exchange(|_| anyhow::bail!("broken output pipe"), 0, 0)
            .err().ok_or_else(|| anyhow::anyhow!("write failure was accepted"))?.to_string().contains("broken output pipe"));
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
        Ok(())
    }
}
