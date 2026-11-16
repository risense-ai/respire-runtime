//! Private delivery of core events to the host's configured plugin executor.
use serde::{Deserialize, Serialize};

pub const HOST_PLUGIN_SCHEMA_V: u32 = 1;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPluginEventRequest {
    pub plugin_event: u32,
    pub id: String,
    pub event: HostPluginEvent,
    pub data: HostPluginSyncData,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostPluginEvent {
    PostSync,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPluginSyncData {
    pub pulled: u64,
    pub pushed: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostPluginEventAck {
    pub plugin_event_ack: u32,
    pub id: String,
    pub result: HostPluginEventResult,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostPluginEventResult {
    Completed { warnings: Vec<String> },
    Failed { error: String },
}
