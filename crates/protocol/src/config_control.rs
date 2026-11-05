//! Private validation of one reviewed client.json candidate under host maintenance.
use crate::{ControlBinding, HostAuthIdentity};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Component, Path, PathBuf};

pub const CONFIG_VALIDATE_METHOD: &str = "control.config_validate";
pub const CONFIG_VALIDATE_SCHEMA_V: u32 = 1;

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigChangeIntent {
    pub data_dir: Option<String>,
    pub addr: Option<String>,
    pub autosync: Option<bool>,
    pub cure_auto: Option<bool>,
    pub rpc_parallelism: Option<u32>,
}

impl ConfigChangeIntent {
    /// The complete allowed edit; unrelated configuration fields survive unchanged.
    pub fn apply(&self, original: &Value) -> Result<Value, &'static str> {
        let mut value = original.clone();
        let object = value
            .as_object_mut()
            .ok_or("client config must be an object")?;
        if let Some(dir) = self.data_dir.as_deref() {
            let dir = dir.trim();
            if dir.is_empty() {
                object.remove("data_dir");
            } else {
                if !(Path::new(dir).is_absolute()
                    || dir.starts_with("~/")
                    || dir.starts_with("~\\"))
                    || Path::new(dir)
                        .components()
                        .any(|part| part == Component::ParentDir)
                {
                    return Err("data dir must be absolute without parent traversal (or use ~/)");
                }
                object.insert("data_dir".into(), Value::String(dir.to_owned()));
            }
        }
        if let Some(addr) = self.addr.as_deref() {
            let addr = addr.trim();
            if !(addr.starts_with("http://") || addr.starts_with("https://")) {
                return Err("server address must start with http:// or https://");
            }
            object.insert("addr".into(), Value::String(addr.to_owned()));
        }
        if let Some(on) = self.autosync {
            object.insert("autosync".into(), Value::Bool(on));
        }
        if let Some(on) = self.cure_auto {
            object.insert("cure_auto".into(), Value::Bool(on));
        }
        if let Some(workers) = self.rpc_parallelism {
            if workers == 0 {
                object.remove("rpc_parallelism");
            } else {
                object.insert("rpc_parallelism".into(), Value::from(workers));
            }
        }
        Ok(value)
    }
}

// The original document may contain private, unrelated fields. Never derive Debug,
// log these parameters, or send them through argv, environment or public HTTP.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigValidateParams {
    pub schema_version: u32,
    pub binding: ControlBinding,
    pub identity: HostAuthIdentity,
    pub source_identity: HostAuthIdentity,
    pub source_profile: PathBuf,
    pub target_profile: PathBuf,
    pub original_revision: Option<String>,
    pub original_config: Option<String>,
    pub candidate_revision: String,
    pub intent: ConfigChangeIntent,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigValidationReceipt {
    pub original_revision: Option<String>,
    pub candidate_revision: String,
    pub intent: ConfigChangeIntent,
    pub source_profile: PathBuf,
    pub target_profile: PathBuf,
    pub source_identity: HostAuthIdentity,
    pub target_identity: HostAuthIdentity,
    pub off_mode: bool,
}

pub const AGENT_CONFIG_SET_METHOD: &str = "control.agent_config.set";
pub const AGENT_CONFIG_RESULT_METHOD: &str = "control.agent_config.result";

/// One setter, not an argv entry point. Keep the original spelling for its output.
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfigIntent {
    pub key: String,
    pub raw_value: String,
}

impl AgentConfigIntent {
    pub fn value(&self) -> Value {
        serde_json::from_str(&self.raw_value).unwrap_or_else(|_| Value::String(self.raw_value.clone()))
    }

    pub fn workspace_mode(&self) -> Result<Option<&str>, &'static str> {
        match self.key.trim() {
            "memory_off" | "readonly" => match self.value().as_bool() {
                Some(false) => Ok(Some("normal")),
                Some(true) => Ok(Some(if self.key.trim() == "memory_off" { "off" } else { "readonly" })),
                None => Err("memory_off and readonly must be true or false"),
            },
            "workspace_mode" => match self.value().as_str() {
                Some("normal") => Ok(Some("normal")), Some("readonly") => Ok(Some("readonly")),
                Some("off") => Ok(Some("off")),
                _ => Err("workspace_mode must be normal, readonly or off"),
            },
            _ => Ok(None),
        }
    }

    pub fn apply(&self, original: &Value) -> Result<Value, &'static str> {
        let key = self.key.trim();
        if key.is_empty() { return Err("key must not be empty"); }
        let value = self.value();
        if key == "recall_mode" && !matches!(value.as_str(), Some("fast" | "quality")) {
            return Err("recall_mode must be fast or quality");
        }
        let mut updated = original.clone();
        if let Some(mode) = self.workspace_mode()? {
            updated.as_object_mut().ok_or("client config must be an object")?
                .insert("service_mode".into(), Value::String(mode.into()));
        } else if let Some(object) = updated.as_object_mut() {
            object.insert(key.to_owned(), value);
        }
        Ok(updated)
    }
}

// Exact original bytes stay in the inherited channel / existing maintenance marker.
#[derive(Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfigReview {
    pub operation_id: String,
    pub installation_root: PathBuf,
    pub profile: PathBuf,
    pub identity: crate::metadata_control::HostMetadataIdentity,
    pub intent: AgentConfigIntent,
    pub original_config: Option<String>,
    pub original_revision: Option<String>,
    pub candidate_revision: String,
    pub fingerprint: String,
}

impl AgentConfigReview {
    pub fn fingerprint_bytes(&self) -> serde_json::Result<Vec<u8>> {
        serde_json::to_vec(&(CONFIG_VALIDATE_SCHEMA_V, AGENT_CONFIG_SET_METHOD, &self.operation_id,
            &self.installation_root, &self.profile, &self.identity, &self.intent,
            &self.original_revision, &self.candidate_revision))
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfigParams {
    pub schema_version: u32,
    pub binding: ControlBinding,
    pub review: AgentConfigReview,
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentConfigOutcome { Committed, RolledBack, Unknown }

#[derive(Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfigReceipt {
    pub review: AgentConfigReview,
    pub outcome: AgentConfigOutcome,
    pub result: Value,
}

/// An extension of maintenance.json, not another journal or target-value proof.
#[derive(Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfigMaintenance {
    pub review: AgentConfigReview,
    pub was_serving: bool,
    pub store_ready: bool,
    pub sent: bool,
    pub receipt: Option<AgentConfigReceipt>,
}
