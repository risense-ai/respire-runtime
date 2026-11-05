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
