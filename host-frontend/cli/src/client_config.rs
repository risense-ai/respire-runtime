//! Host client.json edits. Profile maintenance and database gates stay with Runtime.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use respire_client_host::{config, paths};
use respire_commands::output::{Item, ResultEnvelope, Status};
use respire_protocol::config_control::{
    ConfigChangeIntent, ConfigValidateParams, CONFIG_VALIDATE_SCHEMA_V,
};
use respire_protocol::{ControlBinding, HostAuthIdentity};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub(crate) const DEFAULT_SERVER_ADDR: &str = "https://api.rsrs.rs";

/// None denotes an absent file, not an empty or malformed JSON document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Revision(Option<String>);

impl Revision {
    pub(crate) fn as_deref(&self) -> Option<&str> {
        self.0.as_deref()
    }
}

#[derive(Debug)]
pub(crate) struct ConfigConflict {
    pub expected: Revision,
    pub actual: Revision,
}

impl std::fmt::Display for ConfigConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "client config changed since review; expected {:?}, actual {:?}",
            self.expected, self.actual
        )
    }
}

impl std::error::Error for ConfigConflict {}

#[derive(Clone)]
pub(crate) struct ConfigSnapshot {
    path: PathBuf,
    revision: Revision,
    value: Value,
    bytes: Option<Vec<u8>>,
}

/// These requests must not be silently downgraded to an ordinary JSON write.
pub(crate) enum ConfigPlan {
    ReadOnly(ConfigSnapshot),
    HostWrite(ConfigEdit),
    ProfileMaintenance(ConfigEdit),
    RuntimeValidation(ConfigEdit),
}

pub(crate) struct ConfigEdit {
    original: ConfigSnapshot,
    updated: Value,
    pub previous_profile: PathBuf,
    pub next_profile: PathBuf,
    needs_maintenance: bool,
    pub intent: ConfigChangeIntent,
}

fn revision(bytes: Option<&[u8]>) -> Revision {
    Revision(bytes.map(|bytes| hex::encode(Sha256::digest(bytes))))
}

fn config_lock(path: &Path) -> Result<File> {
    let lock_path = path.with_extension("json.lock");
    fs::create_dir_all(
        lock_path
            .parent()
            .context("client config lock has no parent")?,
    )?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)?;
    lock.lock()?;
    Ok(lock)
}

fn read_at(path: PathBuf) -> Result<ConfigSnapshot> {
    let bytes = match fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).context("cannot read client config"),
    };
    let value = match bytes.as_ref() {
        Some(bytes) => {
            serde_json::from_slice(bytes).context("client config contains invalid JSON")?
        }
        None => json!({}),
    };
    config::validate_client_config(&value, &path)?;
    if let Some(mode) = value.get("service_mode").and_then(Value::as_str) {
        anyhow::ensure!(
            matches!(mode, "normal" | "readonly" | "off"),
            "invalid client service_mode"
        );
    }
    Ok(ConfigSnapshot {
        path,
        revision: revision(bytes.as_deref()),
        value,
        bytes,
    })
}

pub(crate) fn read_config() -> Result<ConfigSnapshot> {
    config::control_roots()?;
    if let Some(raw) = respire_client_host::env::var_os("RSRS_M3_DIR") {
        anyhow::ensure!(
            raw.to_str().is_some_and(|value| !value.trim().is_empty()),
            "RSRS_M3_DIR must be a nonempty UTF-8 path"
        );
    }
    read_at(paths::client_config_path())
}

pub(crate) fn review_agent_config(intent: respire_protocol::config_control::AgentConfigIntent,
    root: PathBuf, profile: PathBuf) -> Result<respire_protocol::config_control::AgentConfigReview> {
    use respire_protocol::config_control::AgentConfigReview;
    let workspace = intent.workspace_mode().map_err(anyhow::Error::msg)?.is_some();
    let path = if workspace { paths::client_config_path() } else { profile.join("agent.json") };
    config::normalize_control_path(&path)?;
    let bytes = if workspace { read_config()?.bytes } else {
        match fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        }
    };
    let original_config = bytes.as_ref().map(|bytes| String::from_utf8(bytes.clone())).transpose()?;
    let original = if workspace {
        original_config.as_deref().map(serde_json::from_str).transpose()?.unwrap_or_else(|| json!({}))
    } else {
        original_config.as_deref().and_then(|text| serde_json::from_str(text).ok()).unwrap_or_else(|| json!({}))
    };
    let candidate = intent.apply(&original).map_err(anyhow::Error::msg)?;
    if workspace { config::validate_client_config(&candidate, &path)?; }
    let mut review = AgentConfigReview { operation_id: uuid::Uuid::new_v4().to_string(),
        installation_root: root, profile: profile.clone(),
        identity: respire_protocol::metadata_control::metadata_identity(&profile, |bytes| hex::encode(Sha256::digest(bytes)))?,
        intent, original_config, original_revision: revision(bytes.as_deref()).0,
        candidate_revision: hex::encode(Sha256::digest(serde_json::to_vec_pretty(&candidate)?)),
        fingerprint: String::new() };
    review.fingerprint = hex::encode(Sha256::digest(review.fingerprint_bytes()?));
    Ok(review)
}

/// Plan the five existing `config` flags without publishing any of them.
pub(crate) fn prepare_config(
    data_dir: Option<&str>,
    addr: Option<&str>,
    autosync: Option<bool>,
    cure_auto: Option<bool>,
    rpc_parallelism: Option<u32>,
) -> Result<ConfigPlan> {
    let original = read_config()?;
    if data_dir.is_none()
        && addr.is_none()
        && autosync.is_none()
        && cure_auto.is_none()
        && rpc_parallelism.is_none()
    {
        return Ok(ConfigPlan::ReadOnly(original));
    }
    let intent = ConfigChangeIntent {
        data_dir: data_dir.map(str::to_owned),
        addr: addr.map(str::to_owned),
        autosync,
        cure_auto,
        rpc_parallelism,
    };
    let updated = intent.apply(&original.value).map_err(anyhow::Error::msg)?;
    config::validate_client_config(&updated, &original.path)?;
    let previous_profile = paths::data_dir_from_config(Some(&original.value));
    let next_profile = paths::data_dir_from_config(Some(&updated));
    let edit = ConfigEdit {
        original,
        updated,
        previous_profile,
        next_profile,
        needs_maintenance: data_dir.is_some(),
        intent,
    };
    Ok(if addr.is_some() || autosync == Some(true) {
        ConfigPlan::RuntimeValidation(edit)
    } else if edit.needs_maintenance {
        ConfigPlan::ProfileMaintenance(edit)
    } else {
        ConfigPlan::HostWrite(edit)
    })
}

impl ConfigEdit {
    pub(crate) fn publish_host(self) -> Result<ConfigSnapshot> {
        anyhow::ensure!(
            !self.needs_maintenance,
            "data_dir change requires host maintenance coordination"
        );
        anyhow::ensure!(
            self.intent.addr.is_none() && self.intent.autosync != Some(true),
            "server or sync change requires private Runtime validation"
        );
        self.publish()
    }

    /// Call only inside the existing host profile drain/verify/rollback transaction.
    /// No file lock is held while that transaction stops or starts a Runtime.
    pub(crate) fn publish_profile_switch(self) -> Result<ConfigSnapshot> {
        anyhow::ensure!(self.needs_maintenance, "expected a reviewed profile change");
        anyhow::ensure!(
            self.intent.addr.is_none() && self.intent.autosync != Some(true),
            "server or sync change requires private Runtime validation"
        );
        self.publish()
    }

    /// Only the config coordinator may stage this before private Runtime validation.
    pub(crate) fn stage_candidate(&self) -> Result<ConfigSnapshot> {
        self.publish()
    }

    pub(crate) fn validation_params(
        &self,
        binding: ControlBinding,
        identity: HostAuthIdentity,
        source_identity: HostAuthIdentity,
        source_profile: PathBuf,
        target_profile: PathBuf,
    ) -> Result<ConfigValidateParams> {
        Ok(ConfigValidateParams {
            schema_version: CONFIG_VALIDATE_SCHEMA_V,
            binding,
            identity,
            source_identity,
            source_profile,
            target_profile,
            original_revision: self.original.revision.0.clone(),
            original_config: self
                .original
                .bytes
                .as_ref()
                .map(|bytes| String::from_utf8(bytes.clone()))
                .transpose()?,
            candidate_revision: hex::encode(Sha256::digest(serde_json::to_vec_pretty(
                &self.updated,
            )?)),
            intent: self.intent.clone(),
        })
    }

    pub(crate) fn assert_candidate(&self) -> Result<ConfigSnapshot> {
        anyhow::ensure!(
            paths::client_config_path() == self.original.path,
            "client config location changed"
        );
        let _lock = config_lock(&self.original.path)?;
        let current = read_at(self.original.path.clone())?;
        let expected = revision(Some(&serde_json::to_vec_pretty(&self.updated)?));
        if current.revision != expected {
            return Err(ConfigConflict {
                expected,
                actual: current.revision,
            }
            .into());
        }
        Ok(current)
    }

    /// Roll back exact original bytes, including original absence; never overwrite a third-party edit.
    pub(crate) fn rollback_candidate(&self) -> Result<()> {
        anyhow::ensure!(
            paths::client_config_path() == self.original.path,
            "client config location changed"
        );
        let _lock = config_lock(&self.original.path)?;
        let current = read_at(self.original.path.clone())?;
        if current.revision == self.original.revision {
            return Ok(());
        }
        let expected = revision(Some(&serde_json::to_vec_pretty(&self.updated)?));
        if current.revision != expected {
            return Err(ConfigConflict {
                expected,
                actual: current.revision,
            }
            .into());
        }
        replace_config(&self.original.path, self.original.bytes.as_deref())
    }

    fn publish(&self) -> Result<ConfigSnapshot> {
        anyhow::ensure!(
            paths::client_config_path() == self.original.path,
            "client config location changed since review"
        );
        let _lock = config_lock(&self.original.path)?;
        let current = read_at(self.original.path.clone())?;
        if current.revision != self.original.revision {
            return Err(ConfigConflict {
                expected: self.original.revision.clone(),
                actual: current.revision,
            }
            .into());
        }
        config::validate_client_config(&self.updated, &self.original.path)?;
        let bytes = serde_json::to_vec_pretty(&self.updated)?;
        replace_config(&self.original.path, Some(&bytes))?;
        Ok(ConfigSnapshot {
            path: self.original.path.clone(),
            revision: revision(Some(&bytes)),
            value: self.updated.clone(),
            bytes: Some(bytes),
        })
    }
}

fn replace_config(path: &Path, bytes: Option<&[u8]>) -> Result<()> {
    let parent = path.parent().context("client config has no parent")?;
    let Some(bytes) = bytes else {
        fs::remove_file(path)?;
        respire_spawn::durable::sync_directory(parent)?;
        return Ok(());
    };
    let temp = parent.join(format!(".client-json-{}.tmp", uuid::Uuid::new_v4()));
    let published = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        respire_spawn::durable::replace_file(&temp, path)?;
        Ok(())
    })();
    if let Err(error) = published {
        if let Err(cleanup) = fs::remove_file(&temp) {
            if cleanup.kind() != std::io::ErrorKind::NotFound {
                return Err(error.context(format!("temporary config cleanup failed: {cleanup}")));
            }
        }
        return Err(error);
    }
    Ok(())
}

impl ConfigSnapshot {
    pub(crate) fn revision(&self) -> &Revision {
        &self.revision
    }

    /// `runtime_workers` must come from a verified Runtime observation, never this CLI's CPU count.
    pub(crate) fn envelope(
        &self,
        runtime_workers: Option<usize>,
        parallelism_changed: bool,
    ) -> ResultEnvelope {
        let profile = paths::data_dir_from_config(Some(&self.value));
        let addr = self.value["addr"]
            .as_str()
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_SERVER_ADDR);
        let autosync = !respire_client_host::env::var("RSRS_NO_AUTOSYNC")
            .is_ok_and(|value| value != "0")
            && self.value["autosync"].as_bool().unwrap_or(true);
        let cure_auto = self.value["cure_auto"].as_bool().unwrap_or(true);
        let saved = self.value["rpc_parallelism"]
            .as_u64()
            .filter(|value| *value > 0);
        let mut workers = runtime_workers
            .map(|value| value.to_string())
            .unwrap_or_else(|| "not observed; Runtime is stopped or did not report worker count".to_owned());
        if parallelism_changed {
            workers.push_str(" (after runtime restart)");
        }
        ResultEnvelope::new(
            "config",
            Status::Ok,
            json!({
                "data_dir":profile.to_string_lossy(), "default_data_dir":paths::default_data_dir().to_string_lossy(),
                "addr":addr, "default_addr":DEFAULT_SERVER_ADDR, "autosync":autosync, "cure_auto":cure_auto,
                "rpc_parallelism":saved, "rpc_workers":runtime_workers,
            }),
            vec![
                Item::new("data dir", Status::Ok, profile.display().to_string()),
                Item::new("server", Status::Ok, addr),
                Item::new("auto-sync", Status::Ok, autosync.to_string()),
                Item::new("auto-cure", Status::Ok, cure_auto.to_string()),
                Item::new(
                    "rpc workers",
                    if runtime_workers.is_some() {
                        Status::Ok
                    } else {
                        Status::Skip
                    },
                    workers,
                ),
            ],
        )
    }
}
