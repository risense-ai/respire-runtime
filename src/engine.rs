//! Public ciphertext orchestration. Account keys never cross the Core ABI.
use anyhow::{Context, Result};
use super::{crypto, model::{Kind, MemoryEntry, MemoryQuery, PayloadV2, StoredMemory}};
use respire_core_sdk::search::Embedder;
pub use respire_core_sdk::RecalledWithContext;

/// Unlocked session key material (in memory; gone when the process ends).
pub struct SessionKeys {
    /// User Root Key
    pub urk: [u8; 32],
    /// Content-encryption data key (derived from URK)
    data_key: [u8; 32],
    legacy_data_key: [u8; 32],
    rsrs_data_key: [u8; 32],
    write_rsrs: bool,
    /// Embedding encryption key (derived from URK, domain-separated; local plaintext copy is for search)
    _embedding_key: [u8; 32],
}

impl SessionKeys {
    /// Build session keys from URK.
    pub fn from_urk(urk: [u8; 32]) -> Result<Self> {
        Self::from_namespace(urk, true)
    }

    /// Unmarked existing vaults keep their write format until explicit migration.
    pub fn from_legacy_urk(urk: [u8; 32]) -> Result<Self> {
        Self::from_namespace(urk, false)
    }

    fn from_namespace(urk: [u8; 32], write_rsrs: bool) -> Result<Self> {
        let legacy_data_key = crypto::derive_subkey(&urk, b"onememory:data:v1")?;
        let rsrs_data_key = crypto::derive_subkey(&urk, b"rsrs:data:v1")?;
        let data_key = if write_rsrs { rsrs_data_key } else { legacy_data_key };
        let embedding_key = crypto::derive_subkey(&urk, if write_rsrs {
            b"rsrs:embedding:v1" } else { b"onememory:embedding:v1" })?;
        Ok(Self {
            urk,
            data_key,
            legacy_data_key,
            rsrs_data_key,
            write_rsrs,
            _embedding_key: embedding_key,
        })
    }

    pub fn encrypt_content(&self, plaintext: &str) -> Result<(String, String)> {
        let (nonce, ciphertext) = crypto::encrypt_item(&self.data_key, plaintext)?;
        Ok((nonce, if self.write_rsrs { format!("{}{ciphertext}", crypto::RSRS_PREFIX) } else { ciphertext }))
    }

    pub fn decrypt_content(&self, ciphertext: &str, nonce: &str) -> Result<String> {
        if let Some(value) = ciphertext.strip_prefix(crypto::RSRS_PREFIX) {
            return crypto::decrypt_item(&self.rsrs_data_key, value, nonce);
        }
        anyhow::ensure!(!ciphertext.starts_with("rsrs:"), "unsupported ciphertext namespace version");
        crypto::decrypt_item(&self.legacy_data_key, ciphertext, nonce)
    }

    /// Re-encrypt the optional older vector payload without recomputing a model.
    pub fn migrate_embedding(&self, value: &str) -> Result<String> {
        if value.is_empty() { return Ok(String::new()); }
        let current = value.strip_prefix(crypto::RSRS_PREFIX);
        let (nonce, ciphertext) = current.unwrap_or(value).split_once(':')
            .context("encrypted embedding has an unsupported format")?;
        let source = crypto::derive_subkey(&self.urk, if current.is_some() {
            b"rsrs:embedding:v1" } else { b"onememory:embedding:v1" })?;
        let bytes = crypto::decrypt_bytes(&source, ciphertext, nonce)?;
        let target = crypto::derive_subkey(&self.urk, b"rsrs:embedding:v1")?;
        let (nonce, ciphertext) = crypto::encrypt_bytes(&target, &bytes)?;
        anyhow::ensure!(crypto::decrypt_bytes(&target, &ciphertext, &nonce)? == bytes,
            "migrated embedding did not round-trip");
        Ok(format!("{}{nonce}:{ciphertext}", crypto::RSRS_PREFIX))
    }

    /// Password + Secret + kdf_salt + wrapped URK → session keys (new-device unlock chain).
    pub fn unlock(
        password: &str,
        account_secret: &str,
        kdf_salt: &str,
        wrapped_urk: &str,
        urk_nonce: &str,
    ) -> Result<Self> {
        let current = wrapped_urk.strip_prefix(crypto::RSRS_PREFIX);
        let kek = if current.is_some() { crypto::derive_rsrs_password_kek(password, account_secret, kdf_salt)? }
            else { crypto::derive_kek(password, account_secret, kdf_salt)? };
        let urk = crypto::unwrap_key(current.unwrap_or(wrapped_urk), urk_nonce, &kek)
            .context("URK unwrap failed: wrong password or recovery key")?;
        Self::from_namespace(urk, current.is_some())
    }

    /// Unlock a cloud vault wrap with the super password (independent of login password).
    pub fn unlock_super(
        super_pass: &str,
        kdf_salt: &str,
        wrapped_urk: &str,
        urk_nonce: &str,
    ) -> Result<Self> {
        let kek = crypto::derive_super_kek(super_pass, kdf_salt)?;
        let current = wrapped_urk.strip_prefix(crypto::RSRS_PREFIX);
        let urk = crypto::unwrap_key(current.unwrap_or(wrapped_urk), urk_nonce, &kek)
            .context("URK unwrap failed: wrong super password")?;
        Self::from_namespace(urk, current.is_some())
    }

    /// Master password + Secret Key unlock vault v3 (1Password model).
    pub fn unlock_vault(
        super_pass: &str,
        secret_key: &str,
        kdf_salt: &str,
        wrapped_urk: &str,
        urk_nonce: &str,
    ) -> Result<Self> {
        let current = wrapped_urk.strip_prefix(crypto::RSRS_PREFIX);
        let kek = if current.is_some() { crypto::derive_rsrs_vault_kek(super_pass, secret_key, kdf_salt)? }
            else { crypto::derive_vault_kek(super_pass, secret_key, kdf_salt)? };
        let urk = crypto::unwrap_key(current.unwrap_or(wrapped_urk), urk_nonce, &kek)
            .context("URK unwrap failed: wrong master password or Secret Key")?;
        Self::from_namespace(urk, current.is_some())
    }

    /// Unlock vault v4 with the super password (system-generated recovery-style key) as the single factor.
    pub fn unlock_v4(
        super_pass: &str,
        kdf_salt: &str,
        wrapped_urk: &str,
        urk_nonce: &str,
    ) -> Result<Self> {
        let current = wrapped_urk.strip_prefix(crypto::RSRS_PREFIX);
        let kek = if current.is_some() { crypto::derive_rsrs_kek(super_pass, kdf_salt)? }
            else { crypto::derive_kek_v4(super_pass, kdf_salt)? };
        let urk = crypto::unwrap_key(current.unwrap_or(wrapped_urk), urk_nonce, &kek)
            .context("URK unwrap failed: wrong super password")?;
        Self::from_namespace(urk, current.is_some())
    }
}

/// Memory engine — plaintext ↔ ciphertext orchestration.
pub struct MemoryEngine;


impl MemoryEngine {
    pub fn seal<E: Embedder>(
        keys: &SessionKeys,
        embedder: &E,
        entry: &MemoryEntry,
        user: &str,
    ) -> Result<StoredMemory> {
        // v2 payload: metadata and content encrypted as a whole (including parent_id — the causal parent travels with ciphertext so the tree restores across devices)
        let payload = PayloadV2 {
            supersedes: entry.supersedes.clone(),
            superseded_by: entry.superseded_by.clone(),
            see_also: entry.see_also.clone(),
            kind: entry.kind.as_str().to_owned(),
            tags: entry.tags.join(","),
            title: entry.title.clone(),
            content: entry.content.clone(),
            user: entry.user.clone(),
            computer: entry.computer.clone(),
            project: entry.project.clone(),
            created_at: entry.created_at.clone(),
            updated_at: entry.updated_at.clone(),
            emotion: entry.emotion,
            parent_id: entry.parent_id.clone(),
            importance: entry.importance.clone(),
            device: entry.device.clone(),
            modified_by: entry.modified_by.clone(),
        };
        let payload_json = serde_json::to_string(&payload).context("payload serialize failed")?;
        let (nonce, ciphertext) = keys.encrypt_content(&payload_json)?;

        let prepared = embedder.prepare(entry)?;

        Ok(StoredMemory {
            id: entry.id.clone(),
            user: user.to_owned(),
            ciphertext,
            nonce,
            embedding_enc: String::new(),
            updated_at: entry.updated_at.clone(),
            deleted: false,
            local_kind: entry.kind.as_str().to_owned(),
            local_tags: entry.tags.join(","),
            local_title: entry.title.clone(),
            local_project: entry.project.clone(),
            local_computer: entry.computer.clone(),
            local_embedding: None,
            local_parent_id: entry.parent_id.clone(),
            local_created_at: entry.created_at.clone(),
            local_content_head: entry.content.chars().take(500).collect(),
            local_recall_count: 0,
            local_importance: entry.importance.clone(),
            local_device: entry.device.clone(),
            local_modified_by: entry.modified_by.clone(),
            local_chunks: Vec::new(),
            local_artifact: prepared.artifact,
        })
    }

    pub fn payload_parent(keys: &SessionKeys, stored: &StoredMemory) -> Result<String> {
        let payload_json = keys.decrypt_content(&stored.ciphertext, &stored.nonce)?;
        let payload: PayloadV2 =
            serde_json::from_str(&payload_json).context("payload parse failed")?;
        Ok(payload.parent_id)
    }

    pub fn restore_version(
        keys: &SessionKeys,
        stored: &mut StoredMemory,
        stamp: &str,
    ) -> Result<()> {
        Self::prepare_resolution(keys, stored, stamp, None)
    }

    pub fn equivalent_versions(
        keys: &SessionKeys,
        left: &StoredMemory,
        right: &StoredMemory,
    ) -> Result<bool> {
        if left.id != right.id || left.deleted != right.deleted {
            return Ok(false);
        }
        if left.ciphertext == right.ciphertext && left.nonce == right.nonce {
            return Ok(true);
        }
        if left.ciphertext.is_empty() || right.ciphertext.is_empty() {
            return Ok(false);
        }
        let normalize = |b: &StoredMemory| -> Result<serde_json::Value> {
            let text = keys.decrypt_content(&b.ciphertext, &b.nonce)?;
            let mut payload: serde_json::Value = serde_json::from_str(&text)?;
            let object = payload
                .as_object_mut()
                .ok_or_else(|| anyhow::anyhow!("invalid encrypted payload"))?;
            object.remove("updated_at");
            Ok(payload)
        };
        Ok(normalize(left)? == normalize(right)?)
    }

    pub fn prepare_resolution(
        keys: &SessionKeys,
        stored: &mut StoredMemory,
        stamp: &str,
        content: Option<&str>,
    ) -> Result<()> {
        let plaintext = keys.decrypt_content(&stored.ciphertext, &stored.nonce)?;
        let mut payload: serde_json::Value = serde_json::from_str(&plaintext)?;
        let object = payload
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("invalid encrypted payload"))?;
        object.insert("updated_at".into(), serde_json::json!(stamp));
        if let Some(content) = content {
            object.insert("content".into(), serde_json::json!(content));
        }
        let (nonce, ciphertext) =
            keys.encrypt_content(&serde_json::to_string(&payload)?)?;
        stored.nonce = nonce;
        stored.ciphertext = ciphertext;
        stored.updated_at = stamp.to_owned();
        stored.deleted = false;
        stored.embedding_enc.clear();
        stored.local_embedding = None;
        stored.local_chunks.clear();
        stored.local_artifact.clear();
        hydrate_local(keys, stored)
    }

    /// Change only encrypted relationships and retain the existing derived index.
    pub fn reseal_edges(keys: &SessionKeys, stored: &StoredMemory, stamp: &str,
        edit: impl FnOnce(&mut PayloadV2)) -> Result<StoredMemory> {
        let plaintext = keys.decrypt_content(&stored.ciphertext, &stored.nonce)?;
        let mut payload: PayloadV2 = serde_json::from_str(&plaintext).context("payload parse failed")?;
        let mut expected = payload.clone();
        edit(&mut payload);
        expected.supersedes = payload.supersedes.clone();
        expected.superseded_by = payload.superseded_by.clone();
        expected.see_also = payload.see_also.clone();
        expected.modified_by = payload.modified_by.clone();
        anyhow::ensure!(serde_json::to_value(&payload)? == serde_json::to_value(&expected)?,
            "relationship edit must not change embedding source metadata");
        payload.updated_at = stamp.to_owned();
        let (nonce,ciphertext) = keys.encrypt_content(&serde_json::to_string(&payload)?)?;
        let mut result = stored.clone();
        result.nonce = nonce;
        result.ciphertext = ciphertext;
        result.updated_at = stamp.to_owned();
        result.local_modified_by = payload.modified_by;
        Ok(result)
    }

    pub fn reseal_parent(
        keys: &SessionKeys,
        stored: &StoredMemory,
        new_parent: &str,
        updated_at: &str,
    ) -> Result<StoredMemory> {
        let payload_json = keys.decrypt_content(&stored.ciphertext, &stored.nonce)?;
        let mut payload: PayloadV2 =
            serde_json::from_str(&payload_json).context("payload parse failed")?;
        payload.parent_id = new_parent.to_owned();
        payload.updated_at = updated_at.to_owned();
        let payload_json = serde_json::to_string(&payload)?;
        let (nonce, ciphertext) = keys.encrypt_content(&payload_json)?;
        let mut out = stored.clone();
        out.ciphertext = ciphertext;
        out.nonce = nonce;
        out.updated_at = updated_at.to_owned();
        out.local_parent_id = new_parent.to_owned();
        Ok(out)
    }

    pub fn open(keys: &SessionKeys, stored: &StoredMemory) -> Result<MemoryEntry> {
        let payload_json = keys.decrypt_content(&stored.ciphertext, &stored.nonce)?;
        let payload: PayloadV2 =
            serde_json::from_str(&payload_json).context("payload parse failed")?;
        Ok(MemoryEntry {
            supersedes: payload.supersedes,
            superseded_by: payload.superseded_by,
            see_also: payload.see_also,
            id: stored.id.clone(),
            kind: Kind::from_str(&payload.kind),
            tags: payload
                .tags
                .split(',')
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .map(ToOwned::to_owned)
                .collect(),
            title: payload.title,
            content: payload.content,
            user: payload.user,
            computer: payload.computer,
            project: payload.project,
            created_at: payload.created_at,
            updated_at: payload.updated_at,
            emotion: payload.emotion,
            // Plaintext columns are always latest (attach/reparent dual-write; pull hydrates) — display uses the columns
            parent_id: stored.local_parent_id.clone(),
            importance: payload.importance,
            device: payload.device,
            modified_by: payload.modified_by,
        })
    }

    pub fn recall_local<E: Embedder>(
        keys: &SessionKeys, embedder: &E, stored_list: &[StoredMemory], query: &MemoryQuery,
    ) -> Result<Vec<MemoryEntry>> {
        let snapshots = snapshots(keys, stored_list);
        respire_core_sdk::query(embedder, &snapshots, query, "plain")
    }

    pub fn recall_local_scored<E: Embedder>(
        keys: &SessionKeys, embedder: &E, stored_list: &[StoredMemory], query: &MemoryQuery,
    ) -> Result<Vec<(f32, MemoryEntry)>> {
        let snapshots = snapshots(keys, stored_list);
        respire_core_sdk::query(embedder, &snapshots, query, "scored")
    }

    pub fn remember_candidates<E: Embedder>(
        keys: &SessionKeys, embedder: &E, stored_list: &[StoredMemory], query: &MemoryQuery,
    ) -> Result<respire_core_sdk::RememberCandidates> {
        let snapshots = snapshots(keys, stored_list);
        respire_core_sdk::remember_candidates(embedder, &snapshots, query)
    }

    pub fn recall_local_contextual<E: Embedder>(
        keys: &SessionKeys, embedder: &E, stored_list: &[StoredMemory], query: &MemoryQuery,
    ) -> Result<Vec<RecalledWithContext>> {
        let snapshots = snapshots(keys, stored_list);
        respire_core_sdk::query(embedder, &snapshots, query, "contextual")
    }
}

pub fn reembed_embedding<E: Embedder>(keys: &SessionKeys, embedder: &E, stored: &StoredMemory) -> Result<(Vec<u8>, String)> {
    let entry = MemoryEngine::open(keys, stored)?;
    let prepared = embedder.prepare(&entry)?;
    Ok((prepared.artifact, String::new()))
}

pub fn hydrate_local(keys: &SessionKeys, stored: &mut StoredMemory) -> Result<()> {
    let payload_json = keys.decrypt_content(&stored.ciphertext, &stored.nonce)?;
    let payload: PayloadV2 = serde_json::from_str(&payload_json).context("payload parse failed")?;
    stored.local_kind = payload.kind;
    stored.local_tags = payload.tags;
    stored.local_title = payload.title;
    stored.local_project = payload.project;
    stored.local_computer = payload.computer;
    stored.local_parent_id = payload.parent_id;
    stored.local_created_at = payload.created_at;
    stored.local_content_head = payload.content.chars().take(500).collect();
    // True importance lives in the payload — previously missed on hydrate, a cross-library pull wiped the index column to empty (956 rows)
    stored.local_importance = payload.importance;
    stored.local_device = payload.device;
    stored.local_modified_by = payload.modified_by;
    Ok(())
}

pub fn snapshots(keys: &SessionKeys, stored: &[StoredMemory]) -> Vec<respire_core_sdk::Snapshot> {
    stored.iter().map(|memory| {
        let entry = if memory.deleted { None } else { MemoryEngine::open(keys, memory).ok() };
        respire_core_sdk::Snapshot::new(memory, entry)
    }).collect()
}
