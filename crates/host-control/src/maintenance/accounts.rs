//! Nonsecret account recovery binding. Published before any private auth effect.
//! It is never inferred from a current selection or an unrelated maintenance owner.
use super::*;
mod keygen_transfer;
pub use keygen_transfer::{KeygenAccountTransfer, KeygenAccountAdmission};
pub(crate) use keygen_transfer::{prepare_keygen_account, lookup_keygen_account};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AccountOrigin {
    pub identity: HostAuthIdentity,
    pub was_serving: bool,
    pub store_ready: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountBinding {
    schema: u32,
    operation_id: String,
    root: PathBuf,
    source: PathBuf,
    register: bool,
    user: String,
    addr: String,
    maintenance_token: String,
    original: AccountOrigin,
    sent: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    keygen_source: Option<keygen_transfer::KeygenSource>,
}

fn binding_path(root: &Path, id: &str) -> Result<PathBuf> {
    let parsed = uuid::Uuid::parse_str(id)?;
    anyhow::ensure!(
        parsed.get_version_num() == 4 && parsed.to_string() == id,
        "account recovery requires a canonical operation ID"
    );
    Ok(root
        .join("runtime/autostart/account-results")
        .join(format!("{id}.json")))
}

fn validate_binding(
    binding: &AccountBinding,
    root: &Path,
    source: &Path,
    operation_id: &str,
    register: bool,
    prior: Option<&Marker>,
) -> Result<()> {
    anyhow::ensure!(
        binding.schema == 1
            && binding.root == root
            && binding.source == source
            && binding.operation_id == operation_id
            && binding.register == register
            && (!binding.original.store_ready || binding.original.was_serving),
        "account recovery does not match its original operation and source"
    );
    let token = uuid::Uuid::parse_str(&binding.maintenance_token)?;
    anyhow::ensure!(
        token.get_version_num() == 4 && token.to_string() == binding.maintenance_token,
        "invalid original account maintenance token"
    );
    if let Some(prior) = prior {
        anyhow::ensure!(
            prior.token == binding.maintenance_token,
            "maintenance belongs to another operation; original account was not resumed"
        );
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AccountRecord {
    path: PathBuf,
    digest: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveAccount {
    schema: u32,
    operation_id: String,
}
fn active_path(root: &Path) -> PathBuf {
    root.join("runtime/autostart/account-active.json")
}
fn read_active(root: &Path) -> Result<Option<String>> {
    let path = respire_client_host::config::normalize_control_path(&active_path(root))?;
    let Some(bytes) = private_io::bounded_bytes(&path, MAINTENANCE_MARKER_MAX_BYTES)? else {
        return Ok(None);
    };
    let active: ActiveAccount = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid original active account binding"))?;
    anyhow::ensure!(active.schema == 1, "unsupported active account binding");
    binding_path(root, &active.operation_id)?;
    Ok(Some(active.operation_id))
}

/// Read-only routing hint. begin_account_locked repeats all binding checks under
/// takeover before any marker change. Neither this pointer nor request input is a grant.
pub(crate) fn pending_account(
    root: &Path,
    register: bool,
    user: &str,
    addr: &str,
) -> Result<Option<(String, PathBuf)>> {
    let Some(id) = read_active(root)? else {
        return Ok(None);
    };
    let path = respire_client_host::config::normalize_control_path(&binding_path(root, &id)?)?;
    let bytes = private_io::bounded_bytes(&path, MAINTENANCE_MARKER_MAX_BYTES)?
        .context("original active account record is missing")?;
    let binding: AccountBinding = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid original active account record"))?;
    validate_binding(&binding, root, &binding.source, &id, register, None)?;
    anyhow::ensure!(
        binding.user == user && binding.addr == addr,
        "another account operation is pending; do not replace its intent"
    );
    Ok(Some((id, binding.source)))
}

pub(crate) fn finish_account_routing(root: &Path, id: &str) -> Result<()> {
    let Some(active) = read_active(root)? else {
        return Ok(());
    };
    anyhow::ensure!(
        active == id,
        "active account operation changed before cleanup"
    );
    let path = active_path(root);
    fs::remove_file(&path)?;
    respire_spawn::durable::sync_directory(path.parent().context("account routing parent missing")?)
        .context("account completed; original routing cleanup is unconfirmed")
}

impl Maintenance {
    pub(crate) fn begin_account_locked(
        takeover: &LibraryLock,
        host: Arc<dyn HostLifecycle>,
        recovery: RecoveryMode,
        operation_id: &str,
        source: &Path,
        register: bool,
        observed: Option<&Health>,
        original_identity: &HostAuthIdentity,
        intent: Option<(&str, &str)>,
    ) -> Result<(Self, HostAuthIdentity, bool)> {
        host.require_account_write()?;
        let (root, _) = selected_roots()?;
        reject_offline_keygen(&root)?;
        anyhow::ensure!(
            takeover.protects(&root.join("runtime/takeover"))?,
            "account recovery requires installation takeover"
        );
        // Presence, even malformed, blocks before marker replacement. The key
        // coordinator alone may inspect/resolve its original journal and token.
        match fs::symlink_metadata(root.join("runtime/autostart/key-control.json")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => anyhow::bail!("finish the original key operation before account control"),
        }
        let source = respire_client_host::config::normalize_control_path(source)?.canonicalize()?;
        let path = binding_path(&root, operation_id)?;
        let path = respire_client_host::config::normalize_control_path(&path)?;
        let bytes = private_io::bounded_bytes(&path, MAINTENANCE_MARKER_MAX_BYTES)?;
        let prior_bytes = marker_bytes(&root)?;
        let prior = prior_bytes.as_deref().map(parse_marker).transpose()?;
        let active = read_active(&root)?;
        anyhow::ensure!(
            active
                .as_deref()
                .is_none_or(|active| active == operation_id),
            "another original account operation is pending; no new authentication was sent"
        );
        let (original, user, addr, token, sent, keygen_source) = match recovery {
            RecoveryMode::Fresh => {
                anyhow::ensure!(
                    bytes.is_none() && prior.is_none(),
                    "fresh account operation cannot replace an existing owner or operation"
                );
                let (user, addr) = intent.context("fresh account intent is missing")?;
                (
                    AccountOrigin {
                        identity: original_identity.clone(),
                        was_serving: observed.is_some(),
                        store_ready: observed.is_some_and(|health| health.store_ready),
                    },
                    user.to_owned(),
                    addr.to_owned(),
                    uuid::Uuid::new_v4().to_string(),
                    false,
                    None,
                )
            }
            RecoveryMode::QueryOriginal => {
                let binding: AccountBinding = serde_json::from_slice(bytes.as_deref().context(
                    "original host account binding is missing; no operation was replayed",
                )?)
                .map_err(|_| anyhow::anyhow!("invalid original host account binding"))?;
                validate_binding(
                    &binding,
                    &root,
                    &source,
                    operation_id,
                    register,
                    prior.as_ref(),
                )?;
                if let Some((user, addr)) = intent {
                    anyhow::ensure!(
                        binding.user == user && binding.addr == addr,
                        "account continuation changed its original user or server"
                    );
                }
                (
                    binding.original,
                    binding.user,
                    binding.addr,
                    binding.maintenance_token,
                    binding.sent,
                    binding.keygen_source,
                )
            }
        };
        // Write the original intent and route before the owner marker. A crash
        // at any boundary remains either unadmitted or discoverably recoverable.
        let binding = AccountBinding {
            schema: 1,
            operation_id: operation_id.to_owned(),
            root: root.clone(),
            source,
            register,
            user,
            addr,
            maintenance_token: token.clone(),
            original: original.clone(),
            sent,
            keygen_source,
        };
        let encoded = serde_json::to_vec(&binding)?;
        if bytes.as_deref() != Some(encoded.as_slice()) {
            private_write(
                &path,
                &encoded,
                bytes.as_ref().map(|bytes| hash(bytes)).as_deref(),
            )?;
        }
        if active.is_none() {
            private_write(
                &active_path(&root),
                &serde_json::to_vec(&ActiveAccount {
                    schema: 1,
                    operation_id: operation_id.to_owned(),
                })?,
                None,
            )?;
        }
        let mut owner = Self::begin_with_token(takeover, host, recovery, Some(&token))?;
        owner.account_origin = Some(original.clone());
        owner.account_record = Some(AccountRecord {
            path,
            digest: hash(&encoded),
        });
        Ok((owner, original.identity, original.was_serving))
    }

    pub(crate) fn account_operation_sent(&self) -> Result<bool> {
        self.check_owner()?;
        let record = self
            .account_record
            .as_ref()
            .context("original account binding unavailable")?;
        let bytes = private_io::bounded_bytes(&record.path, MAINTENANCE_MARKER_MAX_BYTES)?
            .context("original account binding disappeared")?;
        anyhow::ensure!(
            hash(&bytes) == record.digest,
            "original account binding changed"
        );
        let binding: AccountBinding = serde_json::from_slice(&bytes)?;
        anyhow::ensure!(
            binding.maintenance_token == self.marker.token && binding.root == self.root,
            "original account owner changed"
        );
        Ok(binding.sent)
    }

    pub(crate) fn mark_account_operation_sent(&mut self) -> Result<()> {
        anyhow::ensure!(
            !self.account_operation_sent()?,
            "original account operation was already admitted"
        );
        let record = self
            .account_record
            .as_ref()
            .context("original account binding unavailable")?;
        let bytes = private_io::bounded_bytes(&record.path, MAINTENANCE_MARKER_MAX_BYTES)?
            .context("original account binding disappeared")?;
        anyhow::ensure!(
            hash(&bytes) == record.digest,
            "original account binding changed before admission"
        );
        let mut binding: AccountBinding = serde_json::from_slice(&bytes)?;
        binding.sent = true;
        let next = serde_json::to_vec(&binding)?;
        private_write(&record.path, &next, Some(&record.digest))?;
        self.account_record = Some(AccountRecord {
            path: record.path.clone(),
            digest: hash(&next),
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> AccountBinding {
        AccountBinding {
            schema: 1,
            operation_id: uuid::Uuid::new_v4().to_string(),
            root: PathBuf::from("/synthetic/root"),
            source: PathBuf::from("/synthetic/source"),
            register: false,
            user: "synthetic".into(),
            addr: "https://example.invalid".into(),
            maintenance_token: uuid::Uuid::new_v4().to_string(),
            original: AccountOrigin {
                identity: HostAuthIdentity::Absent,
                was_serving: false,
                store_ready: false,
            },
            sent: false,
            keygen_source: None,
        }
    }
    #[test]
    fn original_binding_rejects_other_operation_source_family_and_root() {
        let binding = fixture();
        assert!(validate_binding(
            &binding,
            &binding.root,
            &binding.source,
            &binding.operation_id,
            false,
            None
        )
        .is_ok());
        assert!(validate_binding(
            &binding,
            &binding.root,
            &binding.source,
            &uuid::Uuid::new_v4().to_string(),
            false,
            None
        )
        .is_err());
        assert!(validate_binding(
            &binding,
            &binding.root,
            &binding.source,
            &binding.operation_id,
            true,
            None
        )
        .is_err());
        assert!(validate_binding(
            &binding,
            Path::new("/other"),
            &binding.source,
            &binding.operation_id,
            false,
            None
        )
        .is_err());
        assert!(validate_binding(
            &binding,
            &binding.root,
            Path::new("/other"),
            &binding.operation_id,
            false,
            None
        )
        .is_err());
    }
    #[test]
    fn other_operation_marker_cannot_be_replaced() {
        let binding = fixture();
        let mut marker = Marker {
            schema: 1,
            id: "synthetic".into(),
            token: uuid::Uuid::new_v4().to_string(),
            phase: Phase::Paused,
            expected_profile: None,
            expected_version: "synthetic".into(),
            owner_pid: 42,
            owner_birth: "1".into(),
            snapshot: None,
            agent_config: None,
        };
        assert!(validate_binding(
            &binding,
            &binding.root,
            &binding.source,
            &binding.operation_id,
            false,
            Some(&marker)
        )
        .is_err());
        marker.token = binding.maintenance_token.clone();
        assert!(validate_binding(
            &binding,
            &binding.root,
            &binding.source,
            &binding.operation_id,
            false,
            Some(&marker)
        )
        .is_ok());
    }
    #[test]
    fn original_nonserving_state_is_not_inferred_from_current_owner() -> Result<()> {
        let binding = fixture();
        let bytes = serde_json::to_vec(&binding)?;
        let decoded: AccountBinding = serde_json::from_slice(&bytes)?;
        assert!(!decoded.original.was_serving && !decoded.original.store_ready);
        assert_eq!(decoded.original.identity, HostAuthIdentity::Absent);
        let mut invalid = serde_json::to_value(binding)?;
        invalid["original"]["password"] = Value::String("synthetic-secret".into());
        assert!(serde_json::from_value::<AccountBinding>(invalid).is_err());
        Ok(())
    }
    #[test]
    fn active_original_route_preserves_operation_across_process_contexts() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().canonicalize()?;
        let mut binding = fixture();
        binding.root = root.clone();
        let path = binding_path(&root, &binding.operation_id)?;
        private_write(&path, &serde_json::to_vec(&binding)?, None)?;
        private_write(
            &active_path(&root),
            &serde_json::to_vec(&ActiveAccount {
                schema: 1,
                operation_id: binding.operation_id.clone(),
            })?,
            None,
        )?;
        let marker_before = serde_json::to_vec(&binding)?;
        assert_eq!(
            pending_account(&root, false, &binding.user, &binding.addr)?,
            Some((binding.operation_id.clone(), binding.source.clone()))
        );
        assert!(pending_account(&root, true, &binding.user, &binding.addr).is_err());
        assert!(pending_account(&root, false, "different-user", &binding.addr).is_err());
        assert!(pending_account(&root, false, &binding.user, "https://other.invalid").is_err());
        assert_eq!(std::fs::read(&path)?, marker_before);
        finish_account_routing(&root, &binding.operation_id)?;
        assert!(pending_account(&root, false, &binding.user, &binding.addr)?.is_none());
        assert_eq!(std::fs::read(&path)?, marker_before);
        Ok(())
    }
    #[test]
    fn wrong_operation_cleanup_never_changes_active_routing() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().canonicalize()?;
        let active = ActiveAccount {
            schema: 1,
            operation_id: uuid::Uuid::new_v4().to_string(),
        };
        let bytes = serde_json::to_vec(&active)?;
        private_write(&active_path(&root), &bytes, None)?;
        assert!(finish_account_routing(&root, &uuid::Uuid::new_v4().to_string()).is_err());
        assert_eq!(std::fs::read(active_path(&root))?, bytes);
        Ok(())
    }
    #[test]
    fn interrupted_recovery_keeps_original_token_and_binding_recoverable() -> Result<()> {
        let binding = fixture();
        let mut marker = Marker {
            schema: 1,
            id: "synthetic".into(),
            token: binding.maintenance_token.clone(),
            phase: Phase::Paused,
            expected_profile: None,
            expected_version: "synthetic".into(),
            owner_pid: 42,
            owner_birth: "1".into(),
            snapshot: None,
            agent_config: None,
        };
        let token = account_owner_token(
            RecoveryMode::QueryOriginal,
            Some(&marker),
            Some(&binding.maintenance_token),
        )?;
        marker.token = token;
        marker.owner_pid = 43;
        marker.owner_birth = "2".into();
        // Simulates exit immediately after the owner marker is republished.
        validate_binding(
            &binding,
            &binding.root,
            &binding.source,
            &binding.operation_id,
            false,
            Some(&marker),
        )?;
        assert_eq!(
            account_owner_token(
                RecoveryMode::QueryOriginal,
                None,
                Some(&binding.maintenance_token)
            )?,
            binding.maintenance_token
        );
        assert!(account_owner_token(
            RecoveryMode::QueryOriginal,
            Some(&marker),
            Some(&uuid::Uuid::new_v4().to_string())
        )
        .is_err());
        Ok(())
    }
    #[test]
    fn failed_binding_replace_preserves_original_query_binding() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().canonicalize()?;
        let mut binding = fixture();
        binding.root = root.clone();
        let bytes = serde_json::to_vec(&binding)?;
        let path = binding_path(&root, &binding.operation_id)?;
        private_write(&path, &bytes, None)?;
        assert!(private_write(&path, b"{}", Some("wrong-expected-digest")).is_err());
        assert_eq!(std::fs::read(&path)?, bytes);
        let saved: AccountBinding = serde_json::from_slice(&std::fs::read(&path)?)?;
        assert_eq!(
            account_owner_token(
                RecoveryMode::QueryOriginal,
                None,
                Some(&saved.maintenance_token)
            )?,
            binding.maintenance_token
        );
        Ok(())
    }
    #[test]
    fn initial_publication_boundaries_remain_unadmitted_and_recoverable() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().canonicalize()?;
        let mut binding = fixture();
        binding.root = root.clone();
        let path = binding_path(&root, &binding.operation_id)?;
        let bytes = serde_json::to_vec(&binding)?;
        // Failure after original-record publication, before active routing:
        // no marker and no authentication admission exist.
        private_write(&path, &bytes, None)?;
        assert!(read_active(&root)?.is_none() && marker_bytes(&root)?.is_none());
        assert!(!serde_json::from_slice::<AccountBinding>(&std::fs::read(&path)?)?.sent);
        private_write(
            &active_path(&root),
            &serde_json::to_vec(&ActiveAccount {
                schema: 1,
                operation_id: binding.operation_id.clone(),
            })?,
            None,
        )?;
        // Failure after routing, before marker: the same original id/token can
        // be resumed, but only explicit matching input can admit its first call.
        assert_eq!(
            pending_account(&root, false, &binding.user, &binding.addr)?.map(|value| value.0),
            Some(binding.operation_id.clone())
        );
        assert!(marker_bytes(&root)?.is_none());
        assert_eq!(
            account_owner_token(
                RecoveryMode::QueryOriginal,
                None,
                Some(&binding.maintenance_token)
            )?,
            binding.maintenance_token
        );
        // A failed marker publication leaves both original files unchanged.
        assert!(private_write(&marker_path(&root), b"{}", Some("missing-owner")).is_err());
        assert_eq!(std::fs::read(&path)?, bytes);
        assert_eq!(read_active(&root)?, Some(binding.operation_id));
        Ok(())
    }
}
