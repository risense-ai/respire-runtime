use super::*;
use keyring::credential::{Credential, CredentialApi, CredentialBuilderApi, CredentialPersistence};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

type Slot = (Option<String>, String, String);
type MemorySlots = Arc<Mutex<HashMap<Slot, Arc<keyring::mock::MockCredential>>>>;
#[derive(Default)]
struct MemoryKeyring(MemorySlots);
struct SharedCredential(Arc<keyring::mock::MockCredential>);
impl CredentialApi for SharedCredential {
    fn set_secret(&self, secret: &[u8]) -> keyring::Result<()> {
        self.0.set_secret(secret)
    }
    fn get_secret(&self) -> keyring::Result<Vec<u8>> {
        self.0.get_secret()
    }
    fn delete_credential(&self) -> keyring::Result<()> {
        self.0.delete_credential()
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
impl CredentialBuilderApi for MemoryKeyring {
    fn build(
        &self,
        target: Option<&str>,
        service: &str,
        user: &str,
    ) -> keyring::Result<Box<Credential>> {
        let slot = (
            target.map(str::to_owned),
            service.to_owned(),
            user.to_owned(),
        );
        let credential = self
            .0
            .lock()
            .map_err(|_| {
                keyring::Error::PlatformFailure(Box::new(std::io::Error::other(
                    "keygen handoff test credential store lock was poisoned",
                )))
            })?
            .entry(slot)
            .or_default()
            .clone();
        Ok(Box::new(SharedCredential(credential)))
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn persistence(&self) -> CredentialPersistence {
        CredentialPersistence::ProcessOnly
    }
}
pub(super) struct RestoreMock(MemorySlots);
impl Drop for RestoreMock {
    fn drop(&mut self) {
        keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
    }
}

pub(super) fn memory_keyring() -> RestoreMock {
    let store = MemorySlots::default();
    keyring::set_default_credential_builder(Box::new(MemoryKeyring(store.clone())));
    RestoreMock(store)
}


fn actor(root: &Path) -> HostKeygenRuntimeIdentity {
    HostKeygenRuntimeIdentity { pid: 42, process_start_id: "fixture-birth".into(),
        instance_id: "fixture-instance".into(), generation: 1, image_path: "fixture-image".into(),
        image_sha256: "a".repeat(64), installation_root: root.display().to_string(),
        installation_id: "fixture-installation".into(), profile: root.display().to_string(),
        account_id: digest(root.display().to_string().as_bytes()) }
}

#[test]
fn committed_keygen_handoff_is_readonly_and_rejects_receipt_or_live_changes() -> Result<()> {
    let isolated = crate::test_lock::Isolate::new()?;
    let _credentials = memory_keyring();
    let root = isolated.path().canonicalize()?;
    let id = uuid::Uuid::new_v4().to_string();
    let ownership = AuthOwnership::acquire(&root, &root)?;
    let result = control_keygen(&ownership, &HostAuthIdentity::Absent, &id, &id, false, false)?;
    ensure!(result.outcome == HostAuthOutcome::Committed, "synthetic keygen did not commit");
    drop(ownership);
    let mut params = HostAuthKeygenParams { schema_version: HOST_AUTH_SCHEMA_V,
        binding: respire_protocol::ControlBinding { installation_root: root.clone(), profile: root.clone(),
            launch_id: uuid::Uuid::new_v4().to_string(), expected_account_id: None },
        identity: HostAuthIdentity::Unbound { operation_id: id.clone(),
            session_sha256: result.session_sha256.context("fixture digest missing")? }, force: false };
    let original = std::fs::read(root.join("session.json"))?;
    let before = serde_json::to_vec(&load_journal()?)?;
    let mut calls = 0;
    let receipt = control_keygen_complete(&id, &id, &params, |_, _| { calls += 1; Ok(actor(&root)) })?;
    assert_eq!(calls, 1);
    assert_eq!(receipt.operation_id, id);
    assert_eq!(serde_json::to_vec(&load_journal()?)?, before);
    assert_eq!(std::fs::read(root.join("session.json"))?, original);
    let value = serde_json::to_value(&receipt)?;
    assert!(value.get("super_password").is_none());
    assert!(value.get("outcome").is_none());
    assert!(control_keygen_complete(&id, &id, &params, |_, _| anyhow::bail!("synthetic live verifier refused")).is_err());
    params.force = true;
    assert!(control_keygen_complete(&id, &id, &params, |_, _| { calls += 1; Ok(actor(&root)) }).is_err());
    params.force = false;
    assert!(control_keygen_complete(&id, "different-key", &params, |_, _| { calls += 1; Ok(actor(&root)) }).is_err());
    assert!(control_keygen_complete(&uuid::Uuid::new_v4().to_string(), &id, &params, |_, _| { calls += 1; Ok(actor(&root)) }).is_err());
    assert_eq!(calls, 1);
    let other = root.join("other-profile");
    std::fs::create_dir(&other)?;
    params.binding.profile = other;
    assert!(control_keygen_complete(&id, &id, &params, |_, _| { calls += 1; Ok(actor(&root)) }).is_err());
    params.binding.profile = root.clone();
    assert_eq!(calls, 1);
    let original_identity = params.identity.clone();
    params.identity = HostAuthIdentity::Absent;
    assert!(control_keygen_complete(&id, &id, &params, |_, _| { calls += 1; Ok(actor(&root)) }).is_err());
    params.identity = original_identity;
    assert_eq!(calls, 1);
    let mut journal = load_journal()?;
    for phase in [AuthPhase::Admitted, AuthPhase::Prepared, AuthPhase::RolledBack] {
        journal.operations[0].phase = phase;
        save_journal(&journal)?;
        assert!(control_keygen_complete(&id, &id, &params, |_, _| { calls += 1; Ok(actor(&root)) }).is_err());
    }
    assert_eq!(calls, 1);
    journal.operations[0].phase = AuthPhase::Committed;
    save_journal(&journal)?;
    assert!(control_keygen_complete(&id, &id, &params, |_, _| {
        std::fs::write(root.join("session.json"), b"{}")?;
        Ok(actor(&root))
    }).is_err());
    std::fs::write(root.join("session.json"), &original)?;
    assert!(control_keygen_complete(&id, &id, &params, |_, _| {
        let mut changed = load_journal()?;
        changed.operations[0].idempotency_key = "different".into();
        save_journal(&changed)?;
        Ok(actor(&root))
    }).is_err());
    Ok(())
}
