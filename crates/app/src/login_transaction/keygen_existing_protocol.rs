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


#[test]
fn original_result_binds_key_force_session_and_unknown_queries_never_replay() -> Result<()> {
    let isolated = crate::test_lock::Isolate::new()?;
    let _credentials = memory_keyring();
    let root = isolated.path().canonicalize()?;
    let id = uuid::Uuid::new_v4().to_string();
    let ownership = AuthOwnership::acquire(&root, &root)?;
    let result = control_keygen(&ownership, &HostAuthIdentity::Absent, &id, &id, false, false)?;
    ensure!(result.outcome == HostAuthOutcome::Committed, "synthetic keygen did not commit");
    let identity = HostAuthIdentity::Unbound { operation_id: id.clone(),
        session_sha256: result.session_sha256.context("fixture digest missing")? };
    let original = std::fs::read(root.join("session.json"))?;
    let before = serde_json::to_vec(&load_journal()?)?;
    let query = control_keygen(&ownership, &identity, &id, &id, false, true)?;
    assert!(query.outcome == HostAuthOutcome::Committed);
    assert_eq!(query.operation_id, id);
    assert!(control_keygen(&ownership, &identity, &id, &id, true, true).is_err());
    assert!(control_keygen(&ownership, &identity, &id, "other-key", false, true).is_err());
    let unknown = uuid::Uuid::new_v4().to_string();
    assert!(control_keygen(&ownership, &identity, &unknown, &unknown, false, true).is_err());
    assert!(control_keygen(&ownership, &HostAuthIdentity::Absent, &id, &id, false, true).is_err());
    assert_eq!(std::fs::read(root.join("session.json"))?, original);
    assert_eq!(serde_json::to_vec(&load_journal()?)?, before);
    let mut journal = load_journal()?;
    for phase in [AuthPhase::Admitted, AuthPhase::Prepared, AuthPhase::RolledBack] {
        journal.operations[0].phase = phase;
        save_journal(&journal)?;
        assert!(control_keygen(&ownership, &identity, &id, &id, false, true).is_err());
    }
    journal.operations[0].phase = AuthPhase::Committed;
    save_journal(&journal)?;
    std::fs::write(root.join("session.json"), b"{}")?;
    assert!(control_keygen(&ownership, &identity, &id, &id, false, true).is_err());
    std::fs::write(root.join("session.json"), original)?;
    journal.operations[0].idempotency_key = "changed-key".into();
    save_journal(&journal)?;
    assert!(control_keygen(&ownership, &identity, &id, &id, false, true).is_err());
    Ok(())
}
