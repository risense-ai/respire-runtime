//! Real CLI lifecycle embedding for the shared account and key coordinators.
//! Registration selection and OS supervisor control stay with the CLI. Private
//! grants, requests, journals and maintenance ownership stay in host-control.

use anyhow::{Context, Result};
use respire_commands::net_rpc::Health;
use respire_host_control::{
    AccountCoordinator, HostLifecycle, KeyCoordinator, LaunchContext, RegistrationMode,
    VerifiedRuntime,
};
use respire_protocol::host_control::HostAuthAccountResult;
use respire_protocol::HostAuthIdentity;
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::super::super::{manager, Registration};
use super::{control, lifecycle, model_control, read_registration};

pub(crate) fn accounts() -> AccountCoordinator {
    AccountCoordinator::new(
        crate::embedding::account_host().unwrap_or_else(|| Arc::new(CliHost::default())),
    )
}

pub(crate) fn keys() -> KeyCoordinator {
    KeyCoordinator::new(
        crate::embedding::account_host().unwrap_or_else(|| Arc::new(CliHost::default())),
    )
}

#[derive(Default)]
struct CliHost {
    // The maintenance flag may change under our CAS write. No other registration
    // policy may change between initial inspection and the final OS handoff.
    registration: RefCell<Option<(PathBuf, Option<Registration>)>>,
}

impl CliHost {
    fn checked_registration(&self, root: &Path) -> Result<Option<Registration>> {
        let root = root.canonicalize()?;
        let current = read_registration(&root)?;
        if let Some(config) = current.as_ref() {
            lifecycle::owned(config)?;
            lifecycle::ensure_control_endpoint(config)?;
            let state = manager::inspect(config)?;
            anyhow::ensure!(
                !state.registered || config.artifact_hashes.contains_key("service"),
                "unknown existing startup registration; no lifecycle action taken"
            );
            if config.enabled && !config.manually_stopped {
                anyhow::ensure!(
                    state.registered,
                    "startup registration is missing; account control never creates a registration"
                );
            } else {
                anyhow::ensure!(
                    !state.running,
                    "disabled or stopped startup registration still has a running supervisor"
                );
            }
        }
        let mut snapshot = self.registration.borrow_mut();
        if let Some((expected_root, expected)) = snapshot.as_ref() {
            anyhow::ensure!(
                *expected_root == root,
                "account control installation changed"
            );
            let mut comparable = current.clone();
            if let (Some(actual), Some(expected)) = (comparable.as_mut(), expected.as_ref()) {
                actual.maintenance = expected.maintenance;
            }
            anyhow::ensure!(
                serde_json::to_value(&comparable)? == serde_json::to_value(expected)?,
                "account control startup registration changed"
            );
        } else {
            *snapshot = Some((root, current.clone()));
        }
        Ok(current)
    }

    fn finish_managed_handoff(
        &self,
        profile: &Path,
        identity: &HostAuthIdentity,
        serving: bool,
    ) -> Result<()> {
        let (root, selected) = respire_client_host::config::control_roots()?;
        let root = root.canonicalize()?;
        let selected = selected.canonicalize()?;
        anyhow::ensure!(
            selected == profile && &control::identity(profile)? == identity,
            "completed account selection changed before supervisor handoff"
        );
        let config = self.checked_registration(&root)?;
        let Some(config) = config.filter(|config| config.enabled && !config.manually_stopped)
        else {
            // An explicitly stopped service stays stopped. An unregistered host
            // retains the independently verified direct serving instance.
            return Ok(());
        };
        anyhow::ensure!(
            !config.maintenance
                && !root
                    .join("runtime/autostart/maintenance.json")
                    .try_exists()?,
            "supervisor handoff requires completed durable maintenance"
        );
        anyhow::ensure!(
            !manager::inspect(&config)?.running,
            "supervisor unexpectedly resumed before account handoff"
        );
        if !serving {
            anyhow::ensure!(
                self.probe_runtime()?.is_none() && !self.endpoint_path().try_exists()?,
                "non-serving account completion unexpectedly has a Runtime owner"
            );
            return Ok(());
        }
        let (binary, manifest) = model_control::installed_model_runtime()?;
        let expected_account = match identity {
            HostAuthIdentity::Bound { account_id, .. } => account_id.clone(),
            _ => super::hash(profile.display().to_string().as_bytes()),
        };
        let owner = self
            .probe_runtime()?
            .context("verified account owner disappeared before handoff")?;
        model_control::verify_model_owner(
            &owner,
            &root,
            profile,
            Some(&config),
            &binary,
            &manifest,
            Some(&expected_account),
        )?;
        let require_ready = owner.store_ready;
        // The shared candidate has proved the account and commit. Move back to
        // the existing OS-owned supervisor instead of leaving that temporary
        // --supervised child orphaned when this account command exits.
        respire_host_control::lifecycle_io::drain_runtime(&owner)?;
        anyhow::ensure!(
            self.probe_runtime()?.is_none() && !self.endpoint_path().try_exists()?,
            "account handoff owner did not fully drain"
        );
        self.checked_registration(&root)?;
        manager::start(&config)?;
        lifecycle::wait_ready(&config)?;
        let restored = self
            .probe_runtime()?
            .context("registered account Runtime did not resume")?;
        model_control::verify_model_owner(
            &restored,
            &root,
            profile,
            Some(&config),
            &binary,
            &manifest,
            Some(&expected_account),
        )?;
        let (current_binary, current_manifest) = model_control::installed_model_runtime()?;
        anyhow::ensure!(
            manager::inspect(&config)?.running
                && restored.instance_id != owner.instance_id
                && (!require_ready || restored.store_ready)
                && current_binary == binary
                && current_manifest.version == manifest.version
                && current_manifest
                    .sha256
                    .eq_ignore_ascii_case(&manifest.sha256)
                && respire_client_host::config::control_roots()?
                    .1
                    .canonicalize()?
                    == profile
                && &control::identity(profile)? == identity,
            "registered account Runtime failed independent handoff verification"
        );
        self.checked_registration(&root)?;
        Ok(())
    }
}

impl HostLifecycle for CliHost {
    fn require_account_write(&self) -> Result<()> {
        crate::runtime_policy::require_host("private account and key control")?;
        anyhow::ensure!(
            lifecycle::current_boot_token().is_none(),
            "account and key control must own maintenance independently"
        );
        Ok(())
    }

    fn verified_runtime(&self) -> Result<VerifiedRuntime> {
        let (binary, manifest) = model_control::installed_model_runtime()?;
        let (root, _) = respire_client_host::config::control_roots()?;
        if let Some(config) = self
            .checked_registration(&root)?
            .filter(|config| config.enabled && !config.manually_stopped)
        {
            anyhow::ensure!(
                lifecycle::registered_runtime_image(&config)? == binary,
                "account startup requires the registered installed Runtime"
            );
        } else if let Some(raw) = respire_client_host::env::var_os("RSRS_RUNTIME_BIN") {
            anyhow::ensure!(
                PathBuf::from(raw).canonicalize()? == binary,
                "account startup cannot select an override instead of the installed Runtime"
            );
        }
        VerifiedRuntime::verify_installed(
            &binary,
            &manifest.sha256,
            &manifest.version,
            crate::net_rpc::rpc_port(),
        )
    }

    fn issuer_version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn inspect_registration(&self, root: &Path) -> Result<RegistrationMode> {
        Ok(match self.checked_registration(root)? {
            None => RegistrationMode::Unregistered,
            Some(config) if config.enabled && !config.manually_stopped => {
                RegistrationMode::Managed {
                    coordinator_id: config.id,
                }
            }
            Some(config) => RegistrationMode::Stopped {
                coordinator_id: config.id,
            },
        })
    }

    fn set_maintenance(&self, root: &Path, enabled: bool) -> Result<()> {
        let mut config = self
            .checked_registration(root)?
            .context("account maintenance registration disappeared")?;
        anyhow::ensure!(
            config.enabled && !config.manually_stopped,
            "account maintenance cannot enable a stopped registration"
        );
        config.maintenance = enabled;
        lifecycle::save(&mut config)?;
        if enabled {
            lifecycle::reset_attempts(&config)?;
        }
        self.checked_registration(root)?;
        Ok(())
    }

    fn probe_runtime(&self) -> Result<Option<Health>> {
        crate::rpc::probe_runtime()
    }

    fn endpoint_path(&self) -> PathBuf {
        crate::rpc::endpoint_path()
    }

    fn drain_runtime(&self, health: &Health) -> Result<()> {
        let (root, _) = respire_client_host::config::control_roots()?;
        let config = self
            .checked_registration(&root)?
            .filter(|config| config.enabled && !config.manually_stopped);
        if let Some(config) = config.as_ref() {
            lifecycle::verify_owned_runtime(config, health)?;
        }
        respire_host_control::lifecycle_io::drain_runtime(health)?;
        if let Some(config) = config.as_ref() {
            lifecycle::stop_drained_supervisor(config)?;
        }
        Ok(())
    }

    fn start_account_runtime(&self, launch: &LaunchContext) -> Result<()> {
        if let Some(config) = self
            .checked_registration(launch.installation_root())?
            .filter(|config| config.enabled && !config.manually_stopped)
        {
            anyhow::ensure!(
                !manager::inspect(&config)?.running,
                "account replacement requires the old supervisor to be stopped"
            );
        }
        respire_host_control::lifecycle_io::start_account_runtime(launch, &self.verified_runtime()?)
    }

    fn finish_account_handoff(&self, receipt: &HostAuthAccountResult) -> Result<()> {
        let profile = receipt
            .target_profile
            .as_deref()
            .context("committed account target is missing")?;
        let identity = control::identity(profile)?;
        anyhow::ensure!(
            matches!(&identity,
            HostAuthIdentity::Bound { account_id, session_sha256 }
                if receipt.account_id.as_ref() == Some(account_id)
                    && receipt.session_sha256.as_ref() == Some(session_sha256)),
            "committed account identity changed before supervisor handoff"
        );
        self.finish_managed_handoff(profile, &identity, true)
    }

    fn finish_key_handoff(
        &self,
        profile: &Path,
        identity: &HostAuthIdentity,
        serving: bool,
    ) -> Result<()> {
        self.finish_managed_handoff(profile, identity, serving)
    }
}
