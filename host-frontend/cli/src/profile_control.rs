//! Profile switches use the config coordinator, not local app setters.
use anyhow::{Context, Result};
use respire_client_host::{config, identity};
use respire_commands::output::{Item, ResultEnvelope};
use respire_protocol::HostAuthIdentity;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

fn profile_dir(name: &str) -> Result<PathBuf> {
    anyhow::ensure!(
        !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "account profile name allows only letters/digits/-/_; got `{name}`"
    );
    let (root, _) = config::control_roots()?;
    Ok(if name == "main" {
        root
    } else {
        root.join("accounts").join(name)
    })
}

fn switch_profile(name: &str, dir: &Path, create_missing: bool) -> Result<(ResultEnvelope, Value)> {
    crate::runtime_policy::require_host("existing profile switching")?;
    let path = dir.to_str().context("profile path is not UTF-8")?;
    let (result, verified_identity) =
        crate::autostart::run_profile_config_control(name, create_missing)?;
    // Display follows the verified receipt, never treats an unbound keygen session as Bound.
    let actual =
        match identity::auth_session_identity(dir, |bytes| format!("{:x}", Sha256::digest(bytes)))?
        {
            identity::AuthSessionIdentity::Absent => HostAuthIdentity::Absent,
            identity::AuthSessionIdentity::Unbound {
                operation_id,
                session_sha256,
            } => HostAuthIdentity::Unbound {
                operation_id,
                session_sha256,
            },
            identity::AuthSessionIdentity::Bound {
                account_id,
                session_sha256,
            } => HostAuthIdentity::Bound {
                account_id,
                session_sha256,
            },
        };
    anyhow::ensure!(
        actual == verified_identity,
        "profile identity changed after config validation"
    );
    let user = match &verified_identity {
        HostAuthIdentity::Bound { account_id, .. } => {
            let user = identity::session_user_of_dir(dir)?
                .context("verified Bound profile has no user")?;
            anyhow::ensure!(
                format!("{:x}", Sha256::digest(user.as_bytes())) == *account_id,
                "profile display user differs from the verified Bound identity"
            );
            user
        }
        HostAuthIdentity::Absent | HostAuthIdentity::Unbound { .. } => String::new(),
    };
    let hint = if user.is_empty() {
        "this profile has no account yet \u{2014} run rsrs login (existing account) or rsrs register (new account)"
    } else {
        "switched to this profile \u{2014} local library/keys/session follow the profile and do not mix"
    };
    Ok((
        result,
        json!({"name":name,"dir":path,"user":user,"hint":hint}),
    ))
}

pub(crate) fn account_use(name: &str) -> Result<ResultEnvelope> {
    let dir = profile_dir(name)?;
    let (mut result, value) = switch_profile(name, &dir, true)?;
    result.command = "account".into();
    result.summary = json!({"name":value["name"],"dir":value["dir"],"user":value["user"]});
    result.items = vec![
        Item::new("profile", result.status, name),
        Item::new("directory", result.status, dir.display().to_string()),
    ];
    result.details = Value::Null;
    Ok(result)
}

pub(crate) fn validated_space_name(name: &str) -> Result<&str> {
    let name = name.trim();
    if name.is_empty() || name.len() > 40 {
        return Err(respire_client_host::input_error::InputError(
            "space name must not be empty and must be <=40 bytes".into(),
        )
        .into());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(respire_client_host::input_error::InputError(format!(
            "space name allows only letters/digits/-/_, got \"{name}\""
        ))
        .into());
    }
    Ok(name)
}

pub(crate) fn space_use(name: &str) -> Result<ResultEnvelope> {
    let name = validated_space_name(name)?;
    let dir = profile_dir(name)?;
    match std::fs::metadata(&dir) {
        Ok(metadata) => anyhow::ensure!(metadata.is_dir(), "space profile is not a directory"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(respire_client_host::input_error::InputError(format!(
                "space \"{name}\" does not exist - rsrs space list to see current spaces; to create one, run rsrs space create {name}"
            ))
            .into());
        }
        Err(error) => return Err(error).context("cannot inspect space profile directory"),
    }
    let (mut result, value) = switch_profile(name, &dir, false)?;
    result.command = "space".into();
    result.summary = json!({"action":"use","name":name});
    result.items = vec![
        Item::new("space", result.status, name),
        Item::new("directory", result.status, dir.display().to_string()),
    ];
    result.details = value;
    Ok(result)
}

pub(crate) fn space_create(name: &str) -> Result<ResultEnvelope> {
    let name = validated_space_name(name)?;
    let (mut result, identity) = crate::autostart::run_space_config_control(name)?;
    let directory = profile_dir(name)?;
    let current = respire_client_host::identity::auth_session_identity(&directory, |bytes| {
        use sha2::Digest;
        format!("{:x}", sha2::Sha256::digest(bytes))
    })?;
    anyhow::ensure!(matches!(identity, respire_protocol::HostAuthIdentity::Absent)
        && matches!(current, respire_client_host::identity::AuthSessionIdentity::Absent),
        "new space identity changed after confirmed creation");
    result.command = "space".into();
    result.summary = json!({"action":"create","name":name});
    result.items = vec![Item::new("space", result.status, name)];
    result.details = json!({"name":name,"dir":directory.to_string_lossy(),
        "hint":"space created and switched in - next rsrs register for this space, then space invite to mint an invite code"});
    result.actions.push("space created and switched in - next rsrs register for this space, then space invite to mint an invite code".into());
    Ok(result)
}

/// Fixed installation root itself or installation-root/accounts/NAME allowlist.
pub(crate) struct ProfileTarget {
    root: PathBuf,
    directory: PathBuf,
    create_missing: bool,
    space_name: Option<String>,
}

impl ProfileTarget {
    pub(crate) fn new(name: &str, create_missing: bool) -> Result<Self> {
        let (root, _) = config::control_roots()?;
        // Reject redirected installation ancestors before takeover can create its lock files.
        check_directory(&root)?;
        Ok(Self {
            root,
            directory: profile_dir(name)?,
            create_missing,
            space_name: None,
        })
    }

    pub(crate) fn new_space(name: &str) -> Result<Self> {
        let name = validated_space_name(name)?;
        anyhow::ensure!(name != "main", "\"main\" is reserved for the primary profile; pick another space name");
        let mut target = Self::new(name, true)?;
        target.space_name = Some(name.to_owned());
        Ok(target)
    }

    pub(crate) fn directory(&self) -> &Path {
        &self.directory
    }

    pub(crate) fn verify_existing(&self) -> Result<()> {
        check_directory(&self.root)?;
        check_directory(&self.directory)?;
        anyhow::ensure!(
            config::control_roots()?.0 == self.root
                && self
                    .directory
                    .canonicalize()?
                    .starts_with(self.root.canonicalize()?),
            "profile target or installation root changed"
        );
        Ok(())
    }

    /// The coordinator already owns takeover. Never acquire it again here.
    pub(crate) fn prepare_locked(
        &self,
        takeover: &respire_client_host::lock::LibraryLock,
        next_profile: &Path,
    ) -> Result<PreparedProfile> {
        anyhow::ensure!(
            next_profile == self.directory
                && config::control_roots()?.0 == self.root
                && takeover.protects(&self.root.join("runtime/takeover"))?,
            "profile creation review or takeover root changed"
        );
        check_directory(&self.root)?;
        let maintenance = self.root.join("runtime/autostart/maintenance.json");
        match fs::symlink_metadata(maintenance) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("cannot inspect existing maintenance"),
            Ok(_) => anyhow::bail!("finish existing maintenance before preparing a profile"),
        }
        let mut prepared = PreparedProfile {
            root: self.root.clone(),
            target: self.directory.clone(),
            created: Vec::new(),
            space_name: self.space_name.clone(),
        };
        let preparation = (|| -> Result<()> {
            if self.directory != self.root {
                for directory in [self.root.join("accounts"), self.directory.clone()] {
                    check_directory(directory.parent().context("profile parent missing")?)?;
                    match fs::symlink_metadata(&directory) {
                        Ok(_) => {
                            anyhow::ensure!(self.space_name.is_none() || directory != self.directory,
                                "space \"{}\" already exists - pick another name, or run rsrs space use {}",
                                self.space_name.as_deref().unwrap_or(""), self.space_name.as_deref().unwrap_or(""));
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                            anyhow::ensure!(
                                self.create_missing,
                                "profile does not exist; space use cannot create a profile"
                            );
                            // Exact create, not create_dir_all: existing directories are never claimed.
                            fs::create_dir(&directory)?;
                            check_directory(&directory)?;
                            let token = uuid::Uuid::new_v4().to_string();
                            let marker = directory.join(format!(".rsrs-profile-create-{token}"));
                            prepared.created.push(CreatedDirectory {
                                directory: directory.clone(),
                                marker: marker.clone(),
                                token: token.clone(),
                            });
                            let mut options = fs::OpenOptions::new();
                            options.write(true).create_new(true);
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::OpenOptionsExt;
                                options.mode(0o600);
                            }
                            options.open(marker)?.write_all(token.as_bytes())?;
                        }
                        Err(error) => {
                            return Err(error).context("cannot inspect profile directory")
                        }
                    }
                    check_directory(&directory)?;
                    anyhow::ensure!(
                        directory
                            .canonicalize()?
                            .starts_with(self.root.canonicalize()?),
                        "profile target escapes the installation root"
                    );
                }
            }
            Ok(())
        })();
        if let Err(error) = preparation {
            let warnings = prepared.cleanup(false);
            return Err(error.context(format!("profile preparation cleanup: {warnings:?}")));
        }
        Ok(prepared)
    }
}

fn check_plain(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "profile path contains a symlink: {}",
        path.display()
    );
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        anyhow::ensure!(
            metadata.file_attributes() & 0x400 == 0,
            "profile path contains a reparse point: {}",
            path.display()
        );
    }
    Ok(metadata)
}

fn check_directory(path: &Path) -> Result<()> {
    let (root, _) = config::control_roots()?;
    anyhow::ensure!(
        root.is_absolute() && path.is_absolute()
            && !path.components().any(|part| part == std::path::Component::ParentDir),
        "profile path requires an exact absolute installation root"
    );
    // Permit system aliases above root, never a redirected installation or child.
    anyhow::ensure!(check_plain(&root)?.is_dir(), "installation root is not a directory");
    let canonical_root = root.canonicalize()?;
    let boundary = if path.starts_with(&root) { &root } else { &canonical_root };
    anyhow::ensure!(path.starts_with(boundary), "profile path is outside its installation root");
    for ancestor in path.ancestors().take_while(|ancestor| ancestor.starts_with(boundary)) {
        anyhow::ensure!(
            check_plain(ancestor)?.is_dir(),
            "profile path is not a directory: {}",
            ancestor.display()
        );
        anyhow::ensure!(
            ancestor.canonicalize()? == canonical_root.join(ancestor.strip_prefix(boundary)?),
            "profile path escapes or changed its resolved installation root"
        );
    }
    anyhow::ensure!(root.canonicalize()? == canonical_root, "installation root resolution changed");
    Ok(())
}

struct CreatedDirectory {
    directory: PathBuf,
    marker: PathBuf,
    token: String,
}

pub(crate) struct PreparedProfile {
    root: PathBuf,
    target: PathBuf,
    created: Vec<CreatedDirectory>,
    space_name: Option<String>,
}

impl PreparedProfile {
    /// Only a directory created by this operation can use metadata-only completion.
    pub(crate) fn fresh_empty_target(&self) -> Result<bool> {
        let Some(created) = self
            .created
            .iter()
            .find(|entry| entry.directory == self.target)
        else {
            return Ok(false);
        };
        check_directory(&self.target)?;
        let metadata = check_plain(&created.marker)?;
        anyhow::ensure!(
            metadata.is_file()
                && metadata.len() == created.token.len() as u64
                && fs::read(&created.marker)? == created.token.as_bytes(),
            "new profile ownership changed before completion"
        );
        for entry in fs::read_dir(&self.target)? {
            let path = entry?.path();
            // Existing Runtime ownership may leave its lock file, never a business DB.
            anyhow::ensure!(
                (path == created.marker
                    || path.file_name() == Some(std::ffi::OsStr::new("lock.db")))
                    && check_plain(&path)?.is_file(),
                "new profile gained user or business files before completion"
            );
        }
        Ok(true)
    }

    /// Keep the same takeover guard alive through this call.
    pub(crate) fn finish(self, mut result: Result<ResultEnvelope>) -> Result<ResultEnvelope> {
        if result.is_ok() && self.space_name.is_some() {
            if let Err(error) = self.publish_space_owner() {
                if let Ok(envelope) = result.as_mut() {
                    // Selection already committed. Metadata cleanup cannot roll it back.
                    envelope.status = respire_commands::output::Status::Warn;
                    envelope.errors.push(format!("space selected; owner metadata needs recovery: {error:#}; do not rerun space create"));
                }
            }
        }
        let warnings = self.cleanup(result.is_ok());
        if warnings.is_empty() {
            return result;
        }
        match result {
            Ok(mut envelope) => {
                // The config transaction succeeded. Directory cleanup cannot roll it back.
                envelope.status = respire_commands::output::Status::Warn;
                envelope.errors.extend(warnings);
                Ok(envelope)
            }
            Err(error) => Err(error.context(warnings.join("; "))),
        }
    }

    fn publish_space_owner(&self) -> Result<()> {
        let name = self.space_name.as_ref().context("new space name missing")?;
        anyhow::ensure!(self.fresh_empty_target()?, "space directory creation ownership changed");
        let (root, profile) = config::control_roots()?;
        anyhow::ensure!(root.canonicalize()? == self.root.canonicalize()?
            && profile.canonicalize()? == self.target.canonicalize()?,
            "new space is not the confirmed selected profile");
        let path = self.target.join("space_owner.json");
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path).context("new space owner metadata already exists or is unavailable")?;
        file.write_all(&serde_json::to_vec(&json!({"name": name}))?)?;
        file.sync_all()?;
        respire_spawn::durable::sync_directory(&self.target)?;
        Ok(())
    }

    fn cleanup(self, committed: bool) -> Vec<String> {
        let selected = config::control_roots().map(|(_, profile)| profile);
        let may_remove = !committed
            && selected
                .as_ref()
                .is_ok_and(|profile| *profile != self.target);
        let mut warnings = Vec::new();
        for created in self.created.into_iter().rev() {
            let cleaned = (|| -> Result<()> {
                check_directory(&created.directory)?;
                anyhow::ensure!(
                    created
                        .directory
                        .canonicalize()?
                        .starts_with(self.root.canonicalize()?),
                    "created profile escaped its installation root; retained"
                );
                let metadata = check_plain(&created.marker)?;
                anyhow::ensure!(
                    metadata.is_file()
                        && metadata.len() == created.token.len() as u64
                        && fs::read(&created.marker)? == created.token.as_bytes(),
                    "created profile ownership marker changed; retained"
                );
                fs::remove_file(&created.marker)?;
                if !committed {
                    anyhow::ensure!(
                        may_remove,
                        "profile selection is uncertain or still active; directory retained"
                    );
                    // remove_dir is atomic and refuses nonempty directories; never delete user files.
                    fs::remove_dir(&created.directory)
                        .context("created directory is nonempty or unavailable; retained")?;
                }
                Ok(())
            })();
            if let Err(error) = cleaned {
                warnings.push(format!(
                    "profile directory cleanup pending ({}): {error:#}",
                    created.directory.display()
                ));
            }
        }
        warnings
    }
}
