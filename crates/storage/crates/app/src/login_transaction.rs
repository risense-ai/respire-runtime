//! Prepare login without changing the active account; commit only after vault verification.
use std::path::{Path, PathBuf};
use anyhow::{anyhow, ensure, Context, Result};
use serde_json::{json, Value};
use serde::{Deserialize, Serialize};
use std::io::Write;
use sha2::Digest;

#[derive(Serialize, Deserialize)]
struct Recovery {
    directory: PathBuf,
    original: Option<Vec<u8>>,
    config: Option<Vec<u8>>,
    alias: String,
    backends: Vec<String>,
    #[serde(default)]
    pass_backends: Vec<String>,
    directory_existed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupted_login_restores_existing_and_new_profiles() -> Result<()> {
        let root = tempfile::tempdir()?;
        let previous_root = crate::env::var_os("RSRS_DATA_DIR");
        let previous_super = crate::env::var_os("RSRS_SUPER");
        std::env::set_var("RSRS_DATA_DIR", root.path());
        let code = crate::memory::crypto::generate_secret_key();
        std::env::set_var("RSRS_SUPER", &code);
        let result = (|| -> Result<()> {
            let config = br#"{"custom":"preserve","api_base":"https://previous.invalid"}"#;
            let old = br#"{"user":"existing","token":"old-token"}"#;
            std::fs::write(crate::service::client_config_path(), config)?;
            let existing = crate::service::account_dir("existing")?;
            std::fs::create_dir_all(&existing)?;
            std::fs::write(existing.join("session.json"), old)?;
            let (salt, wrapped, nonce) = crate::auth::wrap_with_v4(&code, &[42; 32])?;
            let vault = json!({"version":4,"kdf_salt":salt,"wrapped_urk":wrapped,"urk_nonce":nonce});
            let case_dir = crate::service::account_dir("shiningray")?;
            std::fs::create_dir_all(&case_dir)?;
            std::fs::write(case_dir.join("session.json"), br#"{"user":"shiningray","addr":"https://old.invalid"}"#)?;
            let cloud_dir = login_directory("https://cloud.invalid", "ShiningRay")?;
            ensure!(cloud_dir != case_dir && !cloud_dir.exists(), "case collision reused source");
            let second_server = login_directory("https://cloud.invalid", "shiningray")?;
            ensure!(second_server != case_dir, "server change reused source");
            ensure!(login_directory("https://old.invalid", "shiningray")? == case_dir, "original identity was not reused");
            for user in ["existing", "new-account"] {
                let mut prepared = PreparedLogin::prepare_with_vault("https://fixture.invalid", &json!({"user":user,"token":"new-token"}), code.clone(), vault.clone(), None)?;
                let directory = prepared.directory.clone();
                prepared.commit()?;
                ensure!(recovery_pending(), "commit did not retain recovery state");
                #[cfg(unix)] {
                    use std::os::unix::fs::PermissionsExt;
                    ensure!(std::fs::metadata(recovery_path())?.permissions().mode() & 0o777 == 0o600, "recovery is not private");
                }
                let record = std::fs::read_to_string(recovery_path())?;
                ensure!(!record.contains(&code), "recovery persisted the super password");
                drop(prepared); // Simulate process loss: only the durable record remains.
                recover_interrupted()?;
                recover_interrupted()?; // Recovery must be idempotent.
                ensure!(std::fs::read(crate::service::client_config_path())? == config, "configuration changed");
                ensure!(std::fs::read(existing.join("session.json"))? == old, "existing session changed");
                if user == "new-account" { ensure!(!directory.exists(), "failed new account remained selectable"); }
                ensure!(!recovery_pending(), "completed recovery retained its journal");
            }
            Ok(())
        })();
        match previous_root { Some(value) => std::env::set_var("RSRS_DATA_DIR", value), None => std::env::remove_var("RSRS_DATA_DIR") }
        match previous_super { Some(value) => std::env::set_var("RSRS_SUPER", value), None => std::env::remove_var("RSRS_SUPER") }
        result
    }
}

fn recovery_path() -> PathBuf {
    crate::service::client_config_path().with_file_name(".login-recovery.json")
}

fn private_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_file_name(format!(".login-write-{}", uuid::Uuid::new_v4().simple()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
    let result = (|| -> Result<()> {
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)?;
        #[cfg(unix)] {
            let parent = path.parent().context("private write target has no parent")?;
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() && temporary.exists() { std::fs::remove_file(&temporary)?; }
    result
}

fn restore(path: &Path, bytes: Option<&[u8]>) -> Result<()> {
    match bytes {
        Some(bytes) => private_write(path, bytes),
        None => match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        },
    }
}

pub fn recovery_pending() -> bool { recovery_path().exists() }

/// Called by the host under its takeover lock, after stopping the interrupted runtime.
/// Roll back local state only. A published cloud v4 wrap is resumed by the existing
/// migration path, which proves that the old and new wraps contain the same URK.
pub fn recover_interrupted() -> Result<()> {
    crate::service::require_profile_change_host()?;
    let path = recovery_path();
    ensure!(!std::fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_symlink()), "login recovery record must not be a symbolic link");
    let record: Recovery = match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).context("invalid login recovery record; retain it for recovery")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    ensure!(record.alias.starts_with("login-") && record.alias.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-'), "invalid recovery credential alias");
    ensure!(record.directory.exists() || record.original.is_none(), "original account directory is missing; retain the recovery record");
    if record.directory.exists() {
        read_original(&record.directory)?;
        restore(&record.directory.join("session.json"), record.original.as_deref())?;
    }
    restore(&crate::service::client_config_path(), record.config.as_deref())?;
    for backend in &record.backends {
        crate::keystore::remove_imported(&record.alias, "super", backend)?;
    }
    for backend in &record.pass_backends {
        crate::keystore::remove_imported(&record.alias, "pass", backend)?;
    }
    if !record.directory_existed && record.directory.exists() {
        let parent = record.directory.parent().context("recovery directory has no parent")?;
        std::fs::rename(&record.directory, parent.join(format!(".failed-{}", record.alias)))?;
    }
    std::fs::remove_file(path)?;
    Ok(())
}

/// Read the selected source as one committed snapshot, without creating plaintext files.
/// WP-2c: the implementation moved into the domain crate (`service::local_snapshot`);
/// this wrapper keeps the `respire_app::login_transaction::local_snapshot` path stable.
pub fn local_snapshot(source_secret: Option<&str>) -> Result<String> {
    crate::service::local_snapshot(source_secret)
}

// A sessionless library can identify itself only by decrypting with the authorized data key.
fn library_accepts_keys(directory: &Path, keys: &crate::memory::SessionKeys) -> Result<bool> {
    let path = crate::service::database_path(directory)?;
    if !path.is_file() { return Ok(false); }
    let database = rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let has_memories: bool = database.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='memories')", [], |row| row.get(0))?;
    if !has_memories { return Ok(false); }
    let mut statement = database.prepare("SELECT ciphertext,nonce FROM memories WHERE ciphertext <> '' AND COALESCE(deleted,0)=0")?;
    let mut rows = statement.query([])?;
    let mut count = 0;
    while let Some(row) = rows.next()? {
        let mut stored = crate::memory::model::StoredMemory::new_pending(String::new(), String::new());
        stored.ciphertext = row.get(0)?;
        stored.nonce = row.get(1)?;
        if crate::memory::MemoryEngine::open(keys, &stored).is_err() { return Ok(false); }
        count += 1;
    }
    Ok(count > 0)
}

/// A remote identity includes its server; filesystem case folding is not account identity.
pub fn login_directory(addr: &str, user: &str) -> Result<PathBuf> {
    use sha2::{Digest, Sha256};
    let base = addr.trim().trim_end_matches('/');
    let matches = |directory: &Path| -> Result<bool> {
        let Some(bytes) = read_original(directory)? else { return Ok(false); };
        let session: Value = serde_json::from_slice(&bytes).context("account session is invalid")?;
        let stored_addr = session["addr"].as_str().unwrap_or("").trim().trim_end_matches('/');
        // Older recovery-only profiles carry v1/v3 factors before the first login.
        let recovery_only = stored_addr.is_empty() && !crate::service::database_path(directory)?.is_file();
        Ok(session["user"].as_str() == Some(user) && (stored_addr == base || recovery_only))
    };
    for directory in [crate::service::data_dir(), crate::service::main_data_dir()] {
        if matches(&directory)? { return Ok(directory); }
    }
    let accounts = crate::service::accounts_root();
    if accounts.is_dir() {
        for item in std::fs::read_dir(&accounts)? {
            let item = item?;
            if item.file_type()?.is_dir() && matches(&item.path())? { return Ok(item.path()); }
        }
    }
    let plain = crate::service::account_dir(user)?;
    if !plain.exists() { return Ok(plain); }
    let suffix = hex::encode(Sha256::digest(format!("{base}\n{user}").as_bytes()));
    let isolated = crate::service::account_dir(&format!("{user}-{}", &suffix[..16]))?;
    ensure!(!isolated.exists() || matches(&isolated)? || read_original(&isolated)?.is_none(),
        "isolated account destination is occupied; original libraries were preserved");
    Ok(isolated)
}

pub struct PreparedLogin {
    pub user: String,
    pub directory: PathBuf,
    original: Option<Vec<u8>>,
    session: Value,
    super_password: String,
    login_password: Option<String>,
    alias: String,
    recovery_written: bool,
    migration_cloud: Option<Value>,
    migration_auth: Option<Value>,
}

fn read_original(directory: &Path) -> Result<Option<Vec<u8>>> {
    let path = directory.join("session.json");
    if std::fs::symlink_metadata(directory).is_ok_and(|metadata| metadata.file_type().is_symlink())
        || std::fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        anyhow::bail!("login destination must not be a symbolic link");
    }
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

impl PreparedLogin {
    pub fn prepare(addr: &str, authorized: &Value, super_password: String) -> Result<Self> {
        let vault = Self::fetch_vault(addr, authorized)?;
        Self::prepare_with_vault(addr, authorized, super_password, vault, None)
    }

    pub fn fetch_vault(addr: &str, authorized: &Value) -> Result<Value> {
        let token = authorized["token"].as_str().filter(|token| !token.is_empty()).context("authorization did not return a token")?;
        match ureq::AgentBuilder::new().redirects(0).timeout(std::time::Duration::from_secs(30)).build()
            .get(&format!("{}/api/self/vault", addr.trim().trim_end_matches('/')))
            .set("Authorization", &format!("Bearer {token}")).call() {
            Ok(response) => response.into_json().map_err(Into::into),
            Err(ureq::Error::Status(404, _)) => Ok(Value::Null),
            Err(error) => Err(error).context("could not fetch the account vault"),
        }
    }

    /// Publish only a fully migrated library's wrap, preserving its original factors.
    pub fn prepare_migration(addr: &str, authorized: &Value, password: &str, legacy_super: Option<&str>, secret_key: Option<&str>, new_super: Option<&str>) -> Result<Self> {
        crate::service::require_profile_change_host()?;
        let mut local = crate::auth::read_session_json()?;
        ensure!(local["user"] == authorized["user"], "select the migrated account before publishing its vault");
        ensure!(local["crypto_namespace"].as_str() == Some(crate::memory::crypto::RSRS_PREFIX),
            "run rsrs migrate --source <source> --account <new-account> first; changing only a vault wrap is not a full migration");
        let original = local.clone();
        let version = local["vault_version"].as_i64().context("local vault missing version")?;
        if let Some(secret) = secret_key.filter(|value| !value.is_empty()) {
            local[if version == 1 { "secret" } else { "secret_key" }] = json!(secret);
        }
        let user = authorized["user"].as_str().context("authorization did not return a user")?;
        let alias = local["keyring_account"].as_str().unwrap_or(user);
        let super_password = if version == 1 {
            ensure!(new_super.is_none() && legacy_super.is_none(), "v1 uses the original login password and Account Secret, not a super Key");
            String::new()
        } else {
            legacy_super.filter(|value| !value.is_empty()).map(str::to_owned)
                .or_else(|| crate::keystore::load_super(alias))
                .context("the original super Key is required; no replacement Key was generated")?
        };
        ensure!(new_super.is_none_or(|value| value == super_password),
            "migration preserves the original super Key; --new-super cannot replace it");
        let keys = crate::auth::unlock_session_keys(&local, password, Some(&super_password), alias)?;
        let cloud = Self::fetch_vault(addr, authorized)?;
        if !cloud.is_null() {
            ensure!(cloud["version"] == local["vault_version"], "migration must preserve the original vault factors");
            let mut cloud_session = local.clone();
            for field in ["kdf_salt", "wrapped_urk", "urk_nonce"] { cloud_session[field] = cloud[field].clone(); }
            let cloud_keys = crate::auth::unlock_session_keys(&cloud_session, password, Some(&super_password), alias)?;
            ensure!(cloud_keys.urk == keys.urk, "cloud and local vault data keys differ; original data was preserved");
        }
        let vault = json!({"version":local["vault_version"],"kdf_salt":local["kdf_salt"],"wrapped_urk":local["wrapped_urk"],"urk_nonce":local["urk_nonce"]});
        let mut factors = authorized.clone();
        factors["pass"] = json!(password);
        if version == 1 { factors["secret"] = local["secret"].clone(); }
        let mut prepared = Self::prepare_with_vault(addr, &factors, super_password, vault.clone(), Some((original, keys.urk)))?;
        if cloud != vault { prepared.migration_cloud = Some(cloud); }
        // Explicit cloud migration recalculates the authentication hash from the
        // same login password. Ordinary login never changes this stored salt.
        let salt = crate::memory::crypto::derive_auth_salt(user)?;
        let pass_hash = crate::memory::crypto::derive_pass_hash(password, &salt)?;
        prepared.session["auth_salt"] = json!(salt);
        prepared.login_password = Some(password.to_owned());
        prepared.migration_auth = Some(json!({"salt":salt,"pass_hash":pass_hash}));
        ureq::AgentBuilder::new().redirects(0).timeout(std::time::Duration::from_secs(30)).build()
            .get(&format!("{}/auth/salt", addr.trim().trim_end_matches('/'))).query("user", user).call()
            .context("cloud namespace migration requires a server supporting /auth/salt; original password was preserved")?;
        Ok(prepared)
    }

    pub fn migration_super_password(&self) -> Option<&str> {
        None
    }

    /// Publish the unchanged URK's new wrap only after host/runtime verification.
    pub fn finish_migration(&self, addr: &str, authorized: &Value) -> Result<()> {
        if self.migration_cloud.is_none() && self.migration_auth.is_none() { return Ok(()); }
        let token = authorized["token"].as_str().context("authorization did not return a token")?;
        if let Some(original) = self.migration_cloud.as_ref() {
        ensure!(Self::fetch_vault(addr, authorized)? == *original, "cloud vault changed during migration; original local session was restored");
        let vault = json!({"version":self.session["vault_version"],"kdf_salt":self.session["kdf_salt"],"wrapped_urk":self.session["wrapped_urk"],"urk_nonce":self.session["urk_nonce"]});
        let mut request = ureq::AgentBuilder::new().redirects(0).timeout(std::time::Duration::from_secs(30)).build()
            .post(&format!("{}/api/self/vault", addr.trim().trim_end_matches('/')))
            .set("Authorization", &format!("Bearer {token}"));
        if original.is_null() { request = request.set("If-None-Match", "*"); }
        let result = request.send_json(vault.clone());
        if let Err(error) = result {
            // A lost HTTP response can follow a committed write; inspect that exact wrap once.
            if !Self::fetch_vault(addr, authorized).is_ok_and(|current| current == vault) {
                return Err(anyhow!("legacy vault publication failed: {error}; retain the original super Key and library"));
            }
        }
        }
        if let Some(authentication) = self.migration_auth.as_ref() {
            let agent = ureq::AgentBuilder::new().redirects(0).timeout(std::time::Duration::from_secs(30)).build();
            let result = agent.post(&format!("{}/api/self/password", addr.trim().trim_end_matches('/')))
                .set("Authorization", &format!("Bearer {token}")).send_json(authentication.clone());
            if let Err(error) = result {
                let confirmed: Value = agent.get(&format!("{}/auth/salt", addr.trim().trim_end_matches('/')))
                    .query("user", &self.user).call()?.into_json()?;
                ensure!(confirmed["salt"] == authentication["salt"],
                    "authentication namespace publication failed: {error}; retry explicit migration with the original password");
            }
        }
        Ok(())
    }

    pub fn prepare_with_vault(addr: &str, authorized: &Value, super_password: String, vault: Value, legacy: Option<(Value, [u8; 32])>) -> Result<Self> {
        crate::service::require_profile_change_host()?;
        let user = authorized["user"].as_str().filter(|user| !user.is_empty()).context("authorization did not return a user")?.to_owned();
        let token = authorized["token"].as_str().filter(|token| !token.is_empty()).context("authorization did not return a token")?;
        let base = addr.trim().trim_end_matches('/');
        let version = vault["version"].as_i64().context("vault missing version")?;
        ensure!((1..=4).contains(&version), "unsupported vault version; original factors were preserved");
        let salt = vault["kdf_salt"].as_str().context("vault missing kdf_salt")?;
        let wrapped = vault["wrapped_urk"].as_str().context("vault missing wrapped_urk")?;
        let nonce = vault["urk_nonce"].as_str().context("vault missing urk_nonce")?;
        let current = crate::service::data_dir();
        let mut directory = if legacy.is_some() && crate::service::session_user_of_dir(&current) == user {
            current.clone()
        } else { login_directory(base, &user)? };
        let original = read_original(&directory)?;
        let mut session: Value = match original.as_deref() {
            Some(bytes) => serde_json::from_slice(bytes).context("target account session is invalid; original files were preserved")?,
            None => json!({}),
        };
        ensure!(session.is_object(), "target account session must be an object");
        let previous_alias = session["keyring_account"].as_str().unwrap_or(&user);
        let login_password = authorized["pass"].as_str().filter(|value| !value.is_empty()).map(str::to_owned)
            .or_else(|| if version == 1 { crate::env::var("RSRS_PASS").ok().filter(|value| !value.is_empty()) } else { None })
            .or_else(|| session["pass"].as_str().filter(|value| !value.is_empty()).map(str::to_owned))
            .or_else(|| crate::keystore::load_login_pass(previous_alias));
        let account_secret = authorized["secret"].as_str().filter(|value| !value.is_empty())
            .or_else(|| session["secret"].as_str().filter(|value| !value.is_empty())).map(str::to_owned);
        let verified = match version {
            1 => crate::memory::SessionKeys::unlock(
                login_password.as_deref().context("original v1 login password is required")?,
                account_secret.as_deref().context("original v1 Account Secret is required")?, salt, wrapped, nonce),
            2 => crate::memory::SessionKeys::unlock_super(&super_password, salt, wrapped, nonce),
            3 => crate::memory::SessionKeys::unlock_vault(&super_password,
                session["secret_key"].as_str().context("original Secret Key is required; select the explicitly migrated profile")?,
                salt, wrapped, nonce),
            _ => crate::memory::SessionKeys::unlock_v4(&super_password, salt, wrapped, nonce),
        }.context("original decryption factors do not unlock this account; the original account was preserved")?;
        if original.is_none() && legacy.is_none() {
            let plain = crate::service::account_dir(&user)?;
            let suffix = hex::encode(sha2::Sha256::digest(format!("{base}\n{user}").as_bytes()));
            let isolated = crate::service::account_dir(&format!("{user}-{}", &suffix[..16]))?;
            for candidate in [current, crate::service::main_data_dir(), plain, isolated] {
                if read_original(&candidate)?.is_none() && library_accepts_keys(&candidate, &verified)? {
                    directory = candidate;
                    break;
                }
            }
        }
        ensure!(session["user"].as_str().is_none_or(|owner| owner.is_empty() || owner == user), "destination belongs to another account");
        if let Some((original, urk)) = legacy.as_ref() {
            ensure!(session == *original && verified.urk == *urk, "legacy session changed or migration would replace its data key");
        }
        let database = crate::service::database_path(&directory)?;
        if database.is_file() {
            let database = rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let has_memories: bool = database.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='memories')", [], |row| row.get(0))?;
            if has_memories {
                let count: i64 = database.query_row("SELECT count(*) FROM memories WHERE ciphertext <> ''", [], |row| row.get(0))?;
                if count > 0 {
                    let same_wrap = session["kdf_salt"] == vault["kdf_salt"] && session["wrapped_urk"] == vault["wrapped_urk"] && session["urk_nonce"] == vault["urk_nonce"];
                    if legacy.is_none() && !same_wrap {
                        // Full logout removes the wrap, and a super-password change can
                        // rewrap the same URK. Prove compatibility against local data.
                        ensure!(library_accepts_keys(&directory, &verified)?,
                            "local library uses different key material or compatibility could not be verified; original data was preserved");
                    }
                }
            }
        }
        let alias = format!("login-{}", uuid::Uuid::new_v4().simple());
        if version == 1 { session["secret"] = json!(account_secret.context("original v1 Account Secret is required")?); }
        for field in ["pass", "super"] { session.as_object_mut().map(|object| object.remove(field)); }
        if version >= 4 {
            for field in ["secret", "secret_key"] { session.as_object_mut().map(|object| object.remove(field)); }
        }
        session["user"] = json!(user);
        session["addr"] = json!(base);
        session["token"] = json!(token);
        session["session_id"] = authorized["session_id"].clone();
        let local_wrap = [session["kdf_salt"].clone(), session["wrapped_urk"].clone(), session["urk_nonce"].clone()];
        session["vault_version"] = json!(version);
        session["kdf_salt"] = vault["kdf_salt"].clone();
        session["wrapped_urk"] = vault["wrapped_urk"].clone();
        session["urk_nonce"] = vault["urk_nonce"].clone();
        if session["crypto_namespace"].as_str() == Some(crate::memory::crypto::RSRS_PREFIX)
            && !wrapped.starts_with(crate::memory::crypto::RSRS_PREFIX) {
            // A local explicit namespace migration can precede cloud rewrapping.
            // Keep its current namespace after verifying the cloud URK above.
            ensure!(local_wrap[1].as_str().is_some_and(|value| value.starts_with(crate::memory::crypto::RSRS_PREFIX)),
                "migrated local wrap is missing; original account was preserved");
            session["kdf_salt"] = local_wrap[0].clone();
            session["wrapped_urk"] = local_wrap[1].clone();
            session["urk_nonce"] = local_wrap[2].clone();
        }
        session["keyring_account"] = json!(alias);
        Ok(Self { user, directory, original, session, super_password, login_password, alias, recovery_written: false, migration_cloud: None, migration_auth: None })
    }

    pub fn commit(&mut self) -> Result<()> {
        ensure!(read_original(&self.directory)? == self.original, "target session changed during login; original account was preserved");
        let result = self.commit_inner();
        if let Err(error) = result {
            return match self.rollback() { Ok(()) => Err(error), Err(rollback) => Err(error.context(format!("login rollback failed: {rollback:#}"))) };
        }
        Ok(())
    }

    fn commit_inner(&mut self) -> Result<()> {
        let path = recovery_path();
        ensure!(!path.exists(), "interrupted login must be recovered before another commit");
        let config = match std::fs::read(crate::service::client_config_path()) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        let mut recovery = Recovery { directory: self.directory.clone(), original: self.original.clone(), config,
            alias: self.alias.clone(), backends: Vec::new(), pass_backends: Vec::new(), directory_existed: self.directory.exists() };
        std::fs::create_dir_all(path.parent().context("recovery root is missing")?)?;
        private_write(&path, &serde_json::to_vec(&recovery)?)?;
        self.recovery_written = true;
        if self.session["vault_version"] == 1 {
            let password = self.login_password.as_deref().context("original v1 login password is required")?;
            if crate::env::var("RSRS_PASS").is_ok_and(|value| !value.is_empty() && value == password) {
                // Headless v1 retains its original password/Account Secret factors.
                self.session.as_object_mut().map(|object| { object.remove("keyring_account"); object.remove("keyring_backend"); });
            } else {
                crate::keystore::import_credential_checkpoint(&self.alias, "pass", password, |backend| {
                    recovery.pass_backends.push(backend.to_owned());
                    private_write(&path, &serde_json::to_vec(&recovery)?)
                })?;
            }
        } else if crate::env::var("RSRS_SUPER").is_ok_and(|value| value == self.super_password) {
            // Headless hosts explicitly supply the same verified key to their runtime.
            self.session.as_object_mut().map(|object| { object.remove("keyring_account"); object.remove("keyring_backend"); });
        } else {
            let backend = crate::keystore::import_credential_checkpoint(&self.alias, "super", &self.super_password, |backend| {
                recovery.backends.push(backend.to_owned());
                private_write(&path, &serde_json::to_vec(&recovery)?)
            })?;
            self.session["keyring_backend"] = json!(backend);
            if let Some(password) = self.login_password.as_deref() {
                crate::keystore::import_credential_checkpoint(&self.alias, "pass", password, |backend| {
                    recovery.pass_backends.push(backend.to_owned());
                    private_write(&path, &serde_json::to_vec(&recovery)?)
                })?;
            }
        }
        if !self.directory.exists() {
            let parent = self.directory.parent().context("account directory has no parent")?;
            std::fs::create_dir_all(parent)?;
            std::fs::create_dir(&self.directory)?;
        }
        private_write(&self.directory.join("session.json"), &serde_json::to_vec_pretty(&self.session)?)?;
        crate::service::set_data_dir(&self.directory.to_string_lossy())?;
        Ok(())
    }

    pub fn rollback(&mut self) -> Result<()> {
        if self.recovery_written {
            recover_interrupted()?;
            self.recovery_written = false;
        }
        Ok(())
    }

    pub fn complete(&self) -> Result<()> {
        std::fs::remove_file(recovery_path()).context("login verified but recovery record could not be retired")
    }
}
