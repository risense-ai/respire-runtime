//! Opt-in, current-user runtime supervision. No registration during ordinary startup.
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

mod lifecycle;
mod manager;
mod supervise;
pub(crate) use lifecycle::current_boot_token as lifecycle_boot_token;
pub(crate) use lifecycle::{
    authorize_detached_boot_locked, background_paused, begin_maintenance_locked,
    check_direct_access, check_managed_request, coordinate_materialization, credential_state,
    ensure_managed_locked, execute, managed_enabled, managed_id, may_reuse_runtime,
    note_credential_access, record_exit, restart_maintenance_locked, restart_stage, stop_managed_locked,
    verify_managed_boot, with_explicit_recovery,
};

pub use respire_commands::autostart::{AutostartCommand, RuntimeCommand};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Platform {
    Linux,
    Macos,
    Windows,
}

impl Platform {
    fn current() -> Result<Self> {
        match std::env::consts::OS {
            "linux" => Ok(Self::Linux),
            "macos" => Ok(Self::Macos),
            "windows" => Ok(Self::Windows),
            _ => bail!("user runtime autostart is unsupported on this platform"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Linux => "systemd-user",
            Self::Macos => "launch-agent",
            Self::Windows => "user-logon-task",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    schema: u32,
    platform: Platform,
    installation: PathBuf,
    executable: PathBuf,
    user_home: PathBuf,
    owner: String,
    id: String,
    enabled: bool,
    manually_stopped: bool,
    maintenance: bool,
    environment: BTreeMap<String, String>,
    artifact_hashes: BTreeMap<String, String>,
    #[serde(skip)]
    digest: Option<String>,
}

fn control_path(root: &Path) -> PathBuf {
    root.join("runtime")
        .join("autostart")
        .join("registration.json")
}

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn identity(root: &Path, owner: &str) -> String {
    hash(format!("respire-runtime-v1\0{}\0{owner}", root.display()).as_bytes())[..24].to_owned()
}

fn plain_value(value: &str) -> Result<()> {
    anyhow::ensure!(
        !value.is_empty() && !value.chars().any(char::is_control),
        "invalid autostart configuration value"
    );
    Ok(())
}

fn read_registration(root: &Path) -> Result<Option<Registration>> {
    let path = control_path(root);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= 64 * 1024,
        "autostart registration must be a bounded regular file"
    );
    let bytes = fs::read(&path)?;
    let mut config: Registration =
        serde_json::from_slice(&bytes).context("invalid autostart registration")?;
    anyhow::ensure!(
        config.schema == 1 && config.platform == Platform::current()?,
        "unsupported autostart registration schema/platform"
    );
    let canonical = root.canonicalize()?;
    anyhow::ensure!(
        config.installation == canonical && config.id == identity(&canonical, &config.owner),
        "autostart registration belongs to another installation"
    );
    anyhow::ensure!(
        config
            .environment
            .get("RSRS_RPC_PORT")
            .and_then(|value| value.parse::<u16>().ok())
            .is_some_and(|port| port != 0),
        "invalid registered runtime port"
    );
    for (key, value) in &config.environment {
        anyhow::ensure!(
            ENVIRONMENT.contains(&key.as_str()),
            "autostart registration contains unsupported environment configuration"
        );
        plain_value(value)?;
    }
    config.digest = Some(hash(&bytes));
    Ok(Some(config))
}

fn private_write(path: &Path, bytes: &[u8], expected: Option<&str>) -> Result<()> {
    let parent = path.parent().context("autostart file has no parent")?;
    // Refuse links in the path rather than writing through an unexpected target.
    for ancestor in parent.ancestors() {
        if let Ok(metadata) = fs::symlink_metadata(ancestor) {
            anyhow::ensure!(
                !metadata.file_type().is_symlink(),
                "autostart parent is a symlink; no files changed"
            );
        }
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= 65536,
                "unknown autostart file; refusing replacement"
            );
            let expected =
                expected.context("existing autostart file is not owned by this installation")?;
            anyhow::ensure!(
                hash(&fs::read(path)?) == expected,
                "autostart file changed; refusing replacement"
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            anyhow::ensure!(
                expected.is_none(),
                "owned autostart file disappeared; inspect registration before retrying"
            );
        }
        Err(error) => return Err(error.into()),
    }
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".respire-autostart-{}", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        if expected.is_some() {
            respire_spawn::durable::replace_file(&temporary, path)?;
        } else {
            respire_spawn::durable::publish_new_file(&temporary, path)?;
        }
        Ok(())
    })();
    if result.is_err() && temporary.try_exists()? {
        fs::remove_file(&temporary)?;
    }
    result
}

// Never persist authentication/recovery material or arbitrary shell environment.
const ENVIRONMENT: &[&str] = &[
    "RSRS_DATA_DIR",
    "RSRS_BIN_DIR",
    "RSRS_RPC_PORT",
    "RSRS_ENGINE",
    "RSRS_M3_DIR",
    "RSRS_INDEX_THREADS",
    "RSRS_RECALL_FEEDBACK",
    "RSRS_NO_AUTOSYNC",
    "RSRS_UPDATE_CHECK",
    "RSRS_MCP_TOOLS_ALLOW",
    "RSRS_MCP_TOOLS_DENY",
];

fn disabled_status() -> Result<Value> {
    let root = respire::service::main_data_dir();
    match read_registration(&root)? {
        None => Ok(
            json!({"schema_version":1,"enabled":false,"registered":false,
            "scope":"user-sign-in","default_enabled":false,"manager":Platform::current()?.name()}),
        ),
        Some(config) => Ok(
            json!({"schema_version":1,"enabled":config.enabled,"registered":true,
            "scope":"user-sign-in","default_enabled":false,"manager":config.platform.name(),
            "installation":config.installation,"id":config.id,"manually_stopped":config.manually_stopped,
            "maintenance":config.maintenance,"configured_rpc_port":config.environment.get("RSRS_RPC_PORT").and_then(|value|value.parse::<u16>().ok())}),
        ),
    }
}

fn systemd_quote(raw: &str) -> Result<String> {
    plain_value(raw)?;
    Ok(format!(
        "\"{}\"",
        raw.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
    ))
}

// Path-valued systemd directives are not ExecStart argv. Keep literal path
// characters and escape only percent specifiers.
fn systemd_path(raw: &str) -> Result<String> {
    plain_value(raw)?;
    anyhow::ensure!(
        raw.starts_with('/'),
        "systemd working directory must be absolute"
    );
    // Unlike ExecStart argv this directive is a scalar path. Keep literal
    // spaces, quotes and backslashes; only escape systemd specifiers. A final
    // '/.' preserves directory identity while preventing trailing whitespace or
    // backslashes from being trimmed/interpreted as a unit-file continuation.
    Ok(format!("{}/.", raw.replace('%', "%%")))
}

fn xml(raw: &str) -> Result<String> {
    plain_value(raw)?;
    Ok(raw
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;"))
}

fn render(config: &Registration) -> Result<String> {
    let executable = config
        .executable
        .to_str()
        .context("native path is not UTF-8")?;
    let root = config
        .installation
        .to_str()
        .context("installation path is not UTF-8")?;
    match config.platform {
        // The registered task starts the CLI supervisor (`runtime supervise`),
        // which owns and restarts the separate rsrs-runtime child process.
        Platform::Linux => Ok(format!("# Respire user runtime {}\n[Unit]\nDescription=Respire current-user runtime\nStartLimitIntervalSec=120\nStartLimitBurst=3\n[Service]\nType=simple\nExecStart=:{} runtime supervise --data-dir {}\nWorkingDirectory={}\nRestart=on-failure\nRestartSec=10\nTimeoutStopSec=60\nKillMode=control-group\nStandardOutput=null\nStandardError=null\n[Install]\nWantedBy=default.target\n",
            config.id, systemd_quote(executable)?, systemd_quote(root)?, systemd_path(root)?)),
        Platform::Macos => Ok(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>Label</key><string>ai.risense.respire.runtime.{}</string><key>ProgramArguments</key><array><string>{}</string><string>runtime</string><string>supervise</string><string>--data-dir</string><string>{}</string></array><key>WorkingDirectory</key><string>{}</string><key>RunAtLoad</key><true/><key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict><key>ThrottleInterval</key><integer>10</integer><key>StandardOutPath</key><string>/dev/null</string><key>StandardErrorPath</key><string>/dev/null</string></dict></plist>\n",
            config.id, xml(executable)?, xml(root)?, xml(root)?)),
        Platform::Windows => {
            let arguments=format!("runtime supervise --data-dir {}",manager::windows_argument(root)?);
            Ok(format!("<?xml version=\"1.0\"?><Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><RegistrationInfo><Description>Respire current-user runtime {}</Description></RegistrationInfo><Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{}</UserId></LogonTrigger></Triggers><Principals><Principal id=\"CurrentUser\"><UserId>{}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Enabled>true</Enabled><StartWhenAvailable>true</StartWhenAvailable><RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure></Settings><Actions Context=\"CurrentUser\"><Exec><Command>{}</Command><Arguments>{}</Arguments><WorkingDirectory>{}</WorkingDirectory></Exec></Actions></Task>\n",config.id,xml(&config.owner)?,xml(&config.owner)?,xml(&manager::windows_task_path(executable)?)?,xml(&arguments)?,xml(&manager::windows_task_path(root)?)?))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn fixture(platform: Platform) -> Registration {
        Registration {
            schema: 1,
            platform,
            installation: PathBuf::from("/tmp/a & b"),
            executable: PathBuf::from("/tmp/a & b/bin/rsrs"),
            user_home: PathBuf::from("/tmp/user"),
            owner: "1001".into(),
            id: "0123456789abcdef01234567".into(),
            enabled: false,
            manually_stopped: false,
            maintenance: false,
            environment: BTreeMap::new(),
            artifact_hashes: BTreeMap::new(),
            digest: None,
        }
    }

    #[test]
    fn absent_registration_is_a_read_only_default() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let missing = temporary.path().join("not-created");
        anyhow::ensure!(
            read_registration(&missing)?.is_none(),
            "fresh profile was unexpectedly configured"
        );
        anyhow::ensure!(!missing.exists(), "status created a profile");
        Ok(())
    }

    #[test]
    fn tampered_registration_is_rejected_without_rewriting_evidence() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().canonicalize()?;
        let path = control_path(&root);
        fs::create_dir_all(path.parent().context("registration parent missing")?)?;
        let mut config = fixture(Platform::current()?);
        config.installation = root.clone();
        config.id = identity(&root, &config.owner);
        config.environment.insert("RSRS_RPC_PORT".into(), "45678".into());
        let original = serde_json::to_value(&config)?;
        let bytes = serde_json::to_vec(&original)?;
        fs::write(&path, &bytes)?;
        let loaded = read_registration(&root)?.context("valid registration missing")?;
        anyhow::ensure!(loaded.digest.as_deref() == Some(hash(&bytes).as_str()));
        // All mutations use synthetic fields. Rejecting a registration must
        // preserve its exact bytes for diagnosis, rather than repairing trust.
        let mut cases = Vec::new();
        for (field, value) in [
            ("schema", json!(2)),
            ("platform", json!(if config.platform == Platform::Linux { "windows" } else { "linux" })),
            ("installation", json!(root.join("other"))),
            ("id", json!("foreign-installation")),
            ("unexpected", json!(true)),
        ] {
            let mut changed = original.clone();
            changed[field] = value;
            cases.push(changed);
        }
        for port in [json!("0"), json!("65536"), json!("invalid"), json!(null)] {
            let mut changed = original.clone();
            changed["environment"]["RSRS_RPC_PORT"] = port;
            cases.push(changed);
        }
        for (key, value) in [("RSRS_SUPER", "synthetic-only"), ("RSRS_ENGINE", "cpu\nforeign")] {
            let mut changed = original.clone();
            changed["environment"][key] = json!(value);
            cases.push(changed);
        }
        for changed in cases {
            let evidence = serde_json::to_vec(&changed)?;
            fs::write(&path, &evidence)?;
            anyhow::ensure!(read_registration(&root).is_err(), "tampered registration accepted");
            anyhow::ensure!(fs::read(&path)? == evidence, "read rewrote rejected evidence");
        }
        for evidence in [b"invalid-json".to_vec(), vec![b' '; 65537]] {
            fs::write(&path, &evidence)?;
            anyhow::ensure!(read_registration(&root).is_err());
            anyhow::ensure!(fs::read(&path)? == evidence);
        }
        fs::remove_file(&path)?;
        fs::create_dir(&path)?;
        anyhow::ensure!(read_registration(&root).is_err());
        fs::remove_dir(&path)?;
        #[cfg(unix)]
        {
            let target = root.join("synthetic-registration.json");
            fs::write(&target, &bytes)?;
            std::os::unix::fs::symlink(&target, &path)?;
            anyhow::ensure!(read_registration(&root).is_err());
            anyhow::ensure!(fs::read(&target)? == bytes);
        }
        Ok(())
    }

    #[test]
    fn templates_supervise_foreground_user_runtime_without_elevation() -> Result<()> {
        // RegisterTask receives a Unicode BSTR, not the UTF-8 file bytes.
        // Keep its declaration encoding-neutral after ReadAllText.
        let windows = render(&fixture(Platform::Windows))?;
        anyhow::ensure!(windows.starts_with("<?xml version=\"1.0\"?>") && !windows.contains("encoding="));
        let linux = render(&fixture(Platform::Linux))?;
        anyhow::ensure!(
            linux.contains("Type=simple")
                && linux.contains("runtime supervise --data-dir")
                && !linux.contains("status --json")
        );
        anyhow::ensure!(!linux.contains("User=root") && !linux.contains("linger"));
        let mac = render(&fixture(Platform::Macos))?;
        anyhow::ensure!(
            mac.contains("a &amp; b")
                && mac.contains("SuccessfulExit")
                && !mac.contains("LaunchDaemon")
        );
        anyhow::ensure!(systemd_quote("/a%u/$x")? == "\"/a%%u/$x\"");
        anyhow::ensure!(systemd_path("/a b%u/\"c\"\\d")? == "/a b%%u/\"c\"\\d/.");
        anyhow::ensure!(plain_value("bad\nvalue").is_err());
        for secret in [
            "RSRS_SUPER",
            "RSRS_TOKEN",
            "RSRS_RPC_TOKEN",
            "GH_TOKEN",
            "CORE_SDK_READ_TOKEN",
        ] {
            anyhow::ensure!(!ENVIRONMENT.contains(&secret));
        }
        Ok(())
    }
}
