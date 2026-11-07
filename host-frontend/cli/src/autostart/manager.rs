//! Current-user OS adapters. The only accepted registrations have our exact owner,
//! installation-specific name, executable and arguments; never use elevation.
use super::{hash, plain_value, private_write, render, Platform, Registration};
use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[derive(Debug, Serialize)]
pub(super) struct State {
    pub registered: bool,
    pub loaded: bool,
    pub running: bool,
    pub enabled: bool,
}

struct Output {
    code: i32,
    stdout: String,
}

/// Creation identity only: never persist a controller command line, which may
/// contain login material. None means that the controller has exited.
pub(crate) fn process_birth(pid: u32) -> Result<Option<String>> {
    #[cfg(target_os = "linux")]
    {
        let raw = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let fields = raw.rsplit_once(')').context("invalid process identity")?.1;
        if fields.split_whitespace().next() == Some("Z") {
            return Ok(None);
        }
        return Ok(Some(
            fields
                .split_whitespace()
                .nth(19)
                .context("process birth missing")?
                .into(),
        ));
    }
    #[cfg(windows)]
    {
        return Ok(respire_spawn::process_birth(pid)?.map(|value| value.to_string()));
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        let output = control(
            "ps",
            &["-p".into(), pid.to_string(), "-o".into(), "lstart=".into()],
        )?;
        if output.code == 1 && output.stdout.trim().is_empty() {
            return Ok(None);
        }
        anyhow::ensure!(
            output.code == 0 && !output.stdout.trim().is_empty(),
            "process identity unavailable"
        );
        Ok(Some(output.stdout.trim().into()))
    }
}

pub(super) fn validate_executable(platform: Platform, path: &Path) -> Result<()> {
    let value = path
        .to_str()
        .context("startup executable path is not UTF-8")?;
    plain_value(value)?;
    anyhow::ensure!(
        path.is_absolute(),
        "startup requires an absolute native path; use an absolute RSRS_DATA_DIR/RSRS_BIN_DIR"
    );
    if platform == Platform::Linux {
        anyhow::ensure!(!value.chars().any(|c|matches!(c,'\\'|'\"'|'\'')),
            "systemd does not support quotes/backslashes in executable paths; choose a safe absolute RSRS_BIN_DIR (the data directory may still contain these characters)");
    }
    Ok(())
}

pub(super) fn windows_task_path(raw: &str) -> Result<String> {
    plain_value(raw)?;
    if let Some(unc) = raw.strip_prefix(r"\\?\UNC\") {
        return Ok(format!(r"\\{}", unc));
    }
    if let Some(dos) = raw.strip_prefix(r"\\?\") {
        let bytes = dos.as_bytes();
        anyhow::ensure!(
            bytes.len() >= 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && bytes[2] == b'\\',
            "unsupported Windows startup path namespace"
        );
        return Ok(dos.to_owned());
    }
    Ok(raw.to_owned())
}

fn program(name: &str) -> Result<PathBuf> {
    if name == "powershell" {
        let root = std::env::var_os("SystemRoot").context("Windows SystemRoot unavailable")?;
        let path = PathBuf::from(root).join("System32/WindowsPowerShell/v1.0/powershell.exe");
        anyhow::ensure!(path.is_file(), "Windows PowerShell unavailable");
        return Ok(path);
    }
    for base in ["/usr/bin", "/bin"] {
        let path = Path::new(base).join(name);
        if path.is_file() {
            return Ok(path);
        }
    }
    bail!("current-user service manager program unavailable: {name}")
}

#[cfg(test)]
type TestControl = Box<dyn FnMut(&str, &[String]) -> Result<Output>>;
#[cfg(test)]
thread_local! { static TEST_CONTROL: std::cell::RefCell<Option<TestControl>> = const { std::cell::RefCell::new(None) }; }

fn control(name: &str, arguments: &[String]) -> Result<Output> {
    #[cfg(test)]
    if let Some(output) = TEST_CONTROL.with(|slot| {
        slot.borrow_mut()
            .as_mut()
            .map(|handler| handler(name, arguments))
    }) {
        return output;
    }
    let mut command = Command::new(program(name)?);
    command
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_clear();
    for key in [
        "HOME",
        "USERPROFILE",
        "USER",
        "LOGNAME",
        "LANG",
        "LC_ALL",
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
        "APPDATA",
        "LOCALAPPDATA",
        "COMPUTERNAME",
        "COMSPEC",
        "PATHEXT",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramData",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    #[cfg(unix)]
    command.env("LC_ALL", "C");
    command.env(
        "PATH",
        if cfg!(windows) {
            std::env::var_os("SystemRoot")
                .map(|root| PathBuf::from(root).join("System32"))
                .unwrap_or_default()
        } else {
            PathBuf::from("/usr/bin:/bin")
        },
    );
    let mut child = respire_spawn::spawn_host_control(&mut command)
        .context("could not invoke current-user service manager")?;
    let stdout = child
        .stdout
        .take()
        .context("service manager stdout missing")?;
    let (tx, rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut data = Vec::new();
        let result = stdout.take(65537).read_to_end(&mut data).map(|_| data);
        let _ = tx.send(result);
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            child
                .kill()
                .context("could not stop timed-out service manager client")?;
            child.wait()?;
            let partial = rx
                .recv_timeout(Duration::from_secs(1))
                .ok()
                .and_then(Result::ok)
                .unwrap_or_default();
            let stage = last_control_stage(&partial);
            bail!("current-user service manager request timed out at fixed stage {stage}; inspect its state before retrying");
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let bytes = rx
        .recv_timeout(Duration::from_secs(1))
        .context("service manager output did not close")??;
    anyhow::ensure!(
        bytes.len() <= 65536,
        "service manager response exceeded limit"
    );
    Ok(Output {
        code: status.code().unwrap_or(-1),
        stdout: String::from_utf8(bytes).context("service manager returned invalid UTF-8")?,
    })
}

const CONTROL_STAGES: &[&str] = &[
    "script",
    "com-created",
    "com-connected",
    "task-looked-up",
    "task-xml-loaded",
    "task-shape",
    "principal-sid",
    "principal-logon",
    "principal-runlevel",
    "principal-runlevel-omitted-limited",
    "trigger-sid",
    "action-executable",
    "action-arguments",
    "action-directory",
    "task-marker",
    "task-validated",
];
fn control_stage(line: &str) -> Option<&str> {
    let value = line
        .trim_start_matches('\u{feff}')
        .strip_prefix("rsrs-control-stage:")?;
    CONTROL_STAGES.contains(&value).then_some(value)
}
fn last_control_stage(bytes: &[u8]) -> String {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|value| value.lines().filter_map(control_stage).last())
        .unwrap_or("unreported")
        .into()
}
fn control_hresult(text: &str) -> &str {
    text.lines()
        .filter_map(|line| line.strip_prefix("rsrs-control-hresult:"))
        .filter(|value| value.len() == 8 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .last()
        .unwrap_or("unreported")
}

fn control_xml_location(text: &str) -> &str {
    text.lines()
        .filter_map(|line| line.strip_prefix("rsrs-control-xml-location:"))
        .filter(|value| {
            value.split_once(',').is_some_and(|(line, column)| {
                [line, column].into_iter().all(|part| {
                    !part.is_empty()
                        && part.len() <= 8
                        && part.bytes().all(|byte| byte.is_ascii_digit())
                })
            })
        })
        .last()
        .unwrap_or("unreported")
}

fn encoded_powershell(script: &str) -> String {
    use base64::Engine as _;
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn checked(name: &str, args: Vec<String>) -> Result<String> {
    let result = control(name, &args)?;
    if result.code != 0 && name == "powershell" {
        bail!("Windows current-user operation failed (exit {}, fixed stage {}, HRESULT {}, XML location {}); inspect the owned registration",result.code,last_control_stage(result.stdout.as_bytes()),control_hresult(&result.stdout),control_xml_location(&result.stdout));
    }
    anyhow::ensure!(
        result.code == 0,
        "{name} current-user operation failed (exit {}); inspect the owned registration",
        result.code
    );
    Ok(result.stdout)
}

fn ps_literal(value: &str) -> Result<String> {
    plain_value(value)?;
    Ok(format!("'{}'", value.replace('\'', "''")))
}

fn powershell(script: String) -> Result<String> {
    let operation = [
        ("WindowsIdentity", "query current user"),
        (".DeleteTask(", "remove owned task"),
        (".RegisterTask(", "register owned task"),
        (".Run($null)", "start owned task"),
        (".Stop(0)", "stop owned task"),
        ("$t.Enabled=$false", "disable owned task"),
        (".GetTask(", "inspect owned task"),
    ]
    .into_iter()
    .find_map(|(needle, label)| script.contains(needle).then_some(label))
    .unwrap_or("query process");
    let wrapped=format!("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);[Console]::Out.WriteLine('rsrs-control-stage:script');try{{{script}}}catch{{$failure=$_.Exception;while($null -ne $failure.InnerException){{$failure=$failure.InnerException}};[Console]::Out.WriteLine('rsrs-control-hresult:'+$failure.HResult.ToString('X8'));$location=[regex]::Match($failure.Message,'\\(([0-9]{{1,8}}),([0-9]{{1,8}})\\)');if($location.Success){{[Console]::Out.WriteLine('rsrs-control-xml-location:'+$location.Groups[1].Value+','+$location.Groups[2].Value)}};exit 1}};exit 0");
    let text = checked(
        "powershell",
        vec![
            "-NoLogo".into(),
            "-NoProfile".into(),
            "-NonInteractive".into(),
            "-EncodedCommand".into(),
            encoded_powershell(&wrapped),
        ],
    )
    .with_context(|| format!("Windows current-user operation failed: {operation}"))?;
    Ok(text
        .trim_start_matches('\u{feff}')
        .lines()
        .filter(|line| control_stage(line).is_none())
        .collect::<Vec<_>>()
        .join("\n"))
}

pub(super) fn owner() -> Result<String> {
    let value = if cfg!(windows) {
        powershell("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value".into())?
    } else {
        checked("id", vec!["-u".into()])?
    };
    let value = value.trim();
    anyhow::ensure!(
        !value.is_empty()
            && if cfg!(windows) {
                value.starts_with("S-")
                    && value
                        .chars()
                        .all(|c| c == 'S' || c == '-' || c.is_ascii_digit())
            } else {
                value.chars().all(|c| c.is_ascii_digit())
            },
        "could not identify current-user service owner"
    );
    Ok(value.to_owned())
}

pub(super) fn item(config: &Registration) -> PathBuf {
    match config.platform {
        Platform::Linux => config
            .user_home
            .join(".config/systemd/user")
            .join(format!("respire-runtime-{}.service", config.id)),
        Platform::Macos => config
            .user_home
            .join("Library/LaunchAgents")
            .join(format!("ai.risense.respire.runtime.{}.plist", config.id)),
        Platform::Windows => super::control_path(&config.installation).with_file_name("task.xml"),
    }
}

fn name(config: &Registration) -> String {
    match config.platform {
        Platform::Linux => format!("respire-runtime-{}.service", config.id),
        Platform::Macos => format!("ai.risense.respire.runtime.{}", config.id),
        Platform::Windows => format!("Respire-runtime-{}", config.id),
    }
}

fn domain(config: &Registration) -> String {
    format!("gui/{}", config.owner)
}

fn systemd_property(
    config: &Registration,
    interface: &str,
    property: &str,
) -> Result<serde_json::Value> {
    let lookup = checked(
        "busctl",
        vec![
            "--user".into(),
            "--json=short".into(),
            "call".into(),
            "org.freedesktop.systemd1".into(),
            "/org/freedesktop/systemd1".into(),
            "org.freedesktop.systemd1.Manager".into(),
            "GetUnit".into(),
            "s".into(),
            name(config),
        ],
    )?;
    let object: serde_json::Value = serde_json::from_str(&lookup)?;
    let path = object["data"][0]
        .as_str()
        .context("systemd unit object unavailable")?;
    anyhow::ensure!(
        path.starts_with("/org/freedesktop/systemd1/unit/"),
        "unexpected systemd unit object"
    );
    let value = checked(
        "busctl",
        vec![
            "--user".into(),
            "--json=short".into(),
            "get-property".into(),
            "org.freedesktop.systemd1".into(),
            path.into(),
            interface.into(),
            property.into(),
        ],
    )?;
    Ok(serde_json::from_str(&value)?)
}

fn verify_systemd_loaded(
    config: &Registration,
    exec: &serde_json::Value,
    dropins: &serde_json::Value,
) -> Result<()> {
    let overrides = dropins["data"]
        .as_array()
        .context("systemd loaded drop-in list unavailable")?;
    anyhow::ensure!(
        overrides.is_empty(),
        "unknown systemd drop-in override; refusing lifecycle action"
    );
    let entries = exec["data"]
        .as_array()
        .context("systemd loaded ExecStart unavailable")?;
    anyhow::ensure!(entries.len() == 1, "unknown systemd loaded ExecStart count");
    let row = entries[0]
        .as_array()
        .context("invalid systemd loaded ExecStart")?;
    let executable = config.executable.to_str().context("non-UTF8 executable")?;
    anyhow::ensure!(
        row.first().and_then(serde_json::Value::as_str) == Some(executable),
        "systemd loaded executable changed; refusing lifecycle action"
    );
    let argv = row
        .get(1)
        .and_then(serde_json::Value::as_array)
        .context("systemd loaded argv unavailable")?;
    let expected = [
        executable,
        "runtime",
        "supervise",
        "--data-dir",
        config
            .installation
            .to_str()
            .context("non-UTF8 installation")?,
    ];
    anyhow::ensure!(
        argv.len() == expected.len()
            && argv
                .iter()
                .zip(expected)
                .all(|(actual, expected)| actual.as_str() == Some(expected)),
        "systemd loaded arguments changed; refusing lifecycle action"
    );
    Ok(())
}
fn launchd_value(raw: &str) -> Result<String> {
    let raw = raw.trim();
    if raw.starts_with('"') {
        return serde_json::from_str(raw).context("unrecognized quoted launchd value");
    }
    plain_value(raw)?;
    Ok(raw.to_owned())
}

fn launchd_enabled(disabled: &str, name: &str) -> Result<bool> {
    anyhow::ensure!(
        disabled.contains("disabled services = {") && disabled.trim_end().ends_with('}'),
        "launchd disabled override status unavailable"
    );
    let key = format!("\"{name}\" => ");
    let mut matched = disabled
        .lines()
        .filter_map(|line| line.trim().strip_prefix(&key));
    let enabled = match matched.next() {
        None => true,
        Some("true" | "disabled") => false,
        Some("false" | "enabled") => true,
        Some(_) => bail!("unknown launchd disabled override value"),
    };
    anyhow::ensure!(matched.next().is_none(), "duplicate launchd override entry");
    Ok(enabled)
}

fn label(config: &Registration) -> String {
    format!("{}/{}", domain(config), name(config))
}

fn file_guard(config: &Registration) -> Result<()> {
    anyhow::ensure!(
        config.owner == owner()?,
        "autostart belongs to another OS user"
    );
    let path = item(config);
    if let Some(expected) = config.artifact_hashes.get("service") {
        let metadata = std::fs::symlink_metadata(&path)?;
        anyhow::ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= 65536,
            "autostart service file is not a bounded regular file"
        );
        anyhow::ensure!(
            hash(&std::fs::read(&path)?) == *expected,
            "autostart service file changed; refusing overwrite or removal"
        );
    } else {
        anyhow::ensure!(
            !path.try_exists()?,
            "unknown autostart service file; refusing replacement"
        );
    }
    Ok(())
}

// Windows argv quoting follows CommandLineToArgvW, including trailing slashes.
pub(super) fn windows_argument(value: &str) -> Result<String> {
    plain_value(value)?;
    let mut result = String::from("\"");
    let mut slashes = 0;
    for c in value.chars() {
        if c == '\\' {
            slashes += 1;
            continue;
        }
        result.push_str(&"\\".repeat(if c == '"' { slashes * 2 + 1 } else { slashes }));
        result.push(c);
        slashes = 0;
    }
    result.push_str(&"\\".repeat(slashes * 2));
    result.push('"');
    Ok(result)
}

fn arguments(config: &Registration) -> Result<String> {
    Ok(format!(
        "runtime supervise --data-dir {}",
        windows_argument(
            config
                .installation
                .to_str()
                .context("non-UTF8 installation")?
        )?
    ))
}

fn task_runlevel_guard() -> &'static str {
    // The scheduler omits default LeastPrivilege from serialized XML. Its
    // typed effective COM value is authoritative; unknown/Highest stays denied.
    r#"function RequireLimited($xmlValue,$effectiveValue){
 if($null -eq $effectiveValue -or $effectiveValue -isnot [int] -or $effectiveValue -ne 0 -or @('','LeastPrivilege') -cnotcontains $xmlValue){throw 'Unknown task run level; refusing lifecycle action'}
}"#
}

fn task_guard(config: &Registration) -> Result<String> {
    let task = ps_literal(&name(config))?;
    let owner = ps_literal(&config.owner)?;
    let exe = ps_literal(&windows_task_path(
        config.executable.to_str().context("non-UTF8 executable")?,
    )?)?;
    let root = ps_literal(&windows_task_path(
        config
            .installation
            .to_str()
            .context("non-UTF8 installation")?,
    )?)?;
    let args = ps_literal(&arguments(config)?)?;
    Ok(format!(
        r#"
{runlevel_guard}
function Sid($value){{try{{if($value -match '^S-\d-'){{return ([Security.Principal.SecurityIdentifier]::new($value)).Value}};return ([Security.Principal.NTAccount]::new($value)).Translate([Security.Principal.SecurityIdentifier]).Value}}catch{{return $null}}}}
$scheduler=[Activator]::CreateInstance([Type]::GetTypeFromProgID('Schedule.Service'));[Console]::Out.WriteLine('rsrs-control-stage:com-created');$scheduler.Connect();[Console]::Out.WriteLine('rsrs-control-stage:com-connected');$folder=$scheduler.GetFolder('\');$t=$null;
try{{$t=$folder.GetTask({task})}}catch{{$failure=$_.Exception;while($null -ne $failure.InnerException){{$failure=$failure.InnerException}};if($failure.HResult -ne -2147024894){{throw}}}}
[Console]::Out.WriteLine('rsrs-control-stage:task-looked-up');
if($null -ne $t){{
 if($t.Xml.Length -gt 65536){{throw 'Task XML exceeds ownership validation limit'}};
 $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;
 $reader=[Xml.XmlReader]::Create([IO.StringReader]::new($t.Xml),$settings);
 $doc=[Xml.XmlDocument]::new();$doc.XmlResolver=$null;try{{$doc.Load($reader)}}finally{{$reader.Dispose()}};
 [Console]::Out.WriteLine('rsrs-control-stage:task-xml-loaded');
 $ns=[Xml.XmlNamespaceManager]::new($doc.NameTable);$ns.AddNamespace('t','http://schemas.microsoft.com/windows/2004/02/mit/task');
 function Text($node,$xpath){{$value=$node.SelectSingleNode($xpath,$ns);if($null -eq $value){{return ''}};return $value.InnerText}}
 $a=@($doc.SelectNodes('/t:Task/t:Actions/*',$ns));$g=@($doc.SelectNodes('/t:Task/t:Triggers/*',$ns));$p=@($doc.SelectNodes('/t:Task/t:Principals/*',$ns));
 [Console]::Out.WriteLine('rsrs-control-stage:task-shape');
 if($p.Count -ne 1 -or $a.Count -ne 1 -or $g.Count -ne 1 -or $a[0].LocalName -ne 'Exec' -or $g[0].LocalName -ne 'LogonTrigger'){{throw 'Unknown task principal/action/trigger count; refusing lifecycle action'}};
 [Console]::Out.WriteLine('rsrs-control-stage:principal-sid');if((Sid (Text $p[0] 't:UserId')) -cne {owner}){{throw 'Unknown task principal; refusing lifecycle action'}};
 [Console]::Out.WriteLine('rsrs-control-stage:principal-logon');if((Text $p[0] 't:LogonType') -cne 'InteractiveToken'){{throw 'Unknown task logon type; refusing lifecycle action'}};
 [Console]::Out.WriteLine('rsrs-control-stage:principal-runlevel');if((Text $p[0] 't:RunLevel') -eq '' -and $t.Definition.Principal.RunLevel -eq 0){{[Console]::Out.WriteLine('rsrs-control-stage:principal-runlevel-omitted-limited')}};
 RequireLimited (Text $p[0] 't:RunLevel') $t.Definition.Principal.RunLevel;
 [Console]::Out.WriteLine('rsrs-control-stage:trigger-sid');if((Sid (Text $g[0] 't:UserId')) -cne {owner}){{throw 'Unknown task trigger identity; refusing lifecycle action'}};
 $arguments=Text $a[0] 't:Arguments';
 [Console]::Out.WriteLine('rsrs-control-stage:action-executable');if(-not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath((Text $a[0] 't:Command')),[IO.Path]::GetFullPath({exe}))){{throw 'Unknown task executable; refusing lifecycle action'}};
 [Console]::Out.WriteLine('rsrs-control-stage:action-arguments');if($arguments -cne {args}){{throw 'Unknown task arguments; refusing lifecycle action'}};
 [Console]::Out.WriteLine('rsrs-control-stage:action-directory');if(-not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath((Text $a[0] 't:WorkingDirectory')),[IO.Path]::GetFullPath({root}))){{throw 'Unknown task directory; refusing lifecycle action'}};
 [Console]::Out.WriteLine('rsrs-control-stage:task-marker');
 if((Text $doc '/t:Task/t:RegistrationInfo/t:Description') -cne {description}){{throw 'Unknown task marker; refusing lifecycle action'}};
}}
[Console]::Out.WriteLine('rsrs-control-stage:task-validated');

"#,
        description = ps_literal(&format!("Respire current-user runtime {}", config.id))?,
        runlevel_guard = task_runlevel_guard()
    ))
}

pub(super) fn inspect(config: &Registration) -> Result<State> {
    file_guard(config)?;
    match config.platform {
        Platform::Linux => {
            let output = control(
                "systemctl",
                &[
                    "--user".into(),
                    "show".into(),
                    name(config),
                    "--no-pager".into(),
                    "--property=LoadState,ActiveState,MainPID,FragmentPath,UnitFileState".into(),
                ],
            )?;
            anyhow::ensure!(
                output.code == 0 || output.code == 4,
                "systemd user session unavailable; no system/linger fallback is performed"
            );
            let fields: std::collections::BTreeMap<_, _> = output
                .stdout
                .lines()
                .filter_map(|line| line.split_once('='))
                .collect();
            let registered = match fields.get("LoadState").copied() {
                Some("not-found") => false,
                Some("loaded") => true,
                _ => bail!("systemd unit load state is unavailable or unexpected; no lifecycle action taken"),
            };
            if registered {
                let fragment = fields
                    .get("FragmentPath")
                    .context("systemd unit path missing")?;
                // systemctl link can expose an installation-owned source via a
                // user-unit symlink. Require the exact same resolved file, not
                // merely matching bytes at an unrelated path.
                anyhow::ensure!(
                    Path::new(fragment).canonicalize()? == item(config).canonicalize()?,
                    "unknown systemd user unit path; refusing lifecycle action"
                );
                let directory = systemd_property(
                    config,
                    "org.freedesktop.systemd1.Service",
                    "WorkingDirectory",
                )?;
                anyhow::ensure!(
                    directory["data"].as_str().map(Path::new)
                        == Some(config.installation.as_path()),
                    "systemd loaded working directory differs from this installation"
                );
                verify_systemd_loaded(
                    config,
                    &systemd_property(config, "org.freedesktop.systemd1.Service", "ExecStart")?,
                    &systemd_property(config, "org.freedesktop.systemd1.Unit", "DropInPaths")?,
                )?;
            }
            Ok(State {
                registered,
                loaded: registered,
                running: fields.get("ActiveState") == Some(&"active"),
                enabled: fields
                    .get("UnitFileState")
                    .is_some_and(|v| matches!(*v, "enabled" | "enabled-runtime")),
            })
        }
        Platform::Macos => {
            let disabled = checked("launchctl", vec!["print-disabled".into(), domain(config)])?;
            let enabled = launchd_enabled(&disabled, &name(config))?;
            let output = control("launchctl", &["print".into(), label(config)])?;
            if output.code != 0 {
                // print-disabled above already verified the user domain; a
                // full domain print can exceed the deliberately bounded output.
                anyhow::ensure!(
                    [3, 113].contains(&output.code),
                    "LaunchAgent query failed; refusing lifecycle action"
                );
                return Ok(State {
                    registered: item(config).is_file(),
                    loaded: false,
                    running: false,
                    enabled,
                });
            }
            let property = |key: &str| -> Result<Option<String>> {
                output
                    .stdout
                    .lines()
                    .find_map(|line| line.trim().strip_prefix(&format!("{key} = ")))
                    .map(launchd_value)
                    .transpose()
            };
            anyhow::ensure!(
                property("path")?.is_some_and(|value| Path::new(&value).canonicalize().is_ok_and(
                    |actual| item(config)
                        .canonicalize()
                        .is_ok_and(|expected| actual == expected)
                )),
                "unknown loaded LaunchAgent path; refusing lifecycle action"
            );
            anyhow::ensure!(
                property("program")?.is_some_and(|value| Path::new(&value)
                    .canonicalize()
                    .is_ok_and(|actual| config
                        .executable
                        .canonicalize()
                        .is_ok_and(|expected| actual == expected))),
                "unknown loaded LaunchAgent program; refusing lifecycle action"
            );
            let args = output
                .stdout
                .split("arguments = {\n")
                .nth(1)
                .and_then(|s| s.split("\n\t}").next())
                .context("loaded LaunchAgent arguments unavailable")?;
            let actual: Vec<String> = args.lines().map(launchd_value).collect::<Result<_>>()?;
            let expected = [
                config.executable.to_str().context("non-UTF8 executable")?,
                "runtime",
                "supervise",
                "--data-dir",
                config
                    .installation
                    .to_str()
                    .context("non-UTF8 installation")?,
            ];
            anyhow::ensure!(
                actual.len() == expected.len()
                    && actual
                        .iter()
                        .zip(expected)
                        .all(|(actual, expected)| actual == expected),
                "loaded LaunchAgent arguments changed; refusing lifecycle action"
            );
            Ok(State {
                registered: true,
                loaded: true,
                running: property("state")?.as_deref() == Some("running"),
                enabled,
            })
        }
        Platform::Windows => {
            let text=powershell(format!("{};$registered=($null -ne $t);$running=($registered -and $t.State -eq 4);$enabled=($registered -and [bool]$t.Enabled);[Console]::Out.WriteLine($registered.ToString().ToLowerInvariant());[Console]::Out.WriteLine($running.ToString().ToLowerInvariant());[Console]::Out.WriteLine($enabled.ToString().ToLowerInvariant())",task_guard(config)?))?;
            let flags: Vec<bool> = text
                .lines()
                .map(str::parse)
                .collect::<std::result::Result<_, _>>()?;
            anyhow::ensure!(
                flags.len() == 3,
                "invalid scheduled task status field count"
            );
            Ok(State {
                registered: flags[0],
                loaded: flags[0],
                running: flags[1],
                enabled: flags[2],
            })
        }
    }
}

pub(super) fn install(config: &mut Registration) -> Result<()> {
    validate_executable(config.platform, &config.executable)?;
    let before = inspect(config)?;
    anyhow::ensure!(
        !before.registered || config.artifact_hashes.contains_key("service"),
        "unknown existing registration; refusing replacement"
    );
    let content = render(config)?;
    private_write(
        &item(config),
        content.as_bytes(),
        config.artifact_hashes.get("service").map(String::as_str),
    )?;
    config
        .artifact_hashes
        .insert("service".into(), hash(content.as_bytes()));
    match config.platform {
        Platform::Linux => {
            checked(
                "systemctl",
                vec![
                    "--user".into(),
                    "link".into(),
                    item(config).to_string_lossy().into_owned(),
                ],
            )?;
            checked("systemctl", vec!["--user".into(), "daemon-reload".into()])?;
            checked(
                "systemctl",
                vec!["--user".into(), "enable".into(), name(config)],
            )?;
        }
        Platform::Macos => {
            checked("launchctl", vec!["enable".into(), label(config)])?;
        }
        Platform::Windows => {
            powershell(format!("{};$xml=[IO.File]::ReadAllText({});[void]$folder.RegisterTask({},$xml,{},{},$null,3,$null)",task_guard(config)?,ps_literal(item(config).to_str().context("non-UTF8 task path")?)?,ps_literal(&name(config))?,if before.registered{6}else{2},ps_literal(&config.owner)?))?;
        }
    }
    Ok(())
}

pub(super) fn reset_backoff(config: &Registration) -> Result<()> {
    let state = inspect(config)?;
    if state.registered && config.platform == Platform::Linux {
        checked(
            "systemctl",
            vec!["--user".into(), "reset-failed".into(), name(config)],
        )?;
    }
    Ok(())
}

pub(super) fn start(config: &Registration) -> Result<()> {
    let current = inspect(config)?;
    anyhow::ensure!(
        current.registered,
        "owned autostart registration is missing"
    );
    match config.platform {
        Platform::Linux => {
            checked(
                "systemctl",
                vec!["--user".into(), "start".into(), name(config)],
            )?;
        }
        Platform::Macos => {
            if !current.loaded {
                checked(
                    "launchctl",
                    vec![
                        "bootstrap".into(),
                        domain(config),
                        item(config).to_string_lossy().into_owned(),
                    ],
                )?;
            } else if !current.running {
                checked("launchctl", vec!["kickstart".into(), label(config)])?;
            }
        }
        Platform::Windows => {
            powershell(format!(
                "{};if($null -eq $t){{throw 'Owned task disappeared'}};[void]$t.Run($null)",
                task_guard(config)?
            ))?;
        }
    }
    Ok(())
}

pub(super) fn stop(config: &Registration) -> Result<()> {
    let current = inspect(config)?;
    match config.platform {
        Platform::Linux => {
            if current.registered {
                checked(
                    "systemctl",
                    vec!["--user".into(), "stop".into(), name(config)],
                )?;
            }
        }
        Platform::Macos => {
            if current.loaded {
                checked("launchctl", vec!["bootout".into(), label(config)])?;
            }
        }
        Platform::Windows => {
            if current.running {
                powershell(format!(
                    "{};if($null -ne $t){{$t.Stop(0);$deadline=[DateTime]::UtcNow.AddSeconds(15);while($folder.GetTask({}).State -eq 4){{if([DateTime]::UtcNow -ge $deadline){{throw 'Owned task did not stop'}};[Threading.Thread]::Sleep(100)}}}}",
                    task_guard(config)?,ps_literal(&name(config))?
                ))?;
            }
        }
    }
    Ok(())
}

pub(super) fn disable(config: &Registration) -> Result<()> {
    let current = inspect(config)?;
    match config.platform {
        Platform::Linux => {
            if current.registered {
                checked(
                    "systemctl",
                    vec!["--user".into(), "disable".into(), name(config)],
                )?;
                // Disabling can remove the user-unit link for an external
                // owned source. Refresh cached FragmentPath before readback.
                checked("systemctl", vec!["--user".into(), "daemon-reload".into()])?;
            }
        }
        Platform::Macos => {
            checked("launchctl", vec!["disable".into(), label(config)])?;
        }
        Platform::Windows => {
            if current.registered {
                powershell(format!(
                    "{};if($null -ne $t){{$t.Enabled=$false}}",
                    task_guard(config)?
                ))?;
            }
        }
    }
    Ok(())
}

pub(super) fn remove(config: &Registration) -> Result<()> {
    let current = inspect(config)?;
    anyhow::ensure!(
        !current.running,
        "stop the owned runtime before removing its startup registration"
    );
    match config.platform {
        Platform::Linux => {
            disable(config)?;
        }
        Platform::Macos => {
            if current.loaded {
                stop(config)?;
            }
            disable(config)?;
        }
        Platform::Windows => {
            if current.registered {
                powershell(format!(
                    "{};if($null -ne $t){{$folder.DeleteTask({},0)}}",
                    task_guard(config)?,
                    ps_literal(&name(config))?
                ))?;
            }
        }
    }
    file_guard(config)?;
    if item(config).is_file() {
        std::fs::remove_file(item(config))?;
    }
    if config.platform == Platform::Linux {
        checked("systemctl", vec!["--user".into(), "daemon-reload".into()])?;
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
pub(super) mod test_adapter {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;
    #[derive(Default)]
    pub struct Fake {
        pub registered: bool,
        pub enabled: bool,
        pub running: bool,
        pub dropin: bool,
        pub fragment: Option<PathBuf>,
        pub fail: Option<String>,
        pub changes: Vec<String>,
    }
    pub struct Scope;
    impl Drop for Scope {
        fn drop(&mut self) {
            TEST_CONTROL.with(|slot| *slot.borrow_mut() = None);
        }
    }
    pub fn install(config: &Registration) -> (Scope, Rc<RefCell<Fake>>) {
        let state = Rc::new(RefCell::new(Fake::default()));
        let shared = state.clone();
        let config = config.clone();
        TEST_CONTROL.with(|slot| *slot.borrow_mut() = Some(Box::new(move |name,args| {
            let mut state = shared.borrow_mut();
            let ok = |stdout:String| Ok(Output{code:0,stdout});
            match name {
                "id" => ok(config.owner.clone()),
                "systemctl" => {
                    anyhow::ensure!(args.first().map(String::as_str) == Some("--user"), "fake refuses non-user operation");
                    let operation = args.get(1).context("manager operation missing")?;
                    if state.fail.as_ref() == Some(operation) { return Ok(Output{code:1,stdout:String::new()}); }
                    if operation == "show" { return ok(format!("LoadState={}\nActiveState={}\nMainPID=0\nFragmentPath={}\nUnitFileState={}\n", if state.registered {"loaded"}else{"not-found"},if state.running {"active"}else{"inactive"},state.fragment.clone().unwrap_or_else(||item(&config)).display(),if state.enabled {"enabled"}else{"disabled"})); }
                    state.changes.push(operation.clone());
                    match operation.as_str() {
                        "link" => state.registered = true,
                        "enable" => state.enabled = true,
                        "disable" => state.enabled = false,
                        "start" => state.running = true,
                        "stop" => state.running = false,
                        "daemon-reload" => {if !item(&config).exists() {state.registered=false;}},
                        "reset-failed" => {},
                        _ => bail!("unexpected fake operation"),
                    }
                    ok(String::new())
                },
                "busctl" => {
                    if args.iter().any(|v|v == "GetUnit") { return ok(serde_json::json!({"data":["/org/freedesktop/systemd1/unit/test"]}).to_string()); }
                    match args.last().map(String::as_str) {
                        Some("DropInPaths") => ok(serde_json::json!({"data":if state.dropin {vec!["/tmp/unknown.conf"]}else{vec![]}}).to_string()),
                        Some("WorkingDirectory") => ok(serde_json::json!({"data":config.installation}).to_string()),
                        Some("ExecStart") => ok(serde_json::json!({"data":[[config.executable,[config.executable,"runtime","supervise","--data-dir",config.installation],false,0,0,0,0,0,0,0]]}).to_string()),
                        _ => bail!("unexpected fake property"),
                    }
                },
                _ => bail!("unexpected fake program"),
            }
        })));
        (Scope, state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn loaded_systemd_configuration_must_match_disk_identity_without_overrides() -> Result<()> {
        let config = super::super::tests::fixture(Platform::Linux);
        let row = serde_json::json!([
            config.executable,
            [
                config.executable,
                "runtime",
                "supervise",
                "--data-dir",
                config.installation
            ],
            false,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        ]);
        let exec = serde_json::json!({"data":[row]});
        let clean = serde_json::json!({"data":[]});
        verify_systemd_loaded(&config, &exec, &clean)?;
        anyhow::ensure!(verify_systemd_loaded(
            &config,
            &exec,
            &serde_json::json!({"data":["/tmp/foreign.conf"]})
        )
        .is_err());
        let mut changed = exec.clone();
        changed["data"][0][0] = serde_json::json!("/tmp/foreign");
        anyhow::ensure!(verify_systemd_loaded(&config, &changed, &clean).is_err());
        changed = exec.clone();
        changed["data"][0][1][4] = serde_json::json!("another-installation");
        anyhow::ensure!(verify_systemd_loaded(&config, &changed, &clean).is_err());
        anyhow::ensure!(
            verify_systemd_loaded(&config, &serde_json::json!({"data":[]}), &clean).is_err()
        );
        Ok(())
    }
    #[test]
    fn launchd_values_preserve_spaces_quotes_and_literal_backslashes() -> Result<()> {
        let value = "/tmp/path spaces % $ \" \\\\";
        anyhow::ensure!(launchd_value(value)? == value);
        anyhow::ensure!(launchd_value(&serde_json::to_string(value)?)? == value);
        anyhow::ensure!(launchd_value("\"unterminated").is_err());
        Ok(())
    }
    #[test]
    fn launchd_status_uses_actual_disabled_override() -> Result<()> {
        anyhow::ensure!(launchd_enabled(
            "disabled services = {\n}",
            "ai.risense.test"
        )?);
        anyhow::ensure!(!launchd_enabled(
            "disabled services = {\n \"ai.risense.test\" => true\n}",
            "ai.risense.test"
        )?);
        anyhow::ensure!(launchd_enabled(
            "disabled services = {\n \"ai.risense.test\" => false\n}",
            "ai.risense.test"
        )?);
        anyhow::ensure!(launchd_enabled(
            "disabled services = {\n \"ai.risense.test\" => unknown\n}",
            "ai.risense.test"
        )
        .is_err());
        anyhow::ensure!(launchd_enabled(
            "disabled services = {\n \"ai.risense.test\" => enabled\n}",
            "ai.risense.test"
        )?);
        anyhow::ensure!(!launchd_enabled(
            "disabled services = {\n \"ai.risense.test\" => disabled\n}",
            "ai.risense.test"
        )?);
        anyhow::ensure!(launchd_enabled("unrecognized", "ai.risense.test").is_err());
        Ok(())
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn user_manager_lifecycle_refuses_loaded_overrides_and_preserves_data() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let mut config = super::super::tests::fixture(Platform::Linux);
        config.installation = temporary.path().canonicalize()?;
        config.user_home = config.installation.join("home");
        config.executable = config.installation.join("bin/rsrs");
        let (_scope, state) = test_adapter::install(&config);
        anyhow::ensure!(!inspect(&config)?.registered);
        install(&mut config)?;
        anyhow::ensure!(inspect(&config)?.enabled);
        start(&config)?;
        anyhow::ensure!(inspect(&config)?.running);
        let changes = state.borrow().changes.len();
        let alias = config.installation.join("unit-link.service");
        std::os::unix::fs::symlink(item(&config), &alias)?;
        state.borrow_mut().fragment = Some(alias.clone());
        anyhow::ensure!(
            inspect(&config)?.registered,
            "exact resolved owned source should be recognized"
        );
        std::fs::remove_file(&alias)?;
        let foreign = config.installation.join("foreign.service");
        std::fs::copy(item(&config), &foreign)?;
        std::os::unix::fs::symlink(&foreign, &alias)?;
        anyhow::ensure!(
            inspect(&config).is_err(),
            "matching bytes at an unrelated source are not ownership"
        );
        state.borrow_mut().fragment = None;
        state.borrow_mut().dropin = true;
        anyhow::ensure!(stop(&config).is_err());
        anyhow::ensure!(remove(&config).is_err());
        anyhow::ensure!(state.borrow().changes.len() == changes && item(&config).exists());
        state.borrow_mut().dropin = false;
        anyhow::ensure!(
            remove(&config).is_err(),
            "running service must not be removed"
        );
        stop(&config)?;
        disable(&config)?;
        reset_backoff(&config)?;
        anyhow::ensure!(!inspect(&config)?.enabled && !inspect(&config)?.running);
        let preserved = config.installation.join("library.db");
        std::fs::write(&preserved, b"synthetic data")?;
        remove(&config)?;
        anyhow::ensure!(!item(&config).exists() && std::fs::read(preserved)? == b"synthetic data");
        config.artifact_hashes.clear();
        anyhow::ensure!(!inspect(&config)?.registered);
        Ok(())
    }
    #[cfg(unix)]
    #[test]
    fn manager_control_is_bounded_private_and_reaps_its_timed_out_child() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|_| anyhow::anyhow!("test environment lock poisoned"))?;
        struct Restore(Option<std::ffi::OsString>);
        impl Drop for Restore {
            fn drop(&mut self) {
                match &self.0 {
                    Some(v) => std::env::set_var("RSRS_SUPER", v),
                    None => std::env::remove_var("RSRS_SUPER"),
                }
            }
        }
        let _restore = Restore(std::env::var_os("RSRS_SUPER"));
        std::env::set_var("RSRS_SUPER", "synthetic-not-for-child");
        let output = checked(
            "sh",
            vec![
                "-c".into(),
                "test -z \"${RSRS_SUPER+x}\" && printf safe".into(),
            ],
        )?;
        anyhow::ensure!(output == "safe");
        anyhow::ensure!(checked("sh", vec!["-c".into(), "exit 7".into()]).is_err());
        anyhow::ensure!(control("sh", &["-c".into(), "head -c 65537 /dev/zero".into()]).is_err());
        anyhow::ensure!(control("sh", &["-c".into(), "printf '\\377'".into()]).is_err());
        anyhow::ensure!(program("respire-missing-manager-fixture").is_err());
        let temp = tempfile::tempdir()?;
        let pid_file = temp.path().join("child.pid");
        let error = control(
            "sh",
            &[
                "-c".into(),
                "printf '%s' \"$$\" > \"$1\"; exec sleep 90".into(),
                "respire-fixture".into(),
                pid_file.to_string_lossy().into_owned(),
            ],
        )
        .err()
        .context("timeout was not enforced")?;
        anyhow::ensure!(error.to_string().contains("timed out"));
        let pid: u32 = std::fs::read_to_string(pid_file)?.parse()?;
        anyhow::ensure!(
            process_birth(pid)?.is_none(),
            "timed out manager child was not reaped"
        );
        Ok(())
    }
    #[test]
    fn encoded_control_preserves_unicode_and_stages_never_echo_arbitrary_output() -> Result<()> {
        use base64::Engine as _;
        let script = "[Console]::WriteLine('\u{4f60}\u{597d} \" $ \\');";
        let bytes = base64::engine::general_purpose::STANDARD.decode(encoded_powershell(script))?;
        let words: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        anyhow::ensure!(String::from_utf16(&words)? == script);
        anyhow::ensure!(
            last_control_stage(b"secret arbitrary output\nrsrs-control-stage:com-connected\n")
                == "com-connected"
        );
        anyhow::ensure!(last_control_stage(b"rsrs-control-stage:secret-value") == "unreported");
        Ok(())
    }
    #[test]
    fn scheduler_paths_keep_identity_without_nt_namespace_or_environment_interpretation(
    ) -> Result<()> {
        anyhow::ensure!(
            windows_task_path(r"\\?\C:\safe folder\rsrs.exe")? == r"C:\safe folder\rsrs.exe"
        );
        anyhow::ensure!(windows_task_path(r"\\?\UNC\server\share\data")? == r"\\server\share\data");
        anyhow::ensure!(windows_task_path(r"\\?\GLOBALROOT\Device").is_err());
        anyhow::ensure!(control_hresult("rsrs-control-hresult:80070005") == "80070005");
        anyhow::ensure!(control_hresult("rsrs-control-hresult:secret-material") == "unreported");
        anyhow::ensure!(control_xml_location("rsrs-control-xml-location:1,39") == "1,39");
        for unsafe_value in ["1,secret", "123456789,2", "1,2,3", ",2"] {
            anyhow::ensure!(
                control_xml_location(&format!("rsrs-control-xml-location:{unsafe_value}"))
                    == "unreported"
            );
        }
        #[cfg(target_os = "linux")]
        {
            validate_executable(Platform::Linux, Path::new("/tmp/data spaces % $/rsrs"))?;
            for path in [
                "/tmp/bad\"/rsrs",
                "/tmp/bad'/rsrs",
                r"/tmp/bad\name/rsrs",
                "relative/rsrs",
            ] {
                anyhow::ensure!(validate_executable(Platform::Linux, Path::new(path)).is_err());
            }
        }
        Ok(())
    }
    #[cfg(windows)]
    #[test]
    fn scheduler_default_runlevel_requires_effective_limited_and_rejects_unknown_values(
    ) -> Result<()> {
        let script = format!(
            r#"{}
$cases=@(
 @{{xml='';value=0;allowed=$true}},@{{xml='LeastPrivilege';value=0;allowed=$true}},
 @{{xml='HighestAvailable';value=0;allowed=$false}},@{{xml='';value=1;allowed=$false}},
 @{{xml='LeastPrivilege';value=1;allowed=$false}},@{{xml='';value=$null;allowed=$false}},
 @{{xml='';value='0';allowed=$false}},@{{xml='';value=$false;allowed=$false}},
 @{{xml='unknown';value=0;allowed=$false}},@{{xml='LeastPrivilege';value=-1;allowed=$false}});
foreach($case in $cases){{$accepted=$true;try{{RequireLimited $case.xml $case.value}}catch{{$accepted=$false}};if($accepted -ne $case.allowed){{throw 'Effective task run-level contract failed'}}}};
[Console]::Out.WriteLine('limited-runlevel-contract:passed');"#,
            task_runlevel_guard()
        );
        anyhow::ensure!(powershell(script)?.trim() == "limited-runlevel-contract:passed");
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn scheduler_validates_unicode_xml_variants_without_registering_a_task() -> Result<()> {
        use base64::Engine as _;
        let temporary = tempfile::tempdir()?;
        let mut config = super::super::tests::fixture(Platform::Windows);
        config.installation = temporary.path().canonicalize()?;
        config.executable = std::env::current_exe()?.canonicalize()?;
        config.owner = owner()?;
        config.id = super::super::identity(&config.installation, &config.owner);
        let xml = super::super::render(&config)?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(xml.as_bytes());
        // TASK_VALIDATE_ONLY=1 checks the identical payload without registering,
        // updating, enabling or running a task. Compare only the declaration.
        let script = format!(
            r#"{guard};if($null -ne $t){{throw 'Validation fixture task already exists'}};
$xml=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}'));
$utf8=$xml.Replace('<?xml version="1.0"?>','<?xml version="1.0" encoding="UTF-8"?>');
try{{[void]$folder.RegisterTask({task},$utf8,1,{owner},$null,3,$null);[Console]::Out.WriteLine('utf8:valid')}}catch{{$failure=$_.Exception;while($null -ne $failure.InnerException){{$failure=$failure.InnerException}};[Console]::Out.WriteLine('utf8:hresult:'+$failure.HResult.ToString('X8'))}};
[void]$folder.RegisterTask({task},$xml,1,{owner},$null,3,$null);[Console]::Out.WriteLine('neutral:valid');
{guard};if($null -ne $t){{throw 'Validation-only unexpectedly created a task'}};
"#,
            guard = task_guard(&config)?,
            task = ps_literal(&name(&config))?,
            owner = ps_literal(&config.owner)?
        );
        let result = powershell(script)?;
        anyhow::ensure!(
            result.lines().any(|line| line == "neutral:valid"),
            "encoding-neutral task XML did not validate"
        );
        // Fixed protocol fields only; never print XML, paths or arbitrary COM errors.
        println!("Task Scheduler validation-only comparison: {result}");
        Ok(())
    }

    #[test]
    fn windows_quoting_and_task_guard_are_literal_and_current_user_only() -> Result<()> {
        anyhow::ensure!(windows_argument("C:\\user folder\\")? == "\"C:\\user folder\\\\\"");
        anyhow::ensure!(ps_literal("a';&b")? == "'a'';&b'");
        let config = super::super::tests::fixture(Platform::Windows);
        let script = task_guard(&config)?;
        anyhow::ensure!(
            script.contains("Interactive")
                && script.contains("LeastPrivilege")
                && script.contains("$arguments -cne")
        );
        anyhow::ensure!(
            !script.contains("RunLevel Highest") && !script.contains("ExecutionPolicy Bypass")
        );
        Ok(())
    }
}
