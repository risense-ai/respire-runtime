#!/usr/bin/env python3
"""Actual native foreground lifecycle in a disposable home; no OS registration.

The executable is the only input. No credentials, user data or inherited Respire
configuration are passed to it. Real sign-in service adapters require a separate
platform acceptance run; passing this script does not claim that acceptance.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--register", action="store_true", help="Exercise a disposable current-user OS registration on an ephemeral GitHub runner")
    parser.add_argument("--previous-binary", type=Path, help="Pinned official DEV.6 native executable for upgrade acceptance")
    args = parser.parse_args()
    if args.previous_binary and not args.register:
        parser.error("previous-version upgrade acceptance requires --register")
    if args.register and not (os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"):
        parser.error("OS registration acceptance is limited to an ephemeral GitHub-hosted runner")
    binary = str(args.binary.resolve(strict=True))
    with tempfile.TemporaryDirectory(prefix="respire-autostart-") as temporary:
        base = Path(temporary)
        home = base / "home"
        home.mkdir()
        root = base / ('data spaces % $ " \\' if os.name == "posix" else "data spaces % and $")
        with socket.socket() as port_socket:
            port_socket.bind(("127.0.0.1", 0))
            port = port_socket.getsockname()[1]
        env = {key: os.environ[key] for key in (
            "PATH", "LANG", "LC_ALL", "SystemRoot", "WINDIR", "TEMP", "TMP",
            "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "LLVM_PROFILE_FILE",
            "APPDATA", "LOCALAPPDATA", "COMPUTERNAME", "COMSPEC", "PATHEXT",
            "ProgramFiles", "ProgramFiles(x86)", "ProgramData"
        ) if key in os.environ}
        if args.register and os.name == "posix" and os.uname().sysname == "Linux":
            import stat
            runtime = Path(f"/run/user/{os.getuid()}")
            if runtime.is_dir() and runtime.stat().st_uid == os.getuid():
                bus = runtime / "bus"
                if bus.exists() and stat.S_ISSOCK(bus.stat().st_mode):
                    env.setdefault("XDG_RUNTIME_DIR", str(runtime))
                    env.setdefault("DBUS_SESSION_BUS_ADDRESS", f"unix:path={bus}")
        env.update(HOME=str(home), USERPROFILE=str(home), RSRS_DATA_DIR=str(root),
                   RSRS_BIN_DIR=str(base / "bin"), RSRS_RPC_PORT=str(port),
                   RSRS_CORE_TEST_MODE="1", RSRS_NO_AUTOSYNC="1", RSRS_UPDATE_CHECK="0")

        restart_stages={"restart_probe","restart_managed","restart_identity","restart_stop","restart_start","restart_ready"}
        def read_restart_stages():
            events=root/"runtime/autostart/events.jsonl"
            try:
                if not events.is_file() or events.is_symlink() or events.stat().st_size>65536:
                    return []
                return [value["event"] for line in events.read_text().splitlines()
                        if isinstance(value:=json.loads(line),dict) and value.get("event") in restart_stages]
            except (OSError,ValueError):
                return [] # Diagnostics must not replace the original timeout.

        def command(*argv):
            try:
                return subprocess.run([binary, "--json", *argv], env=env,
                                      capture_output=True, text=True, timeout=45)
            except subprocess.TimeoutExpired:
                # Fixed stage names only: never dump captured stderr, arguments,
                # registration, raw errors or private account content.
                print("isolated restart stage diagnostic",json.dumps({"stages":read_restart_stages()[-12:]}),flush=True)
                raise

        status = command("runtime", "autostart", "status")
        assert status.returncode == 0, status.stderr
        summary = json.loads(status.stdout)["summary"]
        assert summary["enabled"] is False and summary["registered"] is False
        assert not root.exists(), "status must not create a profile"
        denied = command("--client-only", "runtime", "autostart", "enable", "--now")
        assert denied.returncode != 0 and not root.exists()
        with (base / "foreground.log").open("w+") as log:
            child = subprocess.Popen([binary, "runtime", "run"], env=env,
                                     stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 30
                health = None
                while time.monotonic() < deadline:
                    if child.poll() is not None:
                        log.seek(0)
                        raise AssertionError("foreground exited: " + log.read()[-3000:])
                    try:
                        with urllib.request.urlopen(
                            f"http://127.0.0.1:{port}/api/health", timeout=1
                        ) as response:
                            health = json.load(response)
                        if health.get("store_ready"):
                            break
                    except (OSError, ValueError):
                        pass
                    time.sleep(0.1)
                assert health and health["store_ready"], "store never became ready"
                assert health["pid"] == child.pid and health["managed_id"] is None
                assert Path(health["installation_root"]).resolve() == root.resolve()
                # No inherited RUST_MIN_STACK: the actual dispatch thread must
                # support context-query parsing without terminating its host.
                query=command("--client-only","config")
                assert query.returncode == 0, f"foreground context RPC failed: {query.stdout} {query.stderr}"
                assert json.loads(query.stdout)["summary"]["autosync"] is False
                assert child.poll() is None, "context RPC terminated the foreground host"
                stopped = command("runtime", "stop")
                assert stopped.returncode == 0, stopped.stderr
                assert child.wait(timeout=20) == 0
                assert not (root / "runtime/autostart/registration.json").exists()
            finally:
                if child.poll() is None:
                    child.terminate()
                    child.wait(timeout=20)
        print("PASS: read-only default-off status, client-only denial, actual foreground store readiness and owned stop")
        # A fresh off-mode installation must restart without opening/creating a
        # library. Its detached child is always stopped before leaving the test.
        off_root = base / "off installation"
        off_root.mkdir()
        (off_root / "client.json").write_text(json.dumps({"service_mode":"off"}))
        off_env = dict(env, RSRS_DATA_DIR=str(off_root), RSRS_BIN_DIR=str(base/"off-bin"))
        try:
            for argv in [("runtime","start"),("runtime","stop")]*3+[("runtime","restart")]:
                result = subprocess.run([binary,"--json",*argv],env=off_env,capture_output=True,text=True,timeout=45)
                assert result.returncode == 0, f"off mode {argv}: {result.stdout} {result.stderr}"
                assert not (off_root/"rsrs.db").exists() and not (off_root/"onememory.db").exists(), "off restart created a database"
            if os.name == "nt":
                # Reproduce the real upgrade failure without an account/model:
                # suspend only this fixture's verified unmanaged native owner.
                import ctypes
                from ctypes import wintypes
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health",timeout=5) as response:
                    frozen=json.load(response)
                assert Path(frozen["data_dir"]).resolve()==off_root.resolve()
                kernel=ctypes.WinDLL("kernel32",use_last_error=True)
                kernel.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD];kernel.OpenProcess.restype=wintypes.HANDLE
                kernel.GetProcessId.argtypes=[wintypes.HANDLE];kernel.GetProcessId.restype=wintypes.DWORD
                kernel.QueryFullProcessImageNameW.argtypes=[wintypes.HANDLE,wintypes.DWORD,wintypes.LPWSTR,ctypes.POINTER(wintypes.DWORD)];kernel.QueryFullProcessImageNameW.restype=wintypes.BOOL
                kernel.WaitForSingleObject.argtypes=[wintypes.HANDLE,wintypes.DWORD];kernel.WaitForSingleObject.restype=wintypes.DWORD
                kernel.CloseHandle.argtypes=[wintypes.HANDLE];kernel.CloseHandle.restype=wintypes.BOOL
                ntdll=ctypes.WinDLL("ntdll")
                ntdll.NtSuspendProcess.argtypes=[wintypes.HANDLE];ntdll.NtSuspendProcess.restype=wintypes.LONG
                ntdll.NtResumeProcess.argtypes=[wintypes.HANDLE];ntdll.NtResumeProcess.restype=wintypes.LONG
                owned=kernel.OpenProcess(0x101800,False,frozen["pid"]) # synchronize/query/suspend, never an arbitrary PID
                assert owned and kernel.GetProcessId(owned)==frozen["pid"]
                suspended=False
                try:
                    image=ctypes.create_unicode_buffer(32768);length=wintypes.DWORD(len(image))
                    assert kernel.QueryFullProcessImageNameW(owned,0,image,ctypes.byref(length))
                    assert os.path.samefile(image.value,Path(off_env["RSRS_BIN_DIR"])/"rsrs.exe")
                    assert kernel.WaitForSingleObject(owned,0)==258
                    assert ntdll.NtSuspendProcess(owned)>=0
                    suspended=True
                    recovered=subprocess.run([binary,"--json","runtime","restart"],env=off_env,capture_output=True,text=True,timeout=45)
                    assert recovered.returncode==0, f"suspended owner recovery: {recovered.stdout} {recovered.stderr}"
                    envelope=json.loads(recovered.stdout)
                    assert envelope["command"]=="runtime.restart" and envelope["status"]=="ok", envelope
                    summary=envelope["summary"]
                    assert summary["forced"] is True and summary["stopped_pid"]==frozen["pid"] and summary["pid"]!=frozen["pid"]
                    assert kernel.WaitForSingleObject(owned,15000)==0, "the inspected suspended process survived forced recovery"
                    assert not (off_root/"rsrs.db").exists() and not (off_root/"onememory.db").exists()
                    print("PASS: actual suspended unmanaged Windows runtime recovered with verified native identity, no WMI, and no database")
                finally:
                    if suspended and kernel.WaitForSingleObject(owned,0)==258:
                        assert ntdll.NtResumeProcess(owned)>=0, "owned failed fixture could not be resumed"
                    kernel.CloseHandle(owned)
        finally:
            result = subprocess.run([binary,"--json","runtime","stop"],env=off_env,capture_output=True,text=True,timeout=45)
            assert result.returncode == 0, f"off-mode child cleanup failed: {result.stdout} {result.stderr}"
        print("PASS: fresh memory-off start/stop/restart without a database")
        if args.register:
            if os.name == "posix" and os.uname().sysname == "Linux":
                rejected_root=base/"rejected-native-path"
                rejected=subprocess.run([binary,"--json","runtime","autostart","enable"],
                    env=dict(env,RSRS_DATA_DIR=str(rejected_root),RSRS_BIN_DIR=str(base/'unsupported \" backslash\\')),
                    capture_output=True,text=True,timeout=45)
                assert rejected.returncode != 0 and not rejected_root.exists(), "unsupported executable path created state"
                print("PASS: unsupported systemd executable path refused before any lifecycle state")

            def collect_managed_profiles():
                # A service manager deliberately does not inherit test-runner
                # profiling variables. Collect the real instrumented native
                # child's default profiles from this disposable working root.
                pattern = os.environ.get("LLVM_PROFILE_FILE")
                if not pattern:
                    return
                import shutil
                import uuid
                destination = Path(pattern).parent
                assert destination.is_dir(), "coverage profile destination missing"
                for profile in root.rglob("*.profraw"):
                    assert not profile.is_symlink() and profile.stat().st_size <= 64 * 1024 * 1024
                    shutil.copyfile(profile, destination / f"autostart-managed-{uuid.uuid4().hex}.profraw")

            from contextlib import contextmanager, nullcontext

            @contextmanager
            def owned_windows_pair(expected_root):
                # Kernel-backed process handles bind the exact instances; a
                # stale PID or a Task Scheduler engine must never be killed.
                import ctypes
                from ctypes import wintypes
                assert os.name == "nt"
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health",timeout=5) as response:
                    current=json.load(response)
                expected=json.loads((expected_root/"runtime/autostart/registration.json").read_text())
                assert Path(current["installation_root"]).resolve()==expected_root.resolve() and current["managed_id"]==expected["id"]
                kernel=ctypes.WinDLL("kernel32",use_last_error=True)
                kernel.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD];kernel.OpenProcess.restype=wintypes.HANDLE
                kernel.GetProcessId.argtypes=[wintypes.HANDLE];kernel.GetProcessId.restype=wintypes.DWORD
                kernel.QueryFullProcessImageNameW.argtypes=[wintypes.HANDLE,wintypes.DWORD,wintypes.LPWSTR,ctypes.POINTER(wintypes.DWORD)];kernel.QueryFullProcessImageNameW.restype=wintypes.BOOL
                kernel.GetProcessTimes.argtypes=[wintypes.HANDLE]+[ctypes.POINTER(wintypes.FILETIME)]*4;kernel.GetProcessTimes.restype=wintypes.BOOL
                kernel.TerminateProcess.argtypes=[wintypes.HANDLE,wintypes.UINT];kernel.TerminateProcess.restype=wintypes.BOOL
                kernel.WaitForSingleObject.argtypes=[wintypes.HANDLE,wintypes.DWORD];kernel.WaitForSingleObject.restype=wintypes.DWORD
                kernel.CloseHandle.argtypes=[wintypes.HANDLE];kernel.CloseHandle.restype=wintypes.BOOL
                handles=[]
                def checked_process(pid):
                    assert pid not in (0,os.getpid())
                    handle=kernel.OpenProcess(0x101001,False,pid) # terminate + limited query + synchronize
                    assert handle, "cannot open the owned native fixture process"
                    handles.append(handle)
                    image=ctypes.create_unicode_buffer(32768);size=wintypes.DWORD(len(image))
                    assert kernel.GetProcessId(handle)==pid and kernel.QueryFullProcessImageNameW(handle,0,image,ctypes.byref(size))
                    assert os.path.samefile(image.value,current["exe"]), "fixture process has a foreign executable"
                    values=[wintypes.FILETIME() for _ in range(4)]
                    assert kernel.GetProcessTimes(handle,*[ctypes.byref(value) for value in values])
                    assert kernel.WaitForSingleObject(handle,0)==258, "fixture process already exited"
                    return handle,(values[0].dwHighDateTime<<32)|values[0].dwLowDateTime
                try:
                    child,child_birth=checked_process(current["pid"])
                    class ProcessEntry(ctypes.Structure):
                        _fields_=[("dwSize",wintypes.DWORD),("cntUsage",wintypes.DWORD),
                            ("th32ProcessID",wintypes.DWORD),("th32DefaultHeapID",ctypes.c_size_t),
                            ("th32ModuleID",wintypes.DWORD),("cntThreads",wintypes.DWORD),
                            ("th32ParentProcessID",wintypes.DWORD),("pcPriClassBase",wintypes.LONG),
                            ("dwFlags",wintypes.DWORD),("szExeFile",wintypes.WCHAR*260)]
                    kernel.CreateToolhelp32Snapshot.argtypes=[wintypes.DWORD,wintypes.DWORD]
                    kernel.CreateToolhelp32Snapshot.restype=wintypes.HANDLE
                    for name in ("Process32FirstW","Process32NextW"):
                        method=getattr(kernel,name)
                        method.argtypes=[wintypes.HANDLE,ctypes.POINTER(ProcessEntry)]
                        method.restype=wintypes.BOOL
                    snapshot=kernel.CreateToolhelp32Snapshot(2,0)
                    assert snapshot not in (None,ctypes.c_void_p(-1).value), "process snapshot unavailable"
                    parent_pid=None
                    try:
                        entry=ProcessEntry();entry.dwSize=ctypes.sizeof(entry)
                        available=kernel.Process32FirstW(snapshot,ctypes.byref(entry))
                        for _ in range(65536):
                            if not available:
                                break
                            if entry.th32ProcessID==current["pid"]:
                                parent_pid=entry.th32ParentProcessID
                                break
                            available=kernel.Process32NextW(snapshot,ctypes.byref(entry))
                    finally:
                        kernel.CloseHandle(snapshot)
                    assert parent_pid is not None, "owned child absent from process snapshot"
                    assert parent_pid != current["pid"]
                    parent,parent_birth=checked_process(parent_pid)
                    assert parent_birth <= child_birth, "supervisor PID was reused after the owned child started"
                    yield {"kernel":kernel,"parent":parent,"child":child,"parent_pid":parent_pid,"child_pid":current["pid"],"parent_birth":parent_birth,"child_birth":child_birth,"data_dir":current["data_dir"],"store_ready":current.get("store_ready",False)}
                finally:
                    for handle in handles:
                        kernel.CloseHandle(handle)

            def require_pair_exited(pair):
                assert pair["kernel"].WaitForSingleObject(pair["child"],15000)==0, "owned runtime child survived its lifecycle owner"
                assert pair["kernel"].WaitForSingleObject(pair["parent"],15000)==0, "owned supervisor remained alive after stop"

            def require_replacement_pair(old, expected_profile):
                require_pair_exited(old)
                with owned_windows_pair(root) as fresh:
                    assert (fresh["child_pid"],fresh["child_birth"])!=(old["child_pid"],old["child_birth"])
                    assert (fresh["parent_pid"],fresh["parent_birth"])!=(old["parent_pid"],old["parent_birth"])
                    assert Path(fresh["data_dir"]).resolve()==expected_profile.resolve() and fresh["store_ready"]

            def diagnose_crash_restart():
                # Only this hosted fixture's fixed-field lifecycle state and
                # numeric scheduler policy/result. Never export XML or errors.
                directory=root/"runtime/autostart"
                counts={}
                for event_file in [directory/"events.jsonl",directory/"events.previous.jsonl"]:
                    if event_file.is_file() and event_file.stat().st_size <= 65536:
                        for line in event_file.read_text().splitlines():
                            event=json.loads(line).get("event")
                            if event in {"starting","paused","crash_limit","exit_ok","exit_error"}:
                                counts[event]=counts.get(event,0)+1
                print("isolated crash lifecycle diagnostic",json.dumps({"events":counts,"maintenance":(directory/"maintenance.json").exists()}))
                if os.name != "nt":
                    return
                import base64
                import re
                identity=json.loads((directory/"registration.json").read_text())["id"]
                assert re.fullmatch("[0-9a-f]{24}",identity)
                script="""$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);
$s=[Activator]::CreateInstance([Type]::GetTypeFromProgID('Schedule.Service'));$s.Connect();$t=$s.GetFolder('\\').GetTask('Respire-runtime-IDENTITY');$settings=$t.Definition.Settings;
[Console]::Out.WriteLine('state='+[int]$t.State);[Console]::Out.WriteLine('last_result='+[long]$t.LastTaskResult);
[Console]::Out.WriteLine('restart_count='+[int]$settings.RestartCount);$seconds=-1;try{$seconds=[int][Xml.XmlConvert]::ToTimeSpan($settings.RestartInterval).TotalSeconds}catch{};[Console]::Out.WriteLine('restart_seconds='+$seconds);
[Console]::Out.WriteLine('multiple_instances='+[int]$settings.MultipleInstances);[Console]::Out.WriteLine('enabled='+[int][bool]$t.Enabled);
[Console]::Out.WriteLine('instances='+[int]$t.GetInstances(0).Count);
""".replace("IDENTITY",identity)
                executable=Path(env["SystemRoot"])/"System32/WindowsPowerShell/v1.0/powershell.exe"
                try:
                    result=subprocess.run([str(executable),"-NoProfile","-NonInteractive","-EncodedCommand",base64.b64encode(script.encode("utf-16le")).decode("ascii")],env=env,capture_output=True,text=True,timeout=20)
                    fields={}
                    for line in result.stdout.splitlines():
                        match=re.fullmatch("(state|last_result|restart_count|restart_seconds|multiple_instances|enabled|instances)=(-?[0-9]{1,20})",line)
                        if match:
                            fields[match[1]]=int(match[2])
                    print("isolated scheduler crash diagnostic",json.dumps({"query_exit":result.returncode,"fields":fields}))
                except (OSError,subprocess.TimeoutExpired):
                    print("isolated scheduler crash diagnostic",json.dumps({"available":False}))

            def diagnose_registration():
                import hashlib
                import platform
                if os.name != "posix":
                    return
                identity = hashlib.sha256(f"respire-runtime-v1\0{root.resolve()}\0{os.getuid()}".encode()).hexdigest()[:24]
                system = platform.system()
                if system == "Linux":
                    name = f"respire-runtime-{identity}.service"
                    output = subprocess.run(["/usr/bin/systemctl", "--user", "show", name,
                        "--property=LoadState,FragmentPath,DropInPaths,UnitFileState"], env=env,
                        capture_output=True, text=True, timeout=15)
                    print("isolated systemd path diagnostic", json.dumps({"expected":str(home.resolve()/".config/systemd/user"/name),"properties":output.stdout[:8192]}))
                elif system == "Darwin":
                    label = f"ai.risense.respire.runtime.{identity}"
                    output = subprocess.run(["/bin/launchctl", "print-disabled", f"gui/{os.getuid()}"],
                        env=env, capture_output=True, text=True, timeout=15)
                    matching = [line.strip() for line in output.stdout.splitlines() if line.strip().startswith(f'"{label}" => ')]
                    print("isolated launchd override diagnostic",json.dumps({"label":label,"entries":[line[:160] for line in matching]}))

            def run(*argv):
                result = command(*argv)
                if result.returncode != 0:
                    diagnose_registration()
                assert result.returncode == 0, f"{argv}: {result.stderr} {result.stdout}"
                value = json.loads(result.stdout)
                assert value["status"] == "ok", value
                return value["summary"]

            try:
                if args.previous_binary:
                    import hashlib
                    import shutil
                    previous=args.previous_binary.resolve(strict=True)
                    version=subprocess.run([str(previous),"--version"],env=env,capture_output=True,text=True,timeout=15)
                    assert version.returncode == 0 and "1.0.17-dev.6" in version.stdout, "unexpected previous native version"
                    upgrade_root=base/"previous-version-upgrade"
                    upgrade_env=dict(env,RSRS_DATA_DIR=str(upgrade_root),RSRS_BIN_DIR=str(upgrade_root/"bin"))
                    def upgrade_call(executable,*argv):
                        return subprocess.run([str(executable),"--json",*argv],env=upgrade_env,capture_output=True,text=True,timeout=45)
                    def require_upgrade(*argv):
                        result=upgrade_call(binary,*argv)
                        assert result.returncode == 0, f"upgrade {argv}: {result.stdout} {result.stderr}"
                        return json.loads(result.stdout)["summary"]
                    try:
                        old=upgrade_call(previous,"status")
                        assert old.returncode in (0,2), f"previous native startup failed: {old.stdout} {old.stderr}"
                        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health",timeout=5) as response:
                            old_health=json.load(response)
                        assert old_health["bin"] == "1.0.17-dev.6"
                        upgraded=require_upgrade("runtime","autostart","enable")
                        assert upgraded["enabled"] and upgraded["runtime"]["running"]
                        assert upgraded["runtime"]["version"] == health["bin"] and upgraded["runtime"]["pid"] != old_health["pid"]
                        stable=upgrade_root/"bin"/("rsrs.exe" if os.name=="nt" else "rsrs")
                        fingerprint=hashlib.sha256(stable.read_bytes()).digest()
                        legacy=upgrade_call(previous,"status")
                        # A compatible old client may remain read-only; it must
                        # never replace or restart the live supervised owner.
                        still=require_upgrade("runtime","status")
                        assert still["runtime"]["pid"] == upgraded["runtime"]["pid"] and hashlib.sha256(stable.read_bytes()).digest() == fingerprint
                        if os.name == "nt":
                            with owned_windows_pair(upgrade_root) as pair:
                                require_upgrade("runtime","autostart","disable","--stop")
                                require_pair_exited(pair)
                        else:
                            require_upgrade("runtime","autostart","disable","--stop")
                        # Restore only known public previous-version native
                        # files while stopped. Do not run old code against the
                        # now-upgraded database; the next start is the new CLI.
                        for source in previous.parent.rglob("*"):
                            assert not source.is_symlink(), "previous native package has a symlink"
                            destination=upgrade_root/"bin"/source.relative_to(previous.parent)
                            if source.is_dir():
                                destination.mkdir(parents=True,exist_ok=True)
                            else:
                                assert source.is_file() and not destination.is_symlink()
                                destination.parent.mkdir(parents=True,exist_ok=True)
                                shutil.copy2(source,destination)
                        require_upgrade("runtime","start")
                        disabled_upgrade=require_upgrade("runtime","status")
                        assert disabled_upgrade["enabled"] is False and disabled_upgrade["runtime"]["version"] == health["bin"]
                        require_upgrade("runtime","stop")
                        print("PASS: actual DEV.6 handoff, live legacy-client no-replacement, and disabled-state preservation across native upgrade")
                    finally:
                        stopped=upgrade_call(binary,"runtime","stop")
                        removed=upgrade_call(binary,"runtime","autostart","remove","--stop")
                        assert stopped.returncode == 0 and removed.returncode == 0, f"previous-version fixture cleanup failed: stop={stopped.stdout} {stopped.stderr}; remove={removed.stdout} {removed.stderr}"

                failure_root=base/"failed-installation"
                blocked=base/"blocked-native-directory"
                blocked.write_text("synthetic file, not a directory")
                failure_env=dict(env,RSRS_DATA_DIR=str(failure_root),RSRS_BIN_DIR=str(blocked))
                failed=subprocess.run([binary,"--json","runtime","autostart","enable"],env=failure_env,capture_output=True,text=True,timeout=45)
                assert failed.returncode != 0 and (failure_root/"runtime/autostart/maintenance.json").exists(), "failure fixture did not reach persisted maintenance"
                cleaned=subprocess.run([binary,"--json","runtime","autostart","remove","--stop"],env=failure_env,capture_output=True,text=True,timeout=45)
                assert cleaned.returncode == 0 and not (failure_root/"runtime/autostart/maintenance.json").exists(), f"explicit failed-install cleanup did not recover: {cleaned.stdout} {cleaned.stderr}"
                print("PASS: failed native installation retains a fence and explicit remove --stop safely clears it")
                enabled = run("runtime", "autostart", "enable")
                assert enabled["enabled"] is True and enabled["registered"] is True, enabled
                assert enabled["runtime"]["running"] is False, "enable without --now unexpectedly starts runtime"
                run("runtime", "autostart", "enable")  # idempotent, same installation
                run("runtime", "start")
                up = run("runtime", "status")
                assert up["runtime"]["running"] is True and up["runtime"]["store_ready"] is True, up
                first_pid = up["runtime"]["pid"]
                config_path = root / "runtime/autostart/registration.json"
                # Observe the managed child's captured opt-out through the
                # existing client-only RPC, with the caller deliberately set
                # to the opposite value. No sync or network write is requested.
                config_reply=subprocess.run([binary,"--json","--client-only","config"],
                    env=dict(env,RSRS_NO_AUTOSYNC="0"),capture_output=True,text=True,timeout=45)
                assert config_reply.returncode == 0, f"managed config query failed: {config_reply.stdout} {config_reply.stderr}"
                assert json.loads(config_reply.stdout)["summary"]["autosync"] is False, "managed runtime lost explicit no-autosync opt-out"
                print("PASS: managed child retains no-autosync opt-out independently of caller environment")
                unchanged_config = config_path.read_bytes()
                with socket.socket() as other_socket:
                    other_socket.bind(("127.0.0.1",0))
                    other_port = other_socket.getsockname()[1]
                wrong_endpoint = subprocess.run([binary,"--json","runtime","stop"],
                    env=dict(env,RSRS_RPC_PORT=str(other_port)),capture_output=True,text=True,timeout=45)
                assert wrong_endpoint.returncode != 0 and config_path.read_bytes() == unchanged_config
                assert run("runtime","status")["runtime"]["pid"] == first_pid, "wrong-port stop changed the owned process"
                if os.name == "posix" and os.uname().sysname == "Linux":
                    assert Path(f"/proc/{first_pid}/cwd").resolve() == root.resolve(), "supervised process has the wrong actual working directory"
                # Deliberate SIGKILL/TerminateProcess does not flush LLVM
                # counters; run this fault in the dedicated uninstrumented
                # three-platform job, while coverage keeps graceful profiles.
                if not os.environ.get("LLVM_PROFILE_FILE"):
                    # Kill only the fixture's just-verified managed owner. Observe
                    # HTTP readiness directly afterwards: invoking runtime start or
                    # another auto-starting CLI command would hide a broken OS
                    # restart policy. No user registration/data is involved.
                    import signal
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health",timeout=5) as response:
                        owned_health=json.load(response)
                    assert owned_health["pid"] == first_pid and Path(owned_health["installation_root"]).resolve() == root.resolve()
                    assert owned_health["managed_id"] == json.loads(config_path.read_text())["id"]
                    failed_owner=owned_windows_pair(root) if os.name=="nt" else nullcontext(None)
                    with failed_owner as pair:
                        if pair is not None:
                            assert pair["child_pid"]==first_pid
                            supervisor_before=(pair["parent_pid"],pair["parent_birth"])
                            assert pair["kernel"].TerminateProcess(pair["child"],1), "failed to inject owned child failure"
                            assert pair["kernel"].WaitForSingleObject(pair["child"],15000)==0
                        else:
                            os.kill(first_pid,signal.SIGKILL)
                        restart_deadline=time.monotonic()+140
                        recovered_health=None
                        while time.monotonic() < restart_deadline:
                            try:
                                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health",timeout=1) as response:
                                    candidate=json.load(response)
                                if candidate["pid"] != first_pid and candidate.get("store_ready"):
                                    recovered_health=candidate
                                    break
                            except (OSError,ValueError):
                                pass
                            time.sleep(0.25)
                        if recovered_health is None:
                            diagnose_crash_restart()
                        assert recovered_health is not None, "OS supervisor did not restart its failed native owner"
                        assert recovered_health["managed_id"] == owned_health["managed_id"] and recovered_health["bin"] == health["bin"]
                        assert Path(recovered_health["installation_root"]).resolve() == root.resolve()
                        first_pid=recovered_health["pid"]
                        print("PASS: actual abnormal process exit followed by supervised store-ready restart, without a CLI start request")
                        if pair is not None:
                            with owned_windows_pair(root) as fresh:
                                assert fresh["child_pid"]==recovered_health["pid"] and fresh["child_birth"]!=pair["child_birth"]
                                assert (fresh["parent_pid"],fresh["parent_birth"])==supervisor_before
                                assert fresh["store_ready"] and Path(fresh["data_dir"]).resolve()==root.resolve()
                    if os.name == "nt":
                        with owned_windows_pair(root) as pair:
                            assert (pair["parent_pid"],pair["parent_birth"])==supervisor_before, "child recovery unexpectedly replaced its supervisor"
                            assert pair["kernel"].TerminateProcess(pair["parent"],1), "failed to inject owned supervisor failure"
                            require_pair_exited(pair)
                        # This proves job-bound cleanup, not automatic parent
                        # recovery. Explicit host restart establishes a new pair.
                        run("runtime","restart")
                        with owned_windows_pair(root) as pair:
                            assert pair["parent_birth"]!=supervisor_before[1]
                            first_pid=pair["child_pid"]
                        print("PASS: actual supervisor kill removes its owned child; explicit restart verifies a new store-ready pair without an orphan")
                # Keep the exited Windows process objects referenced until the
                # replacement exists. Otherwise a legitimate numeric PID reuse
                # can invalidate a PID-only comparison after handles are closed.
                stopped_owner=owned_windows_pair(root) if os.name=="nt" else nullcontext(None)
                with stopped_owner as pair:
                    if pair is not None:
                        first_pid=pair["child_pid"]
                    run("runtime", "stop")
                    if pair is not None:
                        require_pair_exited(pair)
                    time.sleep(1)
                    stopped = run("runtime", "status")
                    assert stopped["runtime"]["running"] is False, "manual stop was automatically resurrected"
                    run("runtime", "restart")
                    restarted = run("runtime", "status")
                    assert restarted["runtime"]["running"] and restarted["runtime"]["pid"] != first_pid, restarted
                    if pair is not None:
                        with owned_windows_pair(root) as replacement:
                            assert replacement["child_pid"]==restarted["runtime"]["pid"]
                            assert replacement["child_birth"]!=pair["child_birth"] and replacement["parent_birth"]!=pair["parent_birth"], "restart reused the old process instances"
                secondary = root / "accounts/secondary profile"
                secondary.mkdir(parents=True)
                if os.name == "nt":
                    with owned_windows_pair(root) as pair:
                        run("config", "--data-dir", str(secondary))
                        require_replacement_pair(pair,secondary)
                else:
                    run("config", "--data-dir", str(secondary))
                switched = run("runtime", "status")
                assert Path(switched["runtime"]["data_dir"]).resolve() == secondary.resolve(), switched
                assert switched["runtime"]["pid"] != restarted["runtime"]["pid"]
                if os.name=="nt":
                    with owned_windows_pair(root) as pair:
                        run("config", "--data-dir", str(root))
                        require_replacement_pair(pair,root)
                else:
                    run("config", "--data-dir", str(root))
                restored = run("runtime", "status")
                assert Path(restored["runtime"]["data_dir"]).resolve() == root.resolve(), restored
                assert restored["runtime"]["pid"] != switched["runtime"]["pid"]
                print("PASS: supervised synthetic profile switch and return, with verified new owner processes")

                # Persisted interrupted-controller fixtures are exercised by the
                # actual CLI and OS supervisor. This is process recovery from
                # recorded states, not a physical power-loss experiment.
                import uuid
                registration = root / "runtime/autostart/registration.json"
                marker = registration.with_name("maintenance.json")
                for phase in ("Paused", "Starting", "Verified"):
                    if phase != "Starting":
                        run("runtime", "stop")
                    config = json.loads(registration.read_text())
                    stopped_flag = config["manually_stopped"]
                    config["maintenance"] = True
                    registration.write_text(json.dumps(config))
                    value = {"schema":1,"id":config["id"],"token":str(uuid.uuid4()),"phase":phase,
                        "expected_profile":str(root.resolve()),"expected_version":restarted["runtime"]["version"],
                        "owner_pid":os.getpid(),"owner_birth":"synthetic-expired-controller"}
                    with os.fdopen(os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),"w") as pending:
                        json.dump(value,pending)
                        pending.flush()
                        os.fsync(pending.fileno())
                    database = root / "rsrs.db"
                    before = database.read_bytes()
                    modified = database.stat().st_mtime_ns
                    denied_start = command("runtime", "start")
                    assert denied_start.returncode != 0 and marker.exists()
                    assert json.loads(registration.read_text())["manually_stopped"] == stopped_flag
                    denied_read = command("--direct", "memory-revision")
                    assert denied_read.returncode != 0 and marker.exists()
                    if phase == "Starting":
                        for method in ("model.prepare", "index.prepare"):
                            request = urllib.request.Request(f"http://127.0.0.1:{port}/api/rpc",
                                data=json.dumps({"v":1,"id":str(uuid.uuid4()),"method":method,"args":[]}).encode(),
                                headers={"Content-Type":"application/json"})
                            with urllib.request.urlopen(request,timeout=5) as response:
                                reply=json.load(response)
                            assert reply["ok"] is False and reply["code"] == "runtime_maintenance", reply
                    assert database.read_bytes() == before and database.stat().st_mtime_ns == modified
                    run("runtime", "restart")
                    if phase == "Starting":
                        assert read_restart_stages()[-3:] == ["restart_probe","restart_managed","restart_ready"], "live managed recovery did not follow the verified coordinator"
                    recovered = run("runtime", "status")
                    assert recovered["runtime"]["running"] and recovered["runtime"]["store_ready"]
                    assert not marker.exists() and not json.loads(registration.read_text())["maintenance"]
                    print(f"PASS: native persisted {phase} recovery; direct reads/preparation fenced; manual-stop intent retained until explicit restart")

                # Managed off-mode uses process/profile readiness, not a store
                # that this mode intentionally never opens.
                run("runtime", "stop")
                client = root / "client.json"
                previous_client = client.read_bytes() if client.exists() else None
                settings = json.loads(previous_client) if previous_client else {}
                database = root / "rsrs.db"
                before_database = database.read_bytes()
                before_modified = database.stat().st_mtime_ns
                settings["service_mode"] = "off"
                client.write_text(json.dumps(settings))
                run("runtime", "restart")
                off_status = run("runtime", "status")
                assert off_status["runtime"]["running"] and off_status["runtime"]["store_ready"] is False, off_status
                assert database.read_bytes() == before_database and database.stat().st_mtime_ns == before_modified
                run("runtime", "stop")
                if previous_client is None:
                    client.unlink()
                else:
                    client.write_bytes(previous_client)
                run("runtime", "restart")
                assert run("runtime", "status")["runtime"]["store_ready"] is True
                run("runtime", "autostart", "disable", "--stop")
                disabled = run("runtime", "status")
                assert disabled["enabled"] is False and disabled["runtime"]["running"] is False, disabled
                run("runtime", "autostart", "enable", "--now")
                assert run("runtime", "status")["runtime"]["running"] is True
                preserved = root / "synthetic-preserved-file"
                preserved.write_text("must survive uninstall")
                run("runtime", "autostart", "remove", "--stop")
                removed = run("runtime", "status")
                assert not removed["registered"] and not removed["enabled"] and not removed["runtime"]["running"], removed
                assert preserved.read_text() == "must survive uninstall"
                print("PASS: actual current-user register/readback/start/stop/restart/disable/reenable/remove; data retained")
            finally:
                # The CLI revalidates exact owner/action/files before cleanup;
                # never delete unknown OS tasks/units merely to make a test pass.
                cleanup = command("runtime", "autostart", "remove", "--stop")
                assert cleanup.returncode == 0, f"Owned registration cleanup failed: {cleanup.stderr} {cleanup.stdout}"
                collect_managed_profiles()



if __name__ == "__main__":
    main()
