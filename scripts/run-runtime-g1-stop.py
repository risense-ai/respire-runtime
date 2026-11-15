"""Cross-platform stop driver; reuse frozen preparation and original assertions.

The unchanged memory runner also executes its two preparation checks. Product
output stays private. Only validated scalar observations leave the runner.
"""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from types import SimpleNamespace


CASE = "diary_identity::native_stop_waits_and_explicit_force_reaps_real_core_without_replay"
MODES = ("standalone", "registered", "client2-owned")
ACCEPTED_WRITE_CHECKPOINTS = {
    f"NATIVE_ACCEPTED_WRITE_CHECKPOINT stage={stage}".encode(): stage
    for stage in ("fixture_requested", "fixture_ready", "seed_ready", "runtime_ready",
                  "provider_received", "identity_bound", "stop_accepted", "provider_released",
                  "business_completed", "runtime_stopped", "write_verified")
}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def passed_case(captured):
    text = captured.decode()
    assert len(re.findall(r"^test " + re.escape(CASE) + r" \.\.\. ok\s*$", text, re.M)) == 1
    assert re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", text), "Missing real stop coverage"


def accepted_write_checkpoints(captured):
    lines = [line.removesuffix(b"\r") for line in captured.split(b"\n")[:-1]]
    if f"test {CASE} ... FAILED".encode() not in lines:
        return []
    return [ACCEPTED_WRITE_CHECKPOINTS[line] for line in lines if line in ACCEPTED_WRITE_CHECKPOINTS]


FINISH_STAGES = {"wait_requested", "exit_observed", "exit_verified", "receipt_read", "receipt_parsed",
                 "receipt_verified", "listener_verified", "lock_verified"}
LISTENER_ERROR_KINDS = {
    "NotFound", "PermissionDenied", "ConnectionRefused", "ConnectionReset", "HostUnreachable",
    "NetworkUnreachable", "ConnectionAborted", "NotConnected", "AddrInUse", "AddrNotAvailable",
    "NetworkDown", "BrokenPipe", "AlreadyExists", "WouldBlock", "NotADirectory", "IsADirectory",
    "DirectoryNotEmpty", "ReadOnlyFilesystem", "FilesystemLoop", "StaleNetworkFileHandle", "InvalidInput",
    "InvalidData", "TimedOut", "WriteZero", "StorageFull", "NotSeekable", "QuotaExceeded", "FileTooLarge",
    "ResourceBusy", "ExecutableFileBusy", "Deadlock", "CrossesDevices", "TooManyLinks", "InvalidFilename",
    "ArgumentListTooLong", "Interrupted", "Unsupported", "UnexpectedEof", "OutOfMemory", "InProgress",
    "Other", "Uncategorized",
}
RESTART_EVENTS = {"restart_probe", "restart_managed", "restart_identity", "restart_stop", "restart_start",
                  "restart_ready", "event_file_missing", "event_file_unreadable", "event_file_invalid", "no_restart_event"}
TIMING_STAGES = {"start", "caller_wait_complete", "receipt_verified", "quiet_period_verified",
                 "recovery_requested", "recovery_started", "recovery_stopped", "complete"}
RESTART_ERRORS = {
    "runtime restart blocked: owner health is unavailable": "owner_health_unavailable",
    "runtime restart blocked: stale owner could not be verified": "stale_owner_unverified",
    "runtime maintenance is incomplete": "maintenance_incomplete",
    "maintenance owner changed": "maintenance_owner_changed",
    "unknown existing startup registration": "registration_unknown",
    "systemd user session unavailable": "systemd_unavailable",
    "owned autostart registration is missing": "registration_missing",
    "host runtime exited before readiness": "runtime_exited_before_ready",
    "host runtime did not become ready": "runtime_not_ready",
}


def stop_failure_diagnostics(captured):
    lines = [line.removesuffix(b"\r") for line in captured.split(b"\n")[:-1]]
    if f"test {CASE} ... FAILED".encode() not in lines:
        return {}
    finish, restart, timings, exits, listener_failures = [], [], [], [], []
    listener_failure_invalid = False
    for line in lines:
        if line.startswith(b"NATIVE_STOP_LISTENER_FAILURE "):
            connected = re.fullmatch(rb"NATIVE_STOP_LISTENER_FAILURE outcome=connected probe_elapsed_ms=([0-9]{1,12})", line)
            error = re.fullmatch(rb"NATIVE_STOP_LISTENER_FAILURE outcome=error kind=([A-Za-z]{1,32}) os_error=(None|Some\((-?[0-9]{1,10})\)) probe_elapsed_ms=([0-9]{1,12})", line)
            if connected:
                listener_failures.append({"outcome": "connected", "probe_elapsed_ms": int(connected[1])})
            elif error and error[1].decode() in LISTENER_ERROR_KINDS:
                os_error = int(error[3]) if error[3] is not None else None
                if os_error is None or -(2 ** 31) <= os_error < 2 ** 31:
                    listener_failures.append({"outcome": "error", "kind": error[1].decode(),
                                              "os_error": os_error, "probe_elapsed_ms": int(error[4])})
                else:
                    listener_failure_invalid = True
            else:
                listener_failure_invalid = True
        match = re.fullmatch(rb"NATIVE_STOP_FINISH_CHECKPOINT stage=([a-z_]+) elapsed_ms=([0-9]{1,12})", line)
        if match and match[1].decode() in FINISH_STAGES:
            finish.append({"stage": match[1].decode(), "elapsed_ms": int(match[2])})
        match = re.fullmatch(rb"REGISTERED_RESTART_EVENT stage=([a-z_]+)", line)
        if match and match[1].decode() in RESTART_EVENTS:
            restart.append(match[1].decode())
        match = re.fullmatch(rb"OWNED_STOP_TIMING case=(normal|caller-timeout|explicit-force) stage=([a-z_]+) elapsed_ms=([0-9]{1,12})", line)
        if match and match[2].decode() in TIMING_STAGES:
            timings.append({"case": match[1].decode(), "stage": match[2].decode(), "elapsed_ms": int(match[3])})
        match = re.fullmatch(rb"REGISTERED_LIFECYCLE_EXIT code=([0-9]{1,3})", line)
        if match and int(match[1]) <= 255:
            exits.append(int(match[1]))
    result = {"finish_checkpoints": finish, "registered_restart_events": restart,
              "owned_case_timings": timings, "registered_lifecycle_exit_codes": exits,
              "listener_failures": listener_failures, "listener_failure_invalid": listener_failure_invalid}
    accepted = accepted_write_checkpoints(captured)
    if finish and "business_completed" in accepted and "runtime_stopped" not in accepted:
        result["finish_error_category"] = (
            "exit_timeout" if b"Runtime did not finish native stop" in captured else
            "assertion" if b"panicked at" in captured else
            "returned_error" if any(line.startswith(b"Error: ") for line in lines) else "unclassified")
    if restart:
        private = re.search(rb"REGISTERED_LIFECYCLE_PRIVATE_STDOUT\r?\n(.*?)\r?\nREGISTERED_LIFECYCLE_PRIVATE_STDERR\r?\n",
                            captured, re.S)
        if not private:
            categories = ["private_output_missing"]
        else:
            try:
                envelope = json.loads(private[1])
            except UnicodeDecodeError:
                categories = ["invalid_encoding"]
            except RecursionError:
                categories = ["nesting_limit"]
            except ValueError:
                categories = ["invalid_json"]
            else:
                errors = envelope.get("errors") if isinstance(envelope, dict) else None
                if not isinstance(errors, list) or not all(isinstance(error, str) for error in errors):
                    categories = ["invalid_envelope"]
                else:
                    categories = [name for text, name in RESTART_ERRORS.items()
                                  if any(text in error for error in errors)] or ["unclassified"]
        result["registered_restart_error_categories"] = categories
    return result


def environment(root, request):
    env = {key: value for key, value in os.environ.items() if key.upper() in (
        "PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "RUNNER_TEMP", "GITHUB_ACTIONS",
        "RUNNER_ENVIRONMENT", "GITHUB_SHA", "GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")}
    suffix = ".exe" if sys.platform == "win32" else ""
    metadata = json.loads(Path(request["runtime_metadata"]).read_bytes())
    env.update(HOME=str(root / "home"), USERPROFILE=str(root / "home"),
               APPDATA=str(root / "config"), LOCALAPPDATA=str(root / "data"),
               XDG_CONFIG_HOME=str(root / "config"), XDG_DATA_HOME=str(root / "data"),
               XDG_CACHE_HOME=str(root / "cache"), XDG_RUNTIME_DIR=str(root / "runtime"),
               TMPDIR=str(root / "tmp"), TEMP=str(root / "tmp"), TMP=str(root / "tmp"),
               RSRS_DATA_DIR=str(root / "installation"), RSRS_M3_DIR=str(root / "model"),
               RSRS_CLI_BIN=str(root / "cli" / Path(request["cli"]).name),
               RSRS_CLI_SOURCE_DIR=str(Path(".cli-source").resolve()), RSRS_CLI_SOURCE_SHA=request["cli_source_sha"],
               RSRS_RUNTIME_BIN=str(root / "installation/bin/runtime" / metadata["runtime_version"] / ("rsrs-runtime" + suffix)),
               RSRS_RUNTIME_SOURCE_SHA=request["source_sha"], RSRS_RUNTIME_CANDIDATE_METADATA=request["runtime_metadata"],
               RSRS_CORE_TEST_MODEL_DIR=str(root / "model"), RSRS_CORE_TEST_MODE="1", RSRS_ENGINE="cpu",
               RSRS_NO_AUTOSYNC="1", RSRS_UPDATE_CHECK="0", RUST_MIN_STACK="16777216", RUST_TEST_THREADS="1")
    return env


def failure_record(request, state, error):
    stage = state["stage"]
    diagnostics = dict(state.get("diagnostics", {}))
    if "timings_ms" in state:
        diagnostics["elapsed_ms"] = dict(state["timings_ms"])
    if stage == "preparation" and isinstance(error, subprocess.CalledProcessError):
        command = error.cmd if isinstance(error.cmd, (list, tuple)) else []
        if command[1:4] == ["--json", "runtime", "install"]:
            stage = "preparation_runtime_install"
        elif command[1:4] == ["--json", "model", "install-m3"]:
            stage = "preparation_model_install"
        elif command and command[0] == request["harness"]:
            stage = "preparation_harness"
    if (request["target"] == "x86_64-apple-darwin" and isinstance(error, subprocess.CalledProcessError)
            and error.cmd == [request["harness"], "--list"] and error.returncode == -6):
        try:
            private_log = (Path(request["root"]) / "private.log").read_bytes()
        except OSError:
            diagnostics["log_markers"] = ["unreadable"]
        else:
            markers = {
                "dyld_library_not_loaded": b"Library not loaded:",
                "dyld_symbol_not_found": b"Symbol not found:",
                "libcxx_uncaught_exception": b"libc++abi: terminating due to uncaught exception",
                "assertion_failed": b"Assertion failed:",
            }
            diagnostics["log_markers"] = [name for name, text in markers.items() if text in private_log] or ["unclassified"]
    return {"schema": 1, "passed": False, "stage": stage, "mode": state["mode"],
            "target": request["target"],
            "error_type": "subprocess_exit" if isinstance(error, subprocess.CalledProcessError) else
                          "assertion" if isinstance(error, AssertionError) else
                          "os_error" if isinstance(error, OSError) else "unexpected_error",
            "exit_code": error.returncode if isinstance(error, subprocess.CalledProcessError) else state.get("subprocess_exit_code"),
            "diagnostics": diagnostics}


def execute(request):
    state = {"stage": "preparation", "mode": None, "timings_ms": {}}
    started = time.monotonic()
    try:
        return execute_stages(request, state)
    except Exception as error:
        state["timings_ms"]["total"] = round((time.monotonic() - started) * 1000)
        # Only fixed stages and the original allowlist parser's result are public.
        output = Path("g1-stop-raw")
        output.mkdir(exist_ok=True)
        with (output / "failure.json").open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(failure_record(request, state, error), stream, indent=2)
            stream.write("\n")
        raise


def execute_stages(request, state):
    memory = load("g1_stop_frozen_preparation", Path(__file__).with_name("run-runtime-g1-memory.py"))
    started = time.monotonic()
    try:
        prepared = memory.execute(request)
    finally:
        state["timings_ms"]["preparation"] = round((time.monotonic() - started) * 1000)
    assert prepared["passed"] and prepared["offline_installer_verified"] and prepared["model_sha256"] == memory.MODEL_HASHES
    state["stage"] = "stop_source_binding"
    root = Path(request["root"])
    original = load("g1_stop_original_assertions", Path(".cli-source/scripts/native-account-candidate.py"))
    assert original.CLIENT2_OWNED_SOURCE_SHA == request["client2_source_sha"]
    env = environment(root, request)
    result = {"schema": 1, "passed": False, "test_executed": False, "release_acceptance": False,
              "offline_installer_verified": True, "target": request["target"], "identity": request,
              "model_sha256": memory.MODEL_HASHES, "prepared_memory": prepared, "modes": {}}
    with (root / "stop-private.log").open("wb") as log:
        for mode in MODES:
            state.update(stage="mode_preparation", mode=mode)
            mode_root = root / ("stop-" + mode)
            mode_root.mkdir()
            mode_env = dict(env)
            binding = None
            if mode != "standalone":
                state["stage"] = "probe_build"
                args = SimpleNamespace(suite="g1-owned-stop", owned_stop_mode=mode,
                    client2_source=Path(".client2-source"), cli_source=Path(".cli-source"),
                    cli_sha=request["cli_source_sha"], runtime_sha=request["source_sha"],
                    runtime_archive=Path(request["runtime_archive"]), runtime_metadata=Path(request["runtime_metadata"]),
                    official_cli_metadata=None, legacy_stable_contracts=False, stable_business_cli=None,
                    stable_business_cli_metadata=None, stable_business_runtime_archive=None, require_native_stop=False)
                started = time.monotonic()
                try:
                    probe, binding = original.build_owned_stop_probe(args, mode_root, log)
                finally:
                    state["timings_ms"]["probe_build_" + mode] = round((time.monotonic() - started) * 1000)
                mode_env.update(RSRS_TEST_NATIVE_OWNED_STOP=mode, RSRS_CLIENT2_PROBE_BIN=str(probe))
            command = [request["harness"], CASE, "--exact", "--test-threads=1", "--show-output"]
            manager = None
            credential = None
            try:
                state["stage"] = "credential_setup"
                if sys.platform == "linux" and mode != "standalone":
                    wrapper = [sys.executable, "-B", str(Path(".cli-source/scripts/dev-secret-service-keyring-selftest.py").resolve()),
                               "--root", str(mode_root / "credentials"), "--timeout", "6600"]
                    if mode == "registered":
                        command = [*wrapper, "--hosted-user-bus", "--", *command]
                    else:
                        command = ["dbus-run-session", "--", "env", "RSRS_SS_FIXTURE_BUS=private", *wrapper, "--", *command]
                elif mode != "standalone":
                    native = load("g1_stop_native_" + mode, Path(".cli-source/scripts/dev-migration-keyring-selftest.py"))
                    manager = native.backend.create(mode_root / "credentials")
                    mode_env = manager.configure_env(mode_env)
                    before = {}
                    native.roundtrips(manager, before)
                    assert len(before) == 8
                state["stage"] = "stop_harness"
                started = time.monotonic()
                try:
                    process = subprocess.run(command, env=mode_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                finally:
                    state["timings_ms"]["harness_" + mode] = round((time.monotonic() - started) * 1000)
                log.write(process.stdout)
                log.flush()
                if process.returncode != 0:
                    state["subprocess_exit_code"] = process.returncode
                    state["diagnostics"] = original.safe_failure_diagnostics(process.stdout, [CASE])
                    state["diagnostics"]["accepted_write_checkpoints"] = accepted_write_checkpoints(process.stdout)
                    state["diagnostics"].update(stop_failure_diagnostics(process.stdout))
                    raise subprocess.CalledProcessError(process.returncode, ["native-stop-harness"])
                state["stage"] = "stop_assertions"
                passed_case(process.stdout)
                standalone = original.standalone_stop_checks(process.stdout, request["runtime_binary_sha256"])
                assert standalone["passed"]
                observations = []
                if mode != "standalone":
                    assert memory.digest(probe) == binding["probe_binary_sha256"]
                    observations = original.owned_stop_checks(process.stdout, mode, binding["probe_binary_sha256"], request["runtime_binary_sha256"])
                    if sys.platform == "linux":
                        credential = json.loads((mode_root / "credentials/business-keyring-selftest.json").read_bytes())
                        assert credential["passed"] and credential["business_passed"] and credential["business_credential_cleanup_passed"]
                        assert credential["keyring_cleanup"]["passed"]
                    else:
                        state["stage"] = "credential_after"
                        after = {}
                        native.roundtrips(manager, after)
                        assert len(after) == 8
            finally:
                if manager is not None:
                    previous_stage = state["stage"]
                    state["stage"] = "credential_cleanup"
                    cleanup = manager.cleanup()
                    assert cleanup["passed"] and not cleanup["remaining_entries"], "Native credential cleanup failed"
                    state["stage"] = previous_stage
                    credential = {"passed": True, "credential_before_passed": True,
                                  "credential_after_passed": True, "keyring_cleanup": cleanup}
            result["modes"][mode] = {"passed": True, "standalone": standalone,
                "observations": observations, "source_binding": binding, "credential": credential}
        state.update(stage="final_identity", mode=None)
        for name, sha in memory.MODEL_HASHES.items():
            assert memory.digest(root / "model" / name) == sha
        assert memory.digest(Path(request["harness"])) == request["harness_sha256"]
        assert memory.digest(Path(env["RSRS_CLI_BIN"])) == request["cli_binary_sha256"]
        assert memory.digest(Path(env["RSRS_RUNTIME_BIN"])) == request["runtime_binary_sha256"]
    result.update(passed=True, test_executed=True)
    return result


if __name__ == "__main__":
    request = json.loads(Path(sys.argv[1]).read_bytes())
    result = execute(request)
    with Path(sys.argv[2]).open("x", encoding="utf-8", newline="\n") as output:
        json.dump(result, output, indent=2)
        output.write("\n")
