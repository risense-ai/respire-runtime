"""Pure refusal checks; no OS credentials or product process is created."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("stop_fixture", Path(__file__).with_name("run-runtime-g1-stop.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def refuses(text):
    try:
        fixture.passed_case(text)
    except AssertionError:
        return
    raise AssertionError("Invalid stop coverage was accepted")


text = (f"test {fixture.CASE} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 31 filtered out;\n").encode()
fixture.passed_case(text)
refuses(text.replace(b"0 ignored", b"1 ignored"))
refuses(text.replace(b"1 passed", b"0 passed"))
refuses(text.replace(fixture.CASE.encode(), b"other_case"))
refuses(text + f"test {fixture.CASE} ... ok\n".encode())
assert fixture.MODES == ("standalone", "registered", "client2-owned")
request = {"target": "aarch64-pc-windows-msvc", "harness": "private-canary-harness"}
state = {"stage": "preparation", "mode": None}
for command, expected in [
    (["private-canary-cli", "--json", "runtime", "install", "--file", "private-canary-path"], "preparation_runtime_install"),
    (["private-canary-cli", "--json", "model", "install-m3"], "preparation_model_install"),
    ([request["harness"], "--list"], "preparation_harness"),
]:
    error = subprocess.CalledProcessError(17, command, output=b"private-canary-secret")
    report = fixture.failure_record(request, state, error)
    assert report["stage"] == expected and report["exit_code"] == 17 and not report["passed"]
    assert "private-canary" not in json.dumps(report)
unknown = fixture.failure_record(request, state, RuntimeError("private-canary-secret"))
assert unknown["stage"] == "preparation" and unknown["error_type"] == "unexpected_error"
assert "private-canary" not in json.dumps(unknown)
cleanup = fixture.failure_record(request, {"stage": "credential_cleanup", "mode": "registered",
    "subprocess_exit_code": 29}, RuntimeError("private-canary-cleanup"))
assert cleanup["stage"] == "credential_cleanup" and cleanup["exit_code"] == 29
assert "private-canary" not in json.dumps(cleanup)

stages = ["fixture_requested", "fixture_ready", "seed_ready", "runtime_ready", "provider_received",
          "identity_bound", "stop_accepted", "provider_released", "business_completed",
          "runtime_stopped", "write_verified"]
failed = f"test {fixture.CASE} ... FAILED\r\n".encode()
captured = failed + b"".join(
    f"NATIVE_ACCEPTED_WRITE_CHECKPOINT stage={stage}\r\n".encode() for stage in stages
) + (b"NATIVE_ACCEPTED_WRITE_CHECKPOINT stage=private-canary-secret\n"
     b"NATIVE_ACCEPTED_WRITE_CHECKPOINT stage=fixture_ready private-canary-path\n"
     b"private-canary-prefix NATIVE_ACCEPTED_WRITE_CHECKPOINT stage=fixture_ready\n"
     b"NATIVE_ACCEPTED_WRITE_CHECKPOINT stage=fixture_ready")
assert fixture.accepted_write_checkpoints(captured) == stages
assert fixture.accepted_write_checkpoints(captured.replace(b" ... FAILED", b" ... ok")) == []
assert fixture.accepted_write_checkpoints(captured.replace(fixture.CASE.encode(), b"other_case")) == []

accepted_failure = failed + b"".join(
    f"NATIVE_ACCEPTED_WRITE_CHECKPOINT stage={stage}\n".encode() for stage in stages[:-2]
)
finish_failure = accepted_failure + (
    b"NATIVE_STOP_FINISH_CHECKPOINT stage=wait_requested elapsed_ms=0\r\n"
    b"NATIVE_STOP_FINISH_CHECKPOINT stage=exit_observed elapsed_ms=100\n"
    b"NATIVE_STOP_FINISH_CHECKPOINT stage=private_canary elapsed_ms=1\n"
    b"NATIVE_STOP_FINISH_CHECKPOINT stage=receipt_read elapsed_ms=1 private-canary-secret\n"
    b"thread 'test' panicked at private-canary-path\n"
)
diag = fixture.stop_failure_diagnostics(finish_failure)
assert diag["finish_checkpoints"] == [{"stage": "wait_requested", "elapsed_ms": 0},
                                      {"stage": "exit_observed", "elapsed_ms": 100}]
assert diag["finish_error_category"] == "assertion"
assert fixture.stop_failure_diagnostics(finish_failure.replace(b"thread 'test' panicked at", b"Error: Runtime did not finish native stop"))["finish_error_category"] == "exit_timeout"
assert fixture.stop_failure_diagnostics(finish_failure.replace(b"thread 'test' panicked at", b"Error:"))["finish_error_category"] == "returned_error"
assert fixture.stop_failure_diagnostics(finish_failure.replace(b"thread 'test' panicked at", b"unknown failure"))["finish_error_category"] == "unclassified"
assert fixture.stop_failure_diagnostics(finish_failure.replace(b" ... FAILED", b" ... ok")) == {}
assert "private-canary" not in json.dumps(diag)

for status in ([{"state": "not_loaded"}, {"state": "ready"}]
        + [{"state": "unavailable", "code": code} for code in (
            "access_denied", "platform_failure", "backend_unavailable", "invalid_configuration",
            "ambiguous", "bad_encoding")]):
    marker = b"NATIVE_STOP_PROVIDER_STATUS " + json.dumps(status, separators=(",", ":")).encode() + b"\r\n"
    observed = fixture.stop_failure_diagnostics(failed + marker)
    assert observed["provider_statuses"] == [status] and not observed["provider_status_invalid"]
    contaminated = fixture.stop_failure_diagnostics(failed + marker[:-2] + b" private-canary-secret\n"
        + b'NATIVE_STOP_PROVIDER_STATUS {"state":"unavailable","code":"private-canary-secret"}\n')
    assert contaminated["provider_statuses"] == [] and contaminated["provider_status_invalid"]
    assert "private-canary" not in json.dumps(contaminated)

for error, category in (
    ("systemctl current-user operation failed (exit 1)", "systemctl_failed"),
    ("launchctl current-user operation failed (exit 1)", "launchctl_failed"),
    ("Windows current-user operation failed (exit 1)", "windows_manager_failed"),
    ("host session credential read failed (BackendUnavailable)", "session_credential_read_failed"),
):
    startup_failure = (failed + b"REGISTERED_LIFECYCLE_EXIT code=1\n"
        + b"REGISTERED_LIFECYCLE_PRIVATE_STDOUT\n"
        + json.dumps({"errors": [error + ": private-canary-secret"]}).encode()
        + b"\nREGISTERED_LIFECYCLE_PRIVATE_STDERR\nprivate-canary-path\nREGISTERED_LIFECYCLE_PRIVATE_END\n")
    startup = fixture.stop_failure_diagnostics(startup_failure)
    assert startup["registered_lifecycle_exit_codes"] == [1]
    assert startup["registered_restart_events"] == []
    assert startup["registered_lifecycle_error_categories"] == [category]
    assert "registered_restart_error_categories" not in startup
    assert "private-canary" not in json.dumps(startup)

restart_failure = failed + (
    b"REGISTERED_LIFECYCLE_EXIT code=1\nREGISTERED_LIFECYCLE_EXIT code=999\n"
    b"REGISTERED_LIFECYCLE_PRIVATE_STDOUT\n"
    b'{"errors":["runtime restart blocked: stale owner could not be verified: private-canary-path"]}\n'
    b"REGISTERED_LIFECYCLE_PRIVATE_STDERR\nprivate-canary-secret\nREGISTERED_LIFECYCLE_PRIVATE_END\n"
    b"REGISTERED_RESTART_EVENT stage=restart_probe\nREGISTERED_RESTART_EVENT stage=restart_start\n"
    b"REGISTERED_RESTART_EVENT stage=private_canary\n"
    b"OWNED_STOP_TIMING case=explicit-force stage=recovery_requested elapsed_ms=12345\n"
    b"OWNED_STOP_TIMING case=private-canary stage=complete elapsed_ms=5\n"
    b"OWNED_STOP_TIMING case=normal stage=complete elapsed_ms=5 private-canary\n"
    b"REGISTERED_RESTART_EVENT stage=restart_ready"
)
diag = fixture.stop_failure_diagnostics(restart_failure)
assert diag["registered_restart_events"] == ["restart_probe", "restart_start"]
assert diag["registered_lifecycle_exit_codes"] == [1]
assert diag["registered_restart_error_categories"] == ["stale_owner_unverified"]
assert diag["registered_lifecycle_error_categories"] == diag["registered_restart_error_categories"]
assert diag["owned_case_timings"] == [{"case": "explicit-force", "stage": "recovery_requested", "elapsed_ms": 12345}]
assert "private-canary" not in json.dumps(diag)
invalid = fixture.stop_failure_diagnostics(restart_failure.replace(b'"errors":', b'"bad-json":invalid,'))
assert invalid["registered_restart_error_categories"] == ["invalid_json"]
invalid_encoding = fixture.stop_failure_diagnostics(restart_failure.replace(b"private-canary-path", b"\xff"))
assert invalid_encoding["registered_restart_error_categories"] == ["invalid_encoding"]
invalid_envelope = fixture.stop_failure_diagnostics(restart_failure.replace(b'"errors":[', b'"errors":{"data":[').replace(b'private-canary-path"]}', b'private-canary-path"]}}'))
assert invalid_envelope["registered_restart_error_categories"] == ["invalid_envelope"]
unclassified = fixture.stop_failure_diagnostics(restart_failure.replace(b"runtime restart blocked: stale owner could not be verified", b"unknown private-canary error"))
assert unclassified["registered_restart_error_categories"] == ["unclassified"]
missing = fixture.stop_failure_diagnostics(restart_failure.replace(b"REGISTERED_LIFECYCLE_PRIVATE_STDOUT", b"private-canary"))
assert missing["registered_restart_error_categories"] == ["private_output_missing"]
deep = (failed + b"REGISTERED_LIFECYCLE_PRIVATE_STDOUT\n" + b"[" * 2000 + b"]" * 2000
        + b"\nREGISTERED_LIFECYCLE_PRIVATE_STDERR\nREGISTERED_RESTART_EVENT stage=no_restart_event\n")
with patch.object(fixture.json, "loads", side_effect=RecursionError("private-canary")):
    nesting = fixture.stop_failure_diagnostics(deep)
assert nesting["registered_restart_error_categories"] == ["nesting_limit"]
assert "private-canary" not in json.dumps(nesting)
for report in (invalid, invalid_encoding, invalid_envelope, unclassified, missing):
    assert "private-canary" not in json.dumps(report)

previous = Path.cwd()
with tempfile.TemporaryDirectory(prefix="g1-stop-failure-check-") as directory:
    try:
        os.chdir(directory)
        error = subprocess.CalledProcessError(23, ["private-canary-command"])
        with patch.object(fixture, "execute_stages", side_effect=error):
            try:
                fixture.execute(request)
            except subprocess.CalledProcessError as actual:
                assert actual is error
            else:
                raise AssertionError("Stop failure was swallowed")
        raw = Path("g1-stop-raw")
        report = json.loads((raw / "failure.json").read_bytes())
        assert report["exit_code"] == 23 and report["stage"] == "preparation"
        assert not (raw / "stop.json").exists()
        assert "private-canary" not in json.dumps(report)

        mac_root = Path(directory) / "private-canary-root"
        mac_root.mkdir()
        mac_request = {"root": str(mac_root), "target": "x86_64-apple-darwin",
                       "harness": "private-canary-harness"}
        mac_error = subprocess.CalledProcessError(-6, [mac_request["harness"], "--list"],
                                                  output=b"private-canary-secret")
        private_log = mac_root / "private.log"
        for marker, text in [
            ("dyld_library_not_loaded", b"dyld: Library not loaded: /private-canary-path"),
            ("dyld_symbol_not_found", b"dyld: Symbol not found: private-canary-symbol"),
            ("libcxx_uncaught_exception", b"libc++abi: terminating due to uncaught exception private-canary"),
            ("assertion_failed", b"Assertion failed: private-canary-secret"),
        ]:
            private_log.write_bytes(text)
            report = fixture.failure_record(mac_request, state, mac_error)
            assert report["diagnostics"]["log_markers"] == [marker]
            assert report["exit_code"] == -6 and "private-canary" not in json.dumps(report)
        private_log.write_bytes(b"private-canary-path private-canary-secret")
        report = fixture.failure_record(mac_request, state, mac_error)
        assert report["diagnostics"]["log_markers"] == ["unclassified"]
        assert "private-canary" not in json.dumps(report)

        for other_request, other_error in [
            (dict(mac_request, target="aarch64-apple-darwin"), mac_error),
            (mac_request, subprocess.CalledProcessError(-5, mac_error.cmd)),
            (mac_request, subprocess.CalledProcessError(-6, ["other-harness", "--list"])),
            (mac_request, subprocess.CalledProcessError(-6, [mac_request["harness"], "--list", "extra"])),
            (mac_request, subprocess.CalledProcessError(-6, "private-canary-harness --list")),
        ]:
            with patch.object(Path, "read_bytes", side_effect=AssertionError("unexpected private log read")):
                report = fixture.failure_record(other_request, state, other_error)
            assert "log_markers" not in report["diagnostics"]

        mac_output = Path(directory) / "mac-output"
        mac_output.mkdir()
        os.chdir(mac_output)
        with patch.object(fixture, "execute_stages", side_effect=mac_error), \
             patch.object(Path, "read_bytes", side_effect=PermissionError("private-canary-path")):
            try:
                fixture.execute(mac_request)
            except subprocess.CalledProcessError as actual:
                assert actual is mac_error and actual.returncode == -6
            else:
                raise AssertionError("Stop failure was swallowed")
        report = json.loads(Path("g1-stop-raw/failure.json").read_bytes())
        assert report["exit_code"] == -6 and report["stage"] == "preparation_harness"
        assert report["diagnostics"]["log_markers"] == ["unreadable"]
        assert "private-canary" not in json.dumps(report)
    finally:
        os.chdir(previous)

with tempfile.TemporaryDirectory(prefix="g1-stop-checkpoint-check-") as directory:
    try:
        os.chdir(directory)
        root = Path(directory) / "root"
        root.mkdir()
        request = {"root": str(root), "target": "x86_64-pc-windows-msvc", "harness": "harness",
                   "client2_source_sha": "source"}
        memory = SimpleNamespace(MODEL_HASHES={}, execute=lambda _: {
            "passed": True, "offline_installer_verified": True, "model_sha256": {}})
        original = SimpleNamespace(CLIENT2_OWNED_SOURCE_SHA="source",
            safe_failure_diagnostics=lambda *_: {"failure_codes": {}})
        process = SimpleNamespace(returncode=101, stdout=finish_failure)
        with patch.object(fixture, "load", side_effect=[memory, original]), \
             patch.object(fixture, "environment", return_value={}), \
             patch.object(fixture.subprocess, "run", return_value=process) as native_run, \
             patch.object(fixture.sys, "platform", "linux"):
            try:
                fixture.execute(request)
            except subprocess.CalledProcessError as error:
                assert error.returncode == 101 and error.cmd == ["native-stop-harness"]
            else:
                raise AssertionError("Stop failure was swallowed")
        command = native_run.call_args.args[0]
        assert command[:4] == ["dbus-run-session", "--", "env", "RSRS_SS_FIXTURE_BUS=private"]
        assert "dev-secret-service-keyring-selftest.py" in command[6]
        assert command[-5:] == ["harness", fixture.CASE, "--exact", "--test-threads=1", "--show-output"]
        report = json.loads(Path("g1-stop-raw/failure.json").read_bytes())
        assert report["exit_code"] == 101 and report["stage"] == "stop_harness"
        assert report["diagnostics"]["accepted_write_checkpoints"] == stages[:-2]
        assert report["diagnostics"]["finish_checkpoints"][-1] == {"stage": "exit_observed", "elapsed_ms": 100}
        assert report["diagnostics"]["finish_error_category"] == "assertion"
        elapsed = report["diagnostics"]["elapsed_ms"]
        assert set(elapsed) == {"preparation", "harness_standalone", "total"}
        assert all(type(value) is int and value >= 0 for value in elapsed.values())
        assert "private-canary" not in json.dumps(report)
    finally:
        os.chdir(previous)
print("stop runner refuses missing, ignored, duplicated or unsuccessful native execution")
print("failed preparation writes safe stage/exit evidence and preserves the original exception")
print("failed stop reports only complete allowlisted accepted-write checkpoints")
print("Intel macOS harness abort reports only safe log markers")
