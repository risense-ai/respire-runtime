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
        process = SimpleNamespace(returncode=101, stdout=captured)
        with patch.object(fixture, "load", side_effect=[memory, original]), \
             patch.object(fixture, "environment", return_value={}), \
             patch.object(fixture.subprocess, "run", return_value=process):
            try:
                fixture.execute(request)
            except subprocess.CalledProcessError as error:
                assert error.returncode == 101 and error.cmd == ["native-stop-harness"]
            else:
                raise AssertionError("Stop failure was swallowed")
        report = json.loads(Path("g1-stop-raw/failure.json").read_bytes())
        assert report["exit_code"] == 101 and report["stage"] == "stop_harness"
        assert report["diagnostics"]["accepted_write_checkpoints"] == stages
        assert "private-canary" not in json.dumps(report)
    finally:
        os.chdir(previous)
print("stop runner refuses missing, ignored, duplicated or unsuccessful native execution")
print("failed preparation writes safe stage/exit evidence and preserves the original exception")
print("failed stop reports only complete allowlisted accepted-write checkpoints")
print("Intel macOS harness abort reports only safe log markers")
