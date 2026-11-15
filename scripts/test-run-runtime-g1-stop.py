"""Pure refusal checks; no OS credentials or product process is created."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
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
    finally:
        os.chdir(previous)
print("stop runner refuses missing, ignored, duplicated or unsuccessful native execution")
print("failed preparation writes safe stage/exit evidence and preserves the original exception")
