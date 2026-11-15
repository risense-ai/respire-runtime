"""Run synthetic-key diary fixtures against original frozen native products.

No OS credential fixture is needed. Only the CLI installs models; Runtime never
downloads them. Private product output stays in the disposable runner directory.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile


CASES = [
    "diary_identity::remember_public_payload_covers_created_appended_and_merged",
    "diary_identity::concurrent_same_day_client_commands_preserve_each_successful_addition_once",
]
MODEL_HASHES = {
    "tokenizer.json": "6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790",
    "onnx/model_quantized.onnx": "0826f8c1ab9edf1801db86c61919d4d108e8bfc0b809ec823ad366882ff0b77d",
    "onnx/model_quantized.cpu-v1.ort": "7ff152e912bc234f5c90e4012f99897a7b2ce180f016db2321304057756b64ff",
}


def digest(path):
    assert path.is_file() and not path.is_symlink(), f"Not an ordinary file: {path}"
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def safe_name(name):
    assert name and not any(char in name for char in "\\:\0")
    assert all(part not in ("", ".", "..") for part in name.split("/"))
    return name


def unpack(archive, destination, expected_hash):
    assert digest(archive) == expected_hash, "Original archive digest differs"
    destination.mkdir()
    files = {}
    seen = set()
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle:
            name = member.name.removeprefix("./").rstrip("/") if member.isdir() else member.name.removeprefix("./")
            if member.isdir() and name in ("", "."):
                continue
            safe_name(name)
            assert name not in seen and not member.pax_headers
            seen.add(name)
            assert member.isdir() or member.type in (tarfile.REGTYPE, tarfile.AREGTYPE)
            output = destination / name
            if member.isdir():
                assert member.size == 0
                output.mkdir(parents=True, exist_ok=True)
                continue
            output.parent.mkdir(parents=True, exist_ok=True)
            stream = bundle.extractfile(member)
            assert stream is not None
            with stream, output.open("xb") as target:
                shutil.copyfileobj(stream, target)
            assert output.stat().st_size == member.size
            output.chmod(0o700 if member.mode & 0o111 else 0o600)
            files[name] = {"size": member.size, "sha256": digest(output)}
    return files


def verify_cases(text):
    for case in CASES:
        assert len(re.findall(r"^test " + re.escape(case) + r" \.\.\. ok\s*$", text, re.M)) == 1, f"Missing successful case: {case}"
    assert re.search(r"test result: ok\. 2 passed; 0 failed; 0 ignored;", text), "Incomplete memory coverage"
    return CASES


def verify_installed_payload(directory, binary, archive_binary, inventory):
    # CLI compact_version removes notices after authenticating the full archive.
    assert not (directory / "core-notices").exists(), "Fresh managed Runtime retained archive-only notices"
    expected = {}
    for name, item in inventory.items():
        if name.startswith("core-notices/"):
            continue
        path = binary if name == archive_binary else directory / name
        assert digest(path) == item["sha256"] and path.stat().st_size == item["size"]
        expected[path.relative_to(directory).as_posix()] = item
    actual = {path.relative_to(directory).as_posix() for path in directory.rglob("*") if path.is_file()}
    assert actual == set(expected), "Managed Runtime inventory differs from authenticated runtime files"


def verify_cli_sdk(sdk, expected_sdk, core, inventory, cli_files):
    assert digest(sdk / "manifest.json") == expected_sdk["manifest_sha256"], "CLI SDK manifest digest differs"
    manifest = json.loads((sdk / "manifest.json").read_bytes())
    assert core["target"] == manifest["target"]
    assert core["sdk_version"] == manifest["sdk_version"] == expected_sdk["version"]
    for item in manifest["files"]:
        name = item["path"]
        staged = (name[8:] if name.startswith("runtime/") else
                  "core-notices/" + name[8:] if name.startswith("notices/") else
                  "core-notices/CORE-SDK-LICENSE.txt" if name == "LICENSE.txt" else None)
        if staged is not None:
            assert inventory[staged] == item["sha256"]
            assert cli_files[staged]["size"] == (sdk / safe_name(name)).stat().st_size


def execute(request):
    root = Path(request["root"])
    assert root.is_absolute() and root.parent == Path(os.environ["RUNNER_TEMP"]).resolve()
    root.mkdir()
    for name in ("home", "data", "config", "cache", "runtime", "tmp", "installation"):
        (root / name).mkdir()
    target = request["target"]
    suffix = ".exe" if "windows" in target else ""
    cli_meta = json.loads(Path(request["cli_metadata"]).read_bytes())
    runtime_meta = json.loads(Path(request["runtime_metadata"]).read_bytes())
    assert digest(Path(request["cli_metadata"])) == request["cli_metadata_sha256"]
    assert digest(Path(request["runtime_metadata"])) == request["runtime_metadata_sha256"]
    cli_dir = root / "cli"
    cli_files = unpack(Path(request["cli_archive"]), cli_dir, request["cli_archive_sha256"])
    core = json.loads((cli_dir / "core-runtime.json").read_bytes())
    assert core["schema_version"] == 1 and core["target"] == target
    inventory = {safe_name(item["path"]): item["sha256"] for item in core["files"]}
    assert len(inventory) == len(core["files"])
    assert set(cli_files) == set(inventory) | {"core-runtime.json"}
    for name, sha in inventory.items():
        assert cli_files[name]["sha256"] == sha
    assert digest(Path(".cli-source/sdk/core-sdk.lock.json")) == request["cli_sdk_lock_sha256"]
    expected_sdk = request["actual_cli_native_sdk"]
    assert digest(Path(".cli-source/.sdk-archives") / target / "sdk.tar.gz") == expected_sdk["archive_sha256"]
    verify_cli_sdk(Path(".cli-source/.sdk") / target, expected_sdk, core, inventory, cli_files)
    runtime_files = unpack(Path(request["runtime_archive"]), root / "runtime-payload", request["runtime_archive_sha256"])
    expected = {safe_name(item["path"]): {"size": item["size"], "sha256": item["sha256"]} for item in runtime_meta["files"]}
    assert len(expected) == len(runtime_meta["files"]) and runtime_files == expected
    runtime_name = f"rsrs-runtime-{target}{suffix}"
    assert digest(root / "runtime-payload" / runtime_name) == request["runtime_binary_sha256"]
    cli = cli_dir / f"rsrs-{target}{suffix}"
    shutil.copyfile(request["cli"], cli)
    cli.chmod(0o700)
    assert digest(cli) == request["cli_binary_sha256"] == cli_meta["binary_sha256"]
    env = {key: value for key, value in os.environ.items() if key.upper() in (
        "PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "RUNNER_TEMP",
        "GITHUB_ACTIONS", "RUNNER_ENVIRONMENT")}
    env.update(HOME=str(root / "home"), USERPROFILE=str(root / "home"),
               APPDATA=str(root / "config"), LOCALAPPDATA=str(root / "data"),
               XDG_DATA_HOME=str(root / "data"), XDG_CONFIG_HOME=str(root / "config"),
               XDG_CACHE_HOME=str(root / "cache"), XDG_RUNTIME_DIR=str(root / "runtime"),
               TMPDIR=str(root / "tmp"), TMP=str(root / "tmp"), TEMP=str(root / "tmp"),
               RSRS_DATA_DIR=str(root / "installation"), RSRS_M3_DIR=str(root / "model"),
               RSRS_ENGINE="cpu", RSRS_NO_AUTOSYNC="1", RSRS_UPDATE_CHECK="0",
               RUST_MIN_STACK="16777216", RUST_TEST_THREADS="1")
    with (root / "private.log").open("wb") as log:
        subprocess.run([str(cli), "--json", "runtime", "install", "--file", request["runtime_archive"],
                        "--version", runtime_meta["runtime_version"]], env=env, stdout=log, stderr=log, check=True)
        receipt = json.loads((root / "installation/bin/runtime.json").read_bytes())
        metadata_bytes = Path(request["runtime_metadata"]).read_bytes()
        assert receipt["version"] == runtime_meta["runtime_version"]
        assert receipt["release"]["metadata_json"] == metadata_bytes.decode()
        assert receipt["release"]["metadata_sha256"] == hashlib.sha256(metadata_bytes).hexdigest()
        assert receipt["sha256"] == request["runtime_binary_sha256"]
        installed_dir = root / "installation/bin/runtime" / runtime_meta["runtime_version"]
        installed = installed_dir / ("rsrs-runtime" + suffix)
        assert digest(installed) == request["runtime_binary_sha256"]
        verify_installed_payload(installed_dir, installed, runtime_name, expected)
        subprocess.run([str(cli), "--json", "model", "install-m3"], env=env, stdout=log, stderr=log, check=True)
        sys.path.insert(0, str(Path(".cli-source/scripts").resolve()))
        from dev_model_fixture import share_cpu_container
        share_cpu_container(root, env, root / "model")
        for name, sha in MODEL_HASHES.items():
            assert digest(root / "model" / name) == sha, f"Real model digest differs: {name}"
        env.update(RSRS_CLI_BIN=str(cli), RSRS_CLI_SOURCE_DIR=str(Path(".cli-source").resolve()),
                   RSRS_CLI_SOURCE_SHA=request["cli_source_sha"], RSRS_RUNTIME_BIN=str(installed),
                   RSRS_RUNTIME_SOURCE_SHA=request["source_sha"], RSRS_RUNTIME_CANDIDATE_METADATA=request["runtime_metadata"],
                   RSRS_CORE_TEST_MODEL_DIR=str(root / "model"), RSRS_CORE_TEST_MODE="1")
        harness = Path(request["harness"])
        before = digest(harness)
        listing = subprocess.check_output([str(harness), "--list"], env=env, stderr=log).decode()
        for case in CASES:
            assert listing.splitlines().count(case + ": test") == 1, f"Harness lacks {case}"
        result = subprocess.run([str(harness), *CASES, "--exact", "--test-threads=1"],
                                env=env, stdout=subprocess.PIPE, stderr=log, check=True)
        log.write(result.stdout)
        passed = verify_cases(result.stdout.decode())
        assert before == digest(harness) == request["harness_sha256"]
        assert digest(cli) == request["cli_binary_sha256"] and digest(installed) == request["runtime_binary_sha256"]
    return {"schema": 1, "passed": True, "test_executed": True, "release_acceptance": False,
            "target": target, "passed_cases": passed, "model_sha256": MODEL_HASHES,
            "offline_installer_verified": True, "identity": request}


if __name__ == "__main__":
    request = json.loads(Path(sys.argv[1]).read_bytes())
    result = execute(request)
    with Path(sys.argv[2]).open("x", encoding="utf-8", newline="\n") as output:
        json.dump(result, output, indent=2)
        output.write("\n")
