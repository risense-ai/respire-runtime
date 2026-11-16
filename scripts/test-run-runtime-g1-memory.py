"""Small refusal checks only; no product execution or acceptance claims."""
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile

spec = importlib.util.spec_from_file_location("memory_fixture", Path(__file__).with_name("run-runtime-g1-memory.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def refuses(call):
    try:
        call()
    except (AssertionError, KeyError):
        return
    raise AssertionError("Invalid evidence was accepted")


text = "\n".join(f"test {case} ... ok" for case in fixture.CASES) + "\ntest result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 29 filtered out;\n"
assert fixture.verify_cases(text) == fixture.CASES
refuses(lambda: fixture.verify_cases(text.replace(fixture.CASES[0], "missing")))
refuses(lambda: fixture.verify_cases(text.replace("0 ignored", "1 ignored")))
refuses(lambda: fixture.verify_cases(text + f"test {fixture.CASES[0]} ... ok\n"))
for name in ("/absolute", "../escape", "a/../escape", "C:/drive", "a\\escape", "a//b"):
    refuses(lambda name=name: fixture.safe_name(name))
with tempfile.TemporaryDirectory(prefix="g1-memory-check-") as directory:
    root = Path(directory)
    for index, (name, kind) in enumerate((("payload", tarfile.REGTYPE), ("../escape", tarfile.REGTYPE),
                                           ("link", tarfile.SYMTYPE), ("hardlink", tarfile.LNKTYPE))):
        archive = root / f"{index}.tar.gz"
        with tarfile.open(archive, "w:gz", format=tarfile.USTAR_FORMAT) as bundle:
            item = tarfile.TarInfo(name)
            item.type = kind
            if kind == tarfile.REGTYPE:
                item.size = 3
                bundle.addfile(item, io.BytesIO(b"abc"))
            else:
                item.linkname = "outside"
                bundle.addfile(item)
        output = root / f"out-{index}"
        if index == 0:
            observed = fixture.unpack(archive, output, fixture.digest(archive))
            assert observed == {"payload": {"size": 3, "sha256": fixture.digest(output / "payload")}}
            refuses(lambda: fixture.unpack(archive, root / "bad-hash", "0" * 64))
        else:
            refuses(lambda: fixture.unpack(archive, output, fixture.digest(archive)))
    assert not (root / "escape").exists()
    managed = root / "managed"
    managed.mkdir()
    binary = managed / "rsrs-runtime.exe"
    resource = managed / "provider.bin"
    binary.write_bytes(b"runtime")
    resource.write_bytes(b"provider")
    inventory = {"rsrs-runtime-target.exe": {"size": 7, "sha256": fixture.digest(binary)},
                 "provider.bin": {"size": 8, "sha256": fixture.digest(resource)},
                 "core-notices/consumer/.coderabbit.yaml": {"size": 3, "sha256": "a" * 64}}
    verify = lambda: fixture.verify_installed_payload(managed, binary, "rsrs-runtime-target.exe", inventory)
    verify()
    resource.write_bytes(b"tampered")
    refuses(verify)
    resource.write_bytes(b"provider")
    resource.unlink()
    refuses(verify)
    resource.write_bytes(b"provider")
    extra = managed / "unexpected.bin"
    extra.write_bytes(b"extra")
    refuses(verify)
    extra.unlink()
    (managed / "core-notices").mkdir()
    refuses(verify)
    sdk = root / "cli-sdk"
    (sdk / "runtime").mkdir(parents=True)
    library = sdk / "runtime/core.so"
    library.write_bytes(b"cli-native")
    manifest = sdk / "manifest.json"
    manifest.write_text(json.dumps({"target": "fixture-target", "sdk_version": "2.0.0-dev.4",
                                   "files": [{"path": "runtime/core.so", "sha256": fixture.digest(library)}]}),
                        encoding="utf-8")
    expected_sdk = {"version": "2.0.0-dev.4", "manifest_sha256": fixture.digest(manifest)}
    core = {"target": "fixture-target", "sdk_version": "2.0.0-dev.4"}
    inventory = {"core.so": fixture.digest(library)}
    files = {"core.so": {"size": library.stat().st_size}}
    verify_sdk = lambda: fixture.verify_cli_sdk(sdk, expected_sdk, core, inventory, files)
    verify_sdk()
    runtime_sdk = {"version": "2.0.0-dev.3", "manifest_sha256": "0" * 64}
    refuses(lambda: fixture.verify_cli_sdk(sdk, runtime_sdk, core, inventory, files))
    refuses(lambda: fixture.verify_cli_sdk(sdk, {**expected_sdk, "version": "2.0.0-dev.3"}, core, inventory, files))
    refuses(lambda: fixture.verify_cli_sdk(sdk, expected_sdk, {**core, "target": "other"}, inventory, files))
    refuses(lambda: fixture.verify_cli_sdk(sdk, expected_sdk, core, {"core.so": "0" * 64}, files))
    refuses(lambda: fixture.verify_cli_sdk(sdk, expected_sdk, core, inventory, {"core.so": {"size": 0}}))
    # Exercise the shared preparation's legacy SDK branch, including its lock.
    legacy_target = "fixture-target"
    legacy_sdk = root / ".cli-source/.sdk" / legacy_target
    (legacy_sdk / "runtime").mkdir(parents=True)
    (legacy_sdk / "runtime/core.so").write_bytes(library.read_bytes())
    (legacy_sdk / "manifest.json").write_bytes(manifest.read_bytes())
    sdk_archive = root / ".cli-source/.sdk-archives" / legacy_target / "sdk.tar.gz"
    sdk_archive.parent.mkdir(parents=True)
    sdk_archive.write_bytes(b"synthetic-sdk-archive")
    lock = root / ".cli-source/sdk/core-sdk.lock.json"
    lock.parent.mkdir()
    lock.write_bytes(b"synthetic-sdk-lock")
    legacy_cli = root / "legacy-cli"
    legacy_cli.mkdir()
    legacy_core = {**core, "schema_version": 1, "files": [{"path": "core.so", "sha256": inventory["core.so"]}]}
    core_file = legacy_cli / "core-runtime.json"
    core_file.write_text(json.dumps(legacy_core), encoding="utf-8")
    legacy_files = {"core.so": {"size": library.stat().st_size, "sha256": fixture.digest(library)},
                    "core-runtime.json": {"size": core_file.stat().st_size, "sha256": fixture.digest(core_file)}}
    legacy_request = {"target": legacy_target, "cli_source_sha": "a" * 40, "cli_binary_sha256": "b" * 64,
                      "actual_cli_native_sdk": {**expected_sdk, "archive_sha256": fixture.digest(sdk_archive)},
                      "cli_sdk_lock_sha256": fixture.digest(lock), "cli_archive_sha256": "c" * 64}
    legacy_metadata = {"target": legacy_target, "git_sha": "a" * 40, "binary_file": f"rsrs-{legacy_target}",
                       "binary_sha256": "b" * 64, "runtime_file": f"rsrs-{legacy_target}-runtime.tar.gz",
                       "runtime_sha256": "c" * 64}
    previous = Path.cwd()
    try:
        os.chdir(root)
        verify_legacy = lambda: fixture.verify_cli_payload(legacy_request, legacy_cli, legacy_files, legacy_metadata)
        verify_legacy()
        refuses(lambda: fixture.verify_cli_payload({**legacy_request, "cli_sdk_lock_sha256": "0" * 64}, legacy_cli, legacy_files, legacy_metadata))
        sdk_archive.write_bytes(b"tampered-sdk-archive")
        refuses(verify_legacy)
        sdk_archive.write_bytes(b"synthetic-sdk-archive")
        (legacy_sdk / "manifest.json").write_text("{}", encoding="utf-8")
        refuses(verify_legacy)
    finally:
        os.chdir(previous)
    manifest.write_text("{}", encoding="utf-8")
    refuses(verify_sdk)
    for target in ("x86_64-unknown-linux-gnu", "aarch64-apple-darwin", "aarch64-pc-windows-msvc"):
        suffix = ".exe" if "windows" in target else ""
        binary_name = f"rsrs-{target}{suffix}"
        sidecar_name = f"cli-build-{target}.json"
        loose = root / target
        loose.mkdir()
        binary = loose / binary_name
        binary.write_bytes(b"synthetic-frontend-binary")
        metadata = {"schema_version": 2, "artifact_layout": "cli-frontend-v2", "target": target,
                    "git_sha": "a" * 40, "version": "2.0.0-dev.11", "binary_file": binary_name,
                    "binary_size": binary.stat().st_size, "binary_sha256": fixture.digest(binary),
                    "producer": {"run_id": "13", "run_attempt": "1"}}
        sidecar = loose / sidecar_name
        sidecar.write_text(json.dumps(metadata), encoding="utf-8")
        request = {"target": target, "cli_source_sha": metadata["git_sha"],
                   "actual_cli_native_sdk": None, "cli_sdk_lock_sha256": None,
                   "cli": str(binary), "cli_binary_sha256": fixture.digest(binary),
                   "cli_metadata": str(sidecar), "cli_metadata_sha256": fixture.digest(sidecar)}
        for mutation in ("valid", "different-binary", "different-sidecar", "missing-sidecar", "unexpected-sdk"):
            archive = loose / f"{mutation}.tar.gz"
            with tarfile.open(archive, "w:gz", format=tarfile.USTAR_FORMAT) as bundle:
                for name in (binary_name, sidecar_name):
                    if mutation == "missing-sidecar" and name == sidecar_name:
                        continue
                    data = (loose / name).read_bytes()
                    if mutation == "different-binary" and name == binary_name:
                        data = b"x" * len(data)
                    if mutation == "different-sidecar" and name == sidecar_name:
                        data += b"\n"
                    item = tarfile.TarInfo(name)
                    item.size = len(data)
                    bundle.addfile(item, io.BytesIO(data))
                if mutation == "unexpected-sdk":
                    bundle.add(library, arcname="core.so", recursive=False)
            extracted = loose / mutation
            files = fixture.unpack(archive, extracted, fixture.digest(archive))
            verify_frontend = lambda: fixture.verify_cli_payload(request, extracted, files, metadata)
            if mutation != "valid":
                refuses(verify_frontend)
                continue
            verify_frontend()
            for key in ("actual_cli_native_sdk", "cli_sdk_lock_sha256"):
                incomplete = {name: value for name, value in request.items() if name != key}
                refuses(lambda: fixture.verify_cli_payload(incomplete, extracted, files, metadata))
            refuses(lambda: fixture.verify_cli_payload({**request, "cli_sdk_lock_sha256": "0" * 64}, extracted, files, metadata))
            # A frontend cannot be relabeled as the legacy native SDK consumer.
            refuses(lambda: fixture.verify_cli_payload({**request, "actual_cli_native_sdk": expected_sdk}, extracted, files, metadata))
            for key, value in (("target", "other"), ("git_sha", "b" * 40), ("binary_file", "other"),
                               ("binary_sha256", "0" * 64), ("binary_size", 0), ("schema_version", 1),
                               ("artifact_layout", "other"), ("runtime_file", "legacy.tar.gz"),
                               ("runtime_sha256", "0" * 64)):
                refuses(lambda: fixture.verify_cli_payload(request, extracted, files, {**metadata, key: value}))
            binary.write_bytes(b"x" * binary.stat().st_size)
            refuses(verify_frontend)
            binary.write_bytes(b"synthetic-frontend-binary")
            sidecar.write_bytes(sidecar.read_bytes() + b"\n")
            refuses(verify_frontend)
            sidecar.write_text(json.dumps(metadata), encoding="utf-8")
            verify_frontend()
print("memory preparation checks frontend binary/sidecar bytes, hashes, identity and explicit SDK null; legacy SDK refusal checks retained")
