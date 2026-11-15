"""Small refusal checks only; no product execution or acceptance claims."""
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile

spec = importlib.util.spec_from_file_location("memory_fixture", Path(__file__).with_name("run-runtime-g1-memory.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def refuses(call):
    try:
        call()
    except AssertionError:
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
    manifest.write_text("{}", encoding="utf-8")
    refuses(verify_sdk)
print("memory fixture rejects skipped coverage, duplicate cases, altered archives, traversal and links")
