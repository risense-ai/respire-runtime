"""Pure archive checks, including the CLI producer's real path/hash-only schema."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile

source = Path(__file__).with_name("verify-business-archive-payloads.py")
spec = importlib.util.spec_from_file_location("archive_review", source)
archives = importlib.util.module_from_spec(spec)
spec.loader.exec_module(archives)

with tempfile.TemporaryDirectory(prefix="g1-archive-pure-") as temporary:
    folder = Path(temporary)
    data = b"synthetic-only-payload"
    (folder / "payload").write_bytes(data)
    inventory = {"payload": {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}}
    archive = folder / "payload.tar.gz"
    for mutation in ("valid", "different-bytes", "duplicate", "symlink", "unexpected", "traversal", "missing"):
        with tarfile.open(archive, "w:gz", format=tarfile.GNU_FORMAT) as stream:
            name = "unexpected" if mutation == "unexpected" else "../payload" if mutation == "traversal" else "payload"
            item = tarfile.TarInfo(name)
            item.size = len(data)
            if mutation == "symlink":
                item.type = tarfile.SYMTYPE
                item.linkname = "payload"
                item.size = 0
            if mutation != "missing":
                stream.addfile(item, io.BytesIO(b"x" * len(data) if mutation == "different-bytes" else data))
            if mutation == "duplicate":
                stream.addfile(item, io.BytesIO(data))
        try:
            archives.verify_members(archive, folder, inventory)
        except AssertionError:
            assert mutation != "valid"
        else:
            assert mutation == "valid"
    (folder / "payload").write_bytes(b"changed-staged-payload")
    with tarfile.open(archive, "w:gz", format=tarfile.USTAR_FORMAT) as stream:
        item = tarfile.TarInfo("payload")
        item.size = len(data)
        stream.addfile(item, io.BytesIO(data))
    try:
        archives.verify_members(archive, folder, inventory)
    except AssertionError:
        pass
    else:
        raise AssertionError("Independent staged payload accepted")

with tempfile.TemporaryDirectory(prefix="g1-real-schema-pure-") as temporary:
    folder = Path(temporary)
    cli = folder / "g1-input/cli-assets"
    desktop = folder / "g1-input/client2-assets"
    cli.mkdir(parents=True)
    desktop.mkdir(parents=True)
    payload = b"synthetic-native-library"
    (cli / "library.so").write_bytes(payload)
    # stage-core-runtime.mjs emits path/hash, never a size property.
    core = {"schema_version": 1, "target": "x86_64-unknown-linux-gnu",
            "files": [{"path": "library.so", "sha256": hashlib.sha256(payload).hexdigest()}]}
    (cli / "core-runtime.json").write_text(json.dumps(core), encoding="utf-8")
    (cli / "cli-build-x86_64-unknown-linux-gnu.json").write_text(
        json.dumps({"runtime_file": "native.tar.gz"}), encoding="utf-8")
    with tarfile.open(cli / "native.tar.gz", "w:gz", format=tarfile.GNU_FORMAT) as stream:
        for name in ("core-runtime.json", "library.so"):
            stream.add(cli / name, arcname=name, recursive=False)
    (desktop / "respire").write_bytes(b"\0" * 19002960)
    with tarfile.open(desktop / "respire-linux-amd64.tar.gz", "w:gz", format=tarfile.GNU_FORMAT) as stream:
        stream.add(desktop / "respire", arcname="respire", recursive=False)
    previous = Path.cwd()
    try:
        os.chdir(folder)
        archives.main()
        (cli / "library.so").write_bytes(b"x" * len(payload))
        try:
            archives.main()
        except AssertionError:
            pass
        else:
            raise AssertionError("CLI path/hash-only schema did not protect actual payload")
    finally:
        os.chdir(previous)
print("10 pure archive checks passed; no product execution")
