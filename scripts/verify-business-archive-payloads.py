#!/usr/bin/env python3
"""Compare original CLI/Client2 archive members with actual execution payloads.

Uses the ordinary-member rules of native-account-candidate's stable identity
check and the existing native workflow's exact original Client2 tar inventory.
No archive is extracted, repackaged, modified or executed.
"""
import hashlib
import json
from pathlib import Path
import sys
import tarfile


def ordinary(root, relative):
    assert isinstance(relative, str) and relative and not relative.startswith("/")
    assert not any(part in ("", ".", "..") for part in relative.split("/"))
    assert not any(character in relative for character in "\\:\0")
    path = root
    for part in relative.split("/"):
        path = path / part
        assert not path.is_symlink()
    assert path.is_file()
    return path


def verify_members(archive, root, expected):
    assert archive.is_file() and not archive.is_symlink()
    seen = set()
    files = set()
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle.getmembers():
            name = member.name
            if name.startswith("./"):
                name = name[2:]
            if member.isdir():
                name = name.rstrip("/")
            if member.isdir() and name in ("", "."):
                continue
            assert name and not name.startswith("/")
            assert not any(part in ("", ".", "..") for part in name.split("/"))
            assert not any(character in name for character in "\\:\0")
            assert (member.type in (tarfile.REGTYPE, tarfile.AREGTYPE) or member.isdir()) and not member.pax_headers
            assert name not in seen
            seen.add(name)
            if member.isdir():
                assert member.size == 0 and any(path.startswith(name + "/") for path in expected)
                continue
            assert name in expected and member.size == expected[name]["size"]
            assert 0 <= member.size <= 256 * 1024 * 1024
            stream = bundle.extractfile(member)
            assert stream is not None
            with stream:
                data = stream.read(member.size + 1)
            assert len(data) == member.size
            assert hashlib.sha256(data).hexdigest() == expected[name]["sha256"]
            assert data == ordinary(root, name).read_bytes()
            files.add(name)
    assert files == set(expected)


def main():
    cli = Path("g1-input/cli-assets")
    metadata = json.loads(ordinary(cli, "cli-build-x86_64-unknown-linux-gnu.json").read_bytes())
    core_path = ordinary(cli, "core-runtime.json")
    core = json.loads(core_path.read_bytes())
    inventory = {"core-runtime.json": {"size": core_path.stat().st_size,
                                     "sha256": hashlib.sha256(core_path.read_bytes()).hexdigest()}}
    for item in core["files"]:
        assert item["path"] not in inventory
        staged = ordinary(cli, item["path"])
        # CLI core-runtime entries contain path/hash only; observe actual size.
        inventory[item["path"]] = {"size": staged.stat().st_size, "sha256": item["sha256"]}
    verify_members(ordinary(cli, metadata["runtime_file"]), cli, inventory)
    desktop = Path("g1-input/client2-assets")
    binary = ordinary(desktop, "respire")
    assert binary.stat().st_size == 19002960
    verify_members(ordinary(desktop, "respire-linux-amd64.tar.gz"), desktop,
                   {"respire": {"size": 19002960,
                                "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}})
    print("business_original_archives_match_execution_payloads")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.exit("business_archive_payload_mismatch")
