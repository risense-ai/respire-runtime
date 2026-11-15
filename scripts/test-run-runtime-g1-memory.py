"""Small refusal checks only; no product execution or acceptance claims."""
import importlib.util
import io
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
print("memory fixture rejects skipped coverage, duplicate cases, altered archives, traversal and links")
