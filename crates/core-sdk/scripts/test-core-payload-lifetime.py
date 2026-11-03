"""Offline ownership regression for the real SDK wrapper with a mock FFI boundary.

Run: python3 scripts/test-core-payload-lifetime.py
Requires Python 3.11+, the repository Rust toolchain, and dependencies cached by
the ordinary workspace build. Does not link Core, load models, or access data.
The allocator fixture checks logical deallocation, not RSS or allocator release
to the OS. Native behavior/performance needs separate integration validation.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib


ROOT = Path(__file__).resolve().parents[1]


def extract(source, start, end):
    if source.count(start) != 1 or source.count(end) != 1:
        raise RuntimeError("SDK source boundaries changed; review ownership fixture extraction")
    return source[source.index(start):source.index(end)]


def main():
    source = (ROOT / "crates/core-sdk/src/lib.rs").read_text()
    request = extract(source, "#[derive(Serialize)]", "/// Confined to its owner thread;")
    methods = extract(source, "    pub fn call(&mut self,", "    pub fn capabilities(&mut self)")
    release = "        drop(payload);\n"
    if methods.count(release) != 1:
        raise RuntimeError("Expected exactly one explicit payload release in actual SDK methods")
    fixture = (ROOT / "scripts/fixtures/core-payload-lifetime.rs").read_text()
    prefix = "use anyhow::{bail, Context, Result};\nuse serde::Serialize;\nuse serde_json::{json, Value};\nmod feedback_contract;\nconst FEEDBACK_CONTRACT:u64=0;\n"
    core = "struct Core { handle: ffi::Handle, next_request: u64, poisoned: bool, native_feedback_contract: Option<u64>, native_read_heat_contract: Option<u64> }\n"
    lock = (ROOT / "Cargo.lock").read_text()
    packages = tomllib.loads(lock)["package"]
    versions = {}
    for name in ("anyhow", "serde", "serde_json"):
        matches = [p["version"] for p in packages if p["name"] == name]
        if len(matches) != 1:
            raise RuntimeError(f"Expected one locked {name} version")
        versions[name] = matches[0]
    manifest = ('[package]\nname = "core-payload-lifetime-regression"\nversion = "0.0.0"\n'
                'edition = "2021"\n[workspace]\n[dependencies]\n'
                f'anyhow = "={versions["anyhow"]}"\n'
                f'serde = {{ version = "={versions["serde"]}", features = ["derive"] }}\n'
                f'serde_json = "={versions["serde_json"]}"\n')
    env = os.environ.copy()
    env.setdefault("CARGO_TARGET_DIR", str(ROOT / "target/payload-lifetime-regression"))
    with tempfile.TemporaryDirectory(prefix="core-payload-lifetime-") as directory:
        project = Path(directory)
        (project / "src").mkdir()
        (project / "src/feedback_contract.rs").write_text((ROOT / "crates/core-sdk/src/feedback_contract.rs").read_text())
        (project / "Cargo.toml").write_text(manifest)
        # Reuse the workspace's locked transitive versions; Cargo only prunes
        # unrelated workspace packages and adds this synthetic root package.
        (project / "Cargo.lock").write_text(lock)
        command = ["cargo", "test", "--offline", "--manifest-path", str(project / "Cargo.toml"), "--lib"]
        for negative in (True, False):
            tested = methods.replace(release, "", 1) if negative else methods
            (project / "src/lib.rs").write_text(prefix + request + core + "impl Core {\n" + tested + "}\n" + fixture)
            args = command + (["frees_payload_before_ffi"] if negative else []) + ["--", "--test-threads=1"]
            result = subprocess.run(args, cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            print("NEGATIVE CONTROL" if negative else "ACTUAL SDK METHODS", flush=True)
            print(result.stdout, flush=True)
            if negative:
                if (result.returncode != 101 or "0 passed; 2 failed" not in result.stdout
                        or result.stdout.count("Error: payload still live at FFI entry") != 2):
                    raise RuntimeError("Both original-lifetime branches must fail the deallocation assertion")
            elif result.returncode != 0 or "7 passed; 0 failed" not in result.stdout:
                raise RuntimeError("Actual SDK wrapper ownership regression failed")
    print("PASS: both negative controls detected; all five actual-wrapper and two feedback contract tests passed")


if __name__ == "__main__":
    main()
