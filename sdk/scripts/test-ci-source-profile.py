"""Exercise the actual CI Cargo profile without SDK credentials or dependencies."""
import os
from pathlib import Path
import subprocess
import tempfile

SOURCE = r'''
fn checked(x:i32)->i32 { debug_assert!(x>=0); x+1 }
fn overflowing(x:u8)->u8 { x+1 }
#[test] fn actual_values(){assert_eq!(checked(1),2);assert_eq!(overflowing(1),2);}
#[test] fn debug_assertions_retained(){assert!(std::panic::catch_unwind(||checked(-1)).is_err());}
#[test] fn overflow_checks_retained(){assert!(std::panic::catch_unwind(||overflowing(std::hint::black_box(255))).is_err());}
'''

def main():
    with tempfile.TemporaryDirectory(prefix="ci-source-profile-") as temporary:
        root = Path(temporary)
        (root / "src").mkdir()
        (root / "Cargo.toml").write_text('[package]\nname="ci-source-profile-probe"\nversion="0.0.0"\nedition="2021"\n[workspace]\n[lib]\ndoctest=false\n')
        (root / "src/lib.rs").write_text(SOURCE)
        env = {key: value for key, value in os.environ.items()
               if not any(word in key.upper() for word in ("TOKEN", "SECRET", "PASSWORD"))}
        # Preserve the job's actual profile settings; do not provide defaults
        # that could hide a missing/weakening workflow configuration.
        env.update(CARGO_TARGET_DIR=str(root / "target"),
                   LLVM_PROFILE_FILE=str(root / "profile-%p.profraw"))
        if "CARGO_ENCODED_RUSTFLAGS" in env:
            env["CARGO_ENCODED_RUSTFLAGS"] += "\x1f-C\x1finstrument-coverage"
        else:
            env["RUSTFLAGS"] = (env.get("RUSTFLAGS", "") + " -C instrument-coverage").strip()
        result = subprocess.run(["cargo", "test", "--offline", "--verbose", "--manifest-path", str(root / "Cargo.toml")],
                                cwd=Path(__file__).resolve().parents[1], env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        print(result.stdout)
        if result.returncode != 0 or "3 passed; 0 failed" not in result.stdout:
            raise RuntimeError("Actual CI profile disabled debug/overflow semantics or failed compilation")
        if "[unoptimized" not in result.stdout:
            raise RuntimeError("CI tests unexpectedly enabled optimization")
        if "-C debuginfo=line-tables-only" not in result.stdout:
            raise RuntimeError("CI compiler did not use the intended line-table debug metadata")
        if not any(path.stat().st_size > 0 for path in root.glob("profile-*.profraw")):
            raise RuntimeError("Instrumented profile produced no LLVM coverage counters")
        print("PASS: line-table metadata, debug assertions, overflow checks and LLVM counters retained")


if __name__ == "__main__":
    main()
