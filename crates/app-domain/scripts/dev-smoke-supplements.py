#!/usr/bin/env python3
"""Run independent CLI supplements and then enforce their joint coverage gate."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import signal
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "root", "cli-report"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("binary-sha256", "version", "source-sha"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise SystemExit("Disposable GitHub Actions runner required")
    temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    root = args.root.resolve()
    if root == temp or not root.is_relative_to(temp) or root.exists():
        raise SystemExit("Fresh runner temporary subdirectory required")
    root.mkdir(mode=0o700)
    scripts = Path(__file__).parent
    common = ["--binary", str(args.binary), "--binary-sha256", args.binary_sha256,
              "--version", args.version, "--source-sha", args.source_sha]
    commands = [
        ("outbox", "dev-outbox-smoke.py", common + ["--root", str(root / "outbox"), "--model-dir", str(root / "outbox/models")]),
        ("ai_inject", "dev-ai-inject-smoke.py", common + ["--root", str(root / "ai-inject")]),
        ("runtime", "dev-runtime-smoke.py", common + ["--root", str(root / "runtime"), "--report", str(root / "runtime-coverage.json")]),
        ("legacy_vault", "dev-legacy-vault-smoke.py", common + ["--root", str(root / "legacy-vault")]),
        ("profile_migration", "dev-profile-migration-smoke.py", common + ["--root", str(root / "profile-migration")]),
        ("login_interruption", "dev-login-interruption-smoke.py", common + ["--root", str(root / "login-interruption"), "--model-dir", str(root / "outbox/models")]),
    ]
    def run_suite(command):
        name, script, flags = command
        process = subprocess.Popen([sys.executable, str(scripts / script), *flags],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            process.communicate(timeout=1500)
            outcome = {"suite": name, "exit": process.returncode, "passed": process.returncode == 0}
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
            outcome = {"suite": name, "passed": False, "failure_code": "suite_timeout"}
        print(json.dumps(outcome), flush=True)
        return outcome

    # Each suite owns its profiles and ports. Only login interruption shares outbox's prepared model.
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(run_suite, commands[:-1]))
    outcomes.append(run_suite(commands[-1]))
    (root / "suite-results.json").write_text(json.dumps(outcomes, indent=2) + "\n", encoding="utf-8")
    gate = [sys.executable, str(scripts / "dev-smoke-gate.py"), "--cli-report", str(args.cli_report),
            "--outbox", str(root / "outbox/outbox-coverage.json"), "--ai-inject", str(root / "ai-inject/ai-inject-coverage.json"),
            "--runtime", str(root / "runtime-coverage.json"), "--legacy-vault", str(root / "legacy-vault/legacy-vault-coverage.json"),
            "--profile-migration", str(root / "profile-migration/migration-coverage.json"),
            "--login-interruption", str(root / "login-interruption/interruption-coverage.json"),
            "--report", str(root / "combined-coverage.json"), "--source-sha", args.source_sha,
            "--version", args.version, "--binary-sha256", args.binary_sha256]
    result = subprocess.run(gate, timeout=30)
    return 0 if result.returncode == 0 and all(outcome["passed"] for outcome in outcomes) else 1


if __name__ == "__main__":
    sys.exit(main())
