#!/usr/bin/env python3
"""Hosted native credential fixture check; no CLI, cloud account or model execution."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import secrets
import sys

spec = importlib.util.spec_from_file_location("migration_native_keyring", Path(__file__).with_name("dev-migration-keyring.py"))
backend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend)


def main():
    backend.require(os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted", "disposable_hosted_runner_required")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    root = backend.owned_path(args.root)
    backend.require(args.root.is_absolute() and not root.exists(), "fixture_root_not_fresh")
    root.mkdir(mode=0o700)
    report = {"passed": False, "platform": sys.platform, "source_sha": os.environ.get("GITHUB_SHA"),
        "scope": "Native fixture backend only; no CLI migration compatibility claim.",
        "cases": {}, "keyring_cleanup": {"passed": False, "remaining_entries": []}}
    manager = None
    try:
        manager = backend.create(root / "keyring-home")
        report["keyring_backend"] = manager.name
        second_home = root / "second-home"
        second_home.mkdir()
        manager.configure_env({"HOME": str(second_home)})
        report["cases"]["independent_home_configured"] = {"passed": True}
        account = "ci-migrate-" + secrets.token_hex(8)
        for service in ("1memory", "memocap", "respire", "rsrs"):
            for kind in ("super", "pass"):
                slot = kind + ":" + account
                manager.reserve(service, slot)
                value = secrets.token_urlsafe(32)
                manager.put(service, slot, value)
                backend.require(manager.read(service, slot) == value, "native_credential_roundtrip_failed")
                manager.remove(service, slot)
                manager.remove(service, slot)
                try:
                    manager.read(service, slot)
                except RuntimeError as error:
                    backend.require(str(error) == "fixture_credential_missing", "native_absence_wrong_failure")
                else:
                    raise RuntimeError("native_credential_still_readable")
                report["cases"][service + "_" + kind + "_roundtrip_delete_twice"] = {"passed": True}
        report["status"] = "passed"
    except Exception as error:
        report.update(status="failed", failure_code=str(error) if isinstance(error, RuntimeError) else type(error).__name__)
    finally:
        if manager is not None:
            try:
                report["keyring_cleanup"] = manager.cleanup()
            except Exception as error:
                report["keyring_cleanup"] = {"passed": False, "failure_code": type(error).__name__,
                    "remaining_entries": ["cleanup_not_verified"]}
        report["passed"] = report.get("status") == "passed" and len(report["cases"]) == 9 \
            and report["keyring_cleanup"].get("passed") is True \
            and not report["keyring_cleanup"].get("remaining_entries")
        (root / "keyring-selftest.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": report["passed"], "platform": sys.platform, "cases": len(report["cases"])}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
