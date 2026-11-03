import copy
import importlib.util
import json
from pathlib import Path
import unittest
import os
import subprocess
import sys
import tempfile

root = Path(__file__).parent
spec = importlib.util.spec_from_file_location("gate", root / "dev-smoke-gate.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class BusinessSummaryTests(unittest.TestCase):
    def setUp(self):
        self.mapping = json.loads((root / "dev-runtime-business-coverage.json").read_text())
        self.rows = [{"action": row["action"],
                      **({"removed_by_requirement": True} if row.get("removed_by_requirement") else {"passed": True})}
                     for row in self.mapping["actions"]]

    def test_current_contract_is_64_and_8(self):
        self.assertEqual(gate.business_summary(self.rows, self.mapping),
                         {"passed": True, "observed": 64, "removed_by_requirement": 8})

    def test_invalid_partition_and_counts_rejected(self):
        overlap = copy.deepcopy(self.rows)
        overlap[0]["removed_by_requirement"] = True
        missing = copy.deepcopy(self.rows)
        missing[0].pop("passed")
        wrong = dict(self.mapping, retained=66, removed_by_requirement=6)
        for rows, mapping in [(overlap, self.mapping), (missing, self.mapping),
                              (self.rows + [self.rows[0]], self.mapping), (self.rows[:-1], self.mapping),
                              (self.rows, wrong)]:
            with self.subTest(rows=len(rows), retained=mapping["retained"]):
                with self.assertRaises(RuntimeError):
                    gate.business_summary(rows, mapping)


class MigrationJoinReportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="migration-join-gate-")
        self.addCleanup(self.directory.cleanup)
        self.folder = Path(self.directory.name)
        self.source = "a" * 40
        self.digest = "b" * 64
        self.version = "1.2.3-dev.4"
        supplements = sorted(gate.SUPPLEMENTS)
        self.base = {"source_sha": self.source, "observed_version": self.version,
                     "expected_version": self.version, "binary_sha256": self.digest,
                     "server": "https://api-dev.rsrs.rs", "base_complete": True,
                     "failed": 0, "required_missing": [], "supplemental_required": supplements,
                     "catalog": {"required_remaining": [], "supplemental_required": supplements,
                                 "required_assertions": ["synthetic-base-case"]},
                     "cases": [{"case": "synthetic-base-case", "result": "passed", "status": "ok"}],
                     "cloud_cleanup": {"passed": True, "remaining_users": []}}
        self.migration = {"source_sha": self.source, "version": self.version,
                          "binary_sha256": self.digest, "required_cases": sorted(gate.MIGRATION),
                          "passed": True, "missing_cases": [],
                          "cases": {name: {"passed": True} for name in gate.MIGRATION},
                          "cloud_cleanup": {"passed": True, "remaining_users": []},
                          "keyring_cleanup": {"passed": True, "remaining_entries": []},
                          "platform": sys.platform,
                          "keyring_backend": {"linux": "linux-keyutils", "darwin": "macos-keychain-synthetic-acl",
                                              "win32": "windows-credential-manager"}[sys.platform]}

    def run_gate(self, base, migration):
        for name, value in (("base.json", base), ("migration.json", migration)):
            (self.folder / name).write_text(json.dumps(value))
        report = self.folder / "joined.json"
        env = {key: value for key, value in os.environ.items()
               if not any(word in key.upper() for word in ("TOKEN", "SECRET", "PASSWORD"))}
        env["GITHUB_ACTIONS"] = "true"
        completed = subprocess.run([sys.executable, str(root / "dev-smoke-gate.py"), "--migration-only",
                                    "--cli-report", str(self.folder / "base.json"),
                                    "--profile-migration", str(self.folder / "migration.json"),
                                    "--report", str(report), "--source-sha", self.source,
                                    "--version", self.version, "--binary-sha256", self.digest],
                                   env=env, capture_output=True, text=True, timeout=10)
        return completed, json.loads(report.read_text())

    def test_actual_cli_joins_matching_report_files(self):
        completed, report = self.run_gate(self.base, self.migration)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(report["complete"])
        self.assertTrue(report["components"]["cli"]["passed"])
        self.assertTrue(report["components"]["profile_migration"]["passed"])

    def test_actual_cli_rejects_mixed_source_version_binary_and_incomplete_reports(self):
        for component, field, wrong, code in (
                ("base", "source_sha", "f" * 40, "artifact_source_mismatch"),
                ("migration", "source_sha", "f" * 40, "artifact_source_mismatch"),
                ("base", "binary_sha256", "f" * 64, "artifact_binary_mismatch"),
                ("migration", "binary_sha256", "f" * 64, "artifact_binary_mismatch"),
                ("base", "observed_version", "1.2.3-dev.3", "artifact_version_mismatch"),
                ("migration", "version", "1.2.3-dev.3", "artifact_version_mismatch"),
                ("migration", "passed", False, "migration_incomplete"),
                ("base", "base_complete", False, "cli_base_incomplete")):
            with self.subTest(component=component, field=field):
                base, migration = copy.deepcopy(self.base), copy.deepcopy(self.migration)
                (base if component == "base" else migration)[field] = wrong
                completed, report = self.run_gate(base, migration)
                self.assertNotEqual(completed.returncode, 0)
                self.assertFalse(report["complete"])
                self.assertEqual(report["failure_code"], code)


if __name__ == "__main__":
    unittest.main()
