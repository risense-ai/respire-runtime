import hashlib
import io
import json
from pathlib import Path
import runpy
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from published_upgrade_policy import platform_applicability, select_upgrade_sources


class UpgradePolicyTest(unittest.TestCase):
    def test_only_exact_documented_arm_gaps_are_not_applicable(self):
        for target in ["aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl", "aarch64-pc-windows-msvc"]:
            gaps = ["v1.0.15", "v1.0.16"]
            if "linux" in target:
                gaps.append("v1.0.17-dev.12")
            for tag in gaps:
                self.assertIsNotNone(platform_applicability(tag, target, []))
            for tag in ["v1.0.7", "v1.0.10", "v1.0.12", "v1.0.17", "v1.0.18"]:
                with self.assertRaises(ValueError):
                    platform_applicability(tag, target, [])

    def test_partial_or_non_arm_missing_assets_always_fail(self):
        target = "aarch64-unknown-linux-gnu"
        for asset in [f"rsrs-{target}", f"rsrs-{target}-runtime.tar.gz", f"cli-build-{target}.json"]:
            with self.assertRaises(ValueError):
                platform_applicability("v1.0.16", target, [asset])
        with self.assertRaises(ValueError):
            platform_applicability("v1.0.16", "x86_64-unknown-linux-gnu", [])
        self.assertIsNotNone(platform_applicability("v1.0.19", "x86_64-apple-darwin", []))
        for tag, assets in [("v1.0.20", []), ("v1.0.19", ["rsrs-x86_64-apple-darwin"])]:
            with self.assertRaises(ValueError):
                platform_applicability(tag, "x86_64-apple-darwin", assets)

    def test_present_historical_arm_assets_remain_required(self):
        target = "aarch64-unknown-linux-musl"
        assets = [f"rsrs-{target}", f"rsrs-{target}-runtime.tar.gz", f"cli-build-{target}.json"]
        for tag in ["v1.0.7", "v1.0.16"]:
            self.assertIsNone(platform_applicability(tag, target, assets))


class UpgradeProfileTest(unittest.TestCase):
    target = "aarch64-unknown-linux-gnu"

    def release(self, tag, missing=False, draft=False, prerelease=False):
        names = [f"rsrs-{self.target}", f"rsrs-{self.target}-runtime.tar.gz", f"cli-build-{self.target}.json"]
        return {"tag_name": tag, "draft": draft, "prerelease": prerelease,
                "assets": [] if missing else [{"name": name} for name in names]}

    def test_critical_uses_numeric_version_order(self):
        releases = [self.release(tag) for tag in ["v1.0.9", "v1.0.18", "v1.0.10"]]
        sources = {release["tag_name"]: release for release in releases}
        self.assertEqual(list(select_upgrade_sources(sources, self.target, "critical")), ["v1.0.18"])
        self.assertEqual(select_upgrade_sources(sources, self.target, "full"), sources)

    def test_only_known_whole_platform_gaps_can_fall_back(self):
        sources = {tag: self.release(tag, missing=tag == "v1.0.16") for tag in ["v1.0.12", "v1.0.16"]}
        self.assertEqual(list(select_upgrade_sources(sources, self.target, "critical")), ["v1.0.12"])
        sources["v1.0.18"] = self.release("v1.0.18", missing=True)
        with self.assertRaisesRegex(ValueError, "missing platform artifact"):
            select_upgrade_sources(sources, self.target, "critical")

    def test_partial_latest_or_no_applicable_source_fails(self):
        self.assertEqual(select_upgrade_sources({"v1.0.19": {"assets": []}}, "x86_64-apple-darwin", "critical"), {})
        release = self.release("v1.0.16")
        release["assets"].pop()
        with self.assertRaisesRegex(ValueError, "missing platform artifact"):
            select_upgrade_sources({"v1.0.16": release}, self.target, "critical")
        for sources in [{}, {"v1.0.16": self.release("v1.0.16", missing=True)}]:
            with self.assertRaisesRegex(ValueError, "no applicable formal stable"):
                select_upgrade_sources(sources, self.target, "critical")

    def run_fixture(self, profile=None, missing_latest=False, registry=None, empty_checks=False, checks_transform=None):
        # Execute the real orchestration with local artifact bytes and a fake upgrade child.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / "candidate"
            candidate.write_bytes(b"candidate")
            digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode="w:gz"):
                pass
            releases = [self.release(tag, missing=missing_latest and tag == "v1.0.18")
                        for tag in ["v1.0.12", "v1.0.18", "v1.0.6-dev.37075716045"]]
            releases[-1]["prerelease"] = True
            releases.append(self.release("v1.0.10", draft=True))
            files = {}
            for release in releases:
                tag = release["tag_name"]
                values = [b"old-binary", archive.getvalue()]
                values.append(json.dumps({"version": tag[1:], "target": self.target,
                    "binary_sha256": hashlib.sha256(values[0]).hexdigest(),
                    "runtime_sha256": hashlib.sha256(values[1]).hexdigest()}).encode())
                for asset, value in zip(release["assets"], values):
                    asset.update(digest="sha256:" + hashlib.sha256(value).hexdigest(), id=len(files))
                    files[(tag, asset["name"])] = value
            def output(command, **kwargs):
                if command[0] == "npm":
                    return json.dumps(registry if registry is not None else ["1.0.12", "1.0.18"])
                if command[-1].endswith("/403872621"):
                    return json.dumps(releases[-1])
                return json.dumps(releases)
            upgraded = []
            def run(command, **kwargs):
                if command[0] == "gh":
                    if command[1] == "api":
                        asset_id = int(command[2].rsplit("/", 1)[1])
                        kwargs["stdout"].write(next(value for release in releases for asset in release["assets"]
                            if asset["id"] == asset_id for value in [files[(release["tag_name"], asset["name"])]]))
                    else:
                        tag = command[3]
                        folder = Path(command[command.index("--dir") + 1])
                        for (source, name), value in files.items():
                            if source == tag:
                                (folder / name).write_bytes(value)
                else:
                    result = Path(command[command.index("--output-dir") + 1])
                    result.mkdir(parents=True)
                    upgraded.append(result.parent.name)
                    checks = [{"passed": True, "binary_sha256": digest, "real_model": True, "engine": "cpu",
                        "supervised_worker_checked": True, "global_engine_preserved": True, "distinct_vault_keys": True,
                        "source_and_keys_unchanged": True, "compatible_index_reused": True,
                        "forced_restart_checked": True, "old_rpc_checked": True, "old_rpc_authenticated": False,
                        "resident_stress": None, "in_process_checked": False,
                        "sequence": [{"account": account, "model_rows": {
                            name: {"name": name, "status": "ok"} for name in ["embedder", "model index"]}}
                            for account in ["main", "alternate", "main"]]}]
                    if checks_transform is not None:
                        checks = checks_transform(checks)
                    (result / "real-account-return-verification.json").write_text(
                        json.dumps([] if empty_checks else checks), encoding="utf-8")
            argv = ["test-published-upgrades.py", "--binary", str(candidate), "--target", self.target,
                    "--model-dir", str(root / "model"), "--legacy-model-dir", str(root / "legacy"),
                    "--output-dir", str(root / "reports")]
            if profile is not None:
                argv += ["--profile", profile]
            with patch.object(sys, "argv", argv), patch("shutil.which", side_effect=lambda name: name), \
                    patch("subprocess.check_output", side_effect=output), patch("subprocess.run", side_effect=run):
                if missing_latest or registry is not None or empty_checks or checks_transform is not None:
                    with self.assertRaises((ValueError, AssertionError)):
                        runpy.run_path(str(Path(__file__).with_name("test-published-upgrades.py")), run_name="__main__")
                else:
                    runpy.run_path(str(Path(__file__).with_name("test-published-upgrades.py")), run_name="__main__")
            report = root / "reports/published-upgrades.json"
            return upgraded, json.loads(report.read_text()) if report.exists() else None

    def test_critical_runs_latest_only_and_marks_partial_coverage(self):
        upgraded, report = self.run_fixture("critical")
        self.assertEqual(upgraded, ["v1.0.18"])
        self.assertEqual(report["selected_sources"], ["v1.0.18"])
        self.assertEqual(report["profile"], "critical")
        self.assertTrue(report["passed"])
        self.assertFalse(report["full_coverage"])
        self.assertFalse(report["all_published_sources_covered"])
        self.assertEqual(report["additional_draft_baselines"], [])

    def test_default_full_keeps_all_stables_and_both_baselines(self):
        upgraded, report = self.run_fixture()
        self.assertEqual(set(upgraded), {"v1.0.12", "v1.0.18", "v1.0.10", "v1.0.6-dev.37075716045"})
        self.assertEqual(report["profile"], "full")
        self.assertTrue(report["full_coverage"])
        self.assertTrue(report["all_published_sources_covered"])

    def test_critical_missing_latest_fails_without_running_older(self):
        upgraded, report = self.run_fixture("critical", missing_latest=True)
        self.assertEqual(upgraded, [])
        self.assertFalse(report["passed"])
        self.assertFalse(report["full_coverage"])

    def test_missing_registry_stable_still_fails_in_both_profiles(self):
        for profile in ["critical", "full"]:
            upgraded, _ = self.run_fixture(profile, registry=["1.0.19"])
            self.assertEqual(upgraded, [])

    def test_empty_upgrade_checks_cannot_pass_either_profile(self):
        for profile in ["critical", "full"]:
            _, report = self.run_fixture(profile, empty_checks=True)
            self.assertFalse(report["passed"])
            self.assertFalse(report["full_coverage"])
            self.assertFalse(report["all_published_sources_covered"])

    def assert_rejected_checks(self, transform):
        for profile in ["critical", "full"]:
            _, report = self.run_fixture(profile, checks_transform=transform)
            self.assertFalse(report["passed"])
            self.assertFalse(report["full_coverage"])
            self.assertFalse(report["all_published_sources_covered"])

    def test_sparse_or_duplicate_candidate_reports_fail(self):
        self.assert_rejected_checks(lambda checks: [{"passed": True, "binary_sha256": checks[0]["binary_sha256"]}])
        self.assert_rejected_checks(lambda checks: checks * 2)

    def test_each_required_upgrade_flag_must_be_present_and_strictly_true(self):
        flags = ["passed", "real_model", "supervised_worker_checked", "global_engine_preserved",
                 "distinct_vault_keys", "source_and_keys_unchanged", "compatible_index_reused",
                 "forced_restart_checked", "old_rpc_checked"]
        for name in flags:
            with self.subTest(name=name, value="missing"):
                self.assert_rejected_checks(lambda checks: [{key: value for key, value in checks[0].items() if key != name}])
            for value in [False, 1, "true"]:
                with self.subTest(name=name, value=value):
                    self.assert_rejected_checks(lambda checks: [{**checks[0], name: value}])

    def test_candidate_hash_and_cpu_engine_must_match(self):
        for name, value in [("binary_sha256", "wrong"), ("engine", "gpu")]:
            with self.subTest(name=name):
                self.assert_rejected_checks(lambda checks: [{**checks[0], name: value}])

    def test_account_sequence_cannot_be_missing_shortened_or_reordered(self):
        for sequence in [None, [], ["main", "alternate"], ["main", "main", "alternate"]]:
            with self.subTest(sequence=sequence):
                self.assert_rejected_checks(lambda checks: [{**checks[0], "sequence": None if sequence is None else [
                    {**checks[0]["sequence"][0], "account": account} for account in sequence]}])

    def test_each_account_requires_both_successful_model_rows(self):
        for index in range(3):
            for rows in [None, {}, {"embedder": {"status": "ok"}},
                         {"embedder": {"status": "ok"}, "model index": {"status": "fail"}},
                         {"embedder": {}, "model index": {"status": "ok"}}]:
                with self.subTest(index=index, rows=rows):
                    self.assert_rejected_checks(lambda checks: [{**checks[0], "sequence": [
                        {**step, "model_rows": rows} if position == index else step
                        for position, step in enumerate(checks[0]["sequence"])]}])


if __name__ == "__main__":
    unittest.main()
