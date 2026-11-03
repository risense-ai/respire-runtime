import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import dev_model_fixture as model
# This existing CI entry covers both native public input caches.
from test_native_psutil_wheel_cache import NativePsutilWheelCacheTest

cache_spec = importlib.util.spec_from_file_location("native_model_cache", Path(__file__).with_name("native-model-cache.py"))
model_cache = importlib.util.module_from_spec(cache_spec)
cache_spec.loader.exec_module(model_cache)


class NativeModelCacheTests(unittest.TestCase):
    def test_public_pins_match_existing_consumers_and_key_covers_every_input(self):
        root = Path(__file__).parents[1]
        installer = (root / "crates/commands/src/model_install.rs").read_text(encoding="utf-8")
        cpu = (root / "crates/core-sdk/src/cpu_model.rs").read_text(encoding="utf-8")
        fixture = (root / "scripts/test-real-m3-account-switch.py").read_text(encoding="utf-8")
        self.assertIn(model_cache.REVISION, installer)
        for name, digest in model_cache.FILES.items():
            self.assertIn(digest, cpu if name.endswith(".ort") else fixture)
        self.assertEqual(len(model_cache.FILES), 4)
        key = model_cache.cache_key()
        self.assertRegex(key, r"^native-model-v1-[a-f0-9]{64}$")
        with patch.object(model_cache, "REVISION", "changed"):
            self.assertNotEqual(key, model_cache.cache_key())
        for name in model_cache.FILES:
            with patch.dict(model_cache.FILES, {name: "f" * 64}):
                self.assertNotEqual(key, model_cache.cache_key())

    def test_roundtrip_excludes_fixture_state_and_bad_cache_writes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active, legacy, cache = root / "active models", root / "legacy models", root / "cache"
            contents = {name: name.encode() for name in model_cache.FILES}
            pins = {name: hashlib.sha256(body).hexdigest() for name, body in contents.items()}
            for name, source in model_cache.sources(active, legacy).items():
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_bytes(contents[name])
            (active / "session.json").write_text("never-cache-fixture-state")
            with patch.dict(model_cache.FILES, pins):
                model_cache.stage(cache, active, legacy)
                self.assertEqual({p.relative_to(cache).as_posix() for p in cache.rglob("*") if p.is_file()}, set(pins))
                restored, old = root / "restored", root / "restored legacy"
                model_cache.restore(cache, restored, old)
                model_cache.verify_sources(restored, old)
                (cache / "session.json").write_text("forbidden")
                with self.assertRaisesRegex(RuntimeError, "Unexpected"):
                    model_cache.restore(cache, root / "untouched", root / "untouched legacy")
                self.assertFalse((root / "untouched").exists())
                (cache / "session.json").unlink()
                (cache / "onnx/model_fp16.onnx").write_bytes(b"corrupt")
                with self.assertRaisesRegex(RuntimeError, "checksum"):
                    model_cache.restore(cache, root / "untouched", root / "untouched legacy")
                self.assertFalse((root / "untouched").exists())
                (cache / "onnx/model_fp16.onnx").unlink()
                with self.assertRaisesRegex(RuntimeError, "missing"):
                    model_cache.restore(cache, root / "untouched", root / "untouched legacy")
                self.assertFalse((root / "untouched").exists())
                with patch.object(Path, "is_symlink", return_value=True):
                    with self.assertRaisesRegex(RuntimeError, "linked"):
                        model_cache.verify_cache(cache)

    def test_workflow_keeps_real_validation_and_only_trusted_main_saves_inputs(self):
        workflow = (Path(__file__).parents[1] / ".github/workflows/release-native-validation.yml").read_text(encoding="utf-8")
        self.assertNotIn("actions/cache@v4", workflow)
        self.assertIn("enableCrossOsArchive: true", workflow)
        self.assertIn("enableCrossOsArchive: false", workflow)
        self.assertIn('test "$MATCHED_KEY" = "$EXPECTED_KEY"', workflow)
        self.assertIn('"$exe" --direct model install-m3 --json', workflow)
        self.assertIn('"$exe" --direct model probe --json', workflow)
        self.assertIn('"$py" scripts/test-published-upgrades.py', workflow)
        self.assertIn('scripts/native-model-cache.py verify', workflow)
        self.assertIn("pip==26.2.2 setuptools==84.2.1 wheel==0.48.0", workflow)
        self.assertIn('scripts/native-psutil-wheel-cache.py validate --directory .native-psutil-wheels', workflow)
        self.assertIn('scripts/native-psutil-wheel-cache.py install --directory .native-psutil-wheels', workflow)
        self.assertNotIn('${ACTIONS_CACHE_MODE', workflow)
        self.assertIn('if [ "$TRUSTED_SOURCE" = true ]; then', workflow)
        for block in workflow.split("      - uses: actions/cache/save@v4\n")[1:]:
            block = block.split("\n      - ")[0]
            self.assertIn("continue-on-error: true", block)
            self.assertIn("steps.cache-write.outputs.may_save == 'true'", block)
            self.assertIn("github.ref == 'refs/heads/main'", block)
            self.assertIn("inputs.ref == github.sha", block)
            self.assertIn("github.event_name == 'push' || github.event_name == 'workflow_dispatch'", block)
            self.assertRegex(block, r"path: \.native-(?:model-cache|psutil-wheels)\n")


class ModelFixtureTests(unittest.TestCase):
    def test_pins_match_host_and_fixture_bytes_are_shared_and_verified(self):
        host = (Path(__file__).parents[1] / "crates/core-sdk/src/cpu_model.rs").read_text()
        for value in (model.CPU_NAME, model.CPU_SHA256, str(model.CPU_SIZE)):
            self.assertIn(value, host)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "profile/models/bge-m3/onnx" / model.CPU_NAME
            source.parent.mkdir(parents=True)
            source.write_bytes(b"verified fixture container")
            shared = root / "models"
            env = {"RSRS_DATA_DIR": str(root / "profile")}
            with patch.object(model, "CPU_SIZE", source.stat().st_size), patch.object(
                    model, "CPU_SHA256", hashlib.sha256(source.read_bytes()).hexdigest()):
                model.share_cpu_container(root, env, shared)
                self.assertEqual(source.read_bytes(), (shared / "onnx" / model.CPU_NAME).read_bytes())
                model.share_cpu_container(root, env, shared)
                with self.assertRaisesRegex(RuntimeError, "owned_fixture_child"):
                    model.share_cpu_container(root, env, root.parent)
                (shared / "onnx" / model.CPU_NAME).write_bytes(b"corrupt")
                with self.assertRaisesRegex(RuntimeError, "not_fresh"):
                    model.share_cpu_container(root, env, shared)

    def test_failed_install_does_not_create_shared_container(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(RuntimeError, "missing_or_corrupt"):
                model.share_cpu_container(root, {"RSRS_DATA_DIR": str(root / "profile")}, root / "models")
            self.assertFalse((root / "models").exists())

    def test_diagnostics_keep_errno_and_redact_fixture_and_session_credentials(self):
        spec = importlib.util.spec_from_file_location("legacy", Path(__file__).with_name("dev-legacy-vault-smoke.py"))
        legacy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(legacy)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "session.json").write_text(json.dumps({"token": "private-session-token"}))
            smoke = object.__new__(legacy.Smoke)
            smoke.diagnostic_secrets = {"private-fixture-password"}
            result = subprocess.CompletedProcess([], 1, json.dumps({"errors": [
                "No such file (os error 2) private-fixture-password private-session-token Bearer private-bearer"
            ]}).encode(), b"")
            diagnostic = smoke.redacted_cli_error({"RSRS_DATA_DIR": str(root)}, result)
            self.assertIn("No such file (os error 2)", diagnostic)
            self.assertNotIn("private-", diagnostic)
            self.assertLessEqual(len(diagnostic), 1500)

    def test_diagnostics_without_data_dir_preserve_original_error(self):
        spec = importlib.util.spec_from_file_location("legacy", Path(__file__).with_name("dev-legacy-vault-smoke.py"))
        legacy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(legacy)
        smoke = object.__new__(legacy.Smoke)
        smoke.diagnostic_secrets = {"private-fixture-password"}
        result = subprocess.CompletedProcess([], 1, json.dumps({"errors": [
            "No such file (os error 2) private-fixture-password"
        ]}).encode(), b"")
        diagnostic = smoke.redacted_cli_error({}, result)
        self.assertIn("No such file (os error 2)", diagnostic)
        self.assertNotIn("private-fixture-password", diagnostic)

    def check_reporter_failure(self, filename):
        spec = importlib.util.spec_from_file_location("fixture_reporter", Path(__file__).with_name(filename))
        reporter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(reporter)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "session.json").write_text(json.dumps({"token": "private-session-token"}))
            smoke = object.__new__(reporter.Smoke)
            smoke.root = root
            smoke.args = SimpleNamespace(binary=root / "unused-fixture-cli")
            smoke.report = {}
            smoke.save = Mock()
            smoke.diagnostic_secrets = {"private-fixture-password"}
            failed = subprocess.CompletedProcess([], 1, json.dumps({"errors": [
                "No such file (os error 2) private-fixture-password private-session-token Bearer private-bearer " + "x" * 2000
            ]}).encode(), b"")
            stopped = subprocess.CompletedProcess([], 0, b"", b"")
            with patch.object(subprocess, "run", side_effect=[failed, stopped]) as run:
                with self.assertRaisesRegex(RuntimeError, "cli_failed_remember"):
                    smoke.cli({"RSRS_DATA_DIR": str(root)}, "remember", "synthetic content")
            self.assertEqual(run.call_count, 2)
            self.assertEqual(run.call_args_list[1].args[0],
                [str(smoke.args.binary), "--runtime-internal", "--stop"])
            smoke.save.assert_called()
            diagnostic = smoke.report["cli_failure"]["error"]
            self.assertIn("No such file (os error 2)", diagnostic)
            self.assertIn("[redacted]", diagnostic)
            self.assertNotIn("private-", json.dumps(smoke.report))
            self.assertLessEqual(len(diagnostic), 1500)

    def test_legacy_reporter_saves_bounded_redacted_failure(self):
        self.check_reporter_failure("dev-legacy-vault-smoke.py")

    def test_profile_reporter_saves_bounded_redacted_failure(self):
        self.check_reporter_failure("dev-profile-migration-smoke.py")


if __name__ == "__main__":
    unittest.main()
