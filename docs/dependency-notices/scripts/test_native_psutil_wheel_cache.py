import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch


spec = importlib.util.spec_from_file_location("native_psutil_wheel_cache", Path(__file__).with_name("native-psutil-wheel-cache.py"))
cache = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cache)


class NativePsutilWheelCacheTest(unittest.TestCase):
    def setUp(self):
        self.inputs = {
            "source_url": cache.SOURCE_URL, "source_sha256": cache.SOURCE_SHA256,
            "architecture": "x64", "python_version": "3.12.12 (fixture)",
            "implementation": "cpython", "cache_tag": "cpython-312", "soabi": "cp312-win_amd64",
            "extension_suffix": ".cp312-win_amd64.pyd", "python_platform": "win-amd64",
            "tools": {"pip": "25.3", "setuptools": "80.9.0", "wheel": "0.45.1", "packaging": "24.0"},
            "recipe_sha256": "a" * 64,
        }

    def fixture(self, directory, name="psutil-7.2.2-cp37-abi3-win_amd64.whl"):
        directory.mkdir()
        wheel = directory / name
        wheel.write_bytes(b"local fake wheel; pip is mocked")
        manifest = {"schema_version": 1, "inputs": copy.deepcopy(self.inputs),
                    "wheel": {"name": name, "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest()}}
        (directory / cache.MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")
        return wheel, manifest

    def test_key_binds_every_input_and_has_key_only_stdout(self):
        original = cache.cache_key(self.inputs)
        for name in self.inputs:
            changed = copy.deepcopy(self.inputs)
            changed[name] = "different"
            with self.subTest(name=name):
                self.assertNotEqual(cache.cache_key(changed), original)
        with patch.object(cache, "build_inputs", return_value=self.inputs), \
                patch.object(sys, "argv", ["helper", "key"]), contextlib.redirect_stdout(io.StringIO()) as output:
            cache.main()
        self.assertEqual(output.getvalue(), original + "\n")

    def test_actual_interpreter_architecture_abi_and_tools_are_bound(self):
        with patch.object(sys, "prefix", "isolated-fixture"), \
                patch.object(cache, "native_architecture", return_value="arm64"), \
                patch.object(cache.sysconfig, "get_platform", return_value="win-arm64"), \
                patch.object(cache.importlib.metadata, "version", side_effect=lambda name: "fixed-" + name):
            inputs = cache.build_inputs()
        self.assertEqual(inputs["architecture"], "arm64")
        self.assertEqual(inputs["python_version"], sys.version)
        self.assertEqual(inputs["soabi"], cache.sysconfig.get_config_var("SOABI"))
        self.assertEqual(inputs["cache_tag"], sys.implementation.cache_tag)
        self.assertEqual(inputs["tools"], {name: "fixed-" + name for name in ["pip", "setuptools", "wheel", "packaging"]})
        self.assertEqual(inputs["source_sha256"], cache.SOURCE_SHA256)
        self.assertEqual(inputs["recipe_sha256"], hashlib.sha256(Path(cache.__file__).read_bytes()).hexdigest())
        with patch.object(sys, "prefix", sys.base_prefix), self.assertRaisesRegex(ValueError, "venv"):
            cache.build_inputs()
        with patch.object(sys, "prefix", "isolated-fixture"), \
                patch.object(cache, "native_architecture", return_value="arm64"), \
                patch.object(cache.sysconfig, "get_platform", return_value="win-amd64"), \
                self.assertRaisesRegex(ValueError, "architecture"):
            cache.build_inputs()

    def test_packaging_version_alone_changes_key_and_rejects_old_provenance(self):
        identities = []
        for version in ["24.0", "26.3"]:
            with patch.object(sys, "prefix", "isolated-fixture"), \
                    patch.object(cache, "native_architecture", return_value="x64"), \
                    patch.object(cache.sysconfig, "get_platform", return_value="win-amd64"), \
                    patch.object(cache.importlib.metadata, "version", side_effect=lambda name: version if name == "packaging" else "fixed-" + name):
                identities.append(cache.build_inputs())
        old, current = identities
        self.assertNotEqual(cache.cache_key(old), cache.cache_key(current))
        expected = copy.deepcopy(old)
        expected["tools"]["packaging"] = "26.3"
        self.assertEqual(current, expected)
        for omit_packaging in [False, True]:
            with self.subTest(omit_packaging=omit_packaging), tempfile.TemporaryDirectory() as temporary:
                self.inputs = copy.deepcopy(old)
                if omit_packaging:
                    del self.inputs["tools"]["packaging"]
                directory = Path(temporary) / "wheelhouse"
                self.fixture(directory)
                with patch.object(cache, "pip") as pip, self.assertRaisesRegex(ValueError, "provenance differs"):
                    cache.validate(directory, current)
                pip.assert_not_called()

    def test_native_architecture_uses_windows_api_and_rejects_emulation(self):
        for native, process, expected in [(0x8664, 0, "x64"), (0xAA64, 0, "arm64"),
                                           (0xAA64, 0x8664, None), (0x014C, 0, None)]:
            kernel = Mock()
            def machine_types(handle, process_out, native_out):
                process_out._obj.value = process
                native_out._obj.value = native
                return 1
            kernel.IsWow64Process2.side_effect = machine_types
            with self.subTest(native=native, process=process), patch.object(sys, "platform", "win32"), \
                    patch.object(cache.ctypes, "WinDLL", return_value=kernel, create=True):
                if expected:
                    self.assertEqual(cache.native_architecture(), expected)
                else:
                    with self.assertRaisesRegex(ValueError, "emulation"):
                        cache.native_architecture()

    def test_build_uses_fixed_source_hash_and_saves_only_one_wheel_and_manifest(self):
        calls = []
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "wheelhouse"
            def pip(*arguments):
                calls.append(arguments)
                if arguments[0] == "wheel":
                    destination = Path(arguments[arguments.index("--wheel-dir") + 1])
                    (destination / "psutil-7.2.2-cp37-abi3-win_amd64.whl").write_bytes(b"built fake wheel")
            with patch.object(cache, "pip", side_effect=pip):
                cache.build(directory, self.inputs)
                wheel = cache.validate(directory, self.inputs)
            self.assertEqual({path.name for path in directory.iterdir()}, {cache.MANIFEST, wheel.name})
            self.assertEqual(calls[0][-1], cache.SOURCE_URL + "#sha256=" + cache.SOURCE_SHA256)
            self.assertTrue({"--no-index", "--no-deps", "--no-build-isolation", "--no-cache-dir"}.issubset(calls[0]))
            self.assertEqual(calls[1][0], "install")
            self.assertIn("--dry-run", calls[1])
            self.assertIn("--no-index", calls[1])
            with self.assertRaisesRegex(ValueError, "empty"):
                cache.build(directory, self.inputs)

    def test_validate_rejects_any_changed_source_interpreter_or_tool_input(self):
        for name in self.inputs:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary) / "wheelhouse"
                _, manifest = self.fixture(directory)
                manifest["inputs"][name] = "wrong"
                (directory / cache.MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")
                with patch.object(cache, "pip") as pip, self.assertRaisesRegex(ValueError, "provenance differs"):
                    cache.validate(directory, self.inputs)
                pip.assert_not_called()

    def test_failed_build_leaves_no_usable_provenance(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "wheelhouse"
            with patch.object(cache, "pip", side_effect=subprocess.CalledProcessError(1, ["fake-pip"])), \
                    self.assertRaises(subprocess.CalledProcessError):
                cache.build(directory, self.inputs)
            self.assertEqual(list(directory.iterdir()), [])
            with self.assertRaisesRegex(ValueError, "provenance"):
                cache.validate(directory, self.inputs)

    def test_validate_rejects_modified_bytes_extra_wheels_and_other_files(self):
        for change in ["bytes", "extra-wheel", "session.json", "directory"]:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary) / "wheelhouse"
                wheel, _ = self.fixture(directory)
                if change == "bytes":
                    wheel.write_bytes(b"tampered")
                elif change == "directory":
                    (directory / "extra").mkdir()
                else:
                    (directory / ("extra.whl" if change == "extra-wheel" else change)).write_bytes(b"unexpected")
                with patch.object(cache, "pip") as pip, self.assertRaises(ValueError):
                    cache.validate(directory, self.inputs)
                pip.assert_not_called()

    def test_wrong_architecture_and_non_psutil_wheels_fail_before_pip(self):
        for name in ["psutil-7.2.2-cp37-abi3-win_arm64.whl", "foreign-7.2.2-cp37-abi3-win_amd64.whl"]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary) / "wheelhouse"
                self.fixture(directory, name)
                with patch.object(cache, "pip") as pip, self.assertRaisesRegex(ValueError, "platform differs"):
                    cache.validate(directory, self.inputs)
                pip.assert_not_called()

    def test_pip_compatibility_failure_prevents_install(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "wheelhouse"
            self.fixture(directory, "psutil-7.2.2-cp999-cp999-win_amd64.whl")
            with patch.object(cache, "build_inputs", return_value=self.inputs), \
                    patch.object(sys, "argv", ["helper", "install", "--directory", str(directory)]), \
                    patch.object(cache, "pip", side_effect=subprocess.CalledProcessError(1, ["fake-pip"])) as pip, \
                    self.assertRaises(subprocess.CalledProcessError):
                cache.main()
            self.assertEqual(pip.call_count, 1)
            self.assertIn("--dry-run", pip.call_args.args)

    def test_install_revalidates_then_forces_offline_dependency_free_install(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "wheelhouse"
            wheel, _ = self.fixture(directory)
            with patch.object(cache, "build_inputs", return_value=self.inputs), \
                    patch.object(sys, "argv", ["helper", "install", "--directory", str(directory)]), \
                    patch.object(cache, "pip") as pip:
                cache.main()
            self.assertEqual(pip.call_count, 2)
            self.assertIn("--dry-run", pip.call_args_list[0].args)
            install = pip.call_args_list[1].args
            self.assertNotIn("--dry-run", install)
            self.assertTrue({"--force-reinstall", "--no-user", "--no-index", "--no-deps", "--no-cache-dir"}.issubset(install))
            self.assertEqual(install[-1], str(wheel.resolve()))

    def test_pip_uses_the_current_interpreter_and_isolated_configuration(self):
        with patch.object(cache.subprocess, "run") as run:
            cache.pip("install", "--no-index", "--no-deps", "fixture.whl")
        self.assertEqual(run.call_args.args[0][:5], [sys.executable, "-m", "pip", "--isolated", "--disable-pip-version-check"])
        self.assertTrue(run.call_args.kwargs["check"])


if __name__ == "__main__":
    unittest.main()
