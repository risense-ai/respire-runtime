"""Synthetic Linux PTY checks; no accounts, network, keyring or real secrets."""
import ast
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace

from dev_fixture_tty import run_hidden


def fixture_env(root):
    """Use only fresh fixture directories and non-secret execution settings."""
    env = {"PATH": os.defpath, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    for name in ("HOME", "USERPROFILE", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME",
            "APPDATA", "LOCALAPPDATA", "RSRS_DATA_DIR", "RSRS_BIN_DIR", "TMPDIR"):
        path = Path(root) / name
        path.mkdir(exist_ok=True)
        env[name] = str(path)
    env["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=" + str(Path(root) / "missing-fixture-keyring")
    return env


def descendant_exited(status):
    """Read once: reaping can remove /proc status between exists() and open()."""
    try:
        state = status.read_text()
    except FileNotFoundError:
        return True
    return "State:\tZ" in state


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux fixture driver")
class HiddenInputTests(unittest.TestCase):
    def run_fixture(self, source, prompts, timeout=3):
        """Launch a disposable Python CLI instead of the real network client."""
        with tempfile.TemporaryDirectory() as root:
            script = Path(root) / "fixture.py"
            script.write_text(source)
            return run_hidden([sys.executable, str(script)], prompts=prompts,
                cwd=root, env=fixture_env(root), timeout=timeout)

    def test_native_profile_import_does_not_require_unix_modules(self):
        """Windows profile migration can import shared helpers without Unix APIs."""
        script = """import builtins, importlib.util, pathlib, sys
original = builtins.__import__
def guarded(name, *args, **kwargs):
    if name in ('fcntl', 'pty', 'termios'):
        raise ModuleNotFoundError(name)
    return original(name, *args, **kwargs)
builtins.__import__ = guarded
path = pathlib.Path('scripts/dev-profile-migration-smoke.py')
sys.path.insert(0, str(path.parent))
spec = importlib.util.spec_from_file_location('profile_without_unix', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
import tempfile
from types import SimpleNamespace
with tempfile.TemporaryDirectory() as directory:
    args = SimpleNamespace(root=pathlib.Path(directory) / 'profile', source_sha='synthetic',
        version='synthetic', binary_sha256='synthetic')
    smoke = module.Smoke(args)
    assert smoke.report['required_cases'] == list(module.REQUIRED)
"""
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, "-c", script], capture_output=True, env=fixture_env(directory))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_post_migration_write_scope_in_full_and_focused_suites(self):
        """The real write check and report run for v2 in both workflow scopes."""
        source = Path(__file__).with_name("dev-legacy-vault-smoke.py").read_text()
        tree = ast.parse(source)
        method = next(node for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "run_version")
        guards = []
        for node in ast.walk(method):
            if not isinstance(node, ast.If):
                continue
            for statement in node.body:
                if not isinstance(statement, ast.Assign):
                    continue
                write_check = any(isinstance(target, ast.Name) and target.id == "new_title"
                    for target in statement.targets)
                report_field = any(isinstance(value, ast.Constant)
                    and value.value == "new_memory_write_sync_restart_read"
                    for target in statement.targets for value in ast.walk(target))
                if write_check or report_field:
                    guards.append(node.test)
        self.assertEqual(len(guards), 2, "write assertion and report must both retain explicit scope")
        for guard in guards:
            code = compile(ast.Expression(guard), "fixture-write-scope", "eval")
            for focused in (False, True):
                for version in (1, 2, 3):
                    with self.subTest(focused=focused, version=version):
                        fixture = SimpleNamespace(args=SimpleNamespace(auth_salt_only=focused))
                        self.assertEqual(eval(code, {"__builtins__": {}},
                            {"self": fixture, "version": version}), version == 2)

    def test_ordered_hidden_input_and_json(self):
        """Preserve JSON while submitting passwords through a no-echo terminal."""
        source = '''import json, os, sys, termios
assert os.isatty(0)
assert not termios.tcgetattr(0)[3] & (termios.ECHO | termios.ECHONL)
print("method: ", end="", flush=True)
assert sys.stdin.readline().strip() == "2"
print("password: ", end="", flush=True)
with open("/dev/tty") as tty:
    password = tty.readline().strip()
assert password == "synthetic-password"
print("super: ", end="", flush=True)
with open("/dev/tty") as tty:
    factor = tty.readline().strip()
assert factor == "synthetic-super"
assert not any(password in arg or factor in arg for arg in sys.argv)
print(json.dumps({"status": "ok"}))
'''
        result = self.run_fixture(source, [("method: ", "2"),
            ("password: ", "synthetic-password"), ("super: ", "synthetic-super")])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), b'{"status": "ok"}')
        self.assertNotIn(b"synthetic-", result.stdout + result.stderr)

    def test_accidentally_printed_input_is_redacted(self):
        """Even a faulty CLI cannot return the supplied secret as diagnostics."""
        result = self.run_fixture('import sys\nprint("password: ", end="", flush=True)\np = sys.stdin.readline().strip()\nprint(p)\nprint(p, file=sys.stderr)\nsys.exit(1)',
            [("password: ", "synthetic-password")])
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(b"synthetic-password", result.stdout + result.stderr)
        self.assertIn(b"[redacted]", result.stderr)

    def test_echo_enabled_refuses_input(self):
        """Refuse to send a secret if the child unexpectedly enables echo."""
        with self.assertRaisesRegex(RuntimeError, "fixture_tty_echo_enabled"):
            self.run_fixture('import termios,time\na=termios.tcgetattr(0)\na[3] |= termios.ECHO\ntermios.tcsetattr(0,termios.TCSANOW,a)\nprint("password: ",end="",flush=True)\ntime.sleep(10)',
                [("password: ", "synthetic-password")])

    def test_timeout_kills_child_and_releases_descriptors(self):
        """Wrong prompt order times out and leaves no child or PTY descriptor."""
        before = len(os.listdir("/proc/self/fd"))
        with tempfile.TemporaryDirectory() as root:
            pidfile = Path(root) / "pid"
            script = Path(root) / "fixture.py"
            script.write_text('import os,time\nopen("pid","w").write(str(os.getpid()))\nprint("unexpected prompt",flush=True)\ntime.sleep(20)')
            with self.assertRaisesRegex(RuntimeError, "fixture_tty_timeout"):
                run_hidden([sys.executable, str(script)], prompts=[("password: ", "synthetic-password")],
                    cwd=root, env=fixture_env(root), timeout=0.3)
            self.assertFalse(Path("/proc", pidfile.read_text()).exists())
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_timeout_kills_descendants_holding_output_pipes(self):
        """A sleeping descendant cannot keep the driver or its output pipes alive."""
        def disappeared():
            raise FileNotFoundError("synthetic reaped descendant")

        def denied():
            raise PermissionError("synthetic inaccessible status")

        self.assertTrue(descendant_exited(SimpleNamespace(read_text=disappeared)))
        self.assertTrue(descendant_exited(SimpleNamespace(read_text=lambda: "State:\tZ (zombie)\n")))
        self.assertFalse(descendant_exited(SimpleNamespace(read_text=lambda: "State:\tS (sleeping)\n")))
        with self.assertRaises(PermissionError):
            descendant_exited(SimpleNamespace(read_text=denied))
        with tempfile.TemporaryDirectory() as root:
            script = Path(root) / "fixture.py"
            script.write_text("import subprocess,sys,time\nchild=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])\nopen('child','w').write(str(child.pid))\ntime.sleep(30)")
            with self.assertRaisesRegex(RuntimeError, "fixture_tty_timeout"):
                run_hidden([sys.executable, str(script)], prompts=[], cwd=root,
                    env=fixture_env(root), timeout=0.3)
            status = Path("/proc", (Path(root) / "child").read_text(), "status")
            for _ in range(50):
                if descendant_exited(status):
                    break
                time.sleep(0.01)
            else:
                self.fail("fixture descendant remained running after timeout")

    def test_success_requires_all_prompts(self):
        """A skipped authorization prompt must not silently pass."""
        with self.assertRaisesRegex(RuntimeError, "fixture_tty_missing_prompt"):
            self.run_fixture('print("{}")', [("password: ", "synthetic-password")])

    def test_argv_secret_flags_rejected_before_spawn(self):
        """Legacy secret flags are rejected before creating a process."""
        for flag in ("--pass", "--super", "--secret-key", "--new-super"):
            with self.subTest(flag=flag), self.assertRaisesRegex(RuntimeError, "fixture_secret_argument_forbidden"):
                run_hidden(["unused", flag + "=synthetic"], prompts=[], cwd="/", env={}, timeout=1)


if __name__ == "__main__":
    unittest.main()
