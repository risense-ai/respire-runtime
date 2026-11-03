"""Native credentials for disposable hosted migration fixtures, never user secrets.

macOS fixtures explicitly allow their synthetic secrets to the test binary. This
does not prove that a real legacy Keychain ACL will avoid an authorization prompt.
"""
import ctypes
import errno
import hashlib
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import subprocess
import sys


def require(value, code):
    if not value:
        raise RuntimeError(code)


def owned_path(path):
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
            "disposable_hosted_runner_required")
    temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    value = Path(path).resolve()
    require(value != temp and value.is_relative_to(temp), "fixture_path_outside_runner_temp")
    for home in (os.environ.get("HOME"), os.environ.get("USERPROFILE")):
        if home:
            require(value != Path(home).resolve(), "fixture_cannot_use_runner_home")
    return value


def canonical_identity(path):
    if sys.platform != "win32":
        value = str(Path(path).resolve(strict=True)).replace("\\", "/")
    else:
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                      ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR,
                                                   wintypes.DWORD, wintypes.DWORD]
        kernel.GetFinalPathNameByHandleW.restype = wintypes.DWORD
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        handle = kernel.CreateFileW(str(Path(path).absolute()), 0, 7, None, 3, 0x02000000, None)
        require(handle not in (None, ctypes.c_void_p(-1).value), "fixture_canonical_open_failed")
        try:
            size = kernel.GetFinalPathNameByHandleW(handle, None, 0, 0)
            require(size > 0, "fixture_canonical_size_failed")
            buffer = ctypes.create_unicode_buffer(size + 1)
            written = kernel.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
            require(0 < written < len(buffer), "fixture_canonical_read_failed")
            value = buffer.value.replace("\\", "/").translate(
                str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"))
        finally:
            kernel.CloseHandle(handle)
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class TrackedKeys:
    def __init__(self, root):
        self.root = root
        self.entries = set()

    def configure_env(self, env):
        owned_path(env["HOME"])
        return env

    def reserve(self, service, slot):
        require(service in ("1memory", "memocap", "respire", "rsrs")
                and re.fullmatch(r"(?:super|pass):(?:ci-migrate-[a-f0-9]{16}|legacy-[a-f0-9]{16})", slot),
                "credential_name_not_a_migration_fixture")
        entry = (service, slot)
        if entry in self.entries:
            return
        require(self._read(service, slot) is None, "fixture_credential_already_exists")
        self.entries.add(entry)

    def read(self, service, slot):
        require((service, slot) in self.entries, "credential_not_owned_by_fixture")
        value = self._read(service, slot)
        require(value is not None, "fixture_credential_missing")
        return value

    def track_created_login(self, session, user, super_password, login_password):
        # Claim only the exact alias returned by this owned fixture's successful
        # login transaction, never enumerate credentials on the host.
        require(re.fullmatch(r"ci-migrate-[a-f0-9]{16}", user)
                and session.get("user") == user, "login_credential_fixture_identity_mismatch")
        alias = session.get("keyring_account")
        require(isinstance(alias, str) and re.fullmatch(r"login-[a-f0-9]{32}", alias),
                "login_credential_fixture_alias_invalid")
        for prefix, expected in (("super:", super_password), ("pass:", login_password)):
            if expected is None:
                continue
            entry = ("rsrs", prefix + alias)
            require(entry not in self.entries and self._read(*entry) is not None,
                    "login_credential_fixture_alias_not_created")
            self.entries.add(entry)
            # macOS keeps the product ACL unchanged; the CLI consumer verifies
            # its values separately, while metadata suffices for exact cleanup.
            if sys.platform != "darwin":
                require(self.read(*entry) == expected, "login_credential_fixture_value_changed")

    def put(self, service, slot, value):
        self.reserve(service, slot)
        self._put(service, slot, value)
        require(self.read(service, slot) == value, "fixture_credential_readback_mismatch")

    def remove(self, service, slot):
        require((service, slot) in self.entries, "credential_not_owned_by_fixture")
        self._remove(service, slot)
        require(self._read(service, slot) is None, "fixture_credential_delete_readback_failed")

    def cleanup(self):
        events, remaining = [], []
        for index, (service, slot) in enumerate(sorted(self.entries)):
            try:
                self.remove(service, slot)
                events.append({"entry": index, "passed": True, "code": "credential_removed"})
            except Exception:
                event = {"entry": index, "passed": False, "code": "credential_cleanup_failed"}
                events.append(event)
                remaining.append(event)
        return {"passed": not remaining, "remaining_entries": remaining, "events": events}


class LinuxKeys(TrackedKeys):
    name = "linux-keyutils"
    no_entry_errors = (getattr(errno, "ENOKEY", 126), errno.EACCES,
                       getattr(errno, "EKEYREVOKED", 128), getattr(errno, "EKEYEXPIRED", 127))

    def __init__(self, root):
        super().__init__(root)
        self.lib = ctypes.CDLL("libkeyutils.so.1", use_errno=True)
        signatures = {
            "keyctl_get_persistent": ([ctypes.c_uint, ctypes.c_int32], ctypes.c_long),
            "add_key": ([ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p,
                         ctypes.c_size_t, ctypes.c_int32], ctypes.c_int32),
            "keyctl_search": ([ctypes.c_int32, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int32], ctypes.c_long),
            "keyctl_read": ([ctypes.c_int32, ctypes.c_void_p, ctypes.c_size_t], ctypes.c_long),
            "keyctl_unlink": ([ctypes.c_int32, ctypes.c_int32], ctypes.c_long),
            "keyctl_invalidate": ([ctypes.c_int32], ctypes.c_long),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.lib, name)
            function.argtypes, function.restype = args, result
        self.ring = self.lib.keyctl_get_persistent(ctypes.c_uint(-1).value, -3)
        require(self.ring > 0, "fixture_persistent_keyring_unavailable")

    def _find(self, service, slot):
        description = f"keyring-rs:{slot}@{service}".encode()
        key = self.lib.keyctl_search(self.ring, b"user", description, 0)
        if key < 0:
            error = ctypes.get_errno()
            # Match keyring 3.6.3's NoEntry mapping for exact allowlisted fixture
            # descriptions. Reads after a positive lookup remain strict.
            require(error in self.no_entry_errors, f"fixture_keyring_search_failed_errno_{error}")
            return None
        return key

    def _read(self, service, slot):
        key = self._find(service, slot)
        if key is None:
            return None
        if (service, slot) not in self.entries:
            return ""
        size = self.lib.keyctl_read(key, None, 0)
        require(0 <= size < 65536, "fixture_credential_size_invalid")
        buffer = ctypes.create_string_buffer(size)
        require(self.lib.keyctl_read(key, buffer, size) == size, "fixture_credential_read_failed")
        return buffer.raw.decode("utf-8")

    def _put(self, service, slot, value):
        payload = value.encode("utf-8")
        buffer = ctypes.create_string_buffer(payload)
        key = self.lib.add_key(b"user", f"keyring-rs:{slot}@{service}".encode(),
                               buffer, len(payload), self.ring)
        require(key > 0, "fixture_credential_write_failed")

    def _remove(self, service, slot):
        key = self._find(service, slot)
        if key is not None:
            result = self.lib.keyctl_unlink(key, self.ring)
            error = ctypes.get_errno()
            require(result == 0, f"fixture_credential_unlink_failed_errno_{error}")
            # Unlink first so the persistent ring cannot retain an invalidated
            # reference. Last-reference collection may already remove the key.
            result = self.lib.keyctl_invalidate(key)
            error = ctypes.get_errno()
            require(result == 0 or error in self.no_entry_errors,
                    f"fixture_credential_invalidate_failed_errno_{error}")


class WindowsKeys(TrackedKeys):
    name = "windows-credential-manager"

    def __init__(self, root):
        super().__init__(root)
        from ctypes import wintypes

        class Credential(ctypes.Structure):
            _fields_ = [("Flags", wintypes.DWORD), ("Type", wintypes.DWORD),
                        ("TargetName", wintypes.LPWSTR), ("Comment", wintypes.LPWSTR),
                        ("LastWritten", wintypes.FILETIME), ("CredentialBlobSize", wintypes.DWORD),
                        ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)), ("Persist", wintypes.DWORD),
                        ("AttributeCount", wintypes.DWORD), ("Attributes", ctypes.c_void_p),
                        ("TargetAlias", wintypes.LPWSTR), ("UserName", wintypes.LPWSTR)]

        self.Credential = Credential
        self.pointer = ctypes.POINTER(Credential)
        self.lib = ctypes.WinDLL("advapi32", use_last_error=True)
        self.lib.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                      ctypes.POINTER(self.pointer)]
        self.lib.CredReadW.restype = wintypes.BOOL
        self.lib.CredWriteW.argtypes = [self.pointer, wintypes.DWORD]
        self.lib.CredWriteW.restype = wintypes.BOOL
        self.lib.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
        self.lib.CredDeleteW.restype = wintypes.BOOL
        self.lib.CredFree.argtypes, self.lib.CredFree.restype = [ctypes.c_void_p], None

    def _read(self, service, slot):
        pointer = self.pointer()
        if not self.lib.CredReadW(f"{slot}.{service}", 1, 0, ctypes.byref(pointer)):
            require(ctypes.get_last_error() == 1168, "fixture_credential_read_failed")
            return None
        try:
            value = pointer.contents
            if (service, slot) not in self.entries:
                return ""
            require(value.CredentialBlobSize < 65536, "fixture_credential_size_invalid")
            return ctypes.string_at(value.CredentialBlob, value.CredentialBlobSize).decode("utf-16-le")
        finally:
            self.lib.CredFree(pointer)

    def _put(self, service, slot, value):
        payload = value.encode("utf-16-le")
        buffer = (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload)
        credential = self.Credential()
        credential.Type, credential.Persist = 1, 3
        credential.TargetName, credential.UserName = f"{slot}.{service}", slot
        credential.CredentialBlobSize, credential.CredentialBlob = len(payload), buffer
        require(self.lib.CredWriteW(ctypes.byref(credential), 0), "fixture_credential_write_failed")

    def _remove(self, service, slot):
        if not self.lib.CredDeleteW(f"{slot}.{service}", 1, 0):
            require(ctypes.get_last_error() == 1168, "fixture_credential_delete_failed")


class MacKeys(TrackedKeys):
    name = "macos-keychain-synthetic-acl"

    def __init__(self, root):
        super().__init__(root)
        self.homes = {}
        self.configured = set()
        self.keychain = root / "fixture.keychain-db"
        self.password = secrets.token_urlsafe(32)
        self.created = False
        try:
            self._capture_home(root)
            result = self._security(root, ["create-keychain", "-p", self.password, str(self.keychain)])
            require(result.returncode == 0, "fixture_keychain_create_failed")
            self.created = True
            require(self._security(root, ["unlock-keychain", "-p", self.password,
                                         str(self.keychain)]).returncode == 0, "fixture_keychain_unlock_failed")
            require(self._security(root, ["set-keychain-settings", "-t", "7200", "-u",
                                         str(self.keychain)]).returncode == 0, "fixture_keychain_settings_failed")
            self.configure_env({"HOME": str(root)})
        except Exception:
            self.created = self.created or self.keychain.exists()
            self.cleanup()
            raise RuntimeError("fixture_keychain_initialization_failed") from None

    def _security(self, home, args):
        home = owned_path(home)
        env = dict(os.environ, HOME=str(home), USERPROFILE=str(home))
        try:
            return subprocess.run(["/usr/bin/security", *args], env=env, capture_output=True, timeout=20)
        except subprocess.TimeoutExpired:
            operations = {"create-keychain", "unlock-keychain", "set-keychain-settings",
                          "list-keychains", "default-keychain", "find-generic-password",
                          "add-generic-password", "delete-generic-password", "delete-keychain"}
            operation = args[0] if args and args[0] in operations else "unknown-operation"
            raise RuntimeError("fixture_native_security_timeout_" + operation) from None

    def _capture_home(self, home):
        if home in self.homes:
            return
        preferences = home / "Library/Preferences/com.apple.security.plist"
        require(not preferences.is_symlink(), "fixture_preferences_link_rejected")
        before = preferences.read_bytes() if preferences.is_file() else None
        listed = self._security(home, ["list-keychains", "-d", "user"])
        default = self._security(home, ["default-keychain", "-d", "user"])
        require(listed.returncode == 0, "fixture_keychain_list_failed")
        old_list = shlex.split(listed.stdout.decode("utf-8"))
        old_default = shlex.split(default.stdout.decode("utf-8")) if default.returncode == 0 else []
        self.homes[home] = (preferences, before, old_list, old_default)

    def configure_env(self, env):
        home = owned_path(env["HOME"])
        if home in self.configured:
            return env
        self._capture_home(home)
        preferences = self.homes[home][0]
        preferences.parent.mkdir(parents=True, exist_ok=True)
        require(self._security(home, ["list-keychains", "-d", "user", "-s",
                                     str(self.keychain)]).returncode == 0, "fixture_keychain_search_setup_failed")
        require(self._security(home, ["default-keychain", "-d", "user", "-s",
                                     str(self.keychain)]).returncode == 0, "fixture_keychain_default_setup_failed")
        selected = self._security(home, ["default-keychain", "-d", "user"])
        require(selected.returncode == 0
                and shlex.split(selected.stdout.decode("utf-8")) == [str(self.keychain)],
                "fixture_keychain_default_readback_failed")
        listed = self._security(home, ["list-keychains", "-d", "user"])
        require(listed.returncode == 0
                and shlex.split(listed.stdout.decode("utf-8")) == [str(self.keychain)],
                "fixture_keychain_search_readback_failed")
        self.configured.add(home)
        return env

    def _read(self, service, slot):
        metadata = self._security(self.root, ["find-generic-password", "-s", service,
                                             "-a", slot, str(self.keychain)])
        if metadata.returncode == 44:
            return None
        require(metadata.returncode == 0, "fixture_credential_metadata_failed")
        if (service, slot) not in self.entries:
            return ""
        result = self._security(self.root, ["find-generic-password", "-s", service,
                                           "-a", slot, "-w", str(self.keychain)])
        if result.returncode == 44:
            return None
        require(result.returncode == 0, "fixture_credential_read_failed")
        return result.stdout.decode("utf-8").removesuffix("\n")

    def _put(self, service, slot, value):
        # -A is deliberate only for synthetic CI secrets, not a product ACL change.
        result = self._security(self.root, ["add-generic-password", "-U", "-s", service,
                                           "-a", slot, "-w", value, "-A", str(self.keychain)])
        require(result.returncode == 0, "fixture_credential_write_failed")

    def _remove(self, service, slot):
        result = self._security(self.root, ["delete-generic-password", "-s", service,
                                           "-a", slot, str(self.keychain)])
        require(result.returncode in (0, 44), "fixture_credential_delete_failed")

    def cleanup(self):
        report = super().cleanup()
        if self.created:
            try:
                require(self._security(self.root, ["delete-keychain", str(self.keychain)]).returncode == 0
                        and not self.keychain.exists(), "fixture_keychain_delete_failed")
                self.created = False
            except Exception:
                report["passed"] = False
                report["events"].append({"passed": False, "code": "fixture_keychain_cleanup_failed"})
                report["remaining_entries"].append({"code": "fixture_keychain_cleanup_failed"})
        for home, (preferences, before, old_list, old_default) in reversed(list(self.homes.items())):
            try:
                require(self._security(home, ["list-keychains", "-d", "user", "-s",
                                             *old_list]).returncode == 0, "fixture_keychain_list_restore_failed")
                if old_default:
                    require(len(old_default) == 1 and self._security(home,
                        ["default-keychain", "-d", "user", "-s", *old_default]).returncode == 0,
                        "fixture_keychain_default_restore_failed")
                if before is None:
                    preferences.unlink(missing_ok=True)
                else:
                    preferences.write_bytes(before)
                require((preferences.read_bytes() if preferences.exists() else None) == before,
                        "fixture_preferences_restore_readback_failed")
            except Exception:
                report["passed"] = False
                report["events"].append({"passed": False, "code": "fixture_preferences_restore_failed"})
                report["remaining_entries"].append({"code": "fixture_preferences_restore_failed"})
        return report


def create(root):
    root = owned_path(root)
    require(not root.exists(), "fixture_keyring_home_not_fresh")
    root.mkdir(parents=True, mode=0o700)
    manager = LinuxKeys if sys.platform.startswith("linux") else (
        WindowsKeys if sys.platform == "win32" else MacKeys if sys.platform == "darwin" else None)
    require(manager is not None, "fixture_keyring_platform_unsupported")
    try:
        return manager(root)
    except Exception:
        # This directory was absent before this call and contains only manager
        # initialization files. MacKeys already restores its fixture preferences.
        require(not root.is_symlink() and owned_path(root) == root,
                "fixture_partial_cleanup_path_changed")
        shutil.rmtree(root)
        raise RuntimeError("fixture_keyring_initialization_failed") from None
