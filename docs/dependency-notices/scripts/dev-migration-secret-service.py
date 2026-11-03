"""Real Secret Service fixtures on a private hosted D-Bus session only."""
import importlib.util
from importlib.metadata import version
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time

_spec = importlib.util.spec_from_file_location(
    "migration_native_fixture_keys", Path(__file__).with_name("dev-migration-keyring.py"))
_base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_base)
require = _base.require
owned_path = _base.owned_path
canonical_identity = _base.canonical_identity


class SecretServiceKeys(_base.TrackedKeys):
    name = "linux-secret-service"

    def __init__(self, root):
        super().__init__(root)
        self.daemon = None
        self.connection = None
        self.attribute_snapshots = {}
        self.current_target_entries = set()
        self.generic_schema_observed = set()
        self.normalized_current_entries = set()
        self.bus = os.environ.get("DBUS_SESSION_BUS_ADDRESS", "")
        require(sys.platform.startswith("linux")
                and os.environ.get("RSRS_SS_FIXTURE_BUS") == "private"
                and self.bus.startswith("unix:"), "private_fixture_session_bus_required")
        require(version("SecretStorage") == "3.3.3" and version("jeepney") == "0.9.0",
                "secret_service_fixture_dependencies_not_pinned")
        import secretstorage
        from jeepney import DBusAddress, new_method_call
        self.secretstorage = secretstorage
        try:
            self.connection = secretstorage.dbus_init()
            address = DBusAddress("/org/freedesktop/DBus", "org.freedesktop.DBus",
                                  "org.freedesktop.DBus")
            reply = self.connection.send_and_get_reply(new_method_call(
                address, "NameHasOwner", "s", ("org.freedesktop.secrets",)))
            require(reply.body == (False,), "fixture_bus_already_has_secret_service")
            control = root / "control"
            control.mkdir(mode=0o700)
            env = dict(os.environ, HOME=str(root), USERPROFILE=str(root),
                       XDG_DATA_HOME=str(root / "data"), XDG_CONFIG_HOME=str(root / "config"),
                       XDG_CACHE_HOME=str(root / "cache"), XDG_RUNTIME_DIR=str(control),
                       DBUS_SESSION_BUS_ADDRESS=self.bus)
            env.pop("GNOME_KEYRING_CONTROL", None)
            for key in ("SSH_AUTH_SOCK", "GNOME_KEYRING_PID"):
                env.pop(key, None)
            self.daemon = subprocess.Popen([
                "gnome-keyring-daemon", "--foreground", "--unlock", "--components=secrets",
                "--control-directory", str(control)], env=env, stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.daemon.stdin.write(secrets.token_urlsafe(32).encode("utf-8"))
            self.daemon.stdin.close()
            deadline = time.monotonic() + 10
            while True:
                require(self.daemon.poll() is None, "fixture_secret_service_daemon_exited")
                owner = self.connection.send_and_get_reply(new_method_call(
                    address, "NameHasOwner", "s", ("org.freedesktop.secrets",)))
                if owner.body != (True,):
                    require(time.monotonic() < deadline, "fixture_secret_service_owner_not_ready")
                    time.sleep(0.05)
                    continue
                owner_pid = self.connection.send_and_get_reply(new_method_call(
                    address, "GetConnectionUnixProcessID", "s", ("org.freedesktop.secrets",)))
                require(owner_pid.body == (self.daemon.pid,), "fixture_secret_service_owner_mismatch")
                # Do not address Secret Service until our foreground process owns
                # its bus name: an earlier call could autoactivate a runner daemon.
                try:
                    self.collection = secretstorage.get_collection_by_alias(self.connection, "default")
                    require(not self.collection.is_locked(), "fixture_default_collection_locked")
                    require(not list(self.collection.get_all_items()), "fixture_default_collection_not_empty")
                    break
                except (secretstorage.exceptions.ItemNotFoundException,
                        secretstorage.exceptions.SecretServiceNotAvailableException):
                    require(time.monotonic() < deadline, "fixture_default_collection_not_ready")
                    time.sleep(0.05)
        except Exception as error:
            fixed_codes = {
                "fixture_bus_already_has_secret_service", "fixture_secret_service_daemon_exited",
                "fixture_secret_service_owner_not_ready", "fixture_secret_service_owner_mismatch",
                "fixture_default_collection_locked", "fixture_default_collection_not_ready",
                "fixture_default_collection_not_empty",
            }
            code = str(error) if isinstance(error, RuntimeError) and str(error) in fixed_codes \
                else "fixture_secret_service_initialization_failed"
            try:
                cleanup_passed = self.cleanup()["passed"]
            except Exception:
                cleanup_passed = False
            if not cleanup_passed:
                code += "_cleanup_failed"
            raise RuntimeError(code) from None

    def configure_env(self, env):
        super().configure_env(env)
        env["DBUS_SESSION_BUS_ADDRESS"] = self.bus
        env["RSRS_SS_FIXTURE_BUS"] = "private"
        return env

    @staticmethod
    def attributes(service, slot):
        return {"target": "default", "service": service, "username": slot,
                "application": "rust-keyring"}

    def register_current_target(self, user):
        require(not self.current_target_entries and re.fullmatch(r"ci-migrate-[a-f0-9]{16}", user),
                "fixture_current_target_registration_invalid")
        entries = {("rsrs", prefix + user) for prefix in ("super:", "pass:")}
        for entry in entries:
            require(entry in self.entries and entry not in self.attribute_snapshots
                    and self._find(*entry, check_snapshot=False) is None,
                    "fixture_current_target_not_fresh_owned_entry")
        self.current_target_entries.update(entries)

    def _find(self, service, slot, check_snapshot=True):
        expected = self.attributes(service, slot)
        lookup = {key: expected[key] for key in ("target", "service", "username")}
        items = list(self.collection.search_items(lookup))
        require(len(items) <= 1, "fixture_secret_service_entry_ambiguous")
        if not items:
            return None
        item = items[0]
        # Unreserved collisions only establish existence, never read their secret.
        if (service, slot) in self.entries:
            actual = item.get_attributes()
            require(all(actual.get(key) == value for key, value in expected.items()),
                    "fixture_secret_service_attributes_mismatch")
            if check_snapshot:
                snapshot = self.attribute_snapshots.setdefault((service, slot), dict(actual))
                compared_actual, compared_snapshot = actual, snapshot
                entry = (service, slot)
                if entry in self.current_target_entries:
                    # GNOME maps both an omitted schema and exact Generic to
                    # persisted type 0. Preserve the first raw snapshot; only
                    # these two newly registered target entries use this baseline.
                    generic = "org.freedesktop.Secret.Generic"
                    require(("xdg:schema" not in snapshot or snapshot["xdg:schema"] == generic)
                            and ("xdg:schema" not in actual or actual["xdg:schema"] == generic),
                            "fixture_current_target_schema_not_generic")
                    present = "xdg:schema" in actual
                    require(present or entry not in self.generic_schema_observed,
                            "fixture_current_target_schema_reverted")
                    if present:
                        self.generic_schema_observed.add(entry)
                        if "xdg:schema" not in snapshot:
                            self.normalized_current_entries.add(entry)
                    compared_actual = dict(actual, **{"xdg:schema": generic})
                    compared_snapshot = dict(snapshot, **{"xdg:schema": generic})
                if compared_actual != compared_snapshot:
                    changed = {key for key in actual.keys() | snapshot.keys()
                               if actual.get(key) != snapshot.get(key)}
                    known = {"target", "service", "username", "application", "xdg:schema"}
                    names = "_".join(sorted(changed & known)) or "none"
                    raise RuntimeError("fixture_secret_service_attributes_changed_keys_" + names
                                       + "_unknown_count_" + str(len(changed - known))
                                       + "_schema_was_absent_" + str(int("xdg:schema" not in snapshot))
                                       + "_schema_is_generic_" + str(int(actual.get("xdg:schema")
                                           == "org.freedesktop.Secret.Generic")))
            require(not item.is_locked(), "fixture_secret_service_entry_locked")
        return item

    def _read(self, service, slot):
        item = self._find(service, slot)
        if item is None:
            return None
        if (service, slot) not in self.entries:
            return ""
        return item.get_secret().decode("utf-8")

    def _put(self, service, slot, value):
        require((service, slot) in self.entries, "credential_not_owned_by_fixture")
        item = self._find(service, slot)
        if item is not None:
            item.set_secret(value.encode("utf-8"))
        else:
            attributes = dict(self.attributes(service, slot),
                              **{"xdg:schema": "org.freedesktop.Secret.Generic"})
            self.collection.create_item("Synthetic migration fixture", attributes,
                                        value.encode("utf-8"), replace=False)
        self._find(service, slot)

    def _remove(self, service, slot):
        item = self._find(service, slot, check_snapshot=False)
        if item is not None:
            item.delete()
        require(self._find(service, slot, check_snapshot=False) is None,
                "fixture_credential_delete_readback_failed")
        self.attribute_snapshots.pop((service, slot), None)

    def cleanup(self):
        # The private collection started empty and every slot was reserved absent.
        # Attribute preservation failures must not prevent exact owned cleanup.
        events, remaining = [], []
        for index, (service, slot) in enumerate(sorted(self.entries)):
            try:
                item = self._find(service, slot, check_snapshot=False)
                if item is not None:
                    item.delete()
                require(self._find(service, slot, check_snapshot=False) is None,
                        "fixture_credential_delete_readback_failed")
                self.attribute_snapshots.pop((service, slot), None)
                events.append({"entry": index, "passed": True, "code": "credential_removed"})
            except Exception:
                event = {"entry": index, "passed": False, "code": "credential_cleanup_failed"}
                events.append(event)
                remaining.append(event)
        report = {"passed": not remaining, "remaining_entries": remaining, "events": events}
        report["provider_schema_baseline"] = {
            "scope": "two_new_owned_current_target_credentials_only",
            "registered_entries": len(self.current_target_entries),
            "observed_normalizations": len(self.normalized_current_entries),
            "other_attributes_and_values": "strict",
            "initial_raw_snapshots_overwritten": False,
            "old_namespaces_and_migrated_aliases": "full_raw_attribute_snapshots",
        }
        if hasattr(self, "collection"):
            try:
                require(not list(self.collection.get_all_items()), "fixture_collection_not_empty")
            except Exception:
                report["passed"] = False
                report["remaining_entries"].append({"code": "fixture_collection_cleanup_failed"})
        if self.connection is not None:
            try:
                self.connection.close()
                self.connection = None
            except Exception:
                report["passed"] = False
                report["remaining_entries"].append({"code": "fixture_bus_connection_close_failed"})
        if self.daemon is not None:
            try:
                if self.daemon.poll() is None:
                    self.daemon.terminate()
                    try:
                        self.daemon.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self.daemon.kill()
                        self.daemon.wait(timeout=5)
                require(self.daemon.poll() is not None, "fixture_daemon_still_running")
                self.daemon = None
            except Exception:
                report["passed"] = False
                report["remaining_entries"].append({"code": "fixture_daemon_cleanup_failed"})
        return report


def create(root):
    root = _base.owned_path(root)
    require(not root.exists(), "fixture_keyring_home_not_fresh")
    root.mkdir(parents=True, mode=0o700)
    return SecretServiceKeys(root)
