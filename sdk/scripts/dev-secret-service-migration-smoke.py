#!/usr/bin/env python3
"""Hosted isolated D-Bus: real legacy Secret Service profiles and native aliases."""
import importlib.util
import os
from pathlib import Path
import sys


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


migration = load("secret_service_migration_fixture", "dev-profile-migration-smoke.py")
backend = load("secret_service_native_fixture", "dev-migration-secret-service.py")
EXTRA_CASE = "secret_service_legacy_fields_and_aliases"
required = migration.REQUIRED + (EXTRA_CASE,)


class SecretServiceSmoke(migration.Smoke):
    def __init__(self, args):
        super().__init__(args)
        self.ss_profiles = 0
        self.ss_services = set()
        self.report.update(required_cases=list(required),
            scope="Isolated D-Bus Secret Service credentials, encrypted profiles and native alias migration.")

    def migrated(self, home, fixtures):
        sessions = super().migrated(home, fixtures)
        for fixture in fixtures:
            session_path, session = sessions[fixture["account"]["user"]]
            migration.require(session.get("keyring_backend") == "secret_service",
                "migration_did_not_select_secret_service")
            # Exact old service/username attributes and unchanged native values
            # are verified by the shared migration fixture's native readbacks.
            migration.require(self.keys.name == "linux-secret-service",
                "secret_service_fixture_backend_mismatch")
            self.ss_profiles += 1
            self.ss_services.add(fixture["service"])
        return sessions

    def run(self):
        migration.require(sys.platform == "linux" and os.environ.get("DBUS_SESSION_BUS_ADDRESS"),
            "isolated_secret_service_session_required")
        super().run()
        migration.require(self.ss_services == {"1memory", "memocap", "respire"}
            and self.ss_profiles >= 5, "secret_service_legacy_profiles_missing")
        self.passed(EXTRA_CASE, profiles=self.ss_profiles,
            legacy_services=sorted(self.ss_services), backend="secret_service",
            original_attributes_and_values_preserved=True)


def main():
    # Reuse the same exact-artifact, encrypted-data, account-cleanup and native
    # ownership checks. This independent suite does not replace kernel coverage.
    migration.keyring_backend = backend
    migration.Smoke = SecretServiceSmoke
    migration.REQUIRED = required
    return migration.main()


if __name__ == "__main__":
    sys.exit(main())
