#!/usr/bin/env python3
"""Hosted private D-Bus credential roundtrips; no CLI, cloud or model execution."""
import importlib.util
from pathlib import Path
import sys


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    fixture = load("secret_service_credential_check", "dev-migration-keyring-selftest.py")
    fixture.backend = load("secret_service_owned_credentials", "dev-migration-secret-service.py")
    fixture.backend.require(sys.platform == "linux", "linux_secret_service_fixture_required")
    return fixture.main()


if __name__ == "__main__":
    sys.exit(main())
