#!/usr/bin/env python3
"""Hosted CI only: real encrypted profiles, keyring aliases, WAL and restart migration."""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
from dev_witness_fixture import register_witness_functions, verify_fixture_witness, sqlite_failure_details
import subprocess
import sys
import time
import uuid

spec = importlib.util.spec_from_file_location("vault_smoke_support", Path(__file__).with_name("dev-legacy-vault-smoke.py"))
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)
keyring_spec = importlib.util.spec_from_file_location("migration_native_keyring", Path(__file__).with_name("dev-migration-keyring.py"))
keyring_backend = importlib.util.module_from_spec(keyring_spec)
keyring_spec.loader.exec_module(keyring_backend)
require, digest = support.require, support.digest
REQUIRED = ("model_cpu_real", "onememory_multiaccount_wal_migrated",
    "respire_compatibility_migrated", "legacy_keys_migrated_without_super_override",
    "legacy_api_defaults_rewritten", "migration_repeated_start_idempotent",
    "migration_interrupted_restart_recovered", "existing_rsrs_preserved_and_legacy_imported",
    "migrated_outbox_sync_and_independent_decrypt", "migration_incompatible_primary_keys_rejected",
    "migration_symlink_root_rejected", "migration_client_only_does_not_write",
    "startup_does_not_migrate", "migration_source_order_and_backup_only_idempotent")


class Smoke(support.Smoke):
    def __init__(self, args):
        super().__init__(args)
        self.keys = None
        self.wal_connections = []
        self.report.update(required_cases=list(REQUIRED), cases={}, passed=False,
            scope="Synthetic home/profile data and exact random-user native keyring entries only.",
            platform=sys.platform, keyring_cleanup={"passed": False, "remaining_entries": []})

    def env(self, name, user=None):
        env = super().env(name, user)
        if self.keys is not None:
            self.keys.configure_env(env)
        return env

    def reserve_account(self, user):
        for slot in ("super:", "pass:"):
            self.keys.reserve("rsrs", slot + user)

    def cli(self, env, *args, timeout=180):
        try:
            output = subprocess.run([str(self.args.binary), "--direct", "--json", *args],
                cwd=self.root, env=env, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            self.report["cli_failure"] = {"command": args[0], "timeout_seconds": timeout,
                "error_class": "timeout"}
            self.save()
            raise
        finally:
            stopped = subprocess.run([str(self.args.binary), '--runtime-internal', '--stop'],
                cwd=self.root, env=env, capture_output=True, timeout=60)
            require(stopped.returncode in (0, 2), 'owned_runtime_stop_failed')
        value = None
        try:
            value = json.loads(output.stdout)
        except (ValueError, UnicodeError):
            pass
        failed = output.returncode != 0 or not isinstance(value, dict) \
            or value.get("errors") or value.get("status") in ("error", "failed")
        if failed:
            text = (output.stdout + output.stderr).decode("utf-8", errors="replace").lower()
            categories = (
                ("argument_contract", ("unexpected argument", "required arguments were not provided", "a value is required")),
                ("rate_limited", ("too many requests", "rate limit", "http 429", "status: 429")),
                ("native_credentials", ("keyring", "keychain", "credential manager", "osstatus")),
                ("vault_unlock", ("failed to decrypt", "vault could not be unlocked", "super password required", "secret key required")),
                ("entry_not_found", ("not found #", "memory not found")),
                ("http_transport", ("connection refused", "connection timed out", "network is unreachable", "tls")),
                ("legacy_vault_login", ("this account uses a legacy vault",)),
                ("vault_fetch", ("could not fetch the account vault", "vault missing")),
                ("vault_unlock", ("super password does not unlock this account",)),
                ("local_key_mismatch", ("local library uses different key material", "local library key compatibility could not be verified")),
                ("login_destination", ("target account session", "destination belongs to another account", "destination must not be a symbolic link")),
                ("runtime_readiness", ("did not become ready", "exited before readiness", "runtime owner changed", "runtime is not running")),
                ("runtime_account_verification", ("runtime account verification failed", "runtime account list missing accounts", "runtime did not report a selected account", "runtime account or directory differs from the authorized account")),
                ("library_lock", ("library is locked", "database is locked")),
                ("server_auth", ("http 401", "status: 401", "unauthorized", "invalid password", "invalid credentials")),
                ("native_credential_cleanup", ("owned_runtime_stop_failed",)),
            )
            category = next((name for name, terms in categories if any(term in text for term in terms)), "unclassified")
            self.report["cli_failure"] = {"command": args[0], "exit_code": output.returncode,
                "error_class": category, "json_envelope": isinstance(value, dict),
                "error": self.redacted_cli_error(env, output)}
            self.report["cli_failure"]["runtime_signals"] = [name for name, term in (
                ("child_exited", "host runtime exited before readiness"),
                ("startup_identity_changed", "runtime owner changed during startup"),
                ("readiness_timeout", "host runtime did not become ready"),
                ("old_runtime_restart_failed", "original runtime restart failed"),
                ("spawn_failed", "failed to start host runtime"),
            ) if term in text]
            if args[0] == "sync" and isinstance(value, dict):
                summary = value.get("summary", {})
                self.report["cli_failure"]["sync_counts"] = {
                    key: summary[key] for key in ("local_total", "local_alive", "remote_total", "remote_alive",
                        "pending", "conflicts", "undecodable", "protocol", "total_matched", "converged")
                    if key in summary and type(summary[key]) in (int, bool)}
            self.save()
            reason = "cli_failed_" if output.returncode != 0 else \
                "invalid_cli_json_" if not isinstance(value, dict) else "cli_error_"
            raise RuntimeError(reason + args[0])
        return value

    def reserve_alias(self, source):
        alias = "legacy-" + keyring_backend.canonical_identity(source)[:16]
        for slot in ("super:", "pass:"):
            self.keys.reserve("rsrs", slot + alias)
        return alias

    def verify_mac_native_credentials(self, env, fixture):
        """Consume owned native credentials through the unchanged CLI creator.

        This proves the original values through export and authenticated unwrap;
        it does not test automatic server reauthentication or change item ACLs.
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        clean_env = dict(env)
        for key in ("RSRS_SUPER", "RSRS_PASS", "RSRS_SECRET",
                    "RSRS_KDF_SALT", "RSRS_WRAPPED_URK", "RSRS_URK_NONCE"):
            clean_env.pop(key, None)
        profile = Path(clean_env["RSRS_DATA_DIR"])
        keyring_backend.owned_path(profile)
        session_path = profile / "session.json"
        require(session_path.is_file() and not session_path.is_symlink(), "native_consumer_session_missing")
        original = session_path.read_bytes()
        session = json.loads(original)
        require(session.get("user") == fixture["account"]["user"]
            and session.get("vault_version") == 4
            and all(not session.get(key) for key in ("pass", "super", "secret_key")),
            "native_consumer_session_has_override")
        note = self.root / ("native-recovery-" + secrets.token_hex(8) + ".txt")
        require(not note.exists(), "native_consumer_export_not_fresh")
        try:
            self.report["fixture_operation"] = "native_consumer_super_export"
            self.save()
            self.cli(clean_env, "keys-export", "--out", str(note))
            require(note.is_file() and not note.is_symlink(), "native_consumer_export_missing")
            exported = re.findall(r"^super password: (.+)$", note.read_text(encoding="utf-8"), re.MULTILINE)
            require(exported == [fixture["code"]], "native_consumer_super_changed")
            urk = AESGCM(support.v4_kek(fixture["code"], session["kdf_salt"], session["wrapped_urk"])).decrypt(
                bytes.fromhex(session["urk_nonce"]), support.encrypted_bytes(session["wrapped_urk"]), None)
            require(len(urk) == 32, "native_consumer_urk_invalid")
            salt, nonce, secret = secrets.token_bytes(16).hex(), secrets.token_bytes(12), secrets.token_hex(32)
            wrapped = AESGCM(support.legacy_kek(1, fixture["password"], secret, salt)).encrypt(nonce, urk, None)
            probe = dict(session, vault_version=1, kdf_salt=salt, wrapped_urk=wrapped.hex(),
                         urk_nonce=nonce.hex(), secret=secret)
            for key in ("pass", "super", "secret_key"):
                probe.pop(key, None)
            self.report["fixture_operation"] = "native_consumer_password_unwrap"
            self.save()
            self.write_session(clean_env, probe)
            shown = self.cli(clean_env, "show", fixture["id"])
            require(shown.get("details", {}).get("entry", {}).get("content") == fixture["text"],
                    "native_consumer_original_ciphertext_not_decrypted")
        finally:
            try:
                session_path.write_bytes(original)
            finally:
                note.unlink(missing_ok=True)
            require(session_path.read_bytes() == original, "native_consumer_session_restore_failed")
        database = profile / ("rsrs.db" if (profile / "rsrs.db").exists() else "onememory.db")
        with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
            row = db.execute("SELECT ciphertext,nonce FROM memories WHERE id=?", (fixture["id"],)).fetchone()
            require(support.decrypt_content(urk, *row) == support.decrypt_content(urk, *fixture["cipher"]),
                    "native_consumer_content_changed")
        proof = self.report.setdefault("native_credential_consumer", {
            "platform": "darwin", "super": "cli_keys_export", "password": "cli_v1_kdf_aead_show",
            "consumer_changes_product_acl": False, "automatic_server_reauthentication_tested": False,
            "verified_profiles": 0})
        proof["verified_profiles"] += 1
        self.save()

    @contextmanager
    def selected_profile(self, default, fixture):
        profile = fixture["destination"]
        config_path = profile / "client.json"
        original = config_path.read_bytes() if config_path.exists() else None
        # Consume the migration's actual configuration. Do not repair its path
        # spelling here: runtime verification must exercise the published result.
        try:
            yield dict(default, RSRS_DATA_DIR=str(profile))
        finally:
            if original is None:
                config_path.unlink()
            else:
                config_path.write_bytes(original)
            require((config_path.read_bytes() if config_path.exists() else None) == original,
                "fixture_profile_selection_restore_failed")

    def save(self):
        (self.root / "migration-coverage.json").write_text(json.dumps(self.report, indent=2) + "\n", encoding="utf-8")

    def cleanup(self):
        recoveries = []
        for account in self.accounts:
            if account["confirmed"]:
                continue
            event = {"user": account["user"], "confirmed": False}
            try:
                # Authenticate with this fixture's generated credential; never
                # delete an account by prefix or an unconfirmed username.
                request = support.urllib.request.Request(support.UPSTREAM + "/login",
                    json.dumps({"user": account["user"], "pass_hash": account["pass_hash"],
                        "device_name": "migration-cleanup"}).encode(),
                    {"Content-Type": "application/json"}, method="POST")
                with self.opener.open(request, timeout=45) as response:
                    require(response.status == 200, "cleanup_login_not_confirmed")
                    raw = response.read(1024 * 1024 + 1)
                    require(len(raw) <= 1024 * 1024, "cleanup_login_response_too_large")
                    token = json.loads(raw).get("token")
                require(isinstance(token, str) and bool(token), "cleanup_login_token_missing")
                candidate = dict(account, confirmed=True, token=token)
                identity = self.api(candidate, "GET", "/api/self")
                require(identity.get("user") == account["user"], "cleanup_login_identity_mismatch")
                account.update(confirmed=True, token=token)
                event["confirmed"] = True
            except Exception as error:
                event["failure_code"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
            recoveries.append(event)
        self.report["cloud_cleanup"]["recovered_session_checks"] = recoveries
        super().cleanup()

    def default_env(self, env):
        result = dict(env)
        result.pop("RSRS_DATA_DIR", None)
        result.pop("RSRS_SUPER", None)
        return result

    def seed(self, env, path, service, label):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        path.mkdir(parents=True, exist_ok=True)
        env = dict(env, RSRS_DATA_DIR=str(path))
        user, password = "ci-migrate-" + secrets.token_hex(8), "ci-" + secrets.token_urlsafe(32)
        self.reserve_account(user)
        self.diagnostic_secrets.add(password)
        if service == "rsrs" and self.keys.name == "linux-secret-service":
            self.keys.register_current_target(user)
        account = {"user": user, "token": None, "confirmed": False,
            "pass_hash": None}
        self.accounts.append(account)
        self.report["cloud_cleanup"]["remaining_users"].append(user)
        self.report["fixture_operation"] = "register"
        self.save()
        value = self.cli(env, "register", "--addr", support.UPSTREAM, "--user", user, "--pass", password)
        session = self.session(env)
        require(value["summary"].get("ok") is True and value["summary"].get("user") == user
            and session.get("user") == user and session.get("addr") == support.UPSTREAM
            and bool(session.get("token")), "migration_registered_identity_mismatch")
        account.update(token=session["token"], confirmed=True)
        auth_salt = bytes.fromhex(session["auth_salt"].removeprefix(support.PREFIX))
        account["pass_hash"] = hashlib.pbkdf2_hmac("sha256", password.encode(), auth_salt, 100_000, 32).hex()
        code = value["summary"].get("super")
        require(isinstance(code, str) and bool(code), "migration_super_missing")
        self.diagnostic_secrets.update((code, session["token"], account["pass_hash"]))
        self.report["fixture_operation"] = "verify_registered_native_credentials"
        self.save()
        if sys.platform != "darwin":
            require(self.keys.read("rsrs", "super:" + user) == code
                and self.keys.read("rsrs", "pass:" + user) == password,
                "registered_native_credentials_not_in_owned_store")
        env["RSRS_SUPER"] = code
        self.report["fixture_operation"] = "seed_local_content"
        self.save()
        self.cli(env, "config", "--addr", support.UPSTREAM, "--autosync", "false")
        text = "Synthetic unsynchronized migration content " + label
        created = self.cli(env, "remember", text, "--title", label, "--force", "--importance", "important")
        memory_id = created["summary"]["id"]
        urk = AESGCM(support.v4_kek(code, session["kdf_salt"], session["wrapped_urk"])).decrypt(
            bytes.fromhex(session["urk_nonce"]), support.encrypted_bytes(session["wrapped_urk"]), None)
        db = path / "rsrs.db"
        if service != "rsrs":
            # Produce a genuine old-format fixture from this disposable account.
            db.rename(path / "onememory.db")
            db = path / "onememory.db"
            wrap_nonce = secrets.token_bytes(12)
            session["wrapped_urk"] = AESGCM(support.v4_kek(code, session["kdf_salt"])).encrypt(wrap_nonce, urk, None).hex()
            session["urk_nonce"] = wrap_nonce.hex()
            session.pop("crypto_namespace", None)
            self.api(account, "POST", "/api/self/vault", {
                "version": 4, **{key: session[key] for key in ("kdf_salt", "wrapped_urk", "urk_nonce")}})
        connection = sqlite3.connect(db)
        register_witness_functions(connection)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA wal_autocheckpoint=0")
        connection.execute("CREATE TABLE IF NOT EXISTS migration_wal_fixture(marker TEXT PRIMARY KEY)")
        connection.execute("INSERT INTO migration_wal_fixture VALUES(?)", (label,))
        row = connection.execute("SELECT ciphertext,nonce FROM memories WHERE id=?", (memory_id,)).fetchone()
        require(row is not None, "migration_seed_memory_missing")
        payload = support.decrypt_content(urk, *row)
        if service != "rsrs":
            item_nonce = secrets.token_bytes(12)
            ciphertext = AESGCM(support.hkdf(urk, None, b"onememory:data:v1")).encrypt(item_nonce, payload, None).hex()
            connection.execute("UPDATE memories SET ciphertext=?,nonce=? WHERE id=?", (ciphertext, item_nonce.hex(), memory_id))
            connection.execute("UPDATE core_artifacts SET source=? WHERE memory_id=?", (ciphertext, memory_id))
            connection.execute("UPDATE sync_outbox SET ciphertext=?,nonce=? WHERE id=? AND state='pending'", (ciphertext, item_nonce.hex(), memory_id))
        tombstones = []
        if service != "rsrs":
            tombstone_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            # All deleted payloads must also decrypt and be reencrypted.
            for _ in range(5):
                item_nonce = secrets.token_bytes(12)
                tombstone = (str(uuid.uuid4()), user,
                    AESGCM(support.hkdf(urk, None, b"onememory:data:v1")).encrypt(item_nonce, payload, None).hex(),
                    item_nonce.hex(), 1)
                connection.execute(
                    "INSERT INTO memories (id,user,ciphertext,nonce,deleted,dirty,created_at,updated_at) "
                    "VALUES (?,?,?,?,?,0,?,?)", tombstone + (tombstone_time, tombstone_time))
                tombstones.append(tombstone)
        connection.commit()
        verify_fixture_witness(connection)
        require(Path(str(db) + "-wal").stat().st_size > 0, "migration_wal_fixture_empty")
        row = connection.execute("SELECT ciphertext,nonce FROM memories WHERE id=?", (memory_id,)).fetchone()
        require(row and connection.execute("SELECT COUNT(*) FROM sync_outbox WHERE state='pending'").fetchone()[0] > 0,
            "migration_outbox_fixture_not_pending")
        self.wal_connections.append(connection)
        if sys.platform == "darwin":
            self.verify_mac_native_credentials(env, {"account": account, "code": code, "password": password,
                "id": memory_id, "text": text, "cipher": row})
        if service == "rsrs":
            # This is the genuine current target, not a legacy namespace fixture.
            # Keep the CLI-created credentials and endpoint exactly as registered.
            self.report["fixture_operation"] = "retained_current_credentials"
            self.save()
            return {"account": account, "password": password, "code": code, "service": service,
                "source": path, "id": memory_id, "text": text, "label": label, "cipher": row, "alias": None}
        self.report["fixture_operation"] = "seed_legacy_native_credentials"
        self.save()
        self.keys.put(service, "super:" + user, code)
        self.keys.put(service, "pass:" + user, password)
        # The old service is the only credential source, not an environment override.
        self.report["fixture_operation"] = "remove_current_native_credentials"
        self.save()
        self.keys.remove("rsrs", "super:" + user)
        self.keys.remove("rsrs", "pass:" + user)
        env.pop("RSRS_SUPER", None)
        self.report["fixture_operation"] = "rewrite_legacy_endpoint"
        self.save()
        session["addr"] = {"1memory": "https://api.1memory.ai", "memocap": "https://api.memocap.ai"}.get(service,
            "https://api.respire.ai")
        self.write_session(env, session)
        config_path = path / "client.json"
        config = json.loads(config_path.read_text())
        config["addr"] = session["addr"]
        config_path.write_text(json.dumps(config), encoding="utf-8")
        alias = self.reserve_alias(path)
        return {"account": account, "password": password, "code": code, "service": service,
            "source": path, "id": memory_id, "text": text, "label": label, "cipher": row, "alias": alias,
            "legacy_tombstones": tombstones, "urk": urk, "payload": payload}

    def migrated(self, home, fixtures):
        root = home / ".rsrs"
        require(root.is_dir(), "migration_target_missing")
        sessions = {}
        for path in root.rglob("session.json"):
            value = json.loads(path.read_text())
            if value.get("user") in {f["account"]["user"] for f in fixtures}:
                require(value["user"] not in sessions, "migration_profile_duplicate")
                sessions[value["user"]] = (path, value)
        require(len(sessions) == len(fixtures), "migration_profiles_missing")
        for fixture in fixtures:
            user = fixture["account"]["user"]
            session_path, value = sessions[user]
            profile = session_path.parent
            require(value.get("addr") == "https://api.rsrs.rs", "legacy_api_default_not_rewritten")
            receipt = json.loads((profile / ".rsrs-migration.json").read_text())
            require(receipt.get("namespace_migrated") is True, "full_migration_receipt_missing")
            require(value["wrapped_urk"].startswith(support.PREFIX), "migration_wrap_namespace_missing")
            alias = value.get("keyring_account")
            require(isinstance(alias, str) and alias.startswith("legacy-"), "migration_key_alias_missing")
            require(alias == fixture["alias"], "migration_native_alias_identity_mismatch")
            if sys.platform != "darwin":
                self.report["fixture_operation"] = "new_alias_super"
                self.save()
                require(self.keys.read("rsrs", "super:" + alias) == fixture["code"], "migration_key_changed")
                self.report["fixture_operation"] = "new_alias_pass"
                self.save()
                require(self.keys.read("rsrs", "pass:" + alias) == fixture["password"], "migration_login_password_changed")
            self.report["fixture_operation"] = "legacy_source_super"
            self.save()
            require(self.keys.read(fixture["service"], "super:" + user) == fixture["code"], "legacy_key_source_changed")
            self.report["fixture_operation"] = "legacy_source_pass"
            self.save()
            require(self.keys.read(fixture["service"], "pass:" + user) == fixture["password"], "legacy_password_source_changed")
            with sqlite3.connect((fixture["source"] / "onememory.db").as_uri() + "?mode=ro", uri=True) as source_db:
                require(source_db.execute("SELECT ciphertext,nonce FROM memories WHERE id=?", (fixture["id"],)).fetchone() == fixture["cipher"],
                    "legacy_source_ciphertext_changed")
                for tombstone in fixture["legacy_tombstones"]:
                    require(source_db.execute("SELECT id,user,ciphertext,nonce,deleted FROM memories WHERE id=?",
                        (tombstone[0],)).fetchone() == tombstone, "legacy_source_foreign_tombstone_changed")
            with sqlite3.connect((profile / "rsrs.db").as_uri() + "?mode=ro", uri=True) as db:
                require(db.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "migrated_database_invalid")
                converted = db.execute("SELECT ciphertext,nonce FROM memories WHERE id=?", (fixture["id"],)).fetchone()
                require(converted != fixture["cipher"] and converted[0].startswith(support.PREFIX)
                    and support.decrypt_content(fixture["urk"], *converted) == fixture["payload"], "migration_reencryption_failed")
                require(db.execute("SELECT marker FROM migration_wal_fixture").fetchone()[0] == fixture["label"], "migration_lost_committed_wal")
                require(db.execute("SELECT COUNT(*) FROM sync_outbox WHERE state='pending'").fetchone()[0] > 0, "migration_lost_outbox")
                for tombstone in fixture["legacy_tombstones"]:
                    converted = db.execute("SELECT id,user,ciphertext,nonce,deleted FROM memories WHERE id=?", (tombstone[0],)).fetchone()
                    require(converted[:2] == tombstone[:2] and converted[4] == 1
                        and converted[2].startswith(support.PREFIX)
                        and support.decrypt_content(fixture["urk"], converted[2], converted[3]) == fixture["payload"],
                        "migration_deleted_payload_not_reencrypted")
            fixture["destination"] = profile
        return sessions

    def case(self, name, sources, target=False, interrupt=False):
        self.report["stage"] = name
        env = self.env(name)
        home = Path(env["HOME"])
        fixtures = []
        for folder, service in sources:
            fixture = self.seed(env, home / folder, service, name + "-" + folder)
            fixtures.append(fixture)
        if name == "multiaccount":
            other = self.seed(env, home / ".onememory/accounts/second", "1memory", "multiaccount-secondary")
            fixtures.append(other)
            config_path = home / ".onememory/client.json"
            config = json.loads(config_path.read_text())
            config["data_dir"] = str(other["source"])
            config_path.write_text(json.dumps(config), encoding="utf-8")
            old_lock = sqlite3.connect(fixtures[0]["source"] / "lock.db")
            old_lock.execute("CREATE TABLE IF NOT EXISTS migration_lock_fixture(value TEXT)")
            old_lock.commit()
            old_lock.execute("BEGIN EXCLUSIVE")
            self.wal_connections.append(old_lock)
        if target:
            current = self.seed(env, home / ".rsrs", "rsrs", name + "-existing-rsrs")
            # A current profile must keep its existing credentials and URL untouched.
            current_env = dict(env, RSRS_DATA_DIR=str(current["source"]))
            current_session = self.session(current_env)
        default = self.default_env(env)
        self.cli(default, "status")
        root = home / ".rsrs"
        require(not list(root.rglob(".rsrs-migration.json")), "startup_automatically_migrated_profiles")
        require(not any(json.loads(p.read_text()).get("user") in {f["account"]["user"] for f in fixtures}
            for p in root.rglob("session.json")), "startup_copied_legacy_accounts")
        original_config = (root / "client.json").read_bytes() if (root / "client.json").exists() else None
        original_selection = self.cli(default, "config")["summary"]["data_dir"]
        self.passed("startup_does_not_migrate", existing_target=target)
        candidates = self.cli(default, "migrate")["details"]["profiles"]
        for fixture in fixtures:
            rows = [row for row in candidates if Path(row["source"]).resolve() == fixture["source"].resolve()]
            require(len(rows) == 1 and rows[0]["user"] == fixture["account"]["user"], "selected_migration_source_not_unique")
            fixture["source_id"] = rows[0]["source_id"]
            fixture["destination_account"] = rows[0]["account"]
            fixture["destination"] = root / "accounts" / rows[0]["account"]
        if interrupt:
            padding = fixtures[0]["source"] / "migration-copy-fixture.bin"
            with padding.open("wb") as stream:
                for _ in range(64):
                    stream.write(bytes(1024 * 1024))
            process = subprocess.Popen([str(self.args.binary), "--direct", "--json", "migrate",
                "--source", fixtures[0]["source_id"], "--account", fixtures[0]["destination_account"]],
                env=default, cwd=self.root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.monotonic() + 30
            stage_seen = False
            while process.poll() is None and time.monotonic() < deadline:
                stage = home / ".rsrs-migration-staging"
                if stage.is_dir() and any((p / "onememory.db").is_file() for p in stage.iterdir()) \
                    and not fixtures[0]["destination"].exists():
                    stage_seen = True
                    process.kill()
                    break
                time.sleep(0.002)
            if process.poll() is None:
                process.kill()
            process.wait(timeout=10)
            require(stage_seen, "interruption_fixture_did_not_reach_real_stage")
            require(not fixtures[0]["destination"].exists(), "interruption_fixture_missed_prepublication_window")
        for fixture in fixtures:
            migrated = self.cli(default, "migrate", "--source", fixture["source_id"],
                "--account", fixture["destination_account"])["summary"]
            require(migrated.get("state") == "migrated" and Path(migrated["dir"]).resolve() == fixture["destination"].resolve(),
                "selected_migration_not_published")
            require(((root / "client.json").read_bytes() if (root / "client.json").exists() else None) == original_config,
                "explicit_migration_changed_current_configuration")
        self.migrated(home, fixtures)
        selected = self.cli(default, "config")["summary"]["data_dir"]
        require(Path(selected).resolve() == Path(original_selection).resolve(), "migration_changed_selected_account")
        for fixture in fixtures:
            with self.selected_profile(default, fixture) as user_env:
                require("RSRS_SUPER" not in user_env, "migration_super_override_present")
                if sys.platform == "darwin":
                    self.verify_mac_native_credentials(user_env, fixture)
                self.read_entry(user_env, fixture["id"], fixture["text"])
        if target:
            with sqlite3.connect(current["source"] / "rsrs.db") as db:
                require(db.execute("SELECT ciphertext,nonce FROM memories WHERE id=?", (current["id"],)).fetchone() == current["cipher"],
                    "existing_target_data_overwritten")
            require(self.session(current_env) == current_session, "existing_target_session_overwritten")
            self.report["fixture_operation"] = "retained_current_credentials"
            self.save()
            if sys.platform == "darwin":
                self.verify_mac_native_credentials(current_env, current)
            else:
                user = current["account"]["user"]
                require(self.keys.read("rsrs", "super:" + user) == current["code"]
                    and self.keys.read("rsrs", "pass:" + user) == current["password"],
                    "existing_target_native_credentials_overwritten")
            self.read_entry(current_env, current["id"], current["text"])
            self.passed("existing_rsrs_preserved_and_legacy_imported", imported=len(fixtures))
        before = {str(p.relative_to(home)): digest(p) for p in (home / ".rsrs").rglob(".rsrs-migration.json")}
        self.cli(default, "status")
        require(before == {str(p.relative_to(home)): digest(p) for p in (home / ".rsrs").rglob(".rsrs-migration.json")},
            "repeat_start_changed_receipts")
        require(len([p for p in (home / ".rsrs").rglob("session.json") if json.loads(p.read_text()).get("user") in
            {f["account"]["user"] for f in fixtures}]) == len(fixtures), "repeat_start_duplicated_profiles")
        if name == "multiaccount":
            receipt = json.loads((fixtures[0]["destination"] / ".rsrs-migration.json").read_text())
            require(receipt.get("snapshot_only") is True and receipt.get("legacy_runtime_active") is True,
                "active_legacy_lock_snapshot_not_declared")
            selected = self.cli(default, "config")["summary"]["data_dir"]
            require(Path(selected).resolve() == Path(original_selection).resolve(), "migration_changed_selected_account")
            # A newly appearing earlier source and backup-only directory must
            # not change the identity of already copied profiles.
            backup = home / ".respire" / "bak"
            backup.mkdir(parents=True)
            shutil.copyfile(fixtures[0]["source"] / "session.json", backup / "session.json")
            rows = self.cli(default, "migrate")["details"]["profiles"]
            require({row["source_id"] for row in rows} == {f["source_id"] for f in fixtures},
                "backup_only_directory_became_migration_source")
            earlier = home / ".respire" / "accounts" / "aaa"
            earlier.mkdir(parents=True)
            shutil.copyfile(fixtures[0]["source"] / "session.json", earlier / "session.json")
            reordered = self.cli(default, "migrate")["details"]["profiles"]
            require(len(reordered) == len(fixtures) + 1, "source_order_fixture_not_observed")
            for fixture in reversed(fixtures):
                repeated = self.cli(default, "migrate", "--source", fixture["source_id"], "--account", "different-name")["summary"]
                require(repeated.get("state") == "already_migrated"
                    and Path(repeated["dir"]).resolve() == fixture["destination"].resolve(),
                    "source_order_changed_existing_migration_identity")
            require(before == {str(p.relative_to(home)): digest(p) for p in root.rglob(".rsrs-migration.json")},
                "repeat_explicit_migration_changed_receipts")
            require(not (root / "accounts" / "different-name").exists(), "repeat_explicit_migration_duplicated_account")
            self.passed("migration_source_order_and_backup_only_idempotent", selected_sources=len(fixtures), new_earlier_source=True)
            self.passed("onememory_multiaccount_wal_migrated", profiles=len(fixtures),
                deleted_payloads_reencrypted=sum(len(f["legacy_tombstones"]) for f in fixtures))
            self.passed("legacy_keys_migrated_without_super_override", old_service_unchanged=True)
            self.passed("legacy_api_defaults_rewritten", verified="old defaults to api.rsrs.rs; dev redirect only after verification")
            self.passed("migration_repeated_start_idempotent", profiles=len(fixtures))
            for fixture in fixtures:
                with self.selected_profile(default, fixture) as profile_env:
                    session = self.session(profile_env)
                    session["addr"] = support.UPSTREAM
                    self.write_session(profile_env, session)
                    self.cli(profile_env, "config", "--addr", support.UPSTREAM, "--autosync", "false")
                    created = self.cli(profile_env, "remember", "New-directory migration write",
                        "--title", "post-migration", "--force", "--importance", "important")
                    new_id = created["summary"]["id"]
                    self.cli(profile_env, "migrate", "--vault", "--addr", support.UPSTREAM,
                        "--user", fixture["account"]["user"], "--pass", fixture["password"], "--super", fixture["code"])
                    committed = self.session(profile_env)
                    fixture["account"]["token"] = committed["token"]
                    self.keys.track_created_login(committed, fixture["account"]["user"],
                        fixture["code"], fixture["password"])
                    self.cli(profile_env, "sync")
                    self.report["fixture_operation"] = "post_sync_deleted_payload_erasure"
                    self.save()
                    with sqlite3.connect((fixture["destination"] / "rsrs.db").as_uri() + "?mode=ro", uri=True) as db:
                        for tombstone in fixture["legacy_tombstones"]:
                            row = db.execute("SELECT id,user,ciphertext,nonce,deleted,embedding_enc FROM memories WHERE id=?", (tombstone[0],)).fetchone()
                            # Server 1.0.1 erases deleted payloads after sync; pre-sync re-encryption is checked above.
                            require(row is not None and row[:2] == tombstone[:2] and row[4] == 1
                                and row[2] == row[3] == row[5] == "",
                                "sync_retained_deleted_payload")
                user = fixture["account"]["user"]
                remote = self.env("independent-" + user, user)
                remote["RSRS_SUPER"] = fixture["code"]
                self.cli(remote, "login", "--interactive", "--addr", support.UPSTREAM, "--user", user, "--pass", fixture["password"], "--super", fixture["code"])
                fixture["account"]["token"] = self.session(remote)["token"]
                self.cli(remote, "sync")
                self.read_entry(remote, fixture["id"], fixture["text"])
                self.read_entry(remote, new_id, "New-directory migration write")
                rows = self.cli(remote, "list", "--limit", "100")
                require("post-migration" in json.dumps(rows), "new_directory_write_not_synced")
            self.passed("migrated_outbox_sync_and_independent_decrypt", profiles=len(fixtures),
                deleted_payloads_erased=sum(len(f["legacy_tombstones"]) for f in fixtures))
        elif interrupt:
            self.passed("migration_interrupted_restart_recovered", real_stage_observed=True)
        elif not target:
            self.passed("respire_compatibility_migrated", profiles=len(fixtures),
                deleted_payloads_reencrypted=sum(len(f["legacy_tombstones"]) for f in fixtures))

    def run(self):
        expected_server = os.environ.get("RSRS_DEV_SERVER_SHA", "")
        require(os.environ.get("RSRS_DEV_SERVER_ADDR") == support.UPSTREAM
            and re.fullmatch("[0-9a-f]{40}", expected_server), "exact_development_server_required")
        with self.opener.open(support.UPSTREAM + "/health", timeout=45) as health:
            raw = health.read(1024 * 1024 + 1)
            require(len(raw) <= 1024 * 1024, "deployment_response_too_large")
            value = json.loads(raw)
            require(health.status == 200 and isinstance(value, dict) and value.get("source_revision") == expected_server,
                "development_server_revision_mismatch")
        self.report["server_sha"] = expected_server
        self.keys = keyring_backend.create(self.root / "keyring-home")
        self.report["keyring_backend"] = self.keys.name
        env = self.env("model-probe")
        version = subprocess.run([str(self.args.binary), "--version"], env=env, capture_output=True, timeout=20)
        require(version.returncode == 0 and re.search(r"(?<!\S)" + re.escape(self.args.version) + r"(?!\S)", version.stdout.decode()), "binary_version_mismatch")
        self.cli(env, "model", "install-m3", timeout=900)
        support.share_cpu_container(self.root, env, self.model)
        require(all(digest(self.model / p) == h for p, h in support.MODEL_HASHES.items()), "model_hash_mismatch")
        self.cli(env, "model", "engine", "cpu")
        probe = self.cli(env, "model", "probe", "--model", "m3")["summary"]
        require(probe.get("ready") is True and probe.get("dimensions") == 1024 and str(probe.get("selected")).lower() == "cpu", "real_cpu_probe_failed")
        self.passed("model_cpu_real", dimensions=1024)
        self.case("multiaccount", [(".onememory", "1memory")])
        self.case("respire", [(".respire", "respire")])
        self.case("interrupted", [(".respire", "respire")], interrupt=True)
        self.case("collision", [(".onememory", "1memory"), (".respire", "memocap")], target=True)
        self.negative_cases()
        self.report["status"] = "passed"

    def negative_cases(self):
        env = self.env("negative-source")
        fixture = self.seed(env, Path(env["HOME"]) / ".onememory", "1memory", "negative-source")
        for label, primary in (("missing-pk", ""), ("composite-pk", ",PRIMARY KEY(id,title)")):
            attempt = self.env(label)
            source = Path(attempt["HOME"]) / ".onememory"
            source.mkdir()
            self.reserve_alias(source)
            shutil.copyfile(fixture["source"] / "session.json", source / "session.json")
            with sqlite3.connect(source / "onememory.db") as db:
                db.execute("CREATE TABLE memories(id TEXT,user TEXT,title TEXT,ciphertext TEXT,nonce TEXT,created_at TEXT,updated_at TEXT" + primary + ")")
                db.execute("INSERT INTO memories VALUES(?,?,?,?,?,?,?)", (fixture["id"],fixture["account"]["user"],label,
                    fixture["cipher"][0],fixture["cipher"][1],"2026-10-03T00:00:00Z","2026-10-03T00:00:00Z"))
            before = digest(source / "onememory.db")
            candidates = self.cli(self.default_env(attempt), "migrate")["details"]["profiles"]
            require(len(candidates) == 1, "invalid_schema_source_fixture_missing")
            result = subprocess.run([str(self.args.binary), "--direct", "--json", "migrate",
                "--source", candidates[0]["source_id"], "--account", "rejected-schema"],
                env=self.default_env(attempt), cwd=self.root, capture_output=True, timeout=60)
            rejected = json.loads(result.stdout)
            require(result.returncode == 1 and rejected.get("status") == "fail"
                and any("incompatible pre-encrypted demo format" in error for error in rejected.get("errors", []))
                and not (Path(attempt["HOME"]) / ".rsrs/accounts/rejected-schema").exists(),
                "invalid_primary_key_migration_not_rejected")
            require(digest(source / "onememory.db") == before, "rejected_source_database_changed")
        self.passed("migration_incompatible_primary_keys_rejected", genuine_ciphertext_preserved=True, variants=2)
        link_env = self.env("symlink-root")
        link_home = Path(link_env["HOME"])
        (link_home / ".onememory").symlink_to(fixture["source"], target_is_directory=True)
        source_database = digest(fixture["source"] / "onememory.db")
        source_session = digest(fixture["source"] / "session.json")
        listed = subprocess.run([str(self.args.binary), "--direct", "--json", "migrate"],
            env=self.default_env(link_env), cwd=self.root, capture_output=True, timeout=60)
        listing = json.loads(listed.stdout)
        if listed.returncode != 0:
            require(listing.get("status") == "fail" and any("symbolic link" in error
                for error in listing.get("errors", [])), "symlink_listing_failed_for_unrelated_reason")
        else:
            require(listing.get("status") == "ok", "symlink_listing_status_invalid")
            for row in listing["details"]["profiles"]:
                result = subprocess.run([str(self.args.binary), "--direct", "--json", "migrate",
                    "--source", row["source_id"], "--account", "rejected-link"],
                    env=self.default_env(link_env), cwd=self.root, capture_output=True, timeout=60)
                rejection = json.loads(result.stdout)
                require(result.returncode != 0 and rejection.get("status") == "fail"
                    and any("symbolic link" in error for error in rejection.get("errors", [])),
                    "symlink_root_migration_not_rejected")
        require(not (link_home / ".rsrs").exists(), "symlink_root_migration_created_destination")
        require(digest(fixture["source"] / "onememory.db") == source_database
            and digest(fixture["source"] / "session.json") == source_session,
            "rejected_symlink_source_changed")
        self.passed("migration_symlink_root_rejected", external_target_is_owned_fixture=True)
        source_session = digest(fixture["source"] / "session.json")
        candidate = self.cli(self.default_env(env), "migrate")["details"]["profiles"][0]
        destination = Path(env["HOME"]) / ".rsrs"

        def destination_snapshot():
            if not destination.exists():
                return None
            snapshot = {}
            for path in (destination, *sorted(destination.rglob("*"))):
                stat = path.lstat()
                snapshot[str(path.relative_to(destination))] = (
                    stat.st_mode, stat.st_size, stat.st_mtime_ns,
                    digest(path) if path.is_file() else None)
            return snapshot

        # The host-side cleanup above can already create runtime bookkeeping.
        # Client-only commands must preserve that baseline as well as source data.
        destination_before = destination_snapshot()
        for variable in ("RSRS_CLIENT_ONLY", "RSRS_NO_AUTOSTART"):
            guarded = self.default_env(env)
            guarded[variable] = "1"
            result = subprocess.run([str(self.args.binary), "--version"], env=guarded,
                cwd=self.root, capture_output=True, timeout=30)
            require(result.returncode == 0 and destination_snapshot() == destination_before
                and digest(fixture["source"] / "session.json") == source_session, "client_only_migration_wrote_data")
            blocked = subprocess.run([str(self.args.binary), "--json", "migrate",
                "--source", candidate["source_id"], "--account", "blocked"], env=guarded,
                cwd=self.root, capture_output=True, timeout=30)
            rejection = json.loads(blocked.stdout)
            require(blocked.returncode == 1 and rejection.get("status") == "fail"
                and any("client_only:" in error for error in rejection.get("errors", []))
                and destination_snapshot() == destination_before
                and digest(fixture["source"] / "session.json") == source_session,
                "client_only_explicit_migration_wrote_data")
        self.passed("migration_client_only_does_not_write", guards=2)


def main():
    require(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and sys.platform in ("linux", "darwin", "win32"), "disposable_native_hosted_runner_required")
    parser = argparse.ArgumentParser()
    for name in ("binary", "root"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("binary-sha256", "source-sha", "version"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    require(re.fullmatch(r"[0-9a-f]{64}", args.binary_sha256) and args.binary.is_absolute()
        and args.binary.is_file() and digest(args.binary) == args.binary_sha256, "binary_hash_mismatch")
    require(re.fullmatch(r"[0-9a-f]{40}", args.source_sha) and args.source_sha == os.environ.get("CLI_SHA"), "verified_artifact_source_sha_mismatch")
    require(args.version and not any(c.isspace() for c in args.version), "version_invalid")
    temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    require(args.root.is_absolute() and not args.root.exists(), "root_not_fresh")
    args.root = args.root.resolve()
    require(args.root != temp and args.root.is_relative_to(temp), "root_outside_runner_temp")
    smoke = Smoke(args)
    try:
        smoke.run()
    except Exception as error:
        smoke.report.update(status="failed", failure=str(error) if isinstance(error, RuntimeError) else type(error).__name__)
        sqlite_failure = sqlite_failure_details(error)
        if sqlite_failure is not None:
            smoke.report["sqlite_failure"] = sqlite_failure
    finally:
        for connection in smoke.wal_connections:
            connection.close()
        smoke.cleanup()
        if smoke.keys is not None:
            try:
                smoke.report["keyring_cleanup"] = smoke.keys.cleanup()
            except Exception as error:
                smoke.report["keyring_cleanup"] = {"passed": False, "failure_code": type(error).__name__,
                    "remaining_entries": ["cleanup_not_verified"]}
        smoke.report["missing_cases"] = [case for case in REQUIRED if case not in smoke.report["cases"]]
        smoke.report["passed"] = smoke.report["status"] == "passed" and not smoke.report["missing_cases"] \
            and smoke.report["cloud_cleanup"]["passed"] and smoke.report["keyring_cleanup"]["passed"]
        smoke.save()
    print(json.dumps({"passed": smoke.report["passed"], "cases": len(smoke.report["cases"]),
        "report": str(smoke.root / "migration-coverage.json")}))
    return 0 if smoke.report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
