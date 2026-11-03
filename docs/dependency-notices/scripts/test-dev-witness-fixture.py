#!/usr/bin/env python3
"""Exercise real witness SQL triggers with the fixture's canonical v1 UDFs."""
import hashlib
import sqlite3
import unittest
from pathlib import Path

from dev_witness_fixture import event_digest, register_witness_functions, source_digest, verify_fixture_witness, sqlite_failure_details

SQL = (Path(__file__).resolve().parents[1] /
       "crates/storage/src/transport/local/witness_schema.sql").read_text()
FIELDS = ("id,user,ciphertext,nonce,embedding_enc,updated_at,deleted,kind,tags,title,"
          "project,computer,created_at,parent_id,content_head,importance,device,modified_by")


class WitnessFixtureTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        columns = [f"{name} TEXT" for name in FIELDS.split(",")]
        columns[0] += " PRIMARY KEY"
        columns[6] = "deleted INTEGER"
        self.db.execute("CREATE TABLE memories(" + ",".join(columns) + ")")
        self.db.execute("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT)")
        self.db.execute("INSERT INTO meta VALUES('witness_library_id_v1','synthetic-library')")
        self.db.executescript(SQL)
        self.schema = self.db.execute("SELECT name,sql FROM sqlite_master ORDER BY name").fetchall()
        register_witness_functions(self.db)

    def insert(self):
        values = ["synthetic-id", "synthetic-user", "\u5bc6\u6587\n\"\\", "nonce", None,
                  "2026-10-25T00:00:00Z", 0, "important", "[]", "\u6807\u9898", "", "", "", "", "", "", "", ""]
        self.db.execute("INSERT INTO memories(" + FIELDS + ") VALUES(" + ",".join("?" * 18) + ")", values)
        return values

    def test_canonical_utf8_optional_fields_and_domain(self):
        fields = ["\u7528\u6237\n\"\\/", None] + [""] * 16
        literal = '["\u7528\u6237\\n\\"\\\\/",null,' + ','.join(['""'] * 16) + ']'
        expected = hashlib.sha256(b"rsrs:witness:source:v1\0" + literal.encode()).hexdigest()
        self.assertEqual(source_digest(*fields), expected)
        self.assertNotEqual(source_digest(*fields), source_digest(*([None] * 18)))
        args = ("\u5e93", 9007199254740993, "stamp", "update", "id", "old", None, "digest", "0" * 64)
        literal = '[1,"\u5e93",9007199254740993,"stamp","update","id","old",null,"digest","' + "0" * 64 + '"]'
        self.assertEqual(event_digest(*args), hashlib.sha256(b"rsrs:witness:event:v1\0" + literal.encode()).hexdigest())

    def test_real_create_update_delete_triggers_and_source_binding(self):
        values = self.insert()
        values[6] = "0"  # The actual trigger explicitly casts the SQLite integer.
        self.assertEqual(self.db.execute("SELECT after_digest FROM witness_log").fetchone()[0], source_digest(*values))
        self.db.execute("UPDATE memories SET ciphertext='legacy-cipher',nonce='legacy-nonce'")
        self.db.execute("DELETE FROM memories")
        self.assertEqual([r[0] for r in self.db.execute("SELECT action FROM witness_log ORDER BY seq")], ["create", "update", "prune"])
        self.assertEqual(verify_fixture_witness(self.db)["count"], 3)
        self.assertEqual(self.schema, self.db.execute("SELECT name,sql FROM sqlite_master ORDER BY name").fetchall())

    def test_missing_registration_reproduces_failure_without_source_or_event(self):
        self.insert()
        self.db.commit()
        self.db.create_function("rsrs_witness_source_v1", 18, None)
        with self.assertRaises(sqlite3.OperationalError):
            self.db.execute("UPDATE memories SET ciphertext='cannot-commit'")
        self.assertNotEqual(self.db.execute("SELECT ciphertext FROM memories").fetchone()[0], "cannot-commit")
        self.assertEqual(verify_fixture_witness(self.db)["count"], 1)

    def test_explicit_rollback_keeps_both_source_and_chain(self):
        self.insert()
        self.db.commit()
        before = verify_fixture_witness(self.db)
        self.db.execute("BEGIN")
        self.db.execute("UPDATE memories SET ciphertext='uncommitted'")
        self.assertEqual(verify_fixture_witness(self.db)["count"], 2)
        self.db.rollback()
        self.assertEqual(verify_fixture_witness(self.db), before)

    def test_wrong_types_fail_without_noop_or_constant_digest(self):
        for fields in ([""] * 17, [1] + [""] * 17, [b"blob"] + [""] * 17):
            with self.assertRaises(ValueError):
                source_digest(*fields)
        for seq in (True, 1.0, 2**63):
            with self.assertRaises(ValueError):
                event_digest("l", seq, "t", "a", "i", "", None, None, "p")
        self.insert()
        with self.assertRaises(sqlite3.OperationalError):
            self.db.execute("UPDATE memories SET ciphertext=x'ff'")
        self.assertEqual(verify_fixture_witness(self.db)["count"], 1)

    def test_tamper_and_missing_identity_are_not_reset(self):
        self.insert()
        self.db.execute("UPDATE witness_log SET after_digest='wrong'")
        with self.assertRaises(ValueError):
            verify_fixture_witness(self.db)
        self.db.execute("DELETE FROM meta")
        with self.assertRaises(ValueError):
            verify_fixture_witness(self.db)

    def test_older_cli_without_witness_is_unchanged(self):
        with sqlite3.connect(":memory:") as old:
            register_witness_functions(old)
            self.assertIsNone(verify_fixture_witness(old))
            self.assertEqual(old.execute("SELECT count(*) FROM sqlite_master").fetchone()[0], 0)

    def test_sqlite_diagnostics_never_echo_row_text(self):
        private = "SYNTHETIC-DO-NOT-ECHO"
        self.assertNotIn(private, str(sqlite_failure_details(sqlite3.OperationalError(private))))
        self.assertEqual(sqlite_failure_details(sqlite3.OperationalError(
            "no such function: rsrs_witness_source_v1"))["reason"], "witness_source_udf_missing")
        self.assertIsNone(sqlite_failure_details(ValueError(private)))


if __name__ == "__main__":
    unittest.main()
