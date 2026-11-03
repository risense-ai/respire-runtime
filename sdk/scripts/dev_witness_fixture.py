"""Witness-v1 interoperability for isolated synthetic migration fixtures only.

Keep the real triggers installed. These functions encode the same versioned
JSON tuples as storage/transport/local/witness.rs; no constant/no-op UDFs.
"""
import hashlib
import json
import re
import sqlite3


def _digest(domain, fields):
    payload = json.dumps(fields, ensure_ascii=False, separators=(",", ":"),
                         allow_nan=False).encode("utf-8")
    return hashlib.sha256(domain + payload).hexdigest()


def source_digest(*fields):
    if len(fields) != 18 or any(v is not None and type(v) is not str for v in fields):
        raise ValueError("witness source requires eighteen optional strings")
    return _digest(b"rsrs:witness:source:v1\0", fields)


def event_digest(library, seq, stamp, action, entry, previous_entry, before, after, prev):
    if (type(seq) is not int or not -(2**63) <= seq < 2**63
            or any(type(v) is not str for v in (library, stamp, action, entry, previous_entry, prev))
            or any(v is not None and type(v) is not str for v in (before, after))):
        raise ValueError("invalid witness event types")
    return _digest(b"rsrs:witness:event:v1\0",
                   (1, library, seq, stamp, action, entry, previous_entry, before, after, prev))


def register_witness_functions(connection):
    connection.create_function("rsrs_witness_source_v1", 18, source_digest, deterministic=True)
    connection.create_function("rsrs_witness_event_v1", 9, event_digest, deterministic=True)


def sqlite_failure_details(error):
    """Fixed diagnostic classes only; SQL errors can contain private row text."""
    if not isinstance(error, sqlite3.Error):
        return None
    code = getattr(error, "sqlite_errorcode", None)
    name = getattr(error, "sqlite_errorname", None)
    detail = {"code": code if type(code) is int else None,
              "name": name if type(name) is str and re.fullmatch(r"SQLITE_[A-Z0-9_]+", name) else None}
    known = {"no such function: rsrs_witness_source_v1": "witness_source_udf_missing",
             "no such function: rsrs_witness_event_v1": "witness_event_udf_missing"}
    detail["reason"] = known.get(str(error), "sqlite_error")
    return detail


def verify_fixture_witness(connection):
    """Read-only check; None means the tested older CLI has no witness schema."""
    if not connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='witness_log'").fetchone():
        return None
    identity = connection.execute("SELECT value FROM meta WHERE key='witness_library_id_v1'").fetchone()
    if identity is None or type(identity[0]) is not str:
        raise ValueError("fixture witness identity missing")
    head, count = "0" * 64, 0
    for row in connection.execute("SELECT schema_version,library_id,seq,ts,action,entry_id,previous_entry_id,before_digest,after_digest,prev,hash FROM witness_log ORDER BY seq"):
        version, library, seq, stamp, action, entry, previous_entry, before, after, prev, digest = row
        expected = event_digest(library, seq, stamp, action, entry, previous_entry, before, after, prev)
        if version != 1 or library != identity[0] or seq != count + 1 or prev != head or digest != expected:
            raise ValueError("fixture witness chain invalid")
        count, head = count + 1, digest
    return {"count": count, "head": head, "intact": True}
