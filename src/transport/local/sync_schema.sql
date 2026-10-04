CREATE TABLE IF NOT EXISTS sync_base (id TEXT PRIMARY KEY, rev INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sync_remote_heads (id TEXT PRIMARY KEY, rev INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sync_conflict_analysis (
    epoch TEXT NOT NULL, rev INTEGER NOT NULL, kind TEXT NOT NULL,
    head_rev INTEGER NOT NULL, reason TEXT NOT NULL,
    PRIMARY KEY(epoch,rev)
);
CREATE TABLE IF NOT EXISTS sync_resolutions (
    epoch TEXT NOT NULL, conflict_rev INTEGER NOT NULL, seq INTEGER NOT NULL,
    id TEXT NOT NULL, action TEXT NOT NULL, head_rev INTEGER NOT NULL,
    restore_op_id TEXT, processed_at TEXT NOT NULL,
    PRIMARY KEY(epoch,conflict_rev), UNIQUE(epoch,seq)
);
CREATE TABLE IF NOT EXISTS sync_resolution_outbox (
    epoch TEXT NOT NULL, conflict_rev INTEGER NOT NULL, action TEXT NOT NULL,
    expected_head_rev INTEGER NOT NULL, restore_op_id TEXT,
    PRIMARY KEY(epoch,conflict_rev)
);
CREATE TABLE IF NOT EXISTS sync_outbox (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    op_id TEXT NOT NULL UNIQUE,
    id TEXT NOT NULL,
    base_rev INTEGER,
    parent_op_id TEXT,
    user TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    nonce TEXT NOT NULL,
    embedding_enc TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    deleted INTEGER NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending'
);
CREATE INDEX IF NOT EXISTS sync_outbox_pending ON sync_outbox(state,seq);
CREATE INDEX IF NOT EXISTS sync_outbox_object ON sync_outbox(id,seq DESC);
CREATE TABLE IF NOT EXISTS sync_inbox (
    epoch TEXT NOT NULL, rev INTEGER NOT NULL, id TEXT NOT NULL,
    status TEXT NOT NULL, op_id TEXT, wire TEXT NOT NULL,
    decode_error TEXT NOT NULL DEFAULT '',
    PRIMARY KEY(epoch,rev)
);
-- Every local save and its immutable outgoing version share the SQLite statement.
CREATE TRIGGER IF NOT EXISTS sync_capture_insert AFTER INSERT ON memories WHEN NEW.dirty=1
BEGIN
 INSERT INTO sync_outbox (op_id,id,base_rev,parent_op_id,user,ciphertext,nonce,embedding_enc,updated_at,deleted)
 VALUES (lower(hex(randomblob(16))),NEW.id,(SELECT rev FROM sync_base WHERE id=NEW.id),
 (SELECT op_id FROM sync_outbox WHERE id=NEW.id AND state='pending' ORDER BY seq DESC LIMIT 1),
 NEW.user,NEW.ciphertext,NEW.nonce,'',NEW.updated_at,NEW.deleted);
END;
CREATE TRIGGER IF NOT EXISTS sync_capture_update AFTER UPDATE ON memories
WHEN NEW.dirty=1 AND (NEW.ciphertext<>OLD.ciphertext OR NEW.nonce<>OLD.nonce OR NEW.updated_at<>OLD.updated_at OR NEW.deleted<>OLD.deleted)
BEGIN
 INSERT INTO sync_outbox (op_id,id,base_rev,parent_op_id,user,ciphertext,nonce,embedding_enc,updated_at,deleted)
 VALUES (lower(hex(randomblob(16))),NEW.id,(SELECT rev FROM sync_base WHERE id=NEW.id),
 (SELECT op_id FROM sync_outbox WHERE id=NEW.id AND state='pending' ORDER BY seq DESC LIMIT 1),
 NEW.user,NEW.ciphertext,NEW.nonce,'',NEW.updated_at,NEW.deleted);
END;
-- Upgrade capture must happen before the first network pull.
INSERT INTO sync_outbox (op_id,id,base_rev,user,ciphertext,nonce,updated_at,deleted)
SELECT lower(hex(randomblob(16))),m.id,NULL,m.user,m.ciphertext,m.nonce,m.updated_at,m.deleted
FROM memories m WHERE m.dirty=1 AND NOT EXISTS (
 SELECT 1 FROM sync_outbox o WHERE o.id=m.id AND o.ciphertext=m.ciphertext AND o.nonce=m.nonce
 AND o.updated_at=m.updated_at AND o.deleted=m.deleted AND o.state='pending');
