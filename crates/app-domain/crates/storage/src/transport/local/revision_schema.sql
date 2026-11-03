-- Local snapshot invalidation only; never a cloud version or synchronization cursor.
-- Install in the schema migration transaction, after all memory columns exist.
INSERT OR IGNORE INTO meta(key, value)
VALUES ('memory_revision_v1', lower(hex(randomblob(16))));

CREATE TRIGGER IF NOT EXISTS memory_revision_insert AFTER INSERT ON memories
BEGIN
    UPDATE meta SET value = lower(hex(randomblob(16))) WHERE key = 'memory_revision_v1';
END;

-- Null-safe comparison also supports upgraded TEXT-ID schemas with nullable columns.
-- Dirty acknowledgements, recall counters and derived embeddings are bookkeeping,
-- not new memory content. Polling/listing/recalling must not invalidate themselves.
CREATE TRIGGER IF NOT EXISTS memory_revision_update AFTER UPDATE ON memories
WHEN OLD.id IS NOT NEW.id
  OR OLD.user IS NOT NEW.user
  OR OLD.ciphertext IS NOT NEW.ciphertext
  OR OLD.nonce IS NOT NEW.nonce
  OR OLD.updated_at IS NOT NEW.updated_at
  OR OLD.deleted IS NOT NEW.deleted
  OR OLD.kind IS NOT NEW.kind
  OR OLD.tags IS NOT NEW.tags
  OR OLD.title IS NOT NEW.title
  OR OLD.project IS NOT NEW.project
  OR OLD.computer IS NOT NEW.computer
  OR OLD.created_at IS NOT NEW.created_at
  OR OLD.parent_id IS NOT NEW.parent_id
  OR OLD.content_head IS NOT NEW.content_head
  OR OLD.importance IS NOT NEW.importance
  OR OLD.device IS NOT NEW.device
  OR OLD.modified_by IS NOT NEW.modified_by
BEGIN
    UPDATE meta SET value = lower(hex(randomblob(16))) WHERE key = 'memory_revision_v1';
END;

CREATE TRIGGER IF NOT EXISTS memory_revision_delete AFTER DELETE ON memories
BEGIN
    UPDATE meta SET value = lower(hex(randomblob(16))) WHERE key = 'memory_revision_v1';
END;
