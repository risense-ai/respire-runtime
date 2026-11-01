-- Pending or undecodable heads invalidate the same conservative review CAS.
CREATE TRIGGER IF NOT EXISTS memory_revision_head_insert AFTER INSERT ON sync_remote_heads
BEGIN
    UPDATE meta SET value=lower(hex(randomblob(16))) WHERE key='memory_revision_v1';
END;
CREATE TRIGGER IF NOT EXISTS memory_revision_head_update AFTER UPDATE ON sync_remote_heads
WHEN OLD.id IS NOT NEW.id OR OLD.rev IS NOT NEW.rev
  OR OLD.wire IS NOT NEW.wire OR OLD.decode_error IS NOT NEW.decode_error
BEGIN
    UPDATE meta SET value=lower(hex(randomblob(16))) WHERE key='memory_revision_v1';
END;
CREATE TRIGGER IF NOT EXISTS memory_revision_head_delete AFTER DELETE ON sync_remote_heads
BEGIN
    UPDATE meta SET value=lower(hex(randomblob(16))) WHERE key='memory_revision_v1';
END;
