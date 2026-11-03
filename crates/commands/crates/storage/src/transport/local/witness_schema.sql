-- No user text or key material is stored in witness rows. Digests are domain-separated canonical JSON.
CREATE TABLE IF NOT EXISTS witness_log (
 schema_version INTEGER NOT NULL CHECK(schema_version=1),library_id TEXT NOT NULL,
 seq INTEGER PRIMARY KEY,ts TEXT NOT NULL,action TEXT NOT NULL,entry_id TEXT NOT NULL,previous_entry_id TEXT NOT NULL,
 before_digest TEXT,after_digest TEXT,prev TEXT NOT NULL,hash TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS witness_source_insert_v1 AFTER INSERT ON memories
BEGIN
 INSERT INTO witness_log(schema_version,library_id,seq,ts,action,entry_id,previous_entry_id,before_digest,after_digest,prev,hash)
 SELECT 1,library,sequence,stamp,operation,entry,previous_entry,before_hash,after_hash,previous_hash,
 rsrs_witness_event_v1(library,sequence,stamp,operation,entry,previous_entry,before_hash,after_hash,previous_hash)
 FROM (SELECT (SELECT value FROM meta WHERE key='witness_library_id_v1') AS library,
 COALESCE((SELECT MAX(seq) FROM witness_log),0)+1 AS sequence,strftime('%Y-%m-%dT%H:%M:%fZ','now') AS stamp,
 'create' AS operation,NEW.id AS entry,'' AS previous_entry,NULL AS before_hash,rsrs_witness_source_v1(NEW.id,NEW.user,NEW.ciphertext,NEW.nonce,NEW.embedding_enc,NEW.updated_at,CAST(NEW.deleted AS TEXT),NEW.kind,NEW.tags,NEW.title,NEW.project,NEW.computer,NEW.created_at,NEW.parent_id,NEW.content_head,NEW.importance,NEW.device,NEW.modified_by) AS after_hash,
 COALESCE((SELECT hash FROM witness_log ORDER BY seq DESC LIMIT 1),'0000000000000000000000000000000000000000000000000000000000000000') AS previous_hash);
END;
CREATE TRIGGER IF NOT EXISTS witness_source_update_v1 AFTER UPDATE ON memories WHEN OLD.id IS NOT NEW.id OR OLD.user IS NOT NEW.user OR OLD.ciphertext IS NOT NEW.ciphertext OR OLD.nonce IS NOT NEW.nonce OR OLD.embedding_enc IS NOT NEW.embedding_enc OR OLD.updated_at IS NOT NEW.updated_at OR OLD.deleted IS NOT NEW.deleted OR OLD.kind IS NOT NEW.kind OR OLD.tags IS NOT NEW.tags OR OLD.title IS NOT NEW.title OR OLD.project IS NOT NEW.project OR OLD.computer IS NOT NEW.computer OR OLD.created_at IS NOT NEW.created_at OR OLD.parent_id IS NOT NEW.parent_id OR OLD.content_head IS NOT NEW.content_head OR OLD.importance IS NOT NEW.importance OR OLD.device IS NOT NEW.device OR OLD.modified_by IS NOT NEW.modified_by
BEGIN
 INSERT INTO witness_log(schema_version,library_id,seq,ts,action,entry_id,previous_entry_id,before_digest,after_digest,prev,hash)
 SELECT 1,library,sequence,stamp,operation,entry,previous_entry,before_hash,after_hash,previous_hash,
 rsrs_witness_event_v1(library,sequence,stamp,operation,entry,previous_entry,before_hash,after_hash,previous_hash)
 FROM (SELECT (SELECT value FROM meta WHERE key='witness_library_id_v1') AS library,
 COALESCE((SELECT MAX(seq) FROM witness_log),0)+1 AS sequence,strftime('%Y-%m-%dT%H:%M:%fZ','now') AS stamp,
 CASE WHEN OLD.ciphertext IS NOT NEW.ciphertext AND NEW.ciphertext='' THEN 'purge' WHEN OLD.deleted IS NOT NEW.deleted AND NEW.deleted=1 THEN 'tombstone' WHEN OLD.deleted IS NOT NEW.deleted AND NEW.deleted=0 THEN 'restore' WHEN OLD.parent_id IS NOT NEW.parent_id THEN 'attach' ELSE 'update' END AS operation,NEW.id AS entry,OLD.id AS previous_entry,rsrs_witness_source_v1(OLD.id,OLD.user,OLD.ciphertext,OLD.nonce,OLD.embedding_enc,OLD.updated_at,CAST(OLD.deleted AS TEXT),OLD.kind,OLD.tags,OLD.title,OLD.project,OLD.computer,OLD.created_at,OLD.parent_id,OLD.content_head,OLD.importance,OLD.device,OLD.modified_by) AS before_hash,rsrs_witness_source_v1(NEW.id,NEW.user,NEW.ciphertext,NEW.nonce,NEW.embedding_enc,NEW.updated_at,CAST(NEW.deleted AS TEXT),NEW.kind,NEW.tags,NEW.title,NEW.project,NEW.computer,NEW.created_at,NEW.parent_id,NEW.content_head,NEW.importance,NEW.device,NEW.modified_by) AS after_hash,
 COALESCE((SELECT hash FROM witness_log ORDER BY seq DESC LIMIT 1),'0000000000000000000000000000000000000000000000000000000000000000') AS previous_hash);
END;
CREATE TRIGGER IF NOT EXISTS witness_source_delete_v1 AFTER DELETE ON memories
BEGIN
 INSERT INTO witness_log(schema_version,library_id,seq,ts,action,entry_id,previous_entry_id,before_digest,after_digest,prev,hash)
 SELECT 1,library,sequence,stamp,operation,entry,previous_entry,before_hash,after_hash,previous_hash,
 rsrs_witness_event_v1(library,sequence,stamp,operation,entry,previous_entry,before_hash,after_hash,previous_hash)
 FROM (SELECT (SELECT value FROM meta WHERE key='witness_library_id_v1') AS library,
 COALESCE((SELECT MAX(seq) FROM witness_log),0)+1 AS sequence,strftime('%Y-%m-%dT%H:%M:%fZ','now') AS stamp,
 'prune' AS operation,OLD.id AS entry,OLD.id AS previous_entry,rsrs_witness_source_v1(OLD.id,OLD.user,OLD.ciphertext,OLD.nonce,OLD.embedding_enc,OLD.updated_at,CAST(OLD.deleted AS TEXT),OLD.kind,OLD.tags,OLD.title,OLD.project,OLD.computer,OLD.created_at,OLD.parent_id,OLD.content_head,OLD.importance,OLD.device,OLD.modified_by) AS before_hash,NULL AS after_hash,
 COALESCE((SELECT hash FROM witness_log ORDER BY seq DESC LIMIT 1),'0000000000000000000000000000000000000000000000000000000000000000') AS previous_hash);
END;
