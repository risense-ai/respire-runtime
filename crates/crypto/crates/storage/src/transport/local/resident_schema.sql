-- Derived-cache revisions are local and do not alter synchronized payloads.
CREATE TABLE IF NOT EXISTS retrieval_revision (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1), revision INTEGER NOT NULL
);
INSERT OR IGNORE INTO retrieval_revision VALUES(1,0);
CREATE TABLE IF NOT EXISTS retrieval_changes (
    memory_id TEXT PRIMARY KEY, revision INTEGER NOT NULL
);
CREATE TRIGGER IF NOT EXISTS retrieval_memory_insert AFTER INSERT ON memories BEGIN
    UPDATE retrieval_revision SET revision=revision+1 WHERE singleton=1;
    INSERT INTO retrieval_changes VALUES(NEW.id,(SELECT revision FROM retrieval_revision WHERE singleton=1))
    ON CONFLICT(memory_id) DO UPDATE SET revision=excluded.revision;
END;
CREATE TRIGGER IF NOT EXISTS retrieval_memory_update AFTER UPDATE ON memories BEGIN
    UPDATE retrieval_revision SET revision=revision+1 WHERE singleton=1;
    INSERT INTO retrieval_changes VALUES(NEW.id,(SELECT revision FROM retrieval_revision WHERE singleton=1))
    ON CONFLICT(memory_id) DO UPDATE SET revision=excluded.revision;
END;
CREATE TRIGGER IF NOT EXISTS retrieval_memory_delete AFTER DELETE ON memories BEGIN
    UPDATE retrieval_revision SET revision=revision+1 WHERE singleton=1;
    INSERT INTO retrieval_changes VALUES(OLD.id,(SELECT revision FROM retrieval_revision WHERE singleton=1))
    ON CONFLICT(memory_id) DO UPDATE SET revision=excluded.revision;
END;
CREATE TRIGGER IF NOT EXISTS retrieval_artifact_insert AFTER INSERT ON core_artifacts BEGIN
    UPDATE retrieval_revision SET revision=revision+1 WHERE singleton=1;
    INSERT INTO retrieval_changes VALUES(NEW.memory_id,(SELECT revision FROM retrieval_revision WHERE singleton=1))
    ON CONFLICT(memory_id) DO UPDATE SET revision=excluded.revision;
END;
CREATE TRIGGER IF NOT EXISTS retrieval_artifact_update AFTER UPDATE ON core_artifacts BEGIN
    UPDATE retrieval_revision SET revision=revision+1 WHERE singleton=1;
    INSERT INTO retrieval_changes VALUES(NEW.memory_id,(SELECT revision FROM retrieval_revision WHERE singleton=1))
    ON CONFLICT(memory_id) DO UPDATE SET revision=excluded.revision;
END;
CREATE TRIGGER IF NOT EXISTS retrieval_artifact_delete AFTER DELETE ON core_artifacts BEGIN
    UPDATE retrieval_revision SET revision=revision+1 WHERE singleton=1;
    INSERT INTO retrieval_changes VALUES(OLD.memory_id,(SELECT revision FROM retrieval_revision WHERE singleton=1))
    ON CONFLICT(memory_id) DO UPDATE SET revision=excluded.revision;
END;
