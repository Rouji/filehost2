-- Move deleted uploads out of the hot `uploads` table into `deleted_uploads`.
--
-- Until now deletion was purely soft: rows stayed in `uploads` forever with
-- `deleted_timestamp` set, and ~15 query sites filtered on it. `uploads` only
-- ever holds active rows after this migration; the two read sites that need
-- deleted rows (the admin list and the stats count) query the archive
-- directly, and the two indexes that led with `deleted_timestamp` are rebuilt
-- without it.
--
-- `accesses` keeps its FK but gains ON DELETE CASCADE: a row's download log
-- is purged automatically when the row moves to the archive. Egress forensics
-- for deleted files are deliberately dropped — they were only ever consumed
-- by the one-off abuse analysis (docs/abuse-analysis-2026-11-03.md).
--
-- The statements are not one atomic transaction (DDL autocommits), but each
-- step is safe to re-run: `INSERT IGNORE` skips rows already moved and the
-- `DELETE` simply finds nothing left to delete.

CREATE TABLE deleted_uploads (
    id BINARY(16) PRIMARY KEY,
    upload_timestamp DATETIME NOT NULL,
    expiry_timestamp DATETIME NOT NULL,
    deleted_timestamp DATETIME NOT NULL,
    original_name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL,
    file_size INT NOT NULL,
    hash BINARY(32) DEFAULT NULL,
    uploader_ip VARBINARY(16) NOT NULL,
    content_type VARCHAR(255) DEFAULT NULL,
    user_agent VARCHAR(512) DEFAULT NULL,
    nsfw_score FLOAT DEFAULT NULL
);

-- The FK was created unnamed (20260606000000), so its generated name varies
-- by server version (`accesses_ibfk_1` on MySQL, `1` on newer MariaDB); drop
-- it by looking the name up instead of hardcoding it.
SET @fk := (SELECT constraint_name FROM information_schema.referential_constraints
            WHERE constraint_schema = DATABASE() AND table_name = 'accesses' LIMIT 1);
PREPARE drop_fk FROM CONCAT('ALTER TABLE accesses DROP FOREIGN KEY `', @fk, '`');
EXECUTE drop_fk;
DEALLOCATE PREPARE drop_fk;

ALTER TABLE accesses
    ADD CONSTRAINT accesses_upload_id_fk FOREIGN KEY (upload_id) REFERENCES uploads(id)
    ON DELETE CASCADE;

INSERT IGNORE INTO deleted_uploads
    (id, upload_timestamp, expiry_timestamp, deleted_timestamp, original_name, slug,
     file_size, hash, uploader_ip, content_type, user_agent, nsfw_score)
SELECT id, upload_timestamp, expiry_timestamp, deleted_timestamp, original_name, slug,
       file_size, hash, uploader_ip, content_type, user_agent, nsfw_score
FROM uploads
WHERE deleted_timestamp IS NOT NULL;

-- Cascades away the accesses rows of everything that just moved.
DELETE FROM uploads WHERE deleted_timestamp IS NOT NULL;

-- The column is dead weight now: every row in `uploads` is active.
ALTER TABLE uploads DROP COLUMN deleted_timestamp;

-- The two `deleted_timestamp`-leading indexes are dead weight too; rebuild
-- them over the same workload without the leading column.
ALTER TABLE uploads DROP INDEX idx_uploads_active_uploader_size;
ALTER TABLE uploads DROP INDEX idx_uploads_active_upload_timestamp;
ALTER TABLE uploads ADD INDEX idx_uploads_uploader_size (uploader_ip, file_size);
ALTER TABLE uploads ADD INDEX idx_uploads_upload_timestamp (upload_timestamp);
