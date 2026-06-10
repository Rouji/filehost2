-- Widen hash columns from MD5 (16 bytes) to BLAKE3 (32 bytes).
-- Existing MD5 hashes in uploads are cleared since they are incompatible.
ALTER TABLE uploads MODIFY COLUMN hash BINARY(32) DEFAULT NULL;
UPDATE uploads SET hash = NULL WHERE hash IS NOT NULL;

-- banned_file_hashes has hash as primary key; drop and recreate for new width.
-- Old MD5-based ban entries are incompatible and must be re-added as BLAKE3 hashes.
DROP TABLE IF EXISTS banned_file_hashes;
CREATE TABLE banned_file_hashes (
    hash BINARY(32) NOT NULL PRIMARY KEY,
    reason VARCHAR(255) DEFAULT NULL
);
