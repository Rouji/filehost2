CREATE TABLE IF NOT EXISTS banned_filenames (
    pattern VARCHAR(255) NOT NULL PRIMARY KEY,
    reason VARCHAR(255) DEFAULT NULL
);

INSERT IGNORE INTO banned_filenames (pattern, reason)
SELECT CONCAT('\\.', extension, '$'), NULL FROM banned_file_extensions;

DROP TABLE banned_file_extensions;
