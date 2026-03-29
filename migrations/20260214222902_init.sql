CREATE TABLE IF NOT EXISTS uploads (
    id BINARY(16) PRIMARY KEY,
    upload_timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expiry_timestamp DATETIME NOT NULL,
    deleted_timestamp DATETIME DEFAULT NULL,
    original_name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL,
    file_size INT NOT NULL,
    store_path VARCHAR(255) DEFAULT NULL
);
