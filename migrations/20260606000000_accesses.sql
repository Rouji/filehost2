CREATE TABLE accesses (
    upload_id BINARY(16) NOT NULL,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ipv4      INT UNSIGNED,
    FOREIGN KEY (upload_id) REFERENCES uploads(id)
);
