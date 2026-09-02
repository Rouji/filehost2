CREATE TABLE IF NOT EXISTS challenge_verified_ips (
    ip VARBINARY(16) NOT NULL PRIMARY KEY,
    verified_timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_timestamp DATETIME NOT NULL,
    INDEX idx_challenge_verified_ips_expires (expires_timestamp)
);
