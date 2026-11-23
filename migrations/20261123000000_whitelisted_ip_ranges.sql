CREATE TABLE IF NOT EXISTS whitelisted_ip_ranges (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    start_ip VARBINARY(16) NOT NULL,
    end_ip VARBINARY(16) NOT NULL,
    reason VARCHAR(255) DEFAULT NULL,
    created_timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_whitelisted_ip_ranges_start_end (start_ip, end_ip)
);
