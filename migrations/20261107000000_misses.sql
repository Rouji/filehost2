-- Slug-miss log (1d in docs/abuse-analysis-2026-11-03.md): every 404 on the
-- file route records the requested slug, IP and user agent, so slug
-- enumeration (D8) is visible and the batch rule engine can run over it.
--
-- Deliberately separate from `accesses`: misses have no upload to point at,
-- are dominated by scanner bursts, and only need short retention — the table
-- is high-churn and pruned nightly by `delete-expired`, unlike the permanent
-- egress accounting in `accesses`.

CREATE TABLE misses (
    id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip VARBINARY(16) NOT NULL,
    slug VARCHAR(255) NOT NULL,
    user_agent VARCHAR(512) DEFAULT NULL,
    INDEX idx_misses_ip_ts (ip, timestamp),
    INDEX idx_misses_ts (timestamp)
);
