-- Egress accounting (2a in docs/abuse-analysis-2026-11-03.md): record what a
-- download actually served and how it answered, so download-side abuse rules
-- (per-IP and per-file egress volume, polling regularity, harvester sweeps)
-- have data to run on.
--
-- `bytes` is BIGINT UNSIGNED (the report sketched INT UNSIGNED, but a single
-- file can exceed the 4 GiB INT cap). Both columns are NULL: older rows keep
-- their "unknown" shape, and HEAD requests serve no body.
--
-- The indexes are what every download-side rule needs; before this, per-IP
-- scans over `accesses` were full-table (only the upload_id FK was usable).

ALTER TABLE accesses ADD COLUMN bytes BIGINT UNSIGNED NULL;
ALTER TABLE accesses ADD COLUMN status SMALLINT UNSIGNED NULL;
ALTER TABLE accesses ADD INDEX idx_accesses_ip_ts (ip, timestamp);
ALTER TABLE accesses ADD INDEX idx_accesses_upload_ts (upload_id, timestamp);
