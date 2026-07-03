ALTER TABLE uploads ADD INDEX idx_uploads_slug (slug);

ALTER TABLE uploads ADD INDEX idx_uploads_uploader_ip_upload_timestamp (uploader_ip, upload_timestamp);

ALTER TABLE uploads ADD INDEX idx_uploads_expiry_timestamp (expiry_timestamp);

-- is_ip_banned runs on every upload with a known uploader IP. This table can
-- grow into the hundreds of thousands of rows (country block lists), so the
-- containment check (`? BETWEEN start_ip AND end_ip`) needs a covering index
-- to stay an index-only scan rather than hitting every candidate table row.
ALTER TABLE banned_ipv4_ranges ADD INDEX idx_banned_ipv4_ranges_start_end (start_ip, end_ip);
