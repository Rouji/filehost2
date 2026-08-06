-- Widen IP storage from INT UNSIGNED (IPv4-only, 4 bytes) to VARBINARY(16),
-- using IPv4-mapped IPv6 (::ffff:a.b.c.d) for existing v4 addresses. This
-- keeps the trailing 4 bytes of a mapped address numerically identical to
-- the old u32 value, so BETWEEN-based range comparisons keep working
-- unchanged for IPv4 ranges while also supporting native IPv6 ranges.
--
-- Done as add-shadow-column -> populate -> drop-old -> rename-shadow rather
-- than a plain MODIFY COLUMN, since this is a data transform, not just a
-- wider type. Indexes covering the dropped columns are re-created at the end.

-- uploads.uploader_ip
ALTER TABLE uploads ADD COLUMN uploader_ip_v2 VARBINARY(16) DEFAULT NULL;
UPDATE uploads
SET uploader_ip_v2 = UNHEX(CONCAT('00000000000000000000FFFF', LPAD(HEX(uploader_ip), 8, '0')))
WHERE uploader_ip IS NOT NULL;
ALTER TABLE uploads DROP INDEX idx_uploads_uploader_ip_upload_timestamp;
ALTER TABLE uploads DROP INDEX idx_uploads_active_uploader_size;
ALTER TABLE uploads DROP COLUMN uploader_ip;
ALTER TABLE uploads CHANGE COLUMN uploader_ip_v2 uploader_ip VARBINARY(16) DEFAULT NULL;
ALTER TABLE uploads ADD INDEX idx_uploads_uploader_ip_upload_timestamp (uploader_ip, upload_timestamp);
ALTER TABLE uploads ADD INDEX idx_uploads_active_uploader_size (deleted_timestamp, uploader_ip, file_size);

-- accesses.ipv4 -> accesses.ip
ALTER TABLE accesses ADD COLUMN ip VARBINARY(16) DEFAULT NULL;
UPDATE accesses
SET ip = UNHEX(CONCAT('00000000000000000000FFFF', LPAD(HEX(ipv4), 8, '0')))
WHERE ipv4 IS NOT NULL;
ALTER TABLE accesses DROP COLUMN ipv4;

-- banned_ipv4_ranges -> banned_ip_ranges, start_ip/end_ip widened
ALTER TABLE banned_ipv4_ranges ADD COLUMN start_ip_v2 VARBINARY(16);
ALTER TABLE banned_ipv4_ranges ADD COLUMN end_ip_v2 VARBINARY(16);
UPDATE banned_ipv4_ranges
SET start_ip_v2 = UNHEX(CONCAT('00000000000000000000FFFF', LPAD(HEX(start_ip), 8, '0'))),
    end_ip_v2 = UNHEX(CONCAT('00000000000000000000FFFF', LPAD(HEX(end_ip), 8, '0')));
ALTER TABLE banned_ipv4_ranges DROP INDEX idx_banned_ipv4_ranges_start_end;
ALTER TABLE banned_ipv4_ranges DROP COLUMN start_ip;
ALTER TABLE banned_ipv4_ranges DROP COLUMN end_ip;
ALTER TABLE banned_ipv4_ranges CHANGE COLUMN start_ip_v2 start_ip VARBINARY(16) NOT NULL;
ALTER TABLE banned_ipv4_ranges CHANGE COLUMN end_ip_v2 end_ip VARBINARY(16) NOT NULL;
ALTER TABLE banned_ipv4_ranges ADD INDEX idx_banned_ip_ranges_start_end (start_ip, end_ip);

RENAME TABLE banned_ipv4_ranges TO banned_ip_ranges;
