-- IP-to-ASN mapping used by per-ASN abuse-detection queries (see docs/abuse-analysis-2026-11-03.md).
-- Populated by `filehost2 asn-sync` from iptoasn.com (public domain data).
-- IPs use the same VARBINARY(16) convention as uploads.uploader_ip / accesses.ip:
-- IPv4 stored as ::ffff:-mapped, IPv6 raw. Ranges are sorted and non-overlapping
-- within each family, which makes the "greatest start_ip <= target" point lookup valid.
CREATE TABLE IF NOT EXISTS ip_asn (
    start_ip VARBINARY(16) NOT NULL,
    end_ip   VARBINARY(16) NOT NULL,
    asn      INT UNSIGNED  NOT NULL,
    country  CHAR(2)       NOT NULL DEFAULT '',
    org      VARCHAR(255)  NOT NULL,
    PRIMARY KEY (start_ip, end_ip),
    INDEX idx_ip_asn_start (start_ip)
);
