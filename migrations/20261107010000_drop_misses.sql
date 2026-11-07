-- Reverses 20261107000000_misses.sql: slug-miss forensics in the DB proved
-- unnecessary after a few hours in production (shipped and dropped on
-- 2026-11-07). The brute-force / enumeration signal it fed is handled in
-- memory (per-IP miss counter -> PoW challenge), and the stdout access log
-- already records every miss. The original migration file is kept unchanged
-- because it is already applied — altering it would break checksum validation.

DROP TABLE IF EXISTS misses;
