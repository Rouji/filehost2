-- Normalize banned extensions and MIME types to lowercase so ban checks
-- can use exact string matching without per-request to_lowercase() calls.
-- New inserts are already lowercased by LOWER(?) in the application SQL.
UPDATE banned_file_extensions SET extension = LOWER(extension);
UPDATE banned_file_mimes SET mime = LOWER(mime);