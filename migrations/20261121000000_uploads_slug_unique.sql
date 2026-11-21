-- Slug uniqueness was only enforced by the check-then-insert sequence in
-- allocate_unique_slug (handlers.rs): two concurrent uploads could pass the
-- check with the same candidate slug before either inserted, and
-- get_upload_by_slug would then silently serve one of the two rows
-- (fetch_optional returns the first it sees).
--
-- Make the insert the arbiter instead; the upload handler now retries with a
-- longer id when its insert loses that race. Lookups keep using the same
-- index, just unique now.
--
-- Fails on a database that already holds duplicate slugs; resolve those by
-- hand first (the check-then-insert race makes them unlikely but possible).
ALTER TABLE uploads
    DROP INDEX idx_uploads_slug,
    ADD UNIQUE INDEX uq_uploads_slug (slug);
