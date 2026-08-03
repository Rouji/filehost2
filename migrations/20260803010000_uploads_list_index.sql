-- mainly db::list_uploads
ALTER TABLE uploads ADD INDEX idx_uploads_active_upload_timestamp (deleted_timestamp, upload_timestamp);
