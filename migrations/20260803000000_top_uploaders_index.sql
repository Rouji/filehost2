-- basically for db::top_uploader_ips
ALTER TABLE uploads ADD INDEX idx_uploads_active_uploader_size (deleted_timestamp, uploader_ip, file_size);
