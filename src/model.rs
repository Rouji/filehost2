use sqlx::types::time::PrimitiveDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub(crate) struct Upload {
    pub id: Uuid,
    pub upload_timestamp: PrimitiveDateTime,
    pub expiry_timestamp: PrimitiveDateTime,
    pub deleted_timestamp: Option<PrimitiveDateTime>,
    pub original_name: String,
    pub slug: String,
    pub file_size: i64,
    pub hash: Option<Vec<u8>>,
    pub uploader_ip: Option<u32>,
}

#[derive(Debug, sqlx::FromRow)]
pub(crate) struct BannedIpv4Range {
    pub start_ip: u32,
    pub end_ip: u32,
    pub reason: Option<String>,
    pub banned_timestamp: PrimitiveDateTime,
    pub expires_timestamp: Option<PrimitiveDateTime>,
}

#[derive(Debug, sqlx::FromRow)]
pub(crate) struct BannedFileHash {
    pub hash: Vec<u8>, // 16-byte MD5
    pub reason: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
pub(crate) struct BannedFileExtension {
    pub extension: String,
}

#[derive(Debug, sqlx::FromRow)]
pub(crate) struct BannedFileMime {
    pub mime: String,
}
