use sqlx::types::time::PrimitiveDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub(crate) struct Access {
    pub upload_id: Uuid,
    pub timestamp: PrimitiveDateTime,
    pub ipv4: Option<u32>,
    pub user_agent: Option<String>,
}

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
    pub content_type: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, sqlx::Type)]
#[repr(u32)]
pub enum BanType {
    ReadOnly = 1,
    Full = 2,
}

impl std::fmt::Display for BanType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BanType::ReadOnly => write!(f, "ReadOnly"),
            BanType::Full => write!(f, "Full"),
        }
    }
}

#[derive(Debug, sqlx::FromRow)]
pub(crate) struct BannedIpv4Range {
    pub id: i64,
    pub start_ip: u32,
    pub end_ip: u32,
    pub reason: Option<String>,
    pub banned_timestamp: PrimitiveDateTime,
    pub expires_timestamp: Option<PrimitiveDateTime>,
    #[sqlx(rename = "type")]
    pub type_: BanType,
    pub blacklist_id: Option<i32>,
}

#[derive(Debug, sqlx::FromRow)]
pub(crate) struct Blacklist {
    pub id: i32,
    pub url: String,
    #[sqlx(rename = "type")]
    pub type_: BanType,
    pub last_update: Option<PrimitiveDateTime>,
    pub update_interval_seconds: u64,
}

#[derive(Debug, sqlx::FromRow)]
pub(crate) struct BannedFileHash {
    pub hash: Vec<u8>,
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

#[derive(Debug, sqlx::FromRow)]
pub(crate) struct BannedUserAgent {
    pub pattern: String,
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // db::is_ip_banned runs `WHERE type >= ?` (binding `ban_type as u32`), so a Full ban
    // also satisfies a ReadOnly check only as long as Full's discriminant is the larger
    // one. If this fails, that query needs to change along with the enum.
    #[test]
    fn full_outranks_read_only_for_the_sql_severity_comparison() {
        assert!(BanType::Full as u32 > BanType::ReadOnly as u32);
    }
}
