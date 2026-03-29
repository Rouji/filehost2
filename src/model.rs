use sqlx::types::time::PrimitiveDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
#[allow(non_snake_case)]
pub(crate) struct Upload {
    pub id: Uuid,
    pub upload_timestamp: PrimitiveDateTime,
    pub expiry_timestamp: PrimitiveDateTime,
    pub deleted_timestamp: Option<PrimitiveDateTime>,
    pub original_name: String,
    pub slug: String,
    pub file_size: i64,
}
