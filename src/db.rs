use std::path::Path;

use anyhow::Result;
use sqlx::{Row, mysql::MySqlPool};
use time::PrimitiveDateTime;
use uuid::Uuid;

use crate::model::{BannedFileExtension, BannedFileHash, BannedFileMime, BannedIpv4Range, Upload};
use crate::settings::Settings;
use crate::upload::uuid_to_path;

pub(crate) async fn is_ip_banned(db: &MySqlPool, ip: u32) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query(
        "SELECT 1 FROM banned_ipv4_ranges \
         WHERE ? BETWEEN start_ip AND end_ip \
         AND (expires_timestamp IS NULL OR expires_timestamp > NOW())",
    )
    .bind(ip)
    .fetch_optional(db)
    .await?
    .is_some())
}

pub(crate) async fn is_extension_banned(db: &MySqlPool, ext: &str) -> Result<bool, sqlx::Error> {
    Ok(
        sqlx::query("SELECT 1 FROM banned_file_extensions WHERE extension = ?")
            .bind(ext)
            .fetch_optional(db)
            .await?
            .is_some(),
    )
}

pub(crate) async fn is_mime_banned(db: &MySqlPool, mime: &str) -> Result<bool, sqlx::Error> {
    Ok(
        sqlx::query("SELECT 1 FROM banned_file_mimes WHERE mime = ?")
            .bind(mime)
            .fetch_optional(db)
            .await?
            .is_some(),
    )
}

pub(crate) async fn is_hash_banned(db: &MySqlPool, hash: &[u8]) -> Result<bool, sqlx::Error> {
    Ok(
        sqlx::query("SELECT 1 FROM banned_file_hashes WHERE hash = ?")
            .bind(hash)
            .fetch_optional(db)
            .await?
            .is_some(),
    )
}

/// Soft-deletes every upload matching a `WHERE` clause appended to the base
/// select below, via `bind`. Shared by all the `delete_by_*`/`delete_expired`
/// variants, which differ only in which rows they select.
async fn delete_matching(
    db: &MySqlPool,
    settings: &Settings,
    where_clause: &str,
    bind: impl FnOnce(
        sqlx::query::Query<'_, sqlx::MySql, sqlx::mysql::MySqlArguments>,
    ) -> sqlx::query::Query<'_, sqlx::MySql, sqlx::mysql::MySqlArguments>,
) -> Result<usize> {
    let sql = format!(
        "SELECT id, slug, original_name FROM uploads WHERE {where_clause} AND deleted_timestamp IS NULL"
    );
    let rows = bind(sqlx::query(&sql))
        .try_map(|row: sqlx::mysql::MySqlRow| {
            Ok((
                row.try_get::<Uuid, _>("id")?,
                row.try_get::<String, _>("slug")?,
                row.try_get::<String, _>("original_name")?,
            ))
        })
        .fetch_all(db)
        .await?;
    let count = rows.len();
    for (id, slug, original_name) in rows {
        delete_one(db, settings, id, &slug, &original_name).await?;
    }
    Ok(count)
}

pub(crate) async fn delete_expired(db: &MySqlPool, settings: &Settings) -> Result<usize> {
    delete_matching(db, settings, "expiry_timestamp <= NOW()", |q| q).await
}

pub(crate) async fn delete_by_id(db: &MySqlPool, settings: &Settings, id: Uuid) -> Result<usize> {
    delete_matching(db, settings, "id = ?", |q| q.bind(id)).await
}

pub(crate) async fn delete_by_slug(
    db: &MySqlPool,
    settings: &Settings,
    slug: &str,
) -> Result<usize> {
    delete_matching(db, settings, "slug = ?", |q| q.bind(slug.to_owned())).await
}

pub(crate) async fn delete_by_ip(db: &MySqlPool, settings: &Settings, ip: u32) -> Result<usize> {
    delete_matching(db, settings, "uploader_ip = ?", |q| q.bind(ip)).await
}

pub(crate) async fn delete_by_ip_range(
    db: &MySqlPool,
    settings: &Settings,
    start: u32,
    end: u32,
) -> Result<usize> {
    delete_matching(db, settings, "uploader_ip BETWEEN ? AND ?", |q| {
        q.bind(start).bind(end)
    })
    .await
}

pub(crate) struct NewUpload<'a> {
    pub id: Uuid,
    pub slug: &'a str,
    pub original_name: &'a str,
    pub upload_timestamp: time::PrimitiveDateTime,
    pub expiry_timestamp: time::PrimitiveDateTime,
    pub file_size: i64,
    pub uploader_ip: Option<u32>,
    pub content_type: Option<&'a str>,
}

pub(crate) async fn insert_upload(db: &MySqlPool, upload: &NewUpload<'_>) -> anyhow::Result<bool> {
    let exists = sqlx::query(
        "SELECT 1 FROM uploads WHERE slug = ? AND deleted_timestamp IS NULL",
    )
    .bind(upload.slug)
    .fetch_optional(db)
    .await?
    .is_some();

    if exists {
        return Ok(false);
    }

    sqlx::query(
        "INSERT INTO uploads (id, slug, original_name, upload_timestamp, expiry_timestamp, file_size, uploader_ip, content_type) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(upload.id)
    .bind(upload.slug)
    .bind(upload.original_name)
    .bind(upload.upload_timestamp)
    .bind(upload.expiry_timestamp)
    .bind(upload.file_size)
    .bind(upload.uploader_ip)
    .bind(upload.content_type)
    .execute(db)
    .await?;

    Ok(true)
}

/// Like `insert_upload`, but for log entries whose file no longer exists on disk: the
/// row is inserted already soft-deleted so the app never tries to serve it. Unlike
/// `insert_upload`, existence is checked regardless of `deleted_timestamp` — these are
/// one-time archival records, not something a slug should be allowed to reclaim.
pub(crate) async fn insert_historical_upload(
    db: &MySqlPool,
    upload: &NewUpload<'_>,
    deleted_timestamp: time::PrimitiveDateTime,
) -> anyhow::Result<bool> {
    let exists = sqlx::query("SELECT 1 FROM uploads WHERE slug = ?")
        .bind(upload.slug)
        .fetch_optional(db)
        .await?
        .is_some();

    if exists {
        return Ok(false);
    }

    sqlx::query(
        "INSERT INTO uploads (id, slug, original_name, upload_timestamp, expiry_timestamp, deleted_timestamp, file_size, uploader_ip, content_type) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(upload.id)
    .bind(upload.slug)
    .bind(upload.original_name)
    .bind(upload.upload_timestamp)
    .bind(upload.expiry_timestamp)
    .bind(deleted_timestamp)
    .bind(upload.file_size)
    .bind(upload.uploader_ip)
    .bind(upload.content_type)
    .execute(db)
    .await?;

    Ok(true)
}

pub(crate) async fn uploads_count_last_day(db: &MySqlPool, ip: u32) -> Result<i64, sqlx::Error> {
    let row = sqlx::query(
        "SELECT COUNT(*) FROM uploads \
         WHERE uploader_ip = ? \
         AND upload_timestamp > NOW() - INTERVAL 1 DAY",
    )
    .bind(ip)
    .fetch_one(db)
    .await?;
    Ok(row.try_get::<i64, _>(0).unwrap_or(0))
}

pub(crate) async fn uploads_bytes_last_day(db: &MySqlPool, ip: u32) -> Result<i64, sqlx::Error> {
    let row = sqlx::query(
        "SELECT COALESCE(SUM(file_size), 0) FROM uploads \
         WHERE uploader_ip = ? \
         AND upload_timestamp > NOW() - INTERVAL 1 DAY",
    )
    .bind(ip)
    .fetch_one(db)
    .await?;
    Ok(row.try_get::<i64, _>(0).unwrap_or(0))
}

pub(crate) async fn log_access(
    db: &MySqlPool,
    upload_id: Uuid,
    ipv4: Option<u32>,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO accesses (upload_id, ipv4) VALUES (?, ?)")
        .bind(upload_id)
        .bind(ipv4)
        .execute(db)
        .await?;
    Ok(())
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct GlobalStats {
    pub active_uploads: i64,
    pub active_bytes: i64,
    pub deleted_uploads: i64,
    pub uploads_last_24h: i64,
    pub bytes_last_24h: i64,
}

pub(crate) async fn global_stats(db: &MySqlPool) -> Result<GlobalStats, sqlx::Error> {
    let row = sqlx::query(
        "SELECT \
           CAST(COALESCE(SUM(CASE WHEN deleted_timestamp IS NULL THEN 1 ELSE 0 END), 0) AS SIGNED) AS active_uploads, \
           CAST(COALESCE(SUM(CASE WHEN deleted_timestamp IS NULL THEN file_size ELSE 0 END), 0) AS SIGNED) AS active_bytes, \
           CAST(COALESCE(SUM(CASE WHEN deleted_timestamp IS NOT NULL THEN 1 ELSE 0 END), 0) AS SIGNED) AS deleted_uploads, \
           CAST(COALESCE(SUM(CASE WHEN upload_timestamp > NOW() - INTERVAL 1 DAY THEN 1 ELSE 0 END), 0) AS SIGNED) AS uploads_last_24h, \
           CAST(COALESCE(SUM(CASE WHEN upload_timestamp > NOW() - INTERVAL 1 DAY THEN file_size ELSE 0 END), 0) AS SIGNED) AS bytes_last_24h \
         FROM uploads",
    )
    .fetch_one(db)
    .await?;

    Ok(GlobalStats {
        active_uploads: row.try_get(0)?,
        active_bytes: row.try_get(1)?,
        deleted_uploads: row.try_get(2)?,
        uploads_last_24h: row.try_get(3)?,
        bytes_last_24h: row.try_get(4)?,
    })
}

pub(crate) async fn list_uploads(
    db: &MySqlPool,
    ip: Option<u32>,
    slug: Option<&str>,
    include_deleted: bool,
    limit: i64,
    offset: i64,
) -> Result<Vec<Upload>, sqlx::Error> {
    let mut sql = String::from(
        "SELECT id, upload_timestamp, expiry_timestamp, deleted_timestamp, original_name, \
         slug, file_size, hash, uploader_ip, content_type FROM uploads WHERE 1=1",
    );
    if !include_deleted {
        sql.push_str(" AND deleted_timestamp IS NULL");
    }
    if ip.is_some() {
        sql.push_str(" AND uploader_ip = ?");
    }
    if slug.is_some() {
        sql.push_str(" AND slug = ?");
    }
    sql.push_str(" ORDER BY upload_timestamp DESC LIMIT ? OFFSET ?");

    let mut q = sqlx::query_as::<_, Upload>(&sql);
    if let Some(ip) = ip {
        q = q.bind(ip);
    }
    if let Some(slug) = slug {
        q = q.bind(slug);
    }
    q.bind(limit).bind(offset).fetch_all(db).await
}

pub(crate) async fn list_banned_ips(db: &MySqlPool) -> Result<Vec<BannedIpv4Range>, sqlx::Error> {
    sqlx::query_as::<_, BannedIpv4Range>(
        "SELECT id, start_ip, end_ip, reason, banned_timestamp, expires_timestamp FROM banned_ipv4_ranges ORDER BY id DESC",
    )
    .fetch_all(db)
    .await
}

pub(crate) async fn insert_banned_ip(
    db: &MySqlPool,
    start_ip: u32,
    end_ip: u32,
    reason: Option<&str>,
    expires_timestamp: Option<PrimitiveDateTime>,
) -> Result<i64, sqlx::Error> {
    let result = sqlx::query(
        "INSERT INTO banned_ipv4_ranges (start_ip, end_ip, reason, expires_timestamp) VALUES (?, ?, ?, ?)",
    )
    .bind(start_ip)
    .bind(end_ip)
    .bind(reason)
    .bind(expires_timestamp)
    .execute(db)
    .await?;
    Ok(result.last_insert_id() as i64)
}

pub(crate) async fn delete_banned_ip(db: &MySqlPool, id: i64) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM banned_ipv4_ranges WHERE id = ?")
        .bind(id)
        .execute(db)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub(crate) async fn list_banned_extensions(
    db: &MySqlPool,
) -> Result<Vec<BannedFileExtension>, sqlx::Error> {
    sqlx::query_as::<_, BannedFileExtension>(
        "SELECT extension FROM banned_file_extensions ORDER BY extension",
    )
    .fetch_all(db)
    .await
}

pub(crate) async fn insert_banned_extension(db: &MySqlPool, ext: &str) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT IGNORE INTO banned_file_extensions (extension) VALUES (?)")
        .bind(ext)
        .execute(db)
        .await?;
    Ok(())
}

pub(crate) async fn delete_banned_extension(db: &MySqlPool, ext: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM banned_file_extensions WHERE extension = ?")
        .bind(ext)
        .execute(db)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub(crate) async fn list_banned_mimes(db: &MySqlPool) -> Result<Vec<BannedFileMime>, sqlx::Error> {
    sqlx::query_as::<_, BannedFileMime>("SELECT mime FROM banned_file_mimes ORDER BY mime")
        .fetch_all(db)
        .await
}

pub(crate) async fn insert_banned_mime(db: &MySqlPool, mime: &str) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT IGNORE INTO banned_file_mimes (mime) VALUES (?)")
        .bind(mime)
        .execute(db)
        .await?;
    Ok(())
}

pub(crate) async fn delete_banned_mime(db: &MySqlPool, mime: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM banned_file_mimes WHERE mime = ?")
        .bind(mime)
        .execute(db)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub(crate) async fn list_banned_hashes(db: &MySqlPool) -> Result<Vec<BannedFileHash>, sqlx::Error> {
    sqlx::query_as::<_, BannedFileHash>("SELECT hash, reason FROM banned_file_hashes ORDER BY hash")
        .fetch_all(db)
        .await
}

pub(crate) async fn insert_banned_hash(
    db: &MySqlPool,
    hash: &[u8],
    reason: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT IGNORE INTO banned_file_hashes (hash, reason) VALUES (?, ?)")
        .bind(hash)
        .bind(reason)
        .execute(db)
        .await?;
    Ok(())
}

pub(crate) async fn delete_banned_hash(db: &MySqlPool, hash: &[u8]) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM banned_file_hashes WHERE hash = ?")
        .bind(hash)
        .execute(db)
        .await?;
    Ok(result.rows_affected() > 0)
}

async fn delete_one(
    db: &MySqlPool,
    settings: &Settings,
    id: Uuid,
    slug: &str,
    original_name: &str,
) -> Result<()> {
    let path = uuid_to_path(Path::new(&settings.store_path), &id);
    if let Err(e) = std::fs::remove_file(&path) {
        log::warn!("Failed to delete file {}: {e}", path.display());
    }
    sqlx::query!(
        "UPDATE uploads SET deleted_timestamp = NOW() WHERE id = ?",
        id,
    )
    .execute(db)
    .await?;
    log::info!("Deleted file: {id} {slug} {original_name}");
    Ok(())
}
