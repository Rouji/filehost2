use std::path::Path;

use anyhow::Result;
use sqlx::Row;
use time::PrimitiveDateTime;
use uuid::Uuid;

use crate::db_pool::{self, DbPool};
use crate::model::{
    BanType, BannedFileExtension, BannedFileHash, BannedFileMime, BannedIpv4Range, BannedUserAgent,
    Blacklist, Upload,
};
use crate::settings::Settings;
use crate::upload::uuid_to_path;

pub(crate) async fn is_slug_taken(db: &DbPool, slug: &str) -> Result<bool, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    Ok(sqlx::query!(
        "SELECT 1 AS found FROM uploads WHERE slug = ? AND deleted_timestamp IS NULL",
        slug
    )
    .fetch_optional(&mut *conn)
    .await?
    .is_some())
}

pub(crate) async fn is_ip_banned(
    db: &DbPool,
    ip: u32,
    ban_type: BanType,
) -> Result<bool, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    Ok(sqlx::query!(
        "SELECT 1 AS found FROM banned_ipv4_ranges \
         WHERE ? BETWEEN start_ip AND end_ip \
         AND type >= ? \
         AND (expires_timestamp IS NULL OR expires_timestamp > NOW())",
        ip,
        ban_type as u32
    )
    .fetch_optional(&mut *conn)
    .await?
    .is_some())
}

pub(crate) async fn find_active_upload_by_hash(
    db: &DbPool,
    hash: &[u8],
) -> Result<Option<(uuid::Uuid, String)>, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    Ok(sqlx::query!(
        r#"SELECT id AS `id: Uuid`, slug FROM uploads WHERE hash = ? AND deleted_timestamp IS NULL ORDER BY upload_timestamp DESC LIMIT 1"#,
        hash
    )
    .fetch_optional(&mut *conn)
    .await?
    .map(|r| (r.id, r.slug)))
}

pub(crate) async fn uploads_missing_hash(db: &DbPool) -> Result<Vec<Uuid>, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    let rows = sqlx::query!(
        r#"SELECT id AS `id: Uuid` FROM uploads WHERE hash IS NULL AND deleted_timestamp IS NULL"#
    )
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows.into_iter().map(|r| r.id).collect())
}

pub(crate) async fn uploads_for_nsfw_scan(
    db: &DbPool,
    all: bool,
) -> Result<Vec<Uuid>, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    let mut sql = String::from(
        "SELECT id FROM uploads WHERE deleted_timestamp IS NULL AND content_type LIKE 'image/%'",
    );
    if !all {
        sql.push_str(" AND nsfw_score IS NULL");
    }
    let rows = sqlx::query_as::<_, (Uuid,)>(sqlx::AssertSqlSafe(sql))
        .fetch_all(&mut *conn)
        .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

pub(crate) async fn update_upload_hash(
    db: &DbPool,
    id: Uuid,
    hash: &[u8],
) -> Result<(), sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    sqlx::query!("UPDATE uploads SET hash = ? WHERE id = ?", hash, id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

pub(crate) async fn update_nsfw_score(
    db: &DbPool,
    id: Uuid,
    score: f32,
) -> Result<(), sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    sqlx::query!("UPDATE uploads SET nsfw_score = ? WHERE id = ?", score, id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

pub(crate) struct DedupPair {
    pub dup_id: Uuid,
    pub canonical_id: Uuid,
}

/// for every group of active uploads sharing a hash, pair each older
/// duplicate with the most recently uploaded member of that group (the
/// canonical copy)
pub(crate) async fn find_dedup_pairs(db: &DbPool) -> Result<Vec<DedupPair>, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    let rows = sqlx::query!(
        r#"SELECT u.id AS `dup_id: Uuid`, c.canonical_id AS `canonical_id!: Uuid`
           FROM uploads u
           JOIN (
               SELECT hash, id AS canonical_id,
                      ROW_NUMBER() OVER (PARTITION BY hash ORDER BY upload_timestamp DESC, id DESC) AS rn
               FROM uploads
               WHERE deleted_timestamp IS NULL AND hash IS NOT NULL
           ) c ON c.hash = u.hash AND c.rn = 1
           WHERE u.deleted_timestamp IS NULL AND u.hash IS NOT NULL AND u.id <> c.canonical_id"#
    )
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| DedupPair {
            dup_id: r.dup_id,
            canonical_id: r.canonical_id,
        })
        .collect())
}

/// Soft-deletes every upload matching a `WHERE` clause appended to the base
/// select below, via `bind`. Shared by all the `delete_by_*`/`delete_expired`
/// variants, which differ only in which rows they select. The clause is built
/// at runtime, so this can't use the compile-time-checked query macros.
async fn delete_matching(
    db: &DbPool,
    settings: &Settings,
    where_clause: &'static str,
    bind: impl FnOnce(
        sqlx::query::Query<'_, sqlx::MySql, sqlx::mysql::MySqlArguments>,
    ) -> sqlx::query::Query<'_, sqlx::MySql, sqlx::mysql::MySqlArguments>,
) -> Result<usize> {
    let sql = format!(
        "SELECT id, slug, original_name FROM uploads WHERE {where_clause} AND deleted_timestamp IS NULL"
    );
    let rows = {
        let mut conn = db_pool::conn(db).await?;
        bind(sqlx::query(sqlx::AssertSqlSafe(sql)))
            .try_map(|row: sqlx::mysql::MySqlRow| {
                Ok((
                    row.try_get::<Uuid, _>("id")?,
                    row.try_get::<String, _>("slug")?,
                    row.try_get::<String, _>("original_name")?,
                ))
            })
            .fetch_all(&mut *conn)
            .await?
    };
    let count = rows.len();
    for (id, slug, original_name) in rows {
        delete_one(db, settings, id, &slug, &original_name).await?;
    }
    Ok(count)
}

pub(crate) async fn delete_expired(db: &DbPool, settings: &Settings) -> Result<usize> {
    delete_matching(db, settings, "expiry_timestamp <= NOW()", |q| q).await
}

pub(crate) async fn delete_by_id(db: &DbPool, settings: &Settings, id: Uuid) -> Result<usize> {
    delete_matching(db, settings, "id = ?", |q| q.bind(id)).await
}

pub(crate) async fn delete_by_slug(db: &DbPool, settings: &Settings, slug: &str) -> Result<usize> {
    delete_matching(db, settings, "slug = ?", |q| q.bind(slug.to_owned())).await
}

pub(crate) async fn delete_by_ip(db: &DbPool, settings: &Settings, ip: u32) -> Result<usize> {
    delete_matching(db, settings, "uploader_ip = ?", |q| q.bind(ip)).await
}

pub(crate) async fn delete_by_ip_range(
    db: &DbPool,
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
    pub user_agent: Option<&'a str>,
}

/// A live upload shouldn't reclaim a slug still held by a not-yet-expired historical
/// record, so the existence check only ignores `deleted_timestamp` for historical rows.
async fn insert_upload_checked(
    db: &DbPool,
    upload: &NewUpload<'_>,
    deleted_timestamp: Option<time::PrimitiveDateTime>,
) -> anyhow::Result<bool> {
    let mut conn = db_pool::conn(db).await?;

    let exists = if deleted_timestamp.is_some() {
        sqlx::query!("SELECT 1 AS found FROM uploads WHERE slug = ?", upload.slug)
            .fetch_optional(&mut *conn)
            .await?
            .is_some()
    } else {
        sqlx::query!(
            "SELECT 1 AS found FROM uploads WHERE slug = ? AND deleted_timestamp IS NULL",
            upload.slug
        )
        .fetch_optional(&mut *conn)
        .await?
        .is_some()
    };

    if exists {
        return Ok(false);
    }

    sqlx::query!(
        "INSERT INTO uploads (id, slug, original_name, upload_timestamp, expiry_timestamp, deleted_timestamp, file_size, uploader_ip, content_type, user_agent) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        upload.id,
        upload.slug,
        upload.original_name,
        upload.upload_timestamp,
        upload.expiry_timestamp,
        deleted_timestamp,
        upload.file_size,
        upload.uploader_ip,
        upload.content_type,
        upload.user_agent,
    )
    .execute(&mut *conn)
    .await?;

    Ok(true)
}

pub(crate) async fn insert_upload(db: &DbPool, upload: &NewUpload<'_>) -> anyhow::Result<bool> {
    insert_upload_checked(db, upload, None).await
}

/// Like `insert_upload`, but for log entries whose file no longer exists on disk: the
/// row is inserted already soft-deleted so the app never tries to serve it. Unlike
/// `insert_upload`, existence is checked regardless of `deleted_timestamp` — these are
/// one-time archival records, not something a slug should be allowed to reclaim.
pub(crate) async fn insert_historical_upload(
    db: &DbPool,
    upload: &NewUpload<'_>,
    deleted_timestamp: time::PrimitiveDateTime,
) -> anyhow::Result<bool> {
    insert_upload_checked(db, upload, Some(deleted_timestamp)).await
}

pub(crate) async fn historical_upload_slugs(
    db: &DbPool,
) -> Result<Vec<(Uuid, String)>, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    let rows = sqlx::query!(
        r#"SELECT id AS `id: Uuid`, slug FROM uploads WHERE deleted_timestamp IS NOT NULL"#
    )
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows.into_iter().map(|r| (r.id, r.slug)).collect())
}

/// Inserts a freshly-uploaded file's row. Distinct from `insert_upload`: this one
/// carries the content hash and lets the DB default `upload_timestamp`, matching
/// what `handlers::process_file` needs right after saving the file to disk.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn insert_upload_row(
    db: &DbPool,
    id: Uuid,
    original_name: &str,
    expiry_timestamp: PrimitiveDateTime,
    slug: &str,
    file_size: i64,
    hash: &[u8],
    uploader_ip: Option<u32>,
    content_type: &str,
    user_agent: Option<&str>,
) -> Result<(), sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    sqlx::query!(
        "INSERT INTO uploads (id, original_name, expiry_timestamp, slug, file_size, hash, uploader_ip, content_type, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        id, original_name, expiry_timestamp, slug, file_size, hash, uploader_ip, content_type, user_agent,
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Hard-deletes a row outright, rather than soft-deleting it like `delete_by_id` does.
pub(crate) async fn hard_delete_upload(db: &DbPool, id: Uuid) -> Result<(), sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    sqlx::query!("DELETE FROM uploads WHERE id = ?", id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

pub(crate) async fn uploads_count_last_day(db: &DbPool, ip: u32) -> Result<i64, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    let count = sqlx::query_scalar!(
        "SELECT COUNT(*) FROM uploads \
         WHERE uploader_ip = ? \
         AND upload_timestamp > NOW() - INTERVAL 1 DAY",
        ip
    )
    .fetch_one(&mut *conn)
    .await?;
    Ok(count)
}

pub(crate) async fn uploads_bytes_last_day(db: &DbPool, ip: u32) -> Result<i64, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    let bytes = sqlx::query_scalar!(
        r#"SELECT CAST(COALESCE(SUM(file_size), 0) AS SIGNED) AS `bytes: i64` FROM uploads
         WHERE uploader_ip = ?
         AND upload_timestamp > NOW() - INTERVAL 1 DAY"#,
        ip
    )
    .fetch_one(&mut *conn)
    .await?;
    Ok(bytes)
}

pub(crate) async fn log_access(
    db: &DbPool,
    upload_id: Uuid,
    ipv4: Option<u32>,
    user_agent: Option<&str>,
) -> Result<(), sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    sqlx::query!(
        "INSERT INTO accesses (upload_id, ipv4, user_agent) VALUES (?, ?, ?)",
        upload_id,
        ipv4,
        user_agent
    )
    .execute(&mut *conn)
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

pub(crate) async fn global_stats(db: &DbPool) -> Result<GlobalStats, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    sqlx::query_as!(
        GlobalStats,
        "SELECT \
           CAST(COALESCE(SUM(CASE WHEN deleted_timestamp IS NULL THEN 1 ELSE 0 END), 0) AS SIGNED) AS active_uploads, \
           CAST(COALESCE(SUM(CASE WHEN deleted_timestamp IS NULL THEN file_size ELSE 0 END), 0) AS SIGNED) AS active_bytes, \
           CAST(COALESCE(SUM(CASE WHEN deleted_timestamp IS NOT NULL THEN 1 ELSE 0 END), 0) AS SIGNED) AS deleted_uploads, \
           CAST(COALESCE(SUM(CASE WHEN upload_timestamp > NOW() - INTERVAL 1 DAY THEN 1 ELSE 0 END), 0) AS SIGNED) AS uploads_last_24h, \
           CAST(COALESCE(SUM(CASE WHEN upload_timestamp > NOW() - INTERVAL 1 DAY THEN file_size ELSE 0 END), 0) AS SIGNED) AS bytes_last_24h \
         FROM uploads"
    )
    .fetch_one(&mut *conn)
    .await
}

pub(crate) struct TopUploader {
    pub ip: u32,
    pub count: i64,
    pub bytes: i64,
}

pub(crate) async fn top_uploader_ips(
    db: &DbPool,
    limit: i64,
) -> Result<Vec<TopUploader>, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    sqlx::query_as!(
        TopUploader,
        r#"SELECT uploader_ip AS "ip!: u32", CAST(COUNT(*) AS SIGNED) AS "count!: i64", CAST(COALESCE(SUM(file_size), 0) AS SIGNED) AS "bytes!: i64"
           FROM uploads
           WHERE deleted_timestamp IS NULL AND uploader_ip IS NOT NULL
           GROUP BY uploader_ip
           ORDER BY 2 DESC
           LIMIT ?"#,
        limit
    )
    .fetch_all(&mut *conn)
    .await
}

pub(crate) struct HourlyUploadCount {
    pub hour: String,
    pub count: i64,
}

pub(crate) async fn uploads_hourly_counts(
    db: &DbPool,
    ip: u32,
    hours: i64,
) -> Result<Vec<HourlyUploadCount>, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    let rows = sqlx::query!(
        r#"SELECT DATE_FORMAT(upload_timestamp, '%Y-%m-%dT%H:00:00') AS "bucket!: String", CAST(COUNT(*) AS SIGNED) AS "count!: i64"
           FROM uploads
           WHERE uploader_ip = ? AND deleted_timestamp IS NULL AND upload_timestamp > NOW() - INTERVAL ? HOUR
           GROUP BY 1"#,
        ip,
        hours
    )
    .fetch_all(&mut *conn)
    .await?;

    let counts: std::collections::HashMap<String, i64> =
        rows.into_iter().map(|r| (r.bucket, r.count)).collect();

    let now = time::OffsetDateTime::now_utc();
    let now_hour =
        PrimitiveDateTime::new(now.date(), time::Time::from_hms(now.hour(), 0, 0).unwrap());
    let key_format = time::macros::format_description!("[year]-[month]-[day]T[hour]:00:00");

    Ok((0..hours)
        .map(|i| {
            let slot = now_hour - time::Duration::hours(hours - 1 - i);
            let key = slot.format(&key_format).unwrap_or_default();
            HourlyUploadCount {
                hour: crate::util::format_ts(slot),
                count: counts.get(&key).copied().unwrap_or(0),
            }
        })
        .collect())
}

pub(crate) struct MimeUploadCount {
    pub mime: String,
    pub count: i64,
}

pub(crate) async fn uploads_top_mimes(
    db: &DbPool,
    ip: u32,
    limit: i64,
) -> Result<Vec<MimeUploadCount>, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    sqlx::query_as!(
        MimeUploadCount,
        r#"SELECT content_type AS "mime!: String", CAST(COUNT(*) AS SIGNED) AS "count!: i64"
           FROM uploads
           WHERE uploader_ip = ? AND deleted_timestamp IS NULL AND content_type IS NOT NULL
           GROUP BY content_type
           ORDER BY 2 DESC
           LIMIT ?"#,
        ip,
        limit
    )
    .fetch_all(&mut *conn)
    .await
}

enum ListUploadsParam<'a> {
    U32(u32),
    Str(&'a str),
    I64(i64),
    F32(f32),
}

pub(crate) async fn list_uploads(
    db: &DbPool,
    ip: Option<u32>,
    slug: Option<&str>,
    include_deleted: bool,
    min_nsfw_score: Option<f32>,
    limit: i64,
    offset: i64,
) -> Result<Vec<Upload>, sqlx::Error> {
    let mut sql = String::from(
        "SELECT id, upload_timestamp, expiry_timestamp, deleted_timestamp, original_name, \
         slug, file_size, hash, uploader_ip, content_type, user_agent, nsfw_score \
         FROM uploads WHERE 1=1",
    );
    let mut params = Vec::new();

    if !include_deleted {
        sql.push_str(" AND deleted_timestamp IS NULL");
    }
    if let Some(min_score) = min_nsfw_score {
        sql.push_str(" AND nsfw_score >= ?");
        params.push(ListUploadsParam::F32(min_score));
    }
    if let Some(ip) = ip {
        sql.push_str(" AND uploader_ip = ?");
        params.push(ListUploadsParam::U32(ip));
    }
    if let Some(slug) = slug {
        sql.push_str(" AND slug = ?");
        params.push(ListUploadsParam::Str(slug));
    }
    sql.push_str(" ORDER BY upload_timestamp DESC LIMIT ? OFFSET ?");
    params.push(ListUploadsParam::I64(limit));
    params.push(ListUploadsParam::I64(offset));

    let mut q = sqlx::query_as::<_, Upload>(sqlx::AssertSqlSafe(sql));
    for param in params {
        q = match param {
            ListUploadsParam::U32(v) => q.bind(v),
            ListUploadsParam::Str(v) => q.bind(v),
            ListUploadsParam::I64(v) => q.bind(v),
            ListUploadsParam::F32(v) => q.bind(v),
        };
    }

    let mut conn = db_pool::conn(db).await?;
    q.fetch_all(&mut *conn).await
}

pub(crate) async fn get_upload_by_slug(
    db: &DbPool,
    slug: &str,
) -> Result<Option<Upload>, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    sqlx::query_as!(
        Upload,
        "SELECT id AS `id: Uuid`, upload_timestamp, expiry_timestamp, deleted_timestamp, original_name, \
         slug, file_size, hash AS `hash: Vec<u8>`, uploader_ip, content_type, user_agent, nsfw_score \
         FROM uploads WHERE slug = ? AND deleted_timestamp IS NULL",
        slug
    )
    .fetch_optional(&mut *conn)
    .await
}

pub(crate) async fn list_banned_ips(
    db: &DbPool,
    limit: i64,
    offset: i64,
) -> Result<Vec<BannedIpv4Range>, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    sqlx::query_as!(
        BannedIpv4Range,
        "SELECT id, start_ip, end_ip, reason, banned_timestamp, expires_timestamp, type as \"type_: BanType\", blacklist_id FROM banned_ipv4_ranges ORDER BY id DESC LIMIT ? OFFSET ?",
        limit,
        offset
    )
    .fetch_all(&mut *conn)
    .await
}

pub(crate) async fn insert_banned_ip(
    db: &DbPool,
    start_ip: u32,
    end_ip: u32,
    reason: Option<&str>,
    expires_timestamp: Option<PrimitiveDateTime>,
    blacklist_id: Option<i32>,
    ban_type: BanType,
) -> Result<i64, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    let result = sqlx::query!(
        "INSERT INTO banned_ipv4_ranges (start_ip, end_ip, reason, expires_timestamp, blacklist_id, type) VALUES (?, ?, ?, ?, ?, ?)",
        start_ip,
        end_ip,
        reason,
        expires_timestamp,
        blacklist_id,
        ban_type as u32
    )
    .execute(&mut *conn)
    .await?;
    Ok(result.last_insert_id() as i64)
}

pub(crate) async fn delete_banned_ips_by_blacklist(
    db: &DbPool,
    blacklist_id: i32,
) -> Result<usize, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    let result = sqlx::query!(
        "DELETE FROM banned_ipv4_ranges WHERE blacklist_id = ?",
        blacklist_id
    )
    .execute(&mut *conn)
    .await?;
    Ok(result.rows_affected() as usize)
}

/// The `sqlx` query macros need string literals, so each query is passed in whole
/// rather than assembled from the table/column names.
macro_rules! ban_set_crud {
    (
        $list_fn:ident, $insert_fn:ident, $delete_fn:ident, $struct:ty, $key_ty:ty,
        list = $list_sql:literal, insert = $insert_sql:literal, delete = $delete_sql:literal $(,)?
    ) => {
        pub(crate) async fn $list_fn(db: &DbPool) -> Result<Vec<$struct>, sqlx::Error> {
            let mut conn = db_pool::conn(db).await?;
            sqlx::query_as!($struct, $list_sql)
                .fetch_all(&mut *conn)
                .await
        }

        pub(crate) async fn $insert_fn(db: &DbPool, key: $key_ty) -> Result<(), sqlx::Error> {
            let mut conn = db_pool::conn(db).await?;
            sqlx::query!($insert_sql, key).execute(&mut *conn).await?;
            Ok(())
        }

        pub(crate) async fn $delete_fn(db: &DbPool, key: $key_ty) -> Result<bool, sqlx::Error> {
            let mut conn = db_pool::conn(db).await?;
            let result = sqlx::query!($delete_sql, key).execute(&mut *conn).await?;
            Ok(result.rows_affected() > 0)
        }
    };
}

/// Same as `ban_set_crud`, plus an `Option<&str> reason` column.
macro_rules! ban_set_crud_with_reason {
    (
        $list_fn:ident, $insert_fn:ident, $delete_fn:ident, $struct:ty, $key_ty:ty,
        list = $list_sql:literal, insert = $insert_sql:literal, delete = $delete_sql:literal $(,)?
    ) => {
        pub(crate) async fn $list_fn(db: &DbPool) -> Result<Vec<$struct>, sqlx::Error> {
            let mut conn = db_pool::conn(db).await?;
            sqlx::query_as!($struct, $list_sql)
                .fetch_all(&mut *conn)
                .await
        }

        pub(crate) async fn $insert_fn(
            db: &DbPool,
            key: $key_ty,
            reason: Option<&str>,
        ) -> Result<(), sqlx::Error> {
            let mut conn = db_pool::conn(db).await?;
            sqlx::query!($insert_sql, key, reason)
                .execute(&mut *conn)
                .await?;
            Ok(())
        }

        pub(crate) async fn $delete_fn(db: &DbPool, key: $key_ty) -> Result<bool, sqlx::Error> {
            let mut conn = db_pool::conn(db).await?;
            let result = sqlx::query!($delete_sql, key).execute(&mut *conn).await?;
            Ok(result.rows_affected() > 0)
        }
    };
}

macro_rules! delete_by_id_bool {
    ($fn_name:ident, $id_ty:ty, $sql:literal) => {
        pub(crate) async fn $fn_name(db: &DbPool, id: $id_ty) -> Result<bool, sqlx::Error> {
            let mut conn = db_pool::conn(db).await?;
            let result = sqlx::query!($sql, id).execute(&mut *conn).await?;
            Ok(result.rows_affected() > 0)
        }
    };
}

delete_by_id_bool!(
    delete_banned_ip,
    i64,
    "DELETE FROM banned_ipv4_ranges WHERE id = ?"
);

ban_set_crud!(
    list_banned_extensions,
    insert_banned_extension,
    delete_banned_extension,
    BannedFileExtension,
    &str,
    list = "SELECT extension FROM banned_file_extensions ORDER BY extension",
    insert = "INSERT IGNORE INTO banned_file_extensions (extension) VALUES (LOWER(?))",
    delete = "DELETE FROM banned_file_extensions WHERE extension = LOWER(?)",
);

ban_set_crud!(
    list_banned_mimes,
    insert_banned_mime,
    delete_banned_mime,
    BannedFileMime,
    &str,
    list = "SELECT mime FROM banned_file_mimes ORDER BY mime",
    insert = "INSERT IGNORE INTO banned_file_mimes (mime) VALUES (LOWER(?))",
    delete = "DELETE FROM banned_file_mimes WHERE mime = LOWER(?)",
);

ban_set_crud_with_reason!(
    list_banned_hashes,
    insert_banned_hash,
    delete_banned_hash,
    BannedFileHash,
    &[u8],
    list = "SELECT hash, reason FROM banned_file_hashes ORDER BY hash",
    insert = "INSERT IGNORE INTO banned_file_hashes (hash, reason) VALUES (?, ?)",
    delete = "DELETE FROM banned_file_hashes WHERE hash = ?",
);

ban_set_crud_with_reason!(
    list_banned_user_agents,
    insert_banned_user_agent,
    delete_banned_user_agent,
    BannedUserAgent,
    &str,
    list = "SELECT pattern, reason FROM banned_user_agents ORDER BY pattern",
    insert = "INSERT IGNORE INTO banned_user_agents (pattern, reason) VALUES (?, ?)",
    delete = "DELETE FROM banned_user_agents WHERE pattern = ?",
);

pub(crate) async fn list_blacklist(db: &DbPool) -> Result<Vec<Blacklist>, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    sqlx::query_as!(
        Blacklist,
        "SELECT id, url, type AS `type_: BanType`, last_update, update_interval_seconds FROM blacklist ORDER BY id"
    )
    .fetch_all(&mut *conn)
    .await
}

pub(crate) async fn get_blacklist_by_id(
    db: &DbPool,
    id: i32,
) -> Result<Option<Blacklist>, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    sqlx::query_as!(
        Blacklist,
        "SELECT id, url, type AS `type_: BanType`, last_update, update_interval_seconds FROM blacklist WHERE id = ?",
        id
    )
    .fetch_optional(&mut *conn)
    .await
}

pub(crate) async fn insert_blacklist(
    db: &DbPool,
    url: &str,
    type_: BanType,
    update_interval_seconds: u64,
) -> Result<i32, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    let result = sqlx::query!(
        "INSERT INTO blacklist (url, type, update_interval_seconds) VALUES (?, ?, ?)",
        url,
        type_ as u32,
        update_interval_seconds
    )
    .execute(&mut *conn)
    .await?;
    Ok(result.last_insert_id() as i32)
}

delete_by_id_bool!(delete_blacklist, i32, "DELETE FROM blacklist WHERE id = ?");

async fn delete_one(
    db: &DbPool,
    settings: &Settings,
    id: Uuid,
    slug: &str,
    original_name: &str,
) -> Result<()> {
    let path = uuid_to_path(Path::new(&settings.store_path), &id);
    if let Err(e) = std::fs::remove_file(&path) {
        log::warn!("Failed to delete file {}: {e}", path.display());
    }
    let mut conn = db_pool::conn(db).await?;
    sqlx::query!(
        "UPDATE uploads SET deleted_timestamp = NOW() WHERE id = ?",
        id,
    )
    .execute(&mut *conn)
    .await?;
    log::info!("Deleted file: {id} {slug} {original_name}");
    Ok(())
}
