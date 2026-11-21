use std::net::IpAddr;
use std::path::Path;

use anyhow::Result;
use futures_util::StreamExt;
use sqlx::{Acquire, Row};
use time::PrimitiveDateTime;
use uuid::Uuid;

use crate::db_pool::{self, DbPool};
use crate::ip;
use crate::model::{
    BanType, BannedFileHash, BannedFileMime, BannedFilename, BannedIpRange, BannedUserAgent,
    Blacklist, Upload,
};
use crate::settings::Settings;
use crate::upload::uuid_to_path;

/// how many physical-file unlinks to keep in flight during batch deletion
const UNLINK_CONCURRENCY: usize = 32;

/// True when `e` is a UNIQUE constraint violation (MySQL/MariaDB errcode 1062).
pub(crate) fn is_unique_violation(e: &sqlx::Error) -> bool {
    matches!(
        e,
        sqlx::Error::Database(db) if db.kind() == sqlx::error::ErrorKind::UniqueViolation
    )
}

/// Applies pending migrations. Used by server startup and the `migrate` subcommand.
pub(crate) async fn run_migrations(db: &DbPool) -> Result<(), sqlx::migrate::MigrateError> {
    let mut conn = db_pool::conn(db).await?;
    sqlx::migrate!().run(&mut *conn).await
}

pub(crate) async fn is_slug_taken(db: &DbPool, slug: &str) -> Result<bool, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    Ok(
        sqlx::query!("SELECT 1 AS found FROM uploads WHERE slug = ?", slug)
            .fetch_optional(&mut *conn)
            .await?
            .is_some(),
    )
}

pub(crate) async fn is_ip_banned(
    db: &DbPool,
    ip: IpAddr,
    ban_type: BanType,
) -> Result<bool, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    let ip = ip::to_db_vec(ip);
    Ok(sqlx::query!(
        "SELECT 1 AS found FROM banned_ip_ranges \
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

pub(crate) async fn is_ip_challenge_verified(db: &DbPool, ip: IpAddr) -> Result<bool, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    let ip = ip::to_db_vec(ip);
    Ok(sqlx::query!(
        "SELECT 1 AS found FROM challenge_verified_ips WHERE ip = ? AND expires_timestamp > NOW()",
        ip
    )
    .fetch_optional(&mut *conn)
    .await?
    .is_some())
}

pub(crate) async fn upsert_challenge_verified_ip(
    db: &DbPool,
    ip: IpAddr,
    ttl_seconds: u64,
) -> Result<(), sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    let ip = ip::to_db_vec(ip);
    sqlx::query!(
        "INSERT INTO challenge_verified_ips (ip, verified_timestamp, expires_timestamp) \
         VALUES (?, NOW(), NOW() + INTERVAL ? SECOND) \
         ON DUPLICATE KEY UPDATE verified_timestamp = NOW(), expires_timestamp = NOW() + INTERVAL ? SECOND",
        ip,
        ttl_seconds,
        ttl_seconds
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub(crate) async fn find_active_upload_by_hash(
    db: &DbPool,
    hash: &[u8],
) -> Result<Option<(uuid::Uuid, String)>, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    Ok(sqlx::query!(
        r#"SELECT id AS `id: Uuid`, slug FROM uploads WHERE hash = ? ORDER BY upload_timestamp DESC LIMIT 1"#,
        hash
    )
    .fetch_optional(&mut *conn)
    .await?
    .map(|r| (r.id, r.slug)))
}

pub(crate) async fn uploads_missing_hash(db: &DbPool) -> Result<Vec<Uuid>, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    let rows = sqlx::query!(r#"SELECT id AS `id: Uuid` FROM uploads WHERE hash IS NULL"#)
        .fetch_all(&mut *conn)
        .await?;
    Ok(rows.into_iter().map(|r| r.id).collect())
}

pub(crate) async fn uploads_for_nsfw_scan(
    db: &DbPool,
    all: bool,
) -> Result<Vec<Uuid>, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    let mut sql = String::from("SELECT id FROM uploads WHERE content_type LIKE 'image/%'");
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
               WHERE hash IS NOT NULL
           ) c ON c.hash = u.hash AND c.rn = 1
           WHERE u.hash IS NOT NULL AND u.id <> c.canonical_id"#
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

/// Which uploads a batch delete should match.
pub(crate) enum DeleteTarget {
    Expired,
    Id(Uuid),
    Slug(String),
    Ip(IpAddr),
    IpRange(IpAddr, IpAddr),
}

impl DeleteTarget {
    fn clause(&self) -> &'static str {
        match self {
            Self::Expired => "expiry_timestamp <= ?",
            Self::Id(_) => "id = ?",
            Self::Slug(_) => "slug = ?",
            Self::Ip(_) => "uploader_ip = ?",
            Self::IpRange(..) => "uploader_ip BETWEEN ? AND ?",
        }
    }

    /// `now` is the frozen expiry cutoff, used only by `Expired`.
    fn bind<'q>(
        &self,
        q: sqlx::query::Query<'q, sqlx::MySql, sqlx::mysql::MySqlArguments>,
        now: PrimitiveDateTime,
    ) -> sqlx::query::Query<'q, sqlx::MySql, sqlx::mysql::MySqlArguments> {
        match self {
            Self::Expired => q.bind(now),
            Self::Id(id) => q.bind(*id),
            Self::Slug(slug) => q.bind(slug.clone()),
            Self::Ip(ip) => q.bind(ip::to_db_vec(*ip)),
            Self::IpRange(start, end) => q.bind(ip::to_db_vec(*start)).bind(ip::to_db_vec(*end)),
        }
    }
}

async fn delete_matching(db: &DbPool, settings: &Settings, target: DeleteTarget) -> Result<usize> {
    let where_clause = target.clause();
    let mut conn = db_pool::conn(db).await?;
    let mut tx = conn.begin().await?;

    // Freeze the expiry cutoff so the select, archive and delete below all
    // match the same rows even though NOW() advances between statements.
    let now = sqlx::query_scalar!("SELECT CAST(NOW() AS DATETIME) AS `now!: PrimitiveDateTime`")
        .fetch_one(&mut *tx)
        .await?;

    // Lock the matching rows, then archive and drop them in one transaction
    // before touching the filesystem: an upload arriving mid-delete can't be
    // dropped without its file being unlinked, and a failed archive/delete
    // can't leave live rows pointing at unlinked files. The accesses FK
    // (ON DELETE CASCADE) purges the download logs with the rows.
    let rows = target
        .bind(
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "SELECT id, slug, original_name FROM uploads WHERE {where_clause} FOR UPDATE"
            ))),
            now,
        )
        .try_map(|row: sqlx::mysql::MySqlRow| {
            Ok((
                row.try_get::<Uuid, _>("id")?,
                row.try_get::<String, _>("slug")?,
                row.try_get::<String, _>("original_name")?,
            ))
        })
        .fetch_all(&mut *tx)
        .await?;
    let count = rows.len();
    if count == 0 {
        return Ok(0);
    }

    target
        .bind(
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "INSERT INTO deleted_uploads (id, upload_timestamp, expiry_timestamp, deleted_timestamp, original_name, slug, file_size, hash, uploader_ip, content_type, user_agent, nsfw_score) \
                 SELECT id, upload_timestamp, expiry_timestamp, NOW(), original_name, slug, file_size, hash, uploader_ip, content_type, user_agent, nsfw_score \
                 FROM uploads WHERE {where_clause}"
            ))),
            now,
        )
        .execute(&mut *tx)
        .await?;
    let deleted = target
        .bind(
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "DELETE FROM uploads WHERE {where_clause}"
            ))),
            now,
        )
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    debug_assert_eq!(deleted as usize, count);

    // unlink the physical files concurrently; a failure only leaves an
    // orphaned file (logged), the rows are already archived and gone
    let unlinks: Vec<_> = rows
        .iter()
        .map(|(id, slug, original_name)| {
            let path = uuid_to_path(Path::new(&settings.store_path), id);
            async move {
                if let Err(e) = tokio::fs::remove_file(&path).await {
                    log::warn!("Failed to delete file {}: {e}", path.display());
                }
                log::info!("Deleted file: {id} {slug} {original_name}");
            }
        })
        .collect();
    let mut unlinks = futures_util::stream::iter(unlinks).buffer_unordered(UNLINK_CONCURRENCY);
    while unlinks.next().await.is_some() {}

    Ok(count)
}

pub(crate) async fn delete_expired(db: &DbPool, settings: &Settings) -> Result<usize> {
    delete_matching(db, settings, DeleteTarget::Expired).await
}

pub(crate) async fn delete_by_id(db: &DbPool, settings: &Settings, id: Uuid) -> Result<usize> {
    delete_matching(db, settings, DeleteTarget::Id(id)).await
}

pub(crate) async fn delete_by_slug(db: &DbPool, settings: &Settings, slug: &str) -> Result<usize> {
    delete_matching(db, settings, DeleteTarget::Slug(slug.to_owned())).await
}

pub(crate) async fn delete_by_ip(db: &DbPool, settings: &Settings, ip: IpAddr) -> Result<usize> {
    delete_matching(db, settings, DeleteTarget::Ip(ip)).await
}

pub(crate) async fn delete_by_ip_range(
    db: &DbPool,
    settings: &Settings,
    start: IpAddr,
    end: IpAddr,
) -> Result<usize> {
    anyhow::ensure!(
        ip::same_family(start, end),
        "start and end must be the same IP version"
    );
    delete_matching(db, settings, DeleteTarget::IpRange(start, end)).await
}

/// Inserts a freshly-uploaded file's row. Distinct from the old `insert_upload` (removed with
/// the import feature): this one carries the content hash and lets the DB default
/// `upload_timestamp`, matching what `handlers::process_file` needs right after saving
/// the file to disk.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn insert_upload_row(
    db: &DbPool,
    id: Uuid,
    original_name: &str,
    expiry_timestamp: PrimitiveDateTime,
    slug: &str,
    file_size: i64,
    hash: &[u8],
    uploader_ip: IpAddr,
    content_type: &str,
    user_agent: Option<&str>,
) -> Result<(), sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    let uploader_ip = ip::to_db_vec(uploader_ip);
    sqlx::query!(
        "INSERT INTO uploads (id, original_name, expiry_timestamp, slug, file_size, hash, uploader_ip, content_type, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        id, original_name, expiry_timestamp, slug, file_size, hash, uploader_ip, content_type, user_agent,
    )
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub(crate) async fn has_nsfw_upload_last_week(
    db: &DbPool,
    ip: IpAddr,
    min_score: f32,
) -> Result<bool, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    let (start, end) = ip::quota_range(ip);
    let start = ip::to_db_vec(start);
    let end = ip::to_db_vec(end);
    let found = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM uploads \
         WHERE uploader_ip BETWEEN ? AND ? \
         AND upload_timestamp > NOW() - INTERVAL 7 DAY \
         AND nsfw_score >= ?)",
        start,
        end,
        min_score
    )
    .fetch_one(&mut *conn)
    .await?;
    Ok(found != 0)
}

/// Count and total bytes of the uploader's uploads in the last day, for the
/// per-day rate limits. One query covers both limits.
pub(crate) async fn upload_stats_last_day(
    db: &DbPool,
    ip: IpAddr,
) -> Result<(i64, i64), sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    let (start, end) = ip::quota_range(ip);
    let start = ip::to_db_vec(start);
    let end = ip::to_db_vec(end);
    let row = sqlx::query!(
        r#"SELECT CAST(COUNT(*) AS SIGNED) AS `count!: i64`,
                  CAST(COALESCE(SUM(file_size), 0) AS SIGNED) AS `bytes!: i64`
           FROM uploads
           WHERE uploader_ip BETWEEN ? AND ?
           AND upload_timestamp > NOW() - INTERVAL 1 DAY"#,
        start,
        end
    )
    .fetch_one(&mut *conn)
    .await?;
    Ok((row.count, row.bytes))
}

pub(crate) async fn log_access(
    db: &DbPool,
    upload_id: Uuid,
    ip: Option<IpAddr>,
    user_agent: Option<&str>,
    bytes: Option<i64>,
    status: u16,
) -> Result<(), sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    let ip = ip.map(ip::to_db_vec);
    sqlx::query!(
        "INSERT INTO accesses (upload_id, ip, user_agent, bytes, status) VALUES (?, ?, ?, ?, ?)",
        upload_id,
        ip,
        user_agent,
        bytes,
        status
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
    // `uploads` only holds active rows now; the deleted count lives in the
    // archive table.
    sqlx::query_as!(
        GlobalStats,
        "SELECT \
           CAST(COUNT(*) AS SIGNED) AS `active_uploads!`, \
           CAST(COALESCE(SUM(file_size), 0) AS SIGNED) AS active_bytes, \
           CAST((SELECT COUNT(*) FROM deleted_uploads) AS SIGNED) AS `deleted_uploads!`, \
           CAST(COALESCE(SUM(CASE WHEN upload_timestamp > NOW() - INTERVAL 1 DAY THEN 1 ELSE 0 END), 0) AS SIGNED) AS uploads_last_24h, \
           CAST(COALESCE(SUM(CASE WHEN upload_timestamp > NOW() - INTERVAL 1 DAY THEN file_size ELSE 0 END), 0) AS SIGNED) AS bytes_last_24h \
         FROM uploads"
    )
    .fetch_one(&mut *conn)
    .await
}

pub(crate) struct TopUploader {
    pub ip: Vec<u8>,
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
        r#"SELECT uploader_ip AS "ip!: Vec<u8>", CAST(COUNT(*) AS SIGNED) AS "count!: i64", CAST(COALESCE(SUM(file_size), 0) AS SIGNED) AS "bytes!: i64"
           FROM uploads
           WHERE uploader_ip IS NOT NULL
           GROUP BY uploader_ip
           ORDER BY 2 DESC
           LIMIT ?"#,
        limit
    )
    .fetch_all(&mut *conn)
    .await
}

pub(crate) struct TopNsfwUploader {
    pub ip: Vec<u8>,
    pub count: i64,
    pub avg_score: f64,
}

pub(crate) async fn top_nsfw_uploader_ips(
    db: &DbPool,
    min_score: f32,
    limit: i64,
) -> Result<Vec<TopNsfwUploader>, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    sqlx::query_as!(
        TopNsfwUploader,
        r#"SELECT uploader_ip AS "ip!: Vec<u8>", CAST(COUNT(*) AS SIGNED) AS "count!: i64", CAST(AVG(nsfw_score) AS DOUBLE) AS "avg_score!: f64"
           FROM uploads
           WHERE uploader_ip IS NOT NULL AND nsfw_score >= ?
           GROUP BY uploader_ip
           ORDER BY 2 DESC
           LIMIT ?"#,
        min_score,
        limit
    )
    .fetch_all(&mut *conn)
    .await
}

#[derive(serde::Serialize)]
pub(crate) struct HourlyUploadCount {
    pub hour: String,
    pub count: i64,
}

pub(crate) async fn uploads_hourly_counts(
    db: &DbPool,
    ip: IpAddr,
    hours: i64,
) -> Result<Vec<HourlyUploadCount>, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    let ip = ip::to_db_vec(ip);
    let rows = sqlx::query!(
        r#"SELECT DATE_FORMAT(upload_timestamp, '%Y-%m-%dT%H:00:00') AS "bucket!: String", CAST(COUNT(*) AS SIGNED) AS "count!: i64"
           FROM uploads
           WHERE uploader_ip = ? AND upload_timestamp > NOW() - INTERVAL ? HOUR
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

#[derive(serde::Serialize)]
pub(crate) struct MimeUploadCount {
    pub mime: String,
    pub count: i64,
}

pub(crate) async fn uploads_top_mimes(
    db: &DbPool,
    ip: IpAddr,
    limit: i64,
) -> Result<Vec<MimeUploadCount>, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    let ip = ip::to_db_vec(ip);
    sqlx::query_as!(
        MimeUploadCount,
        r#"SELECT content_type AS "mime!: String", CAST(COUNT(*) AS SIGNED) AS "count!: i64"
           FROM uploads
           WHERE uploader_ip = ? AND content_type IS NOT NULL
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
    Bytes(Vec<u8>),
    Str(&'a str),
    F32(f32),
}

pub(crate) async fn list_uploads(
    db: &DbPool,
    ip: Option<IpAddr>,
    slug: Option<&str>,
    include_deleted: bool,
    min_nsfw_score: Option<f32>,
    limit: i64,
    offset: i64,
) -> Result<Vec<Upload>, sqlx::Error> {
    let mut filters = String::new();
    let mut params = Vec::new();

    if let Some(min_score) = min_nsfw_score {
        filters.push_str(" AND nsfw_score >= ?");
        params.push(ListUploadsParam::F32(min_score));
    }
    if let Some(ip) = ip {
        filters.push_str(" AND uploader_ip = ?");
        params.push(ListUploadsParam::Bytes(ip::to_db_vec(ip)));
    }
    if let Some(slug) = slug {
        filters.push_str(" AND slug = ?");
        params.push(ListUploadsParam::Str(slug));
    }

    // `uploads` no longer carries a deleted_timestamp column (all its rows are
    // active), so the live branch synthesizes a NULL for the shared `Upload`
    // row shape and the archive branch supplies the real value. With
    // `include_deleted` the same filters are applied to both branches, which
    // means every bound parameter appears twice.
    let mut sql = String::from(
        "SELECT id, upload_timestamp, expiry_timestamp, NULL AS deleted_timestamp, \
         original_name, slug, file_size, hash, uploader_ip, content_type, user_agent, nsfw_score \
         FROM uploads WHERE 1=1",
    );
    sql.push_str(&filters);
    if include_deleted {
        sql.push_str(
            " UNION ALL SELECT id, upload_timestamp, expiry_timestamp, deleted_timestamp, \
             original_name, slug, file_size, hash, uploader_ip, content_type, user_agent, nsfw_score \
             FROM deleted_uploads WHERE 1=1",
        );
        sql.push_str(&filters);
    }
    sql.push_str(" ORDER BY upload_timestamp DESC LIMIT ? OFFSET ?");

    let mut q = sqlx::query_as::<_, Upload>(sqlx::AssertSqlSafe(sql));
    let branches = if include_deleted { 2 } else { 1 };
    // The filter parameters bind once per union branch; limit/offset bind last.
    for _ in 0..branches {
        for param in &params {
            q = match param {
                ListUploadsParam::Bytes(v) => q.bind(v.clone()),
                ListUploadsParam::Str(v) => q.bind(v.to_owned()),
                ListUploadsParam::F32(v) => q.bind(*v),
            };
        }
    }
    q = q.bind(limit).bind(offset);

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
        "SELECT id AS `id: Uuid`, upload_timestamp, expiry_timestamp, CAST(NULL AS DATETIME) AS deleted_timestamp, original_name, \
         slug, file_size, hash AS `hash: Vec<u8>`, uploader_ip, content_type, user_agent, nsfw_score \
         FROM uploads WHERE slug = ?",
        slug
    )
    .fetch_optional(&mut *conn)
    .await
}

pub(crate) async fn list_banned_ips(
    db: &DbPool,
    limit: i64,
    offset: i64,
) -> Result<Vec<BannedIpRange>, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    sqlx::query_as!(
        BannedIpRange,
        "SELECT id, start_ip, end_ip, reason, banned_timestamp, expires_timestamp, type as \"type_: BanType\", blacklist_id FROM banned_ip_ranges ORDER BY id DESC LIMIT ? OFFSET ?",
        limit,
        offset
    )
    .fetch_all(&mut *conn)
    .await
}

pub(crate) async fn insert_banned_ip(
    db: &DbPool,
    start_ip: IpAddr,
    end_ip: IpAddr,
    reason: Option<&str>,
    expires_timestamp: Option<PrimitiveDateTime>,
    blacklist_id: Option<i32>,
    ban_type: BanType,
) -> Result<i64, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    let start_ip = ip::to_db_vec(start_ip);
    let end_ip = ip::to_db_vec(end_ip);
    let result = sqlx::query!(
        "INSERT INTO banned_ip_ranges (start_ip, end_ip, reason, expires_timestamp, blacklist_id, type) VALUES (?, ?, ?, ?, ?, ?)",
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

/// Inserts blacklist ranges in one multi-row `INSERT` per chunk, so syncing a
/// large blacklist costs a handful of round trips instead of one per range.
pub(crate) async fn insert_banned_ip_batch(
    db: &DbPool,
    ranges: &[(IpAddr, IpAddr)],
    ban_type: BanType,
    blacklist_id: i32,
) -> Result<usize, sqlx::Error> {
    // One bind per column; 4 * 1000 stays well under `max_allowed_packet`.
    const ROWS_PER_STATEMENT: usize = 1000;

    let mut conn = db_pool::conn(db).await?;
    let mut total = 0;
    for chunk in ranges.chunks(ROWS_PER_STATEMENT) {
        let values = std::iter::repeat_n("(?, ?, ?, ?)", chunk.len())
            .collect::<Vec<_>>()
            .join(", ");
        let mut q = sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO banned_ip_ranges (start_ip, end_ip, blacklist_id, type) VALUES {values}"
        )));
        for (start, end) in chunk {
            q = q
                .bind(ip::to_db_vec(*start))
                .bind(ip::to_db_vec(*end))
                .bind(blacklist_id)
                .bind(ban_type as u32);
        }
        total += q.execute(&mut *conn).await?.rows_affected() as usize;
    }
    Ok(total)
}

pub(crate) async fn delete_banned_ips_by_blacklist(
    db: &DbPool,
    blacklist_id: i32,
) -> Result<usize, sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    let result = sqlx::query!(
        "DELETE FROM banned_ip_ranges WHERE blacklist_id = ?",
        blacklist_id
    )
    .execute(&mut *conn)
    .await?;
    Ok(result.rows_affected() as usize)
}

/// The `sqlx` query macros need string literals, so each query is passed in whole
/// rather than assembled from the table/column names. `with_reason` adds an
/// `Option<&str>` insert parameter for ban sets that carry a reason column.
macro_rules! ban_set_crud {
    (
        @list_and_delete $list_fn:ident, $delete_fn:ident, $struct:ty,
        $list_sql:literal, $delete_sql:literal, $key_ty:ty
    ) => {
        pub(crate) async fn $list_fn(db: &DbPool) -> Result<Vec<$struct>, sqlx::Error> {
            let mut conn = db_pool::conn(db).await?;
            sqlx::query_as!($struct, $list_sql)
                .fetch_all(&mut *conn)
                .await
        }

        pub(crate) async fn $delete_fn(db: &DbPool, key: $key_ty) -> Result<bool, sqlx::Error> {
            let mut conn = db_pool::conn(db).await?;
            let result = sqlx::query!($delete_sql, key).execute(&mut *conn).await?;
            Ok(result.rows_affected() > 0)
        }
    };
    (
        $list_fn:ident, $insert_fn:ident, $delete_fn:ident, $struct:ty, $key_ty:ty,
        list = $list_sql:literal, insert = $insert_sql:literal, delete = $delete_sql:literal $(,)?
    ) => {
        ban_set_crud!(@list_and_delete $list_fn, $delete_fn, $struct, $list_sql, $delete_sql, $key_ty);

        pub(crate) async fn $insert_fn(db: &DbPool, key: $key_ty) -> Result<(), sqlx::Error> {
            let mut conn = db_pool::conn(db).await?;
            sqlx::query!($insert_sql, key).execute(&mut *conn).await?;
            Ok(())
        }
    };
    (
        $list_fn:ident, $insert_fn:ident, $delete_fn:ident, $struct:ty, $key_ty:ty,
        list = $list_sql:literal, insert = $insert_sql:literal, delete = $delete_sql:literal,
        with_reason $(,)?
    ) => {
        ban_set_crud!(@list_and_delete $list_fn, $delete_fn, $struct, $list_sql, $delete_sql, $key_ty);

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
    "DELETE FROM banned_ip_ranges WHERE id = ?"
);

ban_set_crud!(
    list_banned_filenames,
    insert_banned_filename,
    delete_banned_filename,
    BannedFilename,
    &str,
    list = "SELECT pattern, reason FROM banned_filenames ORDER BY pattern",
    insert = "INSERT IGNORE INTO banned_filenames (pattern, reason) VALUES (?, ?)",
    delete = "DELETE FROM banned_filenames WHERE pattern = ?",
    with_reason,
);

ban_set_crud!(
    list_banned_mimes,
    insert_banned_mime,
    delete_banned_mime,
    BannedFileMime,
    &str,
    list = "SELECT mime FROM banned_file_mimes ORDER BY mime",
    insert = "INSERT IGNORE INTO banned_file_mimes (mime) VALUES (?)",
    delete = "DELETE FROM banned_file_mimes WHERE mime = ?",
);

ban_set_crud!(
    list_banned_hashes,
    insert_banned_hash,
    delete_banned_hash,
    BannedFileHash,
    &[u8],
    list = "SELECT hash, reason FROM banned_file_hashes ORDER BY hash",
    insert = "INSERT IGNORE INTO banned_file_hashes (hash, reason) VALUES (?, ?)",
    delete = "DELETE FROM banned_file_hashes WHERE hash = ?",
    with_reason,
);

ban_set_crud!(
    list_banned_user_agents,
    insert_banned_user_agent,
    delete_banned_user_agent,
    BannedUserAgent,
    &str,
    list = "SELECT pattern, reason FROM banned_user_agents ORDER BY pattern",
    insert = "INSERT IGNORE INTO banned_user_agents (pattern, reason) VALUES (?, ?)",
    delete = "DELETE FROM banned_user_agents WHERE pattern = ?",
    with_reason,
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

/// Records a successful blacklist sync.
pub(crate) async fn touch_blacklist(db: &DbPool, id: i32) -> Result<(), sqlx::Error> {
    let mut conn = db_pool::conn(db).await?;
    sqlx::query!("UPDATE blacklist SET last_update = NOW() WHERE id = ?", id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}
