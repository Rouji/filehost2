use std::path::Path;

use anyhow::Result;
use sqlx::mysql::MySqlPool;
use uuid::Uuid;

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

pub(crate) async fn delete_expired(db: &MySqlPool, settings: &Settings) -> Result<usize> {
    let rows = sqlx::query!(
        "SELECT id as `id: Uuid`, slug, original_name FROM uploads WHERE expiry_timestamp <= NOW() AND deleted_timestamp IS NULL"
    )
    .fetch_all(db)
    .await?;
    let count = rows.len();
    for r in rows {
        delete_one(db, settings, r.id, &r.slug, &r.original_name).await?;
    }
    Ok(count)
}

pub(crate) async fn delete_by_id(db: &MySqlPool, settings: &Settings, id: Uuid) -> Result<usize> {
    let rows = sqlx::query!(
        "SELECT id as `id: Uuid`, slug, original_name FROM uploads WHERE id = ? AND deleted_timestamp IS NULL",
        id
    )
    .fetch_all(db)
    .await?;
    let count = rows.len();
    for r in rows {
        delete_one(db, settings, r.id, &r.slug, &r.original_name).await?;
    }
    Ok(count)
}

pub(crate) async fn delete_by_slug(
    db: &MySqlPool,
    settings: &Settings,
    slug: &str,
) -> Result<usize> {
    let rows = sqlx::query!(
        "SELECT id as `id: Uuid`, slug, original_name FROM uploads WHERE slug = ? AND deleted_timestamp IS NULL",
        slug
    )
    .fetch_all(db)
    .await?;
    let count = rows.len();
    for r in rows {
        delete_one(db, settings, r.id, &r.slug, &r.original_name).await?;
    }
    Ok(count)
}

pub(crate) async fn delete_by_ip(db: &MySqlPool, settings: &Settings, ip: u32) -> Result<usize> {
    let rows = sqlx::query!(
        "SELECT id as `id: Uuid`, slug, original_name FROM uploads WHERE uploader_ip = ? AND deleted_timestamp IS NULL",
        ip
    )
    .fetch_all(db)
    .await?;
    let count = rows.len();
    for r in rows {
        delete_one(db, settings, r.id, &r.slug, &r.original_name).await?;
    }
    Ok(count)
}

pub(crate) async fn delete_by_ip_range(
    db: &MySqlPool,
    settings: &Settings,
    start: u32,
    end: u32,
) -> Result<usize> {
    let rows = sqlx::query!(
        "SELECT id as `id: Uuid`, slug, original_name FROM uploads WHERE uploader_ip BETWEEN ? AND ? AND deleted_timestamp IS NULL",
        start,
        end
    )
    .fetch_all(db)
    .await?;
    let count = rows.len();
    for r in rows {
        delete_one(db, settings, r.id, &r.slug, &r.original_name).await?;
    }
    Ok(count)
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
