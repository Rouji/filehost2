use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::Result;
use clap::{Parser, Subcommand};
use sqlx::mysql::MySqlPool;
use uuid::Uuid;

use crate::settings::Settings;
use crate::upload::uuid_to_path;

#[derive(Parser)]
#[command(about = "Minimalistic file hosting service")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Option<Command>,
}

#[derive(Subcommand)]
pub(crate) enum Command {
    Migrate,
    DeleteExpired,
    Delete {
        #[command(subcommand)]
        target: DeleteTarget,
    },
}

#[derive(Subcommand)]
pub(crate) enum DeleteTarget {
    Id { id: Uuid },
    Slug { slug: String },
    Ip { ip: Ipv4Addr },
    IpRange { start: Ipv4Addr, end: Ipv4Addr },
}

pub(crate) async fn migrate(db: &MySqlPool) -> Result<()> {
    sqlx::migrate!().run(db).await?;
    println!("Migrations applied.");
    Ok(())
}

pub(crate) async fn delete_expired(db: &MySqlPool, settings: &Settings) -> Result<()> {
    let uploads = sqlx::query!(
        "SELECT id as `id: Uuid`, slug, original_name FROM uploads WHERE expiry_timestamp <= NOW() AND deleted_timestamp IS NULL"
    )
    .fetch_all(db)
    .await?;

    let count = uploads.len();
    for upload in uploads {
        delete_by_id(db, settings, upload.id, &upload.slug, &upload.original_name).await?;
    }
    println!("Deleted {count} expired upload(s).");
    Ok(())
}

pub(crate) async fn delete(
    db: &MySqlPool,
    settings: &Settings,
    target: DeleteTarget,
) -> Result<()> {
    let count = match target {
        DeleteTarget::Id { id } => {
            let rows = sqlx::query!(
                "SELECT id as `id: Uuid`, slug, original_name FROM uploads WHERE id = ? AND deleted_timestamp IS NULL",
                id
            )
            .fetch_all(db)
            .await?;
            let n = rows.len();
            for r in rows {
                delete_by_id(db, settings, r.id, &r.slug, &r.original_name).await?;
            }
            n
        }
        DeleteTarget::Slug { slug } => {
            let rows = sqlx::query!(
                "SELECT id as `id: Uuid`, slug, original_name FROM uploads WHERE slug = ? AND deleted_timestamp IS NULL",
                slug
            )
            .fetch_all(db)
            .await?;
            let n = rows.len();
            for r in rows {
                delete_by_id(db, settings, r.id, &r.slug, &r.original_name).await?;
            }
            n
        }
        DeleteTarget::Ip { ip } => {
            let ip_int = u32::from(ip);
            let rows = sqlx::query!(
                "SELECT id as `id: Uuid`, slug, original_name FROM uploads WHERE uploader_ip = ? AND deleted_timestamp IS NULL",
                ip_int
            )
            .fetch_all(db)
            .await?;
            let n = rows.len();
            for r in rows {
                delete_by_id(db, settings, r.id, &r.slug, &r.original_name).await?;
            }
            n
        }
        DeleteTarget::IpRange { start, end } => {
            let start_int = u32::from(start);
            let end_int = u32::from(end);
            let rows = sqlx::query!(
                "SELECT id as `id: Uuid`, slug, original_name FROM uploads WHERE uploader_ip BETWEEN ? AND ? AND deleted_timestamp IS NULL",
                start_int,
                end_int,
            )
            .fetch_all(db)
            .await?;
            let n = rows.len();
            for r in rows {
                delete_by_id(db, settings, r.id, &r.slug, &r.original_name).await?;
            }
            n
        }
    };

    println!("Deleted {count} upload(s).");
    Ok(())
}

async fn delete_by_id(
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
