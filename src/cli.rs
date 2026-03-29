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
}

pub(crate) async fn migrate(db: &MySqlPool) -> Result<()> {
    sqlx::migrate!().run(db).await?;
    println!("Migrations applied.");
    Ok(())
}

pub(crate) async fn delete_expired(db: &MySqlPool, settings: &Settings) -> Result<()> {
    let uploads = sqlx::query!(
        "SELECT id as `id: Uuid`, original_name FROM uploads WHERE expiry_timestamp <= NOW() AND deleted_timestamp IS NULL"
    )
    .fetch_all(db)
    .await?;

    let count = uploads.len();
    for upload in uploads {
        let path = uuid_to_path(Path::new(&settings.store_path), &upload.id);
        if let Err(e) = std::fs::remove_file(&path) {
            log::warn!("Failed to delete {}: {e}", path.display());
        }
        sqlx::query!(
            "UPDATE uploads SET deleted_timestamp = NOW() WHERE id = ?",
            upload.id,
        )
        .execute(db)
        .await?;
        log::info!(
            "Deleted expired upload: {} ({})",
            upload.original_name,
            upload.id
        );
    }

    println!("Deleted {count} expired upload(s).");
    Ok(())
}
