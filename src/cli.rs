use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use sqlx::mysql::MySqlPool;
use uuid::Uuid;

use crate::db;
use crate::migrate;
use crate::settings::Settings;

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
    /// Import files from a single_php_filehost instance
    ImportPhp {
        /// Path to the PHP filehost's files directory
        files: PathBuf,
        /// Path to the PHP filehost's upload log
        #[arg(long)]
        log: Option<PathBuf>,
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
    let count = db::delete_expired(db, settings).await?;
    println!("Deleted {count} expired upload(s).");
    Ok(())
}

pub(crate) async fn import_php(
    db: &MySqlPool,
    settings: &Settings,
    files: PathBuf,
    log: Option<PathBuf>,
) -> Result<()> {
    migrate::import_php(db, settings, files, log).await
}

pub(crate) async fn delete(
    db: &MySqlPool,
    settings: &Settings,
    target: DeleteTarget,
) -> Result<()> {
    let count = match target {
        DeleteTarget::Id { id } => db::delete_by_id(db, settings, id).await?,
        DeleteTarget::Slug { slug } => db::delete_by_slug(db, settings, &slug).await?,
        DeleteTarget::Ip { ip } => db::delete_by_ip(db, settings, u32::from(ip)).await?,
        DeleteTarget::IpRange { start, end } => {
            db::delete_by_ip_range(db, settings, u32::from(start), u32::from(end)).await?
        }
    };
    println!("Deleted {count} upload(s).");
    Ok(())
}
