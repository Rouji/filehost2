use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use uuid::Uuid;

use crate::db;
use crate::db_pool::{self, DbPool};
use crate::dedup;
use crate::import;
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
    /// replace existing duplicate upload files with symlinks to the newest duplicate
    Dedup {
        #[arg(long)]
        dry_run: bool,
    },
    /// compute and store the BLAKE3 hash for uploads whose `hash` column is NULL
    Rehash,
}

#[derive(Subcommand)]
pub(crate) enum DeleteTarget {
    Id { id: Uuid },
    Slug { slug: String },
    Ip { ip: Ipv4Addr },
    IpRange { start: Ipv4Addr, end: Ipv4Addr },
}

pub(crate) async fn migrate(db: &DbPool) -> Result<()> {
    let mut conn = db_pool::conn(db).await?;
    sqlx::migrate!().run(&mut *conn).await?;
    println!("Migrations applied.");
    Ok(())
}

pub(crate) async fn delete_expired(db: &DbPool, settings: &Settings) -> Result<()> {
    let count = db::delete_expired(db, settings).await?;
    println!("Deleted {count} expired upload(s).");
    Ok(())
}

pub(crate) async fn import_php(
    db: &DbPool,
    settings: &Settings,
    files: PathBuf,
    log: Option<PathBuf>,
) -> Result<()> {
    import::import_php(db, settings, files, log).await
}

pub(crate) async fn dedup(db: &DbPool, settings: &Settings, dry_run: bool) -> Result<()> {
    dedup::dedup(db, settings, dry_run).await
}

pub(crate) async fn rehash(db: &DbPool, settings: &Settings) -> Result<()> {
    dedup::rehash(db, settings).await
}

pub(crate) async fn delete(db: &DbPool, settings: &Settings, target: DeleteTarget) -> Result<()> {
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
