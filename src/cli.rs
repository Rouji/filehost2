use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use uuid::Uuid;

use crate::db;
use crate::db_pool::{self, DbPool};
use crate::dedup;
use crate::import;
use crate::model::BanType;
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
    /// manage blacklist URL entries
    Blacklist {
        #[command(subcommand)]
        command: BlacklistCommand,
    },
}

#[derive(Subcommand)]
pub(crate) enum BlacklistCommand {
    List,
    Add {
        url: String,
        /// entry type: 1=readonly, 2=full
        #[arg(short, long, default_value_t = 1)]
        type_: u32,
        #[arg(long, default_value_t = 86400)]
        interval: u64,
    },
    Remove {
        id: i32,
    },
    /// fetch and apply IP ranges from all configured blacklist URLs
    Sync,
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

pub(crate) async fn blacklist(db: &DbPool, command: BlacklistCommand) -> Result<()> {
    match command {
        BlacklistCommand::List => list_blacklist(db).await,
        BlacklistCommand::Add {
            url,
            type_,
            interval,
        } => add_blacklist(db, url, type_, interval).await,
        BlacklistCommand::Remove { id } => remove_blacklist(db, id).await,
        BlacklistCommand::Sync => crate::sync::sync_all(db).await,
    }
}

async fn list_blacklist(db: &DbPool) -> Result<()> {
    let entries = db::list_blacklist(db).await?;
    if entries.is_empty() {
        println!("No blacklist entries.");
        return Ok(());
    }
    for entry in &entries {
        let last_update = entry
            .last_update
            .map(|t| t.assume_utc().to_string())
            .unwrap_or_else(|| "never".to_string());
        println!(
            "{:>6}  {:<255}  type={:<2}  interval={:>10}s  last_update={}",
            entry.id, entry.url, entry.type_, entry.update_interval_seconds, last_update
        );
    }
    Ok(())
}

async fn add_blacklist(db: &DbPool, url: String, type_: u32, interval: u64) -> Result<()> {
    if ![1, 2].contains(&type_) {
        anyhow::bail!("type must be 1 (readonly) or 2 (full)");
    }
    let type_ = match type_ {
        1 => BanType::ReadOnly,
        2 => BanType::Full,
        _ => BanType::ReadOnly,
    };
    let id = db::insert_blacklist(db, &url, type_, interval).await?;
    log::info!("blacklist: added entry id={id} url={url}");
    println!("Added entry with id {id}.");
    Ok(())
}

async fn remove_blacklist(db: &DbPool, id: i32) -> Result<()> {
    match db::delete_blacklist(db, id).await? {
        true => {
            log::info!("blacklist: removed entry id={id}");
            println!("Removed entry {id}.");
            Ok(())
        }
        false => anyhow::bail!("No entry with id {id}."),
    }
}
