use std::net::IpAddr;

use anyhow::Result;
use clap::{Parser, Subcommand};
use uuid::Uuid;

use crate::db;
use crate::db_pool::{self, DbPool};
use crate::dedup;
use crate::ip;
use crate::model::BanType;
use crate::settings::Settings;
use crate::util::{format_ts, hex_decode, hex_encode, parse_rfc3339};

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
    /// replace existing duplicate upload files with symlinks to the newest duplicate
    Dedup {
        #[arg(long)]
        dry_run: bool,
    },
    /// compute and store the BLAKE3 hash for uploads whose `hash` column is NULL
    Rehash,
    /// (re-)run NSFW detection against active image uploads (requires NSFW_MODEL_PATH)
    Rensfw {
        /// also rescan uploads that already have a score, not just unscored ones
        #[arg(long)]
        all: bool,
        /// classify and print results without writing `nsfw_score` updates
        #[arg(long)]
        dry_run: bool,
    },
    /// manage blacklist URL entries
    Blacklist {
        #[command(subcommand)]
        command: BlacklistCommand,
    },
    /// manage individual bans (IPs, extensions, mimes, hashes, user agents)
    Ban {
        #[command(subcommand)]
        target: BanTarget,
    },
}

#[derive(Subcommand)]
pub(crate) enum BanTarget {
    Ip {
        #[command(subcommand)]
        command: BanIpCommand,
    },
    Extension {
        #[command(subcommand)]
        command: BanExtensionCommand,
    },
    Mime {
        #[command(subcommand)]
        command: BanMimeCommand,
    },
    Hash {
        #[command(subcommand)]
        command: BanHashCommand,
    },
    UserAgent {
        #[command(subcommand)]
        command: BanUserAgentCommand,
    },
}

#[derive(Subcommand)]
pub(crate) enum BanIpCommand {
    List,
    Add {
        start: IpAddr,
        end: IpAddr,
        #[arg(long)]
        reason: Option<String>,
        /// RFC3339 expiry timestamp, e.g. 2026-01-01T00:00:00Z
        #[arg(long)]
        expires: Option<String>,
        /// ban type: 1=readonly, 2=full
        #[arg(short, long = "type", default_value_t = 1)]
        type_: u32,
    },
    Remove {
        id: i64,
    },
}

#[derive(Subcommand)]
pub(crate) enum BanExtensionCommand {
    List,
    Add { extension: String },
    Remove { extension: String },
}

#[derive(Subcommand)]
pub(crate) enum BanMimeCommand {
    List,
    Add { mime: String },
    Remove { mime: String },
}

#[derive(Subcommand)]
pub(crate) enum BanHashCommand {
    List,
    Add {
        /// lowercase hex-encoded BLAKE3 hash
        hash: String,
        #[arg(long)]
        reason: Option<String>,
    },
    Remove {
        hash: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum BanUserAgentCommand {
    List,
    Add {
        pattern: String,
        #[arg(long)]
        reason: Option<String>,
    },
    Remove {
        pattern: String,
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
    Ip { ip: IpAddr },
    IpRange { start: IpAddr, end: IpAddr },
}

fn parse_ban_type(type_: u32) -> Result<BanType> {
    match type_ {
        1 => Ok(BanType::ReadOnly),
        2 => Ok(BanType::Full),
        _ => anyhow::bail!("type must be 1 (readonly) or 2 (full)"),
    }
}

fn print_list_or_empty<T>(entries: &[T], empty_msg: &str, print_one: impl Fn(&T)) {
    if entries.is_empty() {
        println!("{empty_msg}");
        return;
    }
    for entry in entries {
        print_one(entry);
    }
}

struct RemovalMessages {
    log: String,
    ok: String,
    err: String,
}

fn removal_result(removed: bool, messages: RemovalMessages) -> Result<()> {
    if removed {
        log::info!("{}", messages.log);
        println!("{}", messages.ok);
        Ok(())
    } else {
        anyhow::bail!("{}", messages.err)
    }
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

pub(crate) async fn dedup(db: &DbPool, settings: &Settings, dry_run: bool) -> Result<()> {
    dedup::dedup(db, settings, dry_run).await
}

pub(crate) async fn rehash(db: &DbPool, settings: &Settings) -> Result<()> {
    dedup::rehash(db, settings).await
}

pub(crate) async fn rensfw(
    db: &DbPool,
    settings: &Settings,
    all: bool,
    dry_run: bool,
) -> Result<()> {
    crate::nsfw::rensfw(db, settings, all, dry_run).await
}

pub(crate) async fn delete(db: &DbPool, settings: &Settings, target: DeleteTarget) -> Result<()> {
    let count = match target {
        DeleteTarget::Id { id } => db::delete_by_id(db, settings, id).await?,
        DeleteTarget::Slug { slug } => db::delete_by_slug(db, settings, &slug).await?,
        DeleteTarget::Ip { ip } => db::delete_by_ip(db, settings, ip).await?,
        DeleteTarget::IpRange { start, end } => {
            db::delete_by_ip_range(db, settings, start, end).await?
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
    print_list_or_empty(&entries, "No blacklist entries.", |entry| {
        let last_update = entry
            .last_update
            .map(|t| t.assume_utc().to_string())
            .unwrap_or_else(|| "never".to_string());
        println!(
            "{:>6}  {:<255}  type={:<2}  interval={:>10}s  last_update={}",
            entry.id, entry.url, entry.type_, entry.update_interval_seconds, last_update
        );
    });
    Ok(())
}

async fn add_blacklist(db: &DbPool, url: String, type_: u32, interval: u64) -> Result<()> {
    let type_ = parse_ban_type(type_)?;
    let id = db::insert_blacklist(db, &url, type_, interval).await?;
    log::info!("blacklist: added entry id={id} url={url}");
    println!("Added entry with id {id}.");
    Ok(())
}

async fn remove_blacklist(db: &DbPool, id: i32) -> Result<()> {
    removal_result(
        db::delete_blacklist(db, id).await?,
        RemovalMessages {
            log: format!("blacklist: removed entry id={id}"),
            ok: format!("Removed entry {id}."),
            err: format!("No entry with id {id}."),
        },
    )
}

pub(crate) async fn ban(db: &DbPool, target: BanTarget) -> Result<()> {
    match target {
        BanTarget::Ip { command } => ban_ip(db, command).await,
        BanTarget::Extension { command } => ban_extension(db, command).await,
        BanTarget::Mime { command } => ban_mime(db, command).await,
        BanTarget::Hash { command } => ban_hash(db, command).await,
        BanTarget::UserAgent { command } => ban_user_agent(db, command).await,
    }
}

async fn ban_ip(db: &DbPool, command: BanIpCommand) -> Result<()> {
    match command {
        BanIpCommand::List => {
            let entries = db::list_banned_ips(db, i64::MAX, 0).await?;
            print_list_or_empty(&entries, "No banned IP ranges.", |entry| {
                let reason = entry.reason.as_deref().unwrap_or("-");
                let expires = entry
                    .expires_timestamp
                    .map(format_ts)
                    .unwrap_or_else(|| "never".to_string());
                let start = ip::from_db_bytes(&entry.start_ip)
                    .map(|ip| ip.to_string())
                    .unwrap_or_default();
                let end = ip::from_db_bytes(&entry.end_ip)
                    .map(|ip| ip.to_string())
                    .unwrap_or_default();
                println!(
                    "{:>6}  {:<15}-{:<15}  type={:<8}  reason={:<20}  expires={}",
                    entry.id,
                    start,
                    end,
                    entry.type_.to_string(),
                    reason,
                    expires
                );
            });
            Ok(())
        }
        BanIpCommand::Add {
            start,
            end,
            reason,
            expires,
            type_,
        } => {
            anyhow::ensure!(
                ip::same_family(start, end),
                "start and end must be the same IP version"
            );
            let ban_type = parse_ban_type(type_)?;
            let expires_timestamp = match expires.as_deref() {
                Some(s) => Some(
                    parse_rfc3339(s)
                        .ok_or_else(|| anyhow::anyhow!("Invalid --expires timestamp"))?,
                ),
                None => None,
            };
            let id = db::insert_banned_ip(
                db,
                start,
                end,
                reason.as_deref(),
                expires_timestamp,
                None,
                ban_type,
            )
            .await?;
            log::info!("ban: banned ip range {start}-{end} (id {id})");
            println!("Banned {start}-{end} with id {id}.");
            Ok(())
        }
        BanIpCommand::Remove { id } => removal_result(
            db::delete_banned_ip(db, id).await?,
            RemovalMessages {
                log: format!("ban: removed banned ip range id={id}"),
                ok: format!("Removed ban {id}."),
                err: format!("No banned IP range with id {id}."),
            },
        ),
    }
}

async fn ban_extension(db: &DbPool, command: BanExtensionCommand) -> Result<()> {
    match command {
        BanExtensionCommand::List => {
            let entries = db::list_banned_extensions(db).await?;
            print_list_or_empty(&entries, "No banned extensions.", |entry| {
                println!("{}", entry.extension);
            });
            Ok(())
        }
        BanExtensionCommand::Add { extension } => {
            db::insert_banned_extension(db, &extension).await?;
            log::info!("ban: banned extension {extension}");
            println!("Banned extension {extension}.");
            Ok(())
        }
        BanExtensionCommand::Remove { extension } => removal_result(
            db::delete_banned_extension(db, &extension).await?,
            RemovalMessages {
                log: format!("ban: removed banned extension {extension}"),
                ok: format!("Removed ban on extension {extension}."),
                err: format!("No ban on extension {extension}."),
            },
        ),
    }
}

async fn ban_mime(db: &DbPool, command: BanMimeCommand) -> Result<()> {
    match command {
        BanMimeCommand::List => {
            let entries = db::list_banned_mimes(db).await?;
            print_list_or_empty(&entries, "No banned mime types.", |entry| {
                println!("{}", entry.mime);
            });
            Ok(())
        }
        BanMimeCommand::Add { mime } => {
            db::insert_banned_mime(db, &mime).await?;
            log::info!("ban: banned mime {mime}");
            println!("Banned mime {mime}.");
            Ok(())
        }
        BanMimeCommand::Remove { mime } => removal_result(
            db::delete_banned_mime(db, &mime).await?,
            RemovalMessages {
                log: format!("ban: removed banned mime {mime}"),
                ok: format!("Removed ban on mime {mime}."),
                err: format!("No ban on mime {mime}."),
            },
        ),
    }
}

async fn ban_hash(db: &DbPool, command: BanHashCommand) -> Result<()> {
    match command {
        BanHashCommand::List => {
            let entries = db::list_banned_hashes(db).await?;
            print_list_or_empty(&entries, "No banned hashes.", |entry| {
                let reason = entry.reason.as_deref().unwrap_or("-");
                println!("{}  reason={}", hex_encode(&entry.hash), reason);
            });
            Ok(())
        }
        BanHashCommand::Add { hash, reason } => {
            let bytes = hex_decode(&hash)
                .ok_or_else(|| anyhow::anyhow!("Invalid hash (expected lowercase hex)"))?;
            if bytes.len() != 32 {
                anyhow::bail!("Invalid hash length (expected 32-byte BLAKE3)");
            }
            db::insert_banned_hash(db, &bytes, reason.as_deref()).await?;
            log::info!("ban: banned hash {hash}");
            println!("Banned hash {hash}.");
            Ok(())
        }
        BanHashCommand::Remove { hash } => {
            let bytes = hex_decode(&hash)
                .ok_or_else(|| anyhow::anyhow!("Invalid hash (expected lowercase hex)"))?;
            removal_result(
                db::delete_banned_hash(db, &bytes).await?,
                RemovalMessages {
                    log: format!("ban: removed banned hash {hash}"),
                    ok: format!("Removed ban on hash {hash}."),
                    err: format!("No ban on hash {hash}."),
                },
            )
        }
    }
}

async fn ban_user_agent(db: &DbPool, command: BanUserAgentCommand) -> Result<()> {
    match command {
        BanUserAgentCommand::List => {
            let entries = db::list_banned_user_agents(db).await?;
            print_list_or_empty(&entries, "No banned user agent patterns.", |entry| {
                let reason = entry.reason.as_deref().unwrap_or("-");
                println!("{}  reason={}", entry.pattern, reason);
            });
            Ok(())
        }
        BanUserAgentCommand::Add { pattern, reason } => {
            db::insert_banned_user_agent(db, &pattern, reason.as_deref()).await?;
            log::info!("ban: banned user agent pattern {pattern:?}");
            println!("Banned user agent pattern {pattern:?}.");
            Ok(())
        }
        BanUserAgentCommand::Remove { pattern } => removal_result(
            db::delete_banned_user_agent(db, &pattern).await?,
            RemovalMessages {
                log: format!("ban: removed banned user agent pattern {pattern:?}"),
                ok: format!("Removed ban on user agent pattern {pattern:?}."),
                err: format!("No ban on user agent pattern {pattern:?}."),
            },
        ),
    }
}
