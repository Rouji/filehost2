use std::net::IpAddr;

use anyhow::Result;
use clap::{Parser, Subcommand};
use uuid::Uuid;

use crate::db;
use crate::db_pool::DbPool;
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
    /// download iptoasn.com data and replace the ip_asn table (per-ASN abuse queries)
    AsnSync {
        /// path to a local ip2asn-combined.tsv(.gz), overriding the download
        #[arg(long)]
        path: Option<String>,
    },
    /// manage individual bans (IPs, filenames, mimes, hashes, user agents)
    Ban {
        #[command(subcommand)]
        target: BanTarget,
    },
    /// manage whitelisted IP ranges (skip IP bans and challenges)
    Whitelist {
        #[command(subcommand)]
        command: WhitelistCommand,
    },
}

#[derive(Subcommand)]
pub(crate) enum BanTarget {
    Ip {
        #[command(subcommand)]
        command: BanIpCommand,
    },
    Filename {
        #[command(subcommand)]
        command: BanFilenameCommand,
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
pub(crate) enum WhitelistCommand {
    List,
    Add {
        start: IpAddr,
        end: IpAddr,
        #[arg(long)]
        reason: Option<String>,
    },
    Remove {
        id: i64,
    },
}

#[derive(Subcommand)]
pub(crate) enum BanFilenameCommand {
    List,
    Add {
        /// regex matched against the full uploaded filename
        pattern: String,
        #[arg(long)]
        reason: Option<String>,
    },
    Remove {
        pattern: String,
    },
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
    BanType::try_from(type_).map_err(|_| anyhow::anyhow!("type must be 1 (readonly) or 2 (full)"))
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

/// Uniform output for `ban ... remove`; `what` names the ban, e.g.
/// `filename pattern "\\.exe$"` or `ip range id=3`.
fn removal_result(removed: bool, what: &str) -> Result<()> {
    if removed {
        log::info!("ban: removed {what}");
        println!("Removed ban on {what}.");
        Ok(())
    } else {
        anyhow::bail!("No ban on {what}.")
    }
}

/// Uniform output for `ban ... add`; `noun` is the ban kind, `key` its
/// display form.
fn print_added(noun: &str, key: &str) {
    log::info!("ban: banned {noun} {key}");
    println!("Banned {noun} {key}.");
}

/// Decodes and validates a hex-encoded BLAKE3 hash argument.
fn parse_hash(s: &str) -> Result<Vec<u8>> {
    let bytes =
        hex_decode(s).ok_or_else(|| anyhow::anyhow!("Invalid hash (expected lowercase hex)"))?;
    anyhow::ensure!(
        bytes.len() == 32,
        "Invalid hash length (expected 32-byte BLAKE3)"
    );
    Ok(bytes)
}

pub(crate) async fn migrate(db: &DbPool) -> Result<()> {
    db::run_migrations(db).await?;
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

pub(crate) async fn asn_sync(db: &DbPool, path: Option<&str>) -> Result<()> {
    let count = crate::asn::sync_asn(db, path).await?;
    println!("Replaced ip_asn with {count} ranges.");
    Ok(())
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
    if db::delete_blacklist(db, id).await? {
        log::info!("blacklist: removed entry id={id}");
        println!("Removed entry {id}.");
        Ok(())
    } else {
        anyhow::bail!("No entry with id {id}.")
    }
}

pub(crate) async fn ban(db: &DbPool, target: BanTarget) -> Result<()> {
    match target {
        BanTarget::Ip { command } => ban_ip(db, command).await,
        BanTarget::Filename { command } => ban_filename(db, command).await,
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
                let start = ip::display_db_bytes(&entry.start_ip);
                let end = ip::display_db_bytes(&entry.end_ip);
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
            &format!("ip range id={id}"),
        ),
    }
}

pub(crate) async fn whitelist(db: &DbPool, command: WhitelistCommand) -> Result<()> {
    match command {
        WhitelistCommand::List => {
            let entries = db::list_whitelisted_ips(db, i64::MAX, 0).await?;
            print_list_or_empty(&entries, "No whitelisted IP ranges.", |entry| {
                let reason = entry.reason.as_deref().unwrap_or("-");
                let start = ip::display_db_bytes(&entry.start_ip);
                let end = ip::display_db_bytes(&entry.end_ip);
                println!(
                    "{:>6}  {:<15}-{:<15}  reason={}",
                    entry.id, start, end, reason
                );
            });
            Ok(())
        }
        WhitelistCommand::Add { start, end, reason } => {
            anyhow::ensure!(
                ip::same_family(start, end),
                "start and end must be the same IP version"
            );
            let id = db::insert_whitelisted_ip(db, start, end, reason.as_deref()).await?;
            log::info!("whitelist: added ip range {start}-{end} (id {id})");
            println!("Whitelisted {start}-{end} with id {id}.");
            Ok(())
        }
        WhitelistCommand::Remove { id } => removal_result(
            db::delete_whitelisted_ip(db, id).await?,
            &format!("ip range id={id}"),
        ),
    }
}

async fn ban_filename(db: &DbPool, command: BanFilenameCommand) -> Result<()> {
    match command {
        BanFilenameCommand::List => {
            let entries = db::list_banned_filenames(db).await?;
            print_list_or_empty(&entries, "No banned filename patterns.", |entry| {
                let reason = entry.reason.as_deref().unwrap_or("-");
                println!("{}  reason={}", entry.pattern, reason);
            });
            Ok(())
        }
        BanFilenameCommand::Add { pattern, reason } => {
            if let Err(e) = regex::Regex::new(&pattern) {
                anyhow::bail!("invalid regex {pattern:?}: {e}");
            }
            db::insert_banned_filename(db, &pattern, reason.as_deref()).await?;
            print_added("filename pattern", &format!("{pattern:?}"));
            Ok(())
        }
        BanFilenameCommand::Remove { pattern } => removal_result(
            db::delete_banned_filename(db, &pattern).await?,
            &format!("filename pattern {pattern:?}"),
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
            let mime = mime.to_lowercase();
            db::insert_banned_mime(db, &mime).await?;
            print_added("mime", &mime);
            Ok(())
        }
        BanMimeCommand::Remove { mime } => {
            let mime = mime.to_lowercase();
            removal_result(
                db::delete_banned_mime(db, &mime).await?,
                &format!("mime {mime}"),
            )
        }
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
            let bytes = parse_hash(&hash)?;
            db::insert_banned_hash(db, &bytes, reason.as_deref()).await?;
            print_added("hash", &hash);
            Ok(())
        }
        BanHashCommand::Remove { hash } => removal_result(
            db::delete_banned_hash(db, &parse_hash(&hash)?).await?,
            &format!("hash {hash}"),
        ),
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
            print_added("user agent pattern", &format!("{pattern:?}"));
            Ok(())
        }
        BanUserAgentCommand::Remove { pattern } => removal_result(
            db::delete_banned_user_agent(db, &pattern).await?,
            &format!("user agent pattern {pattern:?}"),
        ),
    }
}
