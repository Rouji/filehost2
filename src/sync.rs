use std::net::Ipv4Addr;

use anyhow::Result;
use time::PrimitiveDateTime;

use crate::db;
use crate::db_pool;
use crate::db_pool::DbPool;
use crate::model::BanType;

fn now() -> PrimitiveDateTime {
    let odt = time::OffsetDateTime::now_utc();
    PrimitiveDateTime::new(odt.date(), odt.time())
}

fn elapsed_seconds(a: PrimitiveDateTime, b: PrimitiveDateTime) -> i64 {
    let a = a.assume_utc();
    let b = b.assume_utc();
    (a - b).whole_seconds()
}

pub(crate) struct IpRangeEntry {
    pub start_ip: u32,
    pub end_ip: u32,
}

/// fetches a blacklist URL and parses IP ranges from the response body
/// one IP, CIDR, or range
/// lines starting with # are comments, empty lines ignored
pub(crate) async fn fetch_ip_ranges(url: &str) -> Result<Vec<IpRangeEntry>> {
    let body = reqwest::get(url).await?.text().await?;
    let mut entries = Vec::new();

    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(entry) = parse_line(line) {
            entries.push(entry);
        }
    }

    Ok(entries)
}

fn parse_line(line: &str) -> Option<IpRangeEntry> {
    let line = line.trim();

    if let Some(entry) = parse_cidr(line) {
        return Some(entry);
    }

    if let Some(entry) = parse_range(line) {
        return Some(entry);
    }

    if let Ok(ip) = line.parse::<Ipv4Addr>() {
        let ip_u32 = u32::from(ip);
        return Some(IpRangeEntry {
            start_ip: ip_u32,
            end_ip: ip_u32,
        });
    }

    None
}

fn parse_cidr(line: &str) -> Option<IpRangeEntry> {
    let parts: Vec<&str> = line.splitn(2, '/').collect();
    if parts.len() != 2 {
        return None;
    }
    let ip: Ipv4Addr = parts[0].parse().ok()?;
    let prefix: u8 = parts[1].parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let ip_u32 = u32::from(ip);
    let mask = if prefix == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix)
    };
    let start = ip_u32 & mask;
    let end = start | !mask;
    Some(IpRangeEntry {
        start_ip: start,
        end_ip: end,
    })
}

fn parse_range(line: &str) -> Option<IpRangeEntry> {
    let parts: Vec<&str> = if let Some(pos) = line.find("-") {
        vec![line[..pos].trim(), line[pos + 1..].trim()]
    } else if let Some(pos) = line.find("..") {
        vec![line[..pos].trim(), line[pos + 2..].trim()]
    } else {
        let pos = line.find(" to ")?;
        vec![line[..pos].trim(), line[pos + 4..].trim()]
    };

    if parts.len() != 2 {
        return None;
    }
    let start: Ipv4Addr = parts[0].parse().ok()?;
    let end: Ipv4Addr = parts[1].parse().ok()?;
    Some(IpRangeEntry {
        start_ip: u32::from(start),
        end_ip: u32::from(end),
    })
}

pub(crate) async fn sync_blacklist(db: &DbPool, blacklist_id: i32) -> Result<()> {
    let entry = db::get_blacklist_by_id(db, blacklist_id).await?;
    let Some(entry) = entry else {
        anyhow::bail!("blacklist entry {blacklist_id} not found");
    };

    let entries = fetch_ip_ranges(&entry.url).await?;

    // Delete existing entries for this blacklist source.
    let deleted = db::delete_banned_ips_by_blacklist(db, blacklist_id).await?;
    log::info!("blacklist: deleted {deleted} old range(s) for id={blacklist_id}");

    let count = entries.len();
    for entry in entries {
        db::insert_banned_ip(
            db,
            entry.start_ip,
            entry.end_ip,
            None,
            None,
            Some(blacklist_id),
        )
        .await?;
    }

    // Update last_update timestamp.
    {
        let mut conn = db_pool::conn(db).await?;
        sqlx::query!(
            "UPDATE blacklist SET last_update = NOW() WHERE id = ?",
            blacklist_id
        )
        .execute(&mut *conn)
        .await?;
    }

    log::info!(
        "blacklist: synced {} range(s) for id={} url={}",
        count,
        blacklist_id,
        entry.url
    );

    Ok(())
}

/// Syncs all blacklist entries whose interval has elapsed.
pub(crate) async fn sync_all(db: &DbPool) -> Result<()> {
    let entries = db::list_blacklist(db).await?;
    let now = now();

    let mut synced = 0u64;
    let mut failed = 0u64;

    for entry in entries {
        let should_sync = entry
            .last_update
            .is_none_or(|last| elapsed_seconds(now, last) >= entry.update_interval_seconds as i64);

        if !should_sync {
            continue;
        }

        log::info!("blacklist: syncing id={} url={}", entry.id, entry.url);
        if let Err(e) = sync_blacklist(db, entry.id).await {
            log::error!("blacklist: sync id={} failed: {e}", entry.id);
            failed += 1;
            continue;
        }

        synced += 1;
    }

    log::info!(
        "blacklist: sync complete — {} ok, {} failed",
        synced,
        failed
    );
    Ok(())
}
