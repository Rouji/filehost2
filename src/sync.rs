use std::net::Ipv4Addr;

use anyhow::Result;
use time::PrimitiveDateTime;

use crate::db;
use crate::db_pool;
use crate::db_pool::DbPool;

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

pub(crate) fn parse_line(line: &str) -> Option<IpRangeEntry> {
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

pub(crate) fn parse_cidr(line: &str) -> Option<IpRangeEntry> {
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

pub(crate) fn parse_range(line: &str) -> Option<IpRangeEntry> {
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

#[cfg(test)]
mod tests {
    use crate::sync::{parse_cidr, parse_line, parse_range};

    fn ip(s: &str) -> u32 {
        s.parse::<std::net::Ipv4Addr>().unwrap().into()
    }

    macro_rules! test_parse {
        ($($name:ident: $fn:ident, $input:expr => ($start:expr, $end:expr);)*) => {
            $(
                #[test]
                fn $name() {
                    let input = $input;
                    let entry = $fn(input).unwrap();
                    assert_eq!(entry.start_ip, $start, "{input}");
                    assert_eq!(entry.end_ip, $end, "{input}");
                }
            )*
        };
    }

    test_parse! {
        single_ip: parse_line, "1.2.3.4" => (ip("1.2.3.4"), ip("1.2.3.4"));
        single_ip_ws: parse_line, "  10.0.0.1  " => (ip("10.0.0.1"), ip("10.0.0.1"));
        cidr_24: parse_cidr, "10.0.0.0/24" => (ip("10.0.0.0"), ip("10.0.0.255"));
        cidr_16: parse_cidr, "172.16.0.0/16" => (ip("172.16.0.0"), ip("172.16.255.255"));
        cidr_8: parse_cidr, "10.0.0.0/8" => (ip("10.0.0.0"), ip("10.255.255.255"));
        cidr_32: parse_cidr, "192.168.1.1/32" => (ip("192.168.1.1"), ip("192.168.1.1"));
        cidr_0: parse_cidr, "0.0.0.0/0" => (0, 0xffff_ffff);
        cidr_20: parse_cidr, "192.168.16.0/20" => (ip("192.168.16.0"), ip("192.168.31.255"));
        cidr_27: parse_cidr, "172.16.5.32/27" => (ip("172.16.5.32"), ip("172.16.5.63"));
        range_hyphen: parse_range, "192.168.1.1 - 192.168.1.100" => (ip("192.168.1.1"), ip("192.168.1.100"));
        range_no_spaces: parse_range, "192.168.1.1-192.168.1.100" => (ip("192.168.1.1"), ip("192.168.1.100"));
        range_dots: parse_range, "10.0.0.1..10.0.0.50" => (ip("10.0.0.1"), ip("10.0.0.50"));
        range_to: parse_range, "172.16.0.1 to 172.16.255.254" => (ip("172.16.0.1"), ip("172.16.255.254"));
        range_single: parse_range, "10.0.0.5-10.0.0.5" => (ip("10.0.0.5"), ip("10.0.0.5"));
        cidr_via_line: parse_line, "10.0.0.0/24" => (ip("10.0.0.0"), ip("10.0.0.255"));
        single_via_line: parse_line, "10.0.0.1" => (ip("10.0.0.1"), ip("10.0.0.1"));
    }

    macro_rules! test_none {
        ($($name:ident: $fn:ident, $input:expr;)*) => {
            $(
                #[test]
                fn $name() {
                    let input = $input;
                    assert!($fn(input).is_none(), "expected none for: {input}");
                }
            )*
        };
    }

    test_none! {
        cidr_no_prefix: parse_cidr, "10.0.0.0";
        cidr_invalid_prefix: parse_cidr, "10.0.0.0/33";
        cidr_invalid_ip: parse_cidr, "999.0.0.0/24";
        range_invalid_end: parse_range, "10.0.0.1 - 999.0.0.1";
        range_no_sep: parse_range, "10.0.0.1 10.0.0.2";
        comment: parse_line, "# comment";
        empty: parse_line, "";
        whitespace: parse_line, "   ";
        garbage: parse_line, "not an ip";
    }
}
