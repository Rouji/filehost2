use std::net::{IpAddr, Ipv4Addr};

use anyhow::Result;
use futures_util::future::join_all;
use regex::Regex;
use time::PrimitiveDateTime;

use crate::db;
use crate::db_pool;
use crate::db_pool::DbPool;

// TODO: ipv6
static IP_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:/(\d{1,2}))?").unwrap()
});

fn seconds_since(last: PrimitiveDateTime) -> i64 {
    (time::OffsetDateTime::now_utc() - last.assume_utc()).whole_seconds()
}

#[derive(Debug, PartialEq)]
pub(crate) struct IpRangeEntry {
    pub start: IpAddr,
    pub end: IpAddr,
}

/// fetches a blacklist URL and parses IP ranges from the response body.
/// Works on plain text, JSON, RSS — uses regex to extract IP patterns.
pub(crate) async fn fetch_ip_ranges(url: &str) -> Result<Vec<IpRangeEntry>> {
    let body = reqwest::get(url).await?.text().await?;
    Ok(parse_body(&body))
}

/// The first and last address of the `/prefix` CIDR block containing `addr`: host bits
/// cleared for the first address, set for the last, so a non-aligned `addr` (e.g.
/// `10.0.0.5/24`) is normalized down to its block's actual range. `prefix` must be 0..=32.
fn cidr_range(addr: u32, prefix: u8) -> (u32, u32) {
    let host_bit_count = 32 - u32::from(prefix);
    // A full 32-bit shift panics in Rust, so /0 (every bit is a host bit) is its own case.
    let host_mask = if host_bit_count == 32 {
        u32::MAX
    } else {
        !(u32::MAX << host_bit_count)
    };
    let network_mask = !host_mask;
    (addr & network_mask, addr | host_mask)
}

pub(crate) fn parse_body(body: &str) -> Vec<IpRangeEntry> {
    let mut entries = Vec::new();
    for cap in IP_RE.captures_iter(body) {
        let addr: Ipv4Addr = match cap[1].parse() {
            Ok(ip) => ip,
            Err(_) => continue,
        };
        let addr_u32 = u32::from(addr);

        let (start, end) = if let Some(prefix_str) = cap.get(2) {
            let prefix: u8 = match prefix_str.as_str().parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            if prefix > 32 {
                continue;
            }
            cidr_range(addr_u32, prefix)
        } else {
            (addr_u32, addr_u32)
        };

        entries.push(IpRangeEntry {
            start: IpAddr::V4(Ipv4Addr::from(start)),
            end: IpAddr::V4(Ipv4Addr::from(end)),
        });
    }
    entries
}

pub(crate) async fn sync_blacklist(db: DbPool, blacklist_id: i32) -> Result<()> {
    let bl_entry = db::get_blacklist_by_id(&db, blacklist_id).await?;
    let Some(bl_entry) = bl_entry else {
        anyhow::bail!("blacklist entry {blacklist_id} not found");
    };

    let entries = fetch_ip_ranges(&bl_entry.url).await?;

    // Delete existing entries for this blacklist source.
    let deleted = db::delete_banned_ips_by_blacklist(&db, blacklist_id).await?;
    log::info!("blacklist: deleted {deleted} old range(s) for id={blacklist_id}");

    let ban_type = bl_entry.type_;
    let count = entries.len();
    for entry in entries {
        db::insert_banned_ip(
            &db,
            entry.start,
            entry.end,
            None,
            None,
            Some(blacklist_id),
            ban_type,
        )
        .await?;
    }

    // Update last_update timestamp.
    {
        let mut conn = db_pool::conn(&db).await?;
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
        bl_entry.url
    );

    Ok(())
}

/// Syncs all blacklist entries whose interval has elapsed.
pub(crate) async fn sync_all(db: &DbPool) -> Result<()> {
    let entries = db::list_blacklist(db).await?;

    let to_sync: Vec<_> = entries
        .into_iter()
        .filter(|e| {
            e.last_update
                .is_none_or(|last| seconds_since(last) >= e.update_interval_seconds as i64)
        })
        .map(|e| (e.id, e.url))
        .collect();

    if to_sync.is_empty() {
        return Ok(());
    }

    let mut tasks = Vec::new();
    for (id, url) in to_sync {
        log::info!("blacklist: syncing id={id} url={url}");
        tasks.push(sync_blacklist(db.clone(), id));
    }

    let results = join_all(tasks).await;

    let mut synced = 0u64;
    let mut failed = 0u64;
    for result in results {
        match result {
            Ok(()) => synced += 1,
            Err(e) => {
                log::error!("blacklist: sync failed: {e}");
                failed += 1;
            }
        }
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
    use crate::sync::parse_body;

    fn ip(s: &str) -> std::net::IpAddr {
        s.parse().unwrap()
    }

    macro_rules! test_parse {
        ($($name:ident: $input:expr => ($start:expr, $end:expr);)*) => {
            $(
                #[test]
                fn $name() {
                    let input = $input;
                    let entries = parse_body(input);
                    assert_eq!(entries.len(), 1, "{input}");
                    assert_eq!(entries[0].start, $start, "{input}");
                    assert_eq!(entries[0].end, $end, "{input}");
                }
            )*
        };
    }

    test_parse! {
        single_ip: "1.2.3.4" => (ip("1.2.3.4"), ip("1.2.3.4"));
        single_ip_ws: "  10.0.0.1  " => (ip("10.0.0.1"), ip("10.0.0.1"));
        cidr_24: "10.0.0.0/24" => (ip("10.0.0.0"), ip("10.0.0.255"));
        cidr_16: "172.16.0.0/16" => (ip("172.16.0.0"), ip("172.16.255.255"));
        cidr_8: "10.0.0.0/8" => (ip("10.0.0.0"), ip("10.255.255.255"));
        cidr_32: "192.168.1.1/32" => (ip("192.168.1.1"), ip("192.168.1.1"));
        cidr_0: "0.0.0.0/0" => (ip("0.0.0.0"), ip("255.255.255.255"));
        cidr_20: "192.168.16.0/20" => (ip("192.168.16.0"), ip("192.168.31.255"));
        cidr_27: "172.16.5.32/27" => (ip("172.16.5.32"), ip("172.16.5.63"));
        cidr_comment: "217.60.250.0/24 ; SBL694808" => (ip("217.60.250.0"), ip("217.60.250.255"));
        cidr_non_aligned_host_address: "10.0.0.5/24" => (ip("10.0.0.0"), ip("10.0.0.255"));
    }

    #[test]
    fn multiple_entries() {
        let entries = parse_body("10.0.0.1\n192.168.1.100\n172.16.0.0/16");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].start, ip("10.0.0.1"));
        assert_eq!(entries[0].end, ip("10.0.0.1"));
        assert_eq!(entries[1].start, ip("192.168.1.100"));
        assert_eq!(entries[1].end, ip("192.168.1.100"));
        assert_eq!(entries[2].start, ip("172.16.0.0"));
        assert_eq!(entries[2].end, ip("172.16.255.255"));
    }

    #[test]
    fn multiline() {
        let entries = parse_body("10.0.0.1\n10.0.0.2\n10.0.0.3\n");
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn empty_body() {
        assert!(parse_body("").is_empty());
    }

    #[test]
    fn json() {
        let body = r#"{"ip":"10.0.0.1","reason":"spam"}"#;
        let entries = parse_body(body);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].start, ip("10.0.0.1"));
        assert_eq!(entries[0].end, ip("10.0.0.1"));
    }

    #[test]
    fn rss() {
        let body = r#"<item><ip>10.0.0.0/24</ip><note>SBL</note></item>"#;
        let entries = parse_body(body);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].start, ip("10.0.0.0"));
        assert_eq!(entries[0].end, ip("10.0.0.255"));
    }

    #[test]
    fn invalid_ip_skipped() {
        let entries = parse_body("999.0.0.1\n10.0.0.1");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].start, ip("10.0.0.1"));
        assert_eq!(entries[0].end, ip("10.0.0.1"));
    }

    #[test]
    fn cidr_prefix_too_large() {
        let entries = parse_body("10.0.0.0/33");
        assert!(entries.is_empty());
    }
}
