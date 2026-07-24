use anyhow::Result;
use futures_util::future::join_all;
use regex::Regex;
use time::PrimitiveDateTime;

use crate::db;
use crate::db_pool;
use crate::db_pool::DbPool;

static IP_RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:/(\d{1,2}))?").unwrap()
});

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

impl PartialEq for IpRangeEntry {
    fn eq(&self, other: &Self) -> bool {
        self.start_ip == other.start_ip && self.end_ip == other.end_ip
    }
}

impl std::fmt::Debug for IpRangeEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpRangeEntry")
            .field("start_ip", &self.start_ip)
            .field("end_ip", &self.end_ip)
            .finish()
    }
}

/// fetches a blacklist URL and parses IP ranges from the response body.
/// Works on plain text, JSON, RSS — uses regex to extract IP patterns.
pub(crate) async fn fetch_ip_ranges(url: &str) -> Result<Vec<IpRangeEntry>> {
    let body = reqwest::get(url).await?.text().await?;
    Ok(parse_body(&body))
}

pub(crate) fn parse_body(body: &str) -> Vec<IpRangeEntry> {
    let mut entries = Vec::new();
    for cap in IP_RE.captures_iter(body) {
        let start: std::net::Ipv4Addr = match cap[1].parse() {
            Ok(ip) => ip,
            Err(_) => continue,
        };
        let start_u32 = u32::from(start);

        let end = if let Some(prefix_str) = cap.get(2) {
            let prefix: u8 = match prefix_str.as_str().parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            if prefix > 32 {
                continue;
            }
            let mask = if prefix == 0 {
                0u32
            } else {
                !0u32 << (32 - prefix)
            };
            start_u32 | !mask
        } else {
            start_u32
        };

        entries.push(IpRangeEntry {
            start_ip: start_u32,
            end_ip: end,
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
            entry.start_ip,
            entry.end_ip,
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
    let now = now();

    let to_sync: Vec<_> = entries
        .into_iter()
        .filter(|e| {
            e.last_update
                .is_none_or(|last| elapsed_seconds(now, last) >= e.update_interval_seconds as i64)
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

    fn ip(s: &str) -> u32 {
        s.parse::<std::net::Ipv4Addr>().unwrap().into()
    }

    macro_rules! test_parse {
        ($($name:ident: $input:expr => ($start:expr, $end:expr);)*) => {
            $(
                #[test]
                fn $name() {
                    let input = $input;
                    let entries = parse_body(input);
                    assert_eq!(entries.len(), 1, "{input}");
                    assert_eq!(entries[0].start_ip, $start, "{input}");
                    assert_eq!(entries[0].end_ip, $end, "{input}");
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
        cidr_0: "0.0.0.0/0" => (0, 0xffff_ffff);
        cidr_20: "192.168.16.0/20" => (ip("192.168.16.0"), ip("192.168.31.255"));
        cidr_27: "172.16.5.32/27" => (ip("172.16.5.32"), ip("172.16.5.63"));
        cidr_comment: "217.60.250.0/24 ; SBL694808" => (ip("217.60.250.0"), ip("217.60.250.255"));
    }

    #[test]
    fn multiple_entries() {
        let entries = parse_body("10.0.0.1\n192.168.1.100\n172.16.0.0/16");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].start_ip, ip("10.0.0.1"));
        assert_eq!(entries[0].end_ip, ip("10.0.0.1"));
        assert_eq!(entries[1].start_ip, ip("192.168.1.100"));
        assert_eq!(entries[1].end_ip, ip("192.168.1.100"));
        assert_eq!(entries[2].start_ip, ip("172.16.0.0"));
        assert_eq!(entries[2].end_ip, ip("172.16.255.255"));
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
        assert_eq!(entries[0].start_ip, ip("10.0.0.1"));
        assert_eq!(entries[0].end_ip, ip("10.0.0.1"));
    }

    #[test]
    fn rss() {
        let body = r#"<item><ip>10.0.0.0/24</ip><note>SBL</note></item>"#;
        let entries = parse_body(body);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].start_ip, ip("10.0.0.0"));
        assert_eq!(entries[0].end_ip, ip("10.0.0.255"));
    }

    #[test]
    fn invalid_ip_skipped() {
        let entries = parse_body("999.0.0.1\n10.0.0.1");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].start_ip, ip("10.0.0.1"));
        assert_eq!(entries[0].end_ip, ip("10.0.0.1"));
    }

    #[test]
    fn cidr_prefix_too_large() {
        let entries = parse_body("10.0.0.0/33");
        assert!(entries.is_empty());
    }
}
