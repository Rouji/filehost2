//! Loads the iptoasn.com IP-to-ASN mapping into the `ip_asn` table, which
//! backs the per-ASN abuse-detection queries. Data is public domain
//! (PDDL 1.0), no attribution or key required.
//!
//! Data shape: `ip2asn-combined.tsv.gz`, tab-separated, one range per line:
//! `range_start\trange_end\tAS_number\tcountry_code\tAS_description`.
//! Within each family the ranges are sorted and non-overlapping, which is
//! what makes the "greatest start_ip <= target" point lookup valid.
//!
//! Run via `filehost2 asn-sync` (cron-driven, one-shot like `rehash`).

use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::sync::LazyLock;

use anyhow::{Context, Result};
use flate2::read::GzDecoder;

use crate::db;
use crate::db_pool::DbPool;
use crate::ip;

const IPTOASN_URL: &str = "https://iptoasn.com/data/ip2asn-combined.tsv.gz";

/// One bind set per column; 5 * 1000 stays well under `max_allowed_packet`
/// (mirrors `insert_banned_ip_batch`'s chunking).
pub(crate) const ROWS_PER_STATEMENT: usize = 1000;

/// Bounds of the IPv4-mapped block as native-v6 addresses. A native-v6 range
/// overlapping it would corrupt the merged 16-byte point-lookup space (a
/// v4-mapped target could resolve to a v6 range instead of its v4 range).
/// iptoasn currently has no such ranges, but filter defensively.
static MAPPED_V4_LO: LazyLock<IpAddr> = LazyLock::new(|| "::ffff:0.0.0.0".parse().unwrap());
static MAPPED_V4_HI: LazyLock<IpAddr> = LazyLock::new(|| "::ffff:255.255.255.255".parse().unwrap());

/// One parsed TSV row, IPs already in DB byte order.
pub(crate) struct AsnRange {
    pub(crate) start: [u8; 16],
    pub(crate) end: [u8; 16],
    pub(crate) asn: u32,
    pub(crate) country: String,
    pub(crate) org: String,
}

/// Parses one TSV line. The description may contain spaces, so split on tabs
/// only. `asn=0` "Not routed" rows are deliberately kept: dropping them would
/// make unmapped IPs silently inherit the neighbouring ASN.
fn parse_line(line: &str) -> Option<AsnRange> {
    let mut fields = line.splitn(5, '\t');
    let start: IpAddr = fields.next()?.trim().parse().ok()?;
    let end: IpAddr = fields.next()?.trim().parse().ok()?;
    let asn: u32 = fields.next()?.trim().parse().ok()?;
    let country = fields.next()?.trim().to_string();
    let org = fields.next()?.trim().to_string();
    if org.is_empty() || !same_family(start, end) || end < start {
        return None;
    }
    // Only native-v6 ranges can overlap the mapped-v4 block; v4 rows live
    // inside it by construction, and a range whose *both* endpoints are
    // ::ffff:-mapped is just a v4 range in v6 clothing — keep those.
    if start.is_ipv6()
        && !(is_mapped_v4(start) && is_mapped_v4(end))
        && overlaps_mapped_v4(start, end)
    {
        log::warn!("asn: skipping v6 range overlapping mapped-v4 block: {start} - {end}");
        return None;
    }
    Some(AsnRange {
        start: ip::to_db_bytes(start),
        end: ip::to_db_bytes(end),
        asn,
        // CHAR(2) column; iptoasn writes "None" for not-routed rows, and asn=0
        // already marks those, so fold anything that isn't a 2-char code to "".
        country: if country.chars().count() == 2 {
            country
        } else {
            String::new()
        },
        org,
    })
}

fn same_family(a: IpAddr, b: IpAddr) -> bool {
    a.is_ipv4() == b.is_ipv4()
}

fn is_mapped_v4(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().is_some(),
        IpAddr::V4(_) => false,
    }
}

fn overlaps_mapped_v4(start: IpAddr, end: IpAddr) -> bool {
    start <= *MAPPED_V4_HI && end >= *MAPPED_V4_LO
}

/// Parses the (possibly gzipped) body. Rejects an empty result so a bad
/// download can never blank the table.
pub(crate) fn parse_body(body: &[u8]) -> Result<Vec<AsnRange>> {
    let gzipped = body.starts_with(&[0x1f, 0x8b]);
    let mut reader: Box<dyn BufRead> = if gzipped {
        Box::new(BufReader::new(GzDecoder::new(body)))
    } else {
        Box::new(BufReader::new(body))
    };
    let mut out = Vec::with_capacity(720_000);
    let mut line = String::new();
    while reader.read_line(&mut line)? > 0 {
        let trimmed = line.trim_end_matches(['\n', '\r']);
        if !trimmed.is_empty()
            && let Some(r) = parse_line(trimmed)
        {
            out.push(r);
        }
        line.clear();
    }
    anyhow::ensure!(
        !out.is_empty(),
        "parsed 0 ranges — refusing to replace ip_asn"
    );
    Ok(out)
}

async fn download() -> Result<Vec<u8>> {
    let resp = reqwest::get(IPTOASN_URL).await?;
    anyhow::ensure!(
        resp.status().is_success(),
        "iptoasn download failed: HTTP {}",
        resp.status()
    );
    Ok(resp.bytes().await?.to_vec())
}

/// Fetches (or reads from `path`) and replaces the `ip_asn` table contents.
pub(crate) async fn sync_asn(db: &DbPool, path: Option<&str>) -> Result<usize> {
    let body = match path {
        Some(p) => std::fs::read(p).with_context(|| format!("read {p}"))?,
        None => download().await?,
    };
    let ranges = parse_body(&body)?;
    log::info!(
        "asn: parsed {} ranges from {}",
        ranges.len(),
        path.unwrap_or(IPTOASN_URL)
    );
    let count = db::replace_ip_asn(db, &ranges).await?;
    log::info!("asn: replaced ip_asn with {count} ranges");
    Ok(count)
}

#[cfg(test)]
pub(crate) fn gz_compress(plain: &[u8]) -> Vec<u8> {
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write as _;
    let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(plain).unwrap();
    enc.finish().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_range(s: &str, e: &str, asn: u32, country: &str, org: &str) -> String {
        format!("{s}\t{e}\t{asn}\t{country}\t{org}\n")
    }

    #[test]
    fn parse_line_happy_path() {
        let r = parse_line("1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET - Cloudflare, Inc.")
            .expect("should parse");
        assert_eq!(r.asn, 13335);
        assert_eq!(r.country, "US");
        assert_eq!(r.org, "CLOUDFLARENET - Cloudflare, Inc.");
        assert_eq!(r.start, ip::to_db_bytes("1.0.0.0".parse().unwrap()));
        assert_eq!(r.end, ip::to_db_bytes("1.0.0.255".parse().unwrap()));
    }

    #[test]
    fn parse_line_keeps_not_routed() {
        let r = parse_line("1.0.1.0\t1.0.3.255\t0\tNone\tNot routed").expect("should parse");
        assert_eq!(r.asn, 0);
    }

    #[test]
    fn parse_line_rejects_garbage() {
        assert!(parse_line("not-an-ip\t1.0.0.0\t1\tUS\torg").is_none());
        assert!(parse_line("1.0.0.0\t1.0.0.255\tUS\torg").is_none()); // missing asn
        assert!(parse_line("1.0.0.0\t1.0.0.255\t1\tUS").is_none()); // missing org
        assert!(parse_line("1.0.0.255\t1.0.0.0\t1\tUS\torg").is_none()); // end < start
        assert!(parse_line("1.0.0.0\t::1\t1\tUS\torg").is_none()); // mixed family
        assert!(parse_line("1.0.0.0\t1.0.0.255\t1\tUS\t").is_none()); // empty org
    }

    #[test]
    fn parse_line_keeps_v4_range_in_mapped_v6_form() {
        // Both endpoints ::ffff:-mapped = a v4 range in v6 clothing; keep it.
        let r = parse_line("::ffff:1.0.0.0\t::ffff:1.0.0.255\t1\tUS\torg").expect("should parse");
        assert_eq!(r.start, ip::to_db_bytes("1.0.0.0".parse().unwrap()));
    }

    #[test]
    fn parse_line_skips_native_v6_range_overlapping_mapped_v4() {
        // A native-v6 range spanning the mapped block would collide with every
        // stored v4 range in the merged 16-byte lookup space.
        let r = parse_line("::\t::ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff\t1\tUS\torg");
        assert!(r.is_none());
        // Mixed: starts mapped, extends into native v6 — also skipped.
        let r = parse_line("::ffff:1.0.0.0\t2001:db8::\t1\tUS\torg");
        assert!(r.is_none());
    }

    #[test]
    fn parse_line_keeps_normal_v6_range() {
        let r = parse_line("2001:db8::\t2001:db8:ffff:ffff:ffff:ffff:ffff:ffff\t1\tDE\torg")
            .expect("should parse");
        assert_eq!(r.start, ip::to_db_bytes("2001:db8::".parse().unwrap()));
    }

    #[test]
    fn parse_body_plain_and_gzipped() {
        let plain = v4_range("1.0.0.0", "1.0.0.255", 13335, "US", "Cloudflare")
            + &v4_range("1.0.1.0", "1.0.3.255", 0, "None", "Not routed");
        assert_eq!(parse_body(plain.as_bytes()).unwrap().len(), 2);

        let gz = gz_compress(plain.as_bytes());
        assert_eq!(parse_body(&gz).unwrap().len(), 2);
    }

    #[test]
    fn parse_body_rejects_empty() {
        assert!(parse_body(b"").is_err());
        assert!(parse_body(&gz_compress(b"")).is_err());
        assert!(parse_body(b"\n\n\n").is_err());
    }

    #[test]
    fn parse_body_skips_blank_lines() {
        let body = format!(
            "\n{}\n{}\n",
            v4_range("1.0.0.0", "1.0.0.255", 1, "US", "a"),
            v4_range("1.0.1.0", "1.0.1.255", 2, "US", "b")
        );
        assert_eq!(parse_body(body.as_bytes()).unwrap().len(), 2);
    }
}
