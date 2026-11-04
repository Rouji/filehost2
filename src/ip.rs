use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(crate) fn to_db_bytes(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

///`None` if `bytes` isn't exactly 16 bytes long
pub(crate) fn from_db_bytes(bytes: &[u8]) -> Option<IpAddr> {
    let octets: [u8; 16] = bytes.try_into().ok()?;
    let v6 = Ipv6Addr::from(octets);
    Some(match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    })
}

pub(crate) fn same_family(a: IpAddr, b: IpAddr) -> bool {
    matches!(
        (a, b),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

/// returns the /64 net address, for quota purposes
pub(crate) fn normalize_for_quota(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
    }
}

/// for use in sql "BETWEEN ? AND ?"
pub(crate) fn quota_range(ip: IpAddr) -> (IpAddr, IpAddr) {
    match ip {
        IpAddr::V4(_) => (ip, ip),
        IpAddr::V6(v6) => {
            let start = normalize_for_quota(ip);
            let mut octets = v6.octets();
            octets[8..].fill(0xff);
            (start, IpAddr::V6(Ipv6Addr::from(octets)))
        }
    }
}

/// First and last address of the `/prefix` block containing `addr`, where `addr` is a
/// `width`-bit address (32 for v4, 128 for v6) carried in the low bits of a u128.
/// `None` if `prefix` is wider than the address family allows.
pub(crate) fn cidr_bounds(addr: u128, prefix: u8, width: u8) -> Option<(u128, u128)> {
    if prefix > width {
        return None;
    }
    let host_bit_count = u32::from(width - prefix);
    // A full 128-bit shift overflows u128, so /0 (every bit is a host bit) is its own case.
    let host_mask = if host_bit_count == 128 {
        u128::MAX
    } else {
        (1u128 << host_bit_count) - 1
    };
    Some((addr & !host_mask, addr | host_mask))
}

/// A CIDR block (`10.0.0.0/8`, `2001:db8::/32`) or a single address (`10.0.0.1`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cidr {
    start: IpAddr,
    end: IpAddr,
}

impl Cidr {
    /// A bare address is treated as a /32 (v4) or /128 (v6).
    pub(crate) fn parse(s: &str) -> Option<Self> {
        let (addr_part, prefix_part) = match s.trim().split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (s, None),
        };
        let addr: IpAddr = addr_part.trim().parse().ok()?;
        let prefix: Option<u8> = match prefix_part {
            Some(p) => Some(p.trim().parse().ok()?),
            None => None,
        };
        let (start, end) = match addr {
            IpAddr::V4(v4) => {
                let (start, end) =
                    cidr_bounds(u128::from(u32::from(v4)), prefix.unwrap_or(32), 32)?;
                (
                    IpAddr::V4(Ipv4Addr::from(u32::try_from(start).ok()?)),
                    IpAddr::V4(Ipv4Addr::from(u32::try_from(end).ok()?)),
                )
            }
            IpAddr::V6(v6) => {
                let (start, end) = cidr_bounds(u128::from(v6), prefix.unwrap_or(128), 128)?;
                (
                    IpAddr::V6(Ipv6Addr::from(start)),
                    IpAddr::V6(Ipv6Addr::from(end)),
                )
            }
        };
        Some(Self { start, end })
    }

    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        // Compared in the 16-byte mapped form, so the two families can't overlap: a v4
        // address maps into ::ffff:0:0/96 and never lands inside a v6-only block.
        let ip = to_db_bytes(ip);
        to_db_bytes(self.start) <= ip && ip <= to_db_bytes(self.end)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct XffTrust {
    /// peers allowed to speak for a client. Empty means "trust no header".
    proxies: Vec<Cidr>,
    /// Trusted proxies between us and the client, counting the socket peer. The client is
    /// the header entry that many places from the right; 1 is a single reverse proxy.
    hops: usize,
}

impl XffTrust {
    pub(crate) fn untrusted() -> Self {
        Self {
            proxies: Vec::new(),
            hops: 1,
        }
    }

    pub(crate) fn new(proxies: Option<&str>, hops: usize) -> (Self, Vec<String>) {
        let mut parsed = Vec::new();
        let mut invalid = Vec::new();
        for entry in proxies.unwrap_or("").split(',') {
            if entry.trim().is_empty() {
                continue;
            }
            match Cidr::parse(entry) {
                Some(cidr) => parsed.push(cidr),
                _ => invalid.push(entry.trim().to_string()),
            }
        }
        (
            Self {
                proxies: parsed,
                hops: hops.max(1),
            },
            invalid,
        )
    }

    pub(crate) fn trusts_peer(&self, peer: IpAddr) -> bool {
        self.proxies.iter().any(|cidr| cidr.contains(peer))
    }

    pub(crate) fn proxy_count(&self) -> usize {
        self.proxies.len()
    }
}

pub(crate) fn client_ip(
    xff: Option<&str>,
    peer: Option<IpAddr>,
    trust: &XffTrust,
) -> Option<IpAddr> {
    if let (Some(header), Some(peer_addr)) = (xff, peer)
        && trust.trusts_peer(peer_addr)
    {
        let entries: Vec<&str> = header
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .collect();
        match entries.len().checked_sub(trust.hops) {
            // Fewer entries than trusted hops: the chain doesn't reach a client
            // address, so the header can't vouch for anything.
            _ => log::warn!(
                "X-Forwarded-For {header:?} has fewer entries than the {} configured hop(s); \
                 falling back to peer {peer_addr}",
                trust.hops
            ),
            Some(index) => match entries[index].parse::<IpAddr>() {
                Ok(ip) => return Some(ip),
                Err(e) => log::warn!(
                    "unparsable X-Forwarded-For entry {:?} ({e}); falling back to peer {peer_addr}",
                    entries[index]
                ),
            },
        }
    }
    peer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_roundtrips_through_mapped_bytes() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let bytes = to_db_bytes(ip);
        assert_eq!(
            bytes,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4]
        );
        assert_eq!(from_db_bytes(&bytes), Some(ip));
    }

    #[test]
    fn v4_mapped_bytes_preserve_u32_ordering() {
        let a = to_db_bytes("1.2.3.4".parse().unwrap());
        let b = to_db_bytes("1.2.3.5".parse().unwrap());
        assert!(a < b);
    }

    #[test]
    fn v6_roundtrips() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let bytes = to_db_bytes(ip);
        assert_eq!(from_db_bytes(&bytes), Some(ip));
    }

    #[test]
    fn from_db_bytes_rejects_wrong_length() {
        assert_eq!(from_db_bytes(&[1, 2, 3, 4]), None);
    }

    #[test]
    fn same_family_checks() {
        let v4: IpAddr = "1.2.3.4".parse().unwrap();
        let v4b: IpAddr = "5.6.7.8".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(same_family(v4, v4b));
        assert!(same_family(v6, v6));
        assert!(!same_family(v4, v6));
    }

    #[test]
    fn normalize_for_quota_leaves_v4_untouched() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(normalize_for_quota(ip), ip);
    }

    #[test]
    fn normalize_for_quota_zeroes_v6_low_64_bits() {
        let a: IpAddr = "2001:db8:1234:5678:aaaa:bbbb:cccc:dddd".parse().unwrap();
        let b: IpAddr = "2001:db8:1234:5678:1111:2222:3333:4444".parse().unwrap();
        assert_eq!(normalize_for_quota(a), normalize_for_quota(b));
        assert_eq!(
            normalize_for_quota(a),
            "2001:db8:1234:5678::".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn normalize_for_quota_distinguishes_different_prefixes() {
        let a: IpAddr = "2001:db8:1234:5678::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1234:9999::1".parse().unwrap();
        assert_ne!(normalize_for_quota(a), normalize_for_quota(b));
    }

    #[test]
    fn quota_range_v4_is_exact() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(quota_range(ip), (ip, ip));
    }

    #[test]
    fn quota_range_v6_covers_whole_64_and_only_that() {
        let ip: IpAddr = "2001:db8:1234:5678:aaaa::1".parse().unwrap();
        let (start, end) = quota_range(ip);
        assert_eq!(start, "2001:db8:1234:5678::".parse::<IpAddr>().unwrap());
        assert_eq!(
            end,
            "2001:db8:1234:5678:ffff:ffff:ffff:ffff"
                .parse::<IpAddr>()
                .unwrap()
        );
        let in_range: IpAddr = "2001:db8:1234:5678:ffff::1".parse().unwrap();
        let out_of_range: IpAddr = "2001:db8:1234:5679::1".parse().unwrap();
        assert!(
            to_db_bytes(start) <= to_db_bytes(in_range)
                && to_db_bytes(in_range) <= to_db_bytes(end)
        );
        assert!(to_db_bytes(out_of_range) > to_db_bytes(end));
    }

    #[test]
    fn cidr_parse_bare_address_is_host_sized() {
        let v4 = Cidr::parse("10.0.0.1").unwrap();
        assert!(v4.contains("10.0.0.1".parse().unwrap()));
        assert!(!v4.contains("10.0.0.2".parse().unwrap()));

        let v6 = Cidr::parse("2001:db8::1").unwrap();
        assert!(v6.contains("2001:db8::1".parse().unwrap()));
        assert!(!v6.contains("2001:db8::2".parse().unwrap()));
    }

    #[test]
    fn cidr_parse_blocks() {
        let block = Cidr::parse("10.0.0.0/24").unwrap();
        assert!(block.contains("10.0.0.0".parse().unwrap()));
        assert!(block.contains("10.0.0.255".parse().unwrap()));
        assert!(!block.contains("10.0.1.0".parse().unwrap()));

        let v6 = Cidr::parse("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:0db8:ffff::1".parse().unwrap()));
        assert!(!v6.contains("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn cidr_parse_tolerates_whitespace_and_normalizes_non_aligned() {
        assert_eq!(
            Cidr::parse("  10.0.0.0/24  ").unwrap().start,
            "10.0.0.0".parse::<IpAddr>().unwrap()
        );
        // a non-aligned base is still the block it sits in, not a /32 with a stray prefix
        let block = Cidr::parse("10.0.0.5/24").unwrap();
        assert!(block.contains("10.0.0.9".parse().unwrap()));
        assert!(!block.contains("10.0.1.5".parse().unwrap()));
    }

    #[test]
    fn cidr_parse_rejects_garbage() {
        assert!(Cidr::parse("").is_none());
        assert!(Cidr::parse("not an ip").is_none());
        assert!(Cidr::parse("10.0.0.0/33").is_none());
        assert!(Cidr::parse("10.0.0.0/-1").is_none());
        assert!(Cidr::parse("2001:db8::/129").is_none());
    }

    #[test]
    fn cidr_never_crosses_families() {
        let v4_only = Cidr::parse("0.0.0.0/0").unwrap();
        assert!(v4_only.contains("8.8.8.8".parse().unwrap()));
        assert!(!v4_only.contains("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn xff_trust_reports_invalid_entries_instead_of_trusting_everything() {
        let (trust, invalid) = XffTrust::new(Some("10.0.0.1, bogus , 192.168.0.0/16"), 1);
        assert_eq!(invalid, vec!["bogus".to_string()]);
        assert_eq!(trust.proxy_count(), 2);
        assert!(trust.trusts_peer("10.0.0.1".parse().unwrap()));
        assert!(trust.trusts_peer("192.168.1.7".parse().unwrap()));
        assert!(!trust.trusts_peer("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn xff_trust_with_no_proxies_trusts_no_peer() {
        let (trust, _) = XffTrust::new(None, 1);
        assert_eq!(trust.proxy_count(), 0);
        assert!(!trust.trusts_peer("127.0.0.1".parse().unwrap()));
    }

    /// Pure `client_ip` cases, for the header arithmetic; the handler tests cover the rest.
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn assert_client(xff: Option<&str>, peer: IpAddr, proxies: &str, hops: usize, want: IpAddr) {
        let (trust, _) = XffTrust::new(Some(proxies), hops);
        assert_eq!(client_ip(xff, Some(peer), &trust), Some(want));
    }

    #[test]
    fn client_prefers_header_from_trusted_proxy() {
        assert_client(
            Some("203.0.113.7"),
            ip("127.0.0.1"),
            "127.0.0.1",
            1,
            ip("203.0.113.7"),
        );
    }

    #[test]
    fn client_ignores_header_from_untrusted_peer() {
        // the whole point of the allowlist: a client that spoofs the header keeps the
        // identity its socket address gives it, not the one it asks for
        assert_client(
            Some("203.0.113.7"),
            ip("198.51.100.7"),
            "127.0.0.1",
            1,
            ip("198.51.100.7"),
        );
    }

    #[test]
    fn client_reads_right_to_left_so_prepended_entry_cannot_vouch() {
        // one trusted hop: it appended the address that connected to it, so everything to
        // the left of that is what the client typed itself and can't vouch for anyone
        assert_client(
            Some("8.8.8.8, 203.0.113.7"),
            ip("127.0.0.1"),
            "127.0.0.1",
            1,
            ip("203.0.113.7"),
        );
        // two hops means the rightmost entry is a proxy, so the client is index 0 — a longer
        // chain never mistakes a proxy's own address for the client's
        assert_client(
            Some("203.0.113.7, 10.0.0.2"),
            ip("10.0.0.1"),
            "10.0.0.0/8",
            2,
            ip("203.0.113.7"),
        );
    }

    #[test]
    fn client_falls_back_to_peer_when_header_is_unusable() {
        // missing
        assert_client(None, ip("198.51.100.7"), "127.0.0.1", 1, ip("198.51.100.7"));
        // empty
        assert_client(
            Some(""),
            ip("198.51.100.7"),
            "127.0.0.1",
            1,
            ip("198.51.100.7"),
        );
        // unparsable at the position we'd use
        assert_client(
            Some("not-an-ip"),
            ip("198.51.100.7"),
            "127.0.0.1",
            1,
            ip("198.51.100.7"),
        );
        // too short for the configured chain: can't vouch for anything
        assert_client(
            Some("203.0.113.7"),
            ip("10.0.0.1"),
            "10.0.0.0/8",
            2,
            ip("10.0.0.1"),
        );
    }

    #[test]
    fn client_falls_back_to_peer_when_no_proxies_configured() {
        let (trust, _) = XffTrust::new(None, 1);
        assert_eq!(
            client_ip(None, Some(ip("198.51.100.7")), &trust),
            Some(ip("198.51.100.7"))
        );
        assert_eq!(
            client_ip(Some("203.0.113.7"), Some(ip("198.51.100.7")), &trust),
            Some(ip("198.51.100.7"))
        );
    }

    #[test]
    fn client_is_none_only_without_any_peer() {
        let (trust, _) = XffTrust::new(Some("127.0.0.1"), 1);
        assert_eq!(client_ip(Some("203.0.113.7"), None, &trust), None);
        assert_eq!(client_ip(None, None, &trust), None);
    }
}
