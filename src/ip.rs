use std::net::{IpAddr, Ipv6Addr};

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
}
