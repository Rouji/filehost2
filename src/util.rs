use time::{OffsetDateTime, PrimitiveDateTime, format_description::well_known::Rfc3339};

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Truncates to at most `max` characters. VARCHAR(n) columns in
/// MySQL/MariaDB count characters, not bytes, and inserts longer than the
/// column fail after the upload has already been saved to disk — so
/// request-supplied strings are cut to the column widths in `crate::db`
/// before insert.
pub(crate) fn truncate_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

pub(crate) fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

pub(crate) fn parse_rfc3339(s: &str) -> Option<PrimitiveDateTime> {
    let odt = OffsetDateTime::parse(s, &Rfc3339).ok()?;
    Some(PrimitiveDateTime::new(odt.date(), odt.time()))
}

pub(crate) fn format_ts(ts: PrimitiveDateTime) -> String {
    ts.assume_utc().format(&Rfc3339).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_chars_keeps_short_strings() {
        assert_eq!(truncate_chars("abc", 5), "abc");
        assert_eq!(truncate_chars("", 3), "");
        assert_eq!(truncate_chars("abc", 0), "");
    }

    #[test]
    fn truncate_chars_cuts_at_max() {
        assert_eq!(truncate_chars("abcdef", 3), "abc");
        assert_eq!(truncate_chars("abcdef", 6), "abcdef");
    }

    #[test]
    fn truncate_chars_counts_chars_not_bytes() {
        // each of these chars is 3 bytes in UTF-8
        let s = "ほげふが";
        assert_eq!(truncate_chars(s, 2), "ほげ");
        assert_eq!(truncate_chars(s, 2).len(), 6);
        assert_eq!(truncate_chars(s, 100), s);
    }
}
