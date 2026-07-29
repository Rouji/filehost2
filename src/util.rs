use time::{OffsetDateTime, PrimitiveDateTime, format_description::well_known::Rfc3339};

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
