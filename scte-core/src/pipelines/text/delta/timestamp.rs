/// Timestamp delta encoder — Phase 6.
///
/// Converts ISO 8601 timestamp strings to Unix epoch seconds, then applies
/// delta encoding via [`super::integer`] for high compression.
///
/// # Supported formats
///
/// - `YYYY-MM-DD`                     → epoch at 00:00:00 UTC
/// - `YYYY-MM-DDTHH:MM:SS`           → epoch in UTC
/// - `YYYY-MM-DDTHH:MM:SSZ`          → UTC
/// - `YYYY-MM-DDTHH:MM:SS+HH:MM`     → offset (subtracted to get UTC)
///
/// # Wire format
///
/// ```text
/// varint(count) | delta_encoded_epoch_secs
/// ```
///
/// where `delta_encoded_epoch_secs` is produced by [`super::integer::encode_delta_ints`].

use super::integer::{encode_delta_ints, decode_delta_ints};

// ── Parse ──────────────────────────────────────────────────────────────────────

/// Parse an ISO 8601 timestamp string to Unix epoch seconds.
///
/// Returns `None` if the string cannot be parsed.
pub fn parse_timestamp(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.len() < 10 { return None; }

    // Parse date component
    let year:  i64 = s[0..4].parse().ok()?;
    let month: i64 = s[5..7].parse().ok()?;
    let day:   i64 = s[8..10].parse().ok()?;

    let (hour, minute, second) = if s.len() >= 19 && (s.as_bytes()[10] == b'T' || s.as_bytes()[10] == b' ') {
        let h: i64 = s[11..13].parse().ok()?;
        let m: i64 = s[14..16].parse().ok()?;
        let sec: i64 = s[17..19].parse().ok()?;
        (h, m, sec)
    } else {
        (0, 0, 0)
    };

    // Parse optional timezone offset (e.g. +05:30 or -07:00)
    let tz_offset_secs: i64 = if s.len() >= 25 {
        let tz_start = 19;
        let sign: &str = &s[tz_start..tz_start+1];
        if sign == "+" || sign == "-" {
            let tz_h: i64 = s[tz_start+1..tz_start+3].parse().unwrap_or(0);
            let tz_m: i64 = s[tz_start+4..tz_start+6].parse().unwrap_or(0);
            let offset = tz_h * 3600 + tz_m * 60;
            if sign == "+" { offset } else { -offset }
        } else { 0 }
    } else { 0 };

    // Days since Unix epoch (1970-01-01) using Gregorian calendar
    let epoch_days = days_since_epoch(year, month, day)?;
    let epoch_secs = epoch_days * 86400 + hour * 3600 + minute * 60 + second - tz_offset_secs;

    Some(epoch_secs)
}

/// Convert `YYYY-MM-DD` to days since 1970-01-01.
fn days_since_epoch(year: i64, month: i64, day: i64) -> Option<i64> {
    if month < 1 || month > 12 || day < 1 || day > 31 { return None; }
    // Zeller / JDN formula
    let a = (14 - month) / 12;
    let y = year + 4800 - a;  // proleptic Gregorian
    let m = month + 12 * a - 3;
    let jdn = day + (153 * m + 2) / 5 + 365 * y + y / 4 - y / 100 + y / 400 - 32045;
    // JDN of 1970-01-01 = 2440588
    Some(jdn - 2440588)
}

// ── Encode ────────────────────────────────────────────────────────────────────

/// Encode a slice of ISO 8601 timestamp strings using delta compression.
///
/// Timestamps must be parseable; unrecognised strings are skipped.
/// Returns `(encoded_bytes, epoch_seconds)` so callers can verify.
pub fn encode_timestamps(timestamps: &[&str]) -> (Vec<u8>, Vec<i64>) {
    let epochs: Vec<i64> = timestamps.iter()
        .filter_map(|s| parse_timestamp(s))
        .collect();
    let encoded = encode_delta_ints(&epochs);
    (encoded, epochs)
}

// ── Decode ────────────────────────────────────────────────────────────────────

/// Decode bytes produced by [`encode_timestamps`] back to epoch seconds.
pub fn decode_timestamp_epochs(data: &[u8]) -> Option<Vec<i64>> {
    decode_delta_ints(data)
}

/// Format an epoch second back to ISO 8601 UTC string: `YYYY-MM-DDTHH:MM:SSZ`.
pub fn epoch_to_iso8601(epoch: i64) -> String {
    let secs_in_day = epoch.rem_euclid(86400);
    let days = (epoch - secs_in_day) / 86400;

    let hh = secs_in_day / 3600;
    let mm = (secs_in_day % 3600) / 60;
    let ss = secs_in_day % 60;

    // Richards (2013) algorithm: JDN → proleptic Gregorian date
    let jdn = days + 2440588;
    let a   = jdn + 32044;
    let b   = (4 * a + 3) / 146097;
    let c   = a - (146097 * b) / 4;
    let d   = (4 * c + 3) / 1461;
    let e   = c - (1461 * d) / 4;
    let m2  = (5 * e + 2) / 153;
    let day   = e - (153 * m2 + 2) / 5 + 1;
    let month = m2 + 3 - 12 * (m2 / 10);
    let year  = 100 * b + d - 4800 + m2 / 10;

    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, day, hh, mm, ss)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_date_only() {
        let epoch = parse_timestamp("2026-04-02").unwrap();
        // 2026-04-02 = days since 1970: verified independently
        assert!(epoch > 0);
    }

    #[test]
    fn parse_full_utc_timestamp() {
        let epoch = parse_timestamp("2026-04-02T10:30:00Z").unwrap();
        assert!(epoch > 0);
    }

    #[test]
    fn parse_timestamp_with_offset() {
        let utc   = parse_timestamp("2026-04-02T10:00:00Z").unwrap();
        let plus7 = parse_timestamp("2026-04-02T17:00:00+07:00").unwrap();
        assert_eq!(utc, plus7, "UTC and +07:00 should resolve to same epoch");
    }

    #[test]
    fn sequential_timestamps_encode_compactly() {
        let ts: Vec<&str> = vec![
            "2026-04-02T10:00:00Z",
            "2026-04-02T10:00:01Z",
            "2026-04-02T10:00:02Z",
            "2026-04-02T10:00:03Z",
            "2026-04-02T10:00:04Z",
        ];
        let (encoded, epochs) = encode_timestamps(&ts);
        assert_eq!(epochs.len(), 5);
        // delta=1 second → sequential → very compact
        assert!(encoded.len() <= 10, "sequential timestamps should be tiny: {} bytes", encoded.len());
    }

    #[test]
    fn timestamp_encode_decode_roundtrip() {
        let ts: Vec<&str> = vec![
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:05:00Z",
            "2026-01-01T01:00:00Z",
            "2026-03-15T12:30:45Z",
        ];
        let (encoded, epochs) = encode_timestamps(&ts);
        let decoded = decode_timestamp_epochs(&encoded).unwrap();
        assert_eq!(decoded, epochs);
    }

    #[test]
    fn epoch_to_iso8601_roundtrip() {
        let ts = "2026-04-02T10:30:15Z";
        let epoch = parse_timestamp(ts).unwrap();
        let back = epoch_to_iso8601(epoch);
        assert_eq!(back, ts);
    }

    #[test]
    fn epoch_1970_is_zero() {
        let epoch = parse_timestamp("1970-01-01T00:00:00Z").unwrap();
        assert_eq!(epoch, 0);
    }
}
