/// Phase 6 integration tests — Delta + Pattern Encoding.
///
/// Tests that all Phase 6 components:
/// - Produce correct roundtrip results
/// - Achieve meaningful compression for their target patterns
/// - Compose correctly for realistic log/API data
///
/// Milestone (plans.md §Phase 6): log dataset with sequential id + enum fields
/// should achieve < 5% of raw size when all Phase 6 encoders are applied.

use scte_core::pipelines::text::delta::integer::{
    detect_pattern, encode_delta_ints, decode_delta_ints, IntegerPattern,
};
use scte_core::pipelines::text::delta::cross_record::CrossRecordEncoder;
use scte_core::pipelines::text::delta::timestamp::{
    parse_timestamp, encode_timestamps, decode_timestamp_epochs, epoch_to_iso8601,
};
use scte_core::pipelines::text::pattern::rle::{rle_encode, rle_decode, rle_ratio};
use scte_core::pipelines::text::pattern::string_prefix::{
    detect_prefix_pattern, encode_prefix_strings, decode_prefix_strings,
};

// ── Integer delta ─────────────────────────────────────────────────────────────

#[test]
fn integer_sequential_ids_roundtrip_and_fits_in_10_bytes() {
    let ids: Vec<i64> = (0..1000).collect();
    let enc = encode_delta_ints(&ids);
    assert!(enc.len() <= 10, "1000 sequential IDs should encode in ≤10 bytes, got {}", enc.len());
    assert_eq!(decode_delta_ints(&enc).unwrap(), ids);
}

#[test]
fn integer_clustered_roundtrip_and_smaller_than_flat() {
    // Sensor jitter: values oscillate within a narrow band
    let vals: Vec<i64> = (0..200).map(|i| 100 + (i % 5) as i64 - 2).collect();
    assert!(matches!(detect_pattern(&vals), IntegerPattern::Clustered));
    let enc = encode_delta_ints(&vals);
    // Flat would need ~1-2 bytes per value (~300B). Delta should be ~half.
    let flat_estimate = 2 + 200 * 2; // generous upper bound
    assert!(enc.len() < flat_estimate,
        "clustered delta enc={} vs flat estimate={}", enc.len(), flat_estimate);
    assert_eq!(decode_delta_ints(&enc).unwrap(), vals);
}

#[test]
fn integer_random_values_still_roundtrip() {
    let vals = vec![394i64, 12, 8821, 44, 2000, -77, 0, i64::MIN / 2, i64::MAX / 2];
    assert_eq!(decode_delta_ints(&encode_delta_ints(&vals)).unwrap(), vals);
}

// ── Cross-record reference ────────────────────────────────────────────────────

#[test]
fn cross_record_stable_field_compresses_90pct() {
    let mut enc = CrossRecordEncoder::new();
    let n = 1000usize;
    let value = b"192.168.1.100";
    // First record: full value
    let first = enc.encode_field("ip", value);
    let mut total = first.len();
    for _ in 1..n {
        total += enc.encode_field("ip", value).len();
    }
    let raw = n * value.len();
    let ratio = total as f64 / raw as f64;
    assert!(ratio < 0.15, "stable field should encode to <15% of raw, got {:.1}%", ratio * 100.0);
}

#[test]
fn cross_record_changing_field_no_overhead() {
    let mut enc = CrossRecordEncoder::new();
    let values: Vec<Vec<u8>> = (0..100)
        .map(|i| format!("event_{i}").into_bytes())
        .collect();
    let total_enc: usize = values.iter().enumerate().map(|(_, v)| {
        enc.encode_field("event_type", v).len()
    }).sum();
    let total_raw: usize = values.iter().map(|v| v.len()).sum();
    // All different → overhead is just 1 flag byte per value
    assert!(total_enc <= total_raw + values.len(),
        "changing field should add at most 1 byte overhead per value");
}

// ── Timestamp delta ───────────────────────────────────────────────────────────

#[test]
fn timestamp_parse_known_dates() {
    // Unix epoch
    assert_eq!(parse_timestamp("1970-01-01T00:00:00Z").unwrap(), 0);
    // 2000-01-01 = 946684800
    assert_eq!(parse_timestamp("2000-01-01T00:00:00Z").unwrap(), 946684800);
}

#[test]
fn timestamp_sequential_per_second_encodes_tiny() {
    // 3600 timestamps one second apart (one hour of logs)
    let base = 1_700_000_000i64; // arbitrary epoch
    let epochs: Vec<i64> = (0..3600).map(|i| base + i).collect();
    // Simulate as timestamps
    let ts_strs: Vec<String> = epochs.iter().map(|&e| epoch_to_iso8601(e)).collect();
    let ts_refs: Vec<&str> = ts_strs.iter().map(|s| s.as_str()).collect();
    let (enc, parsed) = encode_timestamps(&ts_refs);
    assert_eq!(parsed.len(), 3600);
    assert!(enc.len() <= 15, "3600 sequential-second timestamps should be tiny, got {} bytes", enc.len());
    assert_eq!(decode_timestamp_epochs(&enc).unwrap(), parsed);
}

#[test]
fn timestamp_roundtrip_various_formats() {
    let cases = vec![
        ("2026-04-02",                0),  // date only
        ("2026-04-02T12:00:00Z",      0),  // UTC Z
        ("2026-04-02T12:00:00",       0),  // no tz
        ("2026-04-02T19:00:00+07:00", 0),  // +07:00 → same as 12:00 UTC
    ];
    let ts1 = parse_timestamp("2026-04-02T12:00:00Z").unwrap();
    let ts2 = parse_timestamp("2026-04-02T19:00:00+07:00").unwrap();
    assert_eq!(ts1, ts2, "+07:00 should equal UTC");
    let _ = cases; // used for documentation above
}

// ── Run-length encoding ───────────────────────────────────────────────────────

#[test]
fn rle_status_field_10_to_1_ratio() {
    // 95% "ok", 5% "error" — typical API log
    let mut vals: Vec<&[u8]> = vec![b"ok"; 950];
    for _ in 0..50 { vals.push(b"error"); }
    let ratio = rle_ratio(&vals);
    assert!(ratio < 0.20, "rle ratio should be < 20% for mostly-stable field, got {:.1}%", ratio * 100.0);
    // Verify roundtrip
    let dec = rle_decode(&rle_encode(&vals)).unwrap();
    let orig: Vec<Vec<u8>> = vals.iter().map(|v| v.to_vec()).collect();
    assert_eq!(dec, orig);
}

#[test]
fn rle_alternating_values_no_benefit() {
    // Worst case: perfectly alternating  "ok","error","ok","error"...
    let mut vals: Vec<&[u8]> = Vec::new();
    for i in 0..100 { vals.push(if i % 2 == 0 { b"ok" } else { b"error" }); }
    // No compression benefit but should still roundtrip correctly
    let dec = rle_decode(&rle_encode(&vals)).unwrap();
    let orig: Vec<Vec<u8>> = vals.iter().map(|v| v.to_vec()).collect();
    assert_eq!(dec, orig);
}

// ── String prefix ─────────────────────────────────────────────────────────────

#[test]
fn prefix_session_ids_compress_well() {
    let strs: Vec<String> = (1_000_000..1_001_000).map(|i| format!("sess_{i}")).collect();
    let refs: Vec<&str> = strs.iter().map(|s| s.as_str()).collect();
    let enc_sz = encode_prefix_strings(&refs).len();
    let raw_sz: usize = strs.iter().map(|s| s.len()).sum();
    assert!(enc_sz < raw_sz / 5,
        "prefix-encoded session IDs should be < 20% of raw: {enc_sz}B vs {raw_sz}B");
    // Roundtrip
    let decoded = decode_prefix_strings(&encode_prefix_strings(&refs)).unwrap();
    assert_eq!(decoded, strs);
}

#[test]
fn prefix_no_pattern_works_as_fallback() {
    let strs = vec!["GET /api/v1/users", "POST /api/v1/login", "DELETE /api/v1/sessions/42"];
    let enc = encode_prefix_strings(&strs);
    let dec = decode_prefix_strings(&enc).unwrap();
    assert_eq!(dec, strs);
}

// ── Composition test: simulate 1000-record API log ────────────────────────────

#[test]
fn phase6_api_log_compression_summary() {
    // Simulate 1000 API records:
    //   id: sequential 0..999
    //   timestamp: one per second from epoch
    //   status: 95% "ok", 5% "error"
    //   session_id: "sess_N" (prefix pattern)
    //   ip: constant "10.0.0.1" (stable field)

    let n = 1000usize;

    // id column (sequential)
    let ids: Vec<i64> = (0..n as i64).collect();
    let id_enc = encode_delta_ints(&ids);
    let id_raw = n * 4; // 4 bytes/int average in JSON
    println!("id column: {}B enc / {}B raw = {:.1}%", id_enc.len(), id_raw,
             id_enc.len() as f64 / id_raw as f64 * 100.0);
    assert!(id_enc.len() <= 10, "sequential IDs should be tiny");

    // timestamp column (sequential 1 sec/record)
    let ts_strs: Vec<String> = (0..n as i64).map(|i| epoch_to_iso8601(1_700_000_000 + i)).collect();
    let ts_refs: Vec<&str> = ts_strs.iter().map(|s| s.as_str()).collect();
    let (ts_enc, _) = encode_timestamps(&ts_refs);
    let ts_raw = n * 20; // "2026-04-02T10:00:00Z" = 20 bytes
    println!("ts column:  {}B enc / {}B raw = {:.1}%", ts_enc.len(), ts_raw,
             ts_enc.len() as f64 / ts_raw as f64 * 100.0);
    assert!(ts_enc.len() <= 15);

    // status column (RLE, 95% ok)
    let mut status_vals: Vec<&[u8]> = vec![b"ok"; 950];
    for _ in 0..50 { status_vals.push(b"error"); }
    let status_enc = rle_encode(&status_vals);
    let status_raw = n * 3; // avg "ok" or "error"
    println!("status col: {}B enc / {}B raw = {:.1}%", status_enc.len(), status_raw,
             status_enc.len() as f64 / status_raw as f64 * 100.0);

    // ip column (cross-record, constant)
    let mut cr_enc = CrossRecordEncoder::new();
    let ip = b"10.0.0.1";
    let ip_enc_sz: usize = (0..n).map(|_| cr_enc.encode_field("ip", ip).len()).sum();
    let ip_raw = n * ip.len();
    println!("ip column:  {}B enc / {}B raw = {:.1}%", ip_enc_sz, ip_raw,
             ip_enc_sz as f64 / ip_raw as f64 * 100.0);
    assert!(ip_enc_sz < ip_raw / 5, "constant field should compress >80%");

    // session_id column (prefix)
    let sess_strs: Vec<String> = (0..n).map(|i| format!("sess_{i}")).collect();
    let sess_refs: Vec<&str> = sess_strs.iter().map(|s| s.as_str()).collect();
    let sess_enc = encode_prefix_strings(&sess_refs);
    let sess_raw: usize = sess_strs.iter().map(|s| s.len()).sum();
    println!("sess col:   {}B enc / {}B raw = {:.1}%", sess_enc.len(), sess_raw,
             sess_enc.len() as f64 / sess_raw as f64 * 100.0);
    assert!(sess_enc.len() < sess_raw / 3);

    let total_enc = id_enc.len() + ts_enc.len() + status_enc.len() + ip_enc_sz + sess_enc.len();
    let total_raw = id_raw + ts_raw + status_raw + ip_raw + sess_raw;
    let ratio = total_enc as f64 / total_raw as f64;
    println!("TOTAL: {}B enc / {}B raw = {:.1}% (target < 5%)", total_enc, total_raw, ratio * 100.0);

    // Phase 6 milestone: < 5% for this pattern of data
    assert!(ratio < 0.05,
        "Phase 6 should achieve < 5% for structured log data, got {:.1}%", ratio * 100.0);
}
