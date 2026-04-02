/// Integration tests: roundtrip invariant
///
/// Core invariant for ALL phases:
///   decode(encode(x)) == x   (byte-identical)
///
/// These tests run against the public API and do not inspect internals.
use scte_core::{decode, encode};

// ── Roundtrip correctness ────────────────────────────────────────────────────

#[test]
fn roundtrip_empty() {
    let input: &[u8] = b"";
    assert_eq!(decode(&encode(input).unwrap()).unwrap(), input);
}

#[test]
fn roundtrip_single_byte() {
    let input = b"\x00";
    assert_eq!(decode(&encode(input).unwrap()).unwrap(), input);
}

#[test]
fn roundtrip_ascii_text() {
    let input = b"Hello, SCTE Phase 1!";
    assert_eq!(decode(&encode(input).unwrap()).unwrap(), input);
}

#[test]
fn roundtrip_json_payload() {
    // The JSON pipeline canonicalizes key order (sorts keys alphabetically),
    // so byte-identical roundtrip is not expected. Compare canonical forms.
    use scte_core::canonicalize_json;
    let input   = br#"{"user":{"id":1,"name":"Alice"},"active":true}"#;
    let encoded = encode(input).unwrap();
    let decoded = decode(&encoded).unwrap();
    assert_eq!(
        canonicalize_json(input).unwrap(),
        canonicalize_json(&decoded).unwrap(),
        "JSON roundtrip must be semantically identical (canonical forms must match)"
    );
}

#[test]
fn roundtrip_binary_bytes() {
    let input: Vec<u8> = (0u8..=255).collect();
    assert_eq!(decode(&encode(&input).unwrap()).unwrap(), input);
}

#[test]
fn roundtrip_all_zeros() {
    let input = vec![0u8; 4096];
    assert_eq!(decode(&encode(&input).unwrap()).unwrap(), input);
}

#[test]
fn roundtrip_all_ones() {
    let input = vec![0xFFu8; 4096];
    assert_eq!(decode(&encode(&input).unwrap()).unwrap(), input);
}

#[test]
fn roundtrip_1mib_random_like() {
    // Deterministic pseudo-random bytes (no external crate needed).
    let input: Vec<u8> = (0u32..1024 * 1024)
        .map(|i| {
            // LCG: cheap, deterministic, good enough for testing
            ((i.wrapping_mul(1_664_525).wrapping_add(1_013_904_223)) >> 13) as u8
        })
        .collect();
    assert_eq!(decode(&encode(&input).unwrap()).unwrap(), input);
}

#[test]
fn roundtrip_utf8_multibyte() {
    let input = "日本語テスト — unicode roundtrip".as_bytes();
    assert_eq!(decode(&encode(input).unwrap()).unwrap(), input);
}

#[test]
fn roundtrip_csv_like() {
    let input = b"id,name,value\n1,alice,100\n2,bob,200\n3,charlie,300\n";
    assert_eq!(decode(&encode(input).unwrap()).unwrap(), input);
}

// ── Determinism ──────────────────────────────────────────────────────────────

#[test]
fn encode_is_deterministic() {
    let input = b"same input, same output, always";
    let a = encode(input).unwrap();
    let b = encode(input).unwrap();
    assert_eq!(a, b, "encode must produce identical output for identical input");
}

// ── Error cases ───────────────────────────────────────────────────────────────

#[test]
fn decode_rejects_empty_buffer() {
    use scte_core::ScteError;
    assert_eq!(decode(b""), Err(ScteError::UnexpectedEof));
}

#[test]
fn decode_rejects_garbage() {
    use scte_core::ScteError;
    let garbage = b"this is not a scte container at all";
    assert_eq!(decode(garbage), Err(ScteError::InvalidMagic));
}

#[test]
fn decode_rejects_truncated_container() {
    use scte_core::ScteError;
    let encoded = encode(b"truncation test").unwrap();
    // Keep only the header, strip section table and payload.
    let truncated = &encoded[0..24];
    assert_eq!(decode(truncated), Err(ScteError::UnexpectedEof));
}
