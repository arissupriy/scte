/// Integration tests for the Phase 4 entropy pipeline.
///
/// Exercises the full text pipeline end-to-end:
///
/// ```text
/// JSON bytes
///   → canonicalize_json()           (Phase 2)
///   → tokenize_json()               (Phase 2)
///   → Dictionary::build()           (Phase 3)
///   → encode_with_dict()            (Phase 3)
///   → encode_token_bytes()          (Phase 4: rANS + payload packing)
///   → decode_token_bytes()          (Phase 4: unpack)
///   → decode_with_dict()            (Phase 3: dict substitution)
///   == original token stream        ✓
/// ```
///
/// Contracts verified:
/// 1. Full pipeline round-trip is lossless for all JSON types.
/// 2. Encoded output is deterministic.
/// 3. TOKENS payload is smaller than raw JSON for repetitive inputs.
/// 4. Canonical-source independence: raw JSON and canon(JSON) produce
///    the same encoded bytes.
/// 5. All payload types survive the pipeline without corruption.

use scte_core::{
    canonicalize_json, decode_token_bytes, decode_with_dict,
    encode_token_bytes, encode_with_dict, tokenize_json, Dictionary,
};

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Full pipeline: JSON → token stream (decoded back from entropy stream).
fn full_roundtrip(json: &str) -> Vec<scte_core::Token> {
    let toks  = tokenize_json(json.as_bytes()).unwrap();
    let dict  = Dictionary::build(&toks, 1);
    let enc   = encode_with_dict(&toks, &dict);
    let bytes = encode_token_bytes(&enc).unwrap();
    let dec   = decode_token_bytes(&bytes).unwrap();
    decode_with_dict(&dec, &dict).unwrap()
}

fn canon(s: &str) -> String {
    String::from_utf8(canonicalize_json(s.as_bytes()).unwrap()).unwrap()
}

// ── Lossless round-trips ──────────────────────────────────────────────────────

#[test]
fn roundtrip_simple_object() {
    let json = r#"{"name":"Alice","role":"admin"}"#;
    let orig = tokenize_json(json.as_bytes()).unwrap();
    assert_eq!(full_roundtrip(json), orig);
}

#[test]
fn roundtrip_nested_object() {
    let json = r#"{"user":{"id":1,"name":"Alice"},"active":true}"#;
    let orig = tokenize_json(json.as_bytes()).unwrap();
    assert_eq!(full_roundtrip(json), orig);
}

#[test]
fn roundtrip_array_of_objects() {
    let json = r#"[
        {"id":1,"name":"Alice","role":"admin"},
        {"id":2,"name":"Bob",  "role":"user"},
        {"id":3,"name":"Carol","role":"user"},
        {"id":4,"name":"Dave", "role":"admin"}
    ]"#;
    let orig = tokenize_json(json.as_bytes()).unwrap();
    assert_eq!(full_roundtrip(json), orig);
}

#[test]
fn roundtrip_all_primitive_types() {
    let json = r#"{"active":true,"count":42,"nothing":null,"ratio":1.5,"label":"x","delta":-7}"#;
    let orig = tokenize_json(json.as_bytes()).unwrap();
    assert_eq!(full_roundtrip(json), orig);
}

#[test]
fn roundtrip_empty_object() {
    let orig = tokenize_json(b"{}").unwrap();
    assert_eq!(full_roundtrip("{}"), orig);
}

#[test]
fn roundtrip_empty_array() {
    let orig = tokenize_json(b"[]").unwrap();
    assert_eq!(full_roundtrip("[]"), orig);
}

#[test]
fn roundtrip_deeply_nested() {
    let json = r#"{"a":{"b":{"c":{"d":{"e":1}}}}}"#;
    let orig = tokenize_json(json.as_bytes()).unwrap();
    assert_eq!(full_roundtrip(json), orig);
}

#[test]
fn roundtrip_large_array() {
    let mut json = String::from("[");
    for i in 0..500 {
        if i > 0 { json.push(','); }
        json.push_str(&format!(r#"{{"id":{i},"name":"user","active":true}}"#));
    }
    json.push(']');
    let orig = tokenize_json(json.as_bytes()).unwrap();
    assert_eq!(full_roundtrip(&json), orig);
}

// ── Determinism ───────────────────────────────────────────────────────────────

#[test]
fn encode_is_deterministic() {
    let json  = r#"[{"id":1,"name":"Alice"},{"id":2,"name":"Bob"}]"#;
    let toks  = tokenize_json(json.as_bytes()).unwrap();
    let dict  = Dictionary::build(&toks, 1);
    let enc   = encode_with_dict(&toks, &dict);

    let bytes1 = encode_token_bytes(&enc).unwrap();
    let bytes2 = encode_token_bytes(&enc).unwrap();
    assert_eq!(bytes1, bytes2, "encode must be deterministic");
}

// ── Canonical-source independence ─────────────────────────────────────────────

#[test]
fn canonical_source_produces_same_bytes() {
    let raw = r#"{ "name" : "Alice" , "role" : "admin" }"#;
    let can = canon(raw);

    let toks_raw = tokenize_json(raw.as_bytes()).unwrap();
    let toks_can = tokenize_json(can.as_bytes()).unwrap();

    let dict_raw = Dictionary::build(&toks_raw, 1);
    let dict_can = Dictionary::build(&toks_can, 1);

    let enc_raw = encode_with_dict(&toks_raw, &dict_raw);
    let enc_can = encode_with_dict(&toks_can, &dict_can);

    let bytes_raw = encode_token_bytes(&enc_raw).unwrap();
    let bytes_can = encode_token_bytes(&enc_can).unwrap();

    assert_eq!(bytes_raw, bytes_can,
        "encode_token_bytes must be canonical-source-independent");
}

// ── Compression ratio ─────────────────────────────────────────────────────────

#[test]
fn tokens_payload_smaller_than_raw_json_for_repetitive_input() {
    let mut json = String::from("[");
    for i in 0..200 {
        if i > 0 { json.push(','); }
        json.push_str(&format!(r#"{{"id":{i},"name":"user_{i}","active":true}}"#));
    }
    json.push(']');

    let toks  = tokenize_json(json.as_bytes()).unwrap();
    let dict  = Dictionary::build(&toks, 2);
    let enc   = encode_with_dict(&toks, &dict);
    let bytes = encode_token_bytes(&enc).unwrap();

    assert!(
        bytes.len() < json.len(),
        "TOKENS payload ({}) should be smaller than raw JSON ({}) for repetitive data",
        bytes.len(), json.len()
    );
}

// ── Payload type integrity ────────────────────────────────────────────────────

#[test]
fn negative_integers_preserved() {
    let json = r#"{"a":-1,"b":-128,"c":-9999999}"#;
    let orig = tokenize_json(json.as_bytes()).unwrap();
    assert_eq!(full_roundtrip(json), orig);
}

#[test]
fn float_values_preserved_exactly() {
    let json = r#"{"pi":3.14159265358979,"e":2.718281828}"#;
    let orig = tokenize_json(json.as_bytes()).unwrap();
    assert_eq!(full_roundtrip(json), orig);
}

#[test]
fn unicode_strings_preserved() {
    let json = r#"{"greeting":"こんにちは","emoji":"😀"}"#;
    let orig = tokenize_json(json.as_bytes()).unwrap();
    assert_eq!(full_roundtrip(json), orig);
}
