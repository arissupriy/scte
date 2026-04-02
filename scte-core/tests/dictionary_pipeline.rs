/// Integration tests for the Phase 3 dictionary encoding pipeline.
///
/// These tests exercise the full path:
///
/// ```text
/// JSON bytes
///   → tokenize_json()          (Phase 2)
///   → Dictionary::build()      (Phase 3 — frequency analysis)
///   → encode_with_dict()       (Phase 3 — token → DictId substitution)
///   → Dictionary::serialize()  (Phase 3 — DICT section wire format)
///   → Dictionary::deserialize() + decode_with_dict()   (round-trip verify)
/// ```
///
/// Contracts verified:
/// 1. Build + encode + decode round-trip restores the original token stream.
/// 2. Serialized dictionary deserializes to an equivalent lookup table.
/// 3. High-frequency tokens really do get lower IDs.
/// 4. `min_freq` gate is correctly applied.
/// 5. `encode_with_dict(empty_dict)` leaves every token as a literal string.
/// 6. The dictionary is canonical-source-independent.
use scte_core::{
    canonicalize_json, decode_with_dict, encode_with_dict,
    tokenize_json, Dictionary, DictEntryKind, EncodedPayload, TokenKind,
};

// ── Helpers ──────────────────────────────────────────────────────────────────

fn tok(s: &str) -> Vec<scte_core::Token> {
    tokenize_json(s.as_bytes()).expect("tokenize failed")
}

fn canon(s: &str) -> String {
    String::from_utf8(canonicalize_json(s.as_bytes()).unwrap()).unwrap()
}

// ── Full round-trip ───────────────────────────────────────────────────────────

#[test]
fn roundtrip_simple_object() {
    let toks = tok(r#"{"name":"Alice","role":"admin"}"#);
    let dict = Dictionary::build(&toks, 1);
    let enc  = encode_with_dict(&toks, &dict);
    let dec  = decode_with_dict(&enc, &dict).unwrap();
    assert_eq!(toks, dec);
}

#[test]
fn roundtrip_nested_object() {
    let toks = tok(r#"{"user":{"id":1,"name":"Alice"},"active":true}"#);
    let dict = Dictionary::build(&toks, 1);
    let enc  = encode_with_dict(&toks, &dict);
    let dec  = decode_with_dict(&enc, &dict).unwrap();
    assert_eq!(toks, dec);
}

#[test]
fn roundtrip_array_of_objects() {
    let json = r#"[
        {"id":1,"name":"Alice","role":"admin"},
        {"id":2,"name":"Bob",  "role":"user"},
        {"id":3,"name":"Carol","role":"user"},
        {"id":4,"name":"Dave", "role":"admin"}
    ]"#;
    let toks = tok(json);
    let dict = Dictionary::build(&toks, 1);
    let enc  = encode_with_dict(&toks, &dict);
    let dec  = decode_with_dict(&enc, &dict).unwrap();
    assert_eq!(toks, dec);
}

#[test]
fn roundtrip_preserves_all_primitive_types() {
    let toks = tok(r#"{"active":true,"count":42,"label":"x","nothing":null,"ratio":1.5}"#);
    let dict = Dictionary::build(&toks, 1);
    let enc  = encode_with_dict(&toks, &dict);
    let dec  = decode_with_dict(&enc, &dict).unwrap();
    assert_eq!(toks, dec);
}

// ── Dictionary content ────────────────────────────────────────────────────────

#[test]
fn repeated_keys_are_in_dictionary() {
    let json = r#"[
        {"id":1,"name":"A"},
        {"id":2,"name":"B"},
        {"id":3,"name":"C"}
    ]"#;
    let toks = tok(json);
    let dict = Dictionary::build(&toks, 2); // appears 3× each → survives threshold 2
    assert!(dict.lookup(TokenKind::Key, "id").is_some(),   "id must be in dict");
    assert!(dict.lookup(TokenKind::Key, "name").is_some(), "name must be in dict");
}

#[test]
fn min_freq_filters_rare_keys() {
    // "common" appears 3×, "rare" appears 1×
    let json = r#"[
        {"common":1,"rare":1},
        {"common":2},
        {"common":3}
    ]"#;
    let toks = tok(json);
    let dict = Dictionary::build(&toks, 2);
    assert!(dict.lookup(TokenKind::Key, "common").is_some(), "common should survive");
    assert!(dict.lookup(TokenKind::Key, "rare").is_none(),   "rare should be filtered");
}

#[test]
fn higher_freq_token_has_lower_id() {
    // "id" appears 4×, "name" appears 4×, "role" appears 4×,
    // "user" appears 2×, "admin" appears 2×.
    let json = r#"[
        {"id":1,"name":"A","role":"admin"},
        {"id":2,"name":"B","role":"user"},
        {"id":3,"name":"C","role":"user"},
        {"id":4,"name":"D","role":"admin"}
    ]"#;
    let toks = tok(json);
    let dict = Dictionary::build(&toks, 1);

    // Keys appear 4× each, values appear 2× each → key IDs must be lower.
    let id_key_id   = dict.lookup(TokenKind::Key, "id").unwrap();
    let id_str_user = dict.lookup(TokenKind::Str, "user").unwrap();
    assert!(id_key_id < id_str_user, "4× keys should have lower IDs than 2× values");
}

// ── Encode properties ─────────────────────────────────────────────────────────

#[test]
fn known_strings_encoded_as_dict_id() {
    let toks = tok(r#"{"role":"admin"}"#);
    let dict = Dictionary::build(&toks, 1);
    let enc  = encode_with_dict(&toks, &dict);

    let has_dict_id = enc.iter().any(|t| matches!(t.payload, EncodedPayload::DictId(_)));
    assert!(has_dict_id, "at least one token should be a DictId");
}

#[test]
fn empty_dict_leaves_all_strings_literal() {
    let toks = tok(r#"{"name":"Alice"}"#);
    let dict = Dictionary::empty();
    let enc  = encode_with_dict(&toks, &dict);

    let all_str = enc.iter()
        .filter(|t| t.kind == TokenKind::Key || t.kind == TokenKind::Str)
        .all(|t| matches!(t.payload, EncodedPayload::Str(_)));
    assert!(all_str, "with empty dict, all strings must remain literal");
}

#[test]
fn structural_tokens_never_become_dict_id() {
    let toks = tok(r#"{"a":{"b":[1,2]}}"#);
    let dict = Dictionary::build(&toks, 1);
    let enc  = encode_with_dict(&toks, &dict);

    let structural_kinds = [
        TokenKind::ObjOpen,
        TokenKind::ObjClose,
        TokenKind::ArrOpen,
        TokenKind::ArrClose,
        TokenKind::Null,
    ];
    for t in &enc {
        if structural_kinds.contains(&t.kind) {
            assert!(
                matches!(t.payload, EncodedPayload::None),
                "structural token {:?} must carry None payload", t.kind
            );
        }
    }
}

// ── Serialize / deserialize round-trip ───────────────────────────────────────

#[test]
fn dict_serialize_deserialize_roundtrip() {
    let toks = tok(r#"[{"id":1,"name":"Alice"},{"id":2,"name":"Bob"}]"#);
    let dict  = Dictionary::build(&toks, 1);
    let bytes = dict.serialize();
    let dict2 = Dictionary::deserialize(&bytes).expect("deserialize failed");

    // Verify all entries are preserved in correct order.
    assert_eq!(dict.len(), dict2.len());
    for i in 0..dict.len() {
        let e1 = dict.get(i as u16).unwrap();
        let e2 = dict2.get(i as u16).unwrap();
        assert_eq!(e1, e2, "entry {i} differs after deserialize");
    }
}

#[test]
fn full_pipeline_with_serialized_dict() {
    // Simulate encode side: build dict, serialize, encode tokens.
    let json  = r#"[{"id":1,"name":"Alice"},{"id":2,"name":"Bob"}]"#;
    let toks  = tok(json);
    let dict  = Dictionary::build(&toks, 1);
    let dict_bytes = dict.serialize();
    let enc   = encode_with_dict(&toks, &dict);

    // Simulate decode side: deserialize dict, decode tokens.
    let dict2 = Dictionary::deserialize(&dict_bytes).unwrap();
    let dec   = decode_with_dict(&enc, &dict2).unwrap();

    assert_eq!(toks, dec, "full encode/serialize→deserialize/decode round-trip must be lossless");
}

// ── Canonical-source independence ─────────────────────────────────────────────

#[test]
fn dictionary_canonical_source_independent() {
    // tokenize(x) == tokenize(canon(x)) from Phase 2.
    // Therefore build + encode must also be independent of source formatting.
    let raw  = r#"{ "name" : "Alice" , "role" : "admin" }"#;
    let can  = canon(raw);

    let toks_raw = tok(raw);
    let toks_can = tok(&can);

    let dict_raw = Dictionary::build(&toks_raw, 1);
    let dict_can = Dictionary::build(&toks_can, 1);

    assert_eq!(dict_raw.serialize(), dict_can.serialize(),
        "dictionaries built from raw and canonical source must be identical");

    let enc_raw = encode_with_dict(&toks_raw, &dict_raw);
    let enc_can = encode_with_dict(&toks_can, &dict_can);
    assert_eq!(enc_raw, enc_can,
        "encoded streams must be identical regardless of source formatting");
}

// ── DictEntryKind ─────────────────────────────────────────────────────────────

#[test]
fn key_and_str_get_separate_dict_entries() {
    // "name" appears as both a Key and a Str value — they must be distinct entries.
    let toks = tok(r#"{"name":"name"}"#);
    let dict = Dictionary::build(&toks, 1);

    let id_key = dict.lookup(TokenKind::Key, "name");
    let id_str = dict.lookup(TokenKind::Str, "name");

    assert!(id_key.is_some(), "Key 'name' must be in dict");
    assert!(id_str.is_some(), "Str 'name' must be in dict");
    assert_ne!(id_key.unwrap(), id_str.unwrap(), "Key and Str must have distinct IDs");

    // DictEntryKind must match.
    assert_eq!(dict.get(id_key.unwrap()).unwrap().kind, DictEntryKind::Key);
    assert_eq!(dict.get(id_str.unwrap()).unwrap().kind, DictEntryKind::Str);
}
