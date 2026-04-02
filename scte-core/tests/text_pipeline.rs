/// Integration tests for the Phase 2 text pipeline.
///
/// These tests exercise the public API (`canonicalize_json`, `tokenize_json`)
/// and verify the contracts that later phases depend on:
///
///  1. `canonicalize_json` is idempotent.
///  2. `tokenize_json` emits keys in sorted order.
///  3. Both functions agree on the canonical key order.
///  4. `tokenize_json` preserves Key vs Str distinction.
///  5. Round-trip: `canonicalize → tokenize` produces the expected stream.
use scte_core::{
    canonicalize_json, tokenize_json, Token, TokenKind, TokenPayload,
};

// ── Helpers ──────────────────────────────────────────────────────────────────

fn canon(s: &str) -> String {
    let bytes = canonicalize_json(s.as_bytes()).expect("canonicalize failed");
    String::from_utf8(bytes).expect("canonical output must be valid UTF-8")
}

fn tokens(s: &str) -> Vec<Token> {
    tokenize_json(s.as_bytes()).expect("tokenize failed")
}

fn key_tokens(s: &str) -> Vec<String> {
    tokens(s)
        .into_iter()
        .filter(|t| t.kind == TokenKind::Key)
        .map(|t| match t.payload {
            TokenPayload::Str(s) => s,
            _ => panic!("Key payload must be Str"),
        })
        .collect()
}

// ── Canonicalize ─────────────────────────────────────────────────────────────

#[test]
fn canonicalize_is_idempotent() {
    let inputs = [
        r#"{"z":1,"a":2}"#,
        r#"{ "hello" : "world" }"#,
        r#"[3,1,2]"#,
        r#"{"items":[{"id":10,"val":9.99},{"id":11,"val":1}],"meta":null,"user":{"active":true,"id":1,"name":"Alice"}}"#,
    ];
    for input in &inputs {
        let once = canon(input);
        let twice = canon(&once);
        assert_eq!(once, twice, "canon(canon(x)) != canon(x) for: {input}");
    }
}

#[test]
fn canonicalize_sorts_keys_lexicographic() {
    // z > a > ... but byte-order sort: all ASCII letters sort correctly.
    assert_eq!(canon(r#"{"z":1,"a":2,"m":3}"#), r#"{"a":2,"m":3,"z":1}"#);
}

#[test]
fn canonicalize_no_whitespace() {
    assert_eq!(canon(r#"{ "a" : 1 }"#), r#"{"a":1}"#);
}

#[test]
fn canonicalize_int_from_float() {
    // 1.0 should be serialized as 1 (integer normalization in parser).
    assert_eq!(canon("1.0"), "1");
}

#[test]
fn canonicalize_nested_sorted() {
    let result = canon(r#"{"user":{"name":"Alice","id":1},"active":true}"#);
    assert_eq!(result, r#"{"active":true,"user":{"id":1,"name":"Alice"}}"#);
}

// ── Tokenize ─────────────────────────────────────────────────────────────────

#[test]
fn tokenize_sorted_keys_consistent_with_canon() {
    // key order from tokenize(raw) must equal key order from tokenize(canon(raw)).
    let input = r#"{"z":3,"a":1,"m":2}"#;
    let raw_keys  = key_tokens(input);
    let can_keys  = key_tokens(&canon(input));
    assert_eq!(raw_keys, can_keys, "tokenize key order must match canon key order");
    // And the order is lexicographic.
    assert_eq!(raw_keys, ["a", "m", "z"]);
}

#[test]
fn tokenize_key_order_simple() {
    assert_eq!(key_tokens(r#"{"z":1,"a":2,"m":3}"#), ["a", "m", "z"]);
}

#[test]
fn tokenize_nested_key_order() {
    let toks = key_tokens(r#"{"user":{"name":"Alice","id":1},"active":true}"#);
    // Depth-first: outer keys sorted, then inner keys sorted.
    assert_eq!(toks, ["active", "user", "id", "name"]);
}

#[test]
fn tokenize_preserves_key_vs_str() {
    let toks = tokens(r#"{"k":"v"}"#);
    assert_eq!(toks[1].kind, TokenKind::Key);
    assert_eq!(toks[2].kind, TokenKind::Str);
}

#[test]
fn tokenize_array_items_are_str_not_key() {
    let toks = tokens(r#"["hello","world"]"#);
    for t in &toks[1..toks.len() - 1] {
        assert_eq!(t.kind, TokenKind::Str, "array string must be Str, not Key");
    }
}

// ── Round-trip: canonicalize → tokenize ──────────────────────────────────────

#[test]
fn canonical_source_produces_same_token_stream() {
    // tokenize(x) should equal tokenize(canon(x)) for any valid JSON x.
    let input = r#"{"z":1,"a":[true,null,2.5],"m":{"x":0}}"#;
    let raw_tokens   = tokens(input);
    let canon_tokens = tokens(&canon(input));
    assert_eq!(raw_tokens, canon_tokens, "token stream must be canonical-source-independent");
}

// ── Correctness spot-checks ───────────────────────────────────────────────────

#[test]
fn deep_structure_token_count() {
    // {"a":{"b":{"c":1}}}
    // ObjOpen Key ObjOpen Key ObjOpen Key Int ObjClose ObjClose ObjClose = 10
    assert_eq!(tokens(r#"{"a":{"b":{"c":1}}}"#).len(), 10);
}

#[test]
fn array_preserves_order() {
    // Arrays must NOT be sorted — only object keys are.
    let toks = tokens(r#"[3,1,2]"#);
    assert_eq!(toks[1], Token { kind: TokenKind::NumInt, payload: TokenPayload::Int(3) });
    assert_eq!(toks[2], Token { kind: TokenKind::NumInt, payload: TokenPayload::Int(1) });
    assert_eq!(toks[3], Token { kind: TokenKind::NumInt, payload: TokenPayload::Int(2) });
}

#[test]
fn all_primitive_kinds_in_one_object() {
    let toks = tokens(r#"{"active":true,"count":0,"label":"x","nothing":null,"ratio":1.5}"#);
    let kind_map: std::collections::HashMap<String, TokenKind> = toks
        .windows(2)
        .filter(|w| w[0].kind == TokenKind::Key)
        .map(|w| {
            let key = match &w[0].payload {
                TokenPayload::Str(s) => s.clone(),
                _ => panic!(),
            };
            (key, w[1].kind)
        })
        .collect();
    assert_eq!(kind_map["active"],  TokenKind::Bool);
    assert_eq!(kind_map["count"],   TokenKind::NumInt);
    assert_eq!(kind_map["label"],   TokenKind::Str);
    assert_eq!(kind_map["nothing"], TokenKind::Null);
    assert_eq!(kind_map["ratio"],   TokenKind::NumFloat);
}

// ── Error handling ────────────────────────────────────────────────────────────

#[test]
fn canon_rejects_invalid_json() {
    assert!(canonicalize_json(b"not json").is_err());
}

#[test]
fn tokenize_rejects_invalid_json() {
    assert!(tokenize_json(b"{bad}").is_err());
}
