/// Phase 5 integration tests — Schema Inference + Two-Pass Encoding
///
/// Covers:
/// 1. Schema inference on realistic datasets
/// 2. Schema serializer roundtrip
/// 3. Two-pass encode is smaller than naive for enum-heavy data
/// 4. Token-level roundtrips through schema encode/decode
/// 5. Compression ratio targets from plans.md
use scte_core::{
    encode_json_two_pass, schema_deserialize, schema_serialize,
    FieldType, FileSchema,
    pipelines::text::{
        tokenize_json,
        dictionary::Dictionary,
        encode_with_dict, encode_token_bytes,
        schema_encode_tokens, schema_decode_tokens,
    },
};

// ── helpers ───────────────────────────────────────────────────────────────────

fn naive_token_bytes(json: &str, min_freq: u32) -> Vec<u8> {
    let toks  = tokenize_json(json.as_bytes()).unwrap();
    let dict  = Dictionary::build(&toks, min_freq);
    let enc   = encode_with_dict(&toks, &dict);
    encode_token_bytes(&enc).unwrap()
}

fn ratio_pct(compressed: usize, raw: usize) -> f64 {
    compressed as f64 / raw as f64 * 100.0
}

// ── 1. Schema inference ───────────────────────────────────────────────────────

#[test]
fn infers_integer_field() {
    let json = r#"[{"id":1},{"id":2},{"id":3}]"#;
    let toks = tokenize_json(json.as_bytes()).unwrap();
    let s    = FileSchema::build(&toks);
    assert!(matches!(s.field_type("id"), Some(FieldType::Integer { .. })));
}

#[test]
fn infers_bool_field() {
    let json = r#"[{"active":true},{"active":false},{"active":true}]"#;
    let toks = tokenize_json(json.as_bytes()).unwrap();
    let s    = FileSchema::build(&toks);
    assert_eq!(s.field_type("active"), Some(&FieldType::Bool));
}

#[test]
fn infers_enum_field_with_correct_variant_order() {
    // "ok" appears 3×, "warn" 2×, "fail" 1× → order: ok, warn, fail
    let json = r#"[
        {"s":"ok"},{"s":"warn"},{"s":"ok"},
        {"s":"fail"},{"s":"ok"},{"s":"warn"}
    ]"#;
    let toks = tokenize_json(json.as_bytes()).unwrap();
    let s    = FileSchema::build(&toks);
    let FieldType::Enum { ref variants } = *s.field_type("s").unwrap() else {
        panic!("expected Enum");
    };
    assert_eq!(variants[0], "ok");
    assert_eq!(variants[1], "warn");
    assert_eq!(variants[2], "fail");
}

#[test]
fn infers_nested_field_path() {
    let json = r#"[{"user":{"role":"admin"}},{"user":{"role":"user"}}]"#;
    let toks = tokenize_json(json.as_bytes()).unwrap();
    let s    = FileSchema::build(&toks);
    assert!(matches!(s.field_type("user.role"), Some(FieldType::Enum { .. })));
}

#[test]
fn high_cardinality_prefix_int_is_strprefix() {
    // "u0".."u64" share a common prefix "u" with variable-width integer suffixes.
    // The inferencer should recognise the prefix pattern and return StrPrefix,
    // not fall back to Str, regardless of cardinality.
    let entries: String = (0..65)
        .map(|i| format!(r#"{{"name":"u{i}"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let json = format!("[{entries}]");
    let toks = tokenize_json(json.as_bytes()).unwrap();
    let s    = FileSchema::build(&toks);
    assert!(matches!(s.field_type("name"), Some(FieldType::StrPrefix { .. })),
        "expected StrPrefix, got {:?}", s.field_type("name"));
}

// ── 2. Serializer roundtrip ───────────────────────────────────────────────────

#[test]
fn schema_serialize_deserialize_roundtrip() {
    let json = r#"[
        {"id":1,"status":"ok","active":true,"score":1.5},
        {"id":2,"status":"fail","active":false,"score":2.0}
    ]"#;
    let toks = tokenize_json(json.as_bytes()).unwrap();
    let s    = FileSchema::build(&toks);

    let bytes = schema_serialize(&s);
    let rt    = schema_deserialize(&bytes).unwrap();

    for f in &s.fields {
        assert_eq!(
            rt.field_type(&f.path), s.field_type(&f.path),
            "mismatch for field '{}'", f.path
        );
    }
}

#[test]
fn empty_schema_serializes_to_one_byte() {
    let s     = FileSchema::default();
    let bytes = schema_serialize(&s);
    assert_eq!(bytes.len(), 1);
    let rt = schema_deserialize(&bytes).unwrap();
    assert!(rt.fields.is_empty());
}

// ── 3. Token rewrite roundtrip ────────────────────────────────────────────────

#[test]
fn enum_tokens_roundtrip_through_encode_decode() {
    let json = r#"[
        {"status":"ok","env":"prod"},
        {"status":"fail","env":"staging"},
        {"status":"ok","env":"prod"}
    ]"#;
    let toks   = tokenize_json(json.as_bytes()).unwrap();
    let schema = FileSchema::build(&toks);

    let encoded = schema_encode_tokens(&toks, &schema);
    let decoded = schema_decode_tokens(&encoded, &schema);
    assert_eq!(toks, decoded, "schema_encode → schema_decode must be identity");
}

#[test]
fn mixed_field_types_roundtrip() {
    let json = r#"[
        {"id":1,"role":"admin","active":true,"score":9.5,"msg":"hello"},
        {"id":2,"role":"user","active":false,"score":3.0,"msg":"world"},
        {"id":3,"role":"admin","active":true,"score":7.0,"msg":"foo"}
    ]"#;
    let toks   = tokenize_json(json.as_bytes()).unwrap();
    let schema = FileSchema::build(&toks);

    let encoded = schema_encode_tokens(&toks, &schema);
    let decoded = schema_decode_tokens(&encoded, &schema);
    assert_eq!(toks, decoded);
}

// ── 4. Compression ratio tests ────────────────────────────────────────────────

#[test]
fn two_pass_smaller_than_naive_for_enum_heavy_data() {
    // 500 records, 3 enum fields → two-pass must beat naive
    let records: String = (0..500)
        .map(|i| {
            let status = ["ok", "warn", "fail"][i % 3];
            let tier   = ["free", "pro", "ent", "trial"][i % 4];
            let env    = ["prod", "staging"][i % 2];
            format!(r#"{{"id":{i},"status":"{status}","tier":"{tier}","env":"{env}"}}"#)
        })
        .collect::<Vec<_>>()
        .join(",");
    let json = format!("[{records}]");

    let naive   = naive_token_bytes(&json, 2);
    let two_out = encode_json_two_pass(json.as_bytes(), 2).unwrap();

    assert!(
        two_out.token_bytes.len() < naive.len(),
        "two-pass ({} B) should beat naive ({} B)",
        two_out.token_bytes.len(), naive.len()
    );
}

#[test]
fn ratio_under_15pct_for_3_enum_fields() {
    // Milestone from plans.md: dataset DOMINATED by ≥ 3 enum fields → ratio < 15%
    // No unique-id field — that adds incompressible integer entropy.
    // 1000 records: enough to amortize rANS frequency-table overhead.
    let records: String = (0..1000)
        .map(|i| {
            let status = ["ok", "warn", "fail"][i % 3];
            let tier   = ["free", "pro", "ent", "trial"][i % 4];
            let env    = ["prod", "staging"][i % 2];
            let active = if i % 5 == 0 { "false" } else { "true" };
            format!(r#"{{"status":"{status}","tier":"{tier}","env":"{env}","active":{active}}}"#)
        })
        .collect::<Vec<_>>()
        .join(",");
    let json = format!("[{records}]");

    let two_out = encode_json_two_pass(json.as_bytes(), 2).unwrap();
    let ratio   = ratio_pct(two_out.token_bytes.len(), json.len());

    println!("ratio_under_15pct: raw={} B  schema={} B  tokens={} B  ratio={ratio:.1}%",
             json.len(), two_out.schema_bytes.len(), two_out.token_bytes.len());
    assert!(ratio < 15.0, "expected < 15%, got {ratio:.1}%");
}

#[test]
fn ratio_under_20pct_for_homogeneous_api_records() {
    let records: String = (0..500)
        .map(|i| format!(r#"{{"id":{i},"type":"event","status":"ok","code":200,"msg":"success"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let json = format!("[{records}]");

    let two_out = encode_json_two_pass(json.as_bytes(), 2).unwrap();
    let ratio   = ratio_pct(two_out.token_bytes.len(), json.len());

    println!("ratio_under_20pct: raw={} B  tokens={} B  ratio={ratio:.1}%",
             json.len(), two_out.token_bytes.len());
    assert!(ratio < 20.0, "expected < 20%, got {ratio:.1}%");
}

// ── 5. Print summary (visible with `cargo test -- --nocapture`) ───────────────

#[test]
fn print_phase5_compression_summary() {
    fn measure(label: &str, json: &str) {
        let two_out = encode_json_two_pass(json.as_bytes(), 2).unwrap();
        let naive   = naive_token_bytes(json, 2);
        let raw     = json.len();
        let schema  = two_out.schema_bytes.len();
        let tokens  = two_out.token_bytes.len();
        let total   = schema + tokens;
        println!(
            "  {label:50}  raw={raw:8}B  naive={:7}B ({:.1}%)  \
             two-pass={total:7}B ({:.1}%)",
            naive.len(),
            ratio_pct(naive.len(), raw),
            ratio_pct(total, raw),
        );
    }

    println!("\n=== Phase 5 Two-Pass Compression Ratios ===");

    let r50: String = (0..50)
        .map(|i| format!(r#"{{"id":{i},"role":"admin","status":"ok","active":true}}"#))
        .collect::<Vec<_>>().join(",");
    measure("50 homogeneous records (3 enum/bool fields)", &format!("[{r50}]"));

    let r500: String = (0..500)
        .map(|i| {
            let s = ["ok","warn","fail"][i%3];
            let t = ["free","pro","ent","trial"][i%4];
            let e = ["prod","staging"][i%2];
            format!(r#"{{"id":{i},"status":"{s}","tier":"{t}","env":"{e}"}}"#)
        })
        .collect::<Vec<_>>().join(",");
    measure("500 records × 3 enum fields", &format!("[{r500}]"));

    let r2k: String = (0..2000)
        .map(|i| format!(r#"{{"id":{i},"name":"user_{i}","role":"admin","active":true}}"#))
        .collect::<Vec<_>>().join(",");
    measure("2000 records (1 enum + int + bool)", &format!("[{r2k}]"));

    let rapi: String = (0..500)
        .map(|i| format!(r#"{{"type":"event","status":"ok","code":200,"msg":"success","id":{i}}}"#))
        .collect::<Vec<_>>().join(",");
    measure("500 repetitive API responses (3 const enum)", &format!("[{rapi}]"));

    println!("===========================================");
}
