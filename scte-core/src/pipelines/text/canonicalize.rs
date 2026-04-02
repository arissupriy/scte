use crate::{error::ScteError, pipelines::text::value::{parse, Value}};

// ── Public entry point ───────────────────────────────────────────────────────

/// Normalize a JSON byte slice to its canonical form.
///
/// Canonical form guarantees:
/// - No insignificant whitespace
/// - Object keys sorted lexicographically (ascending, byte order)
/// - Integer-valued numbers emitted as integers (`1.0` → `1`)
/// - All strings use minimal escaping (only mandatory JSON escapes)
/// - UTF-8 encoded output; `\uXXXX` sequences decoded to their UTF-8 form
///
/// # Determinism
/// Given the same input semantics, `canonicalize_json` always produces
/// identical bytes on every platform and Rust version.
///
/// # Errors
/// Returns `ScteError::DecodeError` for malformed JSON.
pub fn canonicalize_json(input: &[u8]) -> Result<Vec<u8>, ScteError> {
    let value = parse(input)?;
    let mut out = Vec::with_capacity(input.len());
    write_value(&value, &mut out);
    Ok(out)
}

// ── Internal serializer ──────────────────────────────────────────────────────

/// Serialize a `Value` to canonical JSON bytes.
///
/// Used by both `canonicalize_json` (public) and `tokenizer` (internal),
/// so that both produce output consistent with each other.
pub(crate) fn write_value(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Null         => out.extend_from_slice(b"null"),
        Value::Bool(true)   => out.extend_from_slice(b"true"),
        Value::Bool(false)  => out.extend_from_slice(b"false"),
        Value::Int(n)       => write_int(*n, out),
        Value::Float(f)     => write_float(*f, out),
        Value::Str(s)       => write_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 { out.push(b','); }
                write_value(item, out);
            }
            out.push(b']');
        }
        Value::Object(entries) => {
            // Sort keys lexicographically — canonical invariant.
            // Use a Vec of references; no allocation of owned keys.
            let mut sorted: Vec<&(String, Value)> = entries.iter().collect();
            sorted.sort_unstable_by(|(a, _), (b, _)| a.as_bytes().cmp(b.as_bytes()));

            out.push(b'{');
            for (i, (key, val)) in sorted.iter().enumerate() {
                if i > 0 { out.push(b','); }
                write_string(key, out);
                out.push(b':');
                write_value(val, out);
            }
            out.push(b'}');
        }
    }
}

// ── Primitive formatters ─────────────────────────────────────────────────────

fn write_int(n: i64, out: &mut Vec<u8>) {
    // Inline integer-to-bytes without heap allocation for small values.
    // Falls back to format! for larger numbers.
    let s = n.to_string();
    out.extend_from_slice(s.as_bytes());
}

fn write_float(f: f64, out: &mut Vec<u8>) {
    // This branch is only reached for genuine floats (non-integer values).
    // Integer-valued floats are normalized to Value::Int during parsing.
    //
    // Rust's default Display for f64:
    //   - is deterministic
    //   - produces valid JSON numbers
    //   - does not always include a decimal point (e.g., "1" for 1.0_f64)
    //
    // We ensure a decimal point is always present to disambiguate floats
    // from integers when this output is re-parsed.
    let s = format!("{f}");
    if s.contains('.') || s.contains('e') || s.contains('E')
        || s.contains('n') || s.contains('i')  // NaN / Infinity — parser rejects, defensive
    {
        out.extend_from_slice(s.as_bytes());
    } else {
        out.extend_from_slice(s.as_bytes());
        out.extend_from_slice(b".0");
    }
}

/// Write a JSON string with minimal escaping.
///
/// Escapes: `"`, `\`, and control characters (U+0000–U+001F).
/// All other Unicode code points are emitted as raw UTF-8.
fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            '"'    => out.extend_from_slice(b"\\\""),
            '\\'   => out.extend_from_slice(b"\\\\"),
            '\n'   => out.extend_from_slice(b"\\n"),
            '\r'   => out.extend_from_slice(b"\\r"),
            '\t'   => out.extend_from_slice(b"\\t"),
            '\x08' => out.extend_from_slice(b"\\b"),
            '\x0C' => out.extend_from_slice(b"\\f"),
            c if (c as u32) < 0x20 => {
                // Remaining control characters: \u00XX
                let escape = format!("\\u{:04x}", c as u32);
                out.extend_from_slice(escape.as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(s: &str) -> String {
        String::from_utf8(canonicalize_json(s.as_bytes()).expect("canonicalize failed"))
            .expect("non-UTF8 output")
    }

    fn canon_err(s: &str) -> ScteError {
        canonicalize_json(s.as_bytes()).expect_err("expected error")
    }

    // ── Whitespace removal ───────────────────────────────────────────────────

    #[test]
    fn strips_spaces_from_object() {
        assert_eq!(canon(r#"{ "a" : 1 }"#), r#"{"a":1}"#);
    }

    #[test]
    fn strips_spaces_from_array() {
        assert_eq!(canon("[ 1 , 2 , 3 ]"), "[1,2,3]");
    }

    #[test]
    fn strips_newlines_and_indentation() {
        let pretty = "{\n  \"key\": \"value\"\n}";
        assert_eq!(canon(pretty), r#"{"key":"value"}"#);
    }

    // ── Key sorting ──────────────────────────────────────────────────────────

    #[test]
    fn sorts_object_keys() {
        assert_eq!(canon(r#"{"z":1,"a":2,"m":3}"#), r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn sorts_nested_object_keys() {
        let input = r#"{"z":{"b":2,"a":1},"a":0}"#;
        assert_eq!(canon(input), r#"{"a":0,"z":{"a":1,"b":2}}"#);
    }

    #[test]
    fn single_key_unchanged() {
        assert_eq!(canon(r#"{"k":1}"#), r#"{"k":1}"#);
    }

    #[test]
    fn empty_object_unchanged() {
        assert_eq!(canon("{}"), "{}");
    }

    // ── Number normalization ─────────────────────────────────────────────────

    #[test]
    fn float_one_normalized_to_int() {
        assert_eq!(canon("1.0"), "1");
    }

    #[test]
    fn pure_integer_unchanged() {
        assert_eq!(canon("42"), "42");
    }

    #[test]
    fn genuine_float_preserved() {
        assert_eq!(canon("1.5"), "1.5");
    }

    #[test]
    fn exponent_integer_normalized() {
        assert_eq!(canon("1e2"), "100");
        assert_eq!(canon("2E1"), "20");
    }

    #[test]
    fn negative_int_preserved() {
        assert_eq!(canon("-5"), "-5");
    }

    // ── String escaping ──────────────────────────────────────────────────────

    #[test]
    fn quote_escaped() {
        assert_eq!(canon(r#""\"""#), r#""\"""#);
    }

    #[test]
    fn backslash_escaped() {
        assert_eq!(canon(r#""\\""#), r#""\\""#);
    }

    #[test]
    fn unicode_escape_decoded_to_utf8() {
        // \u00E9 is é — canonical form emits raw UTF-8, not \uXXXX
        let out = canon(r#""\u00E9""#);
        assert_eq!(out, "\"é\"");
    }

    #[test]
    fn tab_normalized_to_escaped_tab() {
        assert_eq!(canon(r#""\t""#), r#""\t""#);
    }

    // ── Determinism ──────────────────────────────────────────────────────────

    #[test]
    fn idempotent() {
        // canonicalize(canonicalize(x)) == canonicalize(x)
        let input = r#"{"z":1,"a":{"q":3,"b":2},"m":[3,1,2]}"#;
        let first  = canon(input);
        let second = canon(&first);
        assert_eq!(first, second, "canonicalization must be idempotent");
    }

    #[test]
    fn same_semantics_same_output() {
        let a = canon(r#"  { "b" : 2 , "a" : 1 }  "#);
        let b = canon(r#"{"a":1,"b":2}"#);
        assert_eq!(a, b);
    }

    // ── Complex payloads ─────────────────────────────────────────────────────

    #[test]
    fn real_world_api_response() {
        let input = r#"
        {
            "user": { "id": 1, "name": "Alice", "active": true },
            "items": [{ "id": 10, "val": 9.99 }, { "id": 11, "val": 1.0 }],
            "meta": null
        }"#;
        let out = canon(input);
        assert_eq!(
            out,
            r#"{"items":[{"id":10,"val":9.99},{"id":11,"val":1}],"meta":null,"user":{"active":true,"id":1,"name":"Alice"}}"#
        );
    }

    // ── Error propagation ────────────────────────────────────────────────────

    #[test]
    fn invalid_json_returns_error() {
        assert!(matches!(canon_err("{bad json}"), ScteError::DecodeError(_)));
    }
}
