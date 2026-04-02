/// Two-pass encoding orchestrator — Phase 5.
///
/// # Encoding pipeline
/// ```text
/// Pass 1 (analyze):  tokenize_json → FileSchema::build
/// Pass 2 (encode):   tokenize_json
///                      → schema_encode_tokens   (Str enum → NumInt index)
///                      → Dictionary::build
///                      → encode_with_dict
///                      → encode_token_bytes      (rANS)
/// ```
///
/// # Why two passes help
/// Enum fields (e.g. `"status": "ok"`) are extremely common in API and log
/// data. A naive encoder stores them as DictId (2 bytes) + the string in DICT.
/// After Phase 5 schema inference the encoder replaces the string payload with
/// a 0-based variant index — typically a single LEB128 byte — while the decoder
/// uses the SCHEMA section to reverse the mapping without the original string.
///
/// # Decode pipeline
/// ```text
/// decode_token_bytes → decode_with_dict → schema_decode_tokens
/// ```
///
/// # Output
/// Returns [`TwoPassOutput`] containing `schema_bytes` (for the SCHEMA section)
/// and `token_bytes` (rANS-compressed TOKENS section).  The caller is
/// responsible for writing these to the SCTE container.

use crate::error::ScteError;
use crate::schema::FieldType;
use std::collections::HashMap;
use crate::pipelines::text::{
    dictionary::Dictionary,
    encode_token_bytes, decode_token_bytes,
    encode_with_dict, decode_with_dict,
    tokenize_json,
};
use crate::pipelines::text::tokenizer::{Token, TokenKind, TokenPayload};
use crate::schema::inferencer::FileSchema;
use crate::schema::serializer;

// ── Output type ───────────────────────────────────────────────────────────────

/// Output of a Phase 5 two-pass encode operation.
#[derive(Debug)]
pub struct TwoPassOutput {
    /// Serialized `FileSchema` — write to SCHEMA section (0x08).
    pub schema_bytes: Vec<u8>,
    /// rANS/CTW-compressed token stream — write to TOKENS section.
    pub token_bytes: Vec<u8>,
    /// Dictionary used — needed for decoding (caller stores in DICT section).
    pub dict: Dictionary,
    /// Schema used — kept for roundtrip testing / decode.
    pub schema: FileSchema,
    /// Delta section bytes — empty if no integer columns were delta-encoded.
    /// Stores the list of field paths that had delta encoding applied (Phase 6).
    pub delta_bytes: Vec<u8>,
}

// ── Public entry points ───────────────────────────────────────────────────────

/// Encode JSON bytes using two-pass schema-aware compression.
///
/// `dict_min_freq` is the minimum token frequency for dictionary inclusion
/// (use `1` for testing, `3` for production).
///
/// # Errors
/// Returns `ScteError::EncodeError` if tokenization fails.
pub fn encode_json_two_pass(
    json: &[u8],
    dict_min_freq: u32,
) -> Result<TwoPassOutput, ScteError> {
    // Pass 1: build schema
    let tokens = tokenize_json(json)
        .map_err(|e| ScteError::EncodeError(format!("tokenize: {e}")))?;
    let schema = FileSchema::build(&tokens);

    // Pass 2: schema-encode → delta-encode → compress
    let schema_encoded          = schema_encode_tokens(&tokens, &schema);
    let (delta_encoded, delta_bytes) = delta_encode_tokens(&schema_encoded, &schema);
    let dict                    = Dictionary::build(&delta_encoded, dict_min_freq);
    let encoded                 = encode_with_dict(&delta_encoded, &dict);
    let token_bytes             = encode_token_bytes(&encoded)
        .map_err(|e| ScteError::EncodeError(format!("token_bytes: {e}")))?;
    let schema_bytes            = serializer::serialize(&schema);

    Ok(TwoPassOutput { schema_bytes, token_bytes, dict, schema, delta_bytes })
}

/// Decode a two-pass compressed token stream back to a `Token` vec,
/// with enum indices restored to their string values and delta integers
/// reconstructed to their original values.
///
/// `token_bytes` is the rANS/CTW-compressed TOKENS section payload.
/// `dict` is the dictionary from the DICT section.
/// `schema` is the schema from the SCHEMA section.
/// `delta_bytes` is the DELTA section payload (empty slice if no delta section).
///
/// Returns the fully decoded token stream. Use `tokens_to_json` to reconstruct
/// the original JSON bytes.
pub fn decode_token_stream(
    token_bytes: &[u8],
    dict: &Dictionary,
    schema: &FileSchema,
    delta_bytes: &[u8],
) -> Result<Vec<Token>, ScteError> {
    let encoded        = decode_token_bytes(token_bytes)?;
    let tokens         = decode_with_dict(&encoded, dict)?;
    let schema_decoded = schema_decode_tokens(&tokens, schema);
    let delta_decoded  = delta_decode_tokens(&schema_decoded, schema, delta_bytes);
    Ok(delta_decoded)
}

// ── Schema-aware token rewriting ──────────────────────────────────────────────

/// Rewrite a token stream replacing `Str` values at enum field paths with
/// `NumInt(variant_index)`.
///
/// This is the core Phase 5 compression step.  The SCHEMA section records
/// the variant mapping so the decoder can reverse it without the strings.
///
/// Only `Str` value tokens at paths the schema classifies as `Enum` are
/// rewritten.  All other tokens are passed through unchanged.
pub fn schema_encode_tokens(tokens: &[Token], schema: &FileSchema) -> Vec<Token> {
    let mut out = Vec::with_capacity(tokens.len());
    let mut ctx = RewriteCtx::new();

    for token in tokens {
        match token.kind {
            TokenKind::ObjOpen  => { ctx.push_obj(); out.push(token.clone()); }
            TokenKind::ObjClose => { ctx.pop();      out.push(token.clone()); }
            TokenKind::ArrOpen  => { ctx.push_arr(); out.push(token.clone()); }
            TokenKind::ArrClose => { ctx.pop();      out.push(token.clone()); }

            TokenKind::Key => {
                if let TokenPayload::Str(ref k) = token.payload {
                    ctx.set_key(k.clone());
                }
                out.push(token.clone());
            }

            TokenKind::Str => {
                let path = ctx.current_path();
                // Try to encode as enum index
                if let (TokenPayload::Str(ref s), Some(idx)) = (
                    &token.payload,
                    schema.enum_variant_index(&path, token_str(token)),
                ) {
                    let _ = s; // consumed in enum_variant_index
                    out.push(Token {
                        kind:    TokenKind::NumInt,
                        payload: TokenPayload::Int(idx as i64),
                    });
                } else {
                    out.push(token.clone());
                }
                ctx.clear_key();
            }

            // Numeric / bool / null: pass through, clear key context
            TokenKind::NumInt | TokenKind::NumFloat | TokenKind::Bool | TokenKind::Null => {
                out.push(token.clone());
                ctx.clear_key();
            }
        }
    }
    out
}

/// Restore enum-encoded `NumInt` tokens back to their `Str` values.
///
/// A `NumInt` at a path the schema classifies as `Enum` is decoded back to
/// `Str(variants[idx])`.  A `NumInt` at a path the schema classifies as
/// `Integer` (or any non-Enum path) is left unchanged — the two are
/// distinguishable by the schema alone.
pub fn schema_decode_tokens(tokens: &[Token], schema: &FileSchema) -> Vec<Token> {
    let mut out = Vec::with_capacity(tokens.len());
    let mut ctx = RewriteCtx::new();

    for token in tokens {
        match token.kind {
            TokenKind::ObjOpen  => { ctx.push_obj(); out.push(token.clone()); }
            TokenKind::ObjClose => { ctx.pop();      out.push(token.clone()); }
            TokenKind::ArrOpen  => { ctx.push_arr(); out.push(token.clone()); }
            TokenKind::ArrClose => { ctx.pop();      out.push(token.clone()); }

            TokenKind::Key => {
                if let TokenPayload::Str(ref k) = token.payload {
                    ctx.set_key(k.clone());
                }
                out.push(token.clone());
            }

            TokenKind::NumInt => {
                let path = ctx.current_path();
                if let TokenPayload::Int(idx) = token.payload {
                    if let Some(s) = schema.enum_variant_str(&path, idx as u32) {
                        out.push(Token {
                            kind:    TokenKind::Str,
                            payload: TokenPayload::Str(s.to_owned()),
                        });
                        ctx.clear_key();
                        continue;
                    }
                }
                out.push(token.clone());
                ctx.clear_key();
            }

            TokenKind::Str | TokenKind::NumFloat | TokenKind::Bool | TokenKind::Null => {
                out.push(token.clone());
                ctx.clear_key();
            }
        }
    }
    out
}

// ── Internal: shared path-context for rewriting ───────────────────────────────

enum RFrame {
    Object { last_key: Option<String> },
    Array,
}

struct RewriteCtx {
    frames: Vec<RFrame>,
}

impl RewriteCtx {
    fn new() -> Self { Self { frames: Vec::new() } }

    fn push_obj(&mut self) { self.frames.push(RFrame::Object { last_key: None }); }
    fn push_arr(&mut self) { self.frames.push(RFrame::Array); }
    fn pop(&mut self)      { self.frames.pop(); }

    fn set_key(&mut self, k: String) {
        if let Some(RFrame::Object { last_key }) = self.frames.last_mut() {
            *last_key = Some(k);
        }
    }

    fn current_path(&self) -> String {
        self.frames
            .iter()
            .filter_map(|f| {
                if let RFrame::Object { last_key: Some(k) } = f { Some(k.as_str()) }
                else { None }
            })
            .collect::<Vec<_>>()
            .join(".")
    }

    fn clear_key(&mut self) {
        if let Some(RFrame::Object { last_key }) = self.frames.last_mut() {
            *last_key = None;
        }
    }
}

/// Extract string payload from a Str token (panics if not Str token).
fn token_str(t: &Token) -> &str {
    match &t.payload {
        TokenPayload::Str(s) => s.as_str(),
        _ => "",
    }
}

// ── Delta encoding (Phase 6) ──────────────────────────────────────────────────

/// Delta-encode integer fields in a token stream.
///
/// For each field path classified as `FieldType::Integer` by `schema`,
/// replaces each `NumInt(v)` token with `NumInt(v - prev)` where `prev`
/// is the last value seen at that field path (starting from 0).
///
/// Enum-encoded `NumInt` tokens (produced by `schema_encode_tokens`) are
/// NOT delta-encoded — they are identified by `FieldType::Enum` in the schema.
///
/// Returns `(encoded_tokens, delta_bytes)` where `delta_bytes` is the
/// serialized DELTA section payload (list of delta-encoded field paths).
pub fn delta_encode_tokens(tokens: &[Token], schema: &FileSchema) -> (Vec<Token>, Vec<u8>) {
    let mut out          = Vec::with_capacity(tokens.len());
    let mut ctx          = RewriteCtx::new();
    let mut last_seen: HashMap<String, i64> = HashMap::new();
    let mut delta_paths: Vec<String>        = Vec::new();

    for token in tokens {
        match token.kind {
            TokenKind::ObjOpen  => { ctx.push_obj(); out.push(token.clone()); }
            TokenKind::ObjClose => { ctx.pop();      out.push(token.clone()); }
            TokenKind::ArrOpen  => { ctx.push_arr(); out.push(token.clone()); }
            TokenKind::ArrClose => { ctx.pop();      out.push(token.clone()); }

            TokenKind::Key => {
                if let TokenPayload::Str(ref k) = token.payload { ctx.set_key(k.clone()); }
                out.push(token.clone());
            }

            TokenKind::NumInt => {
                let path = ctx.current_path();
                if matches!(schema.field_type(&path), Some(FieldType::Integer { .. })) {
                    if let TokenPayload::Int(v) = token.payload {
                        let prev  = *last_seen.get(&path).unwrap_or(&0);
                        let delta = v - prev;
                        last_seen.insert(path.clone(), v);
                        if !delta_paths.contains(&path) {
                            delta_paths.push(path);
                        }
                        out.push(Token {
                            kind:    TokenKind::NumInt,
                            payload: TokenPayload::Int(delta),
                        });
                        ctx.clear_key();
                        continue;
                    }
                }
                out.push(token.clone());
                ctx.clear_key();
            }

            _ => {
                out.push(token.clone());
                ctx.clear_key();
            }
        }
    }

    let delta_bytes = serialize_delta_paths(&delta_paths);
    (out, delta_bytes)
}

/// Reverse delta encoding: reconstruct original integer values from deltas.
///
/// `delta_bytes` is the DELTA section payload produced by `delta_encode_tokens`.
/// An empty `delta_bytes` slice is a no-op.
pub fn delta_decode_tokens(
    tokens: &[Token],
    _schema: &FileSchema,
    delta_bytes: &[u8],
) -> Vec<Token> {
    let delta_paths = deserialize_delta_paths(delta_bytes);
    if delta_paths.is_empty() {
        return tokens.to_vec();
    }

    let mut out      = Vec::with_capacity(tokens.len());
    let mut ctx      = RewriteCtx::new();
    let mut last_seen: HashMap<String, i64> = HashMap::new();

    for token in tokens {
        match token.kind {
            TokenKind::ObjOpen  => { ctx.push_obj(); out.push(token.clone()); }
            TokenKind::ObjClose => { ctx.pop();      out.push(token.clone()); }
            TokenKind::ArrOpen  => { ctx.push_arr(); out.push(token.clone()); }
            TokenKind::ArrClose => { ctx.pop();      out.push(token.clone()); }

            TokenKind::Key => {
                if let TokenPayload::Str(ref k) = token.payload { ctx.set_key(k.clone()); }
                out.push(token.clone());
            }

            TokenKind::NumInt => {
                let path = ctx.current_path();
                if delta_paths.contains(&path) {
                    if let TokenPayload::Int(delta) = token.payload {
                        let prev  = *last_seen.get(&path).unwrap_or(&0);
                        let value = prev + delta;
                        last_seen.insert(path, value);
                        out.push(Token {
                            kind:    TokenKind::NumInt,
                            payload: TokenPayload::Int(value),
                        });
                        ctx.clear_key();
                        continue;
                    }
                }
                out.push(token.clone());
                ctx.clear_key();
            }

            _ => {
                out.push(token.clone());
                ctx.clear_key();
            }
        }
    }
    out
}

fn serialize_delta_paths(paths: &[String]) -> Vec<u8> {
    use crate::varint::encode_u64;
    if paths.is_empty() { return Vec::new(); }
    let mut out = Vec::new();
    encode_u64(paths.len() as u64, &mut out);
    for p in paths {
        let b = p.as_bytes();
        encode_u64(b.len() as u64, &mut out);
        out.extend_from_slice(b);
    }
    out
}

fn deserialize_delta_paths(data: &[u8]) -> Vec<String> {
    use crate::varint::decode_u64;
    if data.is_empty() { return Vec::new(); }
    let mut paths = Vec::new();
    let mut pos   = 0usize;
    let (count, n) = match decode_u64(data, pos) { Some(v) => v, None => return paths };
    pos += n;
    for _ in 0..count {
        let (len, n) = match decode_u64(data, pos) { Some(v) => v, None => break };
        pos += n;
        let end = pos + len as usize;
        if end > data.len() { break; }
        if let Ok(s) = std::str::from_utf8(&data[pos..end]) {
            paths.push(s.to_owned());
        }
        pos = end;
    }
    paths
}

// ── JSON reconstruction ───────────────────────────────────────────────────────

/// Reconstruct compact JSON bytes from a decoded token stream.
///
/// Produces compact JSON (no whitespace). Object keys are emitted in
/// declaration order, matching the original document order.
pub fn tokens_to_json(tokens: &[Token]) -> Vec<u8> {
    let mut out   = Vec::new();
    // Stack: (is_object, items_written_so_far)
    let mut stack: Vec<(bool, usize)> = Vec::new();

    for token in tokens {
        match token.kind {
            TokenKind::ObjOpen => {
                // In array context: comma before this value.
                if let Some((false, ref mut cnt)) = stack.last_mut() {
                    if *cnt > 0 { out.push(b','); }
                    *cnt += 1;
                }
                out.push(b'{');
                stack.push((true, 0));
            }
            TokenKind::ObjClose => {
                stack.pop();
                out.push(b'}');
            }
            TokenKind::ArrOpen => {
                if let Some((false, ref mut cnt)) = stack.last_mut() {
                    if *cnt > 0 { out.push(b','); }
                    *cnt += 1;
                }
                out.push(b'[');
                stack.push((false, 0));
            }
            TokenKind::ArrClose => {
                stack.pop();
                out.push(b']');
            }
            TokenKind::Key => {
                // Comma before each key-value pair except the first.
                if let Some((true, ref mut cnt)) = stack.last_mut() {
                    if *cnt > 0 { out.push(b','); }
                    *cnt += 1;
                }
                if let TokenPayload::Str(ref s) = token.payload {
                    json_write_str(s, &mut out);
                    out.push(b':');
                }
            }
            TokenKind::Str => {
                if let Some((false, ref mut cnt)) = stack.last_mut() {
                    if *cnt > 0 { out.push(b','); }
                    *cnt += 1;
                }
                if let TokenPayload::Str(ref s) = token.payload {
                    json_write_str(s, &mut out);
                }
            }
            TokenKind::NumInt => {
                if let Some((false, ref mut cnt)) = stack.last_mut() {
                    if *cnt > 0 { out.push(b','); }
                    *cnt += 1;
                }
                if let TokenPayload::Int(n) = token.payload {
                    json_write_int(n, &mut out);
                }
            }
            TokenKind::NumFloat => {
                if let Some((false, ref mut cnt)) = stack.last_mut() {
                    if *cnt > 0 { out.push(b','); }
                    *cnt += 1;
                }
                if let TokenPayload::Float(f) = token.payload {
                    json_write_float(f, &mut out);
                }
            }
            TokenKind::Bool => {
                if let Some((false, ref mut cnt)) = stack.last_mut() {
                    if *cnt > 0 { out.push(b','); }
                    *cnt += 1;
                }
                match token.payload {
                    TokenPayload::Bool(true)  => out.extend_from_slice(b"true"),
                    TokenPayload::Bool(false) => out.extend_from_slice(b"false"),
                    _ => {}
                }
            }
            TokenKind::Null => {
                if let Some((false, ref mut cnt)) = stack.last_mut() {
                    if *cnt > 0 { out.push(b','); }
                    *cnt += 1;
                }
                out.extend_from_slice(b"null");
            }
        }
    }
    out
}

fn json_write_str(s: &str, out: &mut Vec<u8>) {
    const HEX: &[u8] = b"0123456789abcdef";
    out.push(b'"');
    for b in s.bytes() {
        match b {
            b'"'  => out.extend_from_slice(br#"\""#),
            b'\\' => out.extend_from_slice(br"\\"),
            b'\n' => out.extend_from_slice(br"\n"),
            b'\r' => out.extend_from_slice(br"\r"),
            b'\t' => out.extend_from_slice(br"\t"),
            b if b < 0x20 => {
                out.extend_from_slice(b"\\u00");
                out.push(HEX[(b >> 4) as usize]);
                out.push(HEX[(b & 0xF) as usize]);
            }
            b => out.push(b),
        }
    }
    out.push(b'"');
}

fn json_write_int(n: i64, out: &mut Vec<u8>) {
    out.extend_from_slice(n.to_string().as_bytes());
}

fn json_write_float(f: f64, out: &mut Vec<u8>) {
    out.extend_from_slice(format!("{f}").as_bytes());
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipelines::text::tokenizer::tokenize_json;
    use crate::schema::inferencer::FileSchema;

    fn tokens(json: &str) -> Vec<Token> {
        tokenize_json(json.as_bytes()).unwrap()
    }

    fn schema(json: &str) -> FileSchema {
        FileSchema::build(&tokens(json))
    }

    // ── schema_encode_tokens ──────────────────────────────────────────────────

    #[test]
    fn enum_str_replaced_with_numint() {
        let json = r#"[{"role":"admin"},{"role":"user"},{"role":"admin"}]"#;
        let toks   = tokens(json);
        let schema = schema(json);
        let rw     = schema_encode_tokens(&toks, &schema);

        // Every "Str" at "role" path should be replaced by NumInt
        let mut found_int = false;
        for t in &rw {
            if t.kind == TokenKind::NumInt {
                if let TokenPayload::Int(idx) = t.payload {
                    assert!(idx == 0 || idx == 1, "unexpected enum index {idx}");
                    found_int = true;
                }
            }
        }
        assert!(found_int, "no NumInt found after rewrite");

        // No Str with value "admin" or "user" should remain
        for t in &rw {
            if let TokenPayload::Str(ref s) = t.payload {
                assert_ne!(s, "admin");
                assert_ne!(s, "user");
            }
        }
    }

    #[test]
    fn non_enum_str_is_unchanged() {
        // 65 unique names → Str field, not Enum
        let entries: String = (0..65)
            .map(|i| format!(r#"{{"name":"user_{i}"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let json   = format!("[{entries}]");
        let toks   = tokens(&json);
        let schema = schema(&json);
        let rw     = schema_encode_tokens(&toks, &schema);

        // Str tokens should remain (no NumInt replacement)
        let orig_str_count = toks.iter().filter(|t| t.kind == TokenKind::Str).count();
        let rw_str_count   = rw.iter().filter(|t| t.kind == TokenKind::Str).count();
        assert_eq!(orig_str_count, rw_str_count);
    }

    // ── schema_decode_tokens ──────────────────────────────────────────────────

    #[test]
    fn encode_decode_tokens_roundtrip() {
        let json   = r#"[{"status":"ok","code":200},{"status":"fail","code":404}]"#;
        let toks   = tokens(json);
        let schema = schema(json);

        let encoded = schema_encode_tokens(&toks, &schema);
        let decoded = schema_decode_tokens(&encoded, &schema);
        assert_eq!(toks, decoded, "token roundtrip failed");
    }

    #[test]
    fn integer_at_enum_path_not_mangled() {
        // Make sure a real integer field is not confused with an enum index
        let json   = r#"[{"id":42},{"id":99}]"#;
        let toks   = tokens(json);
        let schema = schema(json);

        let encoded = schema_encode_tokens(&toks, &schema);
        let decoded = schema_decode_tokens(&encoded, &schema);
        assert_eq!(toks, decoded);
    }

    // ── full two-pass encode ──────────────────────────────────────────────────

    #[test]
    fn encode_json_two_pass_produces_output() {
        let json = r#"[{"status":"ok","code":200},{"status":"fail","code":404}]"#;
        let out  = encode_json_two_pass(json.as_bytes(), 1).unwrap();
        assert!(!out.token_bytes.is_empty());
        assert!(!out.schema_bytes.is_empty());
    }

    #[test]
    fn two_pass_schema_bytes_valid() {
        let json = r#"[{"role":"admin"},{"role":"user"},{"role":"admin"}]"#;
        let out  = encode_json_two_pass(json.as_bytes(), 1).unwrap();
        // schema_bytes should deserialize back cleanly
        let rt = serializer::deserialize(&out.schema_bytes).unwrap();
        assert!(rt.has_field("role"));
    }

    #[test]
    fn two_pass_smaller_than_naive_for_enum_input() {
        // Build a 500-record dataset with 3 enum fields
        let records: String = (0..500)
            .map(|i| {
                let status = if i % 3 == 0 { "ok" } else if i % 3 == 1 { "warn" } else { "fail" };
                let tier   = if i % 4 == 0 { "free" } else if i % 4 == 1 { "pro" }
                             else if i % 4 == 2 { "ent" } else { "trial" };
                let env    = if i % 2 == 0 { "prod" } else { "staging" };
                format!(r#"{{"id":{i},"status":"{status}","tier":"{tier}","env":"{env}"}}"#)
            })
            .collect::<Vec<_>>()
            .join(",");
        let json = format!("[{records}]");

        // Naive single-pass
        let toks_naive   = tokenize_json(json.as_bytes()).unwrap();
        let dict_naive   = Dictionary::build(&toks_naive, 2);
        let enc_naive    = encode_with_dict(&toks_naive, &dict_naive);
        let bytes_naive  = encode_token_bytes(&enc_naive).unwrap();

        // Two-pass
        let out = encode_json_two_pass(json.as_bytes(), 2).unwrap();

        // Two-pass TOKENS should be smaller
        assert!(
            out.token_bytes.len() < bytes_naive.len(),
            "two-pass ({} B) not smaller than naive ({} B)",
            out.token_bytes.len(), bytes_naive.len()
        );
    }
}
