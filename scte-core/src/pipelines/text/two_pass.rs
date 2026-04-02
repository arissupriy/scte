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
use crate::pipelines::text::{
    dictionary::{Dictionary, EncodedToken},
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
    /// rANS-compressed token stream — write to TOKENS section.
    pub token_bytes: Vec<u8>,
    /// Dictionary used — needed for decoding (caller stores in DICT section).
    pub dict: Dictionary,
    /// Schema used — kept for roundtrip testing / decode.
    pub schema: FileSchema,
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

    // Pass 2: rewrite + encode
    let rewritten = schema_encode_tokens(&tokens, &schema);
    let dict = Dictionary::build(&rewritten, dict_min_freq);
    let encoded = encode_with_dict(&rewritten, &dict);
    let token_bytes = encode_token_bytes(&encoded)
        .map_err(|e| ScteError::EncodeError(format!("token_bytes: {e}")))?;
    let schema_bytes = serializer::serialize(&schema);

    Ok(TwoPassOutput { schema_bytes, token_bytes, dict, schema })
}

/// Decode a two-pass compressed token stream back to `EncodedToken`s,
/// with enum indices restored to their string values.
///
/// `token_bytes` is the rANS-compressed TOKENS section payload.
/// `dict` is the dictionary from the DICT section.
/// `schema` is the schema from the SCHEMA section.
///
/// Returns the fully decoded token stream (enum strings restored).
pub fn decode_token_stream(
    token_bytes: &[u8],
    dict: &Dictionary,
    schema: &FileSchema,
) -> Result<Vec<EncodedToken>, ScteError> {
    let encoded = decode_token_bytes(token_bytes)?;
    let mut tokens = decode_with_dict(&encoded, dict)?;

    // Restore enum-encoded NumInt tokens to Str
    tokens = schema_decode_tokens(&tokens, schema);

    // Re-encode as EncodedToken (no dict substitution; just convert types)
    let result = encode_with_dict(&tokens, &Dictionary::empty());
    Ok(result)
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
