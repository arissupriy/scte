/// JSON-specific entropy codec — sits between Phase 3 (dictionary) and
/// the generic `entropy::codec` byte-stream encoder.
///
/// # Responsibilities
/// - Mapping `TokenKind` ↔ `u8` (alphabet = 10 kinds, values 0..=9)
/// - Serializing / deserializing per-token payloads (DictId, literals,
///   integers, floats, booleans)
/// - Calling `entropy::codec::{encode, decode}` with `alphabet_size = 10`
///
/// # Wire format (TOKENS section payload)
/// ```text
/// [entropy blob]    ← entropy::codec::encode(kind_bytes, 10)
/// [payload stream]  ← one entry per token, in token order
/// ```
///
/// The entropy blob is self-contained (stores symbol_count + alphabet_size
/// internally), so the payload stream starts immediately after.
///
/// # Payload encoding per kind
///
/// | Kind              | Encoding                                             |
/// |-------------------|------------------------------------------------------|
/// | ObjOpen/Close     | nothing                                              |
/// | ArrOpen/Close     | nothing                                              |
/// | Null              | nothing                                              |
/// | Key / Str         | DictId  → varint(id)  (id < 65535)                  |
/// |                   | Literal → varint(65535) + varint(len) + utf8_bytes  |
/// | NumInt            | ZigZag + LEB128 (`encode_i64`)                      |
/// | NumFloat          | 8 bytes f64 IEEE 754 little-endian                  |
/// | Bool              | 1 byte: 0x00 = false, 0x01 = true                   |

use crate::{
    entropy::codec as entropy_codec,
    error::ScteError,
    pipelines::text::{
        dictionary::{EncodedPayload, EncodedToken},
        tokenizer::TokenKind,
    },
    varint::{decode_i64, decode_u64, decode_usize, encode_i64, encode_u64, encode_usize},
};

/// Number of distinct TokenKind variants used as rANS alphabet.
/// ObjOpen=0 .. Null=9.
pub const TOKEN_KIND_ALPHABET: usize = 10;

/// Sentinel used in Key/Str payload to signal a literal (non-dict) string.
/// Valid DictId values are 0..=65534; 65535 is therefore safe as sentinel.
const LITERAL_SENTINEL: u64 = 65535;

// ── TokenKind ↔ u8 ────────────────────────────────────────────────────────────

/// Map `TokenKind` to its canonical byte value (0..=9).
pub fn kind_to_byte(kind: TokenKind) -> u8 {
    match kind {
        TokenKind::ObjOpen  => 0,
        TokenKind::ObjClose => 1,
        TokenKind::ArrOpen  => 2,
        TokenKind::ArrClose => 3,
        TokenKind::Key      => 4,
        TokenKind::Str      => 5,
        TokenKind::NumInt   => 6,
        TokenKind::NumFloat => 7,
        TokenKind::Bool     => 8,
        TokenKind::Null     => 9,
    }
}

/// Map a byte value back to `TokenKind`.  Returns `None` for unknown bytes.
pub fn byte_to_kind(b: u8) -> Option<TokenKind> {
    match b {
        0 => Some(TokenKind::ObjOpen),
        1 => Some(TokenKind::ObjClose),
        2 => Some(TokenKind::ArrOpen),
        3 => Some(TokenKind::ArrClose),
        4 => Some(TokenKind::Key),
        5 => Some(TokenKind::Str),
        6 => Some(TokenKind::NumInt),
        7 => Some(TokenKind::NumFloat),
        8 => Some(TokenKind::Bool),
        9 => Some(TokenKind::Null),
        _ => None,
    }
}

// ── Encode ────────────────────────────────────────────────────────────────────

/// Serialize a dictionary-encoded JSON token stream to a compact binary blob.
///
/// Internally calls `entropy::codec::encode` with `alphabet_size = 10`.
///
/// # Errors
/// `ScteError::EncodeError` / `ScteError::DecodeError` on failure.
pub fn encode_token_bytes(tokens: &[EncodedToken]) -> Result<Vec<u8>, ScteError> {
    // ── 1. extract kind stream ────────────────────────────────────────────────
    let kind_bytes: Vec<u8> = tokens.iter().map(|t| kind_to_byte(t.kind)).collect();

    // ── 2. entropy-encode kind stream (generic, format-agnostic) ─────────────
    let entropy_blob = entropy_codec::encode(&kind_bytes, TOKEN_KIND_ALPHABET)?;

    // ── 3. serialize payloads ─────────────────────────────────────────────────
    let mut payload_buf: Vec<u8> = Vec::new();
    for token in tokens {
        encode_payload(token, &mut payload_buf);
    }

    // ── 4. concatenate ────────────────────────────────────────────────────────
    let mut out = Vec::with_capacity(entropy_blob.len() + payload_buf.len());
    out.extend_from_slice(&entropy_blob);
    out.extend_from_slice(&payload_buf);
    Ok(out)
}

fn encode_payload(token: &EncodedToken, out: &mut Vec<u8>) {
    match &token.payload {
        EncodedPayload::None => {}

        EncodedPayload::Bool(b) => {
            out.push(if *b { 0x01 } else { 0x00 });
        }

        EncodedPayload::Int(n) => {
            encode_i64(*n, out);
        }

        EncodedPayload::Float(f) => {
            out.extend_from_slice(&f.to_le_bytes());
        }

        EncodedPayload::DictId(id) => {
            encode_u64(*id as u64, out);
        }

        EncodedPayload::Str(s) => {
            encode_u64(LITERAL_SENTINEL, out);
            let bytes = s.as_bytes();
            encode_usize(bytes.len(), out);
            out.extend_from_slice(bytes);
        }
    }
}

// ── Decode ────────────────────────────────────────────────────────────────────

/// Deserialize a blob produced by `encode_token_bytes` back to `EncodedToken`s.
///
/// # Errors
/// `ScteError::DecodeError` for truncated or corrupted data.
pub fn decode_token_bytes(data: &[u8]) -> Result<Vec<EncodedToken>, ScteError> {
    let mut pos = 0;

    // ── 1. decode kind stream (generic entropy codec) ─────────────────────────
    let (kind_bytes, consumed) = entropy_codec::decode(data, pos)?;
    pos += consumed;

    // ── 2. decode payloads ────────────────────────────────────────────────────
    let mut tokens = Vec::with_capacity(kind_bytes.len());
    for (i, &kb) in kind_bytes.iter().enumerate() {
        let kind = byte_to_kind(kb).ok_or_else(|| {
            ScteError::DecodeError(format!(
                "text/entropic: unknown kind byte {kb:#04X} at index {i}"
            ))
        })?;

        let (payload, n) = decode_payload(kind, data, pos)?;
        pos += n;
        tokens.push(EncodedToken { kind, payload });
    }

    Ok(tokens)
}

fn decode_payload(
    kind: TokenKind,
    data: &[u8],
    pos: usize,
) -> Result<(EncodedPayload, usize), ScteError> {
    match kind {
        TokenKind::ObjOpen
        | TokenKind::ObjClose
        | TokenKind::ArrOpen
        | TokenKind::ArrClose
        | TokenKind::Null => Ok((EncodedPayload::None, 0)),

        TokenKind::Bool => {
            if pos >= data.len() {
                return Err(ScteError::DecodeError(
                    "text/entropic: truncated Bool payload".into(),
                ));
            }
            let b = match data[pos] {
                0x00 => false,
                0x01 => true,
                v => {
                    return Err(ScteError::DecodeError(format!(
                        "text/entropic: invalid Bool byte {v:#04X}"
                    )))
                }
            };
            Ok((EncodedPayload::Bool(b), 1))
        }

        TokenKind::NumInt => {
            let (n, c) = decode_i64(data, pos).ok_or_else(|| {
                ScteError::DecodeError("text/entropic: truncated NumInt payload".into())
            })?;
            Ok((EncodedPayload::Int(n), c))
        }

        TokenKind::NumFloat => {
            if pos + 8 > data.len() {
                return Err(ScteError::DecodeError(
                    "text/entropic: truncated NumFloat payload".into(),
                ));
            }
            let f = f64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
            Ok((EncodedPayload::Float(f), 8))
        }

        TokenKind::Key | TokenKind::Str => {
            let (tag, c) = decode_u64(data, pos).ok_or_else(|| {
                ScteError::DecodeError("text/entropic: truncated Key/Str tag".into())
            })?;
            let mut consumed = c;

            if tag == LITERAL_SENTINEL {
                let (len, c2) = decode_usize(data, pos + consumed).ok_or_else(|| {
                    ScteError::DecodeError(
                        "text/entropic: truncated literal string length".into(),
                    )
                })?;
                consumed += c2;
                let start = pos + consumed;
                if start + len > data.len() {
                    return Err(ScteError::DecodeError(
                        "text/entropic: literal string overruns buffer".into(),
                    ));
                }
                let s = std::str::from_utf8(&data[start..start + len])
                    .map_err(|e| {
                        ScteError::DecodeError(format!("text/entropic: invalid UTF-8: {e}"))
                    })?
                    .to_owned();
                consumed += len;
                Ok((EncodedPayload::Str(s), consumed))
            } else {
                let id = u16::try_from(tag).map_err(|_| {
                    ScteError::DecodeError(format!(
                        "text/entropic: dict id {tag} exceeds u16"
                    ))
                })?;
                Ok((EncodedPayload::DictId(id), consumed))
            }
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipelines::text::{
        dictionary::{encode_with_dict, Dictionary},
        tokenizer::tokenize_json,
    };

    fn make_encoded(json: &str) -> Vec<EncodedToken> {
        let toks = tokenize_json(json.as_bytes()).unwrap();
        let dict = Dictionary::build(&toks, 1);
        encode_with_dict(&toks, &dict)
    }

    // ── kind_to_byte / byte_to_kind ───────────────────────────────────────────

    #[test]
    fn kind_byte_roundtrip_all_variants() {
        let kinds = [
            TokenKind::ObjOpen,  TokenKind::ObjClose,
            TokenKind::ArrOpen,  TokenKind::ArrClose,
            TokenKind::Key,      TokenKind::Str,
            TokenKind::NumInt,   TokenKind::NumFloat,
            TokenKind::Bool,     TokenKind::Null,
        ];
        for k in kinds {
            assert_eq!(byte_to_kind(kind_to_byte(k)), Some(k),
                "roundtrip failed for {k:?}");
        }
    }

    #[test]
    fn byte_to_kind_unknown_returns_none() {
        assert!(byte_to_kind(10).is_none());
        assert!(byte_to_kind(255).is_none());
    }

    // ── Roundtrip ─────────────────────────────────────────────────────────────

    #[test]
    fn roundtrip_simple_object() {
        let enc     = make_encoded(r#"{"name":"Alice","role":"admin"}"#);
        let bytes   = encode_token_bytes(&enc).unwrap();
        let decoded = decode_token_bytes(&bytes).unwrap();
        assert_eq!(enc, decoded);
    }

    #[test]
    fn roundtrip_nested_object() {
        let enc     = make_encoded(r#"{"user":{"id":1,"name":"Alice"},"active":true}"#);
        let bytes   = encode_token_bytes(&enc).unwrap();
        let decoded = decode_token_bytes(&bytes).unwrap();
        assert_eq!(enc, decoded);
    }

    #[test]
    fn roundtrip_all_payload_types() {
        let enc = make_encoded(
            r#"{"active":true,"count":42,"label":"x","nothing":null,"ratio":1.5}"#,
        );
        let bytes   = encode_token_bytes(&enc).unwrap();
        let decoded = decode_token_bytes(&bytes).unwrap();
        assert_eq!(enc, decoded);
    }

    #[test]
    fn roundtrip_negative_integer() {
        let enc     = make_encoded(r#"{"delta":-1024}"#);
        let bytes   = encode_token_bytes(&enc).unwrap();
        let decoded = decode_token_bytes(&bytes).unwrap();
        assert_eq!(enc, decoded);
    }

    #[test]
    fn roundtrip_literal_string_fallback() {
        let toks = tokenize_json(br#"{"name":"Alice"}"#).unwrap();
        let enc  = encode_with_dict(&toks, &Dictionary::empty());
        let has_literal = enc.iter().any(|t| matches!(t.payload, EncodedPayload::Str(_)));
        assert!(has_literal, "expected literal string payloads");
        let bytes   = encode_token_bytes(&enc).unwrap();
        let decoded = decode_token_bytes(&bytes).unwrap();
        assert_eq!(enc, decoded);
    }

    #[test]
    fn roundtrip_array_of_objects() {
        let enc = make_encoded(r#"[
            {"id":1,"name":"Alice","role":"admin"},
            {"id":2,"name":"Bob",  "role":"user"},
            {"id":3,"name":"Carol","role":"user"},
            {"id":4,"name":"Dave", "role":"admin"}
        ]"#);
        let bytes   = encode_token_bytes(&enc).unwrap();
        let decoded = decode_token_bytes(&bytes).unwrap();
        assert_eq!(enc, decoded);
    }

    // ── Compression ───────────────────────────────────────────────────────────

    #[test]
    fn encoded_bytes_smaller_than_naive_for_large_input() {
        let mut json = String::from("[");
        for i in 0..200 {
            if i > 0 { json.push(','); }
            json.push_str(&format!(r#"{{"id":{i},"name":"user_{i}","active":true}}"#));
        }
        json.push(']');
        let enc   = make_encoded(&json);
        let bytes = encode_token_bytes(&enc).unwrap();
        assert!(bytes.len() < json.len(),
            "encoded ({}) should be smaller than raw JSON ({})",
            bytes.len(), json.len());
    }

    // ── Error handling ────────────────────────────────────────────────────────

    #[test]
    fn decode_empty_buffer_returns_error() {
        assert!(decode_token_bytes(&[]).is_err());
    }

    #[test]
    fn decode_truncated_stream_returns_error() {
        let enc   = make_encoded(r#"{"a":1}"#);
        let bytes = encode_token_bytes(&enc).unwrap();
        let truncated = &bytes[..bytes.len().saturating_sub(10)];
        assert!(decode_token_bytes(truncated).is_err());
    }
}
