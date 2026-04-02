/// TOKENS section wire format encoder / decoder.
///
/// Combines Phase 3 (dictionary-encoded token stream) with Phase 4 (rANS
/// entropy coding) into the final binary payload written to the `TOKENS(0x02)`
/// section of the SCTE container.
///
/// # Wire format
/// ```text
/// varint(token_count)
/// [FreqTable bytes]                     ← serialize() / deserialize()
/// varint(kinds_compressed_len)
/// [rANS-compressed token kind stream]   ← entropy/rans.rs
/// [payload stream]                      ← see below, one entry per token
/// ```
///
/// # Payload encoding per token kind
///
/// | Kind              | Payload encoding                                       |
/// |-------------------|--------------------------------------------------------|
/// | `ObjOpen/Close`   | nothing (structural, no payload)                       |
/// | `ArrOpen/Close`   | nothing                                                |
/// | `Null`            | nothing                                                |
/// | `Key` / `Str`     | DictId → `varint(id)` (id < 65535)                    |
/// |                   | Literal → `varint(65535) + varint(len) + utf8_bytes`   |
/// | `NumInt`          | ZigZag + LEB128 (`encode_i64`)                        |
/// | `NumFloat`        | raw 8 bytes, f64 IEEE 754 little-endian               |
/// | `Bool`            | 1 byte: `0x00` = false, `0x01` = true                 |
///
/// Value 65535 is the literal-string sentinel for Key/Str payloads.
/// Valid `DictId` values are 0..=65534 (max 65535 dict entries).

use crate::{
    entropy::{frequency::{FreqTable, DEFAULT_M_BITS}, rans},
    error::ScteError,
    pipelines::text::{
        dictionary::{EncodedPayload, EncodedToken},
        tokenizer::TokenKind,
    },
    varint::{decode_i64, decode_u64, decode_usize, encode_i64, encode_u64, encode_usize},
};

/// Literal-string sentinel for Key/Str payload encoding.
/// Any `varint(65535)` in the payload stream signals a literal string follows.
const LITERAL_SENTINEL: u64 = 65535;

/// Number of distinct TokenKind variants (alphabet size for rANS).
/// Values: ObjOpen=0, ObjClose=1, ArrOpen=2, ArrClose=3, Key=4,
///         Str=5, NumInt=6, NumFloat=7, Bool=8, Null=9.
pub const TOKEN_KIND_ALPHABET: usize = 10;

// ── TokenKind ↔ u8 ────────────────────────────────────────────────────────────

/// Canonical byte value for each `TokenKind`.
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

/// Decode a byte value back to `TokenKind`.
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

/// Serialize a dictionary-encoded token stream to the TOKENS section payload.
///
/// # Steps
/// 1. Extract the kind stream (`Vec<u8>`) from the tokens.
/// 2. Build a `FreqTable` from the kind stream.
/// 3. rANS-encode the kind stream.
/// 4. Serialize payloads in token order.
/// 5. Concatenate: token_count + freq_table + kinds_len + kinds + payloads.
///
/// # Errors
/// `ScteError::DecodeError` if rANS encoding fails (zero-frequency symbol —
/// should never occur since the freq table is built from the same stream).
pub fn encode_token_bytes(tokens: &[EncodedToken]) -> Result<Vec<u8>, ScteError> {
    // ── 1. kind stream ────────────────────────────────────────────────────────
    let kind_bytes: Vec<u8> = tokens.iter().map(|t| kind_to_byte(t.kind)).collect();

    // ── 2. frequency table ────────────────────────────────────────────────────
    let freq = FreqTable::build(&kind_bytes, TOKEN_KIND_ALPHABET, DEFAULT_M_BITS);

    // ── 3. rANS compress kinds ───────────────────────────────────────────────
    let compressed_kinds = rans::encode(&kind_bytes, &freq)?;

    // ── 4. payload stream ─────────────────────────────────────────────────────
    let mut payload_buf: Vec<u8> = Vec::new();
    for token in tokens {
        encode_payload(token, &mut payload_buf);
    }

    // ── 5. assemble output ────────────────────────────────────────────────────
    let mut out = Vec::new();
    encode_usize(tokens.len(), &mut out);

    let freq_bytes = freq.serialize();
    encode_usize(freq_bytes.len(), &mut out);
    out.extend_from_slice(&freq_bytes);

    encode_usize(compressed_kinds.len(), &mut out);
    out.extend_from_slice(&compressed_kinds);

    out.extend_from_slice(&payload_buf);
    Ok(out)
}

fn encode_payload(token: &EncodedToken, out: &mut Vec<u8>) {
    match &token.payload {
        // Structural tokens carry no payload.
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
            // id is always < 65535 (dict cap) — safe to cast.
            encode_u64(*id as u64, out);
        }

        EncodedPayload::Str(s) => {
            // Sentinel signals a literal string follows.
            encode_u64(LITERAL_SENTINEL, out);
            let bytes = s.as_bytes();
            encode_usize(bytes.len(), out);
            out.extend_from_slice(bytes);
        }
    }
}

// ── Decode ────────────────────────────────────────────────────────────────────

/// Deserialize a TOKENS section payload back to a dictionary-encoded
/// token stream.
///
/// # Errors
/// Returns `ScteError::DecodeError` for truncated, corrupted, or invalid data.
pub fn decode_token_bytes(data: &[u8]) -> Result<Vec<EncodedToken>, ScteError> {
    let mut pos = 0;

    // token_count
    let (count, c) = decode_usize(data, pos)
        .ok_or_else(|| ScteError::DecodeError("codec: truncated token_count".into()))?;
    pos += c;

    // freq table length + bytes
    let (freq_len, c) = decode_usize(data, pos)
        .ok_or_else(|| ScteError::DecodeError("codec: truncated freq_len".into()))?;
    pos += c;

    let (freq, freq_consumed) = FreqTable::deserialize(data, pos)?;
    if freq_consumed != freq_len {
        return Err(ScteError::DecodeError(format!(
            "codec: freq_len declared {freq_len} but parsed {freq_consumed}"
        )));
    }
    pos += freq_len;

    // rANS kinds
    let (kinds_len, c) = decode_usize(data, pos)
        .ok_or_else(|| ScteError::DecodeError("codec: truncated kinds_len".into()))?;
    pos += c;

    if pos + kinds_len > data.len() {
        return Err(ScteError::DecodeError("codec: kinds stream truncated".into()));
    }
    let (kind_bytes, kinds_consumed) = rans::decode(data, &freq, count, pos)?;
    if kinds_consumed != kinds_len {
        return Err(ScteError::DecodeError(format!(
            "codec: kinds_len declared {kinds_len} but decoded {kinds_consumed}"
        )));
    }
    pos += kinds_len;

    // payloads
    let mut tokens = Vec::with_capacity(count);
    for (i, &kb) in kind_bytes.iter().enumerate() {
        let kind = byte_to_kind(kb).ok_or_else(|| {
            ScteError::DecodeError(format!("codec: unknown kind byte {kb:#04X} at index {i}"))
        })?;

        let (payload, consumed) = decode_payload(kind, data, pos)?;
        pos += consumed;
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
                return Err(ScteError::DecodeError("codec: truncated Bool payload".into()));
            }
            let b = match data[pos] {
                0x00 => false,
                0x01 => true,
                v    => return Err(ScteError::DecodeError(
                    format!("codec: invalid Bool byte {v:#04X}"),
                )),
            };
            Ok((EncodedPayload::Bool(b), 1))
        }

        TokenKind::NumInt => {
            let (n, c) = decode_i64(data, pos)
                .ok_or_else(|| ScteError::DecodeError("codec: truncated NumInt payload".into()))?;
            Ok((EncodedPayload::Int(n), c))
        }

        TokenKind::NumFloat => {
            if pos + 8 > data.len() {
                return Err(ScteError::DecodeError("codec: truncated NumFloat payload".into()));
            }
            let f = f64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
            Ok((EncodedPayload::Float(f), 8))
        }

        TokenKind::Key | TokenKind::Str => {
            let (tag, c) = decode_u64(data, pos)
                .ok_or_else(|| ScteError::DecodeError("codec: truncated Key/Str tag".into()))?;
            let mut consumed = c;

            if tag == LITERAL_SENTINEL {
                // Literal string follows.
                let (len, c2) = decode_usize(data, pos + consumed)
                    .ok_or_else(|| ScteError::DecodeError(
                        "codec: truncated literal string length".into(),
                    ))?;
                consumed += c2;
                let start = pos + consumed;
                if start + len > data.len() {
                    return Err(ScteError::DecodeError("codec: literal string overruns buffer".into()));
                }
                let s = std::str::from_utf8(&data[start..start + len])
                    .map_err(|e| ScteError::DecodeError(format!("codec: invalid UTF-8: {e}")))?
                    .to_owned();
                consumed += len;
                Ok((EncodedPayload::Str(s), consumed))
            } else {
                // DictId.
                let id = u16::try_from(tag).map_err(|_| {
                    ScteError::DecodeError(format!("codec: dict id {tag} exceeds u16"))
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
            TokenKind::ObjOpen, TokenKind::ObjClose,
            TokenKind::ArrOpen, TokenKind::ArrClose,
            TokenKind::Key, TokenKind::Str,
            TokenKind::NumInt, TokenKind::NumFloat,
            TokenKind::Bool, TokenKind::Null,
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

    // ── Encode / decode roundtrip ─────────────────────────────────────────────

    #[test]
    fn roundtrip_simple_object() {
        let enc = make_encoded(r#"{"name":"Alice","role":"admin"}"#);
        let bytes  = encode_token_bytes(&enc).unwrap();
        let decoded = decode_token_bytes(&bytes).unwrap();
        assert_eq!(enc, decoded);
    }

    #[test]
    fn roundtrip_nested_object() {
        let enc = make_encoded(r#"{"user":{"id":1,"name":"Alice"},"active":true}"#);
        let bytes   = encode_token_bytes(&enc).unwrap();
        let decoded = decode_token_bytes(&bytes).unwrap();
        assert_eq!(enc, decoded);
    }

    #[test]
    fn roundtrip_all_payload_types() {
        let enc = make_encoded(
            r#"{"active":true,"count":42,"label":"x","nothing":null,"ratio":1.5}"#
        );
        let bytes   = encode_token_bytes(&enc).unwrap();
        let decoded = decode_token_bytes(&bytes).unwrap();
        assert_eq!(enc, decoded);
    }

    #[test]
    fn roundtrip_negative_integer() {
        let enc = make_encoded(r#"{"delta":-1024}"#);
        let bytes   = encode_token_bytes(&enc).unwrap();
        let decoded = decode_token_bytes(&bytes).unwrap();
        assert_eq!(enc, decoded);
    }

    #[test]
    fn roundtrip_literal_string_fallback() {
        // With empty dictionary, all strings are literals.
        let toks = tokenize_json(br#"{"name":"Alice"}"#).unwrap();
        let enc  = crate::pipelines::text::dictionary::encode_with_dict(
            &toks, &Dictionary::empty(),
        );

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
        // Build a repetitive JSON array (ideal for compression).
        let mut json = String::from("[");
        for i in 0..200 {
            if i > 0 { json.push(','); }
            json.push_str(&format!(r#"{{"id":{i},"name":"user_{i}","active":true}}"#));
        }
        json.push(']');

        let enc   = make_encoded(&json);
        let bytes = encode_token_bytes(&enc).unwrap();

        // Naïve lower-bound: raw JSON byte length.
        assert!(bytes.len() < json.len(),
            "encoded ({}) should be smaller than raw JSON ({}) for repetitive input",
            bytes.len(), json.len());
    }

    // ── Error handling ────────────────────────────────────────────────────────

    #[test]
    fn decode_empty_buffer_returns_error() {
        assert!(decode_token_bytes(&[]).is_err());
    }

    #[test]
    fn decode_truncated_kind_stream_returns_error() {
        let enc   = make_encoded(r#"{"a":1}"#);
        let bytes = encode_token_bytes(&enc).unwrap();
        // Truncate the last 10 bytes.
        let truncated = &bytes[..bytes.len().saturating_sub(10)];
        assert!(decode_token_bytes(truncated).is_err());
    }
}
