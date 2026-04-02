/// TOKENS section wire format encoder / decoder.
///
/// Combines Phase 3 (dictionary-encoded token stream) with Phase 4 (rANS
/// entropy coding) into the final binary payload written to the `TOKENS(0x02)`
/// section of the SCTE container.
///
/// # Compression model — 1st-order context (Markov)
///
/// The token kind stream is split into **11 independent sub-streams**,
/// one for each possible preceding kind (0-9) plus one for the initial
/// position (context 10).  Each sub-stream has its own `FreqTable` and
/// is entropy-coded separately.
///
/// JSON token sequences are highly regular (after `ObjOpen` almost always
/// comes `Key`, etc.), so conditioning on the previous kind typically reduces
/// effective entropy by 30-50 % compared to a 0-order model.
///
/// # Wire format
/// ```text
/// varint(token_count)
/// for context in 0..11:
///     varint(sym_count)            ← symbols encoded from this context
///     varint(freq_bytes_len)       ← 0 if sym_count == 0
///     [freq_bytes]
///     varint(compressed_len)       ← 0 if sym_count == 0
///     [rANS compressed bytes]
/// [payload stream]                 ← one entry per token (unchanged)
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

/// Total number of context buckets = TOKEN_KIND_ALPHABET + 1 (initial context).
/// Contexts 0-9 correspond to "previous kind was X".
/// Context 10 is used for the very first token (no previous kind).
const NUM_CONTEXTS: usize = TOKEN_KIND_ALPHABET + 1;

/// Context index for the first symbol (no predecessor).
const INITIAL_CTX: usize = TOKEN_KIND_ALPHABET;

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
/// Uses a **1st-order context model**: the kind stream is split into 11
/// sub-streams (one per preceding context), each independently entropy-coded
/// with its own `FreqTable`.  This exploits the strong Markov structure of
/// JSON token sequences for 30-50 % better compression than a 0-order model.
///
/// # Errors
/// `ScteError::DecodeError` if rANS encoding fails.
pub fn encode_token_bytes(tokens: &[EncodedToken]) -> Result<Vec<u8>, ScteError> {
    // ── 1. kind stream ────────────────────────────────────────────────────────
    let kind_bytes: Vec<u8> = tokens.iter().map(|t| kind_to_byte(t.kind)).collect();

    // ── 2. split by context (1st-order Markov) ────────────────────────────────
    // ctx_streams[c] = symbols emitted when context was c.
    let mut ctx_streams: Vec<Vec<u8>> = vec![Vec::new(); NUM_CONTEXTS];
    let mut prev_ctx = INITIAL_CTX;
    for &k in &kind_bytes {
        ctx_streams[prev_ctx].push(k);
        prev_ctx = k as usize;
    }

    // ── 3. encode each sub-stream with its own FreqTable ─────────────────────
    let mut ctx_freq_bytes:  Vec<Vec<u8>> = Vec::with_capacity(NUM_CONTEXTS);
    let mut ctx_compressed:  Vec<Vec<u8>> = Vec::with_capacity(NUM_CONTEXTS);

    for stream in &ctx_streams {
        if stream.is_empty() {
            ctx_freq_bytes.push(Vec::new());
            ctx_compressed.push(Vec::new());
        } else {
            let freq       = FreqTable::build(stream, TOKEN_KIND_ALPHABET, DEFAULT_M_BITS);
            let compressed = rans::encode(stream, &freq)?;
            ctx_freq_bytes.push(freq.serialize());
            ctx_compressed.push(compressed);
        }
    }

    // ── 4. payload stream ─────────────────────────────────────────────────────
    let mut payload_buf: Vec<u8> = Vec::new();
    for token in tokens {
        encode_payload(token, &mut payload_buf);
    }

    // ── 5. assemble output ────────────────────────────────────────────────────
    let mut out = Vec::new();
    encode_usize(tokens.len(), &mut out);

    for ctx in 0..NUM_CONTEXTS {
        encode_usize(ctx_streams[ctx].len(), &mut out);
        encode_usize(ctx_freq_bytes[ctx].len(), &mut out);
        out.extend_from_slice(&ctx_freq_bytes[ctx]);
        encode_usize(ctx_compressed[ctx].len(), &mut out);
        out.extend_from_slice(&ctx_compressed[ctx]);
    }

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

    // ── per-context sub-streams ───────────────────────────────────────────────
    let mut ctx_sym_counts: Vec<usize>  = Vec::with_capacity(NUM_CONTEXTS);
    let mut ctx_decoded:    Vec<Vec<u8>> = Vec::with_capacity(NUM_CONTEXTS);

    for ctx in 0..NUM_CONTEXTS {
        let (sym_count, c) = decode_usize(data, pos)
            .ok_or_else(|| ScteError::DecodeError(
                format!("codec: truncated sym_count for ctx {ctx}"),
            ))?;
        pos += c;
        ctx_sym_counts.push(sym_count);

        let (freq_len, c) = decode_usize(data, pos)
            .ok_or_else(|| ScteError::DecodeError(
                format!("codec: truncated freq_len for ctx {ctx}"),
            ))?;
        pos += c;

        if sym_count == 0 {
            // compressed_len must also be 0; skip it.
            let (compressed_len, c) = decode_usize(data, pos)
                .ok_or_else(|| ScteError::DecodeError(
                    format!("codec: truncated compressed_len for ctx {ctx}"),
                ))?;
            pos += c;
            if compressed_len != 0 {
                return Err(ScteError::DecodeError(format!(
                    "codec: ctx {ctx} has sym_count=0 but compressed_len={compressed_len}"
                )));
            }
            ctx_decoded.push(Vec::new());
            continue;
        }

        let (freq, freq_consumed) = FreqTable::deserialize(data, pos)?;
        if freq_consumed != freq_len {
            return Err(ScteError::DecodeError(format!(
                "codec: ctx {ctx} freq_len declared {freq_len} but parsed {freq_consumed}"
            )));
        }
        pos += freq_len;

        let (compressed_len, c) = decode_usize(data, pos)
            .ok_or_else(|| ScteError::DecodeError(
                format!("codec: truncated compressed_len for ctx {ctx}"),
            ))?;
        pos += c;

        if pos + compressed_len > data.len() {
            return Err(ScteError::DecodeError(format!(
                "codec: ctx {ctx} compressed stream truncated"
            )));
        }

        let (decoded, consumed) = rans::decode(data, &freq, sym_count, pos)?;
        if consumed != compressed_len {
            return Err(ScteError::DecodeError(format!(
                "codec: ctx {ctx} compressed_len declared {compressed_len} but consumed {consumed}"
            )));
        }
        pos += compressed_len;
        ctx_decoded.push(decoded);
    }

    // ── reconstruct kind stream by replaying the context sequence ─────────────
    let mut ctx_pos = vec![0usize; NUM_CONTEXTS];
    let mut kind_bytes = Vec::with_capacity(count);
    let mut prev_ctx = INITIAL_CTX;

    for i in 0..count {
        let bucket = &ctx_decoded[prev_ctx];
        let cp     = ctx_pos[prev_ctx];
        if cp >= bucket.len() {
            return Err(ScteError::DecodeError(format!(
                "codec: ctx {prev_ctx} sub-stream exhausted at token {i}"
            )));
        }
        let k = bucket[cp];
        ctx_pos[prev_ctx] += 1;
        kind_bytes.push(k);
        prev_ctx = k as usize;
    }

    // ── payloads ──────────────────────────────────────────────────────────────
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
