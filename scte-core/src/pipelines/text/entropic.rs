/// JSON-specific entropy codec — sits between Phase 3 (dictionary) and
/// the generic `entropy::codec` byte-stream encoder.
///
/// # Responsibilities
/// - Mapping `TokenKind` ↔ `u8` (alphabet = 10 kinds, values 0..=9)
/// - Serializing / deserializing per-token payloads (DictId, literals,
///   integers, floats, booleans)
/// - Calling `entropy::codec::encode_auto` (Phase 7: auto-selects rANS or CTW)
///
/// # Wire format (TOKENS section payload)
/// ```text
/// [kind blob]    ← encode_auto(kind_bytes, 10)   — self-delimiting
/// [payload blob] ← 0x00 || raw_payload            — no further compression
///                  0x04 || varint(len) || ctw_bytes — CTW compressed
/// ```
///
/// The kind blob is self-delimiting.  The payload blob's first byte is a
/// codec tag: `0x00` = raw, `0x04` = CTW.  If the CTW output is not smaller
/// than the raw payload (plus the 5-byte overhead for tag + varint), the raw
/// path is always taken.
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
    entropy::{codec as entropy_codec, ctw, FreqTable, rans_encode, rans_decode},
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

    // ── 2. entropy-encode kind stream — auto-selects rANS or CTW ────────────
    let entropy_blob = entropy_codec::encode_auto(&kind_bytes, TOKEN_KIND_ALPHABET)?;

    // ── 3. serialize payloads ─────────────────────────────────────────────────
    let mut payload_buf: Vec<u8> = Vec::new();
    for token in tokens {
        encode_payload(token, &mut payload_buf);
    }

    // ── 4. compress payload blob — CTW if smaller, otherwise raw ─────────────
    //  Tag 0x04 = CTW (SectionCodec::Arithmetic), 0x00 = raw (no overhead).
    //  CTW overhead: 1 byte tag + up to 4 bytes varint(len) = 5 bytes.
    const PAYLOAD_TAG_RAW: u8 = 0x00;
    const PAYLOAD_TAG_CTW: u8 = 0x04;
    const CTW_DEPTH: usize    = 8;
    const CTW_OVERHEAD: usize = 5; // tag + varint(len)

    let ctw_payload  = ctw::encode(&payload_buf, CTW_DEPTH);
    let use_ctw      = ctw_payload.len() + CTW_OVERHEAD < payload_buf.len();

    let mut out = Vec::with_capacity(
        entropy_blob.len() + 1 + if use_ctw { 4 + ctw_payload.len() } else { payload_buf.len() }
    );
    out.extend_from_slice(&entropy_blob);

    if use_ctw {
        out.push(PAYLOAD_TAG_CTW);
        encode_usize(ctw_payload.len(), &mut out);
        out.extend_from_slice(&ctw_payload);
    } else {
        out.push(PAYLOAD_TAG_RAW);
        out.extend_from_slice(&payload_buf);
    }
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

    // ── 1. decode kind stream — auto-detect rANS or CTW ──────────────────────
    let (kind_bytes, consumed) = entropy_codec::decode_auto(data, pos)?;
    pos += consumed;

    // ── 2. decode payload blob ────────────────────────────────────────────────
    if pos >= data.len() {
        return Err(ScteError::DecodeError(
            "text/entropic: missing payload codec tag".into()));
    }
    let payload_tag = data[pos];
    pos += 1;

    let payload_data: Vec<u8> = match payload_tag {
        0x00 => data[pos..].to_vec(),  // raw — remainder is payload
        0x04 => {
            // CTW — read varint(len) then decompress
            let (blob_len, hdr) = crate::varint::decode_usize(data, pos)
                .ok_or_else(|| ScteError::DecodeError(
                    "text/entropic: truncated CTW payload length".into()))?;
            pos += hdr;
            if pos + blob_len > data.len() {
                return Err(ScteError::DecodeError(
                    "text/entropic: CTW payload blob truncated".into()));
            }
            let decompressed = ctw::decode(&data[pos..pos + blob_len])
                .ok_or_else(|| ScteError::DecodeError(
                    "text/entropic: CTW payload decode failed".into()))?;
            pos += blob_len;
            decompressed
        }
        tag => return Err(ScteError::DecodeError(
            format!("text/entropic: unknown payload codec tag {tag:#04X}"))),
    };
    let payload = &payload_data;
    let _ = pos; // pos no longer needed — all remaining work is on `payload`
    let mut ppos = 0usize;

    // ── 3. decode per-token payloads ──────────────────────────────────────────
    let mut tokens = Vec::with_capacity(kind_bytes.len());
    for (i, &kb) in kind_bytes.iter().enumerate() {
        let kind = byte_to_kind(kb).ok_or_else(|| {
            ScteError::DecodeError(format!(
                "text/entropic: unknown kind byte {kb:#04X} at index {i}"
            ))
        })?;

        let (tok_payload, n) = decode_payload(kind, payload, ppos)?;
        ppos += n;
        tokens.push(EncodedToken { kind, payload: tok_payload });
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

// ── Multi-stream entropy (TOKENS_RANS section) ───────────────────────────────
//
// The payload is split into three independent byte streams by token kind,
// then each stream is independently compressed with rANS (if profitable) or
// stored raw.  The kind stream is shared with the existing format.
//
// Wire format within the TOKENS_RANS section payload:
// ```text
// [kind_blob]                                    ← self-delimiting entropy blob
// [key_tag u8][key_len varint][key_bytes]        ← Key token payloads
// [str_tag u8][str_len varint][str_bytes]        ← Str token payloads
// [misc_tag u8][misc_len varint][misc_bytes]     ← Bool/NumInt/NumFloat payloads
//
// stream tags:
//   0x00 = raw bytes
//   0x01 = rANS : [ft_len varint][ft_bytes][orig_len varint][rans_len varint][rans_bytes]
//   0x04 = CTW  : [ctw_len varint][ctw_bytes]  (misc stream only)
// ```

const STREAM_TAG_RAW:  u8 = 0x00;
const STREAM_TAG_RANS: u8 = 0x01;
const STREAM_TAG_CTW:  u8 = 0x04;

/// Encode a token stream using three independent sub-streams for Key, Str, and
/// other payloads.  Returns a blob suitable for a `TOKENS_RANS` section.
pub fn encode_token_bytes_multistream(tokens: &[EncodedToken]) -> Result<Vec<u8>, ScteError> {
    // ── 1. kind stream (unchanged from single-stream encode) ─────────────────
    let kind_bytes: Vec<u8> = tokens.iter().map(|t| kind_to_byte(t.kind)).collect();
    let kind_blob = entropy_codec::encode_auto(&kind_bytes, TOKEN_KIND_ALPHABET)?;

    // ── 2. split payloads into three streams ─────────────────────────────────
    let mut key_buf  = Vec::new();
    let mut str_buf  = Vec::new();
    let mut misc_buf = Vec::new();

    for token in tokens {
        match token.kind {
            TokenKind::Key  => encode_payload(token, &mut key_buf),
            TokenKind::Str  => encode_payload(token, &mut str_buf),
            TokenKind::Bool | TokenKind::NumInt | TokenKind::NumFloat
                            => encode_payload(token, &mut misc_buf),
            _ => {} // structural tokens (ObjOpen/Close/ArrOpen/Close/Null) carry no payload
        }
    }

    // ── 3. compress each stream independently ────────────────────────────────
    let key_blob  = compress_sub_stream_rans(&key_buf);
    let str_blob  = compress_sub_stream_rans(&str_buf);
    let misc_blob = compress_sub_stream_ctw(&misc_buf);

    // ── 4. assemble ───────────────────────────────────────────────────────────
    let mut out = Vec::with_capacity(
        kind_blob.len() + key_blob.len() + str_blob.len() + misc_blob.len() + 12,
    );
    out.extend_from_slice(&kind_blob);
    out.extend_from_slice(&key_blob);
    out.extend_from_slice(&str_blob);
    out.extend_from_slice(&misc_blob);
    Ok(out)
}

/// Encode a sub-stream with rANS if profitable, otherwise raw.
/// Emits: `[tag u8][data]`
///   - raw:  `[0x00][len varint][bytes]`
///   - rANS: `[0x01][ft_bytes (self-describing)][orig_len varint][rans_len varint][rans_bytes]`
fn compress_sub_stream_rans(data: &[u8]) -> Vec<u8> {
    if data.len() >= 32 {
        let freq = FreqTable::build(data, 256, 14);
        let ft_bytes = freq.serialize();
        if let Ok(rans_bytes) = rans_encode(data, &freq) {
            // Compare: rans total vs raw total
            let varint_len = |mut n: usize| -> usize { let mut l=1; while n>=0x80{n>>=7;l+=1;} l };
            let raw_total  = 1 + varint_len(data.len()) + data.len();
            // rANS: tag(1) + ft(self-desc) + orig_len varint + rans_len varint + rans_bytes
            let rans_total = 1 + ft_bytes.len()
                + varint_len(data.len()) + varint_len(rans_bytes.len()) + rans_bytes.len();
            if rans_total < raw_total {
                let mut out = Vec::with_capacity(rans_total);
                out.push(STREAM_TAG_RANS);
                out.extend_from_slice(&ft_bytes);        // self-describing; no length prefix
                encode_usize(data.len(), &mut out);      // orig_len
                encode_usize(rans_bytes.len(), &mut out); // rans_len
                out.extend_from_slice(&rans_bytes);
                return out;
            }
        }
    }
    // Fall back to raw.
    let mut out = Vec::with_capacity(1 + data.len() + 4);
    out.push(STREAM_TAG_RAW);
    encode_usize(data.len(), &mut out);
    out.extend_from_slice(data);
    out
}

/// Encode a sub-stream with CTW (for misc payloads) if profitable, else raw.
/// Emits: `[tag u8][len varint][data]`
fn compress_sub_stream_ctw(data: &[u8]) -> Vec<u8> {
    if data.len() > 16 {
        let ctw_bytes = ctw::encode(data, 8);
        if ctw_bytes.len() < data.len().saturating_sub(4) {
            let mut out = Vec::with_capacity(1 + 4 + ctw_bytes.len());
            out.push(STREAM_TAG_CTW);
            encode_usize(ctw_bytes.len(), &mut out);
            out.extend_from_slice(&ctw_bytes);
            return out;
        }
    }
    let mut out = Vec::with_capacity(1 + data.len() + 4);
    out.push(STREAM_TAG_RAW);
    encode_usize(data.len(), &mut out);
    out.extend_from_slice(data);
    out
}

/// Decode a blob produced by `encode_token_bytes_multistream`.
pub fn decode_token_bytes_multistream(data: &[u8]) -> Result<Vec<EncodedToken>, ScteError> {
    let mut pos = 0;

    // ── 1. kind stream ────────────────────────────────────────────────────────
    let (kind_bytes, consumed) = entropy_codec::decode_auto(data, pos)?;
    pos += consumed;

    // ── 2. read three sub-streams ─────────────────────────────────────────────
    let (key_buf,  key_consumed)  = read_sub_stream_rans(data, pos)?;  pos += key_consumed;
    let (str_buf,  str_consumed)  = read_sub_stream_rans(data, pos)?;  pos += str_consumed;
    let (misc_buf, _misc_consumed) = read_sub_stream_ctw(data, pos)?;

    // ── 3. reconstruct tokens ─────────────────────────────────────────────────
    let mut key_pos  = 0usize;
    let mut str_pos  = 0usize;
    let mut misc_pos = 0usize;
    let mut tokens = Vec::with_capacity(kind_bytes.len());

    for (i, &kb) in kind_bytes.iter().enumerate() {
        let kind = byte_to_kind(kb).ok_or_else(|| ScteError::DecodeError(
            format!("entropic/ms: unknown kind byte {kb:#04X} at index {i}"),
        ))?;

        let (payload, n) = match kind {
            TokenKind::Key => {
                let r = decode_payload(kind, &key_buf, key_pos)?;
                key_pos += r.1;
                r
            }
            TokenKind::Str => {
                let r = decode_payload(kind, &str_buf, str_pos)?;
                str_pos += r.1;
                r
            }
            TokenKind::Bool | TokenKind::NumInt | TokenKind::NumFloat => {
                let r = decode_payload(kind, &misc_buf, misc_pos)?;
                misc_pos += r.1;
                r
            }
            _ => (EncodedPayload::None, 0),
        };
        let _ = n;
        tokens.push(EncodedToken { kind, payload });
    }
    Ok(tokens)
}

fn read_sub_stream_rans(data: &[u8], pos: usize) -> Result<(Vec<u8>, usize), ScteError> {
    if pos >= data.len() {
        return Err(ScteError::DecodeError("entropic/ms: sub-stream truncated".into()));
    }
    let tag = data[pos];
    let mut consumed = 1usize;

    match tag {
        STREAM_TAG_RAW => {
            let (len, h) = decode_usize(data, pos + consumed).ok_or_else(|| {
                ScteError::DecodeError("entropic/ms: raw stream length truncated".into())
            })?;
            consumed += h;
            if pos + consumed + len > data.len() {
                return Err(ScteError::DecodeError("entropic/ms: raw stream data truncated".into()));
            }
            let buf = data[pos + consumed..pos + consumed + len].to_vec();
            consumed += len;
            Ok((buf, consumed))
        }
        STREAM_TAG_RANS => {
            // FreqTable is serialized with a self-reported length; read it.
            let (freq, ft_consumed) = FreqTable::deserialize(data, pos + consumed)
                .map_err(|e| ScteError::DecodeError(format!("entropic/ms: FreqTable: {e}")))?;
            consumed += ft_consumed;

            let (orig_len, h2) = decode_usize(data, pos + consumed).ok_or_else(|| {
                ScteError::DecodeError("entropic/ms: rANS orig_len truncated".into())
            })?;
            consumed += h2;
            let (rans_len, h3) = decode_usize(data, pos + consumed).ok_or_else(|| {
                ScteError::DecodeError("entropic/ms: rANS rans_len truncated".into())
            })?;
            consumed += h3;
            if pos + consumed + rans_len > data.len() {
                return Err(ScteError::DecodeError("entropic/ms: rANS data truncated".into()));
            }
            // decode(data, freq, count, pos_within_data)
            let (buf, _) = rans_decode(data, &freq, orig_len, pos + consumed)
                .map_err(|e| ScteError::DecodeError(format!("entropic/ms: rans_decode: {e}")))?;
            consumed += rans_len;
            Ok((buf, consumed))
        }
        t => Err(ScteError::DecodeError(format!("entropic/ms: unknown stream tag {t:#04X}"))),
    }
}

fn read_sub_stream_ctw(data: &[u8], pos: usize) -> Result<(Vec<u8>, usize), ScteError> {
    if pos >= data.len() {
        return Ok((Vec::new(), 0)); // misc stream may be empty
    }
    let tag = data[pos];
    let mut consumed = 1usize;

    match tag {
        STREAM_TAG_RAW => {
            let (len, h) = decode_usize(data, pos + consumed).ok_or_else(|| {
                ScteError::DecodeError("entropic/ms: CTW raw length truncated".into())
            })?;
            consumed += h;
            if pos + consumed + len > data.len() {
                return Err(ScteError::DecodeError("entropic/ms: CTW raw data truncated".into()));
            }
            let buf = data[pos + consumed..pos + consumed + len].to_vec();
            consumed += len;
            Ok((buf, consumed))
        }
        STREAM_TAG_CTW => {
            let (ctw_len, h) = decode_usize(data, pos + consumed).ok_or_else(|| {
                ScteError::DecodeError("entropic/ms: CTW length truncated".into())
            })?;
            consumed += h;
            if pos + consumed + ctw_len > data.len() {
                return Err(ScteError::DecodeError("entropic/ms: CTW data truncated".into()));
            }
            let buf = ctw::decode(&data[pos + consumed..pos + consumed + ctw_len])
                .ok_or_else(|| ScteError::DecodeError("entropic/ms: CTW decode failed".into()))?;
            consumed += ctw_len;
            Ok((buf, consumed))
        }
        t => Err(ScteError::DecodeError(format!("entropic/ms: unknown CTW tag {t:#04X}"))),
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
