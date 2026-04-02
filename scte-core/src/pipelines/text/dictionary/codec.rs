/// Dictionary codec — Phase 3.
///
/// Converts a raw token stream (Phase 2 output) into a dictionary-compressed
/// stream where high-frequency string tokens are replaced by compact `u16` IDs,
/// and reconstructs the original stream from it.
///
/// # Pipeline position
/// ```text
/// Phase 2: tokenize_json()   →  Vec<Token>
/// Phase 3: encode_with_dict  →  Vec<EncodedToken>   (this module)
///          decode_with_dict  →  Vec<Token>           (this module)
/// Phase 4: rANS encoder      ←  (consumes Vec<EncodedToken>)
/// ```

use crate::{
    error::ScteError,
    pipelines::text::tokenizer::{Token, TokenKind, TokenPayload},
};

use super::{Dictionary, DictEntryKind};

// ── Encoded token types ───────────────────────────────────────────────────────

/// Token payload after dictionary substitution.
///
/// `DictId(u16)` replaces the string payload of high-frequency `Key` / `Str`
/// tokens. Low-frequency strings that were not added to the dictionary keep
/// their literal `Str(String)` payload.
///
/// Phase 4 (rANS) will entropy-code the resulting stream of `EncodedToken`s.
#[derive(Debug, Clone, PartialEq)]
pub enum EncodedPayload {
    /// Structural tokens (ObjOpen/ObjClose/ArrOpen/ArrClose/Null) carry no payload.
    None,
    /// The token's string value was found in the dictionary.
    DictId(u16),
    /// The token's string value was NOT in the dictionary (literal fallback).
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
}

/// A single token in the dictionary-encoded stream.
#[derive(Debug, Clone, PartialEq)]
pub struct EncodedToken {
    pub kind:    TokenKind,
    pub payload: EncodedPayload,
}

// ── Encoding / decoding ───────────────────────────────────────────────────────

/// Replace high-frequency string payloads in a token stream with dictionary IDs.
///
/// For each `Key` or `Str` token whose value appears in `dict`, the payload is
/// replaced with `EncodedPayload::DictId(id)`. All other tokens are mapped
/// to their equivalent `EncodedPayload` variant unchanged.
///
/// Time: O(n) — one dictionary lookup per token (BTreeMap: O(log K)).
pub fn encode_with_dict(tokens: &[Token], dict: &Dictionary) -> Vec<EncodedToken> {
    tokens.iter().map(|t| {
        let payload = match &t.payload {
            TokenPayload::None        => EncodedPayload::None,
            TokenPayload::Bool(b)     => EncodedPayload::Bool(*b),
            TokenPayload::Int(n)      => EncodedPayload::Int(*n),
            TokenPayload::Float(f)    => EncodedPayload::Float(*f),
            TokenPayload::Str(s) => {
                match dict.lookup(t.kind, s) {
                    Some(id) => EncodedPayload::DictId(id),
                    None     => EncodedPayload::Str(s.clone()),
                }
            }
        };
        EncodedToken { kind: t.kind, payload }
    }).collect()
}

/// Reconstruct a full token stream from a dictionary-encoded stream.
///
/// `DictId(id)` payloads are resolved back to their string values using `dict`.
///
/// # Errors
/// Returns `ScteError::DecodeError` if a `DictId` references an entry that
/// does not exist in the dictionary (indicates a corrupted or mismatched stream).
pub fn decode_with_dict(
    encoded: &[EncodedToken],
    dict: &Dictionary,
) -> Result<Vec<Token>, ScteError> {
    encoded.iter().map(|et| {
        let payload = match &et.payload {
            EncodedPayload::None      => TokenPayload::None,
            EncodedPayload::Bool(b)   => TokenPayload::Bool(*b),
            EncodedPayload::Int(n)    => TokenPayload::Int(*n),
            EncodedPayload::Float(f)  => TokenPayload::Float(*f),
            EncodedPayload::Str(s)    => TokenPayload::Str(s.clone()),
            EncodedPayload::DictId(id) => {
                let entry = dict.get(*id).ok_or_else(|| ScteError::DecodeError(
                    format!("dict: DictId({id}) out of range (dict has {} entries)", dict.len()),
                ))?;
                // Kind in encoded stream must match kind in dictionary.
                if et.kind != entry.kind.to_token_kind() {
                    return Err(ScteError::DecodeError(format!(
                        "dict: kind mismatch for DictId({id}): \
                         expected {:?}, got {:?}",
                        entry.kind.to_token_kind(), et.kind
                    )));
                }
                TokenPayload::Str(entry.value.clone())
            }
        };
        Ok(Token { kind: et.kind, payload })
    }).collect()
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipelines::text::{
        dictionary::Dictionary,
        tokenizer::tokenize_json,
    };

    fn tokens(s: &str) -> Vec<Token> {
        tokenize_json(s.as_bytes()).expect("tokenize failed")
    }

    fn build_dict(s: &str, min_freq: u32) -> Dictionary {
        Dictionary::build(&tokens(s), min_freq)
    }

    #[test]
    fn encode_replaces_known_keys_with_dict_id() {
        let toks = tokens(r#"{"name":"Alice"}"#);
        let dict = Dictionary::build(&toks, 1);
        let enc  = encode_with_dict(&toks, &dict);

        let key_tok = enc.iter().find(|t| t.kind == TokenKind::Key).unwrap();
        assert!(
            matches!(key_tok.payload, EncodedPayload::DictId(_)),
            "known key must be encoded as DictId"
        );
    }

    #[test]
    fn encode_keeps_unknown_strings_literal() {
        let toks = tokens(r#"{"name":"Alice"}"#);
        let dict = Dictionary::empty();
        let enc  = encode_with_dict(&toks, &dict);

        let key_tok = enc.iter().find(|t| t.kind == TokenKind::Key).unwrap();
        assert!(
            matches!(key_tok.payload, EncodedPayload::Str(_)),
            "unknown token must remain as literal Str"
        );
    }

    #[test]
    fn encode_does_not_touch_int_bool_null() {
        let toks = tokens(r#"{"active":true,"count":5}"#);
        let dict = Dictionary::build(&toks, 1);
        let enc  = encode_with_dict(&toks, &dict);

        let bool_tok = enc.iter().find(|t| t.kind == TokenKind::Bool).unwrap();
        assert!(matches!(bool_tok.payload, EncodedPayload::Bool(_)));

        let int_tok = enc.iter().find(|t| t.kind == TokenKind::NumInt).unwrap();
        assert!(matches!(int_tok.payload, EncodedPayload::Int(_)));
    }

    #[test]
    fn decode_roundtrip() {
        let toks = tokens(r#"{"user":{"id":1,"name":"Alice"},"active":true}"#);
        let dict = Dictionary::build(&toks, 1);
        let enc  = encode_with_dict(&toks, &dict);
        let dec  = decode_with_dict(&enc, &dict).expect("decode failed");
        assert_eq!(toks, dec, "encode→decode must reconstruct original token stream");
    }

    #[test]
    fn decode_invalid_dict_id_returns_error() {
        let dict = Dictionary::empty();
        let enc  = vec![EncodedToken {
            kind:    TokenKind::Key,
            payload: EncodedPayload::DictId(99),
        }];
        assert!(decode_with_dict(&enc, &dict).is_err());
    }

    #[test]
    fn encode_decode_large_stream() {
        let json = r#"[
            {"id":1,"name":"Alice","role":"admin"},
            {"id":2,"name":"Bob",  "role":"user"},
            {"id":3,"name":"Carol","role":"user"},
            {"id":4,"name":"Dave", "role":"admin"}
        ]"#;
        let toks = tokens(json);
        let dict = build_dict(json, 2);
        let enc  = encode_with_dict(&toks, &dict);
        let dec  = decode_with_dict(&enc, &dict).unwrap();
        assert_eq!(toks, dec);

        assert!(dict.lookup(TokenKind::Key, "id").is_some());
        assert!(dict.lookup(TokenKind::Key, "name").is_some());
        assert!(dict.lookup(TokenKind::Key, "role").is_some());
        assert!(dict.lookup(TokenKind::Str, "user").is_some());
        assert!(dict.lookup(TokenKind::Str, "admin").is_some());
    }
}
