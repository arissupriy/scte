use crate::{error::ScteError, pipelines::text::value::{parse, Value}};

// ── Token types ───────────────────────────────────────────────────────────────

/// Discriminant of a single token in the flat token stream.
///
/// # Wire encoding (Phase 4+)
/// Encoded as a 4-bit prefix in the rANS bitstream:
/// `ObjOpen`=0, `ObjClose`=1, `ArrOpen`=2, `ArrClose`=3,
/// `Key`=4, `Str`=5, `NumInt`=6, `NumFloat`=7, `Bool`=8, `Null`=9.
///
/// Phase 3 will replace `Key` and `Str` payloads with dictionary IDs.
/// Phase 4 will entropy-encode the resulting stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenKind {
    ObjOpen,
    ObjClose,
    ArrOpen,
    ArrClose,
    /// Object key (always a string, eligible for dictionary encoding).
    Key,
    /// String value (eligible for dictionary encoding).
    Str,
    /// Integer-valued number.
    NumInt,
    /// Floating-point number (genuine fraction or out-of-i64-range).
    NumFloat,
    Bool,
    Null,
}

/// Payload carried by a token.
///
/// Structural tokens (`ObjOpen`, `ObjClose`, `ArrOpen`, `ArrClose`, `Null`)
/// always carry `None`. All others carry a typed value.
///
/// Phase 3 contract: `Key` and `Str` payloads will be replaced by
/// `DictId(u16)` once the dictionary is built. The variant is added here
/// as `None` placeholder — the enum is intentionally extensible.
#[derive(Debug, Clone, PartialEq)]
pub enum TokenPayload {
    None,
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
}

/// A single token in the flat text pipeline token stream.
///
/// Tokens are emitted in document order: for objects, keys and values
/// are interleaved (`Key`, value, `Key`, value, …) in sorted key order,
/// consistent with the canonical serializer.
#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    pub kind:    TokenKind,
    pub payload: TokenPayload,
}

impl Token {
    fn new(kind: TokenKind, payload: TokenPayload) -> Self {
        Self { kind, payload }
    }

    fn simple(kind: TokenKind) -> Self {
        Self { kind, payload: TokenPayload::None }
    }
}

// ── Public entry point ───────────────────────────────────────────────────────

/// Parse JSON bytes and produce a flat token stream.
///
/// The input is first parsed into a `Value` IR (same as `canonicalize_json`),
/// then walked depth-first to produce tokens. Object keys are emitted in
/// sorted order, identical to the canonical serializer.
///
/// # Token stream example
/// ```text
/// Input:  {"b":2,"a":[1,true]}
/// Stream: ObjOpen
///         Key("a")
///         ArrOpen
///           NumInt(1)
///           Bool(true)
///         ArrClose
///         Key("b")
///         NumInt(2)
///         ObjClose
/// ```
///
/// # Errors
/// Returns `ScteError::DecodeError` for malformed JSON.
pub fn tokenize_json(input: &[u8]) -> Result<Vec<Token>, ScteError> {
    let value = parse(input)?;
    let mut tokens = Vec::new();
    walk(&value, &mut tokens);
    Ok(tokens)
}

// ── Value walker ─────────────────────────────────────────────────────────────

fn walk(value: &Value, out: &mut Vec<Token>) {
    match value {
        Value::Null => out.push(Token::simple(TokenKind::Null)),

        Value::Bool(b) => out.push(Token::new(
            TokenKind::Bool,
            TokenPayload::Bool(*b),
        )),

        Value::Int(n) => out.push(Token::new(
            TokenKind::NumInt,
            TokenPayload::Int(*n),
        )),

        Value::Float(f) => out.push(Token::new(
            TokenKind::NumFloat,
            TokenPayload::Float(*f),
        )),

        Value::Str(s) => out.push(Token::new(
            TokenKind::Str,
            TokenPayload::Str(s.clone()),
        )),

        Value::Array(items) => {
            out.push(Token::simple(TokenKind::ArrOpen));
            for item in items {
                walk(item, out);
            }
            out.push(Token::simple(TokenKind::ArrClose));
        }

        Value::Object(entries) => {
            // Emit in sorted key order — consistent with canonicalize.
            let mut sorted: Vec<&(String, Value)> = entries.iter().collect();
            sorted.sort_unstable_by(|(a, _), (b, _)| a.as_bytes().cmp(b.as_bytes()));

            out.push(Token::simple(TokenKind::ObjOpen));
            for (key, val) in sorted {
                // Key token — Phase 3 replaces payload with dict ID.
                out.push(Token::new(TokenKind::Key, TokenPayload::Str(key.clone())));
                walk(val, out);
            }
            out.push(Token::simple(TokenKind::ObjClose));
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tok(s: &str) -> Vec<Token> {
        tokenize_json(s.as_bytes()).expect("tokenize failed")
    }

    // ── Primitives ───────────────────────────────────────────────────────────

    #[test]
    fn null_token() {
        assert_eq!(tok("null"), vec![Token::simple(TokenKind::Null)]);
    }

    #[test]
    fn bool_true_token() {
        assert_eq!(tok("true"), vec![Token::new(TokenKind::Bool, TokenPayload::Bool(true))]);
    }

    #[test]
    fn bool_false_token() {
        assert_eq!(tok("false"), vec![Token::new(TokenKind::Bool, TokenPayload::Bool(false))]);
    }

    #[test]
    fn int_token() {
        assert_eq!(tok("42"), vec![Token::new(TokenKind::NumInt, TokenPayload::Int(42))]);
    }

    #[test]
    fn float_one_normalized_to_int_token() {
        // 1.0 is normalized to Int(1) during parse.
        assert_eq!(tok("1.0"), vec![Token::new(TokenKind::NumInt, TokenPayload::Int(1))]);
    }

    #[test]
    fn genuine_float_token() {
        assert_eq!(tok("1.5"), vec![Token::new(TokenKind::NumFloat, TokenPayload::Float(1.5))]);
    }

    #[test]
    fn string_token() {
        assert_eq!(
            tok(r#""hello""#),
            vec![Token::new(TokenKind::Str, TokenPayload::Str("hello".into()))]
        );
    }

    // ── Array ────────────────────────────────────────────────────────────────

    #[test]
    fn empty_array() {
        assert_eq!(tok("[]"), vec![
            Token::simple(TokenKind::ArrOpen),
            Token::simple(TokenKind::ArrClose),
        ]);
    }

    #[test]
    fn array_of_ints() {
        assert_eq!(tok("[1,2,3]"), vec![
            Token::simple(TokenKind::ArrOpen),
            Token::new(TokenKind::NumInt, TokenPayload::Int(1)),
            Token::new(TokenKind::NumInt, TokenPayload::Int(2)),
            Token::new(TokenKind::NumInt, TokenPayload::Int(3)),
            Token::simple(TokenKind::ArrClose),
        ]);
    }

    // ── Object ───────────────────────────────────────────────────────────────

    #[test]
    fn empty_object() {
        assert_eq!(tok("{}"), vec![
            Token::simple(TokenKind::ObjOpen),
            Token::simple(TokenKind::ObjClose),
        ]);
    }

    #[test]
    fn simple_object() {
        assert_eq!(tok(r#"{"a":1}"#), vec![
            Token::simple(TokenKind::ObjOpen),
            Token::new(TokenKind::Key, TokenPayload::Str("a".into())),
            Token::new(TokenKind::NumInt, TokenPayload::Int(1)),
            Token::simple(TokenKind::ObjClose),
        ]);
    }

    #[test]
    fn object_keys_emitted_sorted() {
        // Input: z before a — output: a before z.
        let tokens = tok(r#"{"z":2,"a":1}"#);
        assert_eq!(tokens[1], Token::new(TokenKind::Key, TokenPayload::Str("a".into())));
        assert_eq!(tokens[3], Token::new(TokenKind::Key, TokenPayload::Str("z".into())));
    }

    #[test]
    fn nested_object() {
        let tokens = tok(r#"{"user":{"id":1}}"#);
        assert_eq!(tokens[0], Token::simple(TokenKind::ObjOpen));
        assert_eq!(tokens[1], Token::new(TokenKind::Key, TokenPayload::Str("user".into())));
        assert_eq!(tokens[2], Token::simple(TokenKind::ObjOpen));
        assert_eq!(tokens[3], Token::new(TokenKind::Key, TokenPayload::Str("id".into())));
        assert_eq!(tokens[4], Token::new(TokenKind::NumInt, TokenPayload::Int(1)));
        assert_eq!(tokens[5], Token::simple(TokenKind::ObjClose));
        assert_eq!(tokens[6], Token::simple(TokenKind::ObjClose));
    }

    // ── Key vs Str disambiguation ─────────────────────────────────────────────

    #[test]
    fn key_token_not_str_token() {
        // Object keys → TokenKind::Key, not TokenKind::Str.
        let tokens = tok(r#"{"k":"v"}"#);
        assert_eq!(tokens[1].kind, TokenKind::Key);
        assert_eq!(tokens[2].kind, TokenKind::Str);
    }

    #[test]
    fn str_in_array_is_str_not_key() {
        let tokens = tok(r#"["hello"]"#);
        assert_eq!(tokens[1].kind, TokenKind::Str);
    }

    // ── Complex payloads ─────────────────────────────────────────────────────

    #[test]
    fn mixed_types_object() {
        let tokens = tok(r#"{"active":true,"id":1,"name":"Alice","score":null}"#);
        // Expect sorted keys: active, id, name, score
        let keys: Vec<&str> = tokens.iter()
            .filter(|t| t.kind == TokenKind::Key)
            .map(|t| match &t.payload {
                TokenPayload::Str(s) => s.as_str(),
                _ => panic!("key payload must be Str"),
            })
            .collect();
        assert_eq!(keys, ["active", "id", "name", "score"]);
    }

    #[test]
    fn token_count_flat_object() {
        // {"a":1,"b":2} → ObjOpen(1) + [Key,Int]×2(4) + ObjClose(1) = 6
        assert_eq!(tok(r#"{"a":1,"b":2}"#).len(), 6);
    }

    #[test]
    fn token_count_nested() {
        // {"x":{"y":1}} → ObjOpen Key ObjOpen Key Int ObjClose ObjClose = 7
        assert_eq!(tok(r#"{"x":{"y":1}}"#).len(), 7);
    }

    // ── Determinism ──────────────────────────────────────────────────────────

    #[test]
    fn tokenize_is_deterministic() {
        let input = br#"{"z":3,"a":1,"m":2}"#;
        assert_eq!(
            tokenize_json(input).unwrap(),
            tokenize_json(input).unwrap(),
            "tokenize must be deterministic"
        );
    }

    // ── Error propagation ────────────────────────────────────────────────────

    #[test]
    fn invalid_json_returns_error() {
        assert!(tokenize_json(b"not json").is_err());
    }
}
