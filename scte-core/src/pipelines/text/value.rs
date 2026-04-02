use crate::error::ScteError;

// ── Value IR ─────────────────────────────────────────────────────────────────

/// Internal JSON value representation.
///
/// Used as the intermediate representation between raw JSON bytes and the
/// canonical serializer / token stream. Not part of the public API.
///
/// Object entries are stored in **parse order**; the canonical serializer
/// is responsible for sorting them lexicographically.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Value {
    Null,
    Bool(bool),
    /// Integer-valued number (no fractional part, fits in i64).
    ///
    /// JSON numbers like `1.0` or `1e2` are normalized to `Int` during
    /// parsing if their value is exactly representable as i64.
    Int(i64),
    /// Floating-point number (has fractional part or doesn't fit in i64).
    Float(f64),
    Str(String),
    Array(Vec<Value>),
    /// `(key, value)` pairs in original parse order.
    Object(Vec<(String, Value)>),
}

// ── Public parse entry point ─────────────────────────────────────────────────

/// Parse UTF-8 JSON bytes into a [`Value`].
///
/// Leading/trailing whitespace is permitted.
/// Trailing content after the root value is an error.
///
/// # Errors
/// Returns `ScteError::DecodeError` for any syntax error, or
/// `ScteError::UnexpectedEof` if the input ends prematurely.
pub(crate) fn parse(input: &[u8]) -> Result<Value, ScteError> {
    let mut p = Parser::new(input);
    let value = p.parse_value()?;
    p.skip_whitespace();
    if p.pos != p.input.len() {
        return Err(ScteError::DecodeError(format!(
            "trailing content after JSON value at byte {}",
            p.pos
        )));
    }
    Ok(value)
}

// ── Parser ───────────────────────────────────────────────────────────────────

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    #[inline]
    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    #[inline]
    fn advance(&mut self) -> Result<u8, ScteError> {
        let b = self.peek().ok_or(ScteError::UnexpectedEof)?;
        self.pos += 1;
        Ok(b)
    }

    #[inline]
    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect_byte(&mut self, expected: u8) -> Result<(), ScteError> {
        let b = self.advance()?;
        if b != expected {
            return Err(ScteError::DecodeError(format!(
                "expected '{}' (0x{expected:02x}), found 0x{b:02x} at byte {}",
                expected as char,
                self.pos - 1
            )));
        }
        Ok(())
    }

    fn expect_literal(&mut self, literal: &[u8]) -> Result<(), ScteError> {
        let end = self.pos + literal.len();
        if self.input.get(self.pos..end) == Some(literal) {
            self.pos = end;
            Ok(())
        } else {
            Err(ScteError::DecodeError(format!(
                "expected '{}' at byte {}",
                std::str::from_utf8(literal).unwrap_or("?"),
                self.pos
            )))
        }
    }

    // ── Value dispatch ───────────────────────────────────────────────────────

    fn parse_value(&mut self) -> Result<Value, ScteError> {
        self.skip_whitespace();
        match self.peek().ok_or(ScteError::UnexpectedEof)? {
            b'n'             => self.parse_null(),
            b't' | b'f'      => self.parse_bool(),
            b'"'             => self.parse_string().map(Value::Str),
            b'['             => self.parse_array(),
            b'{'             => self.parse_object(),
            b'-' | b'0'..=b'9' => self.parse_number(),
            b => Err(ScteError::DecodeError(format!(
                "unexpected byte 0x{b:02x} at position {}",
                self.pos
            ))),
        }
    }

    // ── Primitives ───────────────────────────────────────────────────────────

    fn parse_null(&mut self) -> Result<Value, ScteError> {
        self.expect_literal(b"null")?;
        Ok(Value::Null)
    }

    fn parse_bool(&mut self) -> Result<Value, ScteError> {
        if self.input[self.pos..].starts_with(b"true") {
            self.pos += 4;
            Ok(Value::Bool(true))
        } else if self.input[self.pos..].starts_with(b"false") {
            self.pos += 5;
            Ok(Value::Bool(false))
        } else {
            Err(ScteError::DecodeError(format!(
                "expected 'true' or 'false' at byte {}",
                self.pos
            )))
        }
    }

    // ── String ───────────────────────────────────────────────────────────────

    fn parse_string(&mut self) -> Result<String, ScteError> {
        self.expect_byte(b'"')?;

        // Collect raw bytes; validate UTF-8 once at the end.
        // This correctly handles multibyte UTF-8 sequences.
        let mut bytes: Vec<u8> = Vec::new();

        loop {
            let b = self.advance()?;
            match b {
                b'"' => {
                    return String::from_utf8(bytes).map_err(|_| {
                        ScteError::DecodeError("invalid UTF-8 in JSON string".into())
                    });
                }
                b'\\' => {
                    let esc = self.advance()?;
                    match esc {
                        b'"'  => bytes.push(b'"'),
                        b'\\' => bytes.push(b'\\'),
                        b'/'  => bytes.push(b'/'),
                        b'n'  => bytes.push(b'\n'),
                        b'r'  => bytes.push(b'\r'),
                        b't'  => bytes.push(b'\t'),
                        b'b'  => bytes.push(0x08),
                        b'f'  => bytes.push(0x0C),
                        b'u'  => {
                            let ch = self.parse_unicode_escape()?;
                            let mut buf = [0u8; 4];
                            bytes.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        other => {
                            return Err(ScteError::DecodeError(format!(
                                "invalid escape '\\{}' at byte {}",
                                other as char,
                                self.pos
                            )));
                        }
                    }
                }
                // JSON forbids unescaped control characters.
                0x00..=0x1F => {
                    return Err(ScteError::DecodeError(format!(
                        "unescaped control character 0x{b:02x} in string"
                    )));
                }
                other => bytes.push(other),
            }
        }
    }

    /// Parse the 4 hex digits after `\u`, handling UTF-16 surrogate pairs.
    fn parse_unicode_escape(&mut self) -> Result<char, ScteError> {
        let code = self.read_4_hex()?;

        // High surrogate (U+D800..U+DBFF) — expect \uXXXX low surrogate.
        if (0xD800..=0xDBFF).contains(&code) {
            if self.input.get(self.pos..self.pos + 2) == Some(b"\\u") {
                self.pos += 2;
                let low = self.read_4_hex()?;
                if !(0xDC00..=0xDFFF).contains(&low) {
                    return Err(ScteError::DecodeError(
                        "invalid low surrogate in UTF-16 pair".into(),
                    ));
                }
                let scalar = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                return char::from_u32(scalar).ok_or_else(|| {
                    ScteError::DecodeError(format!("invalid Unicode scalar 0x{scalar:x}"))
                });
            } else {
                return Err(ScteError::DecodeError(format!(
                    "lone high surrogate U+{code:04X} without low surrogate"
                )));
            }
        }

        // Lone low surrogate — invalid.
        if (0xDC00..=0xDFFF).contains(&code) {
            return Err(ScteError::DecodeError(format!(
                "unexpected low surrogate U+{code:04X}"
            )));
        }

        char::from_u32(code)
            .ok_or_else(|| ScteError::DecodeError(format!("invalid code point 0x{code:x}")))
    }

    fn read_4_hex(&mut self) -> Result<u32, ScteError> {
        let mut code: u32 = 0;
        for _ in 0..4 {
            let b = self.advance()?;
            let digit = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => {
                    return Err(ScteError::DecodeError(format!(
                        "invalid hex digit '{}' in \\u escape",
                        b as char
                    )))
                }
            };
            code = (code << 4) | digit as u32;
        }
        Ok(code)
    }

    // ── Number ───────────────────────────────────────────────────────────────

    fn parse_number(&mut self) -> Result<Value, ScteError> {
        let start = self.pos;

        // Optional leading minus.
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }

        // Integer part.
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
                // After leading zero, only `.`, `e`/`E`, or a non-digit may follow.
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(ScteError::DecodeError(
                        "leading zeros not allowed in JSON number".into(),
                    ));
                }
            }
            Some(b'1'..=b'9') => {
                self.pos += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => {
                return Err(ScteError::DecodeError(format!(
                    "invalid number at byte {start}"
                )))
            }
        }

        let mut is_float = false;

        // Fractional part.
        if self.peek() == Some(b'.') {
            is_float = true;
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(ScteError::DecodeError(
                    "digit expected after decimal point".into(),
                ));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }

        // Exponent part.
        if matches!(self.peek(), Some(b'e' | b'E')) {
            is_float = true;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(ScteError::DecodeError(
                    "digit expected in exponent".into(),
                ));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }

        let num_str = std::str::from_utf8(&self.input[start..self.pos])
            .map_err(|_| ScteError::DecodeError("non-UTF-8 in number token".into()))?;

        if is_float {
            let f: f64 = num_str.parse().map_err(|_| {
                ScteError::DecodeError(format!("invalid float: '{num_str}'"))
            })?;
            if f.is_nan() || f.is_infinite() {
                return Err(ScteError::DecodeError(format!(
                    "float value out of range: '{num_str}'"
                )));
            }
            // Normalize: if float is exactly an integer, store as Int.
            // e.g. 1.0 → Int(1), but 1.5 stays Float(1.5).
            if f.fract() == 0.0 && f >= i64::MIN as f64 && f <= i64::MAX as f64 {
                Ok(Value::Int(f as i64))
            } else {
                Ok(Value::Float(f))
            }
        } else {
            let i: i64 = num_str.parse().map_err(|_| {
                ScteError::DecodeError(format!("integer out of i64 range: '{num_str}'"))
            })?;
            Ok(Value::Int(i))
        }
    }

    // ── Array ────────────────────────────────────────────────────────────────

    fn parse_array(&mut self) -> Result<Value, ScteError> {
        self.expect_byte(b'[')?;
        self.skip_whitespace();

        let mut items: Vec<Value> = Vec::new();

        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }

        loop {
            items.push(self.parse_value()?);
            self.skip_whitespace();
            match self.peek().ok_or(ScteError::UnexpectedEof)? {
                b',' => {
                    self.pos += 1;
                    self.skip_whitespace();
                    if self.peek() == Some(b']') {
                        return Err(ScteError::DecodeError(
                            "trailing comma in array".into(),
                        ));
                    }
                }
                b']' => {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                }
                b => {
                    return Err(ScteError::DecodeError(format!(
                        "expected ',' or ']', found 0x{b:02x} at byte {}",
                        self.pos
                    )))
                }
            }
        }
    }

    // ── Object ───────────────────────────────────────────────────────────────

    fn parse_object(&mut self) -> Result<Value, ScteError> {
        self.expect_byte(b'{')?;
        self.skip_whitespace();

        let mut entries: Vec<(String, Value)> = Vec::new();

        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(entries));
        }

        loop {
            self.skip_whitespace();
            let key = self.parse_string()?;
            self.skip_whitespace();
            self.expect_byte(b':')?;
            let val = self.parse_value()?;
            entries.push((key, val));
            self.skip_whitespace();
            match self.peek().ok_or(ScteError::UnexpectedEof)? {
                b',' => {
                    self.pos += 1;
                    self.skip_whitespace();
                    if self.peek() == Some(b'}') {
                        return Err(ScteError::DecodeError(
                            "trailing comma in object".into(),
                        ));
                    }
                }
                b'}' => {
                    self.pos += 1;
                    return Ok(Value::Object(entries));
                }
                b => {
                    return Err(ScteError::DecodeError(format!(
                        "expected ',' or '}}', found 0x{b:02x} at byte {}",
                        self.pos
                    )))
                }
            }
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Value {
        parse(s.as_bytes()).expect("parse failed")
    }

    fn pe(s: &str) -> ScteError {
        parse(s.as_bytes()).expect_err("expected parse error")
    }

    // ── Null / Bool ──────────────────────────────────────────────────────────

    #[test]
    fn parse_null() { assert_eq!(p("null"), Value::Null); }

    #[test]
    fn parse_true() { assert_eq!(p("true"), Value::Bool(true)); }

    #[test]
    fn parse_false() { assert_eq!(p("false"), Value::Bool(false)); }

    #[test]
    fn whitespace_around_value() { assert_eq!(p("  null  "), Value::Null); }

    // ── Numbers ──────────────────────────────────────────────────────────────

    #[test]
    fn parse_zero()     { assert_eq!(p("0"),   Value::Int(0)); }
    #[test]
    fn parse_positive() { assert_eq!(p("42"),  Value::Int(42)); }
    #[test]
    fn parse_negative() { assert_eq!(p("-7"),  Value::Int(-7)); }

    #[test]
    fn float_normalized_to_int() {
        // 1.0 has no fractional part → Int(1)
        assert_eq!(p("1.0"),  Value::Int(1));
        assert_eq!(p("2.0"),  Value::Int(2));
        assert_eq!(p("-3.0"), Value::Int(-3));
    }

    #[test]
    fn genuine_float() {
        assert_eq!(p("1.5"),  Value::Float(1.5));
        assert_eq!(p("-0.5"), Value::Float(-0.5));
    }

    #[test]
    fn exponent_integer() {
        // 1e2 = 100 → Int(100)
        assert_eq!(p("1e2"), Value::Int(100));
        assert_eq!(p("2E1"), Value::Int(20));
    }

    #[test]
    fn exponent_float() {
        // 1.5e1 = 15.0 → Int(15)
        assert_eq!(p("1.5e1"), Value::Int(15));
        // 1.1e1 = 11.0 → Int(11)
        assert_eq!(p("1.1e1"), Value::Int(11));
        // 1.23e0 = 1.23 → Float(1.23)
        assert_eq!(p("1.23e0"), Value::Float(1.23));
    }

    #[test]
    fn leading_zeros_rejected() {
        assert!(matches!(pe("01"), ScteError::DecodeError(_)));
    }

    // ── Strings ──────────────────────────────────────────────────────────────

    #[test]
    fn empty_string()  { assert_eq!(p(r#""""#), Value::Str("".into())); }
    #[test]
    fn simple_string() { assert_eq!(p(r#""hello""#), Value::Str("hello".into())); }

    #[test]
    fn escape_sequences() {
        assert_eq!(p(r#""\n""#),  Value::Str("\n".into()));
        assert_eq!(p(r#""\t""#),  Value::Str("\t".into()));
        assert_eq!(p(r#""\r""#),  Value::Str("\r".into()));
        assert_eq!(p(r#""\"""#),  Value::Str("\"".into()));
        assert_eq!(p(r#""\\""#),  Value::Str("\\".into()));
    }

    #[test]
    fn unicode_escape_ascii() {
        assert_eq!(p(r#""\u0041""#), Value::Str("A".into()));
    }

    #[test]
    fn unicode_escape_bmp() {
        assert_eq!(p(r#""\u00E9""#), Value::Str("é".into()));
    }

    #[test]
    fn unicode_surrogate_pair() {
        // U+1F600 GRINNING FACE = \uD83D\uDE00
        assert_eq!(p(r#""\uD83D\uDE00""#), Value::Str("😀".into()));
    }

    #[test]
    fn unescaped_control_char_rejected() {
        let mut bad = String::from("\"");
        bad.push('\x0A'); // raw newline
        bad.push('"');
        assert!(matches!(pe(&bad), ScteError::DecodeError(_)));
    }

    // ── Array ────────────────────────────────────────────────────────────────

    #[test]
    fn empty_array()  { assert_eq!(p("[]"), Value::Array(vec![])); }

    #[test]
    fn array_of_ints() {
        assert_eq!(p("[1,2,3]"), Value::Array(vec![
            Value::Int(1), Value::Int(2), Value::Int(3),
        ]));
    }

    #[test]
    fn nested_array() {
        assert_eq!(p("[[1]]"), Value::Array(vec![
            Value::Array(vec![Value::Int(1)]),
        ]));
    }

    #[test]
    fn array_with_whitespace() {
        assert_eq!(p("[ 1 , 2 ]"), Value::Array(vec![Value::Int(1), Value::Int(2)]));
    }

    #[test]
    fn trailing_comma_array_rejected() {
        assert!(matches!(pe("[1,]"), ScteError::DecodeError(_)));
    }

    // ── Object ───────────────────────────────────────────────────────────────

    #[test]
    fn empty_object() { assert_eq!(p("{}"), Value::Object(vec![])); }

    #[test]
    fn simple_object() {
        assert_eq!(p(r#"{"a":1}"#), Value::Object(vec![
            ("a".into(), Value::Int(1)),
        ]));
    }

    #[test]
    fn object_preserves_parse_order() {
        // Keys stored in parse order, NOT sorted (canonicalize sorts them).
        let v = p(r#"{"z":1,"a":2}"#);
        if let Value::Object(entries) = v {
            assert_eq!(entries[0].0, "z");
            assert_eq!(entries[1].0, "a");
        } else {
            panic!("expected Object");
        }
    }

    #[test]
    fn trailing_comma_object_rejected() {
        assert!(matches!(pe(r#"{"a":1,}"#), ScteError::DecodeError(_)));
    }

    #[test]
    fn nested_object() {
        let v = p(r#"{"user":{"id":1}}"#);
        if let Value::Object(entries) = v {
            assert_eq!(entries[0].0, "user");
            if let Value::Object(inner) = &entries[0].1 {
                assert_eq!(inner[0].0, "id");
                assert_eq!(inner[0].1, Value::Int(1));
            } else {
                panic!("expected nested Object");
            }
        } else {
            panic!("expected Object");
        }
    }

    // ── Error cases ──────────────────────────────────────────────────────────

    #[test]
    fn empty_input_errors() {
        assert!(matches!(pe(""), ScteError::UnexpectedEof));
    }

    #[test]
    fn trailing_content_rejected() {
        assert!(matches!(pe("1 2"), ScteError::DecodeError(_)));
    }

    #[test]
    fn lone_high_surrogate_rejected() {
        assert!(matches!(pe(r#""\uD800""#), ScteError::DecodeError(_)));
    }
}
