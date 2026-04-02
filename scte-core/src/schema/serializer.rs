/// Schema section serializer — Phase 5.
///
/// Converts `FileSchema` to/from the binary SCHEMA section (0x08)
/// stored in the SCTE container.
///
/// # Wire format
/// ```text
/// varint(field_count)
/// for each field:
///     varint(path_len) + utf8_bytes(path)
///     u8(field_type_tag)
///         Integer   = 0x00 → followed by u8(int_hint)
///         Float     = 0x01
///         Bool      = 0x02
///         Enum      = 0x03 → followed by varint(variant_count)
///                              then for each: varint(len) + utf8_bytes
///         Timestamp = 0x04
///         Str       = 0x05
///         Null      = 0x06
///     IntHint (only when tag == 0x00):
///         Flat       = 0x00
///         Sequential = 0x01
///         Monotonic  = 0x02
///         Clustered  = 0x03
/// ```
use crate::error::ScteError;
use crate::schema::field_type::{FieldType, IntHint};
use crate::schema::inferencer::{FieldSchema, FileSchema};
use crate::varint::{decode_usize, encode_usize};

// ── Tag constants ─────────────────────────────────────────────────────────────

const TAG_INTEGER:   u8 = 0x00;
const TAG_FLOAT:     u8 = 0x01;
const TAG_BOOL:      u8 = 0x02;
const TAG_ENUM:      u8 = 0x03;
const TAG_TIMESTAMP: u8 = 0x04;
const TAG_STR:       u8 = 0x05;
const TAG_NULL:      u8 = 0x06;

const HINT_FLAT:       u8 = 0x00;
const HINT_SEQUENTIAL: u8 = 0x01;
const HINT_MONOTONIC:  u8 = 0x02;
const HINT_CLUSTERED:  u8 = 0x03;

// ── Public API ────────────────────────────────────────────────────────────────

/// Serialize a `FileSchema` to bytes for the SCHEMA section (0x08).
///
/// An empty schema serializes to a single zero byte (`varint(0)`).
pub fn serialize(schema: &FileSchema) -> Vec<u8> {
    let mut out = Vec::new();
    encode_usize(schema.fields.len(), &mut out);

    for field in &schema.fields {
        // path
        let path_bytes = field.path.as_bytes();
        encode_usize(path_bytes.len(), &mut out);
        out.extend_from_slice(path_bytes);

        // type tag + optional extra bytes
        match &field.field_type {
            FieldType::Integer { hint } => {
                out.push(TAG_INTEGER);
                out.push(hint_to_byte(*hint));
            }
            FieldType::Float     => out.push(TAG_FLOAT),
            FieldType::Bool      => out.push(TAG_BOOL),
            FieldType::Timestamp => out.push(TAG_TIMESTAMP),
            FieldType::Str       => out.push(TAG_STR),
            FieldType::Null      => out.push(TAG_NULL),
            FieldType::Enum { variants } => {
                out.push(TAG_ENUM);
                encode_usize(variants.len(), &mut out);
                for v in variants {
                    let b = v.as_bytes();
                    encode_usize(b.len(), &mut out);
                    out.extend_from_slice(b);
                }
            }
        }
    }

    out
}

/// Deserialize a SCHEMA section payload back to `FileSchema`.
///
/// # Errors
/// Returns `ScteError::DecodeError` if the buffer is truncated, contains
/// unknown type tags, or has invalid UTF-8 in paths/variants.
pub fn deserialize(data: &[u8]) -> Result<FileSchema, ScteError> {
    let mut pos = 0usize;

    let (field_count, consumed) = decode_usize(data, pos)
        .ok_or_else(|| ScteError::DecodeError("schema: truncated field_count".into()))?;
    pos += consumed;

    let mut fields = Vec::with_capacity(field_count);

    for _ in 0..field_count {
        // ── path ──────────────────────────────────────────────────────────────
        let (path_len, consumed) = decode_usize(data, pos)
            .ok_or_else(|| ScteError::DecodeError("schema: truncated path_len".into()))?;
        pos += consumed;

        let path_bytes = data.get(pos..pos + path_len)
            .ok_or_else(|| ScteError::DecodeError("schema: truncated path bytes".into()))?;
        let path = std::str::from_utf8(path_bytes)
            .map_err(|_| ScteError::DecodeError("schema: invalid UTF-8 in path".into()))?
            .to_owned();
        pos += path_len;

        // ── type tag ──────────────────────────────────────────────────────────
        let tag = *data.get(pos)
            .ok_or_else(|| ScteError::DecodeError("schema: missing type tag".into()))?;
        pos += 1;

        let field_type = match tag {
            TAG_INTEGER => {
                let hint_byte = *data.get(pos)
                    .ok_or_else(|| ScteError::DecodeError("schema: missing IntHint".into()))?;
                pos += 1;
                FieldType::Integer { hint: byte_to_hint(hint_byte)? }
            }
            TAG_FLOAT     => FieldType::Float,
            TAG_BOOL      => FieldType::Bool,
            TAG_TIMESTAMP => FieldType::Timestamp,
            TAG_STR       => FieldType::Str,
            TAG_NULL      => FieldType::Null,
            TAG_ENUM => {
                let (variant_count, consumed) = decode_usize(data, pos)
                    .ok_or_else(|| ScteError::DecodeError("schema: truncated variant_count".into()))?;
                pos += consumed;

                let mut variants = Vec::with_capacity(variant_count);
                for _ in 0..variant_count {
                    let (len, consumed) = decode_usize(data, pos)
                        .ok_or_else(|| ScteError::DecodeError("schema: truncated variant len".into()))?;
                    pos += consumed;

                    let bytes = data.get(pos..pos + len)
                        .ok_or_else(|| ScteError::DecodeError("schema: truncated variant bytes".into()))?;
                    let s = std::str::from_utf8(bytes)
                        .map_err(|_| ScteError::DecodeError("schema: invalid UTF-8 in variant".into()))?
                        .to_owned();
                    pos += len;
                    variants.push(s);
                }
                FieldType::Enum { variants }
            }
            other => {
                return Err(ScteError::DecodeError(format!(
                    "schema: unknown field type tag {other:#04x}"
                )))
            }
        };

        fields.push(FieldSchema { path, field_type });
    }

    Ok(FileSchema { fields })
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn hint_to_byte(h: IntHint) -> u8 {
    match h {
        IntHint::Flat       => HINT_FLAT,
        IntHint::Sequential => HINT_SEQUENTIAL,
        IntHint::Monotonic  => HINT_MONOTONIC,
        IntHint::Clustered  => HINT_CLUSTERED,
    }
}

fn byte_to_hint(b: u8) -> Result<IntHint, ScteError> {
    match b {
        HINT_FLAT       => Ok(IntHint::Flat),
        HINT_SEQUENTIAL => Ok(IntHint::Sequential),
        HINT_MONOTONIC  => Ok(IntHint::Monotonic),
        HINT_CLUSTERED  => Ok(IntHint::Clustered),
        other           => Err(ScteError::DecodeError(format!(
            "schema: unknown IntHint byte {other:#04x}"
        ))),
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::inferencer::FileSchema;
    use crate::pipelines::text::tokenizer::tokenize_json;

    fn roundtrip(schema: &FileSchema) -> FileSchema {
        let bytes = serialize(schema);
        deserialize(&bytes).expect("deserialize failed")
    }

    fn schema_of(json: &str) -> FileSchema {
        let tokens = tokenize_json(json.as_bytes()).unwrap();
        FileSchema::build(&tokens)
    }

    #[test]
    fn empty_schema_roundtrip() {
        let s = FileSchema::default();
        let rt = roundtrip(&s);
        assert!(rt.fields.is_empty());
    }

    #[test]
    fn empty_schema_serializes_to_one_byte() {
        let bytes = serialize(&FileSchema::default());
        assert_eq!(bytes, vec![0x00]);
    }

    #[test]
    fn integer_field_roundtrip() {
        let s = schema_of(r#"[{"id":1},{"id":2}]"#);
        let rt = roundtrip(&s);
        assert_eq!(rt.field_type("id"), s.field_type("id"));
    }

    #[test]
    fn bool_field_roundtrip() {
        let s = schema_of(r#"[{"active":true},{"active":false}]"#);
        let rt = roundtrip(&s);
        assert_eq!(rt.field_type("active"), s.field_type("active"));
    }

    #[test]
    fn enum_field_roundtrip() {
        let s = schema_of(
            r#"[{"role":"admin"},{"role":"user"},{"role":"admin"}]"#,
        );
        let rt = roundtrip(&s);
        assert_eq!(rt.field_type("role"), s.field_type("role"));
    }

    #[test]
    fn complex_schema_roundtrip() {
        let json = r#"[
            {"id":1,"status":"ok","active":true,"score":1.5,"tag":"alpha"},
            {"id":2,"status":"fail","active":false,"score":2.0,"tag":"beta"}
        ]"#;
        let s = schema_of(json);
        let rt = roundtrip(&s);
        for f in &s.fields {
            assert_eq!(rt.field_type(&f.path), s.field_type(&f.path),
                       "mismatch for field {}", f.path);
        }
    }

    #[test]
    fn unknown_tag_returns_error() {
        // field_count=1, path="x" (len=1), tag=0xFF
        let bad = vec![0x01, 0x01, b'x', 0xFF];
        assert!(deserialize(&bad).is_err());
    }

    #[test]
    fn truncated_data_returns_error() {
        let s = schema_of(r#"[{"role":"admin"}]"#);
        let mut bytes = serialize(&s);
        bytes.truncate(bytes.len() / 2);
        assert!(deserialize(&bytes).is_err());
    }
}
