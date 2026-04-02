/// Schema section serializer — Phase 5.
///
/// Converts `FileSchema` to/from the binary SCHEMA section (0x08)
/// stored in the SCTE container.
///
/// # Wire format (Phase 5)
/// ```text
/// varint(field_count)
/// for each field:
///     varint(path_len) + utf8_bytes(path)
///     u8(field_type_tag)
///     if Enum:
///         varint(variant_count)
///         for each variant: varint(len) + utf8_bytes
///     if Integer:
///         u8(int_hint)
/// ```
///
/// # Status: STUB (Phase 5)
use crate::error::ScteError;
use crate::schema::inferencer::FileSchema;

/// Serialize a `FileSchema` to bytes for the SCHEMA section.
///
/// # Status: STUB — returns empty bytes (no schema = no change to encoding).
pub fn serialize(_schema: &FileSchema) -> Vec<u8> {
    Vec::new()
}

/// Deserialize a SCHEMA section back to `FileSchema`.
///
/// # Status: STUB — returns empty schema.
pub fn deserialize(_data: &[u8]) -> Result<FileSchema, ScteError> {
    Ok(FileSchema::default())
}
