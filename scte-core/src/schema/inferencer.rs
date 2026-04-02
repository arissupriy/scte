/// Schema inferencer — Phase 5.
///
/// Scans an encoded token stream to build a `FileSchema` describing
/// each field's inferred type and distribution.
///
/// # Status: STUB (Phase 5)
/// Returns an empty schema. Phase 5 will implement full inference.
use crate::schema::field_type::FieldType;

/// Schema entry for one field (JSON path or CSV column name).
#[derive(Debug, Clone)]
pub struct FieldSchema {
    /// Dot-separated field path, e.g. `"user.status"`.
    pub path: String,
    /// Inferred field type.
    pub field_type: FieldType,
}

/// Schema inferred from an entire file by Pass 1.
///
/// Stored in SCHEMA section (0x08). The decoder reads this before
/// decoding the TOKENS section to reconstruct the exact encoding.
#[derive(Debug, Clone, Default)]
pub struct FileSchema {
    /// Fields in the order first observed.
    pub fields: Vec<FieldSchema>,
}

impl FileSchema {
    /// Build a schema by scanning a token stream.
    ///
    /// # Status: STUB — returns empty schema.
    pub fn build(_tokens: &[crate::pipelines::text::dictionary::EncodedToken]) -> Self {
        Self { fields: Vec::new() }
    }

    /// Returns true if a field with the given path is present.
    pub fn has_field(&self, path: &str) -> bool {
        self.fields.iter().any(|f| f.path == path)
    }
}
