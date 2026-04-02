/// Columnarization stage — reorganizes row-oriented token streams into
/// per-column streams for better compression.
///
/// # Phase boundary
/// - **Phase 2**: detect homogeneous arrays, split into `ColumnStream` per field.
/// - **Phase 6**: `IntegerEncoder` on each `ColumnStream` gains delta/pattern
///   detection — plug in without changing this module's interface.
///
/// # Design constraint
/// `ColumnStream` owns `Vec<ColumnValue>` — values are decoded *typed*, not
/// re-serialized as JSON bytes. This lets Phase 6 delta-encode them directly.
use crate::pipelines::text::tokenizer::TokenKind;

// ── ColumnValue ───────────────────────────────────────────────────────────────

/// A single typed value within a column.
///
/// Keeping the type information intact is what allows Phase 6 to apply
/// specialised encoders per field type without re-parsing.
#[derive(Debug, Clone, PartialEq)]
pub enum ColumnValue {
    Int(i64),
    Float(f64),
    Bool(bool),
    Str(String),
    Null,
}

// ── ColumnStream ──────────────────────────────────────────────────────────────

/// One column extracted from a homogeneous JSON array or CSV file.
///
/// The field path (e.g. `"user.id"`) is stored as its dictionary id once
/// the dictionary is built, or as a raw string before that.
#[derive(Debug, Clone, PartialEq)]
pub struct ColumnStream {
    /// Dot-separated JSON path or CSV column name. e.g. `"user.status"`.
    pub field_path: String,
    /// Dominant token kind in this column (aids Phase 6 encoder selection).
    pub dominant_kind: TokenKind,
    /// Values in row order.
    pub values: Vec<ColumnValue>,
}

impl ColumnStream {
    /// Create a new, empty column stream for the given field path.
    pub fn new(field_path: impl Into<String>, dominant_kind: TokenKind) -> Self {
        Self {
            field_path: field_path.into(),
            dominant_kind,
            values: Vec::new(),
        }
    }

    /// Push one value onto this column.
    #[inline]
    pub fn push(&mut self, value: ColumnValue) {
        self.values.push(value);
    }

    /// Number of rows in this column.
    #[inline]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// True if this column contains no values.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Returns true if every value is an integer — aids Phase 6 delta detection.
    pub fn is_all_int(&self) -> bool {
        self.values.iter().all(|v| matches!(v, ColumnValue::Int(_)))
    }

    /// Returns true if every value is the same — trivial RLE candidate.
    pub fn is_constant(&self) -> bool {
        let mut iter = self.values.iter();
        match iter.next() {
            None => true,
            Some(first) => iter.all(|v| v == first),
        }
    }
}

// ── ColumnarBatch ─────────────────────────────────────────────────────────────

/// A set of columns extracted from one homogeneous JSON array.
///
/// Phase 2 produces this from `tokenize_json` output.
/// Phase 6 consumes this for delta/pattern encoding.
#[derive(Debug, Clone)]
pub struct ColumnarBatch {
    /// Number of rows (records) in the original array.
    pub row_count: usize,
    /// One stream per field, in schema-declaration order.
    pub columns: Vec<ColumnStream>,
}

impl ColumnarBatch {
    /// Create an empty batch.
    pub fn new() -> Self {
        Self { row_count: 0, columns: Vec::new() }
    }

    /// Find a column by field path. Returns `None` if not found.
    pub fn column(&self, field_path: &str) -> Option<&ColumnStream> {
        self.columns.iter().find(|c| c.field_path == field_path)
    }
}

impl Default for ColumnarBatch {
    fn default() -> Self {
        Self::new()
    }
}

// ── Detector ─────────────────────────────────────────────────────────────────

/// Returns `true` if the token stream looks like a homogeneous JSON array
/// (array of objects where all objects share the same key set).
///
/// Used by Phase 2 to decide whether to columnarize.
/// Threshold: at least 2 records and all have the same keys.
pub fn is_homogeneous_array(_tokens: &[crate::pipelines::text::tokenizer::Token]) -> bool {
    // Phase 2 TODO: implement full detection.
    // Stub returns false — columnarization disabled until Phase 2 implements this.
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn column_stream_push_and_len() {
        let mut col = ColumnStream::new("user.id", TokenKind::NumInt);
        assert!(col.is_empty());
        col.push(ColumnValue::Int(1));
        col.push(ColumnValue::Int(2));
        assert_eq!(col.len(), 2);
    }

    #[test]
    fn is_all_int_true_for_int_column() {
        let mut col = ColumnStream::new("count", TokenKind::NumInt);
        col.push(ColumnValue::Int(1));
        col.push(ColumnValue::Int(2));
        assert!(col.is_all_int());
    }

    #[test]
    fn is_all_int_false_for_mixed_column() {
        let mut col = ColumnStream::new("val", TokenKind::Str);
        col.push(ColumnValue::Int(1));
        col.push(ColumnValue::Str("x".into()));
        assert!(!col.is_all_int());
    }

    #[test]
    fn is_constant_true_for_same_values() {
        let mut col = ColumnStream::new("status", TokenKind::Str);
        col.push(ColumnValue::Str("ok".into()));
        col.push(ColumnValue::Str("ok".into()));
        col.push(ColumnValue::Str("ok".into()));
        assert!(col.is_constant());
    }

    #[test]
    fn is_constant_false_for_varying_values() {
        let mut col = ColumnStream::new("id", TokenKind::NumInt);
        col.push(ColumnValue::Int(1));
        col.push(ColumnValue::Int(2));
        assert!(!col.is_constant());
    }

    #[test]
    fn columnar_batch_column_lookup() {
        let mut batch = ColumnarBatch::new();
        batch.columns.push(ColumnStream::new("a.b", TokenKind::NumInt));
        assert!(batch.column("a.b").is_some());
        assert!(batch.column("x.y").is_none());
    }
}
