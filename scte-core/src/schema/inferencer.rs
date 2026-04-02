/// Schema inferencer — Phase 5.
///
/// Scans a raw token stream (output of `tokenize_json`) to build a
/// `FileSchema` describing each field's inferred type and distribution.
///
/// # Algorithm
/// Single pass over the token stream. A `PathContext` stack tracks the
/// current dot-separated field path (`"user.role"`, `"items.price"`, etc.).
/// For each value token the field path is looked up in an observation map
/// and the payload type is recorded. After the pass each accumulated
/// `FieldObs` is converted to a `FieldType`.
///
/// # Enum detection
/// A string field with ≤ [`MAX_ENUM_VARIANTS`] distinct observed values is
/// classified as `FieldType::Enum`. Variants are emitted sorted by frequency
/// descending (then alpha ascending on ties) — the highest-frequency variant
/// gets index 0, which the `TwoPassEncoder` stores in the fewest bits.
use std::collections::BTreeMap;

use crate::pipelines::text::tokenizer::{Token, TokenKind, TokenPayload};
use crate::schema::field_type::{FieldType, IntHint};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of unique string values a field may have to be treated as
/// an enum. Fields with more unique values are classified as `Str`.
pub const MAX_ENUM_VARIANTS: usize = 64;

// ── Public types ──────────────────────────────────────────────────────────────

/// Schema entry for one field (dot-separated JSON path).
#[derive(Debug, Clone, PartialEq)]
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
    /// Fields in observation order.
    pub fields: Vec<FieldSchema>,
}

impl FileSchema {
    // ── Construction ──────────────────────────────────────────────────────────

    /// Build a schema by making a single pass over a raw `Token` stream
    /// (output of [`tokenize_json`][crate::pipelines::text::tokenize_json]).
    ///
    /// The returned schema describes the inferred type of every JSON field
    /// path encountered. Array elements are all attributed to the parent
    /// field path (no index suffixes — Phase 6 may refine this).
    pub fn build(tokens: &[Token]) -> Self {
        let mut obs: BTreeMap<String, FieldObs> = BTreeMap::new();
        let mut ctx = PathContext::new();

        for token in tokens {
            match token.kind {
                TokenKind::ObjOpen  => ctx.push_obj(),
                TokenKind::ObjClose => ctx.pop(),
                TokenKind::ArrOpen  => ctx.push_arr(),
                TokenKind::ArrClose => ctx.pop(),

                TokenKind::Key => {
                    if let TokenPayload::Str(ref k) = token.payload {
                        ctx.set_key(k.clone());
                    }
                }

                TokenKind::NumInt => {
                    record_value(&ctx, &mut obs, |o| o.push_int());
                    ctx.clear_key();
                }
                TokenKind::NumFloat => {
                    record_value(&ctx, &mut obs, |o| o.push_float());
                    ctx.clear_key();
                }
                TokenKind::Bool => {
                    record_value(&ctx, &mut obs, |o| o.push_bool());
                    ctx.clear_key();
                }
                TokenKind::Null => {
                    record_value(&ctx, &mut obs, |o| o.push_null());
                    ctx.clear_key();
                }
                TokenKind::Str => {
                    if let TokenPayload::Str(ref s) = token.payload {
                        let s = s.clone();
                        record_value(&ctx, &mut obs, |o| o.push_str(&s));
                    }
                    ctx.clear_key();
                }

                // Structural variants already handled above; exhaustive match.
            }
        }

        // Convert observations → FieldSchema, preserving first-observed order
        // (obs is BTreeMap so keys are sorted alphabetically — acceptable for
        //  Phase 5; Phase 6 may preserve insertion order if needed).
        let fields = obs
            .into_iter()
            .map(|(path, o)| FieldSchema { path, field_type: o.infer() })
            .collect();

        Self { fields }
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    /// Returns `true` if a field with the given path is present.
    pub fn has_field(&self, path: &str) -> bool {
        self.fields.iter().any(|f| f.path == path)
    }

    /// Return the `FieldType` for a path, or `None` if unknown.
    pub fn field_type(&self, path: &str) -> Option<&FieldType> {
        self.fields.iter().find(|f| f.path == path).map(|f| &f.field_type)
    }

    /// If `path` is an `Enum` field, return the 0-based variant index for
    /// `value`.  Returns `None` if the path is not an enum or the value is
    /// not a known variant.
    pub fn enum_variant_index(&self, path: &str, value: &str) -> Option<u32> {
        if let Some(FieldType::Enum { ref variants }) = self.field_type(path) {
            variants.iter().position(|v| v == value).map(|i| i as u32)
        } else {
            None
        }
    }

    /// If `path` is an `Enum` field, return the variant string at `index`.
    pub fn enum_variant_str(&self, path: &str, index: u32) -> Option<&str> {
        if let Some(FieldType::Enum { ref variants }) = self.field_type(path) {
            variants.get(index as usize).map(|s| s.as_str())
        } else {
            None
        }
    }
}

// ── Internal: path-context stack ─────────────────────────────────────────────

enum Frame {
    Object { last_key: Option<String> },
    Array,
}

struct PathContext {
    frames: Vec<Frame>,
}

impl PathContext {
    fn new() -> Self {
        Self { frames: Vec::new() }
    }

    fn push_obj(&mut self) {
        self.frames.push(Frame::Object { last_key: None });
    }

    fn push_arr(&mut self) {
        self.frames.push(Frame::Array);
    }

    fn pop(&mut self) {
        self.frames.pop();
    }

    fn set_key(&mut self, key: String) {
        if let Some(Frame::Object { last_key }) = self.frames.last_mut() {
            *last_key = Some(key);
        }
    }

    /// Dot-separated path for the *value* about to be recorded.
    ///
    /// Collects all `last_key`s from Object frames in stack order.
    /// Array frames do not contribute a path segment.
    fn current_path(&self) -> String {
        let parts: Vec<&str> = self
            .frames
            .iter()
            .filter_map(|f| {
                if let Frame::Object { last_key: Some(k) } = f {
                    Some(k.as_str())
                } else {
                    None
                }
            })
            .collect();
        parts.join(".")
    }

    /// Clear the top Object frame's key after a value has been recorded.
    fn clear_key(&mut self) {
        if let Some(Frame::Object { last_key }) = self.frames.last_mut() {
            *last_key = None;
        }
    }
}

// ── Internal: per-field observation accumulator ───────────────────────────────

#[derive(Default)]
struct FieldObs {
    int_count:   u64,
    float_count: u64,
    bool_count:  u64,
    null_count:  u64,
    /// Observed string values → count.
    str_values:  BTreeMap<String, u64>,
    total:       u64,
}

impl FieldObs {
    fn push_int(&mut self)           { self.int_count   += 1; self.total += 1; }
    fn push_float(&mut self)         { self.float_count += 1; self.total += 1; }
    fn push_bool(&mut self)          { self.bool_count  += 1; self.total += 1; }
    fn push_null(&mut self)          { self.null_count  += 1; self.total += 1; }
    fn push_str(&mut self, s: &str)  {
        *self.str_values.entry(s.to_owned()).or_insert(0) += 1;
        self.total += 1;
    }

    /// Infer the best `FieldType` from accumulated observations.
    fn infer(&self) -> FieldType {
        let str_count: u64 = self.str_values.values().sum();
        let num_count       = self.int_count + self.float_count;
        let typed_count     = num_count + self.bool_count;
        let non_null_total  = self.total.saturating_sub(self.null_count);

        if non_null_total == 0 {
            return FieldType::Null;
        }

        // ── Pure integer ──────────────────────────────────────────────────────
        if self.int_count == non_null_total {
            return FieldType::Integer { hint: IntHint::Flat };
        }

        // ── Pure float (or int+float mix treated as float) ────────────────────
        if num_count == non_null_total && self.bool_count == 0 && str_count == 0 {
            return FieldType::Float;
        }

        // ── Pure bool ─────────────────────────────────────────────────────────
        if self.bool_count == non_null_total {
            return FieldType::Bool;
        }

        // ── Pure string field ─────────────────────────────────────────────────
        if str_count == non_null_total && typed_count == 0 {
            // Timestamp heuristic: YYYY-MM-DD prefix
            if let Some(first) = self.str_values.keys().next() {
                if looks_like_timestamp(first) {
                    return FieldType::Timestamp;
                }
            }

            // Enum: ≤ MAX_ENUM_VARIANTS unique values
            if self.str_values.len() <= MAX_ENUM_VARIANTS {
                let mut variants: Vec<(String, u64)> = self
                    .str_values
                    .iter()
                    .map(|(k, v)| (k.clone(), *v))
                    .collect();
                // Sort: frequency desc, then alpha asc (deterministic)
                variants.sort_unstable_by(|(ka, fa), (kb, fb)| {
                    fb.cmp(fa).then_with(|| ka.as_bytes().cmp(kb.as_bytes()))
                });
                let variant_strings: Vec<String> =
                    variants.into_iter().map(|(k, _)| k).collect();
                return FieldType::Enum { variants: variant_strings };
            }

            return FieldType::Str;
        }

        // Mixed types → fall back to Str
        FieldType::Str
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Record a value observation at the current path (if non-empty).
fn record_value(ctx: &PathContext, obs: &mut BTreeMap<String, FieldObs>, f: impl FnOnce(&mut FieldObs)) {
    let path = ctx.current_path();
    if !path.is_empty() {
        f(obs.entry(path).or_default());
    }
}

/// Heuristic timestamp check: string starts with `YYYY-MM-DD`.
fn looks_like_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b[..4].iter().all(|c| c.is_ascii_digit())
        && b[5..7].iter().all(|c| c.is_ascii_digit())
        && b[8..10].iter().all(|c| c.is_ascii_digit())
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipelines::text::tokenizer::tokenize_json;

    fn build(json: &str) -> FileSchema {
        let tokens = tokenize_json(json.as_bytes()).unwrap();
        FileSchema::build(&tokens)
    }

    #[test]
    fn empty_input_gives_empty_schema() {
        let s = build("{}");
        assert!(s.fields.is_empty());
    }

    #[test]
    fn detects_integer_field() {
        let json = r#"[{"id":1},{"id":2},{"id":3}]"#;
        let s = build(json);
        assert_eq!(s.field_type("id"), Some(&FieldType::Integer { hint: IntHint::Flat }));
    }

    #[test]
    fn detects_bool_field() {
        let s = build(r#"[{"active":true},{"active":false}]"#);
        assert_eq!(s.field_type("active"), Some(&FieldType::Bool));
    }

    #[test]
    fn detects_enum_field() {
        let json = r#"[{"role":"admin"},{"role":"user"},{"role":"admin"}]"#;
        let s = build(json);
        match s.field_type("role") {
            Some(FieldType::Enum { variants }) => {
                // "admin" has freq 2, "user" freq 1 → admin is first
                assert_eq!(variants[0], "admin");
                assert_eq!(variants[1], "user");
            }
            other => panic!("expected Enum, got {other:?}"),
        }
    }

    #[test]
    fn enum_variant_index_and_str_roundtrip() {
        let json = r#"[{"status":"ok"},{"status":"fail"},{"status":"ok"}]"#;
        let s = build(json);
        // "ok" (freq 2) → index 0; "fail" (freq 1) → index 1
        assert_eq!(s.enum_variant_index("status", "ok"),   Some(0));
        assert_eq!(s.enum_variant_index("status", "fail"), Some(1));
        assert_eq!(s.enum_variant_str("status", 0), Some("ok"));
        assert_eq!(s.enum_variant_str("status", 1), Some("fail"));
    }

    #[test]
    fn high_cardinality_string_is_str_not_enum() {
        // 65 unique names → Str, not Enum
        let entries: String = (0..65)
            .map(|i| format!(r#"{{"name":"user_{i}"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let json = format!("[{entries}]");
        let s = build(&json);
        assert_eq!(s.field_type("name"), Some(&FieldType::Str));
    }

    #[test]
    fn nested_field_path() {
        let json = r#"[{"user":{"role":"admin"}},{"user":{"role":"user"}}]"#;
        let s = build(json);
        assert!(matches!(s.field_type("user.role"), Some(FieldType::Enum { .. })));
    }

    #[test]
    fn detects_null_only_field() {
        let s = build(r#"[{"x":null},{"x":null}]"#);
        assert_eq!(s.field_type("x"), Some(&FieldType::Null));
    }

    #[test]
    fn timestamp_detected() {
        let s = build(r#"[{"ts":"2026-04-02T10:00:00Z"},{"ts":"2026-04-03T11:00:00Z"}]"#);
        assert_eq!(s.field_type("ts"), Some(&FieldType::Timestamp));
    }
}
