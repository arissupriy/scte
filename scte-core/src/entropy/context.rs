/// Context builder for high-order entropy models — Phase 7.
///
/// Builds rich context keys from (field_path, value_history, schema_position)
/// to feed CTW or high-order Markov models.
///
/// # Why richer context matters
/// rANS order-1 context = just the previous token kind → 10 buckets.
/// With schema-aware context, we know:
///   "This is the 3rd value of field 'status' in record 42 of a JSON array"
/// → P("ok") can be 0.999 instead of 0.8 → 100× more bits saved.
///
/// # Status: STUB (Phase 7)

/// A context key used to look up a probability distribution.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContextKey {
    /// Schema path of the current field, e.g. `"user.status"`.
    pub field_path: String,
    /// Last N symbol values seen in this field (N = context depth).
    pub history: Vec<u8>,
    /// Position within current record (column index).
    pub record_position: usize,
}

impl ContextKey {
    pub fn new(field_path: impl Into<String>, history: Vec<u8>, record_position: usize) -> Self {
        Self {
            field_path: field_path.into(),
            history,
            record_position,
        }
    }

    /// Fallback: drop deepest history item to get parent context.
    pub fn parent(&self) -> Option<Self> {
        if self.history.is_empty() {
            None
        } else {
            let mut h = self.history.clone();
            h.remove(0);
            Some(Self {
                field_path: self.field_path.clone(),
                history: h,
                record_position: self.record_position,
            })
        }
    }
}
