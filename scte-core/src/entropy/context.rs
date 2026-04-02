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

use std::collections::BTreeMap;

/// A context key used to look up a probability distribution.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
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

// ── ContextModel ──────────────────────────────────────────────────────────────

/// Minimum observations in a context before it is trusted over the parent.
const MIN_MODEL_COUNT: u32 = 4;

/// Per-field, schema-aware bit-probability model backed by a `BTreeMap`.
///
/// Maps each `ContextKey` to a `[count_0, count_1]` pair, then uses the
/// KT estimator with parent-context fallback, mirroring the per-bit logic
/// in `ctw.rs` but keyed by field path instead of a bit-shift history.
pub struct ContextModel {
    /// counts[key] = [count_0, count_1]
    nodes: BTreeMap<ContextKey, [u32; 2]>,
}

impl ContextModel {
    pub fn new() -> Self {
        Self { nodes: BTreeMap::new() }
    }

    /// Record that `bit` was observed under `ctx`.
    /// Also updates all ancestor contexts (via `parent()` chain).
    pub fn update(&mut self, ctx: &ContextKey, bit: bool) {
        let mut key = ctx.clone();
        loop {
            let counts = self.nodes.entry(key.clone()).or_default();
            counts[bit as usize] += 1;
            match key.parent() {
                Some(p) => key = p,
                None    => break,
            }
        }
    }

    /// KT-estimated probability of the next bit being 0 under `ctx`.
    /// Falls back through `parent()` until a well-populated context is found;
    /// returns the uniform prior `(1, 2)` if none exists.
    pub fn prob_zero(&self, ctx: &ContextKey) -> (u64, u64) {
        let mut key: Option<ContextKey> = Some(ctx.clone());
        while let Some(ref k) = key {
            if let Some(&[c0, c1]) = self.nodes.get(k) {
                let total = c0 + c1;
                if k.history.is_empty() || total >= MIN_MODEL_COUNT {
                    let a = c0 as u64;
                    let n = total as u64;
                    return (2 * a + 1, 2 * n + 2);
                }
            }
            key = k.parent();
        }
        (1, 2) // uniform prior
    }
}

impl Default for ContextModel { fn default() -> Self { Self::new() } }

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn key(path: &str, hist: &[u8]) -> ContextKey {
        ContextKey::new(path, hist.to_vec(), 0)
    }

    #[test]
    fn parent_chain_shortens_history() {
        let k = key("f", &[1, 2, 3]);
        assert_eq!(k.parent().unwrap().history, vec![2, 3]);
        assert_eq!(k.parent().unwrap().parent().unwrap().history, vec![3]);
        assert_eq!(k.parent().unwrap().parent().unwrap().parent().unwrap().history, vec![]);
        assert!(k.parent().unwrap().parent().unwrap().parent().unwrap().parent().is_none());
    }

    #[test]
    fn uniform_prior_with_no_data() {
        let m = ContextModel::new();
        assert_eq!(m.prob_zero(&key("x", &[1, 2])), (1, 2));
    }

    #[test]
    fn prob_zero_updates_after_observations() {
        let mut m = ContextModel::new();
        let ctx = key("status", &[0]);
        // Observe 8 zeros → well-populated root context → prob_zero > 0.5
        for _ in 0..8 { m.update(&ctx, false); }
        let (num, den) = m.prob_zero(&ctx);
        assert!(num * 2 > den, "expected prob > 0.5 after 8 zeros, got {num}/{den}");
    }

    #[test]
    fn fallback_to_parent_when_sparse() {
        let mut m = ContextModel::new();
        let root = key("f", &[]);
        let child = key("f", &[1]);
        // Populate root (depth 0) only.
        for _ in 0..8 { m.update(&root, false); }
        // Child has < MIN_MODEL_COUNT observations → falls back to root.
        let (num, den) = m.prob_zero(&child);
        assert!(num * 2 > den, "expected parent fallback to give prob > 0.5, got {num}/{den}");
    }

    #[test]
    fn context_model_is_btreemap_ordered() {
        let mut m = ContextModel::new();
        m.update(&key("a", &[0]), false);
        m.update(&key("z", &[0]), true);
        // If BTreeMap, keys iterate "a" before "z" — just check it doesn't panic.
        let _ = m.prob_zero(&key("a", &[0]));
        let _ = m.prob_zero(&key("z", &[0]));
    }
}
