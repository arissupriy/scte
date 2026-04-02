/// Cross-record reference model — Phase 6.
///
/// For each field in a JSON object stream, checks whether the value at that
/// field is identical to the same field in the previous record.  If yes,
/// encode as a single "same" bit.  If no, encode the new value normally.
///
/// # Wire format per field per record
///
/// ```text
/// same_as_prev:  0x01
/// changed:       0x00  <encoded-value>
/// ```text
///
/// # Compression effect
/// For server logs where most fields repeat (ip, user, status):
/// ```text
/// Record N:   {"ip":"192.168.1.1","user":"alice","status":"ok"}
/// Record N+1: {"ip":"192.168.1.1","user":"alice","status":"error"}
///   ip     → SAME  → 1 bit
///   user   → SAME  → 1 bit
///   status → NEW   → encode "error" (enum → 1 bit with Phase 5)
/// Total: ~3 bits vs ~60 bytes raw → ~99.4% reduction
/// ```text

// Determinism invariant (plans.md §10): all stateful maps in the encode path
// must use BTreeMap, never HashMap, to guarantee identical output across runs
// regardless of hash-randomisation seed.
use std::collections::BTreeMap;

// ── CrossRecordEncoder ────────────────────────────────────────────────────────

/// Stateful encoder that tracks the previous record's field values and emits
/// `0x01` (same) or `0x00` (changed) flags.
#[derive(Debug, Default, Clone)]
pub struct CrossRecordEncoder {
    /// Last seen value per field path.
    /// BTreeMap — not HashMap — to preserve encoding determinism.
    prev: BTreeMap<String, Vec<u8>>,
}

impl CrossRecordEncoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Encode a single field value, returning the compact representation.
    ///
    /// - If `value_bytes` matches the previous value for `field`, emits `[0x01]`.
    /// - Otherwise emits `[0x00]` followed by `value_bytes`, and updates state.
    pub fn encode_field(&mut self, field: &str, value_bytes: &[u8]) -> Vec<u8> {
        if let Some(prev) = self.prev.get(field) {
            if prev.as_slice() == value_bytes {
                return vec![SAME_FLAG];
            }
        }
        let mut out = vec![CHANGED_FLAG];
        out.extend_from_slice(value_bytes);
        self.prev.insert(field.to_owned(), value_bytes.to_vec());
        out
    }

    /// Reset state — call between independent record streams.
    pub fn reset(&mut self) {
        self.prev.clear();
    }
}

// ── CrossRecordDecoder ────────────────────────────────────────────────────────

/// Stateful decoder that reconstructs field values from cross-record references.
#[derive(Debug, Default, Clone)]
pub struct CrossRecordDecoder {
    /// BTreeMap — consistent with encoder; iteration order is never relied upon
    /// but keeping the same type prevents accidental HashMap use in future.
    prev: BTreeMap<String, Vec<u8>>,
}

impl CrossRecordDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode a single field from `data[pos..]`.
    ///
    /// Returns `(value_bytes, bytes_consumed)` or `None` on truncation.
    pub fn decode_field(
        &mut self,
        field: &str,
        data: &[u8],
        pos: usize,
        value_len: usize,
    ) -> Option<(Vec<u8>, usize)> {
        let flag = *data.get(pos)?;
        if flag == SAME_FLAG {
            let prev = self.prev.get(field)?.clone();
            Some((prev, 1))
        } else if flag == CHANGED_FLAG {
            let end = pos + 1 + value_len;
            if end > data.len() { return None; }
            let val = data[pos + 1..end].to_vec();
            self.prev.insert(field.to_owned(), val.clone());
            Some((val, 1 + value_len))
        } else {
            None
        }
    }

    /// Reset state between independent record streams.
    pub fn reset(&mut self) {
        self.prev.clear();
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Ratio of same-as-previous fields in a column of equal-length byte payloads.
///
/// Used in tests to verify compression potential.
pub fn same_ratio(values: &[Vec<u8>]) -> f64 {
    if values.len() < 2 { return 0.0; }
    let same = values.windows(2).filter(|w| w[0] == w[1]).count();
    same as f64 / (values.len() - 1) as f64
}

const SAME_FLAG:    u8 = 0x01;
const CHANGED_FLAG: u8 = 0x00;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_field_always_changed() {
        let mut enc = CrossRecordEncoder::new();
        let out = enc.encode_field("ip", b"192.168.1.1");
        assert_eq!(out[0], 0x00); // CHANGED
        assert_eq!(&out[1..], b"192.168.1.1");
    }

    #[test]
    fn repeated_field_encodes_as_same() {
        let mut enc = CrossRecordEncoder::new();
        enc.encode_field("ip", b"192.168.1.1"); // first record
        let out = enc.encode_field("ip", b"192.168.1.1"); // second record, same
        assert_eq!(out, vec![0x01]); // SAME
    }

    #[test]
    fn changed_field_encodes_full_value() {
        let mut enc = CrossRecordEncoder::new();
        enc.encode_field("status", b"ok");
        let out = enc.encode_field("status", b"error");
        assert_eq!(out[0], 0x00); // CHANGED
        assert_eq!(&out[1..], b"error");
    }

    #[test]
    fn same_ratio_all_same() {
        let values: Vec<Vec<u8>> = vec![b"ok".to_vec(); 10];
        assert!((same_ratio(&values) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn same_ratio_all_different() {
        let values: Vec<Vec<u8>> = (0..10).map(|i| i.to_string().into_bytes()).collect();
        assert!((same_ratio(&values)).abs() < 1e-9);
    }

    #[test]
    fn encoding_saves_bytes_for_stable_fields() {
        let mut enc = CrossRecordEncoder::new();
        let base_value = b"192.168.1.1";
        let n = 100;
        // First record
        let first = enc.encode_field("ip", base_value);
        let mut total_encoded = first.len();
        for _ in 1..n {
            total_encoded += enc.encode_field("ip", base_value).len();
        }
        // Raw: n * 11 bytes.  Encoded: 12 + 99*1 = 111
        let total_raw = n * base_value.len();
        assert!(total_encoded < total_raw,
            "encoded={total_encoded} should be < raw={total_raw}");
    }

    #[test]
    fn reset_clears_state() {
        let mut enc = CrossRecordEncoder::new();
        enc.encode_field("x", b"val");
        enc.reset();
        let out = enc.encode_field("x", b"val");
        // After reset, first record again → CHANGED
        assert_eq!(out[0], 0x00);
    }
}
