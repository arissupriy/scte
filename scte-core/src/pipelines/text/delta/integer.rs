/// Integer delta encoder — Phase 6.
///
/// Detects patterns in integer sequences and encodes deltas instead of flat
/// values, dramatically reducing bits per record.
///
/// # Wire format
///
/// ```text
/// Sequential:   0x00 | varint(zigzag(first)) | varint(zigzag(delta)) | varint(count)
/// Monotonic:    0x01 | varint(count) | varint(zigzag(first)) | [varint(zigzag(Δ))]…
/// Clustered:    0x02 | varint(count) | varint(zigzag(first)) | [varint(zigzag(Δ))]…
/// Flat:         0x03 | varint(count) | [varint(zigzag(v))]…
/// ```

use crate::varint;

const TAG_SEQUENTIAL: u8 = 0x00;
const TAG_MONOTONIC:  u8 = 0x01;
const TAG_CLUSTERED:  u8 = 0x02;
const TAG_FLAT:       u8 = 0x03;
/// Values have a large absolute range but small inter-sample deltas
/// (e.g. sequential timestamp base + random millisecond noise).
/// Encodes as first-value + per-record delta, same wire layout as
/// TAG_MONOTONIC / TAG_CLUSTERED but accepting any-sign deltas.
const TAG_BOUNDED:    u8 = 0x04;

/// Detected pattern in an integer column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegerPattern {
    /// All deltas are equal (e.g. IDs 0,1,2,3 or 0,2,4,6).
    Sequential { delta: i64 },
    /// All deltas non-negative and small (< 1024).
    Monotonic,
    /// Deltas cluster near zero (|delta| ≤ 8).
    Clustered,
    /// Values span a large range but deltas are small relative to that range
    /// (e.g. Unix-ms timestamp with random per-row jitter).
    /// Stored as first-value + per-record signed delta.
    Bounded,
    /// No discernible pattern — use flat encoding.
    Random,
}

/// Detect the compression pattern of an integer slice.
pub fn detect_pattern(values: &[i64]) -> IntegerPattern {
    if values.len() < 2 {
        return IntegerPattern::Random;
    }
    // Use wrapping_sub so that i64::MIN/i64::MAX pairs don't panic in debug mode.
    // The decoder uses wrapping_add, so round-trip is exact across the full range.
    let deltas: Vec<i64> = values.windows(2).map(|w| w[1].wrapping_sub(w[0])).collect();
    let first_delta = deltas[0];
    if deltas.iter().all(|&d| d == first_delta) {
        return IntegerPattern::Sequential { delta: first_delta };
    }
    let max_abs: i64 = deltas.iter().map(|d| d.unsigned_abs() as i64).max().unwrap_or(0);
    if max_abs <= 8 {
        return IntegerPattern::Clustered;
    }
    if deltas.iter().all(|&d| d >= 0 && d < 1024) {
        return IntegerPattern::Monotonic;
    }

    // ── Bounded: values span a large range but per-sample deltas are small ──────
    // Typical case: Unix-ms timestamps with random sub-second jitter, or any
    // "sequential base + bounded noise" column.  Delta encoding stores the large
    // first-value once and then only the small deltas, saving ~3–4 bytes/row vs
    // flat zigzag on the huge absolute values.
    //
    // Condition: max |delta| < value_range / 2  (deltas are < half the value span).
    // This avoids Bounded for truly random fields (e.g. latency_ms 10–2009) where
    // the delta range ≈ the value range → flat raw encoding is equally compact.
    let min_v = values.iter().copied().min().unwrap_or(0);
    let max_v = values.iter().copied().max().unwrap_or(0);
    let value_range = max_v.saturating_sub(min_v);
    if value_range > 0 && max_abs < (value_range >> 1) {
        return IntegerPattern::Bounded;
    }

    IntegerPattern::Random
}

/// Encode a slice of integers using the best detected pattern.
pub fn encode_delta_ints(values: &[i64]) -> Vec<u8> {
    let mut out = Vec::new();
    if values.is_empty() {
        out.push(TAG_FLAT);
        varint::encode_u64(0, &mut out);
        return out;
    }
    match detect_pattern(values) {
        IntegerPattern::Sequential { delta } => {
            out.push(TAG_SEQUENTIAL);
            varint::encode_u64(varint::zigzag_encode(values[0]), &mut out);
            varint::encode_u64(varint::zigzag_encode(delta), &mut out);
            varint::encode_u64(values.len() as u64, &mut out);
        }
        IntegerPattern::Monotonic => {
            out.push(TAG_MONOTONIC);
            varint::encode_u64(values.len() as u64, &mut out);
            varint::encode_u64(varint::zigzag_encode(values[0]), &mut out);
            for w in values.windows(2) {
                varint::encode_u64(varint::zigzag_encode(w[1].wrapping_sub(w[0])), &mut out);
            }
        }
        IntegerPattern::Clustered => {
            out.push(TAG_CLUSTERED);
            varint::encode_u64(values.len() as u64, &mut out);
            varint::encode_u64(varint::zigzag_encode(values[0]), &mut out);
            for w in values.windows(2) {
                varint::encode_u64(varint::zigzag_encode(w[1].wrapping_sub(w[0])), &mut out);
            }
        }
        IntegerPattern::Bounded => {
            out.push(TAG_BOUNDED);
            varint::encode_u64(values.len() as u64, &mut out);
            varint::encode_u64(varint::zigzag_encode(values[0]), &mut out);
            for w in values.windows(2) {
                varint::encode_u64(varint::zigzag_encode(w[1].wrapping_sub(w[0])), &mut out);
            }
        }
        IntegerPattern::Random => {
            out.push(TAG_FLAT);
            varint::encode_u64(values.len() as u64, &mut out);
            for &v in values {
                varint::encode_u64(varint::zigzag_encode(v), &mut out);
            }
        }
    }
    out
}

/// Decode bytes produced by [`encode_delta_ints`].
pub fn decode_delta_ints(data: &[u8]) -> Option<Vec<i64>> {
    let mut pos = 0usize;
    let tag = *data.get(pos)?;
    pos += 1;
    match tag {
        TAG_SEQUENTIAL => {
            let (fz, n) = varint::decode_u64(data, pos)?; pos += n;
            let (dz, n) = varint::decode_u64(data, pos)?; pos += n;
            let (count, _) = varint::decode_u64(data, pos)?;
            let first = varint::zigzag_decode(fz);
            let delta = varint::zigzag_decode(dz);
            // wrapping_mul so [i64::MIN, i64::MAX, ...] with large delta doesn't overflow.
            Some((0..count as i64).map(|i| first.wrapping_add(delta.wrapping_mul(i))).collect())
        }
        TAG_MONOTONIC | TAG_CLUSTERED | TAG_BOUNDED => {
            let (count, n) = varint::decode_u64(data, pos)?; pos += n;
            let (fz, n)    = varint::decode_u64(data, pos)?; pos += n;
            let mut out = Vec::with_capacity(count as usize);
            out.push(varint::zigzag_decode(fz));
            for _ in 1..count {
                let (dz, n) = varint::decode_u64(data, pos)?; pos += n;
                let Some(&prev) = out.last() else { return None; };
                out.push(prev.wrapping_add(varint::zigzag_decode(dz)));
            }
            Some(out)
        }
        TAG_FLAT => {
            let (count, n) = varint::decode_u64(data, pos)?; pos += n;
            let mut out = Vec::with_capacity(count as usize);
            for _ in 0..count {
                let (vz, n) = varint::decode_u64(data, pos)?; pos += n;
                out.push(varint::zigzag_decode(vz));
            }
            Some(out)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(values: &[i64]) -> Vec<i64> {
        decode_delta_ints(&encode_delta_ints(values)).expect("decode failed")
    }

    #[test] fn detect_sequential_ids() {
        let v: Vec<i64> = (0..100).collect();
        assert_eq!(detect_pattern(&v), IntegerPattern::Sequential { delta: 1 });
    }
    #[test] fn detect_sequential_even() {
        let v: Vec<i64> = (0..50).map(|i| i*2).collect();
        assert_eq!(detect_pattern(&v), IntegerPattern::Sequential { delta: 2 });
    }
    #[test] fn detect_sequential_negative() {
        let v: Vec<i64> = (0..10).map(|i| 100 - i).collect();
        assert_eq!(detect_pattern(&v), IntegerPattern::Sequential { delta: -1 });
    }
    #[test] fn detect_monotonic() {
        let v = vec![100i64, 103, 107, 112, 120, 131];
        assert!(matches!(detect_pattern(&v), IntegerPattern::Monotonic));
    }
    #[test] fn detect_clustered() {
        let v = vec![50i64, 51, 50, 52, 51, 50, 53, 52];
        assert!(matches!(detect_pattern(&v), IntegerPattern::Clustered));
    }
    #[test] fn detect_bounded_ts_like() {
        // Sequential base (×1000) + random noise 0–999 → deltas ≈ 1000±999
        // value_range ≈ 9_000_000, max_abs_delta ≈ 1999 << 4_500_000 → Bounded
        let base = 1_743_724_800_000i64;
        let fracs: [i64; 8] = [123, 456, 100, 789, 200, 500, 301, 999];
        let v: Vec<i64> = (0..8).map(|i| base + i * 1000 + fracs[i as usize]).collect();
        assert!(matches!(detect_pattern(&v), IntegerPattern::Bounded));
    }
    #[test] fn detect_random() {
        let v = vec![394i64, 12, 8821, 44, 2000];
        assert_eq!(detect_pattern(&v), IntegerPattern::Random);
    }
    #[test] fn roundtrip_sequential() {
        let v: Vec<i64> = (0..500).collect();
        assert_eq!(roundtrip(&v), v);
    }
    #[test] fn roundtrip_monotonic() {
        let v = vec![100i64, 103, 107, 112, 120, 131, 145];
        assert_eq!(roundtrip(&v), v);
    }
    #[test] fn roundtrip_clustered() {
        let v = vec![50i64, 51, 50, 52, 51, 50, 53, 52];
        assert_eq!(roundtrip(&v), v);
    }
    #[test] fn roundtrip_bounded() {
        let base = 1_743_724_800_000i64;
        let fracs: [i64; 10] = [123, 456, 100, 789, 200, 500, 301, 999, 0, 234];
        let v: Vec<i64> = (0..10).map(|i| base + i * 1000 + fracs[i as usize]).collect();
        assert_eq!(roundtrip(&v), v);
    }
    #[test] fn bounded_much_smaller_than_flat() {
        // Flat encoding would store each 42-bit value (6 bytes zigzag + LEB128).
        // Bounded stores the first value once (6 bytes) + tiny deltas (≤2 bytes each).
        let base = 1_743_724_800_000i64;
        let fracs: [i64; 100] = {
            let mut a = [0i64; 100];
            let mut lcg = 42u64;
            for x in a.iter_mut() {
                lcg = lcg.wrapping_mul(6364136223846793005).wrapping_add(1);
                *x = (lcg >> 54) as i64 % 1000;
            }
            a
        };
        let v: Vec<i64> = (0..100).map(|i| base + i * 1000 + fracs[i as usize]).collect();
        let enc = encode_delta_ints(&v);
        // Bounded: 1 tag + ~2 count + 6 first + 99×2 delta ≈ 207 bytes
        // Flat   : 1 tag + ~2 count + 100×6 ≈ 603 bytes
        assert!(enc.len() < 250, "Bounded encoding too large: {} bytes", enc.len());
        assert_eq!(roundtrip(&v), v);
    }
    #[test] fn random_latency_not_bounded() {
        // latency_ms 10–2009: value_range ≈ 2000, max_abs_delta ≈ 2000 → NOT Bounded
        let v = vec![10i64, 2009, 500, 100, 1800, 300, 1500, 800, 200, 1900];
        // max delta could be ≈ 2000, value_range ≈ 1999 → max_abs ≥ value_range/2
        // So pattern must NOT be Bounded
        assert!(!matches!(detect_pattern(&v), IntegerPattern::Bounded));
    }
    #[test] fn roundtrip_random() {
        let v = vec![394i64, 12, 8821, 44, 2000, -77, 0];
        assert_eq!(roundtrip(&v), v);
    }
    #[test] fn roundtrip_negatives() {
        let v: Vec<i64> = (-50..50).collect();
        assert_eq!(roundtrip(&v), v);
    }
    #[test] fn roundtrip_empty() { assert_eq!(roundtrip(&[]), vec![]); }
    #[test] fn roundtrip_single() { assert_eq!(roundtrip(&[42]), vec![42]); }
    #[test] fn sequential_is_compact() {
        let v: Vec<i64> = (0..500).collect();
        assert!(encode_delta_ints(&v).len() <= 10);
    }
    #[test] fn clustered_smaller_than_flat() {
        let v = vec![50i64,51,50,52,51,50,53,52,49,50,51,52,50,51,53,50,48,51,52,50];
        assert!(encode_delta_ints(&v).len() < 30);
    }
}
