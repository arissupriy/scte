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

/// Detected pattern in an integer column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegerPattern {
    /// All deltas are equal (e.g. IDs 0,1,2,3 or 0,2,4,6).
    Sequential { delta: i64 },
    /// All deltas non-negative and small (< 1024).
    Monotonic,
    /// Deltas cluster near zero (|delta| ≤ 8).
    Clustered,
    /// No discernible pattern — use flat encoding.
    Random,
}

/// Detect the compression pattern of an integer slice.
pub fn detect_pattern(values: &[i64]) -> IntegerPattern {
    if values.len() < 2 {
        return IntegerPattern::Random;
    }
    let deltas: Vec<i64> = values.windows(2).map(|w| w[1] - w[0]).collect();
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
                varint::encode_u64(varint::zigzag_encode(w[1] - w[0]), &mut out);
            }
        }
        IntegerPattern::Clustered => {
            out.push(TAG_CLUSTERED);
            varint::encode_u64(values.len() as u64, &mut out);
            varint::encode_u64(varint::zigzag_encode(values[0]), &mut out);
            for w in values.windows(2) {
                varint::encode_u64(varint::zigzag_encode(w[1] - w[0]), &mut out);
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
            Some((0..count as i64).map(|i| first + i * delta).collect())
        }
        TAG_MONOTONIC | TAG_CLUSTERED => {
            let (count, n) = varint::decode_u64(data, pos)?; pos += n;
            let (fz, n)    = varint::decode_u64(data, pos)?; pos += n;
            let mut out = Vec::with_capacity(count as usize);
            out.push(varint::zigzag_decode(fz));
            for _ in 1..count {
                let (dz, n) = varint::decode_u64(data, pos)?; pos += n;
                let prev = *out.last().unwrap();
                out.push(prev + varint::zigzag_decode(dz));
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
