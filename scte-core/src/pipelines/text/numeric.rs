/// Numeric encoding stage — encodes integer and float values for the token stream.
///
/// # Phase boundary
/// - **Phase 1-4**: `FlatIntegerEncoder` — ZigZag + LEB128 flat (current behaviour).
/// - **Phase 6**: `DeltaIntegerEncoder` replaces or wraps `FlatIntegerEncoder` for
///   sequential/monotonic/clustered columns — plug in via `IntegerEncoder` trait.
///
/// # Design constraint
/// The `IntegerEncoder` trait is intentionally simple. Phase 6 adds a new
/// `DeltaIntegerEncoder` struct implementing the same trait; the rest of
/// the pipeline just calls `encoder.encode(values)` without knowing which
/// variant is active.
use crate::varint::{encode_i64, decode_i64};
use crate::error::ScteError;

// ── IntegerEncoder trait ──────────────────────────────────────────────────────

/// Common interface for all integer-encoding strategies.
///
/// Implementors:
/// - `FlatIntegerEncoder`  — Phase 1-4, ZigZag + LEB128 flat
/// - `DeltaIntegerEncoder` — Phase 6, delta detection + ZigZag + LEB128
pub trait IntegerEncoder: Send + Sync {
    /// Encode a slice of i64 values into bytes.
    fn encode(&self, values: &[i64], out: &mut Vec<u8>);

    /// Decode bytes back to i64 values.
    ///
    /// Returns `(values, bytes_consumed)`.
    fn decode(&self, data: &[u8], count: usize) -> Result<(Vec<i64>, usize), ScteError>;

    /// Human-readable name — useful for debugging / section metadata.
    fn name(&self) -> &'static str;
}

// ── FlatIntegerEncoder ────────────────────────────────────────────────────────

/// Phase 1-4 integer encoder: ZigZag + LEB128, one value at a time.
///
/// No pattern detection. Every value encoded independently.
/// Replaced per-column by `DeltaIntegerEncoder` in Phase 6 when the
/// pattern detector identifies a sequential or clustered distribution.
#[derive(Debug, Clone, Default)]
pub struct FlatIntegerEncoder;

impl IntegerEncoder for FlatIntegerEncoder {
    fn encode(&self, values: &[i64], out: &mut Vec<u8>) {
        for &v in values {
            encode_i64(v, out);
        }
    }

    fn decode(&self, data: &[u8], count: usize) -> Result<(Vec<i64>, usize), ScteError> {
        let mut pos = 0;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            let (v, consumed) = decode_i64(data, pos).ok_or_else(|| {
                ScteError::DecodeError("numeric: truncated integer stream".into())
            })?;
            pos += consumed;
            values.push(v);
        }
        Ok((values, pos))
    }

    fn name(&self) -> &'static str {
        "flat-zigzag-leb128"
    }
}

// ── FloatEncoding ─────────────────────────────────────────────────────────────

/// Encode a single f64 value.
///
/// Strategy (in order of preference):
/// 1. If value is an integer and fits in i64 → ZigZag + LEB128 (saves bytes).
/// 2. If value fits in f32 without precision loss → 4 bytes little-endian.
/// 3. Otherwise → 8 bytes f64 little-endian.
///
/// The first byte is a tag:
/// `0x00` = int-encoded, `0x01` = f32, `0x02` = f64.
pub fn encode_float(v: f64, out: &mut Vec<u8>) {
    // Case 1: integer value
    let as_int = v as i64;
    if as_int as f64 == v {
        out.push(0x00);
        encode_i64(as_int, out);
        return;
    }
    // Case 2: lossless f32
    let as_f32 = v as f32;
    if (as_f32 as f64 - v).abs() < f64::EPSILON * v.abs().max(1.0) {
        out.push(0x01);
        out.extend_from_slice(&as_f32.to_le_bytes());
        return;
    }
    // Case 3: full f64
    out.push(0x02);
    out.extend_from_slice(&v.to_le_bytes());
}

/// Decode a float value encoded by `encode_float`.
///
/// Returns `(value, bytes_consumed)`.
pub fn decode_float(data: &[u8], pos: usize) -> Result<(f64, usize), ScteError> {
    if pos >= data.len() {
        return Err(ScteError::DecodeError("numeric: truncated float".into()));
    }
    match data[pos] {
        0x00 => {
            let (v, c) = decode_i64(data, pos + 1).ok_or_else(|| {
                ScteError::DecodeError("numeric: truncated int-encoded float".into())
            })?;
            Ok((v as f64, 1 + c))
        }
        0x01 => {
            if pos + 5 > data.len() {
                return Err(ScteError::DecodeError("numeric: truncated f32 float".into()));
            }
            let f = f32::from_le_bytes(data[pos+1..pos+5].try_into().unwrap());
            Ok((f as f64, 5))
        }
        0x02 => {
            if pos + 9 > data.len() {
                return Err(ScteError::DecodeError("numeric: truncated f64 float".into()));
            }
            let f = f64::from_le_bytes(data[pos+1..pos+9].try_into().unwrap());
            Ok((f, 9))
        }
        tag => Err(ScteError::DecodeError(format!("numeric: unknown float tag {tag:#04X}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── FlatIntegerEncoder ───────────────────────────────────────────────────

    #[test]
    fn flat_encoder_roundtrip_positive() {
        let enc = FlatIntegerEncoder;
        let values = vec![0i64, 1, 127, 128, 1000, i64::MAX / 2];
        let mut out = Vec::new();
        enc.encode(&values, &mut out);
        let (decoded, _) = enc.decode(&out, values.len()).unwrap();
        assert_eq!(values, decoded);
    }

    #[test]
    fn flat_encoder_roundtrip_negative() {
        let enc = FlatIntegerEncoder;
        let values = vec![-1i64, -128, -1000, i64::MIN / 2];
        let mut out = Vec::new();
        enc.encode(&values, &mut out);
        let (decoded, _) = enc.decode(&out, values.len()).unwrap();
        assert_eq!(values, decoded);
    }

    #[test]
    fn flat_encoder_empty() {
        let enc = FlatIntegerEncoder;
        let mut out = Vec::new();
        enc.encode(&[], &mut out);
        assert!(out.is_empty());
        let (decoded, consumed) = enc.decode(&[], 0).unwrap();
        assert!(decoded.is_empty());
        assert_eq!(consumed, 0);
    }

    #[test]
    fn flat_encoder_truncated_returns_error() {
        let enc = FlatIntegerEncoder;
        let mut out = Vec::new();
        enc.encode(&[300], &mut out);
        let truncated = &out[..1]; // cut mid-varint
        assert!(enc.decode(truncated, 1).is_err());
    }

    // ── FloatEncoding ────────────────────────────────────────────────────────

    #[test]
    fn float_integer_value_roundtrip() {
        let mut out = Vec::new();
        encode_float(42.0, &mut out);
        assert_eq!(out[0], 0x00); // int tag
        let (v, _) = decode_float(&out, 0).unwrap();
        assert_eq!(v, 42.0);
    }

    #[test]
    fn float_genuine_f64_roundtrip() {
        let pi = std::f64::consts::PI;
        let mut out = Vec::new();
        encode_float(pi, &mut out);
        let (v, _) = decode_float(&out, 0).unwrap();
        assert!((v - pi).abs() < 1e-15);
    }

    #[test]
    fn float_negative_integer_roundtrip() {
        let mut out = Vec::new();
        encode_float(-1024.0, &mut out);
        let (v, _) = decode_float(&out, 0).unwrap();
        assert_eq!(v, -1024.0);
    }

    #[test]
    fn float_truncated_returns_error() {
        assert!(decode_float(&[], 0).is_err());
        assert!(decode_float(&[0x02, 0x00], 0).is_err()); // f64 needs 9 bytes total
    }
}
