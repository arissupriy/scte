/// Unsigned LEB128 (Little-Endian Base-128) varint encoding / decoding.
///
/// Used in:
/// - DICT section serialization (entry count + string lengths)
/// - TOKENS section frequency table header (Phase 4)
/// - ZigZag integer encoding (Phase 4)
///
/// # Wire format
/// Each byte carries 7 bits of payload. The MSB is 1 if more bytes follow,
/// 0 on the final byte. Maximum encoded width is 10 bytes (u64).
///
/// # Complexity
/// Encode: O(⌈bits/7⌉) ≤ 10 iterations.
/// Decode: O(bytes_consumed) with early-exit overflow guard.

// ── Encode ────────────────────────────────────────────────────────────────────

/// Append the LEB128 encoding of `value` to `out`.
///
/// # Range
/// Accepts the full `u64` range. Values < 128 encode to exactly 1 byte.
///
/// # Example
/// ```
/// use scte_core::varint::encode_u64;
/// let mut buf = Vec::new();
/// encode_u64(300, &mut buf);
/// assert_eq!(buf, [0xAC, 0x02]); // 300 = 0b1_0010_1100
/// ```
pub fn encode_u64(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

/// Encode a `usize` as LEB128. Thin wrapper over `encode_u64`.
#[inline]
pub fn encode_usize(value: usize, out: &mut Vec<u8>) {
    encode_u64(value as u64, out);
}

// ── Decode ────────────────────────────────────────────────────────────────────

/// Decode one LEB128-encoded `u64` from `data[pos..]`.
///
/// Returns `(value, bytes_consumed)` on success, or `None` if the buffer
/// is exhausted or the encoded value would overflow `u64`.
///
/// # Overflow guard
/// Stops after 10 bytes (max valid width for u64). Any byte beyond that
/// would shift meaningful bits past bit 63 — returns `None`.
///
/// # Example
/// ```
/// use scte_core::varint::decode_u64;
/// assert_eq!(decode_u64(&[0xAC, 0x02, 0xFF], 0), Some((300, 2)));
/// assert_eq!(decode_u64(&[0x05],               0), Some((5,   1)));
/// assert_eq!(decode_u64(&[],                   0), None);
/// ```
pub fn decode_u64(data: &[u8], pos: usize) -> Option<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift:  u32 = 0;
    let mut i = pos;

    loop {
        if i >= data.len() {
            return None; // buffer exhausted mid-sequence
        }
        if shift >= 64 {
            return None; // overflow guard
        }

        let byte = data[i];
        i += 1;

        // Mask off continuation bit and accumulate.
        result |= ((byte & 0x7F) as u64) << shift;
        shift  += 7;

        if byte & 0x80 == 0 {
            return Some((result, i - pos));
        }
    }
}

/// Decode one LEB128-encoded `usize` from `data[pos..]`.
///
/// Returns `None` if the decoded `u64` value exceeds `usize::MAX`,
/// or if the buffer is exhausted / overflow occurs.
pub fn decode_usize(data: &[u8], pos: usize) -> Option<(usize, usize)> {
    let (val, consumed) = decode_u64(data, pos)?;
    let n = usize::try_from(val).ok()?;
    Some((n, consumed))
}

// ── ZigZag signed integer encoding ───────────────────────────────────────────

/// ZigZag-encode a signed `i64` to an unsigned `u64`.
///
/// Maps signed integers to non-negative integers:
///
/// |  i64 |  u64 |
/// |------|------|
/// |    0 |    0 |
/// |   -1 |    1 |
/// |    1 |    2 |
/// |   -2 |    3 |
/// |    2 |    4 |
///
/// Combined with LEB128 this makes small-magnitude negative numbers compact.
///
/// Formula: `(n << 1) ^ (n >> 63)`
#[inline]
pub fn zigzag_encode(n: i64) -> u64 {
    ((n << 1) ^ (n >> 63)) as u64
}

/// Decode a ZigZag-encoded `u64` back to `i64`.
///
/// Formula: `(n >> 1) ^ -(n & 1)`
#[inline]
pub fn zigzag_decode(n: u64) -> i64 {
    ((n >> 1) as i64) ^ -((n & 1) as i64)
}

/// Append a ZigZag + LEB128 encoding of `value` to `out`.
///
/// Encodes small-magnitude signed integers compactly:
/// values in `[-64, 63]` → 1 byte, `[-8192, 8191]` → 2 bytes, etc.
#[inline]
pub fn encode_i64(value: i64, out: &mut Vec<u8>) {
    encode_u64(zigzag_encode(value), out);
}

/// Decode one ZigZag + LEB128 `i64` from `data[pos..]`.
///
/// Returns `(value, bytes_consumed)` or `None` on error.
#[inline]
pub fn decode_i64(data: &[u8], pos: usize) -> Option<(i64, usize)> {
    let (raw, consumed) = decode_u64(data, pos)?;
    Some((zigzag_decode(raw), consumed))
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(v: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        encode_u64(v, &mut buf);
        buf
    }

    fn roundtrip(v: u64) {
        let bytes = encode(v);
        let (decoded, consumed) = decode_u64(&bytes, 0).expect("decode failed");
        assert_eq!(decoded, v, "roundtrip failed for {v}");
        assert_eq!(consumed, bytes.len(), "consumed != encoded len for {v}");
    }

    // ── Known vectors ─────────────────────────────────────────────────────────

    #[test]
    fn zero_encodes_to_one_byte() {
        assert_eq!(encode(0), [0x00]);
    }

    #[test]
    fn one_encodes_to_one_byte() {
        assert_eq!(encode(1), [0x01]);
    }

    #[test]
    fn max_single_byte_is_127() {
        assert_eq!(encode(127), [0x7F]);
    }

    #[test]
    fn min_two_byte_is_128() {
        assert_eq!(encode(128), [0x80, 0x01]);
    }

    #[test]
    fn known_vector_300() {
        // 300 = 0x12C → split as 7-bit groups: 0101100 | 0000010
        //              → 0xAC (with continuation) 0x02 (final)
        assert_eq!(encode(300), [0xAC, 0x02]);
    }

    #[test]
    fn max_u64_encodes_to_ten_bytes() {
        assert_eq!(encode(u64::MAX).len(), 10);
    }

    // ── Roundtrip ─────────────────────────────────────────────────────────────

    #[test]
    fn roundtrip_zero()     { roundtrip(0); }
    #[test]
    fn roundtrip_one()      { roundtrip(1); }
    #[test]
    fn roundtrip_127()      { roundtrip(127); }
    #[test]
    fn roundtrip_128()      { roundtrip(128); }
    #[test]
    fn roundtrip_300()      { roundtrip(300); }
    #[test]
    fn roundtrip_65535()    { roundtrip(65535); }
    #[test]
    fn roundtrip_u32_max()  { roundtrip(u32::MAX as u64); }
    #[test]
    fn roundtrip_u64_max()  { roundtrip(u64::MAX); }

    // ── Decode with offset ────────────────────────────────────────────────────

    #[test]
    fn decode_with_nonzero_pos() {
        let buf = [0xFF, 0xAC, 0x02]; // 1 garbage byte then 300
        let (val, consumed) = decode_u64(&buf, 1).unwrap();
        assert_eq!(val, 300);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn decode_stops_at_non_continuation_byte() {
        // 0x05 followed by unrelated data
        let buf = [0x05, 0xAC, 0x02];
        let (val, consumed) = decode_u64(&buf, 0).unwrap();
        assert_eq!(val, 5);
        assert_eq!(consumed, 1);
    }

    // ── Error cases ───────────────────────────────────────────────────────────

    #[test]
    fn decode_empty_buffer_returns_none() {
        assert!(decode_u64(&[], 0).is_none());
    }

    #[test]
    fn decode_truncated_sequence_returns_none() {
        // Continuation bit set but no more bytes
        assert!(decode_u64(&[0x80], 0).is_none());
    }

    #[test]
    fn decode_pos_beyond_buffer_returns_none() {
        assert!(decode_u64(&[0x01], 5).is_none());
    }

    // ── usize wrapper ─────────────────────────────────────────────────────────

    #[test]
    fn encode_usize_matches_encode_u64() {
        let mut a = Vec::new();
        let mut b = Vec::new();
        encode_usize(12345, &mut a);
        encode_u64(12345, &mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn decode_usize_roundtrip() {
        let mut buf = Vec::new();
        encode_usize(65535, &mut buf);
        let (val, consumed) = decode_usize(&buf, 0).unwrap();
        assert_eq!(val, 65535);
        assert_eq!(consumed, buf.len());
    }

    // ── ZigZag ────────────────────────────────────────────────────────────────

    #[test]
    fn zigzag_zero() {
        assert_eq!(zigzag_encode(0), 0);
        assert_eq!(zigzag_decode(0), 0);
    }

    #[test]
    fn zigzag_positive() {
        assert_eq!(zigzag_encode(1),  2);
        assert_eq!(zigzag_encode(2),  4);
        assert_eq!(zigzag_encode(63), 126);
    }

    #[test]
    fn zigzag_negative() {
        assert_eq!(zigzag_encode(-1), 1);
        assert_eq!(zigzag_encode(-2), 3);
        assert_eq!(zigzag_encode(i64::MIN), u64::MAX);
    }

    #[test]
    fn zigzag_roundtrip_positive() {
        for n in [0i64, 1, 2, 127, 128, 1000, i64::MAX] {
            assert_eq!(zigzag_decode(zigzag_encode(n)), n, "failed for {n}");
        }
    }

    #[test]
    fn zigzag_roundtrip_negative() {
        for n in [-1i64, -2, -128, -129, -1000, i64::MIN] {
            assert_eq!(zigzag_decode(zigzag_encode(n)), n, "failed for {n}");
        }
    }

    #[test]
    fn encode_i64_small_negative_is_compact() {
        // -1 → ZigZag 1 → 1 byte LEB128
        let mut buf = Vec::new();
        encode_i64(-1, &mut buf);
        assert_eq!(buf, [0x01]);
    }

    #[test]
    fn encode_decode_i64_roundtrip() {
        for n in [0i64, 1, -1, 127, -128, 1000, -1000, i64::MAX, i64::MIN] {
            let mut buf = Vec::new();
            encode_i64(n, &mut buf);
            let (decoded, consumed) = decode_i64(&buf, 0).unwrap();
            assert_eq!(decoded, n, "roundtrip failed for {n}");
            assert_eq!(consumed, buf.len(), "consumed mismatch for {n}");
        }
    }
}
