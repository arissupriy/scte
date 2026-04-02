/// High-precision binary arithmetic coder — Phase 7.
///
/// Replaces rANS when `P(symbol) > 0.99` where rANS (M = 2^16) wastes bits.
/// Arithmetic coding gives `-log2(P)` bits per symbol regardless of how
/// close P is to 1.
///
/// # Design decisions
/// - **No floating-point anywhere** — all arithmetic is integer (u32/u64).
///   Probabilities are passed as `(numerator: u64, denominator: u64)` rationals.
///   Guarantees bit-identical output across all platforms (determinism rule).
/// - **E1/E2/E3 (Rissanen-Langdon) renormalization** — the classic scheme.
///   Avoids carry-propagation overflow of naive arithmetic coders.
/// - **Binary alphabet** — one bit at a time. Multi-symbol alphabets handled
///   by caller (CTW decomposes each byte into 8 bits, MSB first).
///
/// # Wire format
/// ```text
/// varint(bit_count)   — total bits encoded
/// [payload bytes]     — MSB-first per byte, last byte zero-padded
/// ```

use crate::{error::ScteError, varint::{encode_usize, decode_usize}};

// ── Constants ─────────────────────────────────────────────────────────────────

const HALF:    u32 = 0x8000_0000; // 2^31
const QUARTER: u32 = 0x4000_0000; // 2^30

// ── Encoder ──────────────────────────────────────────────────────────────────

/// Stateful binary arithmetic encoder. Call [`encode_bit`] per input bit,
/// then [`finish`] to flush and retrieve the compressed bytes.
pub struct ArithmeticEncoder {
    low:     u32,
    high:    u32,
    pending: u32,  // E3 (underflow) pending bits
    bits:    usize,

    bit_buf: u8,
    bit_pos: u8,   // bits written into bit_buf (0..8)
    output:  Vec<u8>,
}

impl ArithmeticEncoder {
    pub fn new() -> Self {
        Self { low: 0, high: u32::MAX, pending: 0, bits: 0,
               bit_buf: 0, bit_pos: 0, output: Vec::new() }
    }

    /// Encode one bit.
    /// `bit = false` → symbol 0 with probability `prob0_num / prob0_den`.
    /// Requires `0 < prob0_num < prob0_den`.
    pub fn encode_bit(&mut self, bit: bool, prob0_num: u64, prob0_den: u64) {
        debug_assert!(prob0_num > 0 && prob0_den > prob0_num,
            "prob0 must be a proper fraction: {prob0_num}/{prob0_den}");
        let range = (self.high as u64) - (self.low as u64) + 1;
        let split = ((range * prob0_num / prob0_den).max(1).min(range - 1)) as u32;
        if !bit {
            self.high = self.low + split - 1;
        } else {
            self.low  = self.low + split;
        }
        self.bits += 1;
        self.normalize_enc();
    }

    /// Flush the final interval and return the fully encoded byte vector
    /// (including the `varint(bit_count)` header).
    pub fn finish(mut self) -> Vec<u8> {
        self.pending += 1;
        if self.low < QUARTER {
            self.emit_bit(false);
            for _ in 0..self.pending { self.emit_bit(true); }
        } else {
            self.emit_bit(true);
            for _ in 0..self.pending { self.emit_bit(false); }
        }
        if self.bit_pos > 0 {
            self.output.push(self.bit_buf << (8 - self.bit_pos));
        }
        let mut out = Vec::with_capacity(self.output.len() + 4);
        encode_usize(self.bits, &mut out);
        out.extend_from_slice(&self.output);
        out
    }

    fn emit_bit(&mut self, b: bool) {
        self.bit_buf = (self.bit_buf << 1) | (b as u8);
        self.bit_pos += 1;
        if self.bit_pos == 8 {
            self.output.push(self.bit_buf);
            self.bit_buf = 0;
            self.bit_pos = 0;
        }
    }

    fn normalize_enc(&mut self) {
        loop {
            if self.high < HALF {
                // E1: top bit is 0.
                self.emit_bit(false);
                for _ in 0..self.pending { self.emit_bit(true); }
                self.pending = 0;
                self.low  <<= 1;
                self.high  = (self.high << 1) | 1;
            } else if self.low >= HALF {
                // E2: top bit is 1.
                self.emit_bit(true);
                for _ in 0..self.pending { self.emit_bit(false); }
                self.pending = 0;
                self.low  = (self.low  - HALF) << 1;
                self.high = ((self.high - HALF) << 1) | 1;
            } else if self.low >= QUARTER && self.high < HALF + QUARTER {
                // E3: interval straddles midpoint; defer 1 bit.
                self.pending += 1;
                self.low  = (self.low  - QUARTER) << 1;
                self.high = ((self.high - QUARTER) << 1) | 1;
            } else {
                break;
            }
        }
    }
}

impl Default for ArithmeticEncoder { fn default() -> Self { Self::new() } }

// ── Decoder ──────────────────────────────────────────────────────────────────

/// Stateful binary arithmetic decoder.
/// Constructed from bytes produced by [`ArithmeticEncoder::finish`].
pub struct ArithmeticDecoder<'a> {
    low:      u32,
    high:     u32,
    value:    u32,  // approximation of encoder's final interval

    data:     &'a [u8],
    byte_pos: usize,
    bit_pos:  u8,   // bit within current byte (0=MSB, 7=LSB)

    pub bit_count: usize,   // total bits in stream (from header)
    decoded:       usize,
}

impl<'a> ArithmeticDecoder<'a> {
    /// Parse the header and initialise the decoder window.
    pub fn new(data: &'a [u8]) -> Result<Self, ScteError> {
        let (bit_count, hdr) = decode_usize(data, 0)
            .ok_or_else(|| ScteError::DecodeError("arithmetic: truncated header".into()))?;
        let payload = &data[hdr..];
        let mut dec = Self {
            low: 0, high: u32::MAX, value: 0,
            data: payload, byte_pos: 0, bit_pos: 0,
            bit_count, decoded: 0,
        };
        // Pre-fill 32-bit value window.
        for _ in 0..32 { dec.value = (dec.value << 1) | dec.read_bit() as u32; }
        Ok(dec)
    }

    /// Decode one bit. Caller must supply the same probabilities used during encoding.
    /// Returns `None` when stream is exhausted.
    pub fn decode_bit(&mut self, prob0_num: u64, prob0_den: u64) -> Option<bool> {
        if self.decoded >= self.bit_count { return None; }
        let range = (self.high as u64) - (self.low as u64) + 1;
        let split = ((range * prob0_num / prob0_den).max(1).min(range - 1)) as u32;
        let bit   = (self.value - self.low) >= split;
        if !bit {
            self.high = self.low + split - 1;
        } else {
            self.low  = self.low + split;
        }
        self.decoded += 1;
        self.normalize_dec();
        Some(bit)
    }

    fn read_bit(&mut self) -> u8 {
        if self.byte_pos >= self.data.len() { return 1; } // safe padding
        let b = (self.data[self.byte_pos] >> (7 - self.bit_pos)) & 1;
        self.bit_pos += 1;
        if self.bit_pos == 8 { self.bit_pos = 0; self.byte_pos += 1; }
        b
    }

    fn normalize_dec(&mut self) {
        loop {
            if self.high < HALF {
                self.low   <<= 1;
                self.high   = (self.high << 1) | 1;
                self.value  = (self.value << 1) | self.read_bit() as u32;
            } else if self.low >= HALF {
                self.low   = (self.low   - HALF) << 1;
                self.high  = ((self.high  - HALF) << 1) | 1;
                self.value = ((self.value - HALF) << 1) | self.read_bit() as u32;
            } else if self.low >= QUARTER && self.high < HALF + QUARTER {
                self.low   = (self.low   - QUARTER) << 1;
                self.high  = ((self.high  - QUARTER) << 1) | 1;
                self.value = ((self.value - QUARTER) << 1) | self.read_bit() as u32;
            } else { break; }
        }
    }
}

// ── Convenience functions ─────────────────────────────────────────────────────

/// Encode `bits` using per-step probabilities `probs[i] = (num, den)` for P(bit[i]==false).
pub fn encode_bits(bits: &[bool], probs: &[(u64, u64)]) -> Result<Vec<u8>, ScteError> {
    if bits.len() != probs.len() {
        return Err(ScteError::EncodeError(
            format!("arithmetic: bits.len()={} != probs.len()={}", bits.len(), probs.len())));
    }
    let mut enc = ArithmeticEncoder::new();
    for (&b, &(num, den)) in bits.iter().zip(probs.iter()) {
        if num == 0 || den <= num {
            return Err(ScteError::EncodeError(
                format!("arithmetic: invalid probability {num}/{den}")));
        }
        enc.encode_bit(b, num, den);
    }
    Ok(enc.finish())
}

/// Decode bits from bytes produced by [`encode_bits`].
pub fn decode_bits(data: &[u8], probs: &[(u64, u64)]) -> Result<Vec<bool>, ScteError> {
    let mut dec = ArithmeticDecoder::new(data)?;
    let mut out = Vec::with_capacity(probs.len());
    for &(num, den) in probs {
        let bit = dec.decode_bit(num, den)
            .ok_or_else(|| ScteError::DecodeError(
                "arithmetic: ran out of bits before probs exhausted".into()))?;
        out.push(bit);
    }
    Ok(out)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(bits: &[bool], probs: &[(u64, u64)]) -> Vec<bool> {
        decode_bits(&encode_bits(bits, probs).unwrap(), probs).unwrap()
    }

    #[test] fn single_zero() { assert_eq!(rt(&[false], &[(3,4)]), [false]); }
    #[test] fn single_one()  { assert_eq!(rt(&[true],  &[(1,4)]), [true]); }

    #[test]
    fn uniform_all_zeros() {
        let b: Vec<bool>        = vec![false; 64];
        let p: Vec<(u64, u64)>  = vec![(1, 2); 64];
        assert_eq!(rt(&b, &p), b);
    }

    #[test]
    fn uniform_all_ones() {
        let b: Vec<bool>        = vec![true; 64];
        let p: Vec<(u64, u64)>  = vec![(1, 2); 64];
        assert_eq!(rt(&b, &p), b);
    }

    #[test]
    fn alternating_bits() {
        let b: Vec<bool>       = (0..100).map(|i| i % 2 == 0).collect();
        let p: Vec<(u64, u64)> = vec![(1, 2); 100];
        assert_eq!(rt(&b, &p), b);
    }

    #[test]
    fn highly_skewed_roundtrip() {
        let b: Vec<bool>       = vec![false; 200];
        let p: Vec<(u64, u64)> = vec![(999, 1000); 200];
        assert_eq!(rt(&b, &p), b);
    }

    #[test]
    fn skewed_is_smaller_than_uniform() {
        let n = 256usize;
        let b: Vec<bool>          = vec![false; n];
        let uni: Vec<(u64, u64)>  = vec![(1, 2); n];
        let ske: Vec<(u64, u64)>  = vec![(999, 1000); n];
        let sz_uni = encode_bits(&b, &uni).unwrap().len();
        let sz_ske = encode_bits(&b, &ske).unwrap().len();
        assert!(sz_ske < sz_uni, "skewed ({sz_ske}B) must be < uniform ({sz_uni}B)");
    }

    #[test]
    fn byte_sequence_roundtrip() {
        let bytes = b"hello world";
        let bits: Vec<bool> = bytes.iter()
            .flat_map(|&b| (0..8u8).rev().map(move |i| (b >> i) & 1 == 1))
            .collect();
        let p: Vec<(u64, u64)> = vec![(1, 2); bits.len()];
        assert_eq!(rt(&bits, &p), bits);
    }

    #[test]
    fn empty_sequence() {
        assert_eq!(rt(&[], &[]), Vec::<bool>::new());
    }

    #[test]
    fn length_mismatch_errors() {
        assert!(encode_bits(&[false, true], &[(1u64, 2u64)]).is_err());
    }

    #[test]
    fn invalid_prob_errors() {
        assert!(encode_bits(&[false], &[(0u64, 1u64)]).is_err());
    }
}
