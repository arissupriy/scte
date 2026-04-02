//! Context Tree Weighting (CTW) — Phase 7.
//!
//! CTW is a universal data compression algorithm that converges to the
//! Shannon entropy of the source without requiring a separate model-fitting pass.
//!
//! # Algorithm sketch
//! - Data is viewed as a binary sequence (8 bits per byte, MSB first).
//! - A context tree records, for each path of up to `max_depth` past bits,
//!   how many 0-bits and 1-bits have occurred.
//! - The probability of the next bit is estimated via the KT (Krichevsky-Trofimov)
//!   estimator: `P(0) = (2a + 1) / (2n + 2)` where `a = count[0]` and
//!   `n = count[0] + count[1]`.
//! - If the deepest context has fewer than `MIN_CONTEXT_COUNT` observations we
//!   fall back to a shallower one; if none qualify we use the uniform prior (1/2).
//! - Probabilities are passed to the underlying [`ArithmeticEncoder`] / [`ArithmeticDecoder`].
//!
//! # Wire format
//! ```text
//! varint(original_byte_count)
//! varint(max_depth)
//! arithmetic payload
//! ```
//! The context tree is **not** serialized. Both encoder and decoder start
//! with an empty tree and update it identically as each bit is processed,
//! yielding the same probabilities at every step.
//!

use std::collections::BTreeMap;
use crate::{
    varint::{encode_usize, decode_usize},
    entropy::arithmetic::{ArithmeticEncoder, ArithmeticDecoder},
};

// ── Tuning ────────────────────────────────────────────────────────────────────

/// Minimum observations at a given depth before that context is trusted.
/// Below this threshold we fall back to a shallower (or prior) estimate.
const MIN_CONTEXT_COUNT: u32 = 4;

// ── Node ─────────────────────────────────────────────────────────────────────

/// Single node in the context tree.
#[derive(Clone, Default)]
struct CtwNode {
    count: [u32; 2],  // [count_0, count_1]
}

impl CtwNode {
    /// KT estimator: `P(0) = (2·a + 1) / (2·n + 2)` — pure integer rational.
    fn kt_prob_zero(&self) -> (u64, u64) {
        let a = self.count[0] as u64;
        let n = (self.count[0] + self.count[1]) as u64;
        (2 * a + 1, 2 * n + 2)
    }
    fn total(&self) -> u32 { self.count[0] + self.count[1] }
}

// ── Context key helpers ───────────────────────────────────────────────────────

/// Pack `(depth, last_depth_bits)` into a single u64 with no collision between
/// different depths: high 16 bits = depth, low 48 bits = context bits.
#[inline]
fn make_key(depth: usize, ctx_bits: u64) -> u64 {
    let mask = if depth >= 48 { u64::MAX } else { (1u64 << depth) - 1 };
    ((depth as u64) << 48) | (ctx_bits & mask)
}

// ── Shared tree logic ─────────────────────────────────────────────────────────

/// Given the current `context_bits` and tree, find the best probability
/// estimate for the next bit.
fn get_prob_zero(nodes: &BTreeMap<u64, CtwNode>, max_depth: usize, ctx: u64) -> (u64, u64) {
    for d in (0..=max_depth).rev() {
        let key = make_key(d, ctx);
        if let Some(node) = nodes.get(&key) {
            if d == 0 || node.total() >= MIN_CONTEXT_COUNT {
                return node.kt_prob_zero();
            }
        }
    }
    (1, 2) // uniform prior
}

/// Update all ancestor contexts (from depth 0 up to max_depth) with the observed bit.
fn update_tree(nodes: &mut BTreeMap<u64, CtwNode>, max_depth: usize, ctx: u64, bit: bool) {
    for d in 0..=max_depth {
        let key = make_key(d, ctx);
        let node = nodes.entry(key).or_default();
        node.count[bit as usize] += 1;
    }
}

// ── Encoder ──────────────────────────────────────────────────────────────────

/// CTW encoder. Wraps an arithmetic coder with a self-updating context tree.
pub struct CtwEncoder {
    nodes:        BTreeMap<u64, CtwNode>,
    max_depth:    usize,
    context_bits: u64,   // sliding window of recent bits
    arith:        ArithmeticEncoder,
    byte_count:   usize,
}

impl CtwEncoder {
    pub fn new(max_depth: usize) -> Self {
        Self {
            nodes: BTreeMap::new(),
            max_depth,
            context_bits: 0,
            arith: ArithmeticEncoder::new(),
            byte_count: 0,
        }
    }

    /// Encode one byte (8 bits, MSB first).
    pub fn encode_byte(&mut self, byte: u8) {
        for i in (0..8).rev() {
            let bit = (byte >> i) & 1 == 1;
            let (num, den) = get_prob_zero(&self.nodes, self.max_depth, self.context_bits);
            self.arith.encode_bit(bit, num, den);
            update_tree(&mut self.nodes, self.max_depth, self.context_bits, bit);
            self.context_bits = (self.context_bits << 1) | (bit as u64);
        }
        self.byte_count += 1;
    }

    /// Finish encoding and return the complete wire bytes.
    ///
    /// Wire format: `varint(byte_count) || varint(max_depth) || arithmetic_payload`.
    /// No tree is serialized — the decoder rebuilds it identically by replaying
    /// the same incremental updates in decode order.
    pub fn finish(self) -> Vec<u8> {
        let arith_bytes = self.arith.finish();
        let mut out = Vec::new();
        encode_usize(self.byte_count, &mut out);
        encode_usize(self.max_depth, &mut out);
        out.extend_from_slice(&arith_bytes);
        out
    }
}

// ── Decoder ──────────────────────────────────────────────────────────────────

/// CTW decoder. Must be given bytes produced by [`CtwEncoder::finish`].
pub struct CtwDecoder<'a> {
    nodes:        BTreeMap<u64, CtwNode>,
    max_depth:    usize,
    context_bits: u64,
    arith:        ArithmeticDecoder<'a>,
    byte_count:   usize,
}

impl<'a> CtwDecoder<'a> {
    /// Parse the header and return a ready-to-use decoder with an empty tree.
    ///
    /// The tree is NOT serialized in the wire format. Instead both encoder and
    /// decoder start with an empty tree and evolve it identically, one bit at
    /// a time, giving the same probabilities at every step.
    pub fn new(data: &'a [u8]) -> Option<Self> {
        let mut pos = 0usize;
        let (byte_count, sz) = decode_usize(data, pos)?;  pos += sz;
        let (max_depth,  sz) = decode_usize(data, pos)?;  pos += sz;
        let arith = ArithmeticDecoder::new(&data[pos..]).ok()?;
        Some(Self {
            nodes: BTreeMap::new(),
            max_depth,
            context_bits: 0,
            arith,
            byte_count,
        })
    }

    /// Decode all bytes.
    pub fn decode_bytes(&mut self) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(self.byte_count);
        for _ in 0..self.byte_count {
            let mut byte = 0u8;
            for i in (0..8).rev() {
                let (num, den) = get_prob_zero(&self.nodes, self.max_depth, self.context_bits);
                let bit = self.arith.decode_bit(num, den)?;
                if bit { byte |= 1 << i; }
                update_tree(&mut self.nodes, self.max_depth, self.context_bits, bit);
                self.context_bits = (self.context_bits << 1) | (bit as u64);
            }
            out.push(byte);
        }
        Some(out)
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Compress `data` using CTW with context depth `max_depth`.
/// Larger depths give better compression on structured data at the cost of
/// higher memory usage during encoding/decoding.
pub fn encode(data: &[u8], max_depth: usize) -> Vec<u8> {
    let mut enc = CtwEncoder::new(max_depth);
    for &b in data { enc.encode_byte(b); }
    enc.finish()
}

/// Decompress bytes produced by [`encode`]. Returns `None` if the payload is malformed.
pub fn decode(data: &[u8]) -> Option<Vec<u8>> {
    CtwDecoder::new(data)?.decode_bytes()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_roundtrip() {
        assert_eq!(decode(&encode(&[], 4)), Some(vec![]));
    }

    #[test]
    fn single_byte_roundtrip() {
        for b in [0u8, 0xFF, 0xAB, 42] {
            let enc = encode(&[b], 4);
            assert_eq!(decode(&enc), Some(vec![b]), "byte={b}");
        }
    }

    #[test]
    fn hello_world_roundtrip() {
        let orig = b"hello world";
        assert_eq!(decode(&encode(orig, 8)).as_deref(), Some(orig.as_ref()));
    }

    #[test]
    fn all_zeros_roundtrip() {
        let orig: Vec<u8> = vec![0u8; 256];
        assert_eq!(decode(&encode(&orig, 8)), Some(orig));
    }

    #[test]
    fn random_bytes_roundtrip() {
        // Deterministic pseudo-random sequence.
        let orig: Vec<u8> = (0u8..=255).collect();
        assert_eq!(decode(&encode(&orig, 8)), Some(orig));
    }

    #[test]
    fn highly_repetitive_compresses_well() {
        let orig: Vec<u8> = b"aaaa".repeat(64);
        let compressed = encode(&orig, 8);
        // Very repetitive data should compress to well under 50% of raw.
        assert!(
            compressed.len() < orig.len() / 2,
            "expected compressed ({}) < raw/2 ({})",
            compressed.len(), orig.len() / 2
        );
    }

    #[test]
    fn depth_0_roundtrip() {
        let orig = b"test depth zero";
        assert_eq!(decode(&encode(orig, 0)).as_deref(), Some(orig.as_ref()));
    }

    #[test]
    fn depth_16_roundtrip() {
        let orig = b"deeper context tree test";
        assert_eq!(decode(&encode(orig, 16)).as_deref(), Some(orig.as_ref()));
    }

    #[test]
    fn corrupt_data_returns_none() {
        assert_eq!(decode(&[0xFF, 0xFF, 0xFF, 0xFF]), None);
    }
}
