/// Frequency table for rANS entropy coding.
///
/// # Role in the pipeline
/// ```text
/// Vec<EncodedToken>  →  kinds: Vec<u8>  →  FreqTable::build()
///                                              ↓
///                                        FreqTable::normalize()
///                                              ↓
///                               rans::encode(kinds, &freq_table)
/// ```
///
/// # Normalization (plans.md §5.8)
/// Raw counts are proportionally scaled to sum exactly `M = 2^k` (k = 12..16).
/// Each symbol that appears at least once is guaranteed ≥ 1 slot after
/// normalization, ensuring every present symbol can be encoded.
///
/// # Slot table
/// A precomputed array of size M maps every slot index → symbol byte,
/// giving O(1) symbol lookup during rANS decoding.
///
/// # Wire format (stored in TOKENS section header)
/// ```text
/// varint(k)               — M = 2^k
/// varint(alphabet_used)   — number of symbols with norm_freq > 0
/// for each present symbol (ascending byte order):
///     u8(symbol_byte)
///     varint(norm_freq)
/// ```

use crate::{
    error::ScteError,
    varint::{decode_usize, decode_u64, encode_u64, encode_usize},
};

/// Default normalization precision: M = 2^14 = 16384 slots.
///
/// Chosen as a balance between:
/// - Coding efficiency (more slots → finer probability resolution)
/// - Slot table size (16 384 bytes — fits in L1 cache)
/// - rANS state arithmetic (state fits comfortably in u32)
pub const DEFAULT_M_BITS: u32 = 14;

/// Full alphabet size for 8-bit symbols.
pub const MAX_SYMBOLS: usize = 256;

/// Frequency table for a single-pass rANS model.
///
/// Symbols are arbitrary bytes (`u8`). Only the `alphabet_size` lowest
/// byte values are tracked; in practice the token-kind alphabet uses only
/// 10 symbols (0x00–0x09).
#[derive(Debug, Clone)]
pub struct FreqTable {
    /// M = 2^m_bits (total normalized frequency slots).
    pub m: u32,
    /// log₂(M).
    pub m_bits: u32,
    /// Raw (unnormalized) counts per symbol.  Length = alphabet_size.
    pub raw_freqs: Vec<u32>,
    /// Normalized frequencies summing to M. Length = alphabet_size.
    pub norm_freqs: Vec<u32>,
    /// Cumulative distribution: cum_freqs[s] = Σ norm_freqs[i] for i < s.
    /// Length = alphabet_size + 1 (last entry == M, sentinel).
    pub cum_freqs: Vec<u32>,
    /// Precomputed slot → symbol lookup. Length = M.
    /// `slot_table[slot] = symbol` for all slot in [0, M).
    pub slot_table: Vec<u8>,
    /// Number of tracked symbols (equals `raw_freqs.len()`).
    pub alphabet_size: usize,
}

impl FreqTable {
    // ── Build from symbol stream ──────────────────────────────────────────────

    /// Build a frequency table from a raw symbol stream.
    ///
    /// `alphabet_size` symbols are tracked (0..alphabet_size).  All symbols
    /// in `symbols` must be in range `[0, alphabet_size)`.
    ///
    /// Normalizes to `M = 2^m_bits` immediately.
    ///
    /// # Panics
    /// Does not panic; out-of-range symbols are silently ignored.
    pub fn build(symbols: &[u8], alphabet_size: usize, m_bits: u32) -> Self {
        assert!(m_bits >= 1 && m_bits <= 24, "m_bits must be in [1, 24]");
        assert!(alphabet_size <= MAX_SYMBOLS, "alphabet_size must be ≤ 256");

        let mut raw_freqs = vec![0u32; alphabet_size];
        for &s in symbols {
            if (s as usize) < alphabet_size {
                raw_freqs[s as usize] += 1;
            }
        }

        let mut table = Self {
            m: 1 << m_bits,
            m_bits,
            raw_freqs,
            norm_freqs: vec![0u32; alphabet_size],
            cum_freqs: vec![0u32; alphabet_size + 1],
            slot_table: Vec::new(),
            alphabet_size,
        };
        table.normalize();
        table.build_slot_table();
        table
    }

    // ── Normalization ─────────────────────────────────────────────────────────

    /// Normalize raw frequencies so they sum exactly to M = 2^m_bits.
    ///
    /// Algorithm:
    /// 1. Scale each count proportionally: `scaled = raw * M / total`.
    /// 2. Round down.  Assign ≥ 1 to every symbol that appeared at least once.
    /// 3. Distribute remaining slots to symbols with largest fractional parts
    ///    (tie-break: highest symbol byte, for determinism).
    fn normalize(&mut self) {
        let total: u64 = self.raw_freqs.iter().map(|&f| f as u64).sum();
        if total == 0 {
            return; // nothing to normalize
        }

        let m = self.m as u64;
        let mut allocated: u32 = 0;

        // Pass 1: floor-scale, guarantee minimum of 1 for present symbols.
        // Collect (fractional_part_numerator, symbol_index) for pass 2.
        let mut remainders: Vec<(u64, usize)> = Vec::new();

        for (i, &raw) in self.raw_freqs.iter().enumerate() {
            if raw == 0 {
                self.norm_freqs[i] = 0;
                continue;
            }
            let exact  = (raw as u64) * m;          // exact * total = raw * m
            let floor  = (exact / total) as u32;
            let floor  = floor.max(1);               // guaranteed minimum
            self.norm_freqs[i] = floor;
            allocated += floor;

            let remainder = exact % total;
            remainders.push((remainder, i));
        }

        // Pass 2: distribute remaining slots by largest remainder (descending).
        // Tie-break: descending symbol index (deterministic).
        let remaining = (m as u32).saturating_sub(allocated);
        if remaining > 0 {
            remainders.sort_unstable_by(|(ra, ia), (rb, ib)| {
                rb.cmp(ra).then_with(|| ib.cmp(ia))
            });
            for &(_, idx) in remainders.iter().take(remaining as usize) {
                self.norm_freqs[idx] += 1;
            }
        }

        // Pass 3: clamp over-allocated present symbols if needed.
        // (Can happen only if #present > M; in practice never for k ≥ 4.)
        let actual_sum: u32 = self.norm_freqs.iter().sum();
        if actual_sum > self.m {
            // Trim excess from the largest symbols.
            let mut excess = actual_sum - self.m;
            let mut indices: Vec<usize> = (0..self.alphabet_size)
                .filter(|&i| self.norm_freqs[i] > 1)
                .collect();
            indices.sort_unstable_by(|&a, &b| self.norm_freqs[b].cmp(&self.norm_freqs[a]));
            for i in indices {
                if excess == 0 { break; }
                let trim = self.norm_freqs[i].min(excess);
                self.norm_freqs[i] -= trim;
                excess -= trim;
            }
        }

        // Build CDF.
        let mut cum = 0u32;
        for i in 0..self.alphabet_size {
            self.cum_freqs[i] = cum;
            cum += self.norm_freqs[i];
        }
        self.cum_freqs[self.alphabet_size] = cum; // sentinel = M
    }

    // ── Slot table ────────────────────────────────────────────────────────────

    fn build_slot_table(&mut self) {
        self.slot_table = vec![0u8; self.m as usize];
        for sym in 0..self.alphabet_size {
            let start = self.cum_freqs[sym] as usize;
            let end   = (self.cum_freqs[sym] + self.norm_freqs[sym]) as usize;
            for slot in start..end {
                self.slot_table[slot] = sym as u8;
            }
        }
    }

    // ── Validation ────────────────────────────────────────────────────────────

    /// Verify that normalized frequencies sum to M and CDF is consistent.
    /// Used in tests.
    pub fn validate(&self) -> bool {
        let sum: u32 = self.norm_freqs.iter().sum();
        if sum != self.m { return false; }

        let mut cum = 0u32;
        for i in 0..self.alphabet_size {
            if self.cum_freqs[i] != cum { return false; }
            cum += self.norm_freqs[i];
        }
        if self.cum_freqs[self.alphabet_size] != self.m { return false; }

        // Spot-check slot table.
        for sym in 0..self.alphabet_size {
            for slot in self.cum_freqs[sym]..self.cum_freqs[sym] + self.norm_freqs[sym] {
                if self.slot_table[slot as usize] != sym as u8 { return false; }
            }
        }
        true
    }

    // ── Wire format ───────────────────────────────────────────────────────────

    /// Serialize the frequency table to bytes (TOKENS section header).
    ///
    /// ```text
    /// varint(m_bits)
    /// varint(alphabet_used)        — count of symbols with norm_freq > 0
    /// for each present symbol (ascending order):
    ///     u8(symbol_byte)
    ///     varint(norm_freq)
    /// ```
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_u64(self.m_bits as u64, &mut out);

        let present: Vec<usize> = (0..self.alphabet_size)
            .filter(|&i| self.norm_freqs[i] > 0)
            .collect();
        encode_usize(present.len(), &mut out);
        for &i in &present {
            out.push(i as u8);
            encode_u64(self.norm_freqs[i] as u64, &mut out);
        }
        out
    }

    /// Deserialize a frequency table from bytes produced by `serialize()`.
    pub fn deserialize(data: &[u8], pos: usize) -> Result<(Self, usize), ScteError> {
        let start = pos;
        let mut p = pos;

        let (m_bits_u64, c) = decode_u64(data, p)
            .ok_or_else(|| ScteError::DecodeError("freq: truncated m_bits".into()))?;
        p += c;
        let m_bits = m_bits_u64 as u32;
        let m = 1u32 << m_bits;

        let (alphabet_used, c) = decode_usize(data, p)
            .ok_or_else(|| ScteError::DecodeError("freq: truncated alphabet_used".into()))?;
        p += c;

        // Infer alphabet_size from highest symbol byte present.
        let mut raw_norm: Vec<(u8, u32)> = Vec::with_capacity(alphabet_used);
        for i in 0..alphabet_used {
            if p >= data.len() {
                return Err(ScteError::DecodeError(
                    format!("freq: truncated at symbol entry {i}"),
                ));
            }
            let sym = data[p];
            p += 1;
            let (f, c) = decode_u64(data, p)
                .ok_or_else(|| ScteError::DecodeError(
                    format!("freq: truncated at freq entry {i}"),
                ))?;
            p += c;
            raw_norm.push((sym, f as u32));
        }

        let alphabet_size = raw_norm.iter().map(|&(s, _)| s as usize + 1).max().unwrap_or(0);
        let mut norm_freqs = vec![0u32; alphabet_size];
        let mut raw_freqs  = vec![0u32; alphabet_size];
        for (sym, f) in raw_norm {
            norm_freqs[sym as usize] = f;
            raw_freqs[sym as usize]  = f; // treat norm as raw for deserialized tables
        }

        // Validate sum.
        let fsum: u32 = norm_freqs.iter().sum();
        if fsum != m {
            return Err(ScteError::DecodeError(
                format!("freq: norm_freqs sum {fsum} != M {m}"),
            ));
        }

        // Build CDF and slot table.
        let mut cum_freqs = vec![0u32; alphabet_size + 1];
        let mut cum = 0u32;
        for i in 0..alphabet_size {
            cum_freqs[i] = cum;
            cum += norm_freqs[i];
        }
        cum_freqs[alphabet_size] = cum;

        let mut slot_table = vec![0u8; m as usize];
        for sym in 0..alphabet_size {
            let start = cum_freqs[sym] as usize;
            let end   = (cum_freqs[sym] + norm_freqs[sym]) as usize;
            for slot in start..end {
                slot_table[slot] = sym as u8;
            }
        }

        let table = Self {
            m, m_bits, raw_freqs, norm_freqs, cum_freqs, slot_table, alphabet_size,
        };
        Ok((table, p - start))
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn build(symbols: &[u8]) -> FreqTable {
        let max_sym = *symbols.iter().max().unwrap_or(&0) as usize + 1;
        FreqTable::build(symbols, max_sym, DEFAULT_M_BITS)
    }

    // ── Normalization invariants ──────────────────────────────────────────────

    #[test]
    fn norm_freqs_sum_to_m() {
        let symbols: Vec<u8> = (0..100u8).map(|i| i % 10).collect();
        let freq = build(&symbols);
        assert_eq!(freq.norm_freqs.iter().sum::<u32>(), freq.m);
    }

    #[test]
    fn uniform_symbols_sum_to_m() {
        // 4 equally likely symbols, 1024 times each.
        let symbols: Vec<u8> = (0..4096u32).map(|i| (i % 4) as u8).collect();
        let freq = FreqTable::build(&symbols, 4, DEFAULT_M_BITS);
        assert_eq!(freq.norm_freqs.iter().sum::<u32>(), freq.m);
    }

    #[test]
    fn every_present_symbol_gets_at_least_one_slot() {
        // Rare symbol: appears once out of 10000.
        let mut symbols = vec![0u8; 9999];
        symbols.push(1u8);
        let freq = FreqTable::build(&symbols, 2, DEFAULT_M_BITS);
        assert!(freq.norm_freqs[1] >= 1, "rare symbol must get ≥ 1 slot");
    }

    #[test]
    fn absent_symbol_gets_zero_slots() {
        let symbols = vec![0u8, 1u8, 2u8];
        let freq = FreqTable::build(&symbols, 4, DEFAULT_M_BITS);
        assert_eq!(freq.norm_freqs[3], 0, "symbol 3 was never seen");
    }

    #[test]
    fn validate_passes() {
        let symbols: Vec<u8> = (0..100u8).map(|i| i % 5).collect();
        let freq = build(&symbols);
        assert!(freq.validate(), "validate() must pass after build");
    }

    // ── Slot table ────────────────────────────────────────────────────────────

    #[test]
    fn slot_table_len_equals_m() {
        let symbols = vec![0u8, 1u8, 2u8];
        let freq = build(&symbols);
        assert_eq!(freq.slot_table.len(), freq.m as usize);
    }

    #[test]
    fn slot_table_consistent_with_cum_freqs() {
        let symbols: Vec<u8> = (0..50u8).map(|i| i % 3).collect();
        let freq = build(&symbols);
        for sym in 0..freq.alphabet_size {
            if freq.norm_freqs[sym] > 0 {
                let slot = freq.cum_freqs[sym] as usize;
                assert_eq!(freq.slot_table[slot], sym as u8);
            }
        }
    }

    // ── Serialize / deserialize ───────────────────────────────────────────────

    #[test]
    fn serialize_deserialize_roundtrip() {
        let symbols: Vec<u8> = (0..100u8).map(|i| i % 7).collect();
        let freq = build(&symbols);
        let bytes = freq.serialize();
        let (restored, consumed) = FreqTable::deserialize(&bytes, 0).expect("deserialize failed");
        assert_eq!(consumed, bytes.len());
        assert_eq!(freq.norm_freqs, restored.norm_freqs);
        assert_eq!(freq.cum_freqs,  restored.cum_freqs);
    }

    #[test]
    fn deserialize_with_offset() {
        let symbols: Vec<u8> = vec![0, 1, 2, 0, 1, 0];
        let freq  = build(&symbols);
        let mut bytes = vec![0xDE, 0xAD]; // 2 garbage bytes
        bytes.extend_from_slice(&freq.serialize());
        let (restored, consumed) = FreqTable::deserialize(&bytes, 2).unwrap();
        assert_eq!(consumed, bytes.len() - 2);
        assert_eq!(freq.norm_freqs, restored.norm_freqs);
    }

    #[test]
    fn deserialize_wrong_sum_returns_error() {
        // Craft a payload with wrong sum.
        let mut bytes = Vec::new();
        encode_u64(DEFAULT_M_BITS as u64, &mut bytes); // m_bits
        encode_usize(1, &mut bytes);                   // 1 symbol
        bytes.push(0u8);                               // symbol 0
        encode_u64(42, &mut bytes);                    // freq 42 (≠ M=16384)
        assert!(FreqTable::deserialize(&bytes, 0).is_err());
    }
}
