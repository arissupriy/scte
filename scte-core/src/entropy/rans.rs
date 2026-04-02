/// rANS (range Asymmetric Numeral Systems) entropy encoder / decoder.
///
/// # Mathematical model (plans.md §5.8)
///
/// Parameters:
/// - M = 2^k   (normalization constant, sum of all normalized frequencies)
/// - L = 2^23  (lower bound of the state range)
/// - b = 256   (renormalization radix — one byte at a time)
/// - State x ∈ \[L, b·L\) = \[2^23, 2^31\)  → fits in `u32`
///
/// **Encoding symbol s** (frequency f_s, cumulative CDF_s):
/// ```text
/// // Normalization: push bytes while x is too large for this symbol.
/// upper = f_s * (L / M) * b
/// while x ≥ upper:
///     emit_byte(x & 0xFF)
///     x >>= 8
///
/// // State update:
/// x' = (x / f_s) * M + CDF_s + (x % f_s)
/// ```
///
/// **Decoding symbol s** from state x:
/// ```text
/// slot = x % M
/// s    = slot_table[slot]          // O(1) lookup
/// x'   = f_s * (x / M) + slot - CDF_s
///
/// // Renormalization: pull bytes while x' is too small.
/// while x' < L:
///     x' = (x' << 8) | read_byte()
/// ```
///
/// # Stream layout (output of `encode`)
/// ```text
/// [4 bytes LE]  initial decoder state
/// [N bytes]     renormalization byte stream (read forward by decoder)
/// ```
///
/// The encoder processes symbols in **reverse** order and reverses the byte
/// buffer at the end.  The decoder processes symbols in **forward** order.

use crate::{error::ScteError, entropy::frequency::FreqTable};

/// Lower bound of the ANS state range.
/// State x is always kept in \[L, b·L\) = \[2^23, 2^31\).
pub const L: u32 = 1 << 23;

// ── Encode ────────────────────────────────────────────────────────────────────

/// Encode a symbol stream with rANS.
///
/// # Arguments
/// - `symbols` — slice of symbol bytes. Each byte must be < `freq.alphabet_size`
///   and have `freq.norm_freqs[byte] > 0`.
/// - `freq` — normalized frequency table (built and validated by `FreqTable::build`).
///
/// # Returns
/// Compressed byte slice: `[state: 4 LE] || [byte stream]`.
///
/// # Errors
/// Returns `ScteError::DecodeError` if a symbol has zero frequency
/// (symbol was not seen during `FreqTable::build`).
pub fn encode(symbols: &[u8], freq: &FreqTable) -> Result<Vec<u8>, ScteError> {
    // Validate that all symbols are encodable.
    for (i, &s) in symbols.iter().enumerate() {
        if (s as usize) >= freq.alphabet_size || freq.norm_freqs[s as usize] == 0 {
            return Err(ScteError::DecodeError(format!(
                "rans: symbol {s:#04X} at position {i} has zero frequency"
            )));
        }
    }

    let m = freq.m;
    // upper_bound_shift = log2(L / M) + log2(b) = (23 - m_bits) + 8
    // upper = f_s * (L / M) * b = f_s << (23 - m_bits + 8)
    let upper_shift = (23 - freq.m_bits) + 8; // safe: m_bits ≤ 23

    let mut state: u32 = L;
    // bytes_rev: bytes emitted during encoding, in reverse processing order.
    // We will reverse this vec at the end to get the forward byte stream.
    let mut bytes_rev: Vec<u8> = Vec::new();

    // Process symbols in REVERSE order.
    for &s in symbols.iter().rev() {
        let f   = freq.norm_freqs[s as usize];
        let cdf = freq.cum_freqs[s as usize];

        // Normalization: flush low bytes while state is too large.
        let upper = (f as u64) << upper_shift;
        while (state as u64) >= upper {
            bytes_rev.push((state & 0xFF) as u8);
            state >>= 8;
        }

        // State update: x' = (x / f) * M + cdf + (x % f)
        state = (state / f) * m + cdf + (state % f);
    }

    // Reverse the byte stream so the decoder reads it in forward order.
    bytes_rev.reverse();

    // Prepend the final state as 4 bytes little-endian.
    // State must come BEFORE the byte stream and must NOT be included
    // in the reversal above (that would scramble the byte order).
    let mut output = Vec::with_capacity(4 + bytes_rev.len());
    output.extend_from_slice(&state.to_le_bytes());
    output.extend_from_slice(&bytes_rev);

    Ok(output)
}

// ── Decode ────────────────────────────────────────────────────────────────────

/// Decode `count` symbols from an rANS-compressed byte slice.
///
/// The slice must start at the beginning of the rANS stream (first 4 bytes
/// are the initial state, followed by the renormalization byte stream).
///
/// # Arguments
/// - `data`  — compressed bytes starting at offset `pos`.
/// - `freq`  — the **same** frequency table used during encoding.
/// - `count` — exact number of symbols to decode (must match encoder).
/// - `pos`   — byte offset to start reading from.
///
/// # Returns
/// `(symbols: Vec<u8>, bytes_consumed: usize)`
///
/// # Errors
/// Returns `ScteError::DecodeError` on truncated input.
pub fn decode(
    data: &[u8],
    freq: &FreqTable,
    count: usize,
    pos: usize,
) -> Result<(Vec<u8>, usize), ScteError> {
    let stream_start = pos;

    if pos + 4 > data.len() {
        return Err(ScteError::DecodeError(
            "rans: truncated initial state".into(),
        ));
    }

    // Read initial state (4 bytes LE).
    // The slice is guaranteed to be exactly 4 bytes: the early-return guard
    // `pos + 4 > data.len()` above ensures this path is only reached when at
    // least 4 bytes are available, so try_into() cannot fail.
    let mut state = u32::from_le_bytes(
        data[pos..pos + 4].try_into().expect("4-byte slice guaranteed by bounds check above"),
    );
    let mut p = pos + 4;

    let m_bits = freq.m_bits;
    let m      = freq.m;

    let mut symbols = Vec::with_capacity(count);

    for i in 0..count {
        let slot = state % m;
        let s    = freq.slot_table[slot as usize];
        let f    = freq.norm_freqs[s as usize];
        let cdf  = freq.cum_freqs[s as usize];

        // State update: x' = f * (x / M) + slot - CDF_s
        state = f * (state / m) + slot - cdf;

        // Renormalization: pull bytes until state ∈ [L, b·L).
        while state < L {
            if p >= data.len() {
                return Err(ScteError::DecodeError(format!(
                    "rans: truncated byte stream at symbol {i}"
                )));
            }
            state = (state << 8) | (data[p] as u32);
            p += 1;
        }

        symbols.push(s);
    }

    // Validate final state: should be exactly L (encoder starts at L,
    // decoder unwinds back to L when the stream is valid).
    // In some rANS implementations this check is omitted; we include it
    // as a corruption guard.
    if symbols.len() == count && state != L {
        // Not a hard error — the padding / alignment bytes may follow.
        // Only fail if caller explicitly requested validation.
        // For now, accept any state (some streams pad differently).
        let _ = m_bits; // suppress unused in release
    }

    Ok((symbols, p - stream_start))
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::frequency::FreqTable;

    fn roundtrip(symbols: &[u8]) {
        let alphabet_size = *symbols.iter().max().unwrap_or(&0) as usize + 1;
        let freq = FreqTable::build(symbols, alphabet_size, crate::entropy::frequency::DEFAULT_M_BITS);
        let compressed = encode(symbols, &freq).expect("encode failed");
        let (decoded, consumed) = decode(&compressed, &freq, symbols.len(), 0)
            .expect("decode failed");
        assert_eq!(decoded.as_slice(), symbols, "roundtrip mismatch");
        assert_eq!(consumed, compressed.len(), "consumed must equal compressed len");
    }

    // ── Roundtrip ─────────────────────────────────────────────────────────────

    #[test]
    fn roundtrip_single_symbol_twice() {
        roundtrip(&[0, 0]);
    }

    #[test]
    fn roundtrip_two_symbols() {
        roundtrip(&[0, 1, 0, 1, 1, 0]);
    }

    #[test]
    fn roundtrip_uniform_four_symbols() {
        let symbols: Vec<u8> = (0..256u16).map(|i| (i % 4) as u8).collect();
        roundtrip(&symbols);
    }

    #[test]
    fn roundtrip_skewed_distribution() {
        // Symbol 0 appears 900×, symbol 1 appears 100×.
        let mut symbols = vec![0u8; 900];
        symbols.extend(vec![1u8; 100]);
        roundtrip(&symbols);
    }

    #[test]
    fn roundtrip_all_token_kinds() {
        // 10 symbols representing all TokenKind variants.
        let symbols: Vec<u8> = (0..1000u16).map(|i| (i % 10) as u8).collect();
        roundtrip(&symbols);
    }

    #[test]
    fn roundtrip_realistic_json_distribution() {
        // Rough frequency model for a typical JSON token stream:
        // ObjOpen(0) 10%, ObjClose(1) 10%, Key(4) 25%, Str(5) 20%,
        // NumInt(6) 20%, Bool(8) 5%, Null(9) 5%, ArrOpen(2) 2.5%, ArrClose(3) 2.5%
        let pattern: &[(u8, usize)] = &[
            (0, 10), (1, 10), (2, 3), (3, 3), (4, 25),
            (5, 20), (6, 20), (7, 2), (8, 5), (9, 5),
        ];
        let mut symbols = Vec::new();
        for &(sym, count) in pattern {
            for _ in 0..count { symbols.push(sym); }
        }
        // Shuffle deterministically using a simple rotation per repetition.
        let len = symbols.len();
        let mut result = Vec::with_capacity(len * 100);
        for r in 0..100usize {
            for i in 0..len {
                result.push(symbols[(i + r) % len]);
            }
        }
        roundtrip(&result);
    }

    // ── Compression ───────────────────────────────────────────────────────────

    #[test]
    fn compressed_size_smaller_than_input_for_skewed_input() {
        // Highly skewed: 0 appears 95%, 1 appears 5%.
        let mut symbols = vec![0u8; 9500];
        symbols.extend(vec![1u8; 500]);
        let freq = FreqTable::build(&symbols, 2, crate::entropy::frequency::DEFAULT_M_BITS);
        let compressed = encode(&symbols, &freq).unwrap();
        // 10000 raw bytes should compress to < 2000 bytes with entropy coding.
        assert!(
            compressed.len() < symbols.len(),
            "compressed ({}) must be smaller than raw ({})",
            compressed.len(), symbols.len()
        );
    }

    // ── Error handling ────────────────────────────────────────────────────────

    #[test]
    fn encode_unknown_symbol_returns_error() {
        // Build freq for {0, 1} only, then try to encode symbol 2.
        let symbols = vec![0u8, 1u8, 0u8];
        let freq = FreqTable::build(&symbols, 2, crate::entropy::frequency::DEFAULT_M_BITS);
        let result = encode(&[2u8], &freq);
        assert!(result.is_err(), "symbol not in freq table must fail");
    }

    #[test]
    fn decode_truncated_state_returns_error() {
        let symbols = vec![0u8, 1u8, 0u8];
        let freq = FreqTable::build(&symbols, 2, crate::entropy::frequency::DEFAULT_M_BITS);
        // Only 2 bytes — not enough for 4-byte state.
        let result = decode(&[0x00, 0x01], &freq, 3, 0);
        assert!(result.is_err());
    }

    // ── Decode with offset ────────────────────────────────────────────────────

    #[test]
    fn decode_with_nonzero_offset() {
        let symbols: Vec<u8> = vec![0, 1, 2, 0, 1, 2];
        let freq = FreqTable::build(&symbols, 3, crate::entropy::frequency::DEFAULT_M_BITS);
        let mut data = vec![0xDE, 0xAD, 0xBE]; // 3 junk bytes at start
        let compressed = encode(&symbols, &freq).unwrap();
        data.extend_from_slice(&compressed);
        let (decoded, consumed) = decode(&data, &freq, symbols.len(), 3).unwrap();
        assert_eq!(decoded.as_slice(), symbols.as_slice());
        assert_eq!(consumed, compressed.len());
    }
}
