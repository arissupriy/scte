/// Generic entropy codec — format-agnostic byte-stream encoder / decoder.
///
/// This module is **format-agnostic**: it knows nothing about JSON, CSV, XML,
/// or any other text format.  It accepts a raw `&[u8]` symbol stream and an
/// `alphabet_size`, and produces a self-contained compressed byte blob.
///
/// Format-specific logic (e.g. JSON token kind → u8 mapping, payload
/// serialization) lives in `pipelines/text/entropic.rs`.
///
/// # Compression model — 1st-order context (Markov)
///
/// The symbol stream is split into `alphabet_size + 1` independent sub-streams,
/// one per preceding symbol value (0..alphabet_size) plus one for the initial
/// position (context = alphabet_size).  Each sub-stream has its own `FreqTable`
/// and is entropy-coded independently.
///
/// # Wire format
/// ```text
/// varint(symbol_count)
/// varint(alphabet_size)
/// for context in 0..=alphabet_size:
///     varint(sym_count)
///     varint(freq_bytes_len)
///     [freq_bytes]
///     varint(compressed_len)
///     [rANS compressed bytes]
/// ```

use crate::{
    entropy::{
        frequency::{FreqTable, DEFAULT_M_BITS},
        rans,
    },
    error::ScteError,
    varint::{decode_usize, encode_usize},
};

/// Compress a raw symbol stream with rANS using a 1st-order context model.
///
/// # Arguments
/// - `symbols`       — stream of symbol bytes; every byte must be < `alphabet_size`.
/// - `alphabet_size` — number of distinct symbols (1..=256).
///
/// # Errors
/// `ScteError::EncodeError` if any symbol >= `alphabet_size`.
pub fn encode(symbols: &[u8], alphabet_size: usize) -> Result<Vec<u8>, ScteError> {
    assert!(alphabet_size >= 1 && alphabet_size <= 256,
        "alphabet_size must be in [1, 256]");

    for (i, &s) in symbols.iter().enumerate() {
        if (s as usize) >= alphabet_size {
            return Err(ScteError::EncodeError(format!(
                "entropy/codec: symbol {s:#04X} at position {i} \
                 exceeds alphabet_size {alphabet_size}"
            )));
        }
    }

    let num_ctx     = alphabet_size + 1;
    let initial_ctx = alphabet_size;

    let mut ctx_streams: Vec<Vec<u8>> = vec![Vec::new(); num_ctx];
    let mut prev_ctx = initial_ctx;
    for &s in symbols {
        ctx_streams[prev_ctx].push(s);
        prev_ctx = s as usize;
    }

    let mut ctx_freq_bytes: Vec<Vec<u8>> = Vec::with_capacity(num_ctx);
    let mut ctx_compressed: Vec<Vec<u8>> = Vec::with_capacity(num_ctx);

    for stream in &ctx_streams {
        if stream.is_empty() {
            ctx_freq_bytes.push(Vec::new());
            ctx_compressed.push(Vec::new());
        } else {
            let freq       = FreqTable::build(stream, alphabet_size, DEFAULT_M_BITS);
            let compressed = rans::encode(stream, &freq)?;
            ctx_freq_bytes.push(freq.serialize());
            ctx_compressed.push(compressed);
        }
    }

    let mut out = Vec::new();
    encode_usize(symbols.len(),  &mut out);
    encode_usize(alphabet_size,  &mut out);

    for ctx in 0..num_ctx {
        encode_usize(ctx_streams[ctx].len(),    &mut out);
        encode_usize(ctx_freq_bytes[ctx].len(), &mut out);
        out.extend_from_slice(&ctx_freq_bytes[ctx]);
        encode_usize(ctx_compressed[ctx].len(), &mut out);
        out.extend_from_slice(&ctx_compressed[ctx]);
    }

    Ok(out)
}

/// Decompress a blob produced by `encode`.
///
/// # Returns
/// `(symbols, bytes_consumed)`
///
/// # Errors
/// `ScteError::DecodeError` for truncated or corrupted data.
pub fn decode(data: &[u8], pos: usize) -> Result<(Vec<u8>, usize), ScteError> {
    let start = pos;
    let mut p = pos;

    let (count, c) = decode_usize(data, p)
        .ok_or_else(|| ScteError::DecodeError("entropy/codec: truncated symbol_count".into()))?;
    p += c;

    let (alphabet_size, c) = decode_usize(data, p)
        .ok_or_else(|| ScteError::DecodeError("entropy/codec: truncated alphabet_size".into()))?;
    p += c;

    if alphabet_size == 0 || alphabet_size > 256 {
        return Err(ScteError::DecodeError(format!(
            "entropy/codec: invalid alphabet_size {alphabet_size}"
        )));
    }

    let num_ctx     = alphabet_size + 1;
    let initial_ctx = alphabet_size;

    let mut ctx_decoded: Vec<Vec<u8>> = Vec::with_capacity(num_ctx);

    for ctx in 0..num_ctx {
        let (sym_count, c) = decode_usize(data, p)
            .ok_or_else(|| ScteError::DecodeError(
                format!("entropy/codec: truncated sym_count ctx={ctx}")))?;
        p += c;

        let (freq_len, c) = decode_usize(data, p)
            .ok_or_else(|| ScteError::DecodeError(
                format!("entropy/codec: truncated freq_len ctx={ctx}")))?;
        p += c;

        if sym_count == 0 {
            let (compressed_len, c) = decode_usize(data, p)
                .ok_or_else(|| ScteError::DecodeError(
                    format!("entropy/codec: truncated compressed_len ctx={ctx}")))?;
            p += c;
            if compressed_len != 0 {
                return Err(ScteError::DecodeError(format!(
                    "entropy/codec: ctx={ctx} sym_count=0 but compressed_len={compressed_len}")));
            }
            ctx_decoded.push(Vec::new());
            continue;
        }

        let (freq, freq_consumed) = FreqTable::deserialize(data, p)?;
        if freq_consumed != freq_len {
            return Err(ScteError::DecodeError(format!(
                "entropy/codec: ctx={ctx} freq_len={freq_len} but parsed {freq_consumed}")));
        }
        p += freq_len;

        let (compressed_len, c) = decode_usize(data, p)
            .ok_or_else(|| ScteError::DecodeError(
                format!("entropy/codec: truncated compressed_len ctx={ctx}")))?;
        p += c;

        if p + compressed_len > data.len() {
            return Err(ScteError::DecodeError(format!(
                "entropy/codec: ctx={ctx} compressed stream truncated")));
        }

        let (decoded, consumed) = rans::decode(data, &freq, sym_count, p)?;
        if consumed != compressed_len {
            return Err(ScteError::DecodeError(format!(
                "entropy/codec: ctx={ctx} compressed_len={compressed_len} \
                 but rans consumed {consumed}")));
        }
        p += compressed_len;
        ctx_decoded.push(decoded);
    }

    let mut ctx_pos  = vec![0usize; num_ctx];
    let mut symbols  = Vec::with_capacity(count);
    let mut prev_ctx = initial_ctx;

    for i in 0..count {
        let bucket = &ctx_decoded[prev_ctx];
        let cp     = ctx_pos[prev_ctx];
        if cp >= bucket.len() {
            return Err(ScteError::DecodeError(format!(
                "entropy/codec: ctx={prev_ctx} sub-stream exhausted at symbol {i}")));
        }
        let s = bucket[cp];
        ctx_pos[prev_ctx] += 1;
        symbols.push(s);
        prev_ctx = s as usize;
    }

    Ok((symbols, p - start))
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(symbols: &[u8], alphabet_size: usize) {
        let blob = encode(symbols, alphabet_size).expect("encode failed");
        let (decoded, consumed) = decode(&blob, 0).expect("decode failed");
        assert_eq!(decoded.as_slice(), symbols, "roundtrip mismatch");
        assert_eq!(consumed, blob.len(), "consumed must equal blob len");
    }

    #[test]
    fn roundtrip_empty_stream() {
        roundtrip(&[], 4);
    }

    #[test]
    fn roundtrip_single_repeated_symbol() {
        roundtrip(&[0, 0, 0, 0, 0], 1);
    }

    #[test]
    fn roundtrip_two_symbols() {
        roundtrip(&[0, 1, 0, 1, 1, 0, 0], 2);
    }

    #[test]
    fn roundtrip_alphabet10_uniform() {
        let symbols: Vec<u8> = (0..1000u16).map(|i| (i % 10) as u8).collect();
        roundtrip(&symbols, 10);
    }

    #[test]
    fn roundtrip_alphabet10_skewed() {
        let mut symbols = vec![4u8; 600];
        symbols.extend((0..400u16).map(|i| (i % 10) as u8));
        roundtrip(&symbols, 10);
    }

    #[test]
    fn roundtrip_alphabet256() {
        let symbols: Vec<u8> = (0..=255u8).collect();
        roundtrip(&symbols, 256);
    }

    #[test]
    fn deterministic_same_output() {
        let symbols: Vec<u8> = (0..500u16).map(|i| (i % 10) as u8).collect();
        let a = encode(&symbols, 10).unwrap();
        let b = encode(&symbols, 10).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn compressed_smaller_than_raw_for_skewed() {
        let mut symbols = vec![0u8; 9000];
        symbols.extend(vec![1u8; 1000]);
        let blob = encode(&symbols, 2).unwrap();
        assert!(blob.len() < symbols.len(),
            "compressed ({}) must be < raw ({})", blob.len(), symbols.len());
    }

    #[test]
    fn decode_with_nonzero_offset() {
        let symbols: Vec<u8> = vec![0, 1, 2, 0, 1, 2];
        let mut data = vec![0xDE, 0xAD];
        let blob = encode(&symbols, 3).unwrap();
        data.extend_from_slice(&blob);
        let (decoded, consumed) = decode(&data, 2).unwrap();
        assert_eq!(decoded.as_slice(), symbols.as_slice());
        assert_eq!(consumed, blob.len());
    }

    #[test]
    fn decode_empty_buffer_returns_error() {
        assert!(decode(&[], 0).is_err());
    }

    #[test]
    fn symbol_out_of_alphabet_returns_error() {
        assert!(encode(&[0, 1, 5], 3).is_err());
    }
}
