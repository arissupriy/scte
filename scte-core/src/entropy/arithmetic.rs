/// High-precision arithmetic coding — Phase 7.
///
/// Used instead of rANS when `P(symbol) > 0.99`, where rANS wastes bits due
/// to its fixed `M = 2^16` denominator precision.
///
/// With arithmetic coding, bits per symbol = `-log2(P)`:
/// - P = 0.999  → 0.0014 bits/symbol
/// - P = 0.9999 → 0.00014 bits/symbol
///
/// rANS at M=2^16 cannot represent probabilities above ~0.9999 efficiently.
///
/// # Status: STUB (Phase 7)
use crate::error::ScteError;

/// Arithmetic-encode `symbols` using the provided probability table.
///
/// `probs[i]` = probability of symbol `i`, sum must equal 1.0.
///
/// # Status: STUB — returns `EncodeError`.
pub fn encode(_symbols: &[u8], _probs: &[f64]) -> Result<Vec<u8>, ScteError> {
    Err(ScteError::EncodeError(
        "arithmetic coder not yet implemented (Phase 7)".into(),
    ))
}

/// Arithmetic-decode `count` symbols from `data` starting at `pos`.
///
/// # Status: STUB — returns `DecodeError`.
pub fn decode(_data: &[u8], _pos: usize, _count: usize, _probs: &[f64])
    -> Result<(Vec<u8>, usize), ScteError>
{
    Err(ScteError::DecodeError(
        "arithmetic coder not yet implemented (Phase 7)".into(),
    ))
}
