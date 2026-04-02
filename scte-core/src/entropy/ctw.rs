/// Context Tree Weighting (CTW) — Phase 7.
///
/// CTW is an information-theoretically optimal adaptive compression algorithm.
/// It builds a binary tree of contexts online (no training data required) and
/// provably converges to the true entropy of the source.
///
/// Paper: Willems, Shtarkov, Tjalkens (1995) — "The Context-Tree Weighting Method"
///
/// # Why CTW over rANS order-1
/// - rANS order-1: context = last symbol only (10 buckets for JSON)
/// - CTW: context = arbitrary-depth suffix of the symbol stream (millions of contexts)
/// - CTW is provably optimal as data grows; rANS order-1 is not
///
/// # Status: STUB (Phase 7)
use crate::error::ScteError;

/// Context Tree Weighting encoder.
///
/// Builds the context tree online from the first symbol.
/// The final tree is serialized and stored in the TOKENS section header.
///
/// # Status: STUB
pub struct CtwEncoder {
    /// Maximum context depth (order). Default: 8 for Phase 7 initial.
    pub max_depth: usize,
}

impl CtwEncoder {
    pub fn new(max_depth: usize) -> Self {
        Self { max_depth }
    }

    /// Encode `symbols` with online CTW model.
    ///
    /// # Status: STUB — returns `EncodeError`.
    pub fn encode(&self, _symbols: &[u8]) -> Result<Vec<u8>, ScteError> {
        Err(ScteError::EncodeError(
            "CTW encoder not yet implemented (Phase 7)".into(),
        ))
    }

    /// Decode symbols, rebuilding the CTW model online.
    ///
    /// # Status: STUB — returns `DecodeError`.
    pub fn decode(&self, _data: &[u8]) -> Result<Vec<u8>, ScteError> {
        Err(ScteError::DecodeError(
            "CTW decoder not yet implemented (Phase 7)".into(),
        ))
    }
}
