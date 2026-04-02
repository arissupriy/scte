/// Entropy coding subsystem.
///
/// # Modules
/// - `frequency`   — frequency table builder, normalizer, and wire format
/// - `rans`        — rANS encode / decode over raw byte symbol streams  (Phase 4)
/// - `codec`       — Generic byte-stream entropy codec (format-agnostic) (Phase 4)
/// - `arithmetic`  — Arithmetic coding stub                              (Phase 7)
/// - `ctw`         — Context-Tree Weighting (CTW) encoder stub           (Phase 7)
/// - `context`     — ContextKey for CTW conditioning                     (Phase 7)
pub mod arithmetic;
pub mod codec;
pub mod context;
pub mod ctw;
pub mod frequency;
pub mod rans;

pub use codec::{encode as codec_encode, decode as codec_decode};
pub use frequency::FreqTable;
pub use rans::{encode as rans_encode, decode as rans_decode};
