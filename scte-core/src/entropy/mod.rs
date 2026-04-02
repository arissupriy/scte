/// Entropy coding subsystem (Phase 4 — rANS).
///
/// # Modules
/// - `frequency` — frequency table builder, normalizer, and wire format
/// - `rans`      — rANS encode / decode over raw byte symbol streams
/// - `codec`     — TOKENS section serializer: combines Phase 3 output with rANS
pub mod codec;
pub mod frequency;
pub mod rans;

pub use codec::{decode_token_bytes, encode_token_bytes, kind_to_byte, byte_to_kind};
pub use frequency::FreqTable;
pub use rans::{encode as rans_encode, decode as rans_decode};
