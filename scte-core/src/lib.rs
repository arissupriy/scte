/// SCTE — Semantic Compression & Transport Engine
///
/// # Crate layout
/// ```text
/// scte-core
/// ├── error      — ScteError (all public errors)
/// ├── types      — PipelineId, SectionType, SectionCodec, constants
/// ├── varint     — LEB128 encode/decode (shared by dict + entropy phases)
/// ├── container
/// │   ├── checksum — FNV-1a 32-bit (Phase 1); replaced by XXH3 in v2
/// │   ├── header   — ScteHeader (24-byte wire format)
/// │   └── section  — SectionEntry (per-section table entry)
/// ├── codec
/// │   ├── encoder  — encode(&[u8]) → Vec<u8>
/// │   └── decoder  — decode(&[u8]) → Result<Vec<u8>, ScteError>
/// └── pipelines
///     └── text
///         ├── value        — JSON Value IR + recursive descent parser
///         ├── canonicalize — canonical JSON serializer
///         ├── tokenizer    — flat token stream from JSON
///         └── dictionary   — frequency analysis + token-to-ID mapping (Phase 3)
/// ```
///
/// # SDK usage
/// ```rust
/// use scte_core::{encode, decode};
///
/// let original = b"hello, SCTE!";
/// let encoded  = encode(original).unwrap();
/// let decoded  = decode(&encoded).unwrap();
/// assert_eq!(decoded, original);
/// ```
pub mod codec;
pub mod container;
pub mod error;
pub mod pipelines;
pub mod types;
pub mod varint;

// ── Top-level convenience re-exports ────────────────────────────────────────

/// Encode `input` bytes into a SCTE container.
///
/// Phase 1: passthrough (no compression). The container is a valid SCTE
/// binary that `decode` can reconstruct byte-identically.
pub use codec::encoder::encode;

/// Decode a SCTE container back to original bytes.
///
/// Validates magic, version, header checksum, and per-section checksums
/// before returning the payload.
pub use codec::decoder::decode;

/// All errors that scte-core can produce.
pub use error::ScteError;

/// Pipeline identifier (stored in the container header).
pub use types::PipelineId;

/// Section type code.
pub use types::SectionType;

/// Section codec code.
pub use types::SectionCodec;

/// Canonicalize JSON bytes to deterministic compact form.
pub use pipelines::text::canonicalize_json;

/// Parse JSON bytes into a flat token stream.
pub use pipelines::text::tokenize_json;

/// A single token in the text pipeline token stream.
pub use pipelines::text::{Token, TokenKind, TokenPayload};

/// Build a dictionary from a token stream (Phase 3).
pub use pipelines::text::Dictionary;

/// A single dictionary entry.
pub use pipelines::text::{DictEntry, DictEntryKind};

/// Dictionary-encoded token and payload types.
pub use pipelines::text::{EncodedToken, EncodedPayload};

/// Encode a token stream against a dictionary.
pub use pipelines::text::encode_with_dict;

/// Decode a dictionary-encoded token stream back to full tokens.
pub use pipelines::text::decode_with_dict;
