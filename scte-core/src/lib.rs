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
/// ├── pipelines
/// │   └── text
/// │       ├── value        — JSON Value IR + recursive descent parser
/// │       ├── canonicalize — canonical JSON serializer
/// │       ├── tokenizer    — flat token stream from JSON
/// │       └── dictionary   — frequency analysis + token-to-ID mapping (Phase 3)
/// └── entropy
///     ├── frequency — FreqTable: build, normalize, serialize (rANS model)
///     ├── rans      — rANS encode / decode (Phase 4)
///     └── codec     — TOKENS section wire format (kinds + payloads)
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
pub mod entropy;
pub mod error;
pub mod pipelines;
pub mod schema;
pub mod types;
pub mod varint;

// ── Pipeline trait + context types ──────────────────────────────────────────
pub use pipelines::{Pipeline, DataClass, TextSubType, EncodeContext, DecodeContext, Encoded, TextPipeline};

/// Reconstruct JSON bytes from a decoded token stream.
pub use pipelines::text::tokens_to_json;

/// Decode a two-pass token stream back to tokens (schema + delta restore).
pub use pipelines::text::decode_token_stream;

/// Two-pass schema-aware JSON encoder (Phase 5+).
pub use pipelines::text::encode_json_two_pass;

/// Output bundle from a Phase 5+ two-pass encode.
pub use pipelines::text::TwoPassOutput;

/// Inferred schema from a JSON file.
pub use schema::{FileSchema, FieldSchema, FieldType, IntHint};

/// Serialize / deserialize a FileSchema to/from SCHEMA section bytes.
pub use schema::serializer::{serialize as schema_serialize, deserialize as schema_deserialize};

// ── Top-level convenience re-exports ────────────────────────────────────────

/// Encode `input` bytes into a SCTE container (Structured mode).
///
/// JSON is transformed through the full pipeline (columnar / two-pass /
/// entropy).  Non-JSON is stored verbatim.  For byte-exact JSON preservation
/// use [`encode_with`] with [`EncodingMode::Raw`].
pub use codec::encoder::encode;

/// Encode with an explicit [`EncodingMode`].
///
/// - `EncodingMode::Structured` — full pipeline (default, best compression)
/// - `EncodingMode::Raw`        — passthrough, always byte-exact
pub use codec::encoder::encode_with;

/// Encode with full control: both [`EncodingMode`] and [`EncodingHint`].
pub use codec::encoder::encode_full;

/// Options bundle (mode + hint) for [`encode_full`].
pub use codec::encoder::EncodeOptions;

/// Controls whether the encoder transforms JSON or stores bytes verbatim.
pub use codec::encoder::EncodingMode;

/// Hint to the encoder controlling the speed/ratio trade-off.
pub use types::EncodingHint;

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

/// Serialize a dictionary-encoded token stream to the TOKENS section payload
/// (rANS-encoded kinds + varint/raw payloads).
pub use pipelines::text::encode_token_bytes;

/// Deserialize a TOKENS section payload back to a dictionary-encoded
/// token stream.
pub use pipelines::text::decode_token_bytes;

/// Frequency table for the rANS entropy model.
pub use entropy::FreqTable;
