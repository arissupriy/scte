// ── Magic & version ─────────────────────────────────────────────────────────

/// Magic bytes identifying a SCTE container: ASCII "SCTE".
pub const MAGIC: [u8; 4] = [0x53, 0x43, 0x54, 0x45];

/// Current wire-format version.
///
/// Bump this when the header layout or checksum algorithm changes.
pub const FORMAT_VERSION: u8 = 0x01;

// ── Safety limits ───────────────────────────────────────────────────────────

/// Decoder refuses to produce output larger than this (default 4 GiB).
pub const MAX_DECOMPRESSED_SIZE: usize = 4 * 1024 * 1024 * 1024;

/// Decoder refuses containers with more sections than this.
pub const MAX_SECTION_COUNT: u16 = 1024;

// ── Pipeline IDs ────────────────────────────────────────────────────────────

/// Identifies which encoding pipeline wrote (and must read) the payload.
///
/// Stored as a single byte at offset 6 of the SCTE header.
/// New pipeline IDs may be added without breaking existing decoders;
/// a decoder that encounters an unknown ID returns `UnsupportedVersion`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PipelineId {
    Unknown          = 0x00,
    /// Text / semantic pipeline (JSON, CSV, log, XML).  ← Phase 2+
    Text             = 0x01,
    /// Structured binary (DOCX, XLSX).                  ← Phase 4+
    StructuredBinary = 0x02,
    /// Binary / executable / firmware.                  ← Phase 3+
    Binary           = 0x03,
    /// Media (audio, video, image).                     ← Phase 4+
    Media            = 0x04,
    /// Official Zstd fallback — always decodable.
    ZstdFallback     = 0xFE,
    /// Passthrough — payload is stored unmodified.      ← Phase 1 (active)
    Passthrough      = 0xFF,
}

impl PipelineId {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x01 => Self::Text,
            0x02 => Self::StructuredBinary,
            0x03 => Self::Binary,
            0x04 => Self::Media,
            0xFE => Self::ZstdFallback,
            0xFF => Self::Passthrough,
            _    => Self::Unknown,
        }
    }
}

// ── Section types ────────────────────────────────────────────────────────────

/// Type of data stored in a section payload.
///
/// Unknown section type bytes are represented by `Unknown(u8)` so that decoders
/// written against older format versions can skip unrecognised sections instead
/// of hard-erroring on forward-compatible container files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionType {
    /// Global dictionary (token → id mapping).
    Dict,
    /// Token stream output of the text pipeline.
    Tokens,
    /// Multi-stream entropy-coded token payload (3 streams: key / str / misc).
    TokensRans,
    /// Delta ops — cross-record delta + pattern encoding (Phase 6).
    Delta,
    /// New chunk payloads (binary pipeline, Phase 3).
    Chunks,
    /// Hash → file-offset index.
    Index,
    /// Raw or secondary-encoded data.  ← Phase 1 uses only this.
    Data,
    /// File-level metadata (original name, mtime, etc.).
    Meta,
    /// Inferred field schema — field types, enum mappings, encoding hints (Phase 5).
    Schema,
    /// Columnar encoding — column-major layout for Array<Object> JSON (Phase 2).
    Columnar,
    /// Global column schema — shared variant tables and FreqTables for all
    /// subsequent COLUMNAR chunks in a multi-chunk container.  Emitted as the
    /// first section before the COLUMNAR sections so that per-chunk sections can
    /// omit redundant variant tables and frequency tables.
    GlobalCols,
    /// Unrecognised section type — decoder should skip this section.
    Unknown(u8),
}

impl SectionType {
    /// Decode a section-type byte.  Never fails — unknown bytes become
    /// `SectionType::Unknown(v)` so decoders can gracefully skip them.
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x01 => Self::Dict,
            0x02 => Self::Tokens,
            0x03 => Self::Delta,
            0x04 => Self::Chunks,
            0x05 => Self::Index,
            0x06 => Self::Data,
            0x07 => Self::Meta,
            0x08 => Self::Schema,
            0x09 => Self::Columnar,
            0x0A => Self::TokensRans,
            0x0B => Self::GlobalCols,
            v    => Self::Unknown(v),
        }
    }

    /// Return the canonical wire byte for this section type.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Dict       => 0x01,
            Self::Tokens     => 0x02,
            Self::Delta      => 0x03,
            Self::Chunks     => 0x04,
            Self::Index      => 0x05,
            Self::Data       => 0x06,
            Self::Meta       => 0x07,
            Self::Schema     => 0x08,
            Self::Columnar   => 0x09,
            Self::TokensRans => 0x0A,
            Self::GlobalCols => 0x0B,
            Self::Unknown(v) => v,
        }
    }
}

// ── Encoding hint ────────────────────────────────────────────────────────────

/// Hint to the encoder controlling the speed/ratio trade-off.
///
/// The hint does **not** affect decode (both modes produce the same wire format).
/// It also does **not** affect correctness: `decode(encode_full(x, opts)) == x`
/// holds for any combination of [`EncodingMode`] and `EncodingHint`.
///
/// # Variants
/// * `Default` — full pipeline; optimises for the smallest output.
/// * `Fast`    — skip the most expensive transforms (period detection, heavy
///   schema inference, rANS). Faster encode; slightly larger output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingHint {
    /// Full pipeline — best compression ratio.  This is the default.
    Default,
    /// Speed-first: disable expensive analysis passes.  Use when encode
    /// latency matters more than ratio (e.g. hot-path API responses).
    Fast,
}

impl Default for EncodingHint {
    fn default() -> Self { Self::Default }
}

// ── Section codecs ───────────────────────────────────────────────────────────

/// Codec applied to a section's payload bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SectionCodec {
    /// No transformation — raw bytes.  ← Phase 1 uses only this.
    None       = 0x00,
    /// Range Asymmetric Numeral Systems (custom rANS).  ← Phase 4+
    Rans       = 0x01,
    /// Zstd compression.
    Zstd       = 0x02,
    /// LEB128 varint stream.  ← Phase 3+
    Varint     = 0x03,
    /// High-precision arithmetic coding — used when P(symbol) > 0.99 (Phase 7).
    Arithmetic = 0x04,
}

impl SectionCodec {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::None),
            0x01 => Some(Self::Rans),
            0x02 => Some(Self::Zstd),
            0x03 => Some(Self::Varint),
            0x04 => Some(Self::Arithmetic),
            _    => None,
        }
    }
}
