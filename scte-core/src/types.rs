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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SectionType {
    /// Global dictionary (token → id mapping).
    Dict   = 0x01,
    /// Token stream output of the text pipeline.
    Tokens = 0x02,
    /// Delta ops — cross-record delta + pattern encoding (Phase 6).
    Delta  = 0x03,
    /// New chunk payloads (binary pipeline, Phase 3).
    Chunks = 0x04,
    /// Hash → file-offset index.
    Index  = 0x05,
    /// Raw or secondary-encoded data.  ← Phase 1 uses only this.
    Data   = 0x06,
    /// File-level metadata (original name, mtime, etc.).
    Meta   = 0x07,
    /// Inferred field schema — field types, enum mappings, encoding hints (Phase 5).
    Schema = 0x08,
}

impl SectionType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Dict),
            0x02 => Some(Self::Tokens),
            0x03 => Some(Self::Delta),
            0x04 => Some(Self::Chunks),
            0x05 => Some(Self::Index),
            0x06 => Some(Self::Data),
            0x07 => Some(Self::Meta),
            0x08 => Some(Self::Schema),
            _    => None,
        }
    }
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
