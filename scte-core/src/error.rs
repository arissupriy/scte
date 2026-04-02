use std::fmt;

/// All errors produced by the SCTE engine.
///
/// Every public function in scte-core returns `Result<T, ScteError>`.
/// Error variants are stable — adding new variants is non-breaking;
/// removing or renaming is a major version bump.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ScteError {
    /// Input does not start with the "SCTE" magic bytes.
    InvalidMagic,

    /// Container uses a format version this engine does not support.
    UnsupportedVersion(u8),

    /// The 4-byte checksum stored in the header does not match computed value.
    InvalidHeaderChecksum,

    /// The checksum stored in a section table entry does not match the payload.
    InvalidSectionChecksum { section_index: usize },

    /// Buffer ended before the expected number of bytes were read.
    UnexpectedEof,

    /// Input or declared original_size exceeds the engine's safety limit.
    InputTooLarge(usize),

    /// `section_count` in header exceeds `MAX_SECTION_COUNT`.
    InvalidSectionCount,

    /// Decoding failed for a semantic reason (e.g. no DATA section present).
    DecodeError(String),
}

impl fmt::Display for ScteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScteError::InvalidMagic => write!(f, "invalid magic bytes (expected 'SCTE')"),
            ScteError::UnsupportedVersion(v) => {
                write!(f, "unsupported format version: 0x{v:02x}")
            }
            ScteError::InvalidHeaderChecksum => {
                write!(f, "header checksum mismatch")
            }
            ScteError::InvalidSectionChecksum { section_index } => {
                write!(f, "section {section_index} checksum mismatch")
            }
            ScteError::UnexpectedEof => write!(f, "unexpected end of input"),
            ScteError::InputTooLarge(n) => {
                write!(f, "input too large: {n} bytes (limit: 4 GiB)")
            }
            ScteError::InvalidSectionCount => {
                write!(f, "section_count exceeds maximum allowed")
            }
            ScteError::DecodeError(msg) => write!(f, "decode error: {msg}"),
        }
    }
}

impl std::error::Error for ScteError {}
