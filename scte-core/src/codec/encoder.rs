use crate::{
    container::{
        header::{ScteHeader, HEADER_SIZE},
        section::{SectionEntry, SECTION_ENTRY_FIXED_SIZE},
    },
    error::ScteError,
    types::{PipelineId, SectionCodec, SectionType, MAX_DECOMPRESSED_SIZE},
};

/// Encode `input` bytes into a SCTE container (Phase 1: passthrough).
///
/// # What this does
/// Wraps the input verbatim into a valid SCTE binary container:
///
/// ```text
/// ┌─────────────────────────────────┐
/// │  Header         (24 bytes)      │
/// ├─────────────────────────────────┤
/// │  Section table  (24 bytes × 1)  │
/// ├─────────────────────────────────┤
/// │  DATA section   (input bytes)   │
/// └─────────────────────────────────┘
/// ```
///
/// No compression is applied. Pipeline ID is set to `Passthrough (0xFF)`.
/// All future pipelines emit the same container shape with a different
/// pipeline ID and section contents.
///
/// # Errors
/// - `InputTooLarge` — input exceeds `MAX_DECOMPRESSED_SIZE` (4 GiB)
pub fn encode(input: &[u8]) -> Result<Vec<u8>, ScteError> {
    if input.len() > MAX_DECOMPRESSED_SIZE {
        return Err(ScteError::InputTooLarge(input.len()));
    }

    // Phase 1: exactly one section (DATA, codec None).
    let section_count: u16 = 1;

    // The section table occupies SECTION_ENTRY_FIXED_SIZE bytes (no meta).
    // DATA payload starts immediately after header + section table.
    let data_offset: u64 = (HEADER_SIZE + SECTION_ENTRY_FIXED_SIZE) as u64;

    let section = SectionEntry::new(
        SectionType::Data,
        SectionCodec::None,
        data_offset,
        input,
    );

    let header = ScteHeader::new(
        PipelineId::Passthrough,
        input.len() as u64,
        section_count,
    );

    // Assemble: header | section_table | payload
    let total = HEADER_SIZE + section.serialized_size() + input.len();
    let mut output = Vec::with_capacity(total);

    output.extend_from_slice(&header.write());
    output.extend_from_slice(&section.write());
    output.extend_from_slice(input);

    debug_assert_eq!(output.len(), total, "encoder: size mismatch");

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::header::HEADER_SIZE;
    use crate::container::section::SECTION_ENTRY_FIXED_SIZE;

    #[test]
    fn encode_empty_input() {
        let out = encode(b"").unwrap();
        // header + 1 section entry + 0 payload bytes
        assert_eq!(out.len(), HEADER_SIZE + SECTION_ENTRY_FIXED_SIZE);
    }

    #[test]
    fn encode_output_starts_with_magic() {
        let out = encode(b"test").unwrap();
        assert_eq!(&out[0..4], b"SCTE");
    }

    #[test]
    fn encode_output_size_is_predictable() {
        let input = b"hello world";
        let out = encode(input).unwrap();
        assert_eq!(
            out.len(),
            HEADER_SIZE + SECTION_ENTRY_FIXED_SIZE + input.len()
        );
    }

    #[test]
    fn encode_large_input() {
        let input = vec![0xABu8; 1024 * 1024]; // 1 MiB
        let out = encode(&input).unwrap();
        assert_eq!(out.len(), HEADER_SIZE + SECTION_ENTRY_FIXED_SIZE + input.len());
    }
}
