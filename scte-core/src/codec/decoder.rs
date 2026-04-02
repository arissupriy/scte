use crate::{
    container::{
        header::{ScteHeader, HEADER_SIZE},
        section::SectionEntry,
    },
    error::ScteError,
    types::{SectionCodec, SectionType, MAX_DECOMPRESSED_SIZE},
};

/// Decode a SCTE container back to the original bytes (Phase 1: passthrough).
///
/// # Validation steps (in order)
/// 1. Buffer long enough for header (24 bytes)
/// 2. Magic bytes == "SCTE"
/// 3. Format version == 0x01
/// 4. Header checksum valid
/// 5. section_count ≤ MAX_SECTION_COUNT
/// 6. original_size ≤ MAX_DECOMPRESSED_SIZE
/// 7. Section table entries parse without error
/// 8. DATA section payload checksum valid
///
/// # Errors
/// Returns a `ScteError` variant if any validation step fails.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, ScteError> {
    if input.len() < HEADER_SIZE {
        return Err(ScteError::UnexpectedEof);
    }

    // Step 1–5: parse and validate header.
    let header = ScteHeader::read(&input[0..HEADER_SIZE])?;

    // Step 6: safety check on declared original size.
    if header.original_size as usize > MAX_DECOMPRESSED_SIZE {
        return Err(ScteError::InputTooLarge(header.original_size as usize));
    }

    // Step 7: parse the section table.
    let mut cursor = HEADER_SIZE;
    let mut sections: Vec<SectionEntry> = Vec::with_capacity(header.section_count as usize);

    for _ in 0..header.section_count {
        let remaining = input.get(cursor..).ok_or(ScteError::UnexpectedEof)?;
        let (entry, consumed) = SectionEntry::read(remaining)?;
        sections.push(entry);
        cursor += consumed;
    }

    // Step 8: find the first DATA section with codec None and return its payload.
    //
    // Phase 1 always has exactly one such section. Future phases may have
    // multiple sections (DICT, TOKENS, etc.) before the DATA section.
    for (idx, section) in sections.iter().enumerate() {
        if section.section_type == SectionType::Data
            && section.codec == SectionCodec::None
        {
            let start = section.offset as usize;
            let end = start
                .checked_add(section.length as usize)
                .ok_or(ScteError::UnexpectedEof)?;

            let payload = input.get(start..end).ok_or(ScteError::UnexpectedEof)?;

            // Verify section payload checksum.
            section.verify_payload(payload, idx)?;

            return Ok(payload.to_vec());
        }
    }

    Err(ScteError::DecodeError(
        "no DATA section with codec None found".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::encoder::encode;

    #[test]
    fn decode_rejects_too_short_buffer() {
        assert_eq!(decode(b"SC"), Err(ScteError::UnexpectedEof));
    }

    #[test]
    fn decode_rejects_wrong_magic() {
        let mut out = encode(b"test").unwrap();
        out[0] = 0x00; // corrupt magic
        assert_eq!(decode(&out), Err(ScteError::InvalidMagic));
    }

    #[test]
    fn decode_rejects_corrupted_header_checksum() {
        let mut out = encode(b"test").unwrap();
        out[20] ^= 0xFF; // corrupt header checksum byte
        assert_eq!(decode(&out), Err(ScteError::InvalidHeaderChecksum));
    }

    #[test]
    fn decode_rejects_corrupted_payload() {
        let mut out = encode(b"hello world").unwrap();
        // Flip a byte in the DATA payload area (after header + section table = 48 bytes).
        let payload_start = 24 + 24; // HEADER_SIZE + SECTION_ENTRY_FIXED_SIZE
        out[payload_start] ^= 0xFF;
        assert_eq!(
            decode(&out),
            Err(ScteError::InvalidSectionChecksum { section_index: 0 })
        );
    }

    #[test]
    fn decode_empty_payload() {
        let encoded = encode(b"").unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, b"");
    }
}
