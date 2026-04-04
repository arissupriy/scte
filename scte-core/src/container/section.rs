use crate::{
    container::checksum::fnv1a_32,
    error::ScteError,
    types::{SectionCodec, SectionType},
};

/// Byte size of the fixed part of a section table entry (excluding meta_bytes).
pub const SECTION_ENTRY_FIXED_SIZE: usize = 24;

/// A section table entry describing one payload section in the SCTE file.
///
/// Wire layout (fixed part, 24 bytes):
/// ```text
/// Offset  Size  Field      Description
/// ------  ----  -----      -----------
/// 0       1     type       SectionType code
/// 1       1     codec      SectionCodec code
/// 2       8     offset     u64 LE — absolute byte offset of payload in file
/// 10      8     length     u64 LE — byte length of payload
/// 18      4     checksum   FNV1a-32 of payload bytes
/// 22      2     meta_len   u16 LE — byte length of inline metadata
/// (24     ?     meta_bytes variable, meta_len bytes)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionEntry {
    /// Data category stored in this section.
    pub section_type: SectionType,
    /// Codec applied to this section's payload.
    pub codec: SectionCodec,
    /// Absolute byte offset of this section's payload within the SCTE file.
    pub offset: u64,
    /// Byte length of this section's payload.
    pub length: u64,
    /// FNV1a-32 checksum of the payload bytes.
    pub checksum: u32,
    /// Optional inline metadata (max 65 535 bytes, usually empty for Phase 1).
    pub meta: Vec<u8>,
}

impl SectionEntry {
    /// Create a new entry. Computes the checksum from `payload`.
    ///
    /// `offset` is the absolute byte position where this section's payload
    /// will be written in the final SCTE file.
    pub fn new(
        section_type: SectionType,
        codec: SectionCodec,
        offset: u64,
        payload: &[u8],
    ) -> Self {
        Self {
            section_type,
            codec,
            offset,
            length: payload.len() as u64,
            checksum: fnv1a_32(payload),
            meta: Vec::new(),
        }
    }

    /// Total serialized byte size of this entry (fixed + meta).
    pub fn serialized_size(&self) -> usize {
        SECTION_ENTRY_FIXED_SIZE + self.meta.len()
    }

    /// Serialize this entry to bytes.
    pub fn write(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.serialized_size());

        buf.push(self.section_type.as_u8());
        buf.push(self.codec as u8);
        buf.extend_from_slice(&self.offset.to_le_bytes());
        buf.extend_from_slice(&self.length.to_le_bytes());
        buf.extend_from_slice(&self.checksum.to_le_bytes());
        buf.extend_from_slice(&(self.meta.len() as u16).to_le_bytes());

        if !self.meta.is_empty() {
            buf.extend_from_slice(&self.meta);
        }

        buf
    }

    /// Parse one entry from a byte slice.
    ///
    /// Returns `(entry, bytes_consumed)` so the caller can advance its cursor.
    ///
    /// # Errors
    /// - `UnexpectedEof`  — buffer too short
    /// - `DecodeError`    — unknown section type or codec byte
    pub fn read(buf: &[u8]) -> Result<(Self, usize), ScteError> {
        if buf.len() < SECTION_ENTRY_FIXED_SIZE {
            return Err(ScteError::UnexpectedEof);
        }

        // Unknown section types become SectionType::Unknown(v) — the decoder
        // skips them gracefully.
        let section_type = SectionType::from_u8(buf[0]);

        let codec = SectionCodec::from_u8(buf[1]).ok_or_else(|| {
            ScteError::DecodeError(format!("unknown section codec: 0x{:02x}", buf[1]))
        })?;

        let offset   = u64::from_le_bytes(buf[2..10].try_into().unwrap());
        let length   = u64::from_le_bytes(buf[10..18].try_into().unwrap());
        let checksum = u32::from_le_bytes(buf[18..22].try_into().unwrap());
        let meta_len = u16::from_le_bytes(buf[22..24].try_into().unwrap()) as usize;

        let total = SECTION_ENTRY_FIXED_SIZE + meta_len;
        if buf.len() < total {
            return Err(ScteError::UnexpectedEof);
        }

        let meta = buf[SECTION_ENTRY_FIXED_SIZE..total].to_vec();

        Ok((
            Self { section_type, codec, offset, length, checksum, meta },
            total,
        ))
    }

    /// Verify that `payload` matches the stored checksum.
    ///
    /// # Errors
    /// Returns `InvalidSectionChecksum { section_index }` on mismatch.
    pub fn verify_payload(&self, payload: &[u8], section_index: usize) -> Result<(), ScteError> {
        let computed = fnv1a_32(payload);
        if computed != self.checksum {
            return Err(ScteError::InvalidSectionChecksum { section_index });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{SectionCodec, SectionType};

    fn dummy_entry(payload: &[u8], offset: u64) -> SectionEntry {
        SectionEntry::new(SectionType::Data, SectionCodec::None, offset, payload)
    }

    #[test]
    fn roundtrip_entry() {
        let payload = b"hello world payload";
        let entry = dummy_entry(payload, 48);
        let bytes = entry.write();
        let (parsed, consumed) = SectionEntry::read(&bytes).unwrap();
        assert_eq!(entry, parsed);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn serialized_size_matches_write_len() {
        let entry = dummy_entry(b"test", 0);
        assert_eq!(entry.write().len(), entry.serialized_size());
    }

    #[test]
    fn verify_correct_payload_succeeds() {
        let payload = b"verify me";
        let entry = dummy_entry(payload, 0);
        assert!(entry.verify_payload(payload, 0).is_ok());
    }

    #[test]
    fn verify_wrong_payload_fails() {
        let entry = dummy_entry(b"original", 0);
        assert_eq!(
            entry.verify_payload(b"tampered", 0),
            Err(ScteError::InvalidSectionChecksum { section_index: 0 })
        );
    }

    #[test]
    fn no_meta_size_is_fixed_size() {
        let entry = dummy_entry(b"", 0);
        assert_eq!(entry.serialized_size(), SECTION_ENTRY_FIXED_SIZE);
    }

    #[test]
    fn reject_too_short_buffer() {
        let short = [0u8; 10];
        assert_eq!(
            SectionEntry::read(&short),
            Err(ScteError::UnexpectedEof)
        );
    }

    #[test]
    fn offset_is_preserved() {
        let entry = dummy_entry(b"data", 9999);
        let (parsed, _) = SectionEntry::read(&entry.write()).unwrap();
        assert_eq!(parsed.offset, 9999);
    }

    #[test]
    fn length_matches_payload_size() {
        let payload = b"exactly 17 bytes!";
        let entry = dummy_entry(payload, 0);
        assert_eq!(entry.length, payload.len() as u64);
    }
}
