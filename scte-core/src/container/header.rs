use crate::{
    container::checksum::fnv1a_32,
    error::ScteError,
    types::{FORMAT_VERSION, MAGIC, MAX_SECTION_COUNT, PipelineId},
};

/// Byte size of the fixed SCTE file header.
pub const HEADER_SIZE: usize = 24;

/// Fixed 24-byte SCTE container header.
///
/// Wire layout:
/// ```text
/// Offset  Size  Field            Description
/// ------  ----  -----            -----------
/// 0       4     magic            0x53 0x43 0x54 0x45  ("SCTE")
/// 4       1     version          format version (currently 0x01)
/// 5       1     flags            bit 0: stateful, bit 1: dict present,
///                                bit 2: delta present, bits 3–7: reserved
/// 6       1     pipeline_id      see PipelineId enum
/// 7       1     reserved         0x00
/// 8       8     original_size    u64 little-endian — uncompressed byte count
/// 16      2     section_count    u16 little-endian — number of sections
/// 18      2     reserved         0x00 0x00
/// 20      4     header_checksum  FNV1a-32 of bytes 0..20
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScteHeader {
    pub version: u8,
    /// Bit flags (see wire layout above).
    pub flags: u8,
    /// Pipeline that encoded (and must decode) the payload.
    pub pipeline_id: PipelineId,
    /// Original (pre-encode) byte length of the payload.
    pub original_size: u64,
    /// Number of sections that follow the header in the section table.
    pub section_count: u16,
}

impl ScteHeader {
    /// Construct a new header with default flags.
    pub fn new(pipeline_id: PipelineId, original_size: u64, section_count: u16) -> Self {
        Self {
            version: FORMAT_VERSION,
            flags: 0x00,
            pipeline_id,
            original_size,
            section_count,
        }
    }

    /// Serialize to exactly [`HEADER_SIZE`] bytes.
    ///
    /// The checksum field is computed over bytes 0..20 of the output,
    /// then written into bytes 20..24.
    pub fn write(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];

        buf[0..4].copy_from_slice(&MAGIC);
        buf[4] = self.version;
        buf[5] = self.flags;
        buf[6] = self.pipeline_id as u8;
        buf[7] = 0x00; // reserved
        buf[8..16].copy_from_slice(&self.original_size.to_le_bytes());
        buf[16..18].copy_from_slice(&self.section_count.to_le_bytes());
        buf[18..20].copy_from_slice(&[0x00, 0x00]); // reserved

        // Checksum covers bytes 0..20.
        let checksum = fnv1a_32(&buf[0..20]);
        buf[20..24].copy_from_slice(&checksum.to_le_bytes());

        buf
    }

    /// Parse and validate a header from a byte slice.
    ///
    /// # Errors
    /// - `UnexpectedEof`         — slice shorter than 24 bytes
    /// - `InvalidMagic`          — magic mismatch
    /// - `UnsupportedVersion`    — version != 0x01
    /// - `InvalidHeaderChecksum` — checksum mismatch
    /// - `InvalidSectionCount`   — section_count > MAX_SECTION_COUNT
    pub fn read(buf: &[u8]) -> Result<Self, ScteError> {
        if buf.len() < HEADER_SIZE {
            return Err(ScteError::UnexpectedEof);
        }

        if buf[0..4] != MAGIC {
            return Err(ScteError::InvalidMagic);
        }

        let version = buf[4];
        if version != FORMAT_VERSION {
            return Err(ScteError::UnsupportedVersion(version));
        }

        // Validate checksum over bytes 0..20.
        let stored = u32::from_le_bytes(buf[20..24].try_into().unwrap());
        let computed = fnv1a_32(&buf[0..20]);
        if stored != computed {
            return Err(ScteError::InvalidHeaderChecksum);
        }

        let section_count = u16::from_le_bytes(buf[16..18].try_into().unwrap());
        if section_count > MAX_SECTION_COUNT {
            return Err(ScteError::InvalidSectionCount);
        }

        Ok(Self {
            version,
            flags: buf[5],
            pipeline_id: PipelineId::from_u8(buf[6]),
            original_size: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            section_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PipelineId;

    fn make_header() -> ScteHeader {
        ScteHeader::new(PipelineId::Passthrough, 1024, 1)
    }

    #[test]
    fn roundtrip_header() {
        let hdr = make_header();
        let bytes = hdr.write();
        let parsed = ScteHeader::read(&bytes).unwrap();
        assert_eq!(hdr, parsed);
    }

    #[test]
    fn write_produces_correct_size() {
        assert_eq!(make_header().write().len(), HEADER_SIZE);
    }

    #[test]
    fn magic_bytes_are_scte() {
        let bytes = make_header().write();
        assert_eq!(&bytes[0..4], b"SCTE");
    }

    #[test]
    fn version_byte_is_current() {
        let bytes = make_header().write();
        assert_eq!(bytes[4], FORMAT_VERSION);
    }

    #[test]
    fn reject_wrong_magic() {
        let mut bytes = make_header().write();
        bytes[0] = 0x00;
        assert_eq!(ScteHeader::read(&bytes), Err(ScteError::InvalidMagic));
    }

    #[test]
    fn reject_wrong_version() {
        let mut bytes = make_header().write();
        bytes[4] = 0x02;
        // Must also recompute checksum so it passes that check.
        let cs = fnv1a_32(&bytes[0..20]);
        bytes[20..24].copy_from_slice(&cs.to_le_bytes());
        assert_eq!(
            ScteHeader::read(&bytes),
            Err(ScteError::UnsupportedVersion(0x02))
        );
    }

    #[test]
    fn reject_tampered_checksum() {
        let mut bytes = make_header().write();
        bytes[20] ^= 0xFF; // corrupt the checksum
        assert_eq!(
            ScteHeader::read(&bytes),
            Err(ScteError::InvalidHeaderChecksum)
        );
    }

    #[test]
    fn reject_too_short_buffer() {
        let bytes = make_header().write();
        assert_eq!(
            ScteHeader::read(&bytes[0..10]),
            Err(ScteError::UnexpectedEof)
        );
    }

    #[test]
    fn pipeline_id_roundtrips() {
        let hdr = ScteHeader::new(PipelineId::Text, 0, 0);
        let parsed = ScteHeader::read(&hdr.write()).unwrap();
        assert_eq!(parsed.pipeline_id, PipelineId::Text);
    }
}
