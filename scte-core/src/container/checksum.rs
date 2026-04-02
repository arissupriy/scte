/// FNV-1a 32-bit hash (Fowler–Noll–Vo variant 1a).
///
/// Used for header and per-section checksums in format version 0x01.
///
/// # Properties
/// - O(n) time, O(1) space
/// - No external dependencies
/// - Deterministic across all platforms and Rust versions
///
/// # Note
/// This will be replaced by XXH3-32 when `FORMAT_VERSION` is bumped to 0x02.
/// Both versions are tagged in the container header, so old files remain
/// decodable by version-aware decoders.
///
/// FNV-1a spec: http://www.isthe.com/chongo/tech/comp/fnv/
pub fn fnv1a_32(data: &[u8]) -> u32 {
    const OFFSET_BASIS: u32 = 2_166_136_261;
    const PRIME: u32 = 16_777_619;

    let mut hash = OFFSET_BASIS;
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_is_offset_basis() {
        // FNV-1a of empty string is the offset basis by definition.
        assert_eq!(fnv1a_32(b""), 2_166_136_261);
    }

    #[test]
    fn known_vector_fnv1a_32() {
        // "hello" → known FNV-1a 32-bit value from the spec.
        assert_eq!(fnv1a_32(b"hello"), 0x4f9f2cab);
    }

    #[test]
    fn deterministic_across_calls() {
        let data = b"SCTE container checksum test";
        assert_eq!(fnv1a_32(data), fnv1a_32(data));
    }

    #[test]
    fn different_inputs_produce_different_hashes() {
        assert_ne!(fnv1a_32(b"abc"), fnv1a_32(b"abd"));
    }
}
