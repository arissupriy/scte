use crate::{
    container::{
        header::{ScteHeader, HEADER_SIZE},
        section::{SectionEntry, SECTION_ENTRY_FIXED_SIZE},
    },
    error::ScteError,
    pipelines::text::{encode_json_two_pass, TwoPassOutput,
                      detect_homogeneous_array, encode_columnar},
    types::{PipelineId, SectionCodec, SectionType, MAX_DECOMPRESSED_SIZE},
};

// ── Public entry point ────────────────────────────────────────────────────────

/// Encode `input` bytes into a SCTE container.
///
/// # Dispatch
/// - **JSON input** (`{…}` or `[…]`): full Phase 2-7 pipeline —
///   schema inference, dictionary, rANS/CTW, delta encoding.
///   Produces a multi-section container: SCHEMA + DICT + TOKENS (+ DELTA if
///   any integer columns were detected).
/// - **All other input**: Phase 1 passthrough — wraps bytes verbatim in a
///   single DATA section for binary-identical reconstruction.
///
/// # Errors
/// - `InputTooLarge` — input exceeds `MAX_DECOMPRESSED_SIZE` (4 GiB)
/// - `EncodeError`   — JSON pipeline error (malformed JSON, etc.)
pub fn encode(input: &[u8]) -> Result<Vec<u8>, ScteError> {
    if input.len() > MAX_DECOMPRESSED_SIZE {
        return Err(ScteError::InputTooLarge(input.len()));
    }

    if looks_like_json(input) {
        encode_json(input)
    } else {
        encode_passthrough(input)
    }
}

// ── JSON path ─────────────────────────────────────────────────────────────────

/// Returns `true` if the first non-whitespace byte is `{` or `[`.
fn looks_like_json(input: &[u8]) -> bool {
    let first = input.iter().find(|&&b| !b.is_ascii_whitespace());
    matches!(first, Some(b'{') | Some(b'['))
}

fn encode_json(input: &[u8]) -> Result<Vec<u8>, ScteError> {
    // Try columnar path first (Array<Object> with uniform schema).
    if detect_homogeneous_array(input) {
        if let Ok(columnar_bytes) = encode_columnar(input) {
            return assemble_columnar_container(input.len(), &columnar_bytes);
        }
    }
    // Fall back to row-major two-pass pipeline.
    let out = encode_json_two_pass(input, 2)?;
    assemble_text_container(input.len(), &out)
}

// ── Columnar path ────────────────────────────────────────────────────────────

/// Assemble a SCTE container for `PipelineId::Text` carrying a single
/// COLUMNAR section (type 0x09). Replaces the full SCHEMA+DICT+TOKENS+DELTA
/// layout for Array<Object> JSON inputs.
pub(crate) fn assemble_columnar_container(
    original_len: usize,
    columnar_bytes: &[u8],
) -> Result<Vec<u8>, ScteError> {
    let section_count: u16 = 1;
    let section_tbl   = SECTION_ENTRY_FIXED_SIZE * section_count as usize;
    let header_size   = HEADER_SIZE + section_tbl;

    let col_off: u64 = header_size as u64;
    let col_sec  = SectionEntry::new(SectionType::Columnar, SectionCodec::None, col_off, columnar_bytes);
    let header   = ScteHeader::new(PipelineId::Text, original_len as u64, section_count);

    let total = header_size + columnar_bytes.len();
    let mut result = Vec::with_capacity(total);
    result.extend_from_slice(&header.write());
    result.extend_from_slice(&col_sec.write());
    result.extend_from_slice(columnar_bytes);
    Ok(result)
}

// ── Text (row-major) path ────────────────────────────────────────────────────

/// Assemble a SCTE container for `PipelineId::Text`.
///
/// Section layout:
/// ```text
/// Header (24 B)
/// Section table: SCHEMA + DICT + TOKENS [+ DELTA]  (24 B each)
/// SCHEMA payload
/// DICT   payload
/// TOKENS payload
/// DELTA  payload   (only when delta_bytes is non-empty)
/// ```
pub(crate) fn assemble_text_container(
    original_len: usize,
    out: &TwoPassOutput,
) -> Result<Vec<u8>, ScteError> {
    let dict_bytes    = out.dict.serialize();
    let has_delta     = !out.delta_bytes.is_empty();
    let section_count: u16 = if has_delta { 4 } else { 3 };
    let section_tbl   = SECTION_ENTRY_FIXED_SIZE * section_count as usize;
    let header_size   = HEADER_SIZE + section_tbl;

    // Absolute byte offsets for each section payload.
    let schema_off: u64 = header_size as u64;
    let dict_off:   u64 = schema_off + out.schema_bytes.len() as u64;
    let tokens_off: u64 = dict_off   + dict_bytes.len() as u64;
    let delta_off:  u64 = tokens_off + out.token_bytes.len() as u64;

    let schema_sec = SectionEntry::new(SectionType::Schema, SectionCodec::None, schema_off, &out.schema_bytes);
    let dict_sec   = SectionEntry::new(SectionType::Dict,   SectionCodec::None, dict_off,   &dict_bytes);
    let tokens_sec = SectionEntry::new(SectionType::Tokens, SectionCodec::None, tokens_off, &out.token_bytes);

    let header = ScteHeader::new(PipelineId::Text, original_len as u64, section_count);

    let payload_len = out.schema_bytes.len()
        + dict_bytes.len()
        + out.token_bytes.len()
        + if has_delta { out.delta_bytes.len() } else { 0 };

    let mut result = Vec::with_capacity(header_size + payload_len);
    result.extend_from_slice(&header.write());
    result.extend_from_slice(&schema_sec.write());
    result.extend_from_slice(&dict_sec.write());
    result.extend_from_slice(&tokens_sec.write());
    if has_delta {
        let delta_sec = SectionEntry::new(SectionType::Delta, SectionCodec::None, delta_off, &out.delta_bytes);
        result.extend_from_slice(&delta_sec.write());
    }
    result.extend_from_slice(&out.schema_bytes);
    result.extend_from_slice(&dict_bytes);
    result.extend_from_slice(&out.token_bytes);
    if has_delta {
        result.extend_from_slice(&out.delta_bytes);
    }
    Ok(result)
}

// ── Passthrough path ──────────────────────────────────────────────────────────

fn encode_passthrough(input: &[u8]) -> Result<Vec<u8>, ScteError> {
    let section_count: u16 = 1;
    let data_offset: u64   = (HEADER_SIZE + SECTION_ENTRY_FIXED_SIZE) as u64;

    let section = SectionEntry::new(SectionType::Data, SectionCodec::None, data_offset, input);
    let header  = ScteHeader::new(PipelineId::Passthrough, input.len() as u64, section_count);

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
        // Empty input is not JSON → passthrough: header + 1 section + 0 payload
        let out = encode(b"").unwrap();
        assert_eq!(out.len(), HEADER_SIZE + SECTION_ENTRY_FIXED_SIZE);
    }

    #[test]
    fn encode_output_starts_with_magic() {
        let out = encode(b"test").unwrap();
        assert_eq!(&out[0..4], b"SCTE");
    }

    #[test]
    fn encode_passthrough_size_is_predictable() {
        let input = b"hello world";
        let out   = encode(input).unwrap();
        assert_eq!(out.len(), HEADER_SIZE + SECTION_ENTRY_FIXED_SIZE + input.len());
    }

    #[test]
    fn encode_large_passthrough() {
        let input = vec![0xABu8; 1024 * 1024]; // 1 MiB binary
        let out   = encode(&input).unwrap();
        assert_eq!(out.len(), HEADER_SIZE + SECTION_ENTRY_FIXED_SIZE + input.len());
    }

    #[test]
    fn encode_json_uses_text_pipeline() {
        let json = br#"[{"id":1,"status":"ok"},{"id":2,"status":"fail"}]"#;
        let out  = encode(json).unwrap();
        assert_eq!(&out[0..4], b"SCTE");
        // Pipeline ID byte is at offset 6 in the header; 0x01 = Text
        assert_eq!(out[6], 0x01, "expected PipelineId::Text for JSON input");
    }

    #[test]
    fn json_encode_smaller_than_passthrough_for_repetitive_data() {
        let records: String = (0..200)
            .map(|i| {
                let s = if i % 2 == 0 { "ok" } else { "fail" };
                format!(r#"{{"id":{i},"status":"{s}","active":true}}"#)
            })
            .collect::<Vec<_>>()
            .join(",");
        let json       = format!("[{records}]").into_bytes();
        let compressed = encode(&json).unwrap();
        let passthru   = encode_passthrough(&json).unwrap();
        assert!(
            compressed.len() < passthru.len(),
            "JSON pipeline ({} B) should be smaller than passthrough ({} B)",
            compressed.len(), passthru.len()
        );
    }
}

