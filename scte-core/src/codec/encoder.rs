use crate::{
    container::{
        header::{ScteHeader, HEADER_SIZE},
        section::{SectionEntry, SECTION_ENTRY_FIXED_SIZE},
    },
    error::ScteError,
    pipelines::text::{encode_json_two_pass_with_tokens, TwoPassOutput,
                      try_encode_columnar_chunks_from_tokens, tokenize_json},
    types::{EncodingHint, PipelineId, SectionCodec, SectionType, MAX_DECOMPRESSED_SIZE},
};

// ── Public entry point ────────────────────────────────────────────────────────

/// Controls how `encode_with` treats the input.
///
/// # Modes
///
/// | Mode | JSON input | Non-JSON input | Decode guarantee |
/// |------|-----------|----------------|-----------------|
/// | `Structured` | full pipeline (columnar / two-pass / entropy) | passthrough | semantic equality |
/// | `Raw` | passthrough (no transform) | passthrough | **byte-exact** |
///
/// Use `Raw` when you need the original bytes back verbatim — for
/// audit logs, binary blobs embedded in JSON, or any context where you
/// cannot afford the whitespace/key-order normalisation that the JSON
/// pipeline applies.
///
/// `Structured` (the default used by `encode`) gives the best compression
/// ratio but re-emits JSON without the original formatting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingMode {
    /// Full pipeline: JSON → columnar / two-pass / entropy encoding.
    /// Maximises compression.  Decodes to semantically identical JSON
    /// (values preserved; whitespace and key order may differ).
    Structured,

    /// Passthrough for all inputs: bytes stored verbatim.
    /// `decode(encode_with(x, Raw)) == x` byte-for-byte, always.
    Raw,
}

/// Encode `input` with an explicit [`EncodingMode`].
///
/// ```rust
/// use scte_core::{encode_with, EncodingMode};
///
/// let json = br#"{"a":1}"#;
///
/// // Structured: transforms JSON (best compression, semantic equality only)
/// let structured = encode_with(json, EncodingMode::Structured).unwrap();
///
/// // Raw: no transform — decode gives back the exact original bytes
/// let raw = encode_with(json, EncodingMode::Raw).unwrap();
/// let decoded = scte_core::decode(&raw).unwrap();
/// assert_eq!(decoded, json);
/// ```

/// Options bundle for [`encode_full`].
///
/// Combines an [`EncodingMode`] (what to encode) with an [`EncodingHint`]
/// (how aggressively to encode).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodeOptions {
    /// Controls whether JSON is transformed or stored verbatim.
    pub mode: EncodingMode,
    /// Controls the encode speed/ratio trade-off.
    pub hint: EncodingHint,
}

impl Default for EncodeOptions {
    fn default() -> Self {
        Self { mode: EncodingMode::Structured, hint: EncodingHint::Default }
    }
}

/// Encode `input` bytes with full control over mode and hint.
///
/// This is the primary low-level entry point.  [`encode`] and [`encode_with`]
/// delegate here with `hint = EncodingHint::Default`.
pub fn encode_full(input: &[u8], options: EncodeOptions) -> Result<Vec<u8>, ScteError> {
    if input.len() > MAX_DECOMPRESSED_SIZE {
        return Err(ScteError::InputTooLarge(input.len()));
    }
    match options.mode {
        EncodingMode::Raw        => encode_passthrough(input),
        EncodingMode::Structured => encode_structured_hint(input, options.hint),
    }
}

pub fn encode_with(input: &[u8], mode: EncodingMode) -> Result<Vec<u8>, ScteError> {
    encode_full(input, EncodeOptions { mode, hint: EncodingHint::Default })
}

/// Encode `input` bytes into a SCTE container using [`EncodingMode::Structured`].
///
/// # Dispatch
/// - **JSON input** (`{…}` or `[…]`): full Phase 2-7 pipeline.
/// - **All other input**: passthrough — bytes stored verbatim.
///
/// For byte-exact reconstruction of JSON use [`encode_with`] with
/// [`EncodingMode::Raw`].
///
/// # Errors
/// - `InputTooLarge` — input exceeds `MAX_DECOMPRESSED_SIZE` (4 GiB)
pub fn encode(input: &[u8]) -> Result<Vec<u8>, ScteError> {
    encode_full(input, EncodeOptions::default())
}

fn encode_structured_hint(input: &[u8], hint: EncodingHint) -> Result<Vec<u8>, ScteError> {
    let _ = hint; // Fast-path branching wired in per-feature as they are added.
    encode_structured(input)
}

fn encode_structured(input: &[u8]) -> Result<Vec<u8>, ScteError> {
    if looks_like_json(input) {
        // `looks_like_json` is a heuristic (first byte is `{` or `[`).
        // Two silent fall-through cases:
        //   1. The content is invalid JSON (e.g. a log starting with `[ts]`).
        //   2. The pipeline overhead exceeds the gain — this happens for small
        //      payloads where schema + section table cost > compression savings.
        //      In that case passthrough is always smaller and byte-exact.
        match encode_json(input) {
            Ok(v) if v.len() < input.len() => return Ok(v),
            Ok(_) => { /* pipeline inflated — fall through to passthrough */ }
            Err(_) => { /* not actually JSON — fall through to passthrough */ }
        }
    }
    encode_passthrough(input)
}

// ── JSON path ─────────────────────────────────────────────────────────────────

/// Returns `true` if the first non-whitespace byte is `{` or `[`.
fn looks_like_json(input: &[u8]) -> bool {
    let first = input.iter().find(|&&b| !b.is_ascii_whitespace());
    matches!(first, Some(b'{') | Some(b'['))
}

fn encode_json(input: &[u8]) -> Result<Vec<u8>, ScteError> {
    // Tokenize once.  Both the columnar-path check and the two-pass fallback
    // consume the same token stream, eliminating the double (or triple) parse
    // that the old detect_homogeneous_array + encode_columnar / encode_json_two_pass
    // pattern incurred on every call.
    let tokens = tokenize_json(input)
        .map_err(|e| ScteError::EncodeError(format!("tokenize: {e}")))?;

    // Try columnar path first (Array<Object> with uniform schema).
    // Returns one or more chunks; large arrays (≥ COLUMNAR_CHUNK_ROWS) are split
    // into separate sections for parallel decode and partial access.
    if let Some(chunks) = try_encode_columnar_chunks_from_tokens(&tokens) {
        return assemble_columnar_container(input.len(), &chunks);
    }

    // Fall back to row-major two-pass pipeline using the pre-parsed tokens.
    let out = encode_json_two_pass_with_tokens(&tokens, 2)?;
    assemble_text_container(input.len(), &out)
}

// ── Columnar path ────────────────────────────────────────────────────────────

/// Assemble a SCTE container for `PipelineId::Text` carrying one or more
/// COLUMNAR sections (type 0x09).
///
/// For single-chunk inputs the layout is identical to the original v1 format
/// (1 section, no meta bytes).  For multi-chunk inputs each `SectionEntry`
/// carries an 8-byte meta field `[row_start: u32 LE][row_end: u32 LE]` that
/// enables parallel decode and partial data access.
pub(crate) fn assemble_columnar_container(
    original_len: usize,
    chunks: &[(u32, u32, Vec<u8>)],
) -> Result<Vec<u8>, ScteError> {
    let section_count = chunks.len() as u16;
    let multi         = section_count > 1;

    // Each section entry is 24 bytes fixed + optional 8-byte meta (multi-chunk).
    let meta_per_entry: usize = if multi { 8 } else { 0 };
    let entry_size    = SECTION_ENTRY_FIXED_SIZE + meta_per_entry;
    let section_tbl   = entry_size * section_count as usize;
    let header_size   = HEADER_SIZE + section_tbl;

    let total_payload: usize = chunks.iter().map(|(_, _, b)| b.len()).sum();
    let mut result = Vec::with_capacity(header_size + total_payload);

    let header = ScteHeader::new(PipelineId::Text, original_len as u64, section_count);
    result.extend_from_slice(&header.write());

    // Section entries — compute absolute payload offsets.
    let mut offset: u64 = header_size as u64;
    for (row_start, row_end, bytes) in chunks {
        let mut entry = SectionEntry::new(
            SectionType::Columnar, SectionCodec::None, offset, bytes,
        );
        if multi {
            let mut meta = [0u8; 8];
            meta[0..4].copy_from_slice(&row_start.to_le_bytes());
            meta[4..8].copy_from_slice(&row_end.to_le_bytes());
            entry.meta = meta.to_vec();
        }
        result.extend_from_slice(&entry.write());
        offset += bytes.len() as u64;
    }
    // Payload data.
    for (_, _, bytes) in chunks {
        result.extend_from_slice(bytes);
    }
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
    // Use the multi-stream TOKENS_RANS section when available; it is always
    // present (encode_json_two_pass_with_tokens falls back to token_bytes on
    // encode failure, so tokens_rans_bytes is never empty).
    let token_payload = &out.tokens_rans_bytes;
    let token_section_type = SectionType::TokensRans;

    let section_count: u16 = if has_delta { 4 } else { 3 };
    let section_tbl   = SECTION_ENTRY_FIXED_SIZE * section_count as usize;
    let header_size   = HEADER_SIZE + section_tbl;

    // Absolute byte offsets for each section payload.
    let schema_off: u64 = header_size as u64;
    let dict_off:   u64 = schema_off + out.schema_bytes.len() as u64;
    let tokens_off: u64 = dict_off   + dict_bytes.len() as u64;
    let delta_off:  u64 = tokens_off + token_payload.len() as u64;

    let schema_sec = SectionEntry::new(SectionType::Schema,   SectionCodec::None, schema_off, &out.schema_bytes);
    let dict_sec   = SectionEntry::new(SectionType::Dict,     SectionCodec::None, dict_off,   &dict_bytes);
    let tokens_sec = SectionEntry::new(token_section_type,    SectionCodec::None, tokens_off, token_payload);

    let header = ScteHeader::new(PipelineId::Text, original_len as u64, section_count);

    let payload_len = out.schema_bytes.len()
        + dict_bytes.len()
        + token_payload.len()
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
    result.extend_from_slice(token_payload);
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
        // Use enough rows that the pipeline overhead is smaller than the gain.
        // 50 uniform rows compress well; a 2-row array would inflate and
        // correctly fall back to passthrough.
        let records: String = (0..50)
            .map(|i| {
                let s = if i % 2 == 0 { "ok" } else { "fail" };
                format!(r#"{{"id":{i},"status":"{s}"}}"#)
            })
            .collect::<Vec<_>>()
            .join(",");
        let json = format!("[{records}]").into_bytes();
        let out  = encode(&json).unwrap();
        assert_eq!(&out[0..4], b"SCTE");
        // Pipeline ID byte is at offset 6 in the header; 0x01 = Text
        assert_eq!(out[6], 0x01, "expected PipelineId::Text for JSON input");
    }

    #[test]
    fn small_json_falls_back_to_passthrough() {
        // A tiny JSON object has more overhead than gain → must not inflate.
        let json = br#"{"name":"Alice","age":30,"city":"Jakarta"}"#;
        let out  = encode(json).unwrap();
        assert!(
            out.len() <= json.len() + HEADER_SIZE + SECTION_ENTRY_FIXED_SIZE,
            "small JSON ({} B input) should not inflate beyond passthrough size, got {} B",
            json.len(), out.len()
        );
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

