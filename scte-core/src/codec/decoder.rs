use crate::{
    container::{
        header::{ScteHeader, HEADER_SIZE},
        section::SectionEntry,
    },
    error::ScteError,
    pipelines::text::{
        Dictionary,
        decode_token_stream,
        decode_token_stream_rans,
        tokens_to_json,
        decode_columnar,
    },
    schema::serializer as schema_ser,
    types::{PipelineId, SectionCodec, SectionType, MAX_DECOMPRESSED_SIZE},
};

// ── Public entry point ────────────────────────────────────────────────────────

/// Decode a SCTE container back to the original bytes.
///
/// # Supported pipelines
/// - `PipelineId::Text` (0x01) — JSON pipeline: reads SCHEMA + DICT + TOKENS
///   (+ optional DELTA) sections and reconstructs the original JSON bytes.
/// - `PipelineId::Passthrough` (0xFF) and all others — returns the raw DATA
///   section payload unchanged (Phase 1 behaviour).
///
/// # Validation steps (in order)
/// 1. Buffer long enough for header (24 bytes)
/// 2. Magic bytes == "SCTE"
/// 3. Format version == 0x01
/// 4. Header checksum valid
/// 5. `section_count` ≤ `MAX_SECTION_COUNT`
/// 6. `original_size` ≤ `MAX_DECOMPRESSED_SIZE`
/// 7. Section table entries parse without error
/// 8. Each accessed section payload checksum valid
///
/// # Errors
/// Returns a `ScteError` variant if any validation step fails.
pub fn decode(input: &[u8]) -> Result<Vec<u8>, ScteError> {
    if input.len() < HEADER_SIZE {
        return Err(ScteError::UnexpectedEof);
    }

    // Steps 1–5: parse and validate header.
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

    // Step 8: dispatch by pipeline.
    match header.pipeline_id {
        PipelineId::Text => decode_text(input, &sections),
        _                => decode_passthrough(input, &sections),
    }
}

// ── Text pipeline ─────────────────────────────────────────────────────────────

fn decode_text(input: &[u8], sections: &[SectionEntry]) -> Result<Vec<u8>, ScteError> {
    let mut schema_payload:      Option<&[u8]> = None;
    let mut dict_payload:         Option<&[u8]> = None;
    let mut token_payload:        Option<&[u8]> = None; // legacy TOKENS section
    let mut tokens_rans_payload:  Option<&[u8]> = None; // TOKENS_RANS section (preferred)
    let mut delta_payload:        &[u8]         = &[];
    // Collect all COLUMNAR sections (sorted by row_start for multi-chunk).
    let mut columnar_chunks: Vec<(u32, &[u8])> = Vec::new();

    for (idx, section) in sections.iter().enumerate() {
        let start = section.offset as usize;
        let end   = start
            .checked_add(section.length as usize)
            .ok_or(ScteError::UnexpectedEof)?;
        let payload = input.get(start..end).ok_or(ScteError::UnexpectedEof)?;
        section.verify_payload(payload, idx)?;

        match section.section_type {
            SectionType::Schema    => schema_payload      = Some(payload),
            SectionType::Dict      => dict_payload         = Some(payload),
            SectionType::Tokens    => token_payload        = Some(payload),
            SectionType::TokensRans => tokens_rans_payload = Some(payload),
            SectionType::Delta     => delta_payload        = payload,
            SectionType::Columnar => {
                // row_start is in the first 4 bytes of meta (if present).
                // For single-chunk files (no meta) we use 0.
                let row_start = if section.meta.len() >= 4 {
                    u32::from_le_bytes(section.meta[0..4].try_into().unwrap())
                } else {
                    0u32
                };
                columnar_chunks.push((row_start, payload));
            }
            _ => {}
        }
    }

    // Fast path: columnar-encoded Array<Object> (single or multi-chunk).
    if !columnar_chunks.is_empty() {
        // Sort by row_start to ensure correct order for multi-chunk files.
        columnar_chunks.sort_by_key(|&(r, _)| r);

        if columnar_chunks.len() == 1 {
            return decode_columnar(columnar_chunks[0].1);
        }

        // Multi-chunk: decode each chunk, strip outer `[`/`]`, stitch into one array.
        let mut out: Vec<u8> = Vec::new();
        out.push(b'[');
        let mut first = true;
        for (_, payload) in &columnar_chunks {
            let decoded = decode_columnar(payload)?;
            // Strip the outer `[` and `]` from each chunk's JSON array.
            let inner: &[u8] = if decoded.first() == Some(&b'[')
                && decoded.last()  == Some(&b']')
            {
                &decoded[1..decoded.len() - 1]
            } else {
                &decoded
            };
            if inner.is_empty() { continue; }
            if !first { out.push(b','); }
            out.extend_from_slice(inner);
            first = false;
        }
        out.push(b']');
        return Ok(out);
    }

    let schema_bytes = schema_payload
        .ok_or_else(|| ScteError::DecodeError("text: missing SCHEMA section".into()))?;
    let dict_bytes   = dict_payload
        .ok_or_else(|| ScteError::DecodeError("text: missing DICT section".into()))?;

    let schema = schema_ser::deserialize(schema_bytes)?;
    let dict   = Dictionary::deserialize(dict_bytes)?;

    // Prefer TOKENS_RANS (multi-stream) over legacy TOKENS.
    let tokens = if let Some(tb) = tokens_rans_payload {
        decode_token_stream_rans(tb, &dict, &schema, delta_payload)?
    } else {
        let tb = token_payload
            .ok_or_else(|| ScteError::DecodeError("text: missing TOKENS section".into()))?;
        decode_token_stream(tb, &dict, &schema, delta_payload)?
    };
    Ok(tokens_to_json(&tokens))
}

// ── Passthrough path ──────────────────────────────────────────────────────────

fn decode_passthrough(input: &[u8], sections: &[SectionEntry]) -> Result<Vec<u8>, ScteError> {
    for (idx, section) in sections.iter().enumerate() {
        if section.section_type == SectionType::Data && section.codec == SectionCodec::None {
            let start = section.offset as usize;
            let end   = start
                .checked_add(section.length as usize)
                .ok_or(ScteError::UnexpectedEof)?;
            let payload = input.get(start..end).ok_or(ScteError::UnexpectedEof)?;
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
        out[0] = 0x00;
        assert_eq!(decode(&out), Err(ScteError::InvalidMagic));
    }

    #[test]
    fn decode_rejects_corrupted_header_checksum() {
        let mut out = encode(b"test").unwrap();
        out[20] ^= 0xFF;
        assert_eq!(decode(&out), Err(ScteError::InvalidHeaderChecksum));
    }

    #[test]
    fn decode_empty_passthrough_payload() {
        let encoded = encode(b"").unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, b"");
    }

    #[test]
    fn passthrough_roundtrip() {
        let input   = b"binary \x00\x01\x02 data";
        let encoded = encode(input).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn json_roundtrip_simple_object() {
        // The decoded JSON is canonical (no extra whitespace), so compare
        // after canonicalization.
        use crate::pipelines::text::canonicalize_json;
        let original = br#"{"id": 1, "name": "Alice", "active": true}"#;
        let encoded = encode(original).unwrap();
        let decoded = decode(&encoded).unwrap();
        let canon_orig = canonicalize_json(original).unwrap();
        let canon_dec  = canonicalize_json(&decoded).unwrap();
        assert_eq!(canon_orig, canon_dec, "JSON roundtrip mismatch");
    }

    #[test]
    fn json_roundtrip_array_of_objects() {
        use crate::pipelines::text::canonicalize_json;
        let records: String = (0..50)
            .map(|i| {
                let s = if i % 2 == 0 { "ok" } else { "fail" };
                format!(r#"{{"id":{i},"status":"{s}","active":true}}"#)
            })
            .collect::<Vec<_>>()
            .join(",");
        let json    = format!("[{records}]").into_bytes();
        let encoded = encode(&json).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(canonicalize_json(&json).unwrap(), canonicalize_json(&decoded).unwrap());
    }
}

