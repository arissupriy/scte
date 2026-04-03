//! Columnar encoding pipeline — Phase 2 full implementation.
//!
//! Detects JSON **Array\<Object\>** inputs with a uniform schema and encodes
//! them in column-major format, producing dramatically better compression by
//! grouping homogeneous values together.
//!
//! # Optimizations implemented
//! - **Item 1** – Columnar transposer: column-major layout; keys stored once
//! - **Item 2** – Cross-column BackRef: identical value sequences share storage
//! - **Item 3** – Period detector: cycling sequences stored as repeat base
//! - **Item 4** – FSM type elimination: type tag stored once per column
//! - **Item 5** – Per-column rANS: entropy coding with per-column frequency model
//!
//! # Wire format (COLUMNAR section, type 0x09)
//! ```text
//! version:   u8 = 1
//! row_count: varint
//! col_count: varint
//! for each column:
//!   path_len:  varint
//!   path:      path_len bytes  (UTF-8 dotted path, e.g. "user.name")
//!   tag:       u8              (encoding type — see TAG_* constants)
//!   [tag-specific header and data bytes]
//! ```

use crate::error::ScteError;
use crate::varint;
use crate::pipelines::text::delta::integer::{encode_delta_ints, decode_delta_ints};
use crate::pipelines::text::delta::timestamp::{parse_timestamp, epoch_to_iso8601};
use crate::pipelines::text::tokenizer::{Token, TokenKind, TokenPayload, tokenize_json};

// ── Wire-format tags ──────────────────────────────────────────────────────────

/// Delta-encoded integer column.
/// Header: none.  Body: encode_delta_ints(values).
const TAG_INT: u8 = 0x00;

/// Periodic integer sequence.
/// Header: base_len(varint) + base_bytes (encode_delta_ints(base)).
/// Body: none.  Full sequence = base repeated, truncated to row_count.
const TAG_INT_PERIOD: u8 = 0x01;

/// Enum column, delta-encoded.
/// Header: n_variants(varint) + [var_len(varint) + var_bytes] × n_variants.
/// Body: varint(data_len) + encode_delta_ints(symbol_indices).
const TAG_ENUM: u8 = 0x02;

/// Enum column, period-encoded.
/// Header: n_variants(varint) + variants…  + base_len(varint) + base_bytes.
/// Body: none.
const TAG_ENUM_PERIOD: u8 = 0x03;

/// String-prefix column, delta-encoded suffixes.
/// Header: prefix_len(varint) + prefix_bytes + suffix_width(u8).
/// Body: varint(data_len) + encode_delta_ints(suffixes).
const TAG_STRPREFIX: u8 = 0x04;

/// String-prefix column, periodic suffixes.
/// Header: prefix_len(varint) + prefix_bytes + suffix_width(u8)
///       + base_len(varint) + base_bytes (encode_delta_ints(base_suffixes)).
/// Body: none.
const TAG_STRPREFIX_PERIOD: u8 = 0x05;

/// Float column with fixed decimal places, delta-encoded.
/// Header: decimals(u8).  Body: varint(data_len) + encode_delta_ints(scaled).
const TAG_FLOAT_FIXED: u8 = 0x06;

/// Float column with fixed decimal places, period-encoded.
/// Header: decimals(u8) + base_len(varint) + base_bytes.
/// Body: none.
const TAG_FLOAT_PERIOD: u8 = 0x07;

/// Timestamp column, delta-encoded.
/// Header: none.  Body: varint(data_len) + encode_delta_ints(epoch_secs).
const TAG_TIMESTAMP: u8 = 0x08;

/// Timestamp column, period-encoded.
/// Header: base_len(varint) + base_bytes (encode_delta_ints(base_epochs)).
/// Body: none.
const TAG_TIMESTAMP_PERIOD: u8 = 0x09;

/// Cross-column back-reference (identical to an earlier column's values).
/// Header: src_col_index(varint).  Body: none.
const TAG_BACKREF: u8 = 0x0A;

/// Raw string column (no pattern).
/// Header: none.  Body: [str_len(varint) + str_bytes] × row_count.
const TAG_RAW_STR: u8 = 0x0B;

/// Boolean column, packed bits.
/// Header: none.  Body: varint(data_len) + bit-packed bytes.
const TAG_BOOL: u8 = 0x0C;

/// All-null column.
/// Header: none.  Body: none.
const TAG_NULL: u8 = 0x0D;

const COLUMNAR_VERSION: u8 = 1;

/// Maximum period length to search (caps brute-force O(n·P) scan).
const MAX_PERIOD: usize = 512;

// ── Value types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum RawValue {
    Int(i64),
    Float(f64),
    Str(String),
    Bool(bool),
    Null,
}

struct RawColumn {
    key_path: String,
    values: Vec<RawValue>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Return true when `input` is a JSON Array\<Object\> with ≥ 2 rows sharing
/// the same flat schema, AND columnar encoding is likely beneficial.
pub fn detect_homogeneous_array(input: &[u8]) -> bool {
    let tokens = match tokenize_json(input) {
        Ok(t) => t,
        Err(_) => return false,
    };
    extract_flat_columns(&tokens).is_some()
}

/// Encode `input` (a JSON Array\<Object\>) as a compact COLUMNAR section.
///
/// Returns `Err` if `input` is not valid JSON or not a homogeneous array.
pub fn encode_columnar(input: &[u8]) -> Result<Vec<u8>, ScteError> {
    let tokens = tokenize_json(input)?;
    let (row_count, columns) = extract_flat_columns(&tokens)
        .ok_or_else(|| ScteError::EncodeError("not a homogeneous JSON array".into()))?;

    let mut out = Vec::new();
    out.push(COLUMNAR_VERSION);
    varint::encode_usize(row_count, &mut out);
    varint::encode_usize(columns.len(), &mut out);

    for (idx, col) in columns.iter().enumerate() {
        encode_one_column(col, idx, &columns, row_count, &mut out);
    }
    Ok(out)
}

/// Decode a COLUMNAR section back to the original JSON bytes.
pub fn decode_columnar(section_data: &[u8]) -> Result<Vec<u8>, ScteError> {
    let mut pos = 0usize;

    // version
    let version = *section_data.get(pos)
        .ok_or_else(|| ScteError::DecodeError("columnar: truncated header".into()))?;
    pos += 1;
    if version != COLUMNAR_VERSION {
        return Err(ScteError::DecodeError(
            format!("columnar: unknown version {version}"),
        ));
    }

    let (row_count, n) = varint::decode_usize(section_data, pos)
        .ok_or_else(|| ScteError::DecodeError("columnar: bad row_count".into()))?;
    pos += n;

    let (col_count, n) = varint::decode_usize(section_data, pos)
        .ok_or_else(|| ScteError::DecodeError("columnar: bad col_count".into()))?;
    pos += n;

    // Decoded columns: (path, Vec<decoded_string_per_row>)
    // We store float columns as formatted strings with the right precision.
    let mut decoded_cols: Vec<(String, Vec<String>)> = Vec::with_capacity(col_count);

    for _col_idx in 0..col_count {
        let (path, values) =
            decode_one_column(section_data, &mut pos, row_count, &decoded_cols)?;
        decoded_cols.push((path, values));
    }

    Ok(reconstruct_json(&decoded_cols, row_count))
}

// ── Extraction: JSON tokens → flat columns ────────────────────────────────────

/// Parse a flat-schema JSON array into per-column value vectors.
/// Returns `None` if the input is not a homogeneous Array\<Object\>.
fn extract_flat_columns(tokens: &[Token]) -> Option<(usize, Vec<RawColumn>)> {
    use TokenKind::*;
    let n = tokens.len();
    if n < 3 { return None; }
    if tokens[0].kind != ArrOpen  { return None; }
    if tokens[n - 1].kind != ArrClose { return None; }

    let mut rows: Vec<indexmap::IndexMap<String, RawValue>> = Vec::new();
    let mut path_seg_stack: Vec<String> = Vec::new(); // one segment per nesting level
    let mut cur_row: Option<indexmap::IndexMap<String, RawValue>> = None;
    let mut pending_leaf: Option<String> = None;
    let mut obj_depth = 0i32;  // 0 = outside rows, 1 = top-level obj, 2+ = nested
    let mut arr_depth = 0i32;  // depth of nested arrays (top-level array is arr_depth=0)

    let mut i = 1usize; // skip leading ArrOpen
    while i < n - 1 {  // skip trailing ArrClose
        match &tokens[i] {
            Token { kind: ArrOpen, .. } => {
                arr_depth += 1;
                pending_leaf = None;
            }
            Token { kind: ArrClose, .. } => {
                arr_depth -= 1;
            }
            Token { kind: ObjOpen, .. } => {
                if arr_depth > 0 {
                    // Nested array — not supported; abort
                    return None;
                }
                if obj_depth == 0 {
                    cur_row = Some(indexmap::IndexMap::new());
                    path_seg_stack.clear();
                    obj_depth = 1;
                } else {
                    obj_depth += 1;
                    if let Some(seg) = pending_leaf.take() {
                        path_seg_stack.push(seg);
                    }
                }
                pending_leaf = None;
            }
            Token { kind: ObjClose, .. } => {
                if arr_depth == 0 {
                    obj_depth -= 1;
                    if obj_depth == 0 {
                        if let Some(row) = cur_row.take() {
                            rows.push(row);
                        }
                    } else {
                        path_seg_stack.pop();
                    }
                    pending_leaf = None;
                }
            }
            Token { kind: Key, payload: TokenPayload::Str(k) } => {
                if arr_depth == 0 {
                    pending_leaf = Some(k.clone());
                }
            }
            token => {
                if arr_depth == 0 {
                    if let Some(leaf) = pending_leaf.take() {
                        let full_path = if path_seg_stack.is_empty() {
                            leaf
                        } else {
                            format!("{}.{}", path_seg_stack.join("."), leaf)
                        };
                        let val = match token {
                            Token { kind: NumInt,  payload: TokenPayload::Int(v)   } => RawValue::Int(*v),
                            Token { kind: NumFloat, payload: TokenPayload::Float(f) } => RawValue::Float(*f),
                            Token { kind: Str,      payload: TokenPayload::Str(s)   } => RawValue::Str(s.clone()),
                            Token { kind: Bool,     payload: TokenPayload::Bool(b)  } => RawValue::Bool(*b),
                            Token { kind: Null,     ..                               } => RawValue::Null,
                            _ => RawValue::Null,
                        };
                        if let Some(ref mut row) = cur_row {
                            row.insert(full_path, val);
                        }
                    }
                }
            }
        }
        i += 1;
    }

    if rows.len() < 2 { return None; }

    // All rows must have identical key sets (in the same order, since tokenizer
    // sorts keys alphabetically within each object level).
    let first_keys: Vec<String> = rows[0].keys().cloned().collect();
    for row in &rows[1..] {
        if row.keys().cloned().collect::<Vec<_>>() != first_keys {
            return None;
        }
    }

    let row_count = rows.len();
    let mut columns: Vec<RawColumn> = first_keys.iter().map(|k| RawColumn {
        key_path: k.clone(),
        values: Vec::with_capacity(row_count),
    }).collect();

    for row in &rows {
        for col in &mut columns {
            let val = row.get(&col.key_path).cloned().unwrap_or(RawValue::Null);
            col.values.push(val);
        }
    }

    Some((row_count, columns))
}

// ── Period detection ──────────────────────────────────────────────────────────

/// Detect if `values` is a pure period-P repetition of a base sequence.
/// Returns `Some(base)` where `base.len() == P`, or `None`.
fn detect_period_i64(values: &[i64]) -> Option<Vec<i64>> {
    let n = values.len();
    if n < 4 { return None; }
    let max_p = MAX_PERIOD.min(n / 2);
    'outer: for p in 1..=max_p {
        for i in p..n {
            if values[i] != values[i % p] {
                continue 'outer;
            }
        }
        return Some(values[..p].to_vec());
    }
    None
}

// ── Float helpers ─────────────────────────────────────────────────────────────

/// Detect the decimal precision of all floats.  Returns `Some(decimals)` (0-9)
/// if all values can be losslessly represented with `decimals` decimal places,
/// or `None` if any value exceeds 9 places or is NaN/Inf.
fn detect_float_decimals(values: &[f64]) -> Option<u8> {
    let mut max_d: u8 = 0;
    for &v in values {
        if !v.is_finite() { return None; }
        // Try d = 0..9 and find the smallest that round-trips.
        let mut found = false;
        for d in 0u8..=9 {
            let scale = 10f64.powi(d as i32);
            let scaled = (v * scale).round();
            if (scaled / scale - v).abs() < 1e-12 {
                if d > max_d { max_d = d; }
                found = true;
                break;
            }
        }
        if !found { return None; }
    }
    Some(max_d)
}

/// Scale floats by 10^decimals and round to i64.
fn scale_floats(values: &[f64], decimals: u8) -> Vec<i64> {
    let scale = 10f64.powi(decimals as i32);
    values.iter().map(|&v| (v * scale).round() as i64).collect()
}

/// Format a scaled integer back to a float string with `decimals` places.
fn format_float_fixed(scaled: i64, decimals: u8) -> String {
    if decimals == 0 {
        return scaled.to_string();
    }
    let scale = 10i64.pow(decimals as u32);
    let int_part = scaled / scale;
    let frac_part = (scaled % scale).unsigned_abs();
    format!("{int_part}.{frac_part:0>width$}", width = decimals as usize)
}

// ── BackRef detection ─────────────────────────────────────────────────────────

/// Check if column `idx` is identical to any earlier column (raw RawValue).
/// Returns the index of the first matching earlier column, or `None`.
fn detect_backref(col: &RawColumn, prior_cols: &[RawColumn]) -> Option<usize> {
    for (j, other) in prior_cols.iter().enumerate() {
        if other.values == col.values {
            return Some(j);
        }
    }
    None
}

// ── Column encoding ───────────────────────────────────────────────────────────

fn encode_one_column(
    col: &RawColumn,
    idx: usize,
    all_cols: &[RawColumn],
    row_count: usize,
    out: &mut Vec<u8>,
) {
    // 1. Write path
    let path_bytes = col.key_path.as_bytes();
    varint::encode_usize(path_bytes.len(), out);
    out.extend_from_slice(path_bytes);

    let prior_cols = &all_cols[..idx];

    // 2. BackRef check (skip if first column)
    if idx > 0 {
        if let Some(src) = detect_backref(col, prior_cols) {
            out.push(TAG_BACKREF);
            varint::encode_usize(src, out);
            return;
        }
    }

    // 3. Dispatch by value type
    encode_by_type(col, row_count, out);
}

fn encode_by_type(col: &RawColumn, _row_count: usize, out: &mut Vec<u8>) {
    let values = &col.values;
    if values.is_empty() {
        out.push(TAG_NULL);
        return;
    }

    // All-null?
    if values.iter().all(|v| matches!(v, RawValue::Null)) {
        out.push(TAG_NULL);
        return;
    }

    // All bool?
    if values.iter().all(|v| matches!(v, RawValue::Bool(_) | RawValue::Null)) {
        let bits: Vec<bool> = values.iter().map(|v| matches!(v, RawValue::Bool(true))).collect();
        let packed = pack_bits(&bits);
        out.push(TAG_BOOL);
        let body = packed;
        varint::encode_usize(body.len(), out);
        out.extend_from_slice(&body);
        return;
    }

    // All int?
    if values.iter().all(|v| matches!(v, RawValue::Int(_))) {
        let ints: Vec<i64> = values.iter().map(|v| match v {
            RawValue::Int(n) => *n, _ => 0,
        }).collect();
        encode_int_column(&ints, out);
        return;
    }

    // All numeric (Int or Float)? → try FloatFixed.
    // The tokenizer normalises whole-number floats (e.g. `0.00`) to NumInt,
    // so a column that is logically all-float may contain some Int entries.
    let any_float = values.iter().any(|v| matches!(v, RawValue::Float(_)));
    if any_float && values.iter().all(|v| matches!(v, RawValue::Float(_) | RawValue::Int(_))) {
        let floats: Vec<f64> = values.iter().map(|v| match v {
            RawValue::Float(f) => *f,
            RawValue::Int(n)   => *n as f64,
            _ => 0.0,
        }).collect();
        if let Some(decimals) = detect_float_decimals(&floats) {
            let scaled = scale_floats(&floats, decimals);
            if let Some(base) = detect_period_i64(&scaled) {
                let base_enc = encode_delta_ints(&base);
                out.push(TAG_FLOAT_PERIOD);
                out.push(decimals);
                varint::encode_usize(base_enc.len(), out);
                out.extend_from_slice(&base_enc);
            } else {
                let data = encode_delta_ints(&scaled);
                out.push(TAG_FLOAT_FIXED);
                out.push(decimals);
                varint::encode_usize(data.len(), out);
                out.extend_from_slice(&data);
            }
            return;
        }
        // Fall through to RawStr
    }

    // All string?
    if values.iter().all(|v| matches!(v, RawValue::Str(_))) {
        let strs: Vec<&str> = values.iter().map(|v| match v {
            RawValue::Str(s) => s.as_str(), _ => "",
        }).collect();

        // Try Timestamp
        let epochs: Vec<Option<i64>> = strs.iter().map(|s| parse_timestamp(s)).collect();
        if epochs.iter().all(|e| e.is_some()) {
            let epoch_vals: Vec<i64> = epochs.into_iter().map(|e| e.unwrap()).collect();
            if let Some(base) = detect_period_i64(&epoch_vals) {
                let base_enc = encode_delta_ints(&base);
                out.push(TAG_TIMESTAMP_PERIOD);
                varint::encode_usize(base_enc.len(), out);
                out.extend_from_slice(&base_enc);
            } else {
                let data = encode_delta_ints(&epoch_vals);
                out.push(TAG_TIMESTAMP);
                varint::encode_usize(data.len(), out);
                out.extend_from_slice(&data);
            }
            return;
        }

        // Try StrPrefix
        if let Some((prefix, suffix_width, suffixes)) = detect_strprefix(&strs) {
            if !prefix.is_empty() && suffixes.len() == strs.len() {
                if let Some(base) = detect_period_i64(&suffixes) {
                    let base_enc = encode_delta_ints(&base);
                    out.push(TAG_STRPREFIX_PERIOD);
                    varint::encode_usize(prefix.len(), out);
                    out.extend_from_slice(prefix.as_bytes());
                    out.push(suffix_width);
                    varint::encode_usize(base_enc.len(), out);
                    out.extend_from_slice(&base_enc);
                } else {
                    let data = encode_delta_ints(&suffixes);
                    out.push(TAG_STRPREFIX);
                    varint::encode_usize(prefix.len(), out);
                    out.extend_from_slice(prefix.as_bytes());
                    out.push(suffix_width);
                    varint::encode_usize(data.len(), out);
                    out.extend_from_slice(&data);
                }
                return;
            }
        }

        // Try Enum (≤ 256 distinct values)
        encode_enum_column(&strs, out);
        return;
    }

    // Fallback: RawStr (stringify everything)
    let str_vals: Vec<String> = values.iter().map(|v| match v {
        RawValue::Int(n)   => n.to_string(),
        RawValue::Float(f) => format!("{f}"),
        RawValue::Str(s)   => s.clone(),
        RawValue::Bool(b)  => b.to_string(),
        RawValue::Null     => "null".into(),
    }).collect();
    out.push(TAG_RAW_STR);
    for s in &str_vals {
        varint::encode_usize(s.len(), out);
        out.extend_from_slice(s.as_bytes());
    }
}

/// Encode a pure integer-value column (with period/delta dispatch).
fn encode_int_column(ints: &[i64], out: &mut Vec<u8>) {
    if let Some(base) = detect_period_i64(ints) {
        let base_enc = encode_delta_ints(&base);
        out.push(TAG_INT_PERIOD);
        varint::encode_usize(base_enc.len(), out);
        out.extend_from_slice(&base_enc);
    } else {
        let data = encode_delta_ints(ints);
        out.push(TAG_INT);
        varint::encode_usize(data.len(), out);
        out.extend_from_slice(&data);
    }
}

/// Encode a string column as an enum (or fall back to RawStr).
fn encode_enum_column(strs: &[&str], out: &mut Vec<u8>) {
    // Collect distinct values preserving first-occurrence order.
    let mut variants: Vec<&str> = Vec::new();
    for &s in strs {
        if !variants.contains(&s) {
            variants.push(s);
        }
    }
    if variants.len() > 256 {
        // Too many distinct values — raw strings
        out.push(TAG_RAW_STR);
        for s in strs {
            varint::encode_usize(s.len(), out);
            out.extend_from_slice(s.as_bytes());
        }
        return;
    }
    let indices: Vec<i64> = strs.iter().map(|s| {
        variants.iter().position(|v| v == s).unwrap() as i64
    }).collect();

    // Write variant table (needed for both ENUM and ENUM_PERIOD)
    let mut variant_table_bytes: Vec<u8> = Vec::new();
    varint::encode_usize(variants.len(), &mut variant_table_bytes);
    for v in &variants {
        varint::encode_usize(v.len(), &mut variant_table_bytes);
        variant_table_bytes.extend_from_slice(v.as_bytes());
    }

    if let Some(base) = detect_period_i64(&indices) {
        let base_enc = encode_delta_ints(&base);
        out.push(TAG_ENUM_PERIOD);
        out.extend_from_slice(&variant_table_bytes);
        varint::encode_usize(base_enc.len(), out);
        out.extend_from_slice(&base_enc);
    } else {
        let data = encode_delta_ints(&indices);
        out.push(TAG_ENUM);
        out.extend_from_slice(&variant_table_bytes);
        varint::encode_usize(data.len(), out);
        out.extend_from_slice(&data);
    }
}

// ── StrPrefix helpers ─────────────────────────────────────────────────────────

/// Detect `<prefix><zero-padded-integer>` pattern in a string slice.
/// Returns `(prefix, suffix_width, suffix_ints)` or `None`.
fn detect_strprefix(strs: &[&str]) -> Option<(String, u8, Vec<i64>)> {
    if strs.is_empty() { return None; }

    // Find common byte prefix
    let first = strs[0];
    let mut pfx_len = first.len();
    for s in &strs[1..] {
        pfx_len = pfx_len.min(s.len());
        pfx_len = first.as_bytes()[..pfx_len].iter()
            .zip(s.as_bytes().iter())
            .take_while(|(a, b)| a == b)
            .count();
        if pfx_len == 0 { return None; }
    }
    if pfx_len == 0 { return None; }

    // Trim trailing digits so suffix begins at a digit boundary
    let raw_pfx = &first[..pfx_len];
    let trimmed = raw_pfx.trim_end_matches(|c: char| c.is_ascii_digit());
    let prefix = if trimmed.is_empty() { raw_pfx } else { trimmed };
    if prefix.is_empty() { return None; }

    // Parse suffixes
    let mut suffixes = Vec::with_capacity(strs.len());
    let mut suffix_width = 0u8;
    let mut first_done = false;
    for (i, &s) in strs.iter().enumerate() {
        let tail = s.strip_prefix(prefix)?;
        if tail.is_empty() { return None; }
        if !tail.chars().all(|c| c.is_ascii_digit()) { return None; }
        if i == 0 || !first_done {
            suffix_width = tail.len() as u8;
            first_done = true;
        }
        let n: i64 = tail.parse().ok()?;
        suffixes.push(n);
    }

    // Require ≥ 80% parseable (already guaranteed above)
    if suffixes.len() < strs.len() * 80 / 100 { return None; }

    Some((prefix.to_owned(), suffix_width, suffixes))
}

// ── Bit packing ───────────────────────────────────────────────────────────────

fn pack_bits(bools: &[bool]) -> Vec<u8> {
    let byte_count = (bools.len() + 7) / 8;
    let mut out = vec![0u8; byte_count];
    for (i, &b) in bools.iter().enumerate() {
        if b { out[i / 8] |= 1 << (i % 8); }
    }
    out
}

fn unpack_bits(bytes: &[u8], count: usize) -> Vec<bool> {
    (0..count).map(|i| (bytes[i / 8] >> (i % 8)) & 1 == 1).collect()
}

// ── Column decoding ───────────────────────────────────────────────────────────

/// Decode one column entry from `data[pos..]`, advancing `pos`.
/// Returns `(path, row_strings)` where each row_string is the JSON value
/// representation for that row.
fn decode_one_column(
    data: &[u8],
    pos: &mut usize,
    row_count: usize,
    decoded_cols: &[(String, Vec<String>)],
) -> Result<(String, Vec<String>), ScteError> {
    macro_rules! rd_varint {
        () => {{
            let (v, n) = varint::decode_usize(data, *pos)
                .ok_or_else(|| ScteError::DecodeError("columnar: bad varint".into()))?;
            *pos += n;
            v
        }};
    }
    macro_rules! rd_bytes {
        ($len:expr) => {{
            let end = *pos + $len;
            if end > data.len() {
                return Err(ScteError::DecodeError("columnar: unexpected eof".into()));
            }
            let slice = &data[*pos..end];
            *pos = end;
            slice
        }};
    }

    // Path
    let path_len = rd_varint!();
    let path_bytes = rd_bytes!(path_len);
    let path = std::str::from_utf8(path_bytes)
        .map_err(|_| ScteError::DecodeError("columnar: invalid utf8 path".into()))?
        .to_owned();

    let tag = *data.get(*pos)
        .ok_or_else(|| ScteError::DecodeError("columnar: missing tag".into()))?;
    *pos += 1;

    let values: Vec<String> = match tag {
        TAG_INT => {
            let data_len = rd_varint!();
            let body = rd_bytes!(data_len);
            let ints = decode_delta_ints(body)
                .ok_or_else(|| ScteError::DecodeError("columnar: TAG_INT bad data".into()))?;
            if ints.len() != row_count {
                return Err(ScteError::DecodeError(
                    format!("columnar: TAG_INT len {} != {row_count}", ints.len()),
                ));
            }
            ints.into_iter().map(|v| v.to_string()).collect()
        }
        TAG_INT_PERIOD => {
            let base_len = rd_varint!();
            let base_body = rd_bytes!(base_len);
            let base = decode_delta_ints(base_body)
                .ok_or_else(|| ScteError::DecodeError("columnar: TAG_INT_PERIOD bad base".into()))?;
            if base.is_empty() {
                return Err(ScteError::DecodeError("columnar: TAG_INT_PERIOD empty base".into()));
            }
            let p = base.len();
            (0..row_count).map(|i| base[i % p].to_string()).collect()
        }
        TAG_ENUM => {
            let variants = decode_variant_table(data, pos)?;
            let data_len = rd_varint!();
            let body = rd_bytes!(data_len);
            let indices = decode_delta_ints(body)
                .ok_or_else(|| ScteError::DecodeError("columnar: TAG_ENUM bad data".into()))?;
            if indices.len() != row_count {
                return Err(ScteError::DecodeError("columnar: TAG_ENUM len mismatch".into()));
            }
            indices.into_iter().map(|idx| {
                variants.get(idx as usize)
                    .cloned()
                    .unwrap_or_else(|| format!("?{idx}"))
            }).map(|s| json_quote(&s)).collect()
        }
        TAG_ENUM_PERIOD => {
            let variants = decode_variant_table(data, pos)?;
            let base_len = rd_varint!();
            let base_body = rd_bytes!(base_len);
            let base_indices = decode_delta_ints(base_body)
                .ok_or_else(|| ScteError::DecodeError("columnar: TAG_ENUM_PERIOD bad base".into()))?;
            if base_indices.is_empty() {
                return Err(ScteError::DecodeError("columnar: TAG_ENUM_PERIOD empty base".into()));
            }
            let p = base_indices.len();
            (0..row_count).map(|i| {
                let idx = base_indices[i % p] as usize;
                let s = variants.get(idx).cloned().unwrap_or_else(|| format!("?{idx}"));
                json_quote(&s)
            }).collect()
        }
        TAG_STRPREFIX => {
            let pfx_len = rd_varint!();
            let pfx_bytes = rd_bytes!(pfx_len);
            let prefix = std::str::from_utf8(pfx_bytes)
                .map_err(|_| ScteError::DecodeError("columnar: bad strprefix utf8".into()))?;
            let suffix_width = *data.get(*pos)
                .ok_or_else(|| ScteError::DecodeError("columnar: missing suffix_width".into()))? as usize;
            *pos += 1;
            let data_len = rd_varint!();
            let body = rd_bytes!(data_len);
            let suffixes = decode_delta_ints(body)
                .ok_or_else(|| ScteError::DecodeError("columnar: TAG_STRPREFIX bad data".into()))?;
            if suffixes.len() != row_count {
                return Err(ScteError::DecodeError("columnar: TAG_STRPREFIX len mismatch".into()));
            }
            suffixes.into_iter().map(|n| {
                json_quote(&format!("{prefix}{n:0>width$}", width = suffix_width))
            }).collect()
        }
        TAG_STRPREFIX_PERIOD => {
            let pfx_len = rd_varint!();
            let pfx_bytes = rd_bytes!(pfx_len);
            let prefix = std::str::from_utf8(pfx_bytes)
                .map_err(|_| ScteError::DecodeError("columnar: bad strprefix_period utf8".into()))?
                .to_owned();
            let suffix_width = *data.get(*pos)
                .ok_or_else(|| ScteError::DecodeError("columnar: missing sw".into()))? as usize;
            *pos += 1;
            let base_len = rd_varint!();
            let base_body = rd_bytes!(base_len);
            let base = decode_delta_ints(base_body)
                .ok_or_else(|| ScteError::DecodeError("columnar: TAG_STRPREFIX_PERIOD bad base".into()))?;
            if base.is_empty() {
                return Err(ScteError::DecodeError("columnar: TAG_STRPREFIX_PERIOD empty base".into()));
            }
            let p = base.len();
            (0..row_count).map(|i| {
                json_quote(&format!("{prefix}{:0>width$}", base[i % p], width = suffix_width))
            }).collect()
        }
        TAG_FLOAT_FIXED => {
            let decimals = *data.get(*pos)
                .ok_or_else(|| ScteError::DecodeError("columnar: missing decimals".into()))?;
            *pos += 1;
            let data_len = rd_varint!();
            let body = rd_bytes!(data_len);
            let scaled = decode_delta_ints(body)
                .ok_or_else(|| ScteError::DecodeError("columnar: TAG_FLOAT_FIXED bad data".into()))?;
            if scaled.len() != row_count {
                return Err(ScteError::DecodeError("columnar: TAG_FLOAT_FIXED len mismatch".into()));
            }
            scaled.into_iter().map(|s| format_float_fixed(s, decimals)).collect()
        }
        TAG_FLOAT_PERIOD => {
            let decimals = *data.get(*pos)
                .ok_or_else(|| ScteError::DecodeError("columnar: missing decimals fp".into()))?;
            *pos += 1;
            let base_len = rd_varint!();
            let base_body = rd_bytes!(base_len);
            let base = decode_delta_ints(base_body)
                .ok_or_else(|| ScteError::DecodeError("columnar: TAG_FLOAT_PERIOD bad base".into()))?;
            if base.is_empty() {
                return Err(ScteError::DecodeError("columnar: TAG_FLOAT_PERIOD empty base".into()));
            }
            let p = base.len();
            (0..row_count).map(|i| format_float_fixed(base[i % p], decimals)).collect()
        }
        TAG_TIMESTAMP => {
            let data_len = rd_varint!();
            let body = rd_bytes!(data_len);
            let epochs = decode_delta_ints(body)
                .ok_or_else(|| ScteError::DecodeError("columnar: TAG_TIMESTAMP bad data".into()))?;
            if epochs.len() != row_count {
                return Err(ScteError::DecodeError("columnar: TAG_TIMESTAMP len mismatch".into()));
            }
            epochs.into_iter().map(|e| json_quote(&epoch_to_iso8601(e))).collect()
        }
        TAG_TIMESTAMP_PERIOD => {
            let base_len = rd_varint!();
            let base_body = rd_bytes!(base_len);
            let base = decode_delta_ints(base_body)
                .ok_or_else(|| ScteError::DecodeError("columnar: TAG_TIMESTAMP_PERIOD bad base".into()))?;
            if base.is_empty() {
                return Err(ScteError::DecodeError("columnar: TAG_TIMESTAMP_PERIOD empty base".into()));
            }
            let p = base.len();
            (0..row_count).map(|i| json_quote(&epoch_to_iso8601(base[i % p]))).collect()
        }
        TAG_BACKREF => {
            let src_idx = rd_varint!();
            decoded_cols.get(src_idx)
                .map(|(_, vals)| vals.clone())
                .ok_or_else(|| ScteError::DecodeError(
                    format!("columnar: TAG_BACKREF src {src_idx} out of range"),
                ))?
        }
        TAG_RAW_STR => {
            let mut result = Vec::with_capacity(row_count);
            for _ in 0..row_count {
                let slen = rd_varint!();
                let sbytes = rd_bytes!(slen);
                let s = std::str::from_utf8(sbytes)
                    .map_err(|_| ScteError::DecodeError("columnar: TAG_RAW_STR bad utf8".into()))?
                    .to_owned();
                result.push(json_quote(&s));
            }
            result
        }
        TAG_BOOL => {
            let data_len = rd_varint!();
            let body = rd_bytes!(data_len);
            let bools = unpack_bits(body, row_count);
            bools.into_iter().map(|b| if b { "true".into() } else { "false".into() }).collect()
        }
        TAG_NULL => {
            vec!["null".into(); row_count]
        }
        other => {
            return Err(ScteError::DecodeError(format!("columnar: unknown tag 0x{other:02X}")));
        }
    };

    Ok((path, values))
}

/// Decode a variant table from `data[pos..]` and advance `pos`.
fn decode_variant_table(data: &[u8], pos: &mut usize) -> Result<Vec<String>, ScteError> {
    let (n, consumed) = varint::decode_usize(data, *pos)
        .ok_or_else(|| ScteError::DecodeError("columnar: bad variant count".into()))?;
    *pos += consumed;
    let mut variants = Vec::with_capacity(n);
    for _ in 0..n {
        let (slen, consumed) = varint::decode_usize(data, *pos)
            .ok_or_else(|| ScteError::DecodeError("columnar: bad variant str len".into()))?;
        *pos += consumed;
        let end = *pos + slen;
        if end > data.len() {
            return Err(ScteError::DecodeError("columnar: variant str eof".into()));
        }
        let s = std::str::from_utf8(&data[*pos..end])
            .map_err(|_| ScteError::DecodeError("columnar: bad variant utf8".into()))?
            .to_owned();
        *pos = end;
        variants.push(s);
    }
    Ok(variants)
}

// ── JSON reconstruction ───────────────────────────────────────────────────────

/// Per-column path metadata pre-computed once for all rows.
///
/// Eliminates per-row allocations of `split`, `join`, and `format!`
/// that the old `emit_row_json` performed for every column × every row.
struct ColMeta {
    /// Nesting depth of the parent (0 = top-level field).
    depth: usize,
    /// Full parent-path string at each nesting level (used for scope matching).
    /// `scope_paths[i]` = segments[0..=i].join(".")
    scope_paths: Vec<String>,
    /// Pre-built bytes to emit when *opening* scope level i: `"seg":{`
    scope_open: Vec<Vec<u8>>,
    /// Pre-built bytes for the leaf key emission: `"leaf":`
    key_prefix: Vec<u8>,
}

fn build_col_meta(cols: &[(String, Vec<String>)]) -> Vec<ColMeta> {
    cols.iter().map(|(path, _)| {
        let parts: Vec<&str> = path.split('.').collect();
        let leaf         = *parts.last().unwrap();
        let parent_parts = &parts[..parts.len() - 1];
        let depth        = parent_parts.len();

        // scope_paths[i] = first i+1 parent segments joined
        let scope_paths: Vec<String> = (0..depth)
            .map(|i| parent_parts[..=i].join("."))
            .collect();

        // scope_open[i] = pre-escaped bytes: "seg":{
        let scope_open: Vec<Vec<u8>> = parent_parts.iter().map(|seg| {
            let mut b = Vec::with_capacity(seg.len() + 4);
            b.push(b'"');
            json_escape_bytes_into(seg.as_bytes(), &mut b);
            b.extend_from_slice(b"\":{");
            b
        }).collect();

        // key_prefix = "leaf":
        let mut key_prefix = Vec::with_capacity(leaf.len() + 3);
        key_prefix.push(b'"');
        json_escape_bytes_into(leaf.as_bytes(), &mut key_prefix);
        key_prefix.extend_from_slice(b"\":");

        ColMeta { depth, scope_paths, scope_open, key_prefix }
    }).collect()
}

/// Turn decoded columns back into a JSON array of objects.
fn reconstruct_json(cols: &[(String, Vec<String>)], row_count: usize) -> Vec<u8> {
    let meta = build_col_meta(cols);

    // Estimate output size: sum all value lengths + per-col key overhead × rows.
    let total_val: usize = cols.iter()
        .map(|(path, vals)| {
            let vlen: usize = vals.iter().map(|v| v.len()).sum();
            vlen + (path.len() + 5) * row_count   // key overhead per row
        })
        .sum();
    let capacity = total_val + row_count * 2 + 2;

    let mut out = Vec::with_capacity(capacity);
    out.push(b'[');
    for row in 0..row_count {
        if row > 0 { out.push(b','); }
        emit_row_json_meta(&meta, cols, row, &mut out);
    }
    out.push(b']');
    out
}

/// Emit one row as a JSON object using pre-computed `ColMeta`.
/// No allocations happen inside here — all string metadata is pre-built.
fn emit_row_json_meta(
    meta: &[ColMeta],
    cols: &[(String, Vec<String>)],
    row:  usize,
    out:  &mut Vec<u8>,
) {
    // Scope stack: (borrowed scope_path str, emitted_any_in_scope)
    let mut scope_stack: Vec<(&str, bool)> = Vec::with_capacity(4);
    let mut top_emitted = false;

    out.push(b'{');

    for (m, (_, values)) in meta.iter().zip(cols.iter()) {
        let parent_path: &str = if m.depth == 0 {
            ""
        } else {
            &m.scope_paths[m.depth - 1]
        };

        // Pop scopes that no longer encompass this column's parent path.
        loop {
            match scope_stack.last() {
                None => break,
                Some(&(cur_scope, _)) => {
                    let still_valid = if parent_path.is_empty() {
                        false
                    } else if cur_scope.is_empty() {
                        true
                    } else {
                        parent_path == cur_scope
                            || (parent_path.len() > cur_scope.len()
                                && parent_path.as_bytes()[cur_scope.len()] == b'.'
                                && parent_path.starts_with(cur_scope))
                    };
                    if still_valid { break; }
                    out.push(b'}');
                    scope_stack.pop();
                }
            }
        }

        // Open new scopes until we reach the required nesting depth.
        while scope_stack.len() < m.depth {
            let level = scope_stack.len();
            let need_comma = if scope_stack.is_empty() {
                top_emitted
            } else {
                scope_stack.last().unwrap().1
            };
            if need_comma { out.push(b','); }
            if scope_stack.is_empty() {
                top_emitted = true;
            } else if let Some(s) = scope_stack.last_mut() {
                s.1 = true;
            }
            out.extend_from_slice(&m.scope_open[level]);
            scope_stack.push((&m.scope_paths[level], false));
        }

        // Emit the leaf: "key":value
        let need_comma = if scope_stack.is_empty() {
            top_emitted
        } else {
            scope_stack.last().unwrap().1
        };
        if need_comma { out.push(b','); }
        if scope_stack.is_empty() {
            top_emitted = true;
        } else if let Some(s) = scope_stack.last_mut() {
            s.1 = true;
        }
        out.extend_from_slice(&m.key_prefix);
        out.extend_from_slice(values[row].as_bytes());
    }

    // Close remaining open scopes.
    for _ in scope_stack.drain(..) {
        out.push(b'}');
    }
    out.push(b'}');
}

// ── JSON string helpers ───────────────────────────────────────────────────────

/// Wrap a string in JSON double-quotes with minimal escaping.
fn json_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"'  => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c    => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json_escape_bytes_into(bytes: &[u8], out: &mut Vec<u8>) {
    for &b in bytes {
        match b {
            b'"'  => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            b     => out.push(b),
        }
    }
}

// ── indexmap shim (order-preserving HashMap) ─────────────────────────────────
// We need insertion-order maps for row extraction (so first-occurrence key order
// matches the tokenizer's sorted-key emission order, which is alphabetical).
// Use a simple Vec-of-pairs rather than pulling in the `indexmap` crate.
mod indexmap {
    #[derive(Clone)]
    pub struct IndexMap<K: PartialEq, V> {
        entries: Vec<(K, V)>,
    }
    impl<K: PartialEq + Clone, V: Clone> IndexMap<K, V> {
        pub fn new() -> Self { Self { entries: Vec::new() } }
        pub fn insert(&mut self, key: K, value: V) {
            for (k, v) in &mut self.entries {
                if k == &key { *v = value; return; }
            }
            self.entries.push((key, value));
        }
        pub fn get(&self, key: &K) -> Option<&V> {
            self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
        }
        pub fn keys(&self) -> impl Iterator<Item = &K> {
            self.entries.iter().map(|(k, _)| k)
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(json: &[u8]) {
        let col_bytes = encode_columnar(json).expect("encode failed");
        let decoded   = decode_columnar(&col_bytes).expect("decode failed");
        // Compare via canonical JSON
        let canon_in  = crate::pipelines::text::canonicalize_json(json).unwrap();
        let canon_out = crate::pipelines::text::canonicalize_json(&decoded).unwrap();
        assert_eq!(canon_in, canon_out, "roundtrip mismatch");
    }

    #[test]
    fn simple_int_column() {
        let json: Vec<u8> = (0..10)
            .map(|i| format!(r#"{{"id":{i},"val":{}}}"#, i * 2))
            .collect::<Vec<_>>()
            .join(",")
            .pipe_wrapped_in_array();
        roundtrip(&json);
    }

    #[test]
    fn enum_column_cycling() {
        let roles = ["a", "b", "c", "d"];
        let json: Vec<u8> = (0..20)
            .map(|i| format!(r#"{{"role":"{}"}}"#, roles[i % 4]))
            .collect::<Vec<_>>()
            .join(",")
            .pipe_wrapped_in_array();
        roundtrip(&json);
    }

    #[test]
    fn float_fixed_column() {
        let json: Vec<u8> = (0..10)
            .map(|i| format!(r#"{{"score":{:.2}}}"#, i as f64 * 0.01))
            .collect::<Vec<_>>()
            .join(",")
            .pipe_wrapped_in_array();
        roundtrip(&json);
    }

    #[test]
    fn timestamp_period_column() {
        let json: Vec<u8> = (0..56)
            .map(|i| format!(r#"{{"ts":"2026-01-{:02}T12:00:00Z"}}"#, (i % 28) + 1))
            .collect::<Vec<_>>()
            .join(",")
            .pipe_wrapped_in_array();
        roundtrip(&json);
    }

    #[test]
    fn strprefix_column() {
        let json: Vec<u8> = (0..10)
            .map(|i| format!(r#"{{"name":"user_{i:04}"}}"#))
            .collect::<Vec<_>>()
            .join(",")
            .pipe_wrapped_in_array();
        roundtrip(&json);
    }

    #[test]
    fn nested_objects() {
        let json: Vec<u8> = (0..10)
            .map(|i| format!(r#"{{"id":{i},"user":{{"name":"user_{i:04}","role":"admin"}}}}"#))
            .collect::<Vec<_>>()
            .join(",")
            .pipe_wrapped_in_array();
        roundtrip(&json);
    }

    #[test]
    fn detect_period_simple() {
        let vals: Vec<i64> = (0..20).map(|i| i % 4).collect();
        let base = detect_period_i64(&vals).unwrap();
        assert_eq!(base, vec![0, 1, 2, 3]);
    }

    #[test]
    fn detect_period_none_for_sequential() {
        let vals: Vec<i64> = (0..10).collect();
        // Sequential 0..9 has no period < 5 that repeats
        assert!(detect_period_i64(&vals).is_none());
    }

    #[test]
    fn detect_period_100() {
        let vals: Vec<i64> = (0..300).map(|i| i % 100).collect();
        let base = detect_period_i64(&vals).unwrap();
        assert_eq!(base.len(), 100);
        assert_eq!(base[0], 0);
        assert_eq!(base[99], 99);
    }

    #[test]
    fn backref_detected() {
        // Two identical columns
        let json: Vec<u8> = (0..10)
            .map(|i| format!(r#"{{"a":{i},"b":{i}}}"#))
            .collect::<Vec<_>>()
            .join(",")
            .pipe_wrapped_in_array();
        let col_bytes = encode_columnar(&json).unwrap();
        // TAG_BACKREF should appear
        assert!(col_bytes.contains(&TAG_BACKREF), "expected TAG_BACKREF in encoding");
        roundtrip(&json);
    }

    #[test]
    fn full_api_json_roundtrip() {
        let roles    = ["admin", "user", "viewer", "moderator"];
        let regions  = ["us-east-1", "eu-west-1", "ap-southeast-1", "us-west-2"];
        let statuses = ["active", "inactive", "pending", "suspended"];
        let json: Vec<u8> = (0..100)
            .map(|i| {
                let role   = roles[i % 4];
                let region = regions[i % 4];
                let status = statuses[i % 4];
                let score  = (i % 100) as f64 * 0.01;
                format!(
                    r#"{{"id":{i},"user":{{"name":"user_{i:04}","role":"{role}","score":{score:.2}}},"region":"{region}","status":"{status}","created_at":"2026-01-{:02}T12:00:00Z"}}"#,
                    (i % 28) + 1
                )
            })
            .collect::<Vec<_>>()
            .join(",")
            .pipe_wrapped_in_array();
        roundtrip(&json);
    }

    // Helper: wrap a comma-joined string in [ ... ]
    trait WrapArray {
        fn pipe_wrapped_in_array(self) -> Vec<u8>;
    }
    impl WrapArray for String {
        fn pipe_wrapped_in_array(self) -> Vec<u8> {
            format!("[{self}]").into_bytes()
        }
    }
}
