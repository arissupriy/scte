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
use crate::entropy::{FreqTable, rans_encode, rans_decode};

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

/// String column with a constant prefix and binary-packed hex suffix.
/// Handles fields like `"scte-a1b2c3d4e5f6"` or `"uuid-deadbeef..."`.
/// The hex suffix (even number of hex digits) is encoded as raw bytes (2 chars → 1 byte).
///
/// Wire layout:
///   TAG_STRPREFIX_HEX  u8
///   prefix_len         varint
///   prefix_bytes       prefix_len bytes
///   hex_byte_len       varint  (number of packed bytes per row; hex chars = hex_byte_len × 2)
///   row_0_packed       hex_byte_len bytes
///   row_1_packed       hex_byte_len bytes
///   …
const TAG_STRPREFIX_HEX: u8 = 0x0E;

/// Enum column entropy-coded with per-column rANS (Level 1 local frequency model).
///
/// Applied when `row_count ≥ 64` and the rANS-coded stream is strictly smaller
/// than the delta-varint baseline (TAG_ENUM).
///
/// Wire layout:
///   TAG_ENUM_RANS        u8
///   variant_table        same as TAG_ENUM (n_variants varint + [len + bytes]…)
///   ft_len               varint  (byte count of serialized FreqTable)
///   ft_bytes             ft_len bytes  (FreqTable::serialize() output)
///   rans_len             varint  (rANS-coded stream length)
///   rans_bytes           rans_len bytes
const TAG_ENUM_RANS: u8 = 0x10;

/// Enum column run-length encoded.
///
/// Applied when consecutive identical values dominate (e.g. long `status=200` runs).
/// Selected when RLE wire size is strictly smaller than the delta/rANS baseline.
///
/// Wire layout:
///   TAG_ENUM_RLE         u8
///   variant_table        n_variants varint + [len + bytes]…
///   rle_count            varint  (number of (variant_idx, run_len) pairs)
///   pairs                rle_count × [variant_idx u8 + run_len varint]
const TAG_ENUM_RLE: u8 = 0x11;

/// Integer column entropy-coded with per-column rANS on delta residuals.
///
/// Applied when `row_count ≥ 64` and rANS-of-deltas is strictly smaller than
/// plain delta-varint encoding (TAG_INT).
///
/// Wire layout:
///   TAG_INT_RANS         u8
///   ft_len               varint
///   ft_bytes             ft_len bytes  (FreqTable on delta residuals)
///   rans_len             varint
///   rans_bytes           rans_len bytes
///   min_delta            i64 varint  (subtracted before rANS to ensure [0, alph))
///   alphabet_bits        u8  (log2 of alphabet size used; actual alph = min(256, range))
const TAG_INT_RANS: u8 = 0x12;

/// Sub-table column: an array-valued field encoded as a nested columnar block.
///
/// Handles `Array<Object>`, `Array<Scalar>`, and arbitrary recursive nesting.
/// Each parent row carries a count of how many elements it contributed.
///
/// Wire layout:
///   TAG_SUB_TABLE        u8
///   total_elements       varint  (sum of all per-row counts)
///   count_body_len       varint
///   count_body           bytes   (encode_delta_ints of per-row element counts)
///   sub_col_count        varint
///   [sub_columns]        path_len + path + tag + data  (recursive)
///     For Array<Scalar>: sub_col_count=1, sub_column path="" (empty)
///     For Array<Object>: sub_col_count = scalar fields + nested sub-tables
const TAG_SUB_TABLE: u8 = 0x13;

/// All values are 36-char UUID strings (8-4-4-4-12 hex groups with hyphens).
/// Wire: TAG_UUID + 16 raw bytes per row (groups concatenated, no hyphens).
const TAG_UUID: u8 = 0x14;

/// All values are base64-encoded strings of identical length (standard alphabet).
/// Wire: TAG_BASE64 + decoded_len varint + decoded_len raw bytes per row.
const TAG_BASE64: u8 = 0x15;

/// Float column entropy-coded with per-column rANS on delta residuals.
///
/// Applied when `row_count ≥ 64` and rANS wire size is strictly smaller than
/// plain delta-varint encoding (TAG_FLOAT_FIXED).  Decimal precision is still
/// stored and used during reconstruction.
///
/// Wire layout:
///   TAG_FLOAT_FIXED_RANS  u8
///   decimals              u8
///   ft_len                varint
///   ft_bytes              ft_len bytes  (FreqTable on delta residuals)
///   orig_delta_len        varint  (delta byte count; needed by rANS decoder)
///   rans_len              varint
///   rans_bytes            rans_len bytes
const TAG_FLOAT_FIXED_RANS: u8 = 0x17;

/// Timestamp column entropy-coded with per-column rANS on epoch delta residuals.
///
/// Applied when `row_count ≥ 64` and rANS wire size is strictly smaller than
/// plain delta-varint encoding (TAG_TIMESTAMP).
///
/// Wire layout:
///   TAG_TIMESTAMP_RANS  u8
///   ft_len              varint
///   ft_bytes            ft_len bytes
///   orig_delta_len      varint
///   rans_len            varint
///   rans_bytes          rans_len bytes
const TAG_TIMESTAMP_RANS: u8 = 0x18;

/// Raw-string column entropy-coded with per-column rANS on the concatenated
/// UTF-8 byte stream.
///
/// Applied when `row_count ≥ 64` and rANS wire size is strictly smaller than
/// the raw UTF-8 fallback (TAG_RAW_STR).  Helps for columns with non-uniform
/// character distributions (e.g. email addresses, URL paths, human names).
///
/// Wire layout:
///   TAG_RAW_STR_RANS   u8
///   lengths_len        varint  (byte count of delta-encoded string lengths)
///   lengths_bytes      lengths_len bytes
///   ft_len             varint
///   ft_bytes           ft_len bytes  (FreqTable on the concatenated bytes)
///   orig_byte_count    varint  (total bytes in the rANS payload)
///   rans_len           varint
///   rans_bytes         rans_len bytes
const TAG_RAW_STR_RANS: u8 = 0x19;

/// Number of rows per columnar SCTE section when chunking large arrays.
///
/// Arrays with more than this many rows are split into multiple SCTE sections.
/// Each section carries `[row_start: u32 LE][row_end: u32 LE]` in its
/// `SectionEntry::meta` field, enabling parallel decode and partial access.
pub(crate) const COLUMNAR_CHUNK_ROWS: usize = 8_192;

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

/// A field value in an object that lives inside an array (array item).
#[derive(Debug, Clone)]
enum ArrayItemField {
    Scalar(RawValue),
    /// A nested array within an array-item object.
    Array(Vec<ArrayItem>),
}

/// A single element in an array field.
#[derive(Debug, Clone)]
enum ArrayItem {
    Scalar(RawValue),
    /// A JSON object as an array element.  Keys are dotted-flattened paths.
    Object(indexmap::IndexMap<String, ArrayItemField>),
}

/// Sub-table derived from an array-valued field.
struct SubTable {
    /// Key path of the array field in the parent table (e.g. "friends").
    path:   String,
    /// Number of array elements contributed by each parent row.
    counts: Vec<usize>,
    /// Sum of all counts.
    total:  usize,
    /// The element data, transposed into columns.
    items:  SubItems,
}

enum SubItems {
    /// `Array<Scalar>`: one flat column of values.
    Scalars(Vec<RawValue>),
    /// `Array<Object>`: transposed fields of the element objects.
    Objects {
        scalar_cols: Vec<RawColumn>,
        sub_tables:  Vec<SubTable>,
    },
}

/// Full extraction result: scalar columns + sub-table array fields.
struct ExtractResult {
    row_count:   usize,
    scalar_cols: Vec<RawColumn>,
    sub_tables:  Vec<SubTable>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Return true when `input` is a JSON Array\<Object\> with ≥ 2 rows sharing
/// the same flat schema, AND columnar encoding is likely beneficial.
pub fn detect_homogeneous_array(input: &[u8]) -> bool {
    let tokens = match tokenize_json(input) {
        Ok(t) => t,
        Err(_) => return false,
    };
    extract_all_columns(&tokens).is_some()
}

/// Encode `input` (a JSON Array\<Object\>) as a compact COLUMNAR section.
///
/// Returns `Err` if `input` is not valid JSON or not a homogeneous array.
pub fn encode_columnar(input: &[u8]) -> Result<Vec<u8>, ScteError> {
    let tokens = tokenize_json(input)?;
    encode_columnar_from_tokens(&tokens)
}

/// Encode a **pre-tokenized** JSON Array\<Object\> as a COLUMNAR section.
///
/// Accepts the token stream produced by a prior `tokenize_json` call so the
/// caller can avoid a second parse for the same input.  Returns `None` if the
/// token stream does not represent a homogeneous array.
///
/// For inputs exceeding [`COLUMNAR_CHUNK_ROWS`] rows use
/// [`try_encode_columnar_chunks_from_tokens`] instead (returns multiple chunks
/// for multi-section container assembly).
pub(crate) fn try_encode_columnar_from_tokens(tokens: &[Token]) -> Option<Vec<u8>> {
    let chunks = try_encode_columnar_chunks_from_tokens(tokens)?;
    if chunks.len() == 1 {
        Some(chunks.into_iter().next().unwrap().2)
    } else {
        // Large arrays chunked — caller should use try_encode_columnar_chunks_from_tokens.
        // Concatenate for backward-compat single-blob consumers (e.g. tests).
        Some(chunks.into_iter().flat_map(|(_, _, b)| b).collect())
    }
}

/// Encode a pre-tokenized JSON Array\<Object\> as one or more COLUMNAR chunks.
///
/// Returns `Some(chunks)` where each chunk is `(row_start, row_end, encoded_bytes)`.
/// Arrays with ≤ [`COLUMNAR_CHUNK_ROWS`] rows produce a single-element vec.
/// Larger arrays are split into `⌈row_count / COLUMNAR_CHUNK_ROWS⌉` chunks,
/// enabling multi-section containers that support parallel decode and partial
/// data access.
///
/// Returns `None` if the input is not a homogeneous `Array<Object>`.
pub(crate) fn try_encode_columnar_chunks_from_tokens(
    tokens: &[Token],
) -> Option<Vec<(u32, u32, Vec<u8>)>> {
    let extract   = extract_all_columns(tokens)?;
    let row_count = extract.row_count;

    if row_count <= COLUMNAR_CHUNK_ROWS {
        let bytes = encode_extract_range(
            &extract.scalar_cols, &extract.sub_tables, 0, row_count,
        );
        return Some(vec![(0u32, row_count as u32, bytes)]);
    }

    let mut chunks = Vec::new();
    let mut start  = 0;
    while start < row_count {
        let end   = (start + COLUMNAR_CHUNK_ROWS).min(row_count);
        let bytes = encode_extract_range(
            &extract.scalar_cols, &extract.sub_tables, start, end,
        );
        chunks.push((start as u32, end as u32, bytes));
        start = end;
    }
    Some(chunks)
}

fn encode_columnar_from_tokens(tokens: &[Token]) -> Result<Vec<u8>, ScteError> {
    let extract = extract_all_columns(tokens)
        .ok_or_else(|| ScteError::EncodeError("not a homogeneous JSON array".into()))?;
    Ok(encode_extract_range(
        &extract.scalar_cols, &extract.sub_tables, 0, extract.row_count,
    ))
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

// ── Extraction: JSON tokens → flat columns + sub-tables ──────────────────────

/// Convert a token to a scalar RawValue (only for non-structural tokens).
#[inline]
fn token_to_raw_value(tok: &Token) -> RawValue {
    match tok {
        Token { kind: TokenKind::NumInt,   payload: TokenPayload::Int(v)   } => RawValue::Int(*v),
        Token { kind: TokenKind::NumFloat, payload: TokenPayload::Float(f) } => RawValue::Float(*f),
        Token { kind: TokenKind::Str,      payload: TokenPayload::Str(s)   } => RawValue::Str(s.clone()),
        Token { kind: TokenKind::Bool,     payload: TokenPayload::Bool(b)  } => RawValue::Bool(*b),
        _ => RawValue::Null,
    }
}

/// Scan forward from `arr_open` to find its matching `ArrClose` (or ObjClose).
/// Uses a single depth counter — valid because JSON is always properly nested.
fn find_arr_close(tokens: &[Token], arr_open: usize) -> usize {
    let mut depth = 1i32;
    let mut i = arr_open + 1;
    while i < tokens.len() {
        match tokens[i].kind {
            TokenKind::ArrOpen | TokenKind::ObjOpen  => depth += 1,
            TokenKind::ArrClose | TokenKind::ObjClose => {
                depth -= 1;
                if depth == 0 { return i; }
            }
            _ => {}
        }
        i += 1;
    }
    arr_open // fallback (only on malformed input)
}

/// Parse the tokens for array elements (between ArrOpen and ArrClose).
/// `start` is the first token after ArrOpen, `end` is the index of ArrClose.
/// Returns `None` if any element is a nested array (array-of-array), which we
/// cannot encode losslessly in the current sub-table format.  Callers must
/// propagate `None` up to force a fallback to the raw text pipeline.
fn parse_array_items(tokens: &[Token], start: usize, end: usize) -> Option<Vec<ArrayItem>> {
    let mut items = Vec::new();
    let mut pos = start;
    while pos < end {
        match tokens[pos].kind {
            TokenKind::ObjOpen => {
                pos += 1;
                if let Some(obj) = parse_item_object(tokens, &mut pos, "") {
                    items.push(ArrayItem::Object(obj));
                }
            }
            TokenKind::ArrOpen => {
                // Array-as-element (e.g. [[1,2],[3,4]]): cannot encode losslessly
                // as a sub-table.  Signal failure so the caller falls back to
                // the raw text pipeline instead of silently writing Null.
                return None;
            }
            TokenKind::ObjClose | TokenKind::ArrClose => break,
            _ => {
                items.push(ArrayItem::Scalar(token_to_raw_value(&tokens[pos])));
                pos += 1;
            }
        }
    }
    Some(items)
}

/// Recursively parse an object that lives inside an array.
/// `pos` must point to the first token after ObjOpen; advances past ObjClose.
/// `path_prefix` is prepended (with ".") to nested object keys.
/// Returns `None` if any nested array contains a nested-array element.
fn parse_item_object(
    tokens: &[Token],
    pos: &mut usize,
    path_prefix: &str,
) -> Option<indexmap::IndexMap<String, ArrayItemField>> {
    let mut obj: indexmap::IndexMap<String, ArrayItemField> = indexmap::IndexMap::new();
    while tokens.get(*pos).map(|t| t.kind) != Some(TokenKind::ObjClose) {
        if *pos >= tokens.len() { return None; }
        let key = if let TokenPayload::Str(k) = &tokens[*pos].payload {
            k.clone()
        } else {
            *pos += 1;
            continue;
        };
        *pos += 1; // consume Key token
        let full_key = if path_prefix.is_empty() {
            key
        } else {
            format!("{path_prefix}.{key}")
        };
        match tokens.get(*pos).map(|t| t.kind) {
            Some(TokenKind::ObjOpen) => {
                *pos += 1;
                if let Some(sub) = parse_item_object(tokens, pos, &full_key) {
                    for (k, v) in sub { obj.insert(k, v); }
                } else {
                    return None; // propagate failure
                }
            }
            Some(TokenKind::ArrOpen) => {
                let close = find_arr_close(tokens, *pos);
                let inner = parse_array_items(tokens, *pos + 1, close)?; // None = bail out
                *pos = close + 1;
                obj.insert(full_key, ArrayItemField::Array(inner));
            }
            Some(TokenKind::ObjClose) | Some(TokenKind::ArrClose) | None => break,
            _ => {
                obj.insert(full_key, ArrayItemField::Scalar(token_to_raw_value(&tokens[*pos])));
                *pos += 1;
            }
        }
    }
    *pos += 1; // consume ObjClose
    Some(obj)
}

/// Convert a flat list of `ArrayItem`s into `SubItems` (Scalars or Objects).
/// Returns `None` if items are mixed types or object schema is inconsistent.
fn make_sub_items(flat: Vec<ArrayItem>) -> Option<SubItems> {
    if flat.is_empty() {
        return Some(SubItems::Scalars(Vec::new()));
    }
    if flat.iter().all(|i| matches!(i, ArrayItem::Scalar(_))) {
        let vals = flat.into_iter().map(|i| match i {
            ArrayItem::Scalar(v) => v, _ => unreachable!()
        }).collect();
        return Some(SubItems::Scalars(vals));
    }
    if !flat.iter().all(|i| matches!(i, ArrayItem::Object(_))) {
        return None; // mixed types → skip
    }
    let objs: Vec<indexmap::IndexMap<String, ArrayItemField>> = flat.into_iter().map(|i| match i {
        ArrayItem::Object(m) => m, _ => unreachable!()
    }).collect();

    // Require homogeneous schema across all elements.
    let first_keys: Vec<String> = objs[0].keys().cloned().collect();
    for obj in &objs[1..] {
        if obj.keys().cloned().collect::<Vec<_>>() != first_keys { return None; }
    }

    let total = objs.len();
    let mut scalar_cols: Vec<RawColumn> = Vec::new();
    let mut sub_tables: Vec<SubTable> = Vec::new();

    for key in &first_keys {
        let is_nested_array = matches!(objs[0].get(key), Some(ArrayItemField::Array(_)));
        if is_nested_array {
            let mut counts = Vec::with_capacity(total);
            let mut flat_inner: Vec<ArrayItem> = Vec::new();
            let mut elem_total = 0usize;
            for obj in &objs {
                if let Some(ArrayItemField::Array(inner)) = obj.get(key) {
                    counts.push(inner.len());
                    elem_total += inner.len();
                    flat_inner.extend(inner.iter().cloned());
                } else {
                    counts.push(0);
                }
            }
            let sub_items = make_sub_items(flat_inner)?; // None → whole sub-table path fails
            sub_tables.push(SubTable { path: key.clone(), counts, total: elem_total, items: sub_items });
        } else {
            let values: Vec<RawValue> = objs.iter().map(|obj| match obj.get(key) {
                Some(ArrayItemField::Scalar(v)) => v.clone(),
                _ => RawValue::Null,
            }).collect();
            scalar_cols.push(RawColumn { key_path: key.clone(), values });
        }
    }
    Some(SubItems::Objects { scalar_cols, sub_tables })
}

/// Full extraction: scalar columns **and** sub-table array fields.
fn extract_all_columns(tokens: &[Token]) -> Option<ExtractResult> {
    use TokenKind::*;
    let n = tokens.len();
    if n < 3 { return None; }
    if tokens[0].kind != ArrOpen    { return None; }
    if tokens[n - 1].kind != ArrClose { return None; }

    // ── First pass: build scalar rows and record array-field token ranges ────
    let mut rows:  Vec<indexmap::IndexMap<String, RawValue>> = Vec::new();
    let mut path_seg_stack: Vec<String> = Vec::new();
    let mut cur_row: Option<indexmap::IndexMap<String, RawValue>> = None;
    let mut pending_leaf: Option<String> = None;
    let mut obj_depth = 0i32;
    // array_field_data[path] = per-row token ranges (start exclusive of ArrOpen, end = ArrClose idx)
    let mut array_field_order: Vec<String> = Vec::new();
    let mut array_field_data: indexmap::IndexMap<String, Vec<Option<(usize, usize)>>> =
        indexmap::IndexMap::new();
    let mut cur_row_arrays: Vec<(String, (usize, usize))> = Vec::new();

    let mut i = 1usize; // skip outer ArrOpen
    while i < n - 1 {
        match &tokens[i] {
            Token { kind: ArrOpen, .. } => {
                // Array value for a field in the current row?
                if let Some(leaf) = pending_leaf.take() {
                    let full_path = if path_seg_stack.is_empty() {
                        leaf
                    } else {
                        format!("{}.{}", path_seg_stack.join("."), leaf)
                    };
                    let close_pos = find_arr_close(tokens, i);
                    cur_row_arrays.push((full_path, (i + 1, close_pos)));
                    i = close_pos + 1; // skip past ArrClose
                    continue;
                }
                // Otherwise this is the outer array separator — ignore
            }
            Token { kind: ArrClose, .. } => { /* outer array close handled by loop bound */ }
            Token { kind: ObjOpen, .. } => {
                if obj_depth == 0 {
                    cur_row = Some(indexmap::IndexMap::new());
                    cur_row_arrays = Vec::new();
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
                obj_depth -= 1;
                if obj_depth == 0 {
                    if let Some(row) = cur_row.take() {
                        let row_idx = rows.len();
                        rows.push(row);
                        // Commit array ranges for this row
                        for (path, range) in cur_row_arrays.drain(..) {
                            if !array_field_data.contains_key(&path) {
                                array_field_order.push(path.clone());
                                array_field_data.insert(path.clone(), vec![None; row_idx]);
                            }
                            array_field_data.get_mut(&path).unwrap().push(Some(range));
                        }
                        // Pad array fields not seen in this row
                        for path in &array_field_order {
                            let v = array_field_data.get_mut(path).unwrap();
                            if v.len() <= row_idx { v.push(None); }
                        }
                    }
                } else {
                    path_seg_stack.pop();
                }
                pending_leaf = None;
            }
            Token { kind: Key, payload: TokenPayload::Str(k) } => {
                pending_leaf = Some(k.clone());
            }
            token => {
                if let Some(leaf) = pending_leaf.take() {
                    let full_path = if path_seg_stack.is_empty() {
                        leaf
                    } else {
                        format!("{}.{}", path_seg_stack.join("."), leaf)
                    };
                    if let Some(ref mut row) = cur_row {
                        row.insert(full_path, token_to_raw_value(token));
                    }
                }
            }
        }
        i += 1;
    }

    if rows.len() < 2 { return None; }

    // All rows must have identical scalar key sets.
    let first_keys: Vec<String> = rows[0].keys().cloned().collect();
    for row in &rows[1..] {
        if row.keys().cloned().collect::<Vec<_>>() != first_keys { return None; }
    }

    let row_count = rows.len();
    let mut scalar_cols: Vec<RawColumn> = first_keys.iter().map(|k| RawColumn {
        key_path: k.clone(),
        values: Vec::with_capacity(row_count),
    }).collect();
    for row in &rows {
        for col in &mut scalar_cols {
            let val = row.get(&col.key_path).cloned().unwrap_or(RawValue::Null);
            col.values.push(val);
        }
    }

    // ── Second pass: build sub-tables from array field token ranges ──────────
    let mut sub_tables: Vec<SubTable> = Vec::new();
    for path in &array_field_order {
        let ranges = match array_field_data.get(path) {
            Some(r) => r,
            None => continue,
        };
        let mut counts      = Vec::with_capacity(row_count);
        let mut total       = 0usize;
        let mut all_items: Vec<ArrayItem> = Vec::new();
        for range_opt in ranges {
            match range_opt {
                None => counts.push(0),
                Some((start, end)) => {
                    let items = parse_array_items(tokens, *start, *end)?;
                    let cnt   = items.len();
                    counts.push(cnt);
                    total += cnt;
                    all_items.extend(items);
                }
            }
        }
        // Pad counts for rows added after this field was first seen
        while counts.len() < row_count { counts.push(0); }

        match make_sub_items(all_items) {
            Some(sub_items) => sub_tables.push(SubTable { path: path.clone(), counts, total, items: sub_items }),
            // Heterogeneous or un-encodable array field: abort the entire columnar
            // path so no field is silently dropped.  The whole input falls back
            // to the raw text pipeline.
            None => return None,
        }
    }

    Some(ExtractResult { row_count, scalar_cols, sub_tables })
}

/// Thin shim kept for internal callers that only need scalar columns.
#[allow(dead_code)]
fn extract_flat_columns(tokens: &[Token]) -> Option<(usize, Vec<RawColumn>)> {
    let r = extract_all_columns(tokens)?;
    Some((r.row_count, r.scalar_cols))
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
                // Try rANS on the delta bytes — helps for smooth float columns
                // where deltas cluster around a few values.
                if values.len() >= 64 {
                    if let Some((ft_bytes, rans_bytes)) = try_rans_on_bytes(&data) {
                        out.push(TAG_FLOAT_FIXED_RANS);
                        out.push(decimals);
                        varint::encode_usize(ft_bytes.len(), out);
                        out.extend_from_slice(&ft_bytes);
                        varint::encode_usize(data.len(), out);
                        varint::encode_usize(rans_bytes.len(), out);
                        out.extend_from_slice(&rans_bytes);
                        return;
                    }
                }
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

        // ── Cardinality pre-screen ────────────────────────────────────────────
        // Count distinct values in a single O(R) pass with a small fixed-size
        // probe.  If cardinality ≤ 256 we can skip detect_strprefix and
        // detect_hex_suffix entirely — those probes are only useful for
        // high-cardinality fields like sequential IDs or trace IDs.
        let cardinality = {
            use std::collections::HashSet;
            let mut seen: HashSet<&str> = HashSet::with_capacity(32);
            let mut high = false;
            for &s in &strs {
                seen.insert(s);
                if seen.len() > 256 { high = true; break; }
            }
            if high { usize::MAX } else { seen.len() }
        };

        if cardinality <= 256 {
            // Low-cardinality: go straight to enum path — skip strprefix/hexsuffix.
            encode_enum_column(&strs, out);
            return;
        }

        // High-cardinality: check timestamp first (cheap pre-screen already),
        // then strprefix, hexsuffix, finally raw.

        // Try Timestamp — fast pre-screen on first value to avoid O(R) parse_timestamp
        // calls on every non-timestamp string column (enum fields, status codes, etc.).
        let first_looks_like_ts = strs.first()
            .map(|s| s.len() >= 4 && s.as_bytes()[0].is_ascii_digit())
            .unwrap_or(false);
        let epochs: Vec<Option<i64>> = if first_looks_like_ts {
            strs.iter().map(|s| parse_timestamp(s)).collect()
        } else {
            vec![]
        };
        if !epochs.is_empty() && epochs.iter().all(|e| e.is_some()) {
            let epoch_vals: Vec<i64> = epochs.into_iter().map(|e| e.unwrap()).collect();
            if let Some(base) = detect_period_i64(&epoch_vals) {
                let base_enc = encode_delta_ints(&base);
                out.push(TAG_TIMESTAMP_PERIOD);
                varint::encode_usize(base_enc.len(), out);
                out.extend_from_slice(&base_enc);
            } else {
                let data = encode_delta_ints(&epoch_vals);
                // Try rANS — timestamp deltas (seconds/ms between events) often
                // have a skewed distribution that rANS can exploit.
                if values.len() >= 64 {
                    if let Some((ft_bytes, rans_bytes)) = try_rans_on_bytes(&data) {
                        out.push(TAG_TIMESTAMP_RANS);
                        varint::encode_usize(ft_bytes.len(), out);
                        out.extend_from_slice(&ft_bytes);
                        varint::encode_usize(data.len(), out);
                        varint::encode_usize(rans_bytes.len(), out);
                        out.extend_from_slice(&rans_bytes);
                        return;
                    }
                }
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

        // Try HexSuffix — constant prefix + hex-encoded binary suffix (e.g. trace IDs, UUIDs)
        if let Some((prefix, hex_byte_len)) = detect_hex_suffix(&strs) {
            out.push(TAG_STRPREFIX_HEX);
            varint::encode_usize(prefix.len(), out);
            out.extend_from_slice(prefix.as_bytes());
            varint::encode_usize(hex_byte_len, out);
            let hex_start = prefix.len();
            for s in &strs {
                let hex_chars = s[hex_start..].as_bytes();
                for i in 0..hex_byte_len {
                    let hi = hex_nibble(hex_chars[i * 2]);
                    let lo = hex_nibble(hex_chars[i * 2 + 1]);
                    out.push((hi << 4) | lo);
                }
            }
            return;
        }

        // Try UUID — standard 36-char UUID packs to 16 bytes/row (vs 36)
        if detect_uuid(&strs) {
            out.push(TAG_UUID);
            for s in &strs {
                out.extend_from_slice(&uuid_to_bytes(s));
            }
            return;
        }

        // Try BASE64 — same-length base64 column packs to decoded bytes (saves ~25%)
        if let Some(decoded_len) = detect_base64(&strs) {
            out.push(TAG_BASE64);
            varint::encode_usize(decoded_len, out);
            for s in &strs {
                let raw = base64_decode_str(s);
                // Pad or trim to exact decoded_len (guard against rare rounding)
                let n = raw.len().min(decoded_len);
                out.extend_from_slice(&raw[..n]);
                for _ in n..decoded_len { out.push(0); }
            }
            return;
        }

        // High-cardinality, no strprefix/hexsuffix/UUID/base64 match → raw strings.
        // Try rANS on the concatenated byte stream (names, emails, paths, etc.).
        if strs.len() >= 64 {
            let all_bytes: Vec<u8> = strs.iter().flat_map(|s| s.bytes()).collect();
            if let Some((ft_bytes, rans_bytes)) = try_rans_on_bytes(&all_bytes) {
                let lens: Vec<i64> = strs.iter().map(|s| s.len() as i64).collect();
                let lens_enc = encode_delta_ints(&lens);
                out.push(TAG_RAW_STR_RANS);
                varint::encode_usize(lens_enc.len(), out);
                out.extend_from_slice(&lens_enc);
                varint::encode_usize(ft_bytes.len(), out);
                out.extend_from_slice(&ft_bytes);
                varint::encode_usize(all_bytes.len(), out);
                varint::encode_usize(rans_bytes.len(), out);
                out.extend_from_slice(&rans_bytes);
                return;
            }
        }
        out.push(TAG_RAW_STR);
        for s in &strs {
            varint::encode_usize(s.len(), out);
            out.extend_from_slice(s.as_bytes());
        }
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

/// Encode a pure integer-value column (with period/delta/rANS dispatch).
fn encode_int_column(ints: &[i64], out: &mut Vec<u8>) {
    if let Some(base) = detect_period_i64(ints) {
        let base_enc = encode_delta_ints(&base);
        out.push(TAG_INT_PERIOD);
        varint::encode_usize(base_enc.len(), out);
        out.extend_from_slice(&base_enc);
        return;
    }

    let deltas = encode_delta_ints(ints);
    let varint_len = |mut n: usize| -> usize {
        let mut l = 1usize; while n >= 0x80 { n >>= 7; l += 1; } l
    };
    let delta_total = 1 + varint_len(deltas.len()) + deltas.len();

    // ── Try rANS on the raw delta bytes (Level 1 frequency model) ────────────
    // The delta byte stream is already de-correlated; rANS captures any
    // non-uniform byte distribution (e.g. response_time_ms in 50-500ms range).
    // Only attempt when: N ≥ 64, delta body not already tiny.
    if ints.len() >= 64 && deltas.len() >= 32 {
        let alphabet = 256usize;
        let freq = FreqTable::build(&deltas, alphabet, 14);
        // Entropy estimate: Σ freq_i * log2(M/freq_i) bits → bytes.
        // Uses integer arithmetic on norm_freqs to avoid floating point.
        let m = freq.m as u64;
        let est_bits: u64 = freq.norm_freqs.iter().zip(freq.raw_freqs.iter())
            .filter(|(&nf, &rf)| nf > 0 && rf > 0)
            .map(|(&nf, &rf)| {
                // bits for all occurrences of this symbol = raw_count * log2(M/norm)
                // log2(M/norm) ≈ log2(m) - log2(nf) — approximate with bit_length
                let log_m = m.next_power_of_two().trailing_zeros() as u64;
                let log_nf = (nf as u64).next_power_of_two().trailing_zeros() as u64;
                (rf as u64) * (log_m.saturating_sub(log_nf) + 1)
            })
            .sum();
        let est_rans_bytes = (est_bits / 8 + 1) as usize;
        let ft_bytes = freq.serialize();
        let rans_total_est = 1 + varint_len(ft_bytes.len()) + ft_bytes.len()
            + varint_len(est_rans_bytes) + est_rans_bytes;
        if rans_total_est < delta_total {
            // Estimate says rANS will win — do the actual encode.
            if let Ok(rans_bytes) = rans_encode(&deltas, &freq) {
                let rans_total = 1 + varint_len(ft_bytes.len()) + ft_bytes.len()
                    + varint_len(rans_bytes.len()) + rans_bytes.len();
                if rans_total < delta_total {
                    out.push(TAG_INT_RANS);
                    varint::encode_usize(ft_bytes.len(), out);
                    out.extend_from_slice(&ft_bytes);
                    // Store original delta byte count so the decoder knows how many
                    // bytes to recover from the rANS stream.
                    varint::encode_usize(deltas.len(), out);
                    varint::encode_usize(rans_bytes.len(), out);
                    out.extend_from_slice(&rans_bytes);
                    return;
                }
            }
        }
    }

    out.push(TAG_INT);
    varint::encode_usize(deltas.len(), out);
    out.extend_from_slice(&deltas);
}

// ── rANS helper ───────────────────────────────────────────────────────────────

/// Attempt to entropy-code `data` with rANS.
///
/// Returns `Some((ft_bytes, rans_bytes))` when the rANS representation is
/// **strictly** smaller than the naive `varint(len) + raw_bytes` layout.
/// Returns `None` immediately for inputs shorter than 32 bytes — overhead
/// never pays off at that scale.
fn try_rans_on_bytes(data: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    if data.len() < 32 { return None; }

    let freq     = FreqTable::build(data, 256, 14);
    let ft_bytes = freq.serialize();

    // Fast entropy estimate — avoids a full rans_encode if it clearly cannot win.
    let m = freq.m as u64;
    let est_bits: u64 = freq.norm_freqs.iter().zip(freq.raw_freqs.iter())
        .filter(|(&nf, &rf)| nf > 0 && rf > 0)
        .map(|(&nf, &rf)| {
            let log_m  = m.next_power_of_two().trailing_zeros() as u64;
            let log_nf = (nf as u64).next_power_of_two().trailing_zeros() as u64;
            (rf as u64) * (log_m.saturating_sub(log_nf) + 1)
        })
        .sum();
    let est_rans_bytes = (est_bits / 8 + 1) as usize;

    let varint_len = |mut n: usize| -> usize {
        let mut l = 1usize; while n >= 0x80 { n >>= 7; l += 1; } l
    };
    let raw_total  = varint_len(data.len()) + data.len();
    let rans_est   = varint_len(ft_bytes.len()) + ft_bytes.len()
        + varint_len(data.len()) + varint_len(est_rans_bytes) + est_rans_bytes;
    if rans_est >= raw_total { return None; }

    // Estimate says rANS wins — do the actual encode.
    let rans_bytes = rans_encode(data, &freq).ok()?;
    let rans_total = varint_len(ft_bytes.len()) + ft_bytes.len()
        + varint_len(data.len()) + varint_len(rans_bytes.len()) + rans_bytes.len();
    if rans_total < raw_total {
        Some((ft_bytes, rans_bytes))
    } else {
        None
    }
}

/// Encode a string column as an enum (or fall back to RawStr).
fn encode_enum_column(strs: &[&str], out: &mut Vec<u8>) {
    use std::collections::HashMap;
    // Collect distinct values in O(R) via HashMap instead of O(R×V) linear scan.
    let mut variants: Vec<&str> = Vec::with_capacity(16);
    let mut index_map: HashMap<&str, u8> = HashMap::with_capacity(16);
    for &s in strs {
        if !index_map.contains_key(s) {
            if variants.len() >= 256 {
                // Too many distinct values — raw strings
                out.push(TAG_RAW_STR);
                for s in strs {
                    varint::encode_usize(s.len(), out);
                    out.extend_from_slice(s.as_bytes());
                }
                return;
            }
            index_map.insert(s, variants.len() as u8);
            variants.push(s);
        }
    }
    let indices: Vec<u8> = strs.iter().map(|s| index_map[s]).collect();

    // Write variant table (needed for both ENUM and ENUM_RANS)
    let mut variant_table_bytes: Vec<u8> = Vec::new();
    varint::encode_usize(variants.len(), &mut variant_table_bytes);
    for v in &variants {
        varint::encode_usize(v.len(), &mut variant_table_bytes);
        variant_table_bytes.extend_from_slice(v.as_bytes());
    }

    // ── Compute delta-encoded baseline (TAG_ENUM / TAG_ENUM_PERIOD) ─────────
    // We pre-compute this so rANS is compared against the *actual* best delta
    // alternative — not against the raw index byte count, which would cause
    // rANS to beat period-detected data (e.g. cycling enums) incorrectly.
    let indices_i64: Vec<i64> = indices.iter().map(|&i| i as i64).collect();
    let (fallback_tag, fallback_body) = if let Some(base) = detect_period_i64(&indices_i64) {
        (TAG_ENUM_PERIOD, encode_delta_ints(&base))
    } else {
        (TAG_ENUM, encode_delta_ints(&indices_i64))
    };
    // Number of bytes a varint-encoded usize occupies on the wire.
    let varint_len = |mut n: usize| -> usize {
        let mut l = 1usize; while n >= 0x80 { n >>= 7; l += 1; } l
    };
    let delta_total = variant_table_bytes.len() + 1
        + varint_len(fallback_body.len()) + fallback_body.len();

    // ── Try RLE (run-length encoding) ─────────────────────────────────────────
    // Efficient when consecutive identical values dominate (long runs of
    // status=200, region="us-east", etc.).  One O(R) pass builds the run list;
    // we emit it only if strictly smaller than the delta baseline.
    {
        let mut runs: Vec<(u8, usize)> = Vec::new();
        let mut i = 0usize;
        while i < indices.len() {
            let sym = indices[i];
            let mut run = 1usize;
            while i + run < indices.len() && indices[i + run] == sym { run += 1; }
            runs.push((sym, run));
            i += run;
        }
        // RLE wire size: variant_table + 1 (tag) + varint(run_count)
        //              + run_count × (1 byte idx + varint(run_len))
        // Assume worst-case varint(run_len) = 2 bytes for estimation.
        let rle_runs_size: usize = runs.iter().map(|(_, r)| 1 + varint_len(*r)).sum();
        let rle_total = variant_table_bytes.len() + 1 + varint_len(runs.len()) + rle_runs_size;
        if rle_total < delta_total {
            out.push(TAG_ENUM_RLE);
            out.extend_from_slice(&variant_table_bytes);
            varint::encode_usize(runs.len(), out);
            for (sym, run) in &runs {
                out.push(*sym);
                varint::encode_usize(*run, out);
            }
            return;
        }
    }

    // ── Try rANS entropy coding (Level 1 local frequency model) ──────────────
    // Apply when N ≥ 64 and rANS wire size is strictly smaller than delta baseline.
    // The FreqTable is built from the actual index distribution of *this column*,
    // not from any prior dataset — fully local, stateless, deterministic.
    // Skip entirely when the delta baseline is already very compact.
    if strs.len() >= 64 && fallback_body.len() >= 32 {
        let m_bits: u32 = match variants.len() {
            0..=4   => 8,    // M =    256
            5..=16  => 10,   // M =  1_024
            17..=64 => 12,   // M =  4_096
            _       => 14,   // M = 16_384
        };
        let freq = FreqTable::build(&indices, variants.len().max(1), m_bits);
        // Entropy estimate from norm_freqs — skip rans_encode if estimate can't win.
        let m = freq.m as u64;
        let est_bits: u64 = freq.norm_freqs.iter().zip(freq.raw_freqs.iter())
            .filter(|(&nf, &rf)| nf > 0 && rf > 0)
            .map(|(&nf, &rf)| {
                let log_m  = m.next_power_of_two().trailing_zeros() as u64;
                let log_nf = (nf as u64).next_power_of_two().trailing_zeros() as u64;
                (rf as u64) * (log_m.saturating_sub(log_nf) + 1)
            })
            .sum();
        let est_rans_bytes = (est_bits / 8 + 1) as usize;
        let ft_bytes = freq.serialize();
        let rans_total_est = variant_table_bytes.len() + 1
            + varint_len(ft_bytes.len()) + ft_bytes.len()
            + varint_len(est_rans_bytes) + est_rans_bytes;
        if rans_total_est < delta_total {
            if let Ok(rans_bytes) = rans_encode(&indices, &freq) {
                let rans_total = variant_table_bytes.len() + 1
                    + varint_len(ft_bytes.len()) + ft_bytes.len()
                    + varint_len(rans_bytes.len()) + rans_bytes.len();
                if rans_total < delta_total {
                    out.push(TAG_ENUM_RANS);
                    out.extend_from_slice(&variant_table_bytes);
                    varint::encode_usize(ft_bytes.len(), out);
                    out.extend_from_slice(&ft_bytes);
                    varint::encode_usize(rans_bytes.len(), out);
                    out.extend_from_slice(&rans_bytes);
                    return;
                }
            }
        }
    }

    // ── Emit the delta baseline (already computed above) ─────────────────────
    out.push(fallback_tag);
    out.extend_from_slice(&variant_table_bytes);
    varint::encode_usize(fallback_body.len(), out);
    out.extend_from_slice(&fallback_body);
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

/// Detect a column where every value is `<fixed_prefix><hex_suffix>` with:
/// - the same prefix for all rows,
/// - all suffixes valid hex digits of identical even length.
///
/// Returns `(prefix, hex_byte_len)` where hex_byte_len = suffix_len / 2.
fn detect_hex_suffix(strs: &[&str]) -> Option<(String, usize)> {
    if strs.len() < 2 { return None; }
    let first = strs[0];
    // Common prefix length across all strings
    let prefix_len = strs[1..].iter().fold(first.len(), |min_len, s| {
        let common = first.bytes().zip(s.bytes()).take_while(|(a, b)| a == b).count();
        min_len.min(common)
    });
    // Suffix of the first string after the common prefix
    let suffix_len = first.len().checked_sub(prefix_len)?;
    // Suffix must be non-empty and have an even number of hex digits
    if suffix_len == 0 || suffix_len % 2 != 0 { return None; }
    let hex_byte_len = suffix_len / 2;
    // Every row's suffix must be the same length and all hex
    for s in strs {
        if s.len() != first.len() { return None; }
        // Only accept lowercase hex — uppercase falls to TAG_RAW_STR so that
        // the decoder (which emits `0-9a-f`) preserves the original casing.
        if !s[prefix_len..].bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) { return None; }
    }
    Some((first[..prefix_len].to_owned(), hex_byte_len))
}

#[inline(always)]
fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _           => 0,
    }
}

// ── UUID helpers ──────────────────────────────────────────────────────────────

/// Returns true iff `s` is a **lowercase** UUID in 8-4-4-4-12 form.
///
/// Uppercase UUIDs are intentionally rejected so that `bytes_to_uuid` (which
/// always emits lowercase) produces an identical string on decode.  Uppercase
/// inputs fall through to TAG_RAW_STR, preserving the original casing.
fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 { return false; }
    if b[8] != b'-' || b[13] != b'-' || b[18] != b'-' || b[23] != b'-' { return false; }
    for (i, &c) in b.iter().enumerate() {
        match i { 8 | 13 | 18 | 23 => continue, _ => {} }
        // Only accept lowercase hex — uppercase UUIDs fall to TAG_RAW_STR.
        if !matches!(c, b'0'..=b'9' | b'a'..=b'f') { return false; }
    }
    true
}

/// Returns true iff all strings are valid UUIDs and there are at least 2.
fn detect_uuid(strs: &[&str]) -> bool {
    strs.len() >= 2 && strs.iter().all(|s| is_uuid(s))
}

/// Pack a UUID string into 16 raw bytes (hyphens dropped, hex decoded).
fn uuid_to_bytes(s: &str) -> [u8; 16] {
    let b = s.as_bytes();
    let mut out = [0u8; 16];
    // hex byte positions in the 36-char string: groups 0-3 (8), 9-12 (4), 14-17 (4), 19-22 (4), 24-35 (12)
    const POS: [usize; 16] = [0, 2, 4, 6, 9, 11, 14, 16, 19, 21, 24, 26, 28, 30, 32, 34];
    for (i, &p) in POS.iter().enumerate() {
        out[i] = (hex_nibble(b[p]) << 4) | hex_nibble(b[p + 1]);
    }
    out
}

/// Unpack 16 raw bytes into a lowercase UUID string.
fn bytes_to_uuid(bytes: &[u8]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2],  bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

// ── Base64 helpers ────────────────────────────────────────────────────────────

static B64_ENC: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Returns the number of decoded bytes if all strings are same-length valid standard base64.
/// None if any string fails validation.
fn detect_base64(strs: &[&str]) -> Option<usize> {
    if strs.len() < 2 { return None; }
    let enc_len = strs[0].len();
    if enc_len == 0 || enc_len % 4 != 0 { return None; }
    for s in strs {
        if s.len() != enc_len { return None; }
        let b = s.as_bytes();
        for (i, &c) in b.iter().enumerate() {
            let valid = c.is_ascii_alphanumeric() || c == b'+' || c == b'/';
            let is_pad = c == b'=';
            if !valid && !is_pad { return None; }
            // padding only allowed in the last two positions
            if is_pad && i < enc_len - 2 { return None; }
        }
    }
    let pad = strs[0].bytes().filter(|&c| c == b'=').count();
    Some(enc_len / 4 * 3 - pad)
}

/// Decode a base64 string into raw bytes (no allocation of lookup table).
fn base64_decode_str(s: &str) -> Vec<u8> {
    let decode_c = |c: u8| -> u8 {
        match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _   => 0,
        }
    };
    let b = s.as_bytes();
    let n = b.len();
    let pad = b.iter().rev().take(2).filter(|&&c| c == b'=').count();
    let mut out = Vec::with_capacity(n / 4 * 3 - pad);
    let mut i = 0;
    while i + 4 <= n {
        let v0 = decode_c(b[i]);   let v1 = decode_c(b[i+1]);
        let v2 = decode_c(b[i+2]); let v3 = decode_c(b[i+3]);
        out.push((v0 << 2) | (v1 >> 4));
        if b[i+2] != b'=' { out.push((v1 << 4) | (v2 >> 2)); }
        if b[i+3] != b'=' { out.push((v2 << 6) | v3); }
        i += 4;
    }
    out
}

/// Encode raw bytes to standard base64.
fn base64_encode_bytes(data: &[u8]) -> String {
    let mut out = Vec::with_capacity((data.len() + 2) / 3 * 4);
    let mut i = 0;
    while i + 3 <= data.len() {
        let (b0, b1, b2) = (data[i], data[i+1], data[i+2]);
        out.push(B64_ENC[(b0 >> 2) as usize]);
        out.push(B64_ENC[((b0 & 3) << 4 | b1 >> 4) as usize]);
        out.push(B64_ENC[((b1 & 0xf) << 2 | b2 >> 6) as usize]);
        out.push(B64_ENC[(b2 & 0x3f) as usize]);
        i += 3;
    }
    match data.len() - i {
        1 => {
            let b0 = data[i];
            out.push(B64_ENC[(b0 >> 2) as usize]);
            out.push(B64_ENC[((b0 & 3) << 4) as usize]);
            out.extend_from_slice(b"==");
        }
        2 => {
            let (b0, b1) = (data[i], data[i+1]);
            out.push(B64_ENC[(b0 >> 2) as usize]);
            out.push(B64_ENC[((b0 & 3) << 4 | b1 >> 4) as usize]);
            out.push(B64_ENC[((b1 & 0xf) << 2) as usize]);
            out.push(b'=');
        }
        _ => {}
    }
    // SAFETY: B64_ENC contains only ASCII
    unsafe { String::from_utf8_unchecked(out) }
}

// ── Sub-table encoding ────────────────────────────────────────────────────────

/// Write a TAG_SUB_TABLE entry for one array-valued column.
/// Wire format:
///   path_len varint + path bytes
///   TAG_SUB_TABLE (0x13)
///   total_elements varint
///   count_body_len varint + count_body (delta-encoded per-row element counts)
///   sub_col_count varint
///   [sub-columns: each recursively encoded]
fn encode_sub_table(sub: &SubTable, out: &mut Vec<u8>) {
    // Path + tag
    varint::encode_usize(sub.path.len(), out);
    out.extend_from_slice(sub.path.as_bytes());
    out.push(TAG_SUB_TABLE);

    // Total number of elements across all rows
    varint::encode_usize(sub.total, out);

    // Per-row counts, delta-encoded
    let counts_i64: Vec<i64> = sub.counts.iter().map(|&c| c as i64).collect();
    let count_body = encode_delta_ints(&counts_i64);
    varint::encode_usize(count_body.len(), out);
    out.extend_from_slice(&count_body);

    match &sub.items {
        SubItems::Scalars(values) => {
            // One implicit sub-column with an empty path
            varint::encode_usize(1, out);
            let col = RawColumn { key_path: String::new(), values: values.clone() };
            varint::encode_usize(0, out); // empty path length
            encode_by_type(&col, sub.total, out);
        }
        SubItems::Objects { scalar_cols, sub_tables } => {
            varint::encode_usize(scalar_cols.len() + sub_tables.len(), out);
            for (idx, col) in scalar_cols.iter().enumerate() {
                encode_one_column(col, idx, scalar_cols, sub.total, out);
            }
            for nested in sub_tables {
                encode_sub_table(nested, out);
            }
        }
    }
}

// ── Chunked columnar encoding ─────────────────────────────────────────────────

/// Encode the row-range `[row_start, row_end)` from pre-extracted columns into
/// a complete COLUMNAR section body (version byte, row_count, col_count, columns).
///
/// This is the inner worker for both the single-chunk fast path and the
/// multi-chunk path in [`try_encode_columnar_chunks_from_tokens`].
fn encode_extract_range(
    scalar_cols: &[RawColumn],
    sub_tables:  &[SubTable],
    row_start:   usize,
    row_end:     usize,
) -> Vec<u8> {
    let row_count = row_end - row_start;
    let col_count = scalar_cols.len() + sub_tables.len();
    let mut out   = Vec::new();
    out.push(COLUMNAR_VERSION);
    varint::encode_usize(row_count, &mut out);
    varint::encode_usize(col_count, &mut out);

    // Slice scalar columns to the requested row range.
    let sliced: Vec<RawColumn> = scalar_cols.iter().map(|col| RawColumn {
        key_path: col.key_path.clone(),
        values:   col.values[row_start..row_end].to_vec(),
    }).collect();
    for (idx, col) in sliced.iter().enumerate() {
        encode_one_column(col, idx, &sliced, row_count, &mut out);
    }
    for sub in sub_tables {
        encode_sub_table_range(sub, row_start, row_end, &mut out);
    }
    out
}

/// Encode the sub-table rows that correspond to parent rows `[row_start, row_end)`.
///
/// The element range is derived by summing `sub.counts[..row_start]` and
/// `sub.counts[..row_end]`, then slicing items accordingly.  Nested sub-tables
/// are handled recursively using the derived element range as their row range.
fn encode_sub_table_range(
    sub:       &SubTable,
    row_start:  usize,
    row_end:    usize,
    out:       &mut Vec<u8>,
) {
    // Path + tag
    varint::encode_usize(sub.path.len(), out);
    out.extend_from_slice(sub.path.as_bytes());
    out.push(TAG_SUB_TABLE);

    // Element range for the requested parent-row slice.
    let elem_start: usize = sub.counts[..row_start].iter().sum();
    let elem_end:   usize = sub.counts[..row_end].iter().sum();
    let total_elements    = elem_end - elem_start;

    varint::encode_usize(total_elements, out);

    // Per-chunk row counts, delta-encoded.
    let chunk_counts: Vec<i64> = sub.counts[row_start..row_end]
        .iter().map(|&c| c as i64).collect();
    let count_body = encode_delta_ints(&chunk_counts);
    varint::encode_usize(count_body.len(), out);
    out.extend_from_slice(&count_body);

    match &sub.items {
        SubItems::Scalars(values) => {
            varint::encode_usize(1, out); // sub_col_count = 1
            varint::encode_usize(0, out); // empty path
            let sliced = values[elem_start..elem_end].to_vec();
            let col = RawColumn { key_path: String::new(), values: sliced };
            encode_by_type(&col, total_elements, out);
        }
        SubItems::Objects { scalar_cols, sub_tables } => {
            varint::encode_usize(scalar_cols.len() + sub_tables.len(), out);
            let sliced_scalars: Vec<RawColumn> = scalar_cols.iter().map(|col| RawColumn {
                key_path: col.key_path.clone(),
                values:   col.values[elem_start..elem_end].to_vec(),
            }).collect();
            for (idx, col) in sliced_scalars.iter().enumerate() {
                encode_one_column(col, idx, &sliced_scalars, total_elements, out);
            }
            // Nested sub-tables: their "rows" are indexed by element position.
            for nested in sub_tables {
                encode_sub_table_range(nested, elem_start, elem_end, out);
            }
        }
    }
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
        TAG_STRPREFIX_HEX => {
            let pfx_len     = rd_varint!();
            let pfx_bytes   = rd_bytes!(pfx_len);
            let prefix = std::str::from_utf8(pfx_bytes)
                .map_err(|_| ScteError::DecodeError("columnar: TAG_STRPREFIX_HEX bad utf8".into()))?;
            let hex_byte_len = rd_varint!();
            let hex_char_len = hex_byte_len * 2;
            let mut result = Vec::with_capacity(row_count);
            for _ in 0..row_count {
                let packed = rd_bytes!(hex_byte_len);
                let mut s = String::with_capacity(pfx_len + hex_char_len);
                s.push_str(prefix);
                for &byte in packed {
                    static HEX: &[u8; 16] = b"0123456789abcdef";
                    s.push(HEX[(byte >> 4) as usize] as char);
                    s.push(HEX[(byte & 0x0F) as usize] as char);
                }
                result.push(json_quote(&s));
            }
            result
        }
        TAG_ENUM_RANS => {
            // Level 1 local frequency model: FreqTable built from this column's
            // index distribution at encode time; rANS-decoded here.
            let variants = decode_variant_table(data, pos)?;
            let ft_len   = rd_varint!();
            let ft_bytes = rd_bytes!(ft_len);
            let (freq, _) = FreqTable::deserialize(ft_bytes, 0)
                .map_err(|e| ScteError::DecodeError(format!("columnar: ENUM_RANS ft: {e}")))?;
            let rans_len   = rd_varint!();
            let rans_bytes = rd_bytes!(rans_len);
            let (idx_bytes, _) = rans_decode(rans_bytes, &freq, row_count, 0)
                .map_err(|e| ScteError::DecodeError(format!("columnar: ENUM_RANS decode: {e}")))?;
            if idx_bytes.len() != row_count {
                return Err(ScteError::DecodeError(
                    format!("columnar: ENUM_RANS got {} symbols, expected {row_count}", idx_bytes.len()),
                ));
            }
            idx_bytes.into_iter().map(|idx| {
                let s = variants.get(idx as usize).cloned()
                    .unwrap_or_else(|| format!("?{idx}"));
                json_quote(&s)
            }).collect()
        }
        TAG_ENUM_RLE => {
            let variants = decode_variant_table(data, pos)?;
            let run_count = rd_varint!();
            let mut result = Vec::with_capacity(row_count);
            for _ in 0..run_count {
                let idx = *data.get(*pos)
                    .ok_or_else(|| ScteError::DecodeError("columnar: TAG_ENUM_RLE missing idx".into()))?;
                *pos += 1;
                let run_len = rd_varint!();
                let s = variants.get(idx as usize).cloned()
                    .unwrap_or_else(|| format!("?{idx}"));
                let quoted = json_quote(&s);
                for _ in 0..run_len {
                    result.push(quoted.clone());
                }
            }
            if result.len() != row_count {
                return Err(ScteError::DecodeError(
                    format!("columnar: TAG_ENUM_RLE decoded {} rows, expected {row_count}", result.len()),
                ));
            }
            result
        }
        TAG_INT_RANS => {
            let ft_len   = rd_varint!();
            let ft_bytes = rd_bytes!(ft_len);
            let (freq, _) = FreqTable::deserialize(ft_bytes, 0)
                .map_err(|e| ScteError::DecodeError(format!("columnar: INT_RANS ft: {e}")))?;
            let delta_byte_count = rd_varint!();
            let rans_len   = rd_varint!();
            let rans_bytes = rd_bytes!(rans_len);
            let (delta_bytes, _) = rans_decode(rans_bytes, &freq, delta_byte_count, 0)
                .map_err(|e| ScteError::DecodeError(format!("columnar: INT_RANS rans_decode: {e}")))?;
            let ints = decode_delta_ints(&delta_bytes)
                .ok_or_else(|| ScteError::DecodeError("columnar: INT_RANS delta decode fail".into()))?;
            if ints.len() != row_count {
                return Err(ScteError::DecodeError(
                    format!("columnar: INT_RANS got {} ints, expected {row_count}", ints.len()),
                ));
            }
            ints.into_iter().map(|v| v.to_string()).collect()
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
        TAG_UUID => {
            let mut result = Vec::with_capacity(row_count);
            for _ in 0..row_count {
                let bytes = rd_bytes!(16);
                result.push(json_quote(&bytes_to_uuid(bytes)));
            }
            result
        }
        TAG_BASE64 => {
            let decoded_len = rd_varint!();
            let mut result = Vec::with_capacity(row_count);
            for _ in 0..row_count {
                let bytes = rd_bytes!(decoded_len);
                result.push(json_quote(&base64_encode_bytes(bytes)));
            }
            result
        }
        TAG_SUB_TABLE => {
            let total_elements = rd_varint!();
            let count_len = rd_varint!();
            let count_body = rd_bytes!(count_len);
            let counts_i64 = decode_delta_ints(count_body)
                .ok_or_else(|| ScteError::DecodeError("columnar: TAG_SUB_TABLE bad counts".into()))?;
            if counts_i64.len() != row_count {
                return Err(ScteError::DecodeError(
                    format!("columnar: TAG_SUB_TABLE counts len {} != {row_count}", counts_i64.len()),
                ));
            }
            let counts: Vec<usize> = counts_i64.iter().map(|&c| c as usize).collect();
            let sub_col_count = rd_varint!();
            let mut sub_decoded: Vec<(String, Vec<String>)> = Vec::with_capacity(sub_col_count);
            for _ in 0..sub_col_count {
                let entry = decode_one_column(data, pos, total_elements, &sub_decoded)?;
                sub_decoded.push(entry);
            }
            // Reconstruct one JSON array string per parent row
            let is_scalar_col = sub_col_count == 1 && sub_decoded[0].0.is_empty();
            let mut result = Vec::with_capacity(row_count);
            let mut offset = 0usize;
            for &cnt in &counts {
                let arr: String = if cnt == 0 {
                    "[]".into()
                } else if is_scalar_col {
                    let vals = &sub_decoded[0].1;
                    let inner = vals[offset..offset + cnt].join(",");
                    format!("[{inner}]")
                } else {
                    let slice: Vec<(String, Vec<String>)> = sub_decoded
                        .iter()
                        .map(|(p, v)| (p.clone(), v[offset..offset + cnt].to_vec()))
                        .collect();
                    let bytes = reconstruct_json(&slice, cnt);
                    String::from_utf8(bytes).unwrap_or_else(|_| "[]".into())
                };
                result.push(arr);
                offset += cnt;
            }
            result
        }
        TAG_FLOAT_FIXED_RANS => {
            let decimals = *data.get(*pos)
                .ok_or_else(|| ScteError::DecodeError("columnar: FLOAT_FIXED_RANS missing decimals".into()))?;
            *pos += 1;
            let ft_len   = rd_varint!();
            let ft_bytes = rd_bytes!(ft_len);
            let (freq, _) = FreqTable::deserialize(ft_bytes, 0)
                .map_err(|e| ScteError::DecodeError(format!("columnar: FLOAT_FIXED_RANS ft: {e}")))?;
            let delta_byte_count = rd_varint!();
            let rans_len   = rd_varint!();
            let rans_bytes = rd_bytes!(rans_len);
            let (delta_bytes, _) = rans_decode(rans_bytes, &freq, delta_byte_count, 0)
                .map_err(|e| ScteError::DecodeError(format!("columnar: FLOAT_FIXED_RANS rans_decode: {e}")))?;
            let scaled = decode_delta_ints(&delta_bytes)
                .ok_or_else(|| ScteError::DecodeError("columnar: FLOAT_FIXED_RANS delta fail".into()))?;
            if scaled.len() != row_count {
                return Err(ScteError::DecodeError(
                    format!("columnar: FLOAT_FIXED_RANS got {} values, expected {row_count}", scaled.len()),
                ));
            }
            scaled.into_iter().map(|s| format_float_fixed(s, decimals)).collect()
        }
        TAG_TIMESTAMP_RANS => {
            let ft_len   = rd_varint!();
            let ft_bytes = rd_bytes!(ft_len);
            let (freq, _) = FreqTable::deserialize(ft_bytes, 0)
                .map_err(|e| ScteError::DecodeError(format!("columnar: TIMESTAMP_RANS ft: {e}")))?;
            let delta_byte_count = rd_varint!();
            let rans_len   = rd_varint!();
            let rans_bytes = rd_bytes!(rans_len);
            let (delta_bytes, _) = rans_decode(rans_bytes, &freq, delta_byte_count, 0)
                .map_err(|e| ScteError::DecodeError(format!("columnar: TIMESTAMP_RANS rans_decode: {e}")))?;
            let epochs = decode_delta_ints(&delta_bytes)
                .ok_or_else(|| ScteError::DecodeError("columnar: TIMESTAMP_RANS delta fail".into()))?;
            if epochs.len() != row_count {
                return Err(ScteError::DecodeError(
                    format!("columnar: TIMESTAMP_RANS got {} values, expected {row_count}", epochs.len()),
                ));
            }
            epochs.into_iter().map(|e| json_quote(&epoch_to_iso8601(e))).collect()
        }
        TAG_RAW_STR_RANS => {
            let lens_len   = rd_varint!();
            let lens_bytes = rd_bytes!(lens_len);
            let lens_i64   = decode_delta_ints(lens_bytes)
                .ok_or_else(|| ScteError::DecodeError("columnar: RAW_STR_RANS bad lengths".into()))?;
            if lens_i64.len() != row_count {
                return Err(ScteError::DecodeError(
                    format!("columnar: RAW_STR_RANS lens {} != row_count {row_count}", lens_i64.len()),
                ));
            }
            let ft_len   = rd_varint!();
            let ft_bytes = rd_bytes!(ft_len);
            let (freq, _) = FreqTable::deserialize(ft_bytes, 0)
                .map_err(|e| ScteError::DecodeError(format!("columnar: RAW_STR_RANS ft: {e}")))?;
            let orig_byte_count = rd_varint!();
            let rans_len   = rd_varint!();
            let rans_bytes = rd_bytes!(rans_len);
            let (all_bytes, _) = rans_decode(rans_bytes, &freq, orig_byte_count, 0)
                .map_err(|e| ScteError::DecodeError(format!("columnar: RAW_STR_RANS rans_decode: {e}")))?;
            let mut result   = Vec::with_capacity(row_count);
            let mut byte_pos = 0usize;
            for l in lens_i64 {
                let len = l as usize;
                let end = byte_pos + len;
                if end > all_bytes.len() {
                    return Err(ScteError::DecodeError("columnar: RAW_STR_RANS byte overrun".into()));
                }
                let s = std::str::from_utf8(&all_bytes[byte_pos..end])
                    .map_err(|_| ScteError::DecodeError("columnar: RAW_STR_RANS bad utf8".into()))?
                    .to_owned();
                result.push(json_quote(&s));
                byte_pos = end;
            }
            result
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
        pub entries: Vec<(K, V)>,
    }
    impl<K: PartialEq + Clone, V: Clone> IndexMap<K, V> {
        pub fn new() -> Self { Self { entries: Vec::new() } }
        #[allow(dead_code)]
        pub fn with_capacity(n: usize) -> Self { Self { entries: Vec::with_capacity(n) } }
        pub fn insert(&mut self, key: K, value: V) {
            for (k, v) in &mut self.entries {
                if k == &key { *v = value; return; }
            }
            self.entries.push((key, value));
        }
        pub fn get(&self, key: &K) -> Option<&V> {
            self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
        }
        pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
            self.entries.iter_mut().find(|(k, _)| k == key).map(|(_, v)| v)
        }
        pub fn contains_key(&self, key: &K) -> bool {
            self.entries.iter().any(|(k, _)| k == key)
        }
        pub fn keys(&self) -> impl Iterator<Item = &K> {
            self.entries.iter().map(|(k, _)| k)
        }
        #[allow(dead_code)]
        pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
            self.entries.iter().map(|(k, v)| (k, v))
        }
        #[allow(dead_code)]
        pub fn len(&self) -> usize { self.entries.len() }
        #[allow(dead_code)]
        pub fn is_empty(&self) -> bool { self.entries.is_empty() }
        #[allow(dead_code)]
        pub fn push_raw(&mut self, key: K, value: V) {
            // Unchecked insert (for use when keys are known unique)
            self.entries.push((key, value));
        }
    }
    impl<K: PartialEq + Clone, V: Clone> IntoIterator for IndexMap<K, V> {
        type Item = (K, V);
        type IntoIter = std::vec::IntoIter<(K, V)>;
        fn into_iter(self) -> Self::IntoIter { self.entries.into_iter() }
    }
    impl<K: PartialEq + Clone + std::fmt::Debug, V: Clone + std::fmt::Debug> std::fmt::Debug
        for IndexMap<K, V>
    {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_map()
                .entries(self.entries.iter().map(|(k, v)| (k, v)))
                .finish()
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
    fn nested_array_of_scalars() {
        // Each row has a "tags" field containing an array of strings
        let json: Vec<u8> = (0..10)
            .map(|i| format!(r#"{{"id":{i},"tags":["alpha","beta","gamma"]}}"#))
            .collect::<Vec<_>>()
            .join(",")
            .pipe_wrapped_in_array();
        roundtrip(&json);
    }

    #[test]
    fn nested_array_of_objects() {
        // Each row has a "friends" field containing an array of objects
        let json: Vec<u8> = (0..8)
            .map(|i| format!(
                r#"{{"id":{i},"friends":[{{"name":"alice","age":30}},{{"name":"bob","age":25}}]}}"#
            ))
            .collect::<Vec<_>>()
            .join(",")
            .pipe_wrapped_in_array();
        roundtrip(&json);
    }

    #[test]
    fn nested_array_varying_counts() {
        // Rows with different numbers of friends (including zero)
        let rows = [
            r#"{"id":0,"friends":[]}"#,
            r#"{"id":1,"friends":[{"name":"alice","score":10}]}"#,
            r#"{"id":2,"friends":[{"name":"bob","score":20},{"name":"carol","score":30}]}"#,
            r#"{"id":3,"friends":[]}"#,
            r#"{"id":4,"friends":[{"name":"dave","score":40}]}"#,
        ];
        let json: Vec<u8> = rows.join(",").pipe_wrapped_in_array();
        roundtrip(&json);
    }

    #[test]
    fn deep_nested_arrays() {
        // Two levels of nesting: rows → friends → hobbies
        let rows = [
            r#"{"id":0,"friends":[{"name":"alice","hobbies":["chess","hiking"]},{"name":"bob","hobbies":["chess"]}]}"#,
            r#"{"id":1,"friends":[{"name":"carol","hobbies":["tennis"]}]}"#,
            r#"{"id":2,"friends":[{"name":"dave","hobbies":["chess","tennis","hiking"]}]}"#,
            r#"{"id":3,"friends":[]}"#,
        ];
        let json: Vec<u8> = rows.join(",").pipe_wrapped_in_array();
        roundtrip(&json);
    }

    #[test]
    fn uuid_column_roundtrip() {
        // Lowercase UUID column — should activate TAG_UUID, packing 16B/row vs 36 chars
        let json: Vec<u8> = (0..20)
            .map(|i| format!(
                r#"{{"id":{i},"trace":"550e8400-e29b-41d4-a716-{:012x}"}}"#, i as u64
            ))
            .collect::<Vec<_>>()
            .join(",")
            .pipe_wrapped_in_array();
        roundtrip(&json);
    }

    #[test]
    fn uuid_helpers_roundtrip() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        assert!(is_uuid(uuid));
        let packed = uuid_to_bytes(uuid);
        let unpacked = bytes_to_uuid(&packed);
        assert_eq!(unpacked, uuid);
    }

    #[test]
    fn base64_column_roundtrip() {
        // Fixed-length base64 strings — should activate TAG_BASE64
        let payloads = [
            "SGVsbG8gV29ybGQh",  // "Hello World!" in base64 (16 chars = 12 bytes)
            "QW5vdGhlciBUZXN0",
            "VGhpcmQgUGF5bG9h",
            "Rm91cnRoIGVudHJ5",
            "RmlmdGggcGF5bG9h",
        ];
        let json: Vec<u8> = payloads.iter().enumerate()
            .map(|(i, p)| format!(r#"{{"id":{i},"payload":"{p}"}}"#))
            .collect::<Vec<_>>()
            .join(",")
            .pipe_wrapped_in_array();
        roundtrip(&json);
    }

    #[test]
    fn base64_helpers_roundtrip() {
        let original = b"Hello, World! This is a test of base64 encoding.";
        let encoded = base64_encode_bytes(original);
        let decoded = base64_decode_str(&encoded);
        assert_eq!(decoded, original);
    }

    #[test]
    fn uuid_detect_rejects_non_uuid() {
        assert!(!is_uuid("not-a-uuid"));
        assert!(!is_uuid("550e8400-e29b-41d4-a716-44665544000Z")); // invalid hex
        assert!(!is_uuid("550e8400e29b41d4a716446655440000"));       // missing hyphens
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

    // ── Bug-A regression: uppercase UUID must NOT be silently lowercased ─────────
    #[test]
    fn uppercase_uuid_must_not_mangle_case() {
        // TAG_UUID decoder emits lowercase, so an uppercase UUID must fall through
        // to TAG_RAW_STR and be preserved verbatim.
        let json: Vec<u8> = (0..5)
            .map(|i| format!(r#"{{"id":"AABBCCDD-EEFF-1122-3344-{:012X}"}}"#, i))
            .collect::<Vec<_>>()
            .join(",")
            .pipe_wrapped_in_array();
        roundtrip(&json);
    }

    // ── Bug-B regression: uppercase hex suffix must NOT be silently lowercased ──
    #[test]
    fn uppercase_hex_suffix_must_not_mangle_case() {
        let json: Vec<u8> = (0..5)
            .map(|i| format!(r#"{{"token":"prefix-{:04X}"}}"#, i * 7))
            .collect::<Vec<_>>()
            .join(",")
            .pipe_wrapped_in_array();
        roundtrip(&json);
    }

    // ── Bug-C regression: array-of-array must not be silently nulled ─────────────
    #[test]
    fn array_of_array_not_silently_nulled() {
        // A top-level array whose elements are arrays themselves cannot be encoded
        // losslessly via the sub-table path.  The engine must fall back to the raw
        // text pipeline and round-trip the data byte-for-byte.
        let json = br#"[[1,2,3],[4,5,6],[7,8,9]]"#;
        let encoded = crate::codec::encoder::encode(json).expect("encode failed");
        let decoded = crate::codec::decoder::decode(&encoded).expect("decode failed");
        let canon_in  = crate::pipelines::text::canonicalize_json(json).unwrap();
        let canon_out = crate::pipelines::text::canonicalize_json(&decoded).unwrap();
        assert_eq!(canon_in, canon_out, "array-of-array roundtrip mismatch");
    }

    // ── Bug-D regression: heterogeneous sub-table field must survive ─────────────
    #[test]
    fn heterogeneous_sub_table_field_survives() {
        // Each row has a "tags" array, but the objects inside have different keys.
        // The columnar engine must NOT drop the field; it must fall back gracefully.
        let json = br#"[{"id":1,"tags":[{"a":1},{"b":2}]},{"id":2,"tags":[{"c":3}]}]"#;
        let encoded = crate::codec::encoder::encode(json).expect("encode failed");
        let decoded = crate::codec::decoder::decode(&encoded).expect("decode failed");
        let canon_in  = crate::pipelines::text::canonicalize_json(json).unwrap();
        let canon_out = crate::pipelines::text::canonicalize_json(&decoded).unwrap();
        assert_eq!(canon_in, canon_out, "heterogeneous sub-table mismatch");
    }

    // ── Bug-E regression: i64 extremes must not overflow/panic ───────────────────
    #[test]
    fn integer_extremes_roundtrip() {
        use crate::pipelines::text::delta::integer::{encode_delta_ints, decode_delta_ints};
        let cases: &[&[i64]] = &[
            &[i64::MIN, i64::MAX],
            &[i64::MAX, i64::MIN],
            &[i64::MIN, i64::MIN + 1, i64::MIN + 2],
            &[i64::MAX - 2, i64::MAX - 1, i64::MAX],
            &[0, i64::MIN, i64::MAX, 0],
        ];
        for &vals in cases {
            let encoded = encode_delta_ints(vals);
            let decoded = decode_delta_ints(&encoded).unwrap_or_else(|| panic!("decode failed for {vals:?}"));
            assert_eq!(vals, decoded.as_slice(), "i64 extreme roundtrip mismatch for {vals:?}");
        }
    }

    // ── Gap: passthrough binary must round-trip byte-for-exact-byte ──────────────
    #[test]
    fn passthrough_binary_byte_equality() {
        // Build a binary blob that looks nothing like JSON (starts with 0x00).
        // The encoder must use the passthrough path and reconstructed bytes
        // must be bit-for-bit identical to the input.
        let binary: Vec<u8> = (0u8..=255).collect();
        let encoded = crate::codec::encoder::encode(&binary).expect("encode failed");
        let decoded = crate::codec::decoder::decode(&encoded).expect("decode failed");
        assert_eq!(binary, decoded, "passthrough binary is not byte-exact after roundtrip");
    }

    // ── Gap: UTF-8 edge cases must survive the full pipeline ─────────────────────
    #[test]
    fn utf8_edge_cases_roundtrip() {
        // emoji, BMP multi-byte sequences, escaped solidus, unicode escapes
        // Note: \u0000 (null) is explicitly excluded — strict JSON parsers
        // reject unescaped NUL bytes in strings, which is correct behaviour.
        let json: Vec<u8> = (0..5)
            .map(|i| format!(r#"{{"msg":"hello 🎉 \u4e2d\u6587 caf\u00e9 {i}"}}"#))
            .collect::<Vec<_>>()
            .join(",")
            .pipe_wrapped_in_array();
        roundtrip(&json);
    }

    // ── Gap: two-pass pipeline explicit roundtrip (non-columnar input) ───────────
    #[test]
    fn two_pass_pipeline_non_columnar_roundtrip() {
        // A single JSON object (not an array of objects) goes through the two-pass
        // pipeline, NOT the columnar path.  Assert it round-trips correctly.
        let inputs: &[&[u8]] = &[
            br#"{"a":1,"b":"hello","c":true,"d":null}"#,
            br#"{"nested":{"x":1,"y":[2,3,4]}}"#,
            br#"[[1,2],[3,4],[5,6]]"#,
            br#"[1,"two",3.0,null,false]"#,
        ];
        for &input in inputs {
            let encoded = crate::codec::encoder::encode(input).expect("encode failed");
            let decoded = crate::codec::decoder::decode(&encoded).expect("decode failed");
            let c_in  = crate::pipelines::text::canonicalize_json(input).unwrap();
            let c_out = crate::pipelines::text::canonicalize_json(&decoded).unwrap();
            assert_eq!(c_in, c_out, "two-pass mismatch for {}", std::str::from_utf8(input).unwrap_or("<binary>"));
        }
    }

    // ── New feature tests ─────────────────────────────────────────────────────

    #[test]
    fn multi_chunk_roundtrip_above_threshold() {
        // Generate COLUMNAR_CHUNK_ROWS+50 rows to force multi-chunk encoding.
        use super::COLUMNAR_CHUNK_ROWS;
        let n = COLUMNAR_CHUNK_ROWS + 50;
        let json: Vec<u8> = (0..n)
            .map(|i| {
                let s = if i % 3 == 0 { "ok" } else if i % 3 == 1 { "warn" } else { "err" };
                format!(r#"{{"id":{i},"status":"{s}","score":{:.2}}}"#, (i % 100) as f64 * 0.01)
            })
            .collect::<Vec<_>>()
            .join(",")
            .pipe_wrapped_in_array();

        // Encoding must produce multiple sections.
        let chunks = try_encode_columnar_chunks_from_tokens(
            &crate::pipelines::text::tokenizer::tokenize_json(&json).unwrap(),
        ).expect("chunked encode failed");
        assert!(chunks.len() >= 2, "expected ≥2 chunks for {} rows, got {}", n, chunks.len());

        // Decode must round-trip correctly.
        let encoded = crate::codec::encoder::encode(&json).expect("encode failed");
        let decoded = crate::codec::decoder::decode(&encoded).expect("decode failed");
        let c_in  = crate::pipelines::text::canonicalize_json(&json).unwrap();
        let c_out = crate::pipelines::text::canonicalize_json(&decoded).unwrap();
        assert_eq!(c_in, c_out, "multi-chunk roundtrip mismatch");
    }

    #[test]
    fn multi_chunk_row_order_preserved() {
        // IDs 0..N must round-trip in correct order after multi-chunk decode.
        // Verified by canonical JSON equality (order must match).
        use super::COLUMNAR_CHUNK_ROWS;
        let n = COLUMNAR_CHUNK_ROWS + 100;
        let json: Vec<u8> = (0..n)
            .map(|i| format!(r#"{{"id":{i},"val":{}}}"#, i * 2))
            .collect::<Vec<_>>()
            .join(",")
            .pipe_wrapped_in_array();

        let encoded = crate::codec::encoder::encode(&json).expect("encode failed");
        let decoded = crate::codec::decoder::decode(&encoded).expect("decode failed");
        let c_in  = crate::pipelines::text::canonicalize_json(&json).unwrap();
        let c_out = crate::pipelines::text::canonicalize_json(&decoded).unwrap();
        assert_eq!(c_in, c_out, "multi-chunk row order mismatch");

        // Quick row-count sanity check.
        let id_fields = c_out.windows(5).filter(|w| *w == b"\"id\":").count();
        assert_eq!(id_fields, n, "expected {n} id fields, found {id_fields}");
    }

    #[test]
    fn float_fixed_rans_roundtrip() {
        // Enough rows (≥64) with smooth float values to trigger FLOAT_FIXED_RANS.
        let json: Vec<u8> = (0..200)
            .map(|i| format!(r#"{{"v":{:.3}}}"#, (i % 10) as f64 * 0.001))
            .collect::<Vec<_>>()
            .join(",")
            .pipe_wrapped_in_array();
        roundtrip(&json);
    }

    #[test]
    fn timestamp_rans_roundtrip() {
        // ISO-8601 timestamps with known period — some variants may use TIMESTAMP_RANS.
        let base = 1700000000i64; // arbitrary epoch
        let json: Vec<u8> = (0..200)
            .map(|i| {
                let ts = base + (i as i64 * 60); // 1-minute intervals
                let dt = crate::pipelines::text::delta::timestamp::epoch_to_iso8601(ts);
                format!(r#"{{"ts":"{dt}"}}"#)
            })
            .collect::<Vec<_>>()
            .join(",")
            .pipe_wrapped_in_array();
        roundtrip(&json);
    }

    #[test]
    fn raw_str_rans_roundtrip() {
        // High-cardinality strings with a skewed character distribution
        // (all lowercase letters + digits) to exercise TAG_RAW_STR_RANS.
        let json: Vec<u8> = (0..200)
            .map(|i| {
                // Names drawn from a small alphabet — rANS should compress well.
                let name = format!("user_{:08}", i % 50);
                format!(r#"{{"name":"{name}","n":{i}}}"#)
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
