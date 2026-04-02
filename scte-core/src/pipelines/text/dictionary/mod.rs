/// Phase 3 — Dictionary
///
/// Owns the `Dictionary` type: build from a token stream, lookup by ID,
/// and serialize / deserialize for the SCTE DICT section wire format.
///
/// Encoding / decoding of token streams using the dictionary lives in the
/// companion module [`codec`].
///
/// # Algorithm (plans.md §5.6)
/// 1. Single-pass frequency count over all `Key` and `Str` tokens.
/// 2. Discard entries with frequency < `min_freq` (default 1; prod default 3).
/// 3. Sort descending by frequency — most common token gets `dict_id = 0`.
///    Ties broken by byte-order of value string (determinism).
/// 4. Assign sequential `u16` IDs.  Max capacity: 65 535 entries.
/// 5. Serialize to DICT section wire format for the SCTE container.

pub mod codec;

// Re-export codec types so callers can import them via the `dictionary` path,
// e.g. `dictionary::{EncodedPayload, EncodedToken}` — identical to before the split.
pub use codec::{EncodedPayload, EncodedToken, encode_with_dict, decode_with_dict};

use std::collections::BTreeMap;

use crate::{
    error::ScteError,
    pipelines::text::tokenizer::{Token, TokenKind, TokenPayload},
    varint::{decode_usize, encode_usize},
};

// ── Entry kind ────────────────────────────────────────────────────────────────

/// Discriminant stored in the DICT section for each entry.
///
/// Only `Key` and `Str` token kinds carry string payloads and are eligible
/// for dictionary substitution. All other kinds are left as-is in the
/// encoded stream.
///
/// Wire byte:
/// - `0x01` = Key
/// - `0x02` = Str
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DictEntryKind {
    Key = 0x01,
    Str = 0x02,
}

impl DictEntryKind {
    pub(crate) fn from_token_kind(kind: TokenKind) -> Option<Self> {
        match kind {
            TokenKind::Key => Some(Self::Key),
            TokenKind::Str => Some(Self::Str),
            _              => None,
        }
    }

    pub fn to_token_kind(self) -> TokenKind {
        match self {
            Self::Key => TokenKind::Key,
            Self::Str => TokenKind::Str,
        }
    }

    pub(crate) fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Key),
            0x02 => Some(Self::Str),
            _    => None,
        }
    }
}

// ── Dictionary entry ──────────────────────────────────────────────────────────

/// One slot in the dictionary, addressed by a `u16` ID.
///
/// Frequencies are NOT persisted in the wire format — the DICT section stores
/// only the table needed for decoding. Frequency data is ephemeral, used only
/// during `build()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DictEntry {
    pub kind:  DictEntryKind,
    pub value: String,
}

// ── Dictionary ────────────────────────────────────────────────────────────────

/// A built dictionary mapping high-frequency string tokens to compact IDs.
///
/// # Invariants
/// - `entries[id]` is the authoritative entry for `dict_id = id`.
/// - `index` is the exact inverse: `index[(kind, value)] == id` iff
///   `entries[id] == DictEntry { kind, value }`.
/// - `entries.len() <= 65535` (enforced in `build()`).
#[derive(Debug, Clone)]
pub struct Dictionary {
    pub(crate) entries: Vec<DictEntry>,
    index:              BTreeMap<(DictEntryKind, String), u16>,
}

impl Dictionary {
    // ── Construction ──────────────────────────────────────────────────────────

    /// Build a dictionary from a token stream.
    ///
    /// Only `Key` and `Str` tokens with string payloads are considered.
    /// Integer, float, bool, null, and structural tokens are never added.
    ///
    /// # Parameters
    /// - `tokens`   — flat token stream from Phase 2 `tokenize_json`
    /// - `min_freq` — minimum frequency threshold; tokens below this are not
    ///                added to the dictionary.  Use `1` during testing and
    ///                `3` (plans.md default) in production.
    ///
    /// # Determinism
    /// Sort order is: frequency descending, then `(kind, value)` byte-order
    /// ascending on ties. This is fully deterministic for identical input.
    ///
    /// # Capacity
    /// If more than 65 535 entries would be created, excess entries are
    /// silently truncated (the stream encoder falls back to literal strings
    /// for those low-frequency tokens below the 65 535 cut).
    pub fn build(tokens: &[Token], min_freq: u32) -> Self {
        // ── 1. frequency count ───────────────────────────────────────────────
        let mut freq: BTreeMap<(DictEntryKind, String), u32> = BTreeMap::new();

        for token in tokens {
            let Some(ek) = DictEntryKind::from_token_kind(token.kind) else {
                continue;
            };
            let TokenPayload::Str(ref s) = token.payload else {
                continue;
            };
            *freq.entry((ek, s.clone())).or_insert(0) += 1;
        }

        // ── 2. filter by min_freq ────────────────────────────────────────────
        let mut candidates: Vec<((DictEntryKind, String), u32)> = freq
            .into_iter()
            .filter(|(_, f)| *f >= min_freq)
            .collect();

        // ── 3. sort: descending frequency, then ascending (kind, value) ─────
        candidates.sort_unstable_by(|((ka, va), fa), ((kb, vb), fb)| {
            fb.cmp(fa)                           // frequency desc
                .then_with(|| ka.cmp(kb))         // kind asc (tie-break)
                .then_with(|| va.as_bytes().cmp(vb.as_bytes())) // value asc
        });

        // ── 4. assign IDs (cap at 65535) ─────────────────────────────────────
        let capacity = candidates.len().min(65535);
        let mut entries = Vec::with_capacity(capacity);
        let mut index   = BTreeMap::new();

        for ((kind, value), _freq) in candidates.into_iter().take(65535) {
            let id = entries.len() as u16;
            index.insert((kind, value.clone()), id);
            entries.push(DictEntry { kind, value });
        }

        Self { entries, index }
    }

    /// Create an empty dictionary (no substitutions will be made).
    pub fn empty() -> Self {
        Self { entries: Vec::new(), index: BTreeMap::new() }
    }

    // ── Lookup ────────────────────────────────────────────────────────────────

    /// Look up a string token in the dictionary.
    ///
    /// Returns the `dict_id` if the token is in the dictionary, or `None` if
    /// it should be stored literally in the encoded stream.
    pub fn lookup(&self, kind: TokenKind, value: &str) -> Option<u16> {
        let ek = DictEntryKind::from_token_kind(kind)?;
        self.index.get(&(ek, value.to_owned())).copied()
    }

    /// Retrieve an entry by its `dict_id`.
    pub fn get(&self, id: u16) -> Option<&DictEntry> {
        self.entries.get(id as usize)
    }

    /// Number of entries in the dictionary.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the dictionary has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    // ── Wire format ───────────────────────────────────────────────────────────

    /// Serialize to the DICT section wire format (plans.md §5.6):
    ///
    /// ```text
    /// varint(K)                          — number of entries
    /// for each entry:
    ///   u8    type_byte                  — 0x01=Key, 0x02=Str
    ///   varint(value_len)                — UTF-8 byte length
    ///   [u8]  value_bytes                — raw UTF-8
    /// ```
    ///
    /// Entries are written in `dict_id` order (0, 1, 2, …) so the decoder
    /// can reconstruct IDs by position.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_usize(self.entries.len(), &mut out);
        for entry in &self.entries {
            out.push(entry.kind as u8);
            let bytes = entry.value.as_bytes();
            encode_usize(bytes.len(), &mut out);
            out.extend_from_slice(bytes);
        }
        out
    }

    /// Deserialize from a DICT section payload produced by `serialize()`.
    ///
    /// # Errors
    /// Returns `ScteError::DecodeError` for:
    /// - truncated buffer
    /// - unknown type byte
    /// - invalid UTF-8 in a value string
    /// - entry count exceeds 65 535
    pub fn deserialize(data: &[u8]) -> Result<Self, ScteError> {
        let mut pos = 0;

        let (count, consumed) = decode_usize(data, pos)
            .ok_or_else(|| ScteError::DecodeError("dict: truncated entry count".into()))?;
        pos += consumed;

        if count > 65535 {
            return Err(ScteError::DecodeError(
                format!("dict: entry count {count} exceeds u16::MAX"),
            ));
        }

        let mut entries = Vec::with_capacity(count);
        let mut index   = BTreeMap::new();

        for i in 0..count {
            if pos >= data.len() {
                return Err(ScteError::DecodeError(
                    format!("dict: truncated at entry {i} type byte"),
                ));
            }
            let kind = DictEntryKind::from_byte(data[pos])
                .ok_or_else(|| ScteError::DecodeError(
                    format!("dict: unknown type byte 0x{:02X} at entry {i}", data[pos]),
                ))?;
            pos += 1;

            let (len, consumed) = decode_usize(data, pos)
                .ok_or_else(|| ScteError::DecodeError(
                    format!("dict: truncated at entry {i} value length"),
                ))?;
            pos += consumed;

            if pos + len > data.len() {
                return Err(ScteError::DecodeError(
                    format!("dict: entry {i} value overruns buffer"),
                ));
            }
            let value = std::str::from_utf8(&data[pos..pos + len])
                .map_err(|e| ScteError::DecodeError(
                    format!("dict: entry {i} invalid UTF-8: {e}"),
                ))?
                .to_owned();
            pos += len;

            let id = entries.len() as u16;
            index.insert((kind, value.clone()), id);
            entries.push(DictEntry { kind, value });
        }

        Ok(Self { entries, index })
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipelines::text::tokenizer::tokenize_json;

    fn tokens(s: &str) -> Vec<Token> {
        tokenize_json(s.as_bytes()).expect("tokenize failed")
    }

    fn build(s: &str, min_freq: u32) -> Dictionary {
        Dictionary::build(&tokens(s), min_freq)
    }

    // ── Dictionary build ──────────────────────────────────────────────────────

    #[test]
    fn empty_token_stream_produces_empty_dict() {
        let dict = Dictionary::build(&[], 1);
        assert_eq!(dict.len(), 0);
    }

    #[test]
    fn single_key_is_added() {
        let dict = build(r#"{"name":"Alice"}"#, 1);
        assert!(dict.lookup(TokenKind::Key, "name").is_some());
    }

    #[test]
    fn single_str_value_is_added() {
        let dict = build(r#"{"name":"Alice"}"#, 1);
        assert!(dict.lookup(TokenKind::Str, "Alice").is_some());
    }

    #[test]
    fn primitives_not_added_to_dict() {
        let dict = build(r#"{"active":true,"id":1,"score":9.9}"#, 1);
        // Only "active", "id", "score" keys; no bool/int/float
        assert_eq!(dict.len(), 3);
    }

    #[test]
    fn higher_frequency_gets_lower_id() {
        let toks = tokens(r#"{"x":1,"x":2,"x":3,"y":1}"#);
        let dict = Dictionary::build(&toks, 1);
        let id_x = dict.lookup(TokenKind::Key, "x").expect("x in dict");
        let id_y = dict.lookup(TokenKind::Key, "y").expect("y in dict");
        assert!(id_x < id_y, "higher-freq token must have lower id");
    }

    #[test]
    fn min_freq_filters_low_frequency_entries() {
        let toks = tokens(r#"{"x":1,"x":2,"y":1}"#);
        let dict = Dictionary::build(&toks, 2);
        assert!(dict.lookup(TokenKind::Key, "x").is_some(), "x should survive");
        assert!(dict.lookup(TokenKind::Key, "y").is_none(), "y should be filtered");
    }

    #[test]
    fn key_and_str_are_independent() {
        let dict = build(r#"{"name":"name"}"#, 1);
        let id_key = dict.lookup(TokenKind::Key, "name").expect("key name");
        let id_str = dict.lookup(TokenKind::Str, "name").expect("str name");
        assert_ne!(id_key, id_str, "Key and Str must have separate IDs");
    }

    #[test]
    fn lookup_missing_token_returns_none() {
        let dict = build(r#"{"a":1}"#, 1);
        assert!(dict.lookup(TokenKind::Key, "b").is_none());
    }

    #[test]
    fn get_by_id_roundtrips() {
        let dict = build(r#"{"name":"Alice"}"#, 1);
        let id    = dict.lookup(TokenKind::Key, "name").unwrap();
        let entry = dict.get(id).unwrap();
        assert_eq!(entry.kind,  DictEntryKind::Key);
        assert_eq!(entry.value, "name");
    }

    #[test]
    fn get_out_of_range_returns_none() {
        let dict = build(r#"{"a":1}"#, 1);
        assert!(dict.get(9999).is_none());
    }

    #[test]
    fn build_is_deterministic() {
        let input = r#"{"z":1,"a":2,"m":1,"a":3}"#;
        let toks = tokens(input);
        assert_eq!(
            Dictionary::build(&toks, 1).serialize(),
            Dictionary::build(&toks, 1).serialize(),
            "build must be deterministic"
        );
    }

    // ── Serialize / deserialize ───────────────────────────────────────────────

    #[test]
    fn empty_dict_serializes_to_one_zero_byte() {
        let dict = Dictionary::empty();
        assert_eq!(dict.serialize(), [0x00]);
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let dict = build(r#"{"name":"Alice","id":"Bob","name":"Charlie"}"#, 1);
        let bytes = dict.serialize();
        let restored = Dictionary::deserialize(&bytes).expect("deserialize failed");
        assert_eq!(dict.entries, restored.entries);
    }

    #[test]
    fn deserialize_preserves_lookup_index() {
        let dict = build(r#"{"role":"admin","user":"alice"}"#, 1);
        let bytes = dict.serialize();
        let restored = Dictionary::deserialize(&bytes).unwrap();
        for entry in &dict.entries {
            let id_orig = dict.lookup(entry.kind.to_token_kind(), &entry.value).unwrap();
            let id_rest = restored.lookup(entry.kind.to_token_kind(), &entry.value).unwrap();
            assert_eq!(id_orig, id_rest, "ID must match after deserialize");
        }
    }

    #[test]
    fn deserialize_truncated_returns_error() {
        let bytes = [0x05];
        assert!(Dictionary::deserialize(&bytes).is_err());
    }

    #[test]
    fn deserialize_unknown_type_byte_returns_error() {
        let bytes = [0x01, 0xFF, 0x01, b'x'];
        assert!(Dictionary::deserialize(&bytes).is_err());
    }
}
