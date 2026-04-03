/// Inferred type for a single field — Phase 5.
///
/// Assigned by `inferencer::FileSchema::build()` after scanning a token stream.
/// Used to select the optimal per-field encoder in Phase 5+.

/// Encoding hint for integer fields — set by pattern analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntHint {
    /// Values are independent — use flat ZigZag + LEB128.
    Flat,
    /// Values are sequential (delta constant) — Phase 6 can encode in ~0 bits.
    Sequential,
    /// Values are monotonic with small deltas — delta encoding beneficial.
    Monotonic,
    /// Values cluster around previous value — small delta encoding beneficial.
    Clustered,
}

/// Inferred type of a field in the schema.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldType {
    /// Integer values — may be further sub-typed by `IntHint` in Phase 6.
    Integer { hint: IntHint },
    /// Floating-point values.
    Float,
    /// Boolean values.
    Bool,
    /// Enum — limited set of known string values.
    ///
    /// `variants` lists all observed string values in frequency order.
    /// Phase 5 stores this mapping in the SCHEMA section.
    Enum { variants: Vec<String> },
    /// Timestamp string — ISO 8601 or Unix epoch.
    /// Encoded as delta-compressed Unix epoch seconds (NumInt) in the token stream.
    Timestamp,
    /// Arbitrary string — no pattern detected.
    Str,
    /// Always null.
    Null,
    /// High-cardinality string field where values follow `<prefix><integer>` pattern.
    ///
    /// E.g. `"user_0042"` → prefix `"user_"`, suffix `42`.  
    /// The suffix integer is stored as `NumInt` and delta-encoded.
    /// `suffix_width` is the zero-padded width (0 = no padding).
    StrPrefix { prefix: String, suffix_width: u8 },
    /// Float field where all observed values have at most `decimals` decimal places.
    ///
    /// Encoded as `round(v × 10^decimals)` integer (NumInt), delta-compressed.
    FloatFixed { decimals: u8 },
}
