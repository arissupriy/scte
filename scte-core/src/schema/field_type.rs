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
    Timestamp,
    /// Arbitrary string — no pattern detected.
    Str,
    /// Always null.
    Null,
}
