/// Integer delta encoder — Phase 6.
///
/// Detects patterns in integer sequences:
/// - **Sequential**: 0,1,2,3 → delta=+1 constant → ~0 bits/value
/// - **Monotonic**:  100,103,107 → small positive deltas
/// - **Clustered**:  50,51,50,52 → delta ±1-2 → 2-3 bits/value
/// - **Random**:     fallback to `FlatIntegerEncoder`
///
/// # Status: STUB (Phase 6)
///
/// The classifier and encoder will be implemented in Phase 6.
/// Until then, all integer columns use `FlatIntegerEncoder`.

/// Detected pattern for an integer column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegerPattern {
    /// delta is constant (e.g. sequential IDs).
    Sequential { delta: i64 },
    /// All deltas are small (< 256).
    Monotonic,
    /// Deltas cluster around zero (|delta| typically ≤ 4).
    Clustered,
    /// No discernible pattern — use flat encoding.
    Random,
}

/// Detect the pattern of an integer slice.
///
/// # Status: STUB — always returns `Random` until Phase 6.
pub fn detect_pattern(_values: &[i64]) -> IntegerPattern {
    IntegerPattern::Random
}
