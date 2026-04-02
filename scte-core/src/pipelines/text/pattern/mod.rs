/// String pattern encoders — Phase 6.
///
/// Detects and encodes string patterns:
/// - Prefix templates: "user_001","user_002" → template + counter
/// - Run-length encoding for repeated string values

pub mod rle;
pub mod string_prefix;
