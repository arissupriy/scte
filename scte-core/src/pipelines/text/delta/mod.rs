/// Delta encoding for integer column streams — Phase 6.
///
/// Detects sequential, monotonic, and clustered integer patterns and encodes
/// deltas instead of flat values, dramatically reducing bits per record.
///
/// # Status: STUB (Phase 6)

pub mod cross_record;
pub mod integer;
pub mod timestamp;
