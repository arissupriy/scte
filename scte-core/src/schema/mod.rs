/// Schema inference subsystem — Phase 5.
///
/// Scans a token stream in Pass 1 to build a `FileSchema` describing
/// each field's type, distribution, and encoding hint.
///
/// The schema is serialized into section `0x08 SCHEMA` and embedded
/// in the SCTE file header — the decoder reads it to reconstruct the
/// exact encoding used, ensuring lossless round-trip.

pub mod field_type;
pub mod inferencer;
pub mod serializer;

pub use field_type::FieldType;
pub use inferencer::FileSchema;
