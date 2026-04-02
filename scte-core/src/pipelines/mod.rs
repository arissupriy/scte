/// Pipeline trait — implemented by every encoding pipeline.
///
/// Each pipeline is responsible for encoding/decoding a specific class of data.
/// Stub pipelines delegate to `ZstdFallback` or return `can_handle = false`.
///
/// # Phase status
/// - Phase 1-4: Text pipeline active; all others are stubs
/// - Phase 3:   Binary pipeline + C ABI
/// - Phase 4:   Media + container stubs promoted
use crate::error::ScteError;

// ── Submodules ────────────────────────────────────────────────────────────────

pub mod text;

// ── DataClass ────────────────────────────────────────────────────────────────

/// Broad classification of input data assigned by the Detector/Classifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataClass {
    /// Structured human-readable text: JSON, CSV, log, XML, YAML, TOML.
    Text(TextSubType),
    /// Binary / executable / firmware.
    Binary,
    /// Container formats: DOCX, XLSX, ZIP-based.
    Container,
    /// Media: audio, video, image.
    Media,
    /// Entropy too high for semantic compression — passthrough.
    HighEntropy,
}

/// Sub-classification within the Text class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextSubType {
    Json,
    Csv,
    Xml,
    Log,
    Yaml,
    Toml,
    PlainText,
}

// ── EncodeContext / DecodeContext ─────────────────────────────────────────────

/// Runtime context passed to `Pipeline::encode`.
#[derive(Debug, Clone, Default)]
pub struct EncodeContext {
    /// Minimum token frequency to include in dictionary (default: 2).
    pub dict_min_freq: u32,
}

/// Runtime context passed to `Pipeline::decode`.
#[derive(Debug, Clone, Default)]
pub struct DecodeContext;

// ── Encoded ───────────────────────────────────────────────────────────────────

/// Opaque result of a pipeline encode operation.
///
/// Contains section payloads assembled by the Packer into the SCTE container.
#[derive(Debug, Clone)]
pub struct Encoded {
    /// Serialized DICT section payload.
    pub dict: Vec<u8>,
    /// Serialized TOKENS section payload.
    pub tokens: Vec<u8>,
    /// Serialized SCHEMA section payload (Phase 5+, empty until then).
    pub schema: Vec<u8>,
    /// Serialized DELTA section payload (Phase 6+, empty until then).
    pub delta: Vec<u8>,
}

impl Encoded {
    /// Create an Encoded result with only DICT + TOKENS (Phase 1-4 path).
    pub fn text_only(dict: Vec<u8>, tokens: Vec<u8>) -> Self {
        Self { dict, tokens, schema: Vec::new(), delta: Vec::new() }
    }
}

// ── Pipeline trait ────────────────────────────────────────────────────────────

/// Common interface for all encoding pipelines.
pub trait Pipeline: Send + Sync {
    fn id(&self) -> crate::types::PipelineId;
    fn can_handle(&self, class: &DataClass) -> bool;
    /// Returns score in `[0.0, 1.0]` — 0 = no benefit, 1 = maximum.
    fn estimate_benefit(&self, sample: &[u8]) -> f32;
    fn encode(&self, input: &[u8], ctx: &EncodeContext) -> Result<Encoded, ScteError>;
    fn decode(&self, encoded: &Encoded, ctx: &DecodeContext) -> Result<Vec<u8>, ScteError>;
    /// Increment when encoding format changes in a breaking way.
    fn pipeline_version(&self) -> u32;
}
// ── TextPipeline ──────────────────────────────────────────────────────────────

/// Concrete implementation of `Pipeline` for JSON / text data.
///
/// Under the hood delegates to `encode_json_two_pass` and `decode_token_stream`.
/// This is the only concrete `Pipeline` implementation for Phase 5-7.
pub struct TextPipeline;

impl Pipeline for TextPipeline {
    fn id(&self) -> crate::types::PipelineId {
        crate::types::PipelineId::Text
    }

    fn can_handle(&self, class: &DataClass) -> bool {
        matches!(class, DataClass::Text(..))
    }

    fn estimate_benefit(&self, sample: &[u8]) -> f32 {
        // Simple heuristic: JSON-like data compresses well.
        let first = sample.iter().find(|&&b| !b.is_ascii_whitespace());
        if matches!(first, Some(b'{') | Some(b'[')) { 0.85 } else { 0.0 }
    }

    fn encode(&self, input: &[u8], ctx: &EncodeContext) -> Result<Encoded, ScteError> {
        let out = text::encode_json_two_pass(input, ctx.dict_min_freq)?;
        Ok(Encoded {
            dict:   out.dict.serialize(),
            tokens: out.token_bytes,
            schema: out.schema_bytes,
            delta:  out.delta_bytes,
        })
    }

    fn decode(&self, encoded: &Encoded, _ctx: &DecodeContext) -> Result<Vec<u8>, ScteError> {
        let schema = crate::schema::serializer::deserialize(&encoded.schema)?;
        let dict   = text::Dictionary::deserialize(&encoded.dict)?;
        let tokens = text::decode_token_stream(
            &encoded.tokens, &dict, &schema, &encoded.delta,
        )?;
        Ok(text::tokens_to_json(&tokens))
    }

    fn pipeline_version(&self) -> u32 { 7 }
}