# SCTE — Semantic Compression & Transport Engine
# Engineering Plan v1.0
# Date: 2026-04-02

---

## 1. Problem Statement

Given a file F ∈ {0,1}* on the client side, the goal is:

    minimize |T(F, S)|  subject to  D(T(F, S), S) = F

Where:
- T = encoding transformation (client-side)
- D = decoding / reconstruction (server-side)
- S = server state {C, D, V} (chunk index, dictionary, version history)

**Primary constraint**: lossless, byte-identical reconstruction — decode(encode(F)) == F.

**Secondary goal**: minimize bytes-on-the-wire for real-world text-based payloads
(JSON, CSV, log, XML, config files).

---

## 2. Scope (MVP)

**In scope:**
- Text-based data only: JSON, CSV, plain log, XML, YAML, TOML
- Lossless compression
- CLI tool (encode / decode / inspect)
- Single-file / stream input
- Stateless mode (no server state required for MVP)
- Stateful mode (server-assisted, Phase 2)

**Out of scope (deferred):**
- Binary / executable pipeline (stub only)
- Container formats: DOCX, XLSX (stub only)
- Media pipeline (stub only)
- Lossy mode
- Multi-platform bindings: C ABI, WASM, Dart FFI, FRB wrapper (Phase 3)
- Node.js / Python bindings (Phase 4)

---

## 3. System Architecture

### 3.1 High-Level Flow

```
[Input]
   │
   ▼
[Detector]          — magic bytes, MIME sniff, heuristic entropy estimate
   │
   ▼
[Classifier]        — assigns DataClass + estimates redundancy score
   │
   ▼
[Negotiator] (*)    — queries server state: known chunks, dict version, file version
   │                  (*) no-op in stateless mode
   ▼
[Router]            — selects Pipeline based on DataClass + server response
   │
   ├──▶ [Text Pipeline]         ← ACTIVE (MVP)
   ├──▶ [Binary Pipeline]       ← STUB → fallback zstd
   ├──▶ [Container Pipeline]    ← STUB → fallback zstd
   └──▶ [HighEntropy Pipeline]  ← passthrough / fallback zstd
           │
           ▼
      [Packer]                  — bitstream assembly + section table
           │
           ▼
      [Entropy Coder]           — rANS (custom)
           │
           ▼
      [SCTE Container Output]   — .scte binary file
```

### 3.2 Dual-Role Deployment

One `scte-core` crate. Two roles:

| Role           | Responsibilities                               |
|----------------|------------------------------------------------|
| Client/Encoder | detect → classify → negotiate → encode → send  |
| Server/Decoder | receive → decode → reconstruct → store         |

**Critical invariant**: encoder and decoder must use identical algorithm versions.
Any mismatch → hard error, not silent corruption.

---

## 4. Wire Format (Container Spec)

### 4.1 File Header — Fixed 24 bytes

```
Offset  Size  Field            Description
------  ----  -----            -----------
0       4     magic            0x53 0x43 0x54 0x45  ("SCTE")
4       1     version          format version, currently 0x01
5       1     flags            bit 0: stateful, bit 1: dict present,
                               bit 2: delta present, bits 3-7: reserved
6       1     pipeline_id      see Pipeline Registry below
7       1     reserved         0x00
8       8     original_size    u64 LE — uncompressed byte size
16      2     section_count    u16 LE — number of sections
18      2     reserved         0x0000
20      4     header_checksum  XXH3-32 of bytes 0–19
```

### 4.2 Pipeline Registry (pipeline_id)

```
0x00  — Unknown / unset
0x01  — Text (semantic) pipeline        ← ACTIVE
0x02  — Structured binary (container)   ← STUB
0x03  — Binary / executable             ← STUB
0x04  — Media                           ← STUB
0xFE  — Zstd fallback (official)        ← ACTIVE (fallback)
0xFF  — Passthrough (high entropy)      ← ACTIVE
```

**Zstd fallback (0xFE) is a first-class pipeline**, not an else-branch.
Any SCTE decoder must be able to decode a 0xFE file unconditionally.

### 4.3 Section Table Entry — 26 bytes each

```
Offset  Size  Field      Description
------  ----  -----      -----------
0       1     type       section type code (see below)
1       1     codec      encoding applied to this section
2       8     offset     u64 LE — byte offset from start of file
10      8     length     u64 LE — byte length of this section
18      4     checksum   XXH3-32 of section content
22      2     meta_len   u16 LE — length of inline metadata
24      ?     meta_bytes (meta_len bytes)
```

### 4.4 Section Types

```
0x01  DICT    global dictionary
0x02  TOKENS  token stream (text pipeline output)
0x03  DELTA   delta ops (future)
0x04  CHUNKS  new chunk data (binary pipeline)
0x05  INDEX   hash → offset index
0x06  DATA    raw or secondary-compressed payload
0x07  META    file-level metadata (original filename, mtime, etc.)
```

### 4.5 Section Codecs

```
0x00  None (raw)
0x01  rANS
0x02  Zstd
0x03  LEB128-varint stream
```

### 4.6 Integrity

- Per-section: XXH3-32 in section table entry
- Whole-file: XXH3-64 appended as final 8 bytes after all sections
- Optional strong hash: BLAKE3-256 (activated via flags bit 3)

---

## 5. Text Pipeline (Detailed Spec)

This is the only active pipeline in MVP. All other pipelines are stubs.

### 5.1 Input Classification (pre-pipeline)

Before entering pipeline, Classifier assigns a sub-type:

```
TextSubType:
  Json
  Csv
  Xml
  Log       (line-oriented, arbitrary fields)
  Yaml
  Toml
  PlainText (fallback text)
```

Classification uses:
1. File extension (weak signal)
2. First 4KB sniff: structural character frequency ('{', '[', ',', '<', '=')
3. Entropy estimate H ≈ -Σ p_i log₂ p_i over byte histogram

If H > 7.2 bits/byte → skip text pipeline → route to HighEntropy (passthrough).

### 5.2 Stage 1 — Canonicalization

Purpose: remove semantically-equivalent variation that creates false entropy.

| Sub-type  | Canonicalization rules |
|-----------|------------------------|
| JSON      | sort object keys lexicographically, normalize numbers (1.0→1, 1e3→1000 only for integers), UTF-8 NFC normalize, strip insignificant whitespace |
| CSV       | normalize line endings (CRLF→LF), trim trailing whitespace per cell, normalize empty fields |
| XML       | C14N subset: normalize attribute order, collapse whitespace in text nodes, normalize namespace prefixes |
| Log       | normalize timestamps to ISO-8601 UTC if detectable |
| YAML/TOML | convert to canonical form (no aliases, consistent quoting) |

**Contract**: canonicalize(F) must be deterministic. If exact original byte-for-byte
reproduction is required, raw original bytes are stored in a META section.

### 5.3 Stage 2 — Tokenization

Token types:

```
TokenKind:
  Key(id)        — object key / column header
  Str(id)        — string value (dict-encoded)
  StrRaw(bytes)  — string value (not in dict, inline)
  NumInt(i64)    — integer value
  NumFloat(f64)  — float value
  Bool(bool)
  Null
  ArrOpen / ArrClose
  ObjOpen / ObjClose
  Delim          — comma, semicolon
  PathRef(id)    — flattened JSON path reference
```

Representation in bitstream:

```
[3-bit kind tag][variable payload]
```

For dict-encoded tokens, payload = varint(dict_id).
For inline strings, payload = varint(len) + bytes.

### 5.4 Stage 3 — Path Flattening (JSON-specific)

Transform nested JSON into flat path-value pairs:

```
{"user": {"id": 1, "name": "Alice"}}
→ (user.id = 1), (user.name = "Alice")
```

Benefits:
- Path strings repeat across records → high dict compression
- Values per path have predictable types → better entropy model per-column

Path strings are assigned a `path_id` in the dictionary.

### 5.5 Stage 4 — Columnarization (CSV and JSON arrays)

Detect array of homogeneous objects:

```json
[{"ts": 1, "val": 0.5}, {"ts": 2, "val": 0.6}, ...]
```

Reorganize into per-column streams:

```
col "ts":  [1, 2, 3, ...]      → delta-encode → ZigZag → LEB128 varint
col "val": [0.5, 0.6, ...]     → quantize or raw f32/f64
col "key": ["alice", "bob"...] → dict lookup or RLE
```

Column-oriented layout drastically reduces entropy per-column since values
within a column are from the same distribution.

### 5.6 Stage 5 — Dictionary Building

Single-pass frequency count over all tokens.

Algorithm:
1. Count frequency f(t) for all token values
2. Select top-K by frequency, threshold: f(t) ≥ 3 (configurable)
3. Assign dict_id in frequency-descending order (most common = id 0)
4. Encode dictionary as: varint(K) + for each entry: [type(1)] + [payload]

Dictionary is stored in a DICT section, referenced by dict_id in the token stream.

K is bounded: max 65535 entries (u16 dict_id).

For cross-session reuse (stateful mode), dictionary is given a content-based
hash ID and cached server-side.

### 5.7 Stage 6 — Numeric Encoding

For integer columns / values:

```
ZigZag encoding:  zz(n) = (n << 1) ^ (n >> 63)
Then:             LEB128 varint encoding
```

For delta sequences (timestamps, sequential IDs):

```
delta(v[i]) = v[i] - v[i-1]
then ZigZag + varint
```

For float values: store as IEEE 754 f32 or f64 based on precision analysis.
If value fits in f32 without loss → use f32 (saves 4 bytes per value).

### 5.8 Stage 7 — Entropy Coding (rANS)

Applied to the token stream after dictionary encoding.

**Frequency model**: built from the token stream in a single pass before encoding.
Model is stored alongside the compressed data for the decoder.

**rANS parameters**:

```
M = Σ f_i  (total frequency, normalized to power of 2: M = 2^k, k = 12 to 16)
L = 1 << 23  (lower bound of state range)
b = 256      (byte I/O)
state x ∈ [L, b·L)
```

**Encoding** (symbol s with frequency f_s, cumulative CDF_s):

```
Normalization (flush bytes):
  while x >= (f_s << 8) * (L / M):
      output_byte(x & 0xFF)
      x >>= 8

Encode:
  x' = (x / f_s) * M + CDF_s + (x % f_s)
```

**Decoding** (reverse order, stack-based):

```
slot = x % M
s    = symbol_from_slot(slot)        ← table lookup O(1)
x'   = f_s * (x / M) + slot - CDF_s

Renormalization:
  while x' < L:
      x' = (x' << 8) | read_byte()
```

**Frequency table storage**: stored in TOKENS section header as:

```
varint(alphabet_size) + for each symbol: varint(frequency)
```

Frequencies normalized to sum = M = 2^k before storage.

### 5.9 Bit-level Packing Summary

| Data type      | Encoding            |
|----------------|---------------------|
| dict_id        | LEB128 varint       |
| string length  | LEB128 varint       |
| integer values | ZigZag + LEB128     |
| delta integers | ZigZag + LEB128     |
| boolean flags  | bit-packed (8/byte) |
| token kind     | 3-bit prefix        |
| float values   | raw f32 / f64       |

---

## 6. Pipeline Trait Contract

All pipelines (including stubs) must implement:

```rust
trait Pipeline: Send + Sync {
    fn id(&self) -> PipelineId;

    fn can_handle(&self, input: &DataClass) -> bool;

    /// Estimate compression benefit. Returns score in [0.0, 1.0].
    /// 0.0 = no benefit (passthrough), 1.0 = maximum benefit.
    /// Used by Router to select optimal pipeline.
    fn estimate_benefit(&self, sample: &[u8], server_state: Option<&ServerState>) -> f32;

    fn encode(&self, input: &[u8], ctx: &EncodeContext) -> Result<Encoded, ScteError>;

    fn decode(&self, encoded: &Encoded, ctx: &DecodeContext) -> Result<Vec<u8>, ScteError>;

    fn pipeline_version(&self) -> u32;
}
```

Stub pipelines: `can_handle` → false, `encode` → delegate to ZstdPipeline.

---

## 7. Negotiator (Stateful Mode)

In stateful mode, Negotiator runs between Classifier and Router.
In stateless mode (MVP), Negotiator is a no-op passthrough.

### 7.1 Handshake Protocol (binary)

Client → Server request:

```
[4]  magic:       0x53 0x43 0x4E 0x48  ("SCNH")
[1]  version:     0x01
[1]  flags:       bit 0 = has_file_hash, bit 1 = wants_dict
[8]  file_hash:   XXH3-64 of original file (if known)
[2]  engine_ver:  client engine version
```

Server → Client response:

```
[4]  magic:       0x53 0x43 0x4E 0x52  ("SCNR")
[1]  status:      0x00 ok, 0x01 unknown, 0x02 version_mismatch
[1]  flags:       bit 0 = has_dict, bit 1 = has_chunks, bit 2 = has_version
[8]  dict_id:     XXH3-64 of known dictionary (if available)
[4]  version_num: file version number server has
[2]  engine_ver:  server engine version
```

If `engine_ver` mismatch → client falls back to ZstdPipeline (pipeline_id 0xFE).

### 7.2 Router Decision (post-negotiation)

```
score = pipeline.estimate_benefit(sample, server_state)

if score < 0.15:   use HighEntropyPipeline (passthrough)
elif score < 0.30: use ZstdFallback
else:              use selected pipeline
```

---

## 8. Crate Structure (Rust Workspace)

```
scte/
├── Cargo.toml                  (workspace)
│
├── scte-core/                  (shared: no I/O, no network)
│   └── src/
│       ├── lib.rs
│       ├── error.rs
│       ├── types.rs            (DataClass, PipelineId, Encoded, etc.)
│       ├── container/
│       │   ├── header.rs       (wire format read/write)
│       │   ├── section.rs
│       │   └── checksum.rs     (XXH3 wrapper)
│       ├── detect/
│       │   ├── classifier.rs
│       │   └── entropy.rs      (byte histogram + H estimate)
│       ├── pipelines/
│       │   ├── mod.rs          (Pipeline trait)
│       │   ├── text/
│       │   │   ├── mod.rs
│       │   │   ├── canonicalize.rs
│       │   │   ├── tokenizer.rs
│       │   │   ├── dictionary.rs
│       │   │   ├── path_flatten.rs
│       │   │   ├── columnar.rs
│       │   │   └── numeric.rs
│       │   ├── zstd_fallback.rs    (official fallback pipeline 0xFE)
│       │   ├── passthrough.rs      (high entropy 0xFF)
│       │   ├── binary_stub.rs
│       │   └── container_stub.rs
│       ├── entropy/
│       │   ├── rans.rs             (rANS encode/decode)
│       │   ├── frequency.rs        (frequency table builder + normalizer)
│       │   └── varint.rs           (LEB128 + ZigZag)
│       └── router.rs
│
├── scte-client/
│   └── src/
│       ├── lib.rs
│       ├── analyzer.rs         (file analysis wrapper)
│       ├── encoder.rs          (encode + pack to SCTE container)
│       ├── negotiator.rs       (handshake, stateful mode)
│       └── net.rs              (HTTP / WS client)
│
├── scte-server/
│   └── src/
│       ├── lib.rs
│       ├── decoder.rs
│       ├── reconstructor.rs
│       ├── storage.rs          (chunk index, dict cache, version store)
│       └── api.rs              (Axum routes)
│
├── scte-ffi/                   (C ABI layer — stable boundary, no Rust types exposed)
│   ├── include/
│   │   └── scte.h              (public C header, generated + hand-maintained)
│   └── src/
│       ├── lib.rs              (cdecl extern functions, #[no_mangle])
│       ├── encode.rs           (scte_encode, scte_encode_free)
│       ├── decode.rs           (scte_decode, scte_decode_free)
│       ├── inspect.rs          (scte_inspect — returns JSON metadata string)
│       └── error.rs            (scte_last_error, scte_error_free)
│
├── scte-cli/
│   ├── src/
│   │   └── main.rs             (encode / decode / inspect subcommands)
│   └── tests/
│       └── roundtrip.rs        (property-based: decode(encode(x)) == x)
│
└── bindings/                   (language-specific wrappers over scte-ffi)
    ├── dart/                   (Dart FFI — works in Flutter and Dart CLI)
    │   ├── lib/
    │   │   ├── scte_bindings.dart      (dart:ffi low-level bindings)
    │   │   └── scte.dart               (ergonomic Dart wrapper)
    │   └── pubspec.yaml
    ├── frb/                    (Flutter Rust Bridge — optional, DX layer only)
    │   └── README.md           (NOTE: FRB wraps Rust API, NOT the C ABI)
    ├── node/                   (N-API / napi-rs — Phase 4)
    │   └── src/
    │       └── lib.rs
    ├── python/                 (cffi / ctypes — Phase 4)
    │   └── scte.py
    └── wasm/                   (wasm-pack / wasm-bindgen — Phase 3)
        └── src/
            └── lib.rs
```

---

## 9. Error Handling Contract

All public-facing functions return `Result<T, ScteError>`.

```
ScteError:
  InvalidMagic
  UnsupportedVersion(u8)
  PipelineMismatch { expected: PipelineId, found: PipelineId }
  ChecksumFailed { section: SectionType }
  EncodingFailed(String)
  DecodingFailed(String)
  DictionaryNotFound(u64)           — stateful mode
  EngineMismatch { client: u16, server: u16 }
  InputTooLarge(usize)
  RecursionLimitExceeded
```

Decoder hard limits (configurable, these are defaults):

| Limit                  | Default  |
|------------------------|----------|
| Max decompressed size  | 4 GB     |
| Max section count      | 1024     |
| Max dictionary entries | 65535    |
| Max recursion depth    | 64       |

---

## 10. Determinism Guarantees

These invariants must hold for all pipeline implementations:

1. `encode(F, config) = encode(F, config)` — same input + same config = same output
2. `decode(encode(F)) = F` — byte-identical reconstruction
3. Identical output across x86_64 and aarch64
4. Identical output across Rust versions (stable API surface only)

Enforcement rules:

| Rule                                        | Reason                               |
|---------------------------------------------|--------------------------------------|
| No `HashMap` in encode path                 | Non-deterministic iteration order    |
| Use `BTreeMap` or sorted `Vec`              | Deterministic key ordering           |
| No floating-point in entropy model          | Platform-specific rounding           |
| All integer ops: wrapping/checked explicit  | No undefined overflow behavior       |
| rANS state: u64 only, no u128              | Cross-platform bit-exact consistency |

---

## 11. Benchmarking Plan

### 11.1 Datasets

| Dataset                    | Size    | Expected benefit |
|----------------------------|---------|------------------|
| JSON API dump              | 1–10 MB | Very high        |
| Log file (nginx)           | 5 MB    | High             |
| CSV wide (1M rows)         | 50 MB   | High             |
| CSV narrow (100K rows)     | 5 MB    | High             |
| XML (Maven POM collection) | 2 MB    | High             |
| Random bytes               | 1 MB    | None (baseline)  |

### 11.2 Baselines

| Tool              | Mode              |
|-------------------|-------------------|
| `zstd --level 3`  | speed-optimized   |
| `zstd --level 19` | ratio-optimized   |
| `gzip -9`         | classic           |
| `brotli -q 11`    | ratio-optimized   |

### 11.3 Metrics

| Metric               | Unit               |
|----------------------|--------------------|
| Compression ratio    | compressed/original|
| Encode throughput    | MB/s               |
| Decode throughput    | MB/s               |
| Encode latency p50   | ms                 |
| Encode latency p95   | ms                 |
| Encode latency p99   | ms                 |
| Peak memory (encode) | MB                 |
| Peak memory (decode) | MB                 |

### 11.4 Validity Rule

A benchmark result is only valid if:
- `decode(encode(x)) == x` for every test file (checksum verified)
- Benchmark run on same machine, same OS, no background load
- Results reproducible across 3 consecutive runs (< 5% variance)

---

## 12. Transport Model (MVP)

MVP uses **Model 2 — Multipart HTTP** as the only transport.
Most portable, no middleware dependency, easiest to debug.

```
POST /upload  HTTP/1.1
Content-Type: multipart/form-data; boundary=----SCTEBoundary

------SCTEBoundary
Content-Disposition: form-data; name="meta"
Content-Type: application/json

{
  "engine_version": 1,
  "original_filename": "data.json",
  "pipeline": "text"
}

------SCTEBoundary
Content-Disposition: form-data; name="payload"
Content-Type: application/octet-stream

[binary SCTE container bytes]
------SCTEBoundary--
```

Model 1 (HTTP `Content-Encoding: scte`) and Model 3 (WebSocket/gRPC streaming)
are deferred to Phase 3.

---

## 13. Roadmap

### Phase 1 — MVP (Target: 3 weeks)

**Goals:**
- Text pipeline fully working: JSON + log + plaintext
- rANS encoder/decoder implemented from scratch
- CLI: `scte encode <file>`, `scte decode <file>`, `scte inspect <file>`
- Roundtrip test suite: 100% pass
- Benchmark baseline established

**Deliverables:**
- `scte-core`: container format + text pipeline + rANS
- `scte-cli`: encode / decode / inspect
- Benchmark report vs zstd

**Milestone**: compression ratio > zstd level 3 on real JSON API payload.

---

### Phase 2 — Stateful + Extended Text (Target: +3 weeks)

**Goals:**
- CSV columnarization
- XML support
- Stateful mode: server negotiation + dictionary cache
- `scte-server`: Axum-based, minimal storage backend
- `scte-client`: negotiator + HTTP transport

**Milestone**: second upload of same-schema JSON uses cached dictionary,
encoding 30%+ faster than first upload.

---

### Phase 3 — Binary Pipeline + C ABI + WASM (Target: +4 weeks)

**Goals:**
- CDC (Rabin-Karp rolling hash) + chunk dedup
- Binary delta stream
- `scte-ffi`: C ABI layer with stable `scte.h` header
- `bindings/dart/`: Dart FFI wrapper (Flutter + Dart CLI compatible)
- `bindings/wasm/`: WASM build via wasm-pack
- FRB wrapper as optional DX layer on top of Dart FFI (not as core)

**ABI stability rule**: once `scte.h` is tagged v1.0, function signatures
are frozen. New functions may be added; existing ones must not change.

**Milestone**: binary file with 5% change → transfer size ≤ 10% of original.
Flutter app can encode/decode via Dart FFI without any Rust toolchain.

---

### Phase 4 — Production Hardening + Multi-Language Bindings (Target: +4 weeks)

**Goals:**
- SIMD-optimized rANS (x86_64 + aarch64)
- Adaptive frequency model (dynamic f_i(t) update)
- DOCX/XLSX container pipeline
- Distributed server (Redis chunk index)
- Format versioning + backward compatibility test suite
- `bindings/node/`: Node.js binding via napi-rs
- `bindings/python/`: Python binding via cffi

**Milestone**: end-to-end decode throughput > 500 MB/s on modern hardware.
Same `.scte` file decodable from Rust CLI, Flutter app, Node.js, and Python.

---

## 14. Key Decisions Log

| Decision                        | Choice                       | Rationale                                              |
|---------------------------------|------------------------------|--------------------------------------------------------|
| Entropy coder                   | rANS (custom)                | Speed + ratio, SIMD-friendly, proven in zstd/brotli          |
| Fallback pipeline               | Zstd as official 0xFE        | Not else-branch; decodable by all engine versions            |
| Transport MVP                   | Multipart HTTP               | Most portable, no middleware dependency                      |
| Dictionary iteration order      | BTreeMap / sorted Vec        | Deterministic output across platforms                        |
| Integer format                  | LEB128 + ZigZag              | Standard, no endianness issues                               |
| Checksum                        | XXH3 fast + BLAKE3 opt-in    | Speed-first, strong hash available when needed               |
| Client/server core              | Single crate, two roles      | Prevents algorithm divergence between sides                  |
| Routing mechanism               | score-based estimate_benefit | Quantitative, extensible, not hard-coded if/else             |
| MVP data scope                  | JSON + log + plaintext       | Highest real-world redundancy, fastest demonstrable result   |
| No HashMap in encode path       | BTreeMap only                | Deterministic output across runs and platforms               |
| Mobile/cross-platform binding   | C ABI (scte-ffi) as core     | Language-agnostic, ABI-stable, works in Flutter/Node/Python  |
| Flutter Rust Bridge (FRB)       | Optional wrapper only        | FRB locks to Dart; C ABI is the real system boundary         |
| Binding priority order          | C ABI → Dart FFI → FRB       | Portability first, ergonomics layered on top                 |
---

## 15. FFI & Multi-Platform Bindings Architecture

### 15.1 Layering Principle

```
┌─────────────────────────────────────────────────────┐
│               scte-core  (pure Rust)                │
│   no I/O, no network, no platform dependencies      │
└────────────────────┬────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────┐
│            scte-ffi  (C ABI layer)                  │
│   #[no_mangle] extern "C" functions                 │
│   stable scte.h header — system boundary            │
└──┬─────────────┬──────────────┬──────────────┬──────┘
   │             │              │              │
   ▼             ▼              ▼              ▼
[Dart FFI]   [wasm-pack]   [napi-rs]     [cffi/ctypes]
 Flutter       Browser       Node.js        Python
 Dart CLI
   │
   ▼ (optional DX layer)
 [FRB wrapper]
  Flutter only
```

**Rule**: no Rust type leaks across the C ABI boundary.
Only `u8*`, `size_t`, `int32_t`, `char*` cross the boundary.

---

### 15.2 C ABI Public Interface (`scte.h`)

```c
/* Encode: returns heap-allocated buffer. Caller must free with scte_free(). */
uint8_t* scte_encode(
    const uint8_t* input,
    size_t         input_len,
    size_t*        out_len       /* written on success */
);

/* Decode: returns heap-allocated buffer. Caller must free with scte_free(). */
uint8_t* scte_decode(
    const uint8_t* input,
    size_t         input_len,
    size_t*        out_len
);

/* Inspect: returns null-terminated JSON string. Free with scte_free_str(). */
char* scte_inspect(
    const uint8_t* input,
    size_t         input_len
);

/* Memory management */
void scte_free(uint8_t* ptr, size_t len);
void scte_free_str(char* ptr);

/* Error handling (thread-local) */
int32_t     scte_last_error_code(void);
const char* scte_last_error_message(void);  /* static lifetime, no free needed */

/* Version */
uint32_t scte_engine_version(void);   /* major<<16 | minor<<8 | patch */
```

**Invariants:**
- All functions are thread-safe (no global mutable state)
- Null input → returns NULL, sets error code `SCTE_ERR_NULL_INPUT` (1)
- On error: returns NULL, `scte_last_error_code()` non-zero
- Caller owns returned buffer; must call `scte_free` / `scte_free_str`

---

### 15.3 Dart FFI Binding (Flutter + Dart CLI)

`bindings/dart/` wraps `scte.h` using `dart:ffi`. Works in:
- Flutter (Android, iOS, macOS, Windows, Linux)
- Dart CLI (standalone)
- **Not** browser (use WASM binding instead)

Key design:
- `Uint8List encode(Uint8List input)` — copies result into Dart-managed memory,
  calls `scte_free` immediately after copy
- All memory management hidden from Dart caller
- Throws `ScteException` (wraps error code + message) on failure

```dart
// Usage in Flutter / Dart
final encoded = ScteEngine.encode(inputBytes);
final decoded = ScteEngine.decode(encoded);
assert(decoded == inputBytes);
```

---

### 15.4 Flutter Rust Bridge (FRB) — Optional Only

FRB may be used as an **additional ergonomics layer** for Flutter developers
who prefer generated async Dart API with futures and streams.

**Hard constraint**: FRB must sit above the Dart FFI layer or above `scte-core`
directly — it must **never** be the system boundary that other bindings depend on.

```
FRB wrapper
     │
     └── depends on → scte-core (Rust API)   ← acceptable
                   or → scte-ffi (C ABI)      ← acceptable
                   NOT ON → unique Dart types  ← forbidden as core contract
```

FRB is a developer convenience, not an architectural commitment.

---

### 15.5 WASM Binding

`bindings/wasm/` uses `wasm-pack` + `wasm-bindgen`.

Wraps `scte-core` directly (not via C ABI — WASM has its own ABI model).

```javascript
// Usage in browser / Node.js (WASM)
import init, { encode, decode } from './scte_wasm.js';
await init();
const encoded = encode(inputBytes);
const decoded = decode(encoded);
```

Notes:
- WASM build excludes `scte-ffi` (not needed)
- `wasm-pack build --target web` for browser
- `wasm-pack build --target nodejs` for Node.js WASM path
- Native Node.js binding (napi-rs) is preferred over WASM for server-side Node

---

### 15.6 Memory Safety Contract Across FFI

| Scenario                          | Owner       | Action                        |
|-----------------------------------|-------------|-------------------------------|
| Buffer returned by `scte_encode`  | Caller (C)  | Must call `scte_free(ptr, len)`|
| String returned by `scte_inspect` | Caller (C)  | Must call `scte_free_str(ptr)` |
| Input buffer passed to any fn     | Caller      | Must remain valid during call  |
| Dart `Uint8List` after encode     | Dart GC     | Copied before `scte_free`      |
| WASM memory                       | WASM heap   | Managed by wasm-bindgen        |

**No double-free, no use-after-free**: enforced by not exposing raw pointers
to Dart/JS — the binding layer always copies before releasing.

---

### 15.7 Build Targets Matrix

| Target                   | Crate used          | Output              | Platform          |
|--------------------------|---------------------|---------------------|-------------------|
| Native binary (CLI)      | scte-cli            | ELF / Mach-O / PE   | Linux/macOS/Win   |
| Shared library (FFI)     | scte-ffi            | .so / .dylib / .dll | All native        |
| Android (Flutter)        | scte-ffi            | .so (arm64, x86_64) | Android NDK       |
| iOS (Flutter)            | scte-ffi            | .a (static, xcfmwk) | Xcode             |
| Browser                  | bindings/wasm       | .wasm + .js glue    | Browser / Deno    |
| Node.js native           | bindings/node       | .node               | Node.js           |
| Server (Rust direct)     | scte-core           | linked as crate     | Any               |