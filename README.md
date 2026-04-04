# SCTE — Semantic Compression & Transport Engine

Structure-aware encoding engine for semi-structured data (JSON, logs, tabular payloads), written in Rust.

---

## What It Does

SCTE encodes JSON by exploiting its structure rather than treating it as an opaque byte stream:

- **Columnar layout** — for `Array<Object>` inputs, values from the same field across all rows are grouped together before encoding
- **Schema inference** — integer, enum, timestamp, UUID, base64, and prefix-pattern fields each get a type-specific encoder
- **Entropy coding** — per-column rANS on top of delta/enum residuals
- **Period detection** — cycling sequences stored as a single base cycle
- **Passthrough** — non-JSON inputs (binary, XML, CSV, logs) are stored verbatim, byte-exact

---

## Measured Results

All figures from `cargo test --release --test benchmark`. `decode(encode(x)) == x` verified for every row via canonical JSON comparison. zstd numbers are reference, same machine.

```
Dataset                                    Raw         SCTE    enc MB/s   dec MB/s   zstd-3    zstd-19
──────────────────────────────────────────────────────────────────────────────────────────────────────
Real files — nested JSON (row-major text pipeline)
  users_100.json                         29929B    3070B  10.3%   22.8 MB/s   77.8 MB/s   16.6%   13.2%
  users_1k.json                         311042B   18074B   5.8%   19.5 MB/s   87.3 MB/s   14.7%    9.4%
  users_10k.json                       3084967B  164623B   5.3%   16.4 MB/s   75.3 MB/s   14.4%    8.1%

Real files — flat JSON (columnar pipeline)
  flat_users_1k.json                     54171B    3126B   5.8%   26.1 MB/s  146.1 MB/s   16.7%   12.8%
  flat_users_10k.json                   551951B   23657B   4.3%   26.1 MB/s  141.7 MB/s   15.9%   10.1%
  flat_users_100k.json [GlobalCols]    5619926B  222438B   4.0%   20.4 MB/s  140.4 MB/s   15.6%    9.8%

Entropy ceiling — UUID keys + base64 payloads + random latencies
  uuid-b64   1000 rows                  109060B   30282B  27.8%   25.8 MB/s   52.8 MB/s   37.9%   36.5%
  uuid-b64  10000 rows                 1090984B  298988B  27.4%   37.3 MB/s   97.7 MB/s   38.2%   35.9%

Semi-structured — small-vocab categoricals + random value fields
  api-semi   1000 rows                  148561B   11983B   8.1%   35.5 MB/s  165.6 MB/s   18.2%   13.4%
  api-semi   5000 rows                  746507B   55707B   7.5%   37.4 MB/s  171.6 MB/s   18.3%   12.9%
  api-semi  10000 rows                 1494038B  111353B   7.5%   32.5 MB/s  161.6 MB/s   18.3%   12.7%

Random flat JSON — no cycling pattern
  log-json  1000 rows                    99855B    5060B   5.1%   34.0 MB/s  173.2 MB/s   11.4%    7.1%
  log-json  5000 rows                   503481B   16322B   3.2%   33.7 MB/s  184.7 MB/s   11.3%    6.9%
  log-json 10000 rows                  1008244B   32639B   3.2%   32.4 MB/s  184.1 MB/s   11.3%    6.8%

Cycling fields — columnar pipeline, period detector active
  api-json  1000 rows [periodic]        145641B     862B   0.6%   33.0 MB/s  185.1 MB/s    2.8%    2.2%
  api-json  5000 rows [periodic]        732641B     862B   0.1%   31.8 MB/s  188.1 MB/s    1.9%    1.5%
  api-json 10000 rows [periodic]       1466391B    1855B   0.1%   29.6 MB/s  183.6 MB/s    1.7%    1.4%

All fields independently random per row
  api-json  1000 rows [random]          146468B    4491B   3.1%   33.1 MB/s  189.4 MB/s    9.8%    7.3%
  api-json  5000 rows [random]          737129B   18628B   2.5%   30.3 MB/s  197.1 MB/s    9.6%    7.1%
  api-json 10000 rows [random]         1475245B   37221B   2.5%   27.8 MB/s  195.2 MB/s    9.6%    7.0%
```

Non-JSON passthrough (byte-exact):

```
  HPC_2k.log           149178B → 149226B  byte-exact=YES
  OpenStack_2k.log     593120B → 593168B  byte-exact=YES
  Proxifier_2k.log     236962B → 237010B  byte-exact=YES
  CSV (2.2 MB)        2272701B → 2272749B  byte-exact=YES
  book5.3.0.xml          7734B →   7782B  byte-exact=YES
  15mb.xml           15400141B → 15400189B  byte-exact=YES
```

The ~48 byte overhead on non-JSON inputs is the SCTE container header and section table.

---

## Encoding Modes

```rust
use scte_core::{encode, encode_with, EncodingMode, decode};

// Structured: full pipeline — best compression, semantic equality
// values preserved; whitespace and key order may differ from input
let encoded = encode(json_bytes)?;

// Raw: passthrough for all inputs — byte-exact always
let encoded = encode_with(input, EncodingMode::Raw)?;
assert_eq!(decode(&encoded)?, input);
```

| Mode | JSON | Non-JSON | Guarantee |
|---|---|---|---|
| `Structured` | full pipeline | passthrough | values preserved; whitespace/key-order may change |
| `Raw` | passthrough | passthrough | byte-exact |

---

## Architecture

```
encode(input)
  ├─ looks_like_json? (first non-whitespace byte is { or [)
  │    ├─ tokenize_json()  ← one parse, shared by both downstream paths
  │    ├─ homogeneous Array<Object>?
  │    │    └─ columnar pipeline  →  COLUMNAR section (0x09)
  │    └─ otherwise
  │         └─ two-pass text pipeline  →  SCHEMA + DICT + TOKENS + DELTA sections
  └─ not JSON  (or JSON parse fails)
       └─ passthrough  →  PAYLOAD section, byte-exact
```

### Columnar Pipeline

Activated for `Array<Object>` with a uniform key schema and ≥2 rows.

Each column gets an independent encoder selected by size comparison:

| Tag | Strategy |
|---|---|
| `TAG_INT_PERIOD` | period repeat |
| `TAG_INT_RANS` | rANS on delta residuals (≥64 rows) |
| `TAG_INT` | delta zigzag-varint |
| `TAG_ENUM_PERIOD` | period repeat on variant indices |
| `TAG_ENUM_RANS` | rANS on variant indices (≥64 rows) |
| `TAG_ENUM_RLE` | run-length on variant indices |
| `TAG_ENUM` | delta-encoded variant index (≤256 distinct strings) |
| `TAG_STRPREFIX` | common prefix + delta integer suffix |
| `TAG_STRPREFIX_HEX` | common prefix + binary-packed hex suffix |
| `TAG_UUID` | 36-char UUID → 16 raw bytes |
| `TAG_BASE64` | base64 → raw bytes |
| `TAG_TIMESTAMP` | delta epoch-seconds |
| `TAG_TIMESTAMP_RANS` | rANS on epoch delta bytes (≥64 rows) |
| `TAG_FLOAT_FIXED` | scale × 10^d as delta integer |
| `TAG_FLOAT_FIXED_RANS` | rANS on float delta bytes (≥64 rows) |
| `TAG_BACKREF` | copy of earlier identical column |
| `TAG_BOOL` | bit-packed |
| `TAG_NULL` | empty |
| `TAG_SUB_TABLE` | recursive columnar block for array-valued fields |
| `TAG_RAW_STR` | verbatim per-row strings |
| `TAG_RAW_STR_RANS` | rANS on concatenated string bytes (≥64 rows) |

Arrays exceeding **8 192 rows** are split into independent columnar chunks, each stored as a separate `COLUMNAR` section. The decoder reassembles chunks in row order and stitches the JSON arrays together.

### Two-Pass Text Pipeline

For JSON that is not a homogeneous array:

```
Pass 1 — tokenize_json() → FileSchema::build()
         infers per-field type: Enum, StrPrefix, FloatFixed, Timestamp,
         Integer{Sequential|Monotonic|Clustered|Bounded|Flat}

Pass 2 — schema_encode_tokens()   (Str → NumInt for enum/prefix/timestamp)
       → delta_encode_tokens()    (integer columns → delta residuals)
       → Dictionary::build()      (high-frequency tokens → compact IDs)
       → encode_with_dict()
       → encode_token_bytes()     (rANS on token stream)
```

### Integer Delta Patterns

Five patterns for integer columns, applied in priority order:

| Pattern | Condition | Wire cost |
|---|---|---|
| `Sequential` | all deltas equal | first + step + count (3 varints) |
| `Clustered` | max\|delta\| ≤ 8 | first + N×1–2 byte deltas |
| `Monotonic` | all deltas ≥0 and <1024 | first + N×1–2 byte deltas |
| `Bounded` | max\|delta\| < value\_range/2 | first + N small signed deltas |
| `Flat` | none above | N full-width zigzag varints |

`Bounded` handles fields like Unix-ms timestamps (`1743724800123`) where the value spans a large range but changes by <2000 per row. Without it, each value stored 6+ bytes; with it, only the first value is full-width.

---

## Wire Format

Container header (24 bytes):
```
[0..3]  magic      "SCTE"
[4..5]  version    u16
[6..7]  pipeline   u16   (0x01 = Text)
[8..11] flags      u32
[12..19] orig_len  u64   (original unencoded length)
[20..21] sec_count u16
[22..23] pad
```

Section entry (20 bytes fixed + optional meta):
```
[0]     type    u8    (0x01=DICT, 0x02=TOKENS, 0x07=PAYLOAD,
                        0x08=SCHEMA, 0x09=COLUMNAR, 0x0A=DELTA, …)
[1]     codec   u8    (0x00=None, 0x01=Zstd)
[2..3]  pad
[4..11] offset  u64
[12..19] length u64
[20..27] meta   u64   (COLUMNAR only, multi-chunk: row_start u32 LE | row_end u32 LE)
```
Single-chunk containers omit the meta field; multi-chunk containers include it for every section entry.

---

## Crate Structure

```
scte/
├── scte-core/     Pure Rust engine — no I/O, no network deps
│   ├── src/
│   │   ├── codec/           encode() / decode() entry points, EncodingMode
│   │   ├── container/       header and section wire format
│   │   ├── entropy/         rANS codec (FreqTable, rans_encode, rans_decode)
│   │   ├── pipelines/
│   │   │   └── text/
│   │   │       ├── columnar_pipeline.rs   Array<Object> encoder/decoder
│   │   │       ├── two_pass.rs            row-major schema-aware pipeline
│   │   │       ├── tokenizer.rs           JSON → token stream
│   │   │       ├── value.rs               JSON parser + internal IR
│   │   │       ├── canonicalize.rs        deterministic JSON serializer
│   │   │       ├── delta/
│   │   │       │   ├── integer.rs         Sequential/Clustered/Monotonic/Bounded/Flat
│   │   │       │   └── timestamp.rs       ISO 8601 ↔ epoch seconds
│   │   │       ├── dictionary/            token frequency dictionary
│   │   │       └── pattern/               prefix pattern detection
│   │   └── schema/          field type inference (Enum/StrPrefix/FloatFixed/Timestamp)
│   └── tests/
│       ├── benchmark.rs      correctness + throughput tests (real asset files)
│       └── roundtrip.rs      low-level encode/decode contract tests
├── scte-cli/      Command-line encode/decode/inspect
└── assets/        JSON files used by benchmark tests
```

---

## Building

```bash
# Build everything
cargo build --release

# Run unit tests (351 tests)
cargo test --release --lib

# Run integration + benchmark tests (~45 s)
cargo test --release --test benchmark -- --nocapture

# Run roundtrip contract tests
cargo test --release --test roundtrip

# Run only correctness tests
cargo test --release --test benchmark verify
```

Requires: **Rust 1.70+** (stable)

---

## CLI Reference

Build the CLI binary:

```bash
cargo build --release -p scte-cli
# binary: target/release/scte-cli
```

### `encode <input> <output.scte>`

Wraps any file in a SCTE container. Pipeline is selected automatically:

- JSON `Array<Object>` with uniform keys → columnar pipeline
- Any other JSON → two-pass text pipeline
- Non-JSON (CSV, XML, logs, binary, …) → verbatim passthrough, byte-exact

```bash
scte-cli encode data/users.json  data/users.scte
# encode: 311042 bytes → 18074 bytes  (ratio 0.058)
```

### `decode <input.scte> <output>`

Restores the original file from a SCTE container.

```bash
scte-cli decode data/users.scte  data/users_restored.json
# decode: 18074 bytes → 311042 bytes  ✓ checksum ok
```

> **Note on JSON:** SCTE canonicalizes JSON on decode — object keys are sorted alphabetically and
> whitespace is normalized. All field values are preserved exactly; numeric precision and array
> order are unchanged.  For non-JSON files, decoding is byte-for-byte identical to the original.

### `inspect <input.scte>`

Prints container metadata: pipeline type, original size, section layout, and per-section checksums.

**Single-section example** (`users_1k.json` — 1 k rows, 1 columnar section):

```
── SCTE Container ──────────────────────────────────────────
  file_size      : 18074 bytes
  format version : 0x01
  flags          : 0x00
  pipeline_id    : 0x01  (Text)
  original_size  : 311042 bytes
  section_count  : 1
────────────────────────────────────────────────────────────
  [0]  type=Columnar  codec=None  offset=48  length=18026  checksum=0xf8a294ed  ✓
────────────────────────────────────────────────────────────
```

**Multi-chunk example** (`flat_users_100k.json` — 100 k rows, 1 GlobalCols section + 13 columnar chunks):

```
── SCTE Container ──────────────────────────────────────────
  file_size      : 222438 bytes
  format version : 0x01
  flags          : 0x00
  pipeline_id    : 0x01  (Text)
  original_size  : 5619926 bytes
  section_count  : 14
────────────────────────────────────────────────────────────
  [0]  type=GlobCols  codec=None  offset=     464  length=    636  checksum=0x1121fb95  ✓
  [1]  type=Columnar  codec=None  offset=    1100  length=  18116  checksum=0x46cd649e  ✓
  [2]  type=Columnar  codec=None  offset=   19216  length=  18130  checksum=0x52ece6fa  ✓
  ...
  [13] type=Columnar  codec=None  offset=  218470  length=   3968  checksum=0x178705d0  ✓
────────────────────────────────────────────────────────────
```

### Section type codes

| Code | Name | Contents |
|------|------|----------|
| `0x01` | `Dict` | Token frequency dictionary |
| `0x02` | `Tokens` | Legacy rANS/CTW token stream |
| `0x07` | `Payload` | Verbatim passthrough bytes |
| `0x08` | `Schema` | Field type schema (enums, timestamps, prefixes) |
| `0x09` | `Columnar` | Columnar-encoded `Array<Object>` chunk |
| `0x0A` | `TokensRans` | Multi-stream rANS token payload (Key / Str / misc) |
| `0x0B` | `GlobalCols` | Shared variant tables + FreqTables for multi-chunk containers (≥ 3 chunks) |

---

## Correctness

- `decode(encode(x))` verified for every dataset in `tests/benchmark.rs`
- JSON inputs: canonical comparison (all values identical; whitespace and key order normalized)
- Non-JSON inputs: byte-exact (`decode(encode(x)) == x`)
- 351 unit tests, 26 integration tests (12 benchmark + 14 roundtrip)

### CLI Roundtrip Test Results

Verified with `scte-cli encode → scte-cli decode` on all real-world assets.
JSON files compared semantically (field values identical; key order and whitespace normalized).
Non-JSON files compared byte-exact via SHA-256.

```
=== JSON nested — text pipeline ===
  users_100.json                              29929B →    3070B ( 10.3%)  PASS  (semantic)
  users_1k.json                              311042B →   18074B (  5.8%)  PASS  (semantic)
  users_10k.json                            3084967B →  164623B (  5.3%)  PASS  (semantic)
  users_100k.json                          30944519B → 1626619B (  5.3%)  PASS  (semantic)

=== JSON flat — columnar pipeline ===
  flat_users_1k.json                          54171B →    3126B (  5.8%)  PASS  (semantic)
  flat_users_10k.json                        551951B →   23657B (  4.3%)  PASS  (semantic)
  flat_users_100k.json                      5619926B →  222438B (  4.0%)  PASS  (semantic)  [GlobalCols + 13 chunks]

=== Logs — passthrough ===
  HPC_2k.log                                 149178B →  149226B           PASS  (byte-exact, +48 B)
  OpenStack_2k.log                           593120B →  593168B           PASS  (byte-exact, +48 B)
  Proxifier_2k.log                           236962B →  237010B           PASS  (byte-exact, +48 B)

=== XML — passthrough ===
  book5.3.0.xml                                7734B →    7782B           PASS  (byte-exact, +48 B)
  rows.xml                                222469817B → 222469865B         PASS  (byte-exact, +48 B)

=== CSV — passthrough ===
  business-operations-survey-2022-....csv   2272701B →  2272749B          PASS  (byte-exact, +48 B)
  Business-price-indexes-....csv           14297017B → 14297065B          PASS  (byte-exact, +48 B)
  overseas-trade-indexes-....csv           24211830B → 24211878B          PASS  (byte-exact, +48 B)

15 / 15 files PASS
```

Key observations:
- JSON key order is alphabetized on encode; semantic equality is preserved, not byte identity
- `flat_users_100k.json` exceeds the 8 192-row chunk limit → stored as 1 `GlobalCols` section (shared variant tables) + 13 independent `Columnar` sections
- Non-JSON overhead is always exactly +48 bytes (24-byte container header + 20-byte section entry + 4-byte pad)

---

## License

TBD
