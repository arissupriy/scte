# SCTE — Semantic Compression & Transport Engine

A next-generation compression and transport engine that integrates
structure-aware encoding, adaptive pipelines, and entropy coding to
outperform traditional byte-level compression algorithms in real-world
data transfer scenarios.

---

## Overview

SCTE is a **Rust-based, production-grade encoding engine** designed around one core insight:

> Most data transferred today is not random bytes — it has structure.
> Exploiting that structure before entropy coding yields far better results
> than treating data as an opaque byte stream.

Instead of a single compression algorithm, SCTE routes data through a
**type-aware pipeline** — JSON takes a different path than a binary executable,
which takes a different path than a log file — and applies the most effective
combination of transformations per data class.

---

## Architecture

```
Input → Detect → Classify → Route → Encode → SCTE Container
                                │
                                ├─ Text Pipeline     (JSON, CSV, XML, log)
                                ├─ Binary Pipeline   (executables, firmware)
                                ├─ Container Pipeline(DOCX, XLSX)
                                └─ Passthrough       (encrypted / random)
```

The engine is split into a **single core library** deployed in two roles:

| Role   | Responsibility                                   |
|--------|--------------------------------------------------|
| Client | Detect → transform → encode → send              |
| Server | Receive → decode → reconstruct → store          |

One codebase. No algorithm drift between sides.

---

## Crate Structure

```
scte/
├── scte-core/      Pure Rust engine — no I/O, no network, no platform deps
├── scte-cli/       Command-line interface (encode / decode / inspect)
├── scte-ffi/       C ABI layer for mobile and cross-language bindings  (Phase 7)
└── bindings/
    ├── dart/       Flutter + Dart CLI via dart:ffi                     (Phase 7)
    ├── wasm/       Browser / Node.js via wasm-pack                     (Phase 8)
    ├── node/       Node.js native via napi-rs                          (Phase 4)
    └── python/     Python via cffi                                     (Phase 4)
```

---

## CLI Usage

```bash
# Encode a file into a SCTE container
scte encode input.json output.scte

# Decode back to original
scte decode output.scte restored.json

# Inspect container metadata
scte inspect output.scte
```

---

## Development Phases

| Phase | Feature                        | Status        |
|-------|--------------------------------|---------------|
| 1     | Minimal core — container format| ✅ Complete    |
| 2     | Text pipeline — JSON           | ✅ Complete    |
| 3     | Dictionary encoding            | ✅ Complete    |
| 4     | Entropy coding (rANS)          | 🔄 Next       |
| 5     | Pipeline integration           | ⏳ Planned    |
| 6     | Memory & zero-copy optimization| ⏳ Planned    |
| 7     | C ABI / FFI layer              | ⏳ Planned    |
| 8     | WASM binding                   | ⏳ Planned    |

## Text Pipeline (Phase 2 & 3)

The text pipeline processes JSON through four stages:

```
JSON bytes
  → canonicalize_json()    — deterministic form, sorted keys, no whitespace
  → tokenize_json()        — flat token stream (ObjOpen/Key/Str/NumInt/…)
  → Dictionary::build()    — frequency analysis, token → u16 ID mapping
  → encode_with_dict()     — high-frequency strings replaced by compact IDs
```

Stage output is stored in two SCTE sections:
- `DICT (0x01)` — serialized dictionary (LEB128 wire format)
- `TOKENS (0x02)` — dictionary-encoded token stream (Phase 4: rANS-coded)

### Token kinds

| Kind       | Description                              |
|------------|------------------------------------------|
| `ObjOpen`  | `{`                                      |
| `ObjClose` | `}`                                      |
| `ArrOpen`  | `[`                                      |
| `ArrClose` | `]`                                      |
| `Key`      | Object key string (dict-eligible)        |
| `Str`      | String value (dict-eligible)             |
| `NumInt`   | Integer-normalised number (i64)          |
| `NumFloat` | Genuine floating-point (f64)             |
| `Bool`     | `true` / `false`                         |
| `Null`     | `null`                                   |

### Dictionary properties
- Max capacity: **65 535 entries** (u16 ID space)
- Sort order: frequency descending; ties broken by `(kind, value)` byte order
- `Key` and `Str` with the same string value get **separate** dictionary entries
- Wire format: `varint(K)` + per entry: `type(1) + varint(len) + utf8_bytes`

---



- **Lossless** — `decode(encode(x)) == x`, always, byte-identical
- **Deterministic** — identical input + config = identical output across platforms
- **Zero external dependencies** in `scte-core` (Phases 1–3)
- **Language-agnostic** — C ABI as the stable system boundary
- **Mobile-ready** — designed for Dart FFI (Flutter) and WASM from the ground up

---

## Building

```bash
# Run all tests
cargo test

# Build release binary
cargo build --release

# Binary location
./target/release/scte-cli
```

Requires: **Rust 1.70+** (stable)

---

## License

TBD
