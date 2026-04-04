# SCTE Bug Fix Plan — Analisis Validasi Roundtrip

**Tanggal analisa**: April 3, 2026  
**Status engine**: 333 tests passing, benchmark verified

---

## 1. Kontrak Aktif Engine

Untuk **JSON input**, kontrak yang berlaku adalah:

```
canonicalize(decode(encode(x))) == canonicalize(x)
```

Ini intentional karena:
- Tokenizer selalu mengurutkan object keys alfabetikal
- Output decoder selalu dalam format canonical (no whitespace)
- `{"b":1,"a":2}` → encode → decode → `{"a":2,"b":1}` ✓ canonical, ✗ byte-equal

Untuk **non-JSON passthrough** (binary data), kontraknya adalah byte equality:

```
decode(encode(x)) == x
```

---

## 2. Lapisan Integrity yang Sudah Ada

| Layer | Mekanisme | Scope |
|---|---|---|
| Container header | FNV1a-32 checksum (24 bytes) | Verified at decode entry |
| Section payload | FNV1a-32 per-section | Verified before decode logic |
| Unit tests | `canonicalize(in) == canonicalize(out)` | 333 tests |
| Benchmark | `canonicalize(in) == canonicalize(out)` | Semua dataset |

---

## 3. Bug Terkonfirmasi (Harus Diperbaiki)

### 🔴 Bug A: UUID Uppercase → Lowercase Silently

**File**: `scte-core/src/pipelines/text/columnar_pipeline.rs`  
**Fungsi**: `is_uuid`, `bytes_to_uuid`

```rust
// is_uuid: accepts uppercase (is_ascii_hexdigit is case-insensitive)
fn is_uuid(s: &str) -> bool {
    ...
    if !c.is_ascii_hexdigit() { return false; }  // accepts A-F too
    ...
}

// bytes_to_uuid: always emits lowercase
fn bytes_to_uuid(bytes: &[u8]) -> String {
    format!("{:02x}{:02x}...", ...)  // lowercase only
}
```

**Dampak**: Input `"550E8400-E29B-41D4-A716-..."` → decoded `"550e8400-e29b-41d4-a716-..."`.  
`canonicalize_json` tidak menyamakan string case → `canon_in != canon_out`.

**Tidak terdeteksi karena**: Semua test UUID pakai lowercase hex (`{:08x}`).

**Fix opsi**:
- ✅ Pilihan 1 (rekomendasi): Tolak uppercase di `detect_uuid` — gunakan `is_ascii_lowercase_hex | is_ascii_digit`, sehingga uppercase jatuh ke `TAG_RAW_STR`.
- Pilihan 2: Normalize case (lowercase) di detection stage, simpan normalization flag di wire.

---

### 🔴 Bug B: TAG_STRPREFIX_HEX Uppercase → Lowercase Silently

**File**: `scte-core/src/pipelines/text/columnar_pipeline.rs`  
**Fungsi**: `encode_by_type` (TAG_STRPREFIX_HEX decode branch)

```rust
// Decoder uses hardcoded lowercase hex lookup:
static HEX: &[u8; 16] = b"0123456789abcdef";
```

**Dampak**: Input `"trace-DEADBEEF"` → decoded `"trace-deadbeef"`.  
Case tidak dipreservasi.

**Tidak terdeteksi karena**: Semua test trace IDs pakai lowercase (`{:012x}`).

**Fix**: Di `detect_hex_suffix`, tambahkan syarat semua suffix harus lowercase:
```rust
if !s[prefix_len..].bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
    return None;
}
```

---

### 🔴 Bug C: Array-of-Array Elements Jadi Null

**File**: `scte-core/src/pipelines/text/columnar_pipeline.rs`  
**Fungsi**: `parse_array_items`

```rust
TokenKind::ArrOpen => {
    // nested array-as-element: treat as opaque scalar (rare in practice)
    let close = find_arr_close(tokens, pos);
    pos = close + 1;
    items.push(ArrayItem::Scalar(RawValue::Null));  // ← DATA LOSS
}
```

**Dampak**: Input `[["a","b"], ["c"]]` sebagai field value → decoded sebagai `[null, null]`.  
Silent data loss, tidak ada error.

**Fix**: Jika menemukan `ArrOpen` sebagai element, return `None` dari `parse_array_items`  
→ `make_sub_items` return `None` → field tersebut tidak masuk sub-table → fall-through ke raw text pipeline.

---

### 🟠 Bug D: Heterogeneous Sub-Table Schema = Silent Null (Field Hilang)

**File**: `scte-core/src/pipelines/text/columnar_pipeline.rs`  
**Fungsi**: `make_sub_items`

```rust
// Schema homogeneity check:
if obj.keys().cloned().collect::<Vec<_>>() != first_keys { return None; }
```

Jika `make_sub_items` return `None`, field array tersebut **tidak di-encode sama sekali** (hilang dari output).

**Dampak**: Data loss untuk rows dengan optional array fields atau mixed-type arrays.

**Fix**: Di `extract_all_columns`, jika `make_sub_items` return `None` untuk suatu path, **jangan include rows tersebut di columnar path** → fallback ke raw text pipeline untuk seluruh input. Ini konsisten dengan prinsip "columnar path is optional, must not corrupt".

---

### 🟠 Bug E: Integer Delta Overflow — Panic di Debug Mode

**File**: `scte-core/src/pipelines/text/delta/integer.rs`  
**Fungsi**: `detect_pattern`

```rust
let deltas: Vec<i64> = values.windows(2).map(|w| w[1] - w[0]).collect();
//                                                         ^^ overflow di debug mode
```

**Dampak**: Input `[i64::MIN, i64::MAX]` → `i64::MAX - i64::MIN` = overflow → **panic di debug mode**.  
Di release mode, wrapping arithmetic menjaga round-trip (karena decode juga wrapping-add).

**Tidak terdeteksi karena**: Semua test integers pakai LCG values dalam range yang aman.

**Fix**:
```rust
let deltas: Vec<i64> = values.windows(2).map(|w| w[1].wrapping_sub(w[0])).collect();
```
Dan di decoder, pastikan reconstruct juga menggunakan `wrapping_add`.

---

## 4. Coverage Gaps yang Perlu Ditambah

| Gap | Priority | Expected Result Saat Ini |
|---|---|---|
| Uppercase UUID roundtrip | 🔴 Critical | FAIL — case mismatch |
| Uppercase hex suffix roundtrip | 🔴 Critical | FAIL — case mismatch |
| `[i64::MIN, i64::MAX]` int column | 🟠 High | PANIC di debug mode |
| Passthrough binary byte-equality | 🟠 High | Unknown — belum ada test |
| 3-level nested array (array-of-array as element) | 🟠 High | Data loss (Null) |
| Heterogeneous sub-table fallback | 🟠 High | Data loss (field hilang) |
| UTF-8 edge: emoji `🔥`, null byte `\0`, BMP chars | 🟡 Medium | Likely OK (canonical handles it) |
| JSON string dengan `\uXXXX` escape | 🟡 Medium | Likely OK |
| Float column dengan high-precision values | 🟡 Medium | Falls to RAW_STR, OK |
| Two-pass pipeline direct unit tests | 🟡 Medium | Only covered by benchmark |
| Property-based testing / cargo-fuzz | 🟢 Nice-to-have | Not implemented |

---

## 5. Test yang Perlu Ditambah

### Test Suite: Correctness Guards

```rust
// Test A: Uppercase UUID must roundtrip correctly
#[test]
fn uppercase_uuid_roundtrip() {
    let json = (0..10).map(|i| format!(
        r#"{{"id":{i},"trace":"550E8400-E29B-41D4-A716-{:012X}"}}"#, i as u64
    )).collect::<Vec<_>>().join(",").wrap_in_array();
    roundtrip(&json);  // must not mangle case
}

// Test B: Uppercase hex suffix must roundtrip correctly
#[test]
fn uppercase_hex_suffix_roundtrip() {
    let json = (0..10).map(|i| format!(
        r#"{{"id":{i},"hash":"prefix-{:08X}"}}"#, i * 0x1234567
    )).collect::<Vec<_>>().join(",").wrap_in_array();
    roundtrip(&json);
}

// Test C: Integer extremes
#[test]
fn integer_extremes_roundtrip() {
    let vals = [i64::MIN, 0, i64::MAX, -1, 1, i64::MIN / 2, i64::MAX / 2];
    let json = vals.iter().enumerate().map(|(i, &v)| format!(
        r#"{{"id":{i},"val":{v}}}"#
    )).collect::<Vec<_>>().join(",").wrap_in_array();
    roundtrip(&json);
}

// Test D: Passthrough binary byte-equality
#[test]
fn passthrough_binary_roundtrip() {
    let data: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
    let encoded = encode(&data).unwrap();
    let decoded = decode(&encoded).unwrap();
    assert_eq!(data, decoded);  // byte equality, not canonical
}

// Test E: Array-of-array (must not become Null)
#[test]
fn array_of_array_not_silently_dropped() {
    let json = br#"[{"id":1,"matrix":[[1,2],[3,4]]},{"id":2,"matrix":[[5,6],[7,8]]}]"#;
    roundtrip(json);  // matrix must survive, not become [[null,null],[null,null]]
}

// Test F: Heterogeneous sub-table fallback (field must survive)
#[test]
fn heterogeneous_sub_table_survives() {
    let json = br#"[
        {"id":1,"data":[{"x":1},{"x":2}]},
        {"id":2,"data":[{"x":3,"y":4}]}
    ]"#;  // schema mismatch in "data" → must not lose "data" field
    roundtrip(json);
}
```

---

## 6. Kenapa Benchmark Tidak Cukup untuk Correctness

Benchmark dataset dirancang untuk performance, bukan adversarial correctness:

| Property | Benchmark Data | Adversarial Data |
|---|---|---|
| UUID case | Selalu lowercase | Mixed case |
| Hex suffix | Selalu lowercase | UPPERCASE |
| Integer range | LCG values (safe range) | `i64::MIN`/`i64::MAX` |
| Sub-table schema | Selalu homogeneous | Mixed keys/types |
| Array nesting | Max 2 levels, objects | Array-of-array |
| Binary data | Tidak ditest | Arbitrary bytes |

---

## 7. Urutan Perbaikan Rekomendasi

1. **Fix Bug A** — tolak uppercase di `detect_uuid` (1 line di `is_uuid`)
2. **Fix Bug B** — tolak uppercase di `detect_hex_suffix` (1 line)
3. **Fix Bug C** — return `None` dari `parse_array_items` jika ada nested ArrOpen, bukan push Null
4. **Fix Bug E** — `wrapping_sub` di `detect_pattern` (1 line di `integer.rs`)
5. **Fix Bug D** — jika `make_sub_items` return None, exclude dari sub-tables (field harus survive via fallback, bukan hilang)
6. **Tambah test suite** — semua test di section 5
7. **Cargo-fuzz** — setup `fuzz/` crate setelah semua bugs fixed

---

## 8. Wire Compatibility Note

Bug A dan B fixes mengubah **behavior detector** (uppercase → jatuh ke RAW_STR, bukan TAG_UUID).  
Ini **tidak mengubah wire format** — file yang sudah di-encode dengan lowercase UUID tetap decode benar.  
File yang di-encode sebelum fix dengan uppercase UUID (jika ada) akan mengalami case change saat decode.  
Karena engine masih pre-production, ini acceptable.
