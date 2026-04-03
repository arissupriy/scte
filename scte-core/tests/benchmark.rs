/// SCTE encoding benchmark.
///
/// Run with:
///   cargo test --test benchmark benchmark_summary -- --nocapture
///
/// Requires `zstd` binary on PATH (used as a reference point — no claims are made).
/// All rows verify: decode(encode(input)) == input (canonical JSON comparison).

/// High-entropy JSON: UUID primary keys, base64 payloads, random latencies.
/// Models table rows from a service audit log or blob-store index.
/// UUID column → TAG_UUID (16 B vs 36 chars), base64 → TAG_BASE64 (64 B vs 88 chars).
fn gen_uuid_json(n: usize, seed: u64) -> Vec<u8> {
    let statuses = ["ok", "error", "timeout"];
    let mut s = String::with_capacity(n * 160);
    s.push('[');
    let mut lcg = seed;
    let next = |lcg: &mut u64| -> u64 {
        *lcg = lcg.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *lcg
    };
    for i in 0..n {
        if i > 0 { s.push(','); }
        // UUID: 16 random bytes formatted as 8-4-4-4-12
        let hi = next(&mut lcg); let lo = next(&mut lcg);
        let uuid = format!(
            "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
            (hi >> 32) as u32,
            (hi >> 16) as u16,
            hi as u16,
            (lo >> 48) as u16,
            lo & 0x0000_ffff_ffff_ffff,
        );
        // Base64: 12 random bytes = 16-char base64 (short but realistic for small blobs)
        let b64_raw: [u8; 12] = {
            let w1 = next(&mut lcg); let w2 = next(&mut lcg);
            let mut arr = [0u8; 12];
            arr[..8].copy_from_slice(&w1.to_le_bytes());
            arr[8..].copy_from_slice(&w2.to_le_bytes()[..4]);
            arr
        };
        let b64 = base64_encode(&b64_raw);
        let status = statuses[next(&mut lcg) as usize % 3];
        let latency = (next(&mut lcg) >> 20) % 2000 + 1;
        s.push_str(&format!(
            r#"{{"id":"{uuid}","payload":"{b64}","status":"{status}","latency_ms":{latency}}}"#
        ));
    }
    s.push(']');
    s.into_bytes()
}

/// Minimal base64 encoder (std alphabet, no external deps).
fn base64_encode(data: &[u8]) -> String {
    const ENC: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity((data.len() + 2) / 3 * 4);
    let mut i = 0;
    while i + 3 <= data.len() {
        let (b0, b1, b2) = (data[i], data[i+1], data[i+2]);
        out.push(ENC[(b0 >> 2) as usize]);
        out.push(ENC[((b0 & 3) << 4 | b1 >> 4) as usize]);
        out.push(ENC[((b1 & 0xf) << 2 | b2 >> 6) as usize]);
        out.push(ENC[(b2 & 0x3f) as usize]);
        i += 3;
    }
    match data.len() - i {
        1 => {
            let b0 = data[i];
            out.push(ENC[(b0 >> 2) as usize]); out.push(ENC[((b0 & 3) << 4) as usize]);
            out.extend_from_slice(b"==");
        }
        2 => {
            let (b0, b1) = (data[i], data[i+1]);
            out.push(ENC[(b0 >> 2) as usize]);
            out.push(ENC[((b0 & 3) << 4 | b1 >> 4) as usize]);
            out.push(ENC[((b1 & 0xf) << 2) as usize]); out.push(b'=');
        }
        _ => {}
    }
    unsafe { String::from_utf8_unchecked(out) }
}

use std::path::Path;
use std::process::Command;
use scte_core::{encode, encode_with, EncodingMode, decode, canonicalize_json};

// ── Dedicated correctness test for real asset files ───────────────────────────

/// Verifies that every real asset file round-trips exactly:
///   decode(encode(original)) == original  (canonical JSON comparison)
///
/// This is a pure correctness check — no throughput measurement.
/// Fails with a diff excerpt if any file is corrupted by the codec.
#[test]
fn verify_asset_files_roundtrip() {
    let assets = Path::new(env!("CARGO_MANIFEST_DIR")).join("../assets");

    let files = [
        "users_100.json",
        "users_1k.json",
        "users_10k.json",
        "flat_users_1k.json",
        "flat_users_10k.json",
        "flat_users_100k.json",
    ];

    let mut any_missing = false;
    let mut failures: Vec<String> = Vec::new();

    for name in &files {
        let path = assets.join(name);
        if !path.exists() {
            println!("  SKIP  {name}  (file not found)");
            any_missing = true;
            continue;
        }

        let original = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("cannot read {name}: {e}"));

        // encode → decode
        let encoded = encode(&original)
            .unwrap_or_else(|e| panic!("{name}: encode failed: {e}"));
        let decoded = decode(&encoded)
            .unwrap_or_else(|e| panic!("{name}: decode failed: {e}"));

        // canonical comparison: key order / whitespace don't matter
        let canon_orig = canonicalize_json(&original)
            .unwrap_or_else(|e| panic!("{name}: canonicalize original failed: {e}"));
        let canon_dec  = canonicalize_json(&decoded)
            .unwrap_or_else(|e| panic!("{name}: canonicalize decoded failed: {e}"));

        let byte_exact  = original == decoded;
        let canon_match = canon_orig == canon_dec;

        let ratio = encoded.len() as f64 / original.len() as f64 * 100.0;
        let byte_tag  = if byte_exact  { "byte-exact=YES" } else { "byte-exact=NO (whitespace/key-order differ)" };
        let canon_tag = if canon_match { "content=MATCH"  } else { "content=MISMATCH" };

        if canon_match {
            println!(
                "  PASS  {name:<30}  {}B → {}B ({:.1}%)  {}  {}",
                original.len(), encoded.len(), ratio, byte_tag, canon_tag,
            );
        } else {
            // Show first divergence as a small excerpt to aid debugging.
            let snip_orig = std::str::from_utf8(&canon_orig[..canon_orig.len().min(300)])
                .unwrap_or("<non-utf8>");
            let snip_dec  = std::str::from_utf8(&canon_dec [..canon_dec .len().min(300)])
                .unwrap_or("<non-utf8>");
            let msg = format!(
                "FAIL  {name}\n  original : {snip_orig}\n  decoded  : {snip_dec}"
            );
            println!("  {msg}");
            failures.push(msg);
        }
    }

    if any_missing {
        println!("  (some files were missing — run scripts/gen_assets.sh to generate them)");
    }
    assert!(
        failures.is_empty(),
        "roundtrip failures:\n{}",
        failures.join("\n")
    );
}

// ── Mode contract tests ─────────────────────────────────────────────────────

/// EncodingMode::Raw on JSON → byte-exact roundtrip (no transformation).
/// This is the "strict" contract: user gets the exact bytes back.
#[test]
fn encoding_mode_raw_json_is_byte_exact() {
    let inputs: &[&[u8]] = &[
        br#"{"b":2,"a":1}"#,                    // key order preserved
        br#"[  1,   2,   3 ]"#,                // whitespace preserved
        br#"{"name":"caf\u00e9","score":9.5}"#, // unicode escape preserved
        br#"[{"id":1},{"id":2}]"#,              // array of objects
    ];
    for &input in inputs {
        let encoded = encode_with(input, EncodingMode::Raw)
            .unwrap_or_else(|e| panic!("Raw encode failed: {e}"));
        let decoded = decode(&encoded)
            .unwrap_or_else(|e| panic!("Raw decode failed: {e}"));
        assert_eq!(
            input, decoded.as_slice(),
            "EncodingMode::Raw must be byte-exact for: {}",
            std::str::from_utf8(input).unwrap_or("<binary>")
        );
    }
}

/// EncodingMode::Structured on JSON → semantic equality, NOT necessarily byte-exact.
/// Documents that key-order / whitespace normalisation is expected and correct.
#[test]
fn encoding_mode_structured_json_is_semantically_equal() {
    let inputs: &[&[u8]] = &[
        br#"{  "b" : 2 , "a" : 1  }"#,  // extra whitespace + unsorted keys
        br#"[{"z":3,"a":1},{"z":4,"a":2}]"#,
    ];
    for &input in inputs {
        let encoded = encode_with(input, EncodingMode::Structured)
            .unwrap_or_else(|e| panic!("Structured encode failed: {e}"));
        let decoded = decode(&encoded)
            .unwrap_or_else(|e| panic!("Structured decode failed: {e}"));
        let c_in  = canonicalize_json(input).unwrap();
        let c_out = canonicalize_json(&decoded).unwrap();
        assert_eq!(c_in, c_out, "Structured mode must preserve semantic content");
    }
}

/// Invalid JSON that starts with `[` (looks like JSON) must never panic;
/// both modes must silently fall back to passthrough → byte-exact output.
#[test]
fn invalid_json_never_panics_and_is_byte_exact() {
    let inputs: &[&[u8]] = &[
        b"[not json at all",
        b"[10.30 16:49:06] system log entry",   // Proxifier-style log
        b"{broken: json, no quotes}",
        b"[1,2,3,",                              // truncated
        b"{\xFF\xFE}",                            // invalid UTF-8 inside braces
    ];
    for &input in inputs {
        // Both modes must handle this without panicking.
        for mode in [EncodingMode::Structured, EncodingMode::Raw] {
            let encoded = encode_with(input, mode)
                .unwrap_or_else(|e| panic!("{mode:?} encode panicked on invalid JSON: {e}"));
            let decoded = decode(&encoded)
                .unwrap_or_else(|e| panic!("{mode:?} decode panicked on invalid JSON: {e}"));
            assert_eq!(
                input, decoded.as_slice(),
                "{mode:?} must be byte-exact for invalid JSON input: {:?}",
                &input[..input.len().min(40)]
            );
        }
    }
}

/// EncodingMode::Raw on binary (non-JSON) blob → byte-exact, same as Structured.
#[test]
fn encoding_mode_raw_binary_is_byte_exact() {
    // A buffer that starts with `[` (would fool looks_like_json) but contains
    // arbitrary binary after it — proves Raw never attempts JSON parsing.
    let mut mixed = b"[".to_vec();
    mixed.extend(0u8..=255u8);
    for mode in [EncodingMode::Structured, EncodingMode::Raw] {
        let encoded = encode_with(&mixed, mode)
            .unwrap_or_else(|e| panic!("{mode:?} encode failed on binary: {e}"));
        let decoded = decode(&encoded)
            .unwrap_or_else(|e| panic!("{mode:?} decode failed on binary: {e}"));
        assert_eq!(mixed, decoded, "{mode:?} must be byte-exact for binary input");
    }
}

/// Verifies that non-JSON asset files (CSV, XML, log) round-trip **byte-for-byte**:
///   decode(encode(original)) == original  (exact bytes, no interpretation)
///
/// Non-JSON input uses the passthrough path — the codec wraps bytes verbatim
/// in a single DATA section and reconstructs them identically.
#[test]
fn verify_non_json_asset_files_roundtrip_byte_exact() {
    let assets = Path::new(env!("CARGO_MANIFEST_DIR")).join("../assets");

    let files = [
        "HPC_2k.log",
        "OpenStack_2k.log",
        "Proxifier_2k.log",
        "business-operations-survey-2022-price-and-wage-setting.csv",
        "book5.3.0.xml",
        "15mb.xml",
    ];

    let mut any_missing = false;
    let mut failures: Vec<String> = Vec::new();

    for name in &files {
        let path = assets.join(name);
        if !path.exists() {
            println!("  SKIP  {name}  (file not found)");
            any_missing = true;
            continue;
        }

        let original = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("cannot read {name}: {e}"));

        let encoded = encode(&original)
            .unwrap_or_else(|e| panic!("{name}: encode failed: {e}"));
        let decoded = decode(&encoded)
            .unwrap_or_else(|e| panic!("{name}: decode failed: {e}"));

        let ratio = encoded.len() as f64 / original.len() as f64 * 100.0;

        if original == decoded {
            println!(
                "  PASS  {name:<55}  {}B → {}B ({:.1}%)  byte-exact=YES",
                original.len(), encoded.len(), ratio,
            );
        } else {
            // Find first differing byte position
            let first_diff = original.iter().zip(decoded.iter())
                .enumerate()
                .find(|(_, (a, b))| a != b)
                .map(|(i, _)| i)
                .unwrap_or_else(|| original.len().min(decoded.len()));

            let msg = format!(
                "FAIL  {name}  ({}B original, {}B decoded)  first diff at byte {}",
                original.len(), decoded.len(), first_diff
            );
            println!("  {msg}");
            failures.push(msg);
        }
    }

    if any_missing {
        println!("  (some files were missing — skipped)");
    }
    assert!(
        failures.is_empty(),
        "byte-exact roundtrip failures:\n{}",
        failures.join("\n")
    );
}



/// JSON array of structured log records (same schema as phase7_pipeline tests).
fn gen_log_json(n: usize, seed: u64) -> Vec<u8> {
    let statuses = ["ok", "error", "timeout", "retry"];
    let methods  = ["GET", "POST", "PUT", "DELETE"];
    let mut s = String::with_capacity(n * 100);
    s.push('[');
    let mut lcg = seed;
    for i in 0..n {
        if i > 0 { s.push(','); }
        lcg = lcg.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let status   = statuses[(lcg >> 33) as usize % 4];
        let method   = methods[(lcg >> 17) as usize % 4];
        let path_id  = (lcg >> 5) % 101;
        let latency  = (lcg >> 20) % 500 + 1;
        let success  = (lcg >> 8) & 1 == 0;
        s.push_str(&format!(
            r#"{{"id":{i},"status":"{status}","method":"{method}","latency_ms":{latency},"path":"/api/v1/res/{path_id}","success":{success}}}"#
        ));
    }
    s.push(']');
    s.into_bytes()
}

/// JSON array of "API response" records — **periodic/cycling** data.
///
/// All categorical fields and numeric fields cycle with small periods:
/// - role/region/status: period 4
/// - score: period 100
/// - created_at: period 28
///
/// SCTE can represent this as a small period base regardless of `n`, so
/// output size is O(1) in `n`.  This is a **stateless** encode — no shared
/// dictionary or prior state — but the data itself has maximal repetition.
/// Label clearly as "PERIODIC" in benchmarks.
fn gen_api_json_periodic(n: usize) -> Vec<u8> {
    let roles    = ["admin", "user", "viewer", "moderator"];
    let regions  = ["us-east-1", "eu-west-1", "ap-southeast-1", "us-west-2"];
    let statuses = ["active", "inactive", "pending", "suspended"];
    let mut s = String::with_capacity(n * 150);
    s.push('[');
    for i in 0..n {
        if i > 0 { s.push(','); }
        let role   = roles[i % 4];
        let region = regions[i % 4];
        let status = statuses[i % 4];
        let score  = (i % 100) as f64 * 0.01;
        s.push_str(&format!(
            r#"{{"id":{i},"user":{{"name":"user_{i:04}","role":"{role}","score":{score:.2}}},"region":"{region}","status":"{status}","created_at":"2026-01-{:02}T12:00:00Z"}}"#,
            (i % 28) + 1
        ));
    }
    s.push(']');
    s.into_bytes()
}

/// JSON array of "API response" records — **random / non-periodic** data.
///
/// Uses an LCG to randomise all fields independently per row.  No period
/// structure exists, so SCTE must encode every value.  This is a fair
/// apples-to-apples comparison against zstd.
fn gen_api_json_random(n: usize, seed: u64) -> Vec<u8> {
    let roles    = ["admin", "user", "viewer", "moderator"];
    let regions  = ["us-east-1", "eu-west-1", "ap-southeast-1", "us-west-2"];
    let statuses = ["active", "inactive", "pending", "suspended"];
    let mut s = String::with_capacity(n * 150);
    s.push('[');
    let mut lcg = seed;
    for i in 0..n {
        if i > 0 { s.push(','); }
        // advance LCG
        lcg = lcg.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let role   = roles[(lcg >> 33) as usize % 4];
        lcg = lcg.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let region = regions[(lcg >> 33) as usize % 4];
        lcg = lcg.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let status = statuses[(lcg >> 33) as usize % 4];
        lcg = lcg.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        // score: random 0.00 – 99.99 (2 dp)
        let score = ((lcg >> 17) % 10000) as f64 * 0.01;
        lcg = lcg.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        // day: random 1-28
        let day = (lcg >> 21) % 28 + 1;
        s.push_str(&format!(
            r#"{{"id":{i},"user":{{"name":"user_{i:04}","role":"{role}","score":{score:.2}}},"region":"{region}","status":"{status}","created_at":"2026-01-{day:02}T12:00:00Z"}}"#
        ));
    }
    s.push(']');
    s.into_bytes()
}

/// Semi-structured realistic API payload.
/// Mixed: categorical fields use small vocabulary (partially periodic-ish),
/// IDs are sequential, latencies/trace IDs are random, timestamps are sequential.
/// Models real-world service-mesh telemetry where schema is regular but values vary.
fn gen_api_json_semi(n: usize, seed: u64) -> Vec<u8> {
    let services = ["auth", "payment", "inventory", "search",
                    "recommendation", "notification", "analytics", "gateway"];
    let envs  = ["prod", "staging", "canary"];
    let dcs   = ["us-east-1a", "us-east-1b", "eu-west-1a", "eu-west-1b",
                 "ap-southeast-1a", "us-west-2a"];
    // Status code distribution biased heavily toward 200
    let codes = [200u16, 200, 200, 200, 200, 201, 204,
                 400, 401, 403, 404, 429, 500, 502, 503];
    let mut s = String::with_capacity(n * 200);
    s.push('[');
    let mut lcg = seed;
    for i in 0..n {
        if i > 0 { s.push(','); }
        lcg = lcg.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let svc  = services[(lcg >> 33) as usize % services.len()];
        lcg = lcg.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let env  = envs[(lcg >> 33) as usize % envs.len()];
        lcg = lcg.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let dc   = dcs[(lcg >> 33) as usize % dcs.len()];
        lcg = lcg.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let code = codes[(lcg >> 33) as usize % codes.len()];
        lcg = lcg.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let lat  = (lcg >> 20) % 2000 + 10;    // 10–2009 ms, unique per row
        lcg = lcg.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let trace_lo = lcg & 0x0000_ffff_ffff_ffff;  // 48-bit random suffix
        // Timestamp: sequential seconds from 2026-04-03 00:00:00 UTC — NOT cycling
        let ts_sec  = 1_743_724_800u64 + i as u64;
        let ts_frac = (lcg >> 10) % 1000;
        s.push_str(&format!(
            r#"{{"seq":{i},"service":"{svc}","env":"{env}","dc":"{dc}","status":{code},"latency_ms":{lat},"trace_id":"scte-{trace_lo:012x}","ts":{ts_sec}.{ts_frac:03}}}"#
        ));
    }
    s.push(']');
    s.into_bytes()
}

// ── zstd reference ───────────────────────────────────────────────────────────

/// Returns compressed byte count using the `zstd` CLI at the given level.
/// Used as a reference data point only — no comparative claims are made.
fn zstd_len(data: &[u8], level: i32) -> usize {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = Command::new("zstd")
        .args([&format!("-{level}"), "--no-progress", "-q", "-c", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("zstd not found on PATH");

    child.stdin.take().unwrap().write_all(data).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    out.stdout.len()
}

// ── Row printer ─────────────────────────────────────────────────────────────

/// Self-calibrating timing: runs `op` once to measure single-iteration cost,
/// then repeats enough times to fill `target_ms` milliseconds.
/// Returns (total iterations, elapsed_secs).
fn calibrated_time<F: FnMut()>(mut op: F, target_ms: u64) -> (usize, f64) {
    use std::time::Instant;
    // Single warmup + timing
    let t0 = Instant::now();
    op();
    let single_ns = t0.elapsed().as_nanos().max(1);
    // How many more to reach target?
    let target_ns = (target_ms as u128) * 1_000_000;
    let extra = ((target_ns / single_ns) as usize).max(0).min(200);
    for _ in 0..extra { op(); }
    let total_iters = 1 + extra;
    let total_secs  = t0.elapsed().as_secs_f64(); // warmup + extra iters
    (total_iters, total_secs)
}

/// Encode, verify roundtrip, measure throughput, print one result row.
fn measure(label: &str, data: &[u8]) {
    let raw = data.len();

    // ── encode throughput (self-calibrated to ~300 ms) ────────────────────────
    let mut last_encoded: Vec<u8> = Vec::new();
    let (enc_n, enc_secs) = calibrated_time(
        || { last_encoded = encode(data).expect("scte encode"); },
        300,
    );
    let encoded  = last_encoded;
    let enc_len  = encoded.len();
    let enc_pct  = enc_len as f64 / raw as f64 * 100.0;
    let enc_mbs  = raw as f64 * enc_n as f64 / enc_secs / 1_048_576.0;

    // ── roundtrip verify ──────────────────────────────────────────────────────
    let decoded   = decode(&encoded).expect("scte decode failed");
    let canon_in  = canonicalize_json(data)    .expect("canonicalize input");
    let canon_out = canonicalize_json(&decoded).expect("canonicalize decoded");
    assert_eq!(canon_in, canon_out, "ROUNDTRIP MISMATCH: {label}");

    // ── decode throughput (self-calibrated to ~300 ms) ────────────────────────
    let (dec_n, dec_secs) = calibrated_time(
        || { let _ = decode(&encoded).unwrap(); },
        300,
    );
    // Decode throughput: measured as reconstructed (output) bytes/sec.
    // For asymmetric codecs the output size is the meaningful work unit.
    let dec_mbs = raw as f64 * dec_n as f64 / dec_secs / 1_048_576.0;

    let z3  = zstd_len(data, 3);
    let z19 = zstd_len(data, 19);
    let z3_pct  = z3  as f64 / raw as f64 * 100.0;
    let z19_pct = z19 as f64 / raw as f64 * 100.0;

    println!(
        "  {label:<48}  {raw:>10}B  {enc_len:>8}B {enc_pct:5.1}%  \
         {enc_mbs:>7.1} MB/s  {dec_mbs:>7.1} MB/s  \
         {z3:>8}B {z3_pct:5.1}%  {z19:>8}B {z19_pct:5.1}%"
    );
}

// ── Individual tests ──────────────────────────────────────────────────────────

#[test]
fn benchmark_log_1k()  { measure("log-json 1k  [random]", &gen_log_json(1_000,  42)); }
#[test]
fn benchmark_log_5k()  { measure("log-json 5k  [random]", &gen_log_json(5_000,  42)); }
#[test]
fn benchmark_log_10k() { measure("log-json 10k [random]", &gen_log_json(10_000, 42)); }

#[test]
fn benchmark_api_1k() {
    measure("api-json 1k [periodic]", &gen_api_json_periodic(1_000));
    measure("api-json 1k [random]",   &gen_api_json_random(1_000, 42));
}
#[test]
fn benchmark_api_5k() {
    measure("api-json 5k [periodic]", &gen_api_json_periodic(5_000));
    measure("api-json 5k [random]",   &gen_api_json_random(5_000, 42));
}

#[test]
fn benchmark_summary() {
    let assets = Path::new(env!("CARGO_MANIFEST_DIR")).join("../assets");

    println!();
    println!("{:=<148}", "");
    let build = if cfg!(debug_assertions) { "debug  (run with --release for representative throughput numbers)" } else { "release" };
    println!("  SCTE encoding results  [build: {build}]");
    println!("  All rows verified: decode(encode(input)) == input (canonical JSON comparison)");
    println!("  zstd columns are reference data only.");
    println!("  [periodic] = all fields cycle with small periods — columnar period detector stores base cycle only.");
    println!("  [random]   = fields randomised independently per row via LCG.");
    println!("{:=<148}", "");
    println!(
        "  {:<48}  {:>11}  {:>15}  {:>13}  {:>13}  {:>15}  {:>15}",
        "Dataset", "Raw", "SCTE", "enc MB/s", "dec MB/s", "zstd -3 ref", "zstd -19 ref"
    );
    println!("{:-<148}", "");

    // ── Real asset files ─────────────────────────────────────────────────────
    // users_*.json structure: [{"id":N,"name":"...","friends":[{"name":"...","hobbies":[...]}]}]
    // Nested arrays prevent columnar activation — row-major text pipeline is used.
    println!("  [real files — assets/users_*.json  (nested JSON, row-major text pipeline)]");
    for name in &["users_100.json", "users_1k.json", "users_10k.json"] {
        let path = assets.join(name);
        if path.exists() {
            let data = std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
            measure(name, &data);
        } else {
            println!("  {name:<48}  (not found, skipped)");
        }
    }

    println!();

    // ── Real asset files — flat (columnar pipeline active) ────────────────────
    // flat_users_*.json: real users data with nested arrays stripped → 4 columns:
    //   id (sequential int → TAG_INT_RANS), name (high-card string → TAG_STRPREFIX or RAW_STR),
    //   city (25 distinct → TAG_ENUM_RANS), age (int 18-99 → TAG_INT or TAG_INT_RANS).
    // Generated from assets/users_*.json by stripping non-scalar fields.
    println!("  [real files — assets/flat_users_*.json  (flat real data, columnar pipeline active)]");
    for name in &["flat_users_1k.json", "flat_users_10k.json", "flat_users_100k.json"] {
        let path = assets.join(name);
        if path.exists() {
            let data = std::fs::read(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
            measure(name, &data);
        } else {
            println!("  {name:<48}  (not found, skipped)");
        }
    }

    println!();
    // ── UUID + base64 payload data (entropy ceiling probe) ───────────────────────
    // UUID primary key → TAG_UUID packs 16 B vs 36 chars/row.
    // Base64 payload → TAG_BASE64 packs decoded bytes vs encoded chars.
    // "entropy ceiling": even at maximum-entropy per field, ratio should stay sane.
    println!("  [entropy ceiling — UUID primary keys + base64 payloads + random latencies]");
    for &n in &[1_000usize, 10_000] {
        measure(
            &format!("uuid-b64 {n:>5} rows [entropy]"),
            &gen_uuid_json(n, 42),
        );
    }

    println!();
    // ── Semi-structured (realistic service-mesh telemetry) ────────────────────
    // Categorical fields: small vocab (service×8, env×3, dc×6, status codes×15)
    // Value fields: sequential IDs, random latencies, random trace IDs
    // Not purely periodic, not purely random — typical real-world API log shape.
    println!("  [synthetic flat JSON — semi-structured: small-vocab categoricals + random value fields]");
    for &n in &[1_000usize, 5_000, 10_000] {
        measure(
            &format!("api-semi  {n:>5} rows [semi]"),
            &gen_api_json_semi(n, 42),
        );
    }

    println!();

    // ── Synthetic flat JSON — LCG random ─────────────────────────────────────
    println!("  [synthetic flat JSON — random fields, no cycling pattern]");
    for &n in &[1_000usize, 5_000, 10_000] {
        measure(
            &format!("log-json {n:>5} rows [random]"),
            &gen_log_json(n, 42),
        );
    }

    println!();

    // ── Synthetic flat JSON — periodic (columnar pipeline active) ─────────────
    println!("  [synthetic flat JSON — cycling fields (i%4 / i%100 / i%28), columnar pipeline active]");
    for &n in &[1_000usize, 5_000, 10_000] {
        measure(
            &format!("api-json {n:>5} rows [periodic]"),
            &gen_api_json_periodic(n),
        );
    }

    println!();

    // ── Synthetic flat JSON — all fields independently randomised ─────────────
    println!("  [synthetic flat JSON — all fields independently randomised per row]");
    for &n in &[1_000usize, 5_000, 10_000] {
        measure(
            &format!("api-json {n:>5} rows [random]"),
            &gen_api_json_random(n, 42),
        );
    }

    println!("{:=<148}", "");
    println!();
}
