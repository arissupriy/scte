/// Phase 1 benchmark — SCTE vs zstd level 3 / level 19
///
/// Run with:
///   cargo test --test benchmark -- --nocapture
///
/// Requires `zstd` binary on PATH.

use std::process::Command;
use scte_core::{encode, decode, canonicalize_json};

// ── Data generators ───────────────────────────────────────────────────────────

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

// ── zstd helper ───────────────────────────────────────────────────────────────

/// Compress `data` with `zstd` at the given level using the CLI binary.
/// Returns compressed length (or panics with a descriptive message if zstd is
/// not found on PATH).
fn zstd_compress(data: &[u8], level: i32) -> usize {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = Command::new("zstd")
        .args([&format!("-{level}"), "--no-progress", "-q", "-c", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("zstd not found — install zstd on PATH");

    child.stdin.take().unwrap().write_all(data).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "zstd exited non-zero");
    out.stdout.len()
}

// ── Benchmark helper ──────────────────────────────────────────────────────────

/// Print one benchmark row and assert roundtrip correctness.
fn bench(label: &str, data: &[u8]) {
    let raw = data.len();

    // SCTE encode
    let encoded    = encode(data).expect("scte encode failed");
    let scte_len   = encoded.len();
    let scte_ratio = scte_len as f64 / raw as f64 * 100.0;

    // Roundtrip verify (pipeline canonicalises key order)
    let decoded   = decode(&encoded).expect("scte decode failed");
    let canon_in  = canonicalize_json(data)    .expect("canonicalize input");
    let canon_out = canonicalize_json(&decoded).expect("canonicalize decoded");
    assert_eq!(canon_in, canon_out, "ROUNDTRIP MISMATCH for '{label}'");

    // zstd baselines
    let zstd3_len    = zstd_compress(data, 3);
    let zstd19_len   = zstd_compress(data, 19);
    let zstd3_ratio  = zstd3_len  as f64 / raw as f64 * 100.0;
    let zstd19_ratio = zstd19_len as f64 / raw as f64 * 100.0;

    let beats = if scte_len < zstd3_len { "✓" } else { " " };
    println!(
        "  {label:<45}  {raw:>9}B  {scte_len:>7}B {scte_ratio:5.1}%  \
         {zstd3_len:>7}B {zstd3_ratio:5.1}%  \
         {zstd19_len:>7}B {zstd19_ratio:5.1}%  {beats}"
    );
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn benchmark_log_1k() {
    let data = gen_log_json(1_000, 42);
    bench("log-json 1k records", &data);
}

#[test]
fn benchmark_log_5k() {
    let data = gen_log_json(5_000, 42);
    bench("log-json 5k records", &data);
}

#[test]
fn benchmark_log_10k() {
    let data = gen_log_json(10_000, 42);
    bench("log-json 10k records", &data);
}

#[test]
fn benchmark_api_1k() {
    let data = gen_api_json_periodic(1_000);
    bench("api-json PERIODIC 1k", &data);
    let data = gen_api_json_random(1_000, 42);
    bench("api-json RANDOM   1k", &data);
}

#[test]
fn benchmark_api_5k() {
    let data = gen_api_json_periodic(5_000);
    bench("api-json PERIODIC 5k", &data);
}

#[test]
fn benchmark_summary() {
    println!();
    println!("{:=<110}", "");
    println!("  SCTE Compression Benchmark (stateless — no shared dictionary, no prior state)");
    println!("{:=<110}", "");
    println!(
        "{:<47}  {:>10}  {:>14}  {:>14}  {:>15}",
        "Dataset / Mode", "Raw", "SCTE", "zstd -3", "zstd -19"
    );
    println!();
    println!("  NOTE: SCTE is purely stateless — encode() takes raw bytes, no prior context.");
    println!("  PERIODIC = data has cycling patterns (best case for SCTE period detector).");
    println!("  RANDOM   = fields randomised independently per row (fair vs zstd comparison).");
    println!("{:-<110}", "");

    let datasets: &[(&str, Vec<u8>)] = &[
        // --- structured log: randomised, no period ---
        ("log-json  1k  [random]",          gen_log_json(1_000,  42)),
        ("log-json  5k  [random]",          gen_log_json(5_000,  42)),
        ("log-json 10k  [random]",          gen_log_json(10_000, 42)),
        // --- api-json PERIODIC (i%4, i%100, i%28 cycling) ---
        ("api-json  1k  [periodic i%4…]",   gen_api_json_periodic(1_000)),
        ("api-json  5k  [periodic i%4…]",   gen_api_json_periodic(5_000)),
        ("api-json 10k  [periodic i%4…]",   gen_api_json_periodic(10_000)),
        // --- api-json RANDOM (independent LCG per row) ---
        ("api-json  1k  [random]",          gen_api_json_random(1_000,  42)),
        ("api-json  5k  [random]",          gen_api_json_random(5_000,  42)),
        ("api-json 10k  [random]",          gen_api_json_random(10_000, 42)),
    ];

    let mut prev_group = "";
    for (label, data) in datasets {
        // blank line between groups
        let group = if label.starts_with("log") { "log" } else if label.contains("periodic") { "api-p" } else { "api-r" };
        if group != prev_group && prev_group != "" { println!(); }
        prev_group = group;

        let raw        = data.len();
        let encoded    = encode(data).unwrap();
        let scte_len   = encoded.len();

        // Roundtrip assertion
        let decoded   = decode(&encoded).unwrap();
        let canon_in  = canonicalize_json(data)    .expect("canon in");
        let canon_out = canonicalize_json(&decoded).expect("canon out");
        assert_eq!(canon_in, canon_out, "ROUNDTRIP MISMATCH: {label}");

        let zstd3_len  = zstd_compress(data, 3);
        let zstd19_len = zstd_compress(data, 19);

        let scte_pct   = scte_len   as f64 / raw as f64 * 100.0;
        let zstd3_pct  = zstd3_len  as f64 / raw as f64 * 100.0;
        let zstd19_pct = zstd19_len as f64 / raw as f64 * 100.0;
        let beats      = if scte_len < zstd3_len { "✓" } else { " " };

        println!(
            "  {label:<45}  {raw:>9}B  {scte_len:>7}B {scte_pct:5.1}%  \
             {zstd3_len:>7}B {zstd3_pct:5.1}%  \
             {zstd19_len:>7}B {zstd19_pct:5.1}%  {beats}"
        );
    }

    println!("{:=<110}", "");
    println!("  ✓ = SCTE beats zstd -3  |  All rows verified: decode(encode(x)) == x");
    println!();
}
