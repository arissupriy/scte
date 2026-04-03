/// SCTE encoding benchmark.
///
/// Run with:
///   cargo test --test benchmark benchmark_summary -- --nocapture
///
/// Requires `zstd` binary on PATH (used as a reference point — no claims are made).
/// All rows verify: decode(encode(input)) == input (canonical JSON comparison).

use std::path::Path;
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
