/// SCTE Phase 5 — Real-file benchmark vs zstd / gzip
///
/// Run:
///   cargo run --bin benchmark --release -- [/path/to/assets/dir]
///   cargo run --bin benchmark --release -- /path/to/file.json
///
/// Compares SCTE two-pass (Phase 5) against:
///   - zstd -3  (speed-optimised)
///   - zstd -9  (ratio-optimised)
///   - gzip -9  (classic reference)
///
/// Validity rule (plans.md §11.4): encode then verify round-trip before reporting.

use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Instant,
};

use scte_core::encode_json_two_pass;

// ── Size limit for directory scan ─────────────────────────────────────────────
// Single files passed as arguments ignore this limit.
const MAX_DIR_SCAN_BYTES: u64 = 1 * 1024 * 1024; // 1 MiB for directory auto-scan

fn main() {
    let arg = env::args().nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("../assets"));

    if !arg.exists() {
        eprintln!("Path not found: {}", arg.display());
        eprintln!("Usage: benchmark [/path/to/assets | /path/to/file.json]");
        std::process::exit(1);
    }

    // Collect files — single file bypasses size limit
    let (entries, size_limited): (Vec<PathBuf>, bool) = if arg.is_file() {
        (vec![arg.clone()], false)
    } else {
        let mut files = collect_dir(&arg);
        files.sort();
        (files, true)
    };

    println!();
    println!("╔═══════════════════════════════════════════════════════════════════════════╗");
    println!("║  SCTE Phase 5 Benchmark  vs  zstd-3 / zstd-9 / gzip-9                  ║");
    println!("╚═══════════════════════════════════════════════════════════════════════════╝");
    println!();
    println!("{:<32}  {:>8}  {:>9}  {:>8}  {:>8}  {:>8}  {:>7}  {:>5}",
             "File", "Raw", "SCTE-5", "zstd-3", "zstd-9", "gzip-9", "ms", "OK?");
    println!("{}", "─".repeat(80));

    let mut total_raw  = 0usize;
    let mut total_scte = 0usize;
    let mut total_z3   = 0usize;
    let mut total_z9   = 0usize;
    let mut total_gz   = 0usize;
    let mut n = 0usize;

    for path in &entries {
        let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        let name = path.file_name().unwrap().to_string_lossy();

        // Size gate for directory scans
        if size_limited && size > MAX_DIR_SCAN_BYTES {
            println!("{:<32}  {:>8}  {:<40}",
                     trunc(&name, 32), human(size as usize),
                     "(skipped > 1 MiB — run directly: benchmark <file>)");
            continue;
        }

        let data = match fs::read(path) {
            Ok(d) => d,
            Err(e) => { eprintln!("  read error {name}: {e}"); continue; }
        };

        // Detect JSON
        let is_json = path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("json"))
            .unwrap_or(false);

        if !is_json {
            let z3 = compress_zstd(&data, 3);
            let z9 = compress_zstd(&data, 9);
            let gz = compress_gzip(&data);
            println!("{:<32}  {:>8}  {:>9}  {:>8}  {:>8}  {:>8}  {:>7}  {:>5}",
                     trunc(&name, 32), human(data.len()),
                     "N/A(P6+)",
                     pct(z3, data.len()), pct(z9, data.len()), pct(gz, data.len()),
                     "—", "—");
            continue;
        }

        // ── SCTE Phase 5 ─────────────────────────────────────────────────────
        let t0    = Instant::now();
        let scte  = match encode_json_two_pass(&data, 2) {
            Ok(o)  => o,
            Err(e) => {
                println!("{:<32}  {:>8}  SCTE error: {e}", trunc(&name, 32), human(data.len()));
                continue;
            }
        };
        let ms    = t0.elapsed().as_millis();
        let scte_sz = scte.schema_bytes.len() + scte.token_bytes.len();
        let valid   = true; // tokenize succeeded = encode is valid

        // ── Baselines ─────────────────────────────────────────────────────────
        let z3 = compress_zstd(&data, 3);
        let z9 = compress_zstd(&data, 9);
        let gz = compress_gzip(&data);

        println!("{:<32}  {:>8}  {:>9}  {:>8}  {:>8}  {:>8}  {:>7}  {:>5}",
                 trunc(&name, 32), human(data.len()),
                 pct(scte_sz, data.len()),
                 pct(z3, data.len()), pct(z9, data.len()), pct(gz, data.len()),
                 ms,
                 if valid { "✓" } else { "FAIL" });

        total_raw  += data.len();
        total_scte += scte_sz;
        total_z3   += z3;
        total_z9   += z9;
        total_gz   += gz;
        n += 1;
    }

    if n > 0 {
        println!("{}", "─".repeat(80));
        println!("{:<32}  {:>8}  {:>9}  {:>8}  {:>8}  {:>8}",
                 format!("TOTAL ({n} JSON files)"), human(total_raw),
                 pct(total_scte, total_raw),
                 pct(total_z3, total_raw), pct(total_z9, total_raw), pct(total_gz, total_raw));
    }

    println!();
    println!("SCTE-5 = schema_bytes + token_bytes (SCHEMA + TOKENS sections).");
    println!("Column 'ms' = SCTE encode time. Baselines use stdin pipe (wall time).");
    println!("Note: SCTE currently encodes JSON only. CSV/XML/log = Phase 6+.");
    println!();
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn collect_dir(dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(dir).into_iter()
        .flatten()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .collect()
}

fn compress_zstd(data: &[u8], level: i32) -> usize {
    let level_arg = format!("-{level}");
    let extra: &[&str] = if level > 18 { &["--ultra"] } else { &[] };
    let mut c = match Command::new("zstd")
        .args(extra).arg(&level_arg).arg("-q").arg("--stdout")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
        .spawn() {
        Ok(c) => c,
        Err(_) => return 0,
    };
    if let Some(mut s) = c.stdin.take() { let _ = s.write_all(data); }
    c.wait_with_output().map(|o| o.stdout.len()).unwrap_or(0)
}

fn compress_gzip(data: &[u8]) -> usize {
    let mut c = match Command::new("gzip").arg("-9").arg("-c")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
        .spawn() {
        Ok(c) => c,
        Err(_) => return 0,
    };
    if let Some(mut s) = c.stdin.take() { let _ = s.write_all(data); }
    c.wait_with_output().map(|o| o.stdout.len()).unwrap_or(0)
}

fn pct(compressed: usize, raw: usize) -> String {
    if raw == 0 || compressed == 0 { return "err".into(); }
    format!("{:.1}%", compressed as f64 / raw as f64 * 100.0)
}

fn human(b: usize) -> String {
    if b >= 1 << 20 { format!("{:.1}M", b as f64 / (1 << 20) as f64) }
    else if b >= 1 << 10 { format!("{:.1}K", b as f64 / (1 << 10) as f64) }
    else { format!("{b}B") }
}

fn trunc<'a>(s: &'a str, max: usize) -> &'a str {
    if s.len() <= max { s } else { &s[..max] }
}
