use std::{env, fs, process};

use scte_core::{
    container::header::{ScteHeader, HEADER_SIZE},
    decode, encode,
};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        process::exit(1);
    }

    match args[1].as_str() {
        "encode"  => cmd_encode(&args[2..]),
        "decode"  => cmd_decode(&args[2..]),
        "inspect" => cmd_inspect(&args[2..]),
        "help" | "--help" | "-h" => {
            print_usage();
        }
        other => {
            eprintln!("error: unknown command '{other}'");
            print_usage();
            process::exit(1);
        }
    }
}

// ── Commands ──────────────────────────────────────────────────────────────────

/// `scte encode <input> <output>`
fn cmd_encode(args: &[String]) {
    let (input_path, output_path) = require_two_args("encode", args);

    let input = read_file(input_path);
    let original_len = input.len();

    let encoded = encode(&input).unwrap_or_else(|e| {
        eprintln!("error: encode failed: {e}");
        process::exit(1);
    });

    let encoded_len = encoded.len();
    write_file(output_path, &encoded);

    let ratio = encoded_len as f64 / original_len.max(1) as f64;
    println!(
        "encode: {original_len} bytes → {encoded_len} bytes  (ratio {ratio:.3})"
    );
}

/// `scte decode <input> <output>`
fn cmd_decode(args: &[String]) {
    let (input_path, output_path) = require_two_args("decode", args);

    let input = read_file(input_path);
    let encoded_len = input.len();

    let decoded = decode(&input).unwrap_or_else(|e| {
        eprintln!("error: decode failed: {e}");
        process::exit(1);
    });

    let decoded_len = decoded.len();
    write_file(output_path, &decoded);

    println!("decode: {encoded_len} bytes → {decoded_len} bytes  ✓ checksum ok");
}

/// `scte inspect <input>`
///
/// Prints a human-readable summary of a SCTE container's header and section table.
fn cmd_inspect(args: &[String]) {
    if args.is_empty() {
        eprintln!("usage: scte inspect <input.scte>");
        process::exit(1);
    }

    let input = read_file(&args[0]);

    if input.len() < HEADER_SIZE {
        eprintln!("error: file too short to be a SCTE container");
        process::exit(1);
    }

    let header = ScteHeader::read(&input[0..HEADER_SIZE]).unwrap_or_else(|e| {
        eprintln!("error: invalid header: {e}");
        process::exit(1);
    });

    println!("── SCTE Container ──────────────────────────────");
    println!("  format version : 0x{:02x}", header.version);
    println!("  flags          : 0x{:02x}", header.flags);
    println!("  pipeline_id    : 0x{:02x}  ({:?})", header.pipeline_id as u8, header.pipeline_id);
    println!("  original_size  : {} bytes", header.original_size);
    println!("  section_count  : {}", header.section_count);
    println!("  file_size      : {} bytes", input.len());
    println!("────────────────────────────────────────────────");
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn require_two_args<'a>(cmd: &str, args: &'a [String]) -> (&'a str, &'a str) {
    if args.len() < 2 {
        eprintln!("usage: scte {cmd} <input> <output>");
        process::exit(1);
    }
    (args[0].as_str(), args[1].as_str())
}

fn read_file(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| {
        eprintln!("error: cannot read '{path}': {e}");
        process::exit(1);
    })
}

fn write_file(path: &str, data: &[u8]) {
    fs::write(path, data).unwrap_or_else(|e| {
        eprintln!("error: cannot write '{path}': {e}");
        process::exit(1);
    });
}

fn print_usage() {
    println!("scte — Semantic Compression & Transport Engine (Phase 1)");
    println!();
    println!("USAGE:");
    println!("  scte encode  <input>      <output.scte>   Wrap file in SCTE container");
    println!("  scte decode  <input.scte> <output>        Reconstruct original file");
    println!("  scte inspect <input.scte>                 Print container metadata");
    println!("  scte help                                  Show this message");
}
