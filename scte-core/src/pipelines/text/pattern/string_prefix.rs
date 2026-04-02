/// Prefix template encoder — Phase 6.
///
/// Detects strings sharing a `<prefix><integer>` pattern and delta-encodes suffixes.
///
/// # Wire format
/// ```text
/// varint(prefix_len) bytes(prefix) delta_encoded_suffixes   [prefix path]
/// varint(0) varint(count) [varint(len) bytes(str)]…         [fallback path]
/// ```

use crate::pipelines::text::delta::integer::{encode_delta_ints, decode_delta_ints};
use crate::varint;

/// Find the longest common byte prefix of a slice of strings.
pub fn common_prefix<'a>(strings: &[&'a str]) -> &'a str {
    if strings.is_empty() { return ""; }
    let first = strings[0];
    let mut len = first.len();
    for s in &strings[1..] {
        len = len.min(s.len());
        len = first.as_bytes()[..len].iter()
            .zip(s.as_bytes().iter())
            .take_while(|(a, b)| a == b)
            .count();
        if len == 0 { break; }
    }
    &first[..len]
}

/// Detect `<prefix><integer>` pattern. Returns `(prefix, suffixes)` or `("", [])`.
pub fn detect_prefix_pattern(strings: &[&str]) -> (String, Vec<i64>) {
    if strings.is_empty() { return (String::new(), Vec::new()); }
    let raw_prefix = common_prefix(strings);
    if raw_prefix.is_empty() { return (String::new(), Vec::new()); }
    // Trim trailing digit characters from the prefix so that the numeric suffix
    // is always complete (no leading zeros stripped by parse). For example,
    // "sess_1000" is trimmed to "sess_" so suffixes "1000000"–"1000999" round-
    // trip correctly rather than "000"–"999" losing leading zeros.
    let trimmed = raw_prefix.trim_end_matches(|c: char| c.is_ascii_digit());
    let prefix = if trimmed.is_empty() { raw_prefix } else { trimmed };
    let suffixes: Vec<Option<i64>> = strings.iter()
        .map(|s| s.strip_prefix(prefix)?.parse::<i64>().ok())
        .collect();
    let valid = suffixes.iter().filter(|s| s.is_some()).count();
    if valid * 100 / strings.len() < 80 { return (String::new(), Vec::new()); }
    (prefix.to_owned(), suffixes.into_iter().flatten().collect())
}

/// Encode strings using prefix template compression.
pub fn encode_prefix_strings(strings: &[&str]) -> Vec<u8> {
    let (prefix, suffixes) = detect_prefix_pattern(strings);
    let mut out = Vec::new();
    varint::encode_u64(prefix.len() as u64, &mut out);
    out.extend_from_slice(prefix.as_bytes());
    if prefix.is_empty() || suffixes.is_empty() {
        varint::encode_u64(strings.len() as u64, &mut out);
        for s in strings {
            varint::encode_u64(s.len() as u64, &mut out);
            out.extend_from_slice(s.as_bytes());
        }
    } else {
        out.extend_from_slice(&encode_delta_ints(&suffixes));
    }
    out
}

/// Decode bytes produced by [`encode_prefix_strings`].
pub fn decode_prefix_strings(data: &[u8]) -> Option<Vec<String>> {
    let mut pos = 0;
    let (pfx_len, n) = varint::decode_u64(data, pos)?; pos += n;
    if pfx_len == 0 {
        let (count, n) = varint::decode_u64(data, pos)?; pos += n;
        let mut out = Vec::new();
        for _ in 0..count {
            let (slen, n) = varint::decode_u64(data, pos)?; pos += n;
            let end = pos + slen as usize;
            if end > data.len() { return None; }
            out.push(std::str::from_utf8(&data[pos..end]).ok()?.to_owned());
            pos = end;
        }
        return Some(out);
    }
    let pfx_end = pos + pfx_len as usize;
    if pfx_end > data.len() { return None; }
    let prefix = std::str::from_utf8(&data[pos..pfx_end]).ok()?.to_owned();
    let suffixes = decode_delta_ints(&data[pfx_end..])?;
    Some(suffixes.iter().map(|&n| format!("{prefix}{n}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn common_prefix_simple() {
        // "user_001/002/003" share "user_00" (not "user_") — 3-digit zero-padded
        assert_eq!(common_prefix(&["user_001","user_002","user_003"]), "user_00");
        // non-padded: common prefix is exactly "user_"
        assert_eq!(common_prefix(&["user_1","user_2","user_3"]), "user_");
    }
    #[test] fn common_prefix_empty() {
        assert_eq!(common_prefix(&["abc","xyz"]), "");
    }
    #[test] fn detect_sequential_suffix() {
        let strs: Vec<String> = (1..=10).map(|i| format!("user_{i}")).collect();
        let refs: Vec<&str> = strs.iter().map(|s| s.as_str()).collect();
        let (prefix, suffixes) = detect_prefix_pattern(&refs);
        assert_eq!(prefix, "user_");
        assert_eq!(suffixes, (1..=10).map(|i| i as i64).collect::<Vec<_>>());
    }
    #[test] fn no_pattern_no_prefix() {
        let (p, s) = detect_prefix_pattern(&["alpha","beta","gamma"]);
        assert!(p.is_empty() && s.is_empty());
    }
    #[test] fn roundtrip_prefix() {
        // Use non-padded format so integer suffix roundtrip is lossless.
        let strs: Vec<String> = (0..20).map(|i| format!("req_{i}")).collect();
        let refs: Vec<&str> = strs.iter().map(|s| s.as_str()).collect();
        assert_eq!(decode_prefix_strings(&encode_prefix_strings(&refs)).unwrap(), strs);
    }
    #[test] fn roundtrip_fallback() {
        let strs = vec!["alpha","beta","gamma","delta"];
        assert_eq!(decode_prefix_strings(&encode_prefix_strings(&strs)).unwrap(), strs);
    }
    #[test] fn prefix_compresses_well() {
        let strs: Vec<String> = (0..100).map(|i| format!("user_{i:04}")).collect();
        let refs: Vec<&str> = strs.iter().map(|s| s.as_str()).collect();
        let enc_sz = encode_prefix_strings(&refs).len();
        let raw_sz: usize = strs.iter().map(|s| s.len()).sum();
        assert!(enc_sz < raw_sz / 2, "enc={enc_sz} raw={raw_sz}");
    }
}
