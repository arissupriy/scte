/// Run-length encoding for repeated byte values — Phase 6.
///
/// # Wire format
/// ```text
/// varint(pair_count) [varint(value_len) bytes(value) varint(run)]…
/// ```

use crate::varint;

/// Encode using run-length encoding.
pub fn rle_encode(values: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    if values.is_empty() {
        varint::encode_u64(0, &mut out);
        return out;
    }
    let mut pairs: Vec<(&[u8], u64)> = Vec::new();
    let mut cur = values[0];
    let mut count = 1u64;
    for &v in &values[1..] {
        if v == cur { count += 1; }
        else { pairs.push((cur, count)); cur = v; count = 1; }
    }
    pairs.push((cur, count));
    varint::encode_u64(pairs.len() as u64, &mut out);
    for (val, run) in &pairs {
        varint::encode_u64(val.len() as u64, &mut out);
        out.extend_from_slice(val);
        varint::encode_u64(*run, &mut out);
    }
    out
}

/// Decode bytes produced by [`rle_encode`].
pub fn rle_decode(data: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut pos = 0;
    let (pair_count, n) = varint::decode_u64(data, pos)?; pos += n;
    let mut out = Vec::new();
    for _ in 0..pair_count {
        let (val_len, n) = varint::decode_u64(data, pos)?; pos += n;
        let end = pos + val_len as usize;
        if end > data.len() { return None; }
        let val = data[pos..end].to_vec(); pos = end;
        let (run, n) = varint::decode_u64(data, pos)?; pos += n;
        for _ in 0..run { out.push(val.clone()); }
    }
    Some(out)
}

/// Ratio: encoded_size / raw_size.
pub fn rle_ratio(values: &[&[u8]]) -> f64 {
    let raw: usize = values.iter().map(|v| v.len()).sum();
    if raw == 0 { return 1.0; }
    rle_encode(values).len() as f64 / raw as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rt(v: &[&[u8]]) -> Vec<Vec<u8>> {
        rle_decode(&rle_encode(v)).unwrap()
    }
    #[test] fn roundtrip_all_same() {
        let v: Vec<&[u8]> = vec![b"ok"; 100];
        let d = rt(&v);
        assert_eq!(d.len(), 100);
        assert!(d.iter().all(|x| x == b"ok"));
    }
    #[test] fn roundtrip_all_different() {
        let s: Vec<Vec<u8>> = (0..10).map(|i: u32| i.to_string().into_bytes()).collect();
        let v: Vec<&[u8]> = s.iter().map(|x| x.as_slice()).collect();
        assert_eq!(rt(&v), s);
    }
    #[test] fn roundtrip_mixed() {
        let v: Vec<&[u8]> = vec![b"ok",b"ok",b"ok",b"error",b"ok",b"ok"];
        let expected: Vec<Vec<u8>> = v.iter().map(|x| x.to_vec()).collect();
        assert_eq!(rt(&v), expected);
    }
    #[test] fn roundtrip_empty() { assert!(rt(&[]).is_empty()); }
    #[test] fn roundtrip_single() { assert_eq!(rt(&[b"hi"]), vec![b"hi".to_vec()]); }
    #[test] fn compresses_long_runs() {
        let v: Vec<&[u8]> = vec![b"active"; 500];
        let enc = rle_encode(&v);
        let raw: usize = v.iter().map(|x| x.len()).sum();
        assert!(enc.len() < raw / 10);
    }
    #[test] fn correct_pair_count() {
        let v: Vec<&[u8]> = vec![b"ok",b"ok",b"error",b"ok"];
        let enc = rle_encode(&v);
        let (n, _) = varint::decode_u64(&enc, 0).unwrap();
        assert_eq!(n, 3);
    }
}
