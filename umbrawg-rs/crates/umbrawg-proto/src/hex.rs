pub(crate) fn decode_hex(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if bytes.len() & 1 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for index in (0..bytes.len()).step_by(2) {
        let hi = decode_nibble(bytes[index])?;
        let lo = decode_nibble(bytes[index + 1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_lower_and_upper_case() {
        assert_eq!(decode_hex("deadBEEF"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(decode_hex(""), Some(Vec::new()));
    }

    #[test]
    fn rejects_odd_and_invalid() {
        assert_eq!(decode_hex("abc"), None);
        assert_eq!(decode_hex("zz"), None);
    }
}
