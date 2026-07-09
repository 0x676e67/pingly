/// Encode bytes as lowercase hexadecimal text.
pub fn hex_encode(data: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let data = data.as_ref();
    let mut encoded = String::with_capacity(data.len().saturating_mul(2));
    for byte in data {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::hex_encode;

    #[test]
    fn encodes_lowercase_hex() {
        assert_eq!(hex_encode([]), "");
        assert_eq!(hex_encode([0x00, 0x0f, 0x10, 0xab, 0xff]), "000f10abff");
    }
}
