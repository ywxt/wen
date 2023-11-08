pub(crate) fn u32_to_tls_handshake_len(n: u32) -> [u8; 3] {
    let mut len = n & 0xffffff;
    let mut bytes = [0u8; 3];
    for i in 0..3 {
        bytes[2 - i] = (len & 0xff) as u8;
        len >>= 8;
    }
    bytes
}

#[cfg(test)]
mod tests {
    use crate::utils::u32_to_tls_handshake_len;

    #[test]
    fn test_u32_to_tls_handshake_len() {
        assert_eq!(u32_to_tls_handshake_len(0), [0, 0, 0]);
        assert_eq!(u32_to_tls_handshake_len(1), [0, 0, 1]);
        assert_eq!(u32_to_tls_handshake_len(2), [0, 0, 2]);
        assert_eq!(u32_to_tls_handshake_len(256), [0, 1, 0]);
        assert_eq!(u32_to_tls_handshake_len(65536), [1, 0, 0]);
    }
}
