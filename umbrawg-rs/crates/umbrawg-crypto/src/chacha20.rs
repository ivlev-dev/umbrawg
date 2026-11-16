//! Raw ChaCha20 keystream used by UmbraWG header protection.
//!
//! UmbraWG derives the nonce from the first twelve bytes of a packet (the
//! `S1..S4` junk prefix) and XORs a variable-length header prefix with the
//! ChaCha20 keystream starting at block counter zero.

use core::fmt;

use ::chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use ::chacha20::ChaCha20;

use crate::Key;

/// Length of the ChaCha20 nonce in bytes.
pub const NONCE_LEN: usize = 12;

/// A stateful ChaCha20 keystream generator.
pub struct Keystream {
    cipher: ChaCha20,
}

impl Keystream {
    /// Creates a keystream from a key and a 96-bit nonce.
    #[must_use]
    pub fn new(key: &Key, nonce: &[u8; NONCE_LEN]) -> Self {
        Self {
            cipher: ChaCha20::new_from_slices(key.as_bytes(), nonce)
                .expect("ChaCha20 requires a 32-byte key and a 12-byte nonce"),
        }
    }

    /// XORs the next keystream bytes into `data`.
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        self.cipher.apply_keystream(data);
    }

    /// Rewinds the keystream to block counter zero.
    pub fn reset(&mut self) {
        self.cipher.seek(0);
    }
}

impl fmt::Debug for Keystream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Keystream")
    }
}

/// XORs `data` with the ChaCha20 keystream from block counter zero.
pub fn xor(key: &Key, nonce: &[u8; NONCE_LEN], data: &mut [u8]) {
    Keystream::new(key, nonce).apply_keystream(data);
}

/// Returns the first four keystream bytes.
///
/// UmbraWG uses them to decode the protected message type field without
/// decrypting the whole header.
#[must_use]
pub fn mask4(key: &Key, nonce: &[u8; NONCE_LEN]) -> [u8; 4] {
    let mut mask = [0u8; 4];
    Keystream::new(key, nonce).apply_keystream(&mut mask);
    mask
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(input: &str) -> Vec<u8> {
        let bytes = input.as_bytes();
        (0..bytes.len() / 2)
            .map(|index| {
                let decode = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => panic!("invalid hex"),
                };
                (decode(bytes[index * 2]) << 4) | decode(bytes[index * 2 + 1])
            })
            .collect()
    }

    fn test_key() -> Key {
        Key::from_bytes(core::array::from_fn(|index| 0x80 + index as u8))
    }

    #[test]
    fn go_mask_vector() {
        let nonce = *b"UmbraWGS1234";
        assert_eq!(mask4(&test_key(), &nonce), [0x55, 0x39, 0x5a, 0x8b]);
    }

    #[test]
    fn go_header_vector() {
        let nonce = *b"UmbraWGS1234";
        let mut data = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f90919293");
        xor(&test_key(), &nonce, &mut data);
        assert_eq!(data, hex("55385888977c1fd5c623e75ce6123e1b82179e2a9fdc4e0ca708c6c7fa02948191dfdaf48528dc824af9c3c46caa3d63e39659d7378e5e46f6cfeac37742a9d89abedf10f2a0e3fa9b4317821dad78e2fcb7719f0999f06a2149a82172cc5e574d1015cadf5a91d80a7e3ce732fbd8f2c6982cca97ebe0d0a406de1590b7722b414d1796a40c8ccdf7ab6488d87df6afae3e5bf8"));
    }

    #[test]
    fn xor_is_involutive() {
        let nonce = *b"UmbraWGS1234";
        let original = b"header bytes".to_vec();
        let mut data = original.clone();
        xor(&test_key(), &nonce, &mut data);
        assert_ne!(data, original);
        xor(&test_key(), &nonce, &mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn reset_rewinds_keystream() {
        let nonce = *b"UmbraWGS1234";
        let mut stream = Keystream::new(&test_key(), &nonce);
        let mut first = [0u8; 16];
        stream.apply_keystream(&mut first);
        stream.reset();
        let mut second = [0u8; 16];
        stream.apply_keystream(&mut second);
        assert_eq!(first, second);
    }
}
