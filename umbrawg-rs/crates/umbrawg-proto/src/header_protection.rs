//! ChaCha20-based header protection.
//!
//! The nonce is taken from the first [`NONCE_LEN`] bytes of a packet, which is
//! the `S1..S4` junk prefix. The keystream always starts at block counter zero.

use umbrawg_crypto::{chacha20, Key};

/// Length of the header protection nonce in bytes.
pub const NONCE_LEN: usize = chacha20::NONCE_LEN;

/// Length of one ChaCha20 keystream block in bytes.
pub const BLOCK_LEN: usize = 64;

/// Minimum `S1..S4` value required when header protection is enabled.
pub const MIN_PADDING: u16 = NONCE_LEN as u16;

/// Copies the nonce from the first twelve bytes of a packet.
#[must_use]
pub fn nonce_from_packet(packet: &[u8]) -> Option<[u8; NONCE_LEN]> {
    packet.get(..NONCE_LEN)?.try_into().ok()
}

/// Returns the first four keystream bytes used to mask the message type.
#[must_use]
pub fn mask4(key: &Key, nonce: &[u8; NONCE_LEN]) -> [u8; 4] {
    chacha20::mask4(key, nonce)
}

/// XORs an arbitrary header slice with the ChaCha20 keystream.
pub fn xor(key: &Key, nonce: &[u8; NONCE_LEN], data: &mut [u8]) {
    chacha20::xor(key, nonce, data);
}

/// ChaCha20 keystream positioned at block counter zero.
///
/// The first block is generated on construction so that a single block serves
/// both the type mask and the start of the header.
pub struct HeaderStream {
    block: [u8; BLOCK_LEN],
    stream: chacha20::Keystream,
}

impl HeaderStream {
    /// Creates a stream for `key` and `nonce` with the first block ready.
    #[must_use]
    pub fn new(key: &Key, nonce: &[u8; NONCE_LEN]) -> Self {
        let mut stream = chacha20::Keystream::new(key, nonce);
        let mut block = [0u8; BLOCK_LEN];
        stream.apply_keystream(&mut block);
        Self { block, stream }
    }

    /// Returns the first four keystream bytes.
    #[must_use]
    pub fn mask4(&self) -> [u8; 4] {
        [self.block[0], self.block[1], self.block[2], self.block[3]]
    }

    /// XORs `data` with the keystream, starting at block counter zero.
    pub fn apply(&mut self, data: &mut [u8]) {
        let cached = data.len().min(BLOCK_LEN);
        for (byte, mask) in data[..cached].iter_mut().zip(&self.block[..cached]) {
            *byte ^= mask;
        }
        if data.len() > cached {
            self.stream.apply_keystream(&mut data[cached..]);
        }
    }
}

impl core::fmt::Debug for HeaderStream {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("HeaderStream")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_is_first_twelve_bytes() {
        let packet = b"UmbraWGS1234rest";
        assert_eq!(nonce_from_packet(packet), Some(*b"UmbraWGS1234"));
        assert_eq!(nonce_from_packet(b"short"), None);
    }

    #[test]
    fn mask_matches_go_vector() {
        let key = Key::from_bytes(core::array::from_fn(|index| 0x80 + index as u8));
        assert_eq!(mask4(&key, b"UmbraWGS1234"), [0x55, 0x39, 0x5a, 0x8b]);
    }

    #[test]
    fn header_stream_matches_reference_xor() {
        let key = Key::from_bytes(core::array::from_fn(|index| 0x80 + index as u8));
        let nonce = *b"UmbraWGS1234";
        let original = [0x5au8; 200];
        for length in [4usize, 16, 64, 68, 148] {
            let mut stream = HeaderStream::new(&key, &nonce);
            assert_eq!(
                stream.mask4(),
                chacha20::mask4(&key, &nonce),
                "mask differs at length {length}"
            );
            let mut produced = original;
            stream.apply(&mut produced[..length]);
            let mut reference = original;
            xor(&key, &nonce, &mut reference[..length]);
            assert_eq!(produced, reference, "keystream differs at length {length}");
        }
    }

    #[test]
    fn header_stream_is_involutive() {
        let key = Key::from_bytes([7u8; 32]);
        let nonce = *b"UmbraWGS1234";
        let original = [0x11u8; 32];
        let mut data = original;
        HeaderStream::new(&key, &nonce).apply(&mut data);
        HeaderStream::new(&key, &nonce).apply(&mut data);
        assert_eq!(data, original);
    }
}
