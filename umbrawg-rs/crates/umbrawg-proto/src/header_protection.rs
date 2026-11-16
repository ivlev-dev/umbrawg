//! ChaCha20-based header protection.
//!
//! The nonce is taken from the first [`NONCE_LEN`] bytes of a packet, which is
//! the `S1..S4` junk prefix. The keystream always starts at block counter zero.

use umbrawg_crypto::{chacha20, Key};

/// Length of the header protection nonce in bytes.
pub const NONCE_LEN: usize = chacha20::NONCE_LEN;

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
}
