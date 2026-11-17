use core::fmt;

use rand_core::RngCore;
use subtle::{Choice, ConstantTimeEq};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of a symmetric key, public key and private key in bytes.
pub const KEY_LEN: usize = 32;

/// Errors produced while decoding textual key representations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    /// The input is not valid hexadecimal.
    #[error("invalid hexadecimal input")]
    InvalidHex,
    /// The input has the wrong number of hexadecimal characters.
    #[error("invalid hexadecimal length: expected {expected} characters, got {actual}")]
    InvalidLength {
        /// Expected number of hexadecimal characters.
        expected: usize,
        /// Actual number of hexadecimal characters.
        actual: usize,
    },
}

fn zero_bytes(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |acc, byte| acc | byte) == 0
}

fn decode_hex<const N: usize>(input: &str) -> Result<[u8; N], KeyError> {
    let bytes = input.as_bytes();
    if bytes.len() != N * 2 {
        return Err(KeyError::InvalidLength {
            expected: N * 2,
            actual: bytes.len(),
        });
    }
    let mut out = [0u8; N];
    for index in 0..N {
        let hi = decode_nibble(bytes[index * 2]).ok_or(KeyError::InvalidHex)?;
        let lo = decode_nibble(bytes[index * 2 + 1]).ok_or(KeyError::InvalidHex)?;
        out[index] = (hi << 4) | lo;
    }
    Ok(out)
}

fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn encode_hex(bytes: &[u8], formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

/// A 256-bit symmetric key.
///
/// The key is zeroized on drop and never printed by [`fmt::Debug`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key([u8; KEY_LEN]);

impl Key {
    /// Creates a key from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the raw key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Copies the raw key bytes out of the key.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; KEY_LEN] {
        self.0
    }

    /// Decodes a key from 64 hexadecimal characters.
    pub fn from_hex(input: &str) -> Result<Self, KeyError> {
        decode_hex(input).map(Self)
    }

    /// Returns `true` if every byte of the key is zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        zero_bytes(&self.0)
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Key(<redacted>)")
    }
}

impl ConstantTimeEq for Key {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Key {}

impl From<[u8; KEY_LEN]> for Key {
    fn from(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }
}

/// A 256-bit X25519 public key.
#[derive(Clone, Copy)]
pub struct PublicKey([u8; KEY_LEN]);

impl PublicKey {
    /// Creates a public key from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the raw public key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Copies the raw public key bytes out of the key.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; KEY_LEN] {
        self.0
    }

    /// Decodes a public key from 64 hexadecimal characters.
    pub fn from_hex(input: &str) -> Result<Self, KeyError> {
        decode_hex(input).map(Self)
    }

    /// Returns `true` if every byte of the public key is zero.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        zero_bytes(&self.0)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PublicKey(")?;
        encode_hex(&self.0, formatter)?;
        formatter.write_str(")")
    }
}

impl ConstantTimeEq for PublicKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for PublicKey {}

impl From<[u8; KEY_LEN]> for PublicKey {
    fn from(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }
}

/// A 256-bit X25519 private key.
///
/// The key is zeroized on drop and never printed by [`fmt::Debug`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey([u8; KEY_LEN]);

impl PrivateKey {
    /// Generates a clamped private key from a cryptographic random source.
    pub fn generate(rng: &mut impl RngCore) -> Self {
        let mut bytes = [0u8; KEY_LEN];
        rng.fill_bytes(&mut bytes);
        let mut key = Self(bytes);
        key.clamp();
        key
    }

    /// Creates a private key from raw bytes and clamps it.
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        let mut key = Self(bytes);
        key.clamp();
        key
    }

    /// Creates a private key from raw bytes without clamping.
    ///
    /// X25519 clamps the scalar during every multiplication, so unclamped
    /// input is still processed correctly and is required to reproduce
    /// published RFC 7748 test vectors.
    #[must_use]
    pub const fn from_bytes_unclamped(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Applies the X25519 clamping to the stored scalar.
    pub fn clamp(&mut self) {
        self.0[0] &= 248;
        self.0[KEY_LEN - 1] = (self.0[KEY_LEN - 1] & 127) | 64;
    }

    /// Returns the raw private key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Copies the raw private key bytes out of the key.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; KEY_LEN] {
        self.0
    }

    /// Derives the matching X25519 public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(x25519(self.0, X25519_BASEPOINT_BYTES))
    }

    /// Computes the X25519 shared secret with `peer`.
    ///
    /// Returns `None` when the result is the all-zero point, which happens for
    /// low-order public keys and must be rejected by the noise handshake.
    #[must_use]
    pub fn diffie_hellman(&self, peer: &PublicKey) -> Option<Key> {
        let shared = x25519(self.0, peer.0);
        if bool::from(shared.ct_eq(&[0u8; KEY_LEN])) {
            None
        } else {
            Some(Key(shared))
        }
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateKey(<redacted>)")
    }
}

impl ConstantTimeEq for PrivateKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for PrivateKey {}

#[cfg(test)]
mod tests {
    use rand_core::RngCore;

    use super::*;

    struct FixedRng(u8);

    impl RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0u8; 4];
            self.fill_bytes(&mut bytes);
            u32::from_le_bytes(bytes)
        }

        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0u8; 8];
            self.fill_bytes(&mut bytes);
            u64::from_le_bytes(bytes)
        }

        fn fill_bytes(&mut self, dst: &mut [u8]) {
            for byte in dst {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dst);
            Ok(())
        }
    }

    #[test]
    fn private_key_debug_is_redacted() {
        let key = PrivateKey::from_bytes([0xab; KEY_LEN]);
        assert_eq!(format!("{key:?}"), "PrivateKey(<redacted>)");
    }

    #[test]
    fn key_debug_is_redacted() {
        let key = Key::from_bytes([0xcd; KEY_LEN]);
        assert_eq!(format!("{key:?}"), "Key(<redacted>)");
    }

    #[test]
    fn public_key_debug_prints_hex() {
        let key = PublicKey::from_bytes([0x01; KEY_LEN]);
        assert_eq!(
            format!("{key:?}"),
            format!("PublicKey({})", "01".repeat(KEY_LEN))
        );
    }

    #[test]
    fn clamping_sets_expected_bits() {
        let mut key = PrivateKey::from_bytes_unclamped([0xff; KEY_LEN]);
        key.clamp();
        assert_eq!(key.as_bytes()[0], 0xf8);
        assert_eq!(key.as_bytes()[KEY_LEN - 1], 0x7f);
    }

    #[test]
    fn from_bytes_clamps() {
        let mut expected = [0xff; KEY_LEN];
        expected[0] &= 248;
        expected[KEY_LEN - 1] = (expected[KEY_LEN - 1] & 127) | 64;
        assert_eq!(PrivateKey::from_bytes([0xff; KEY_LEN]).to_bytes(), expected);
    }

    #[test]
    fn hex_roundtrip() {
        let hex = "11".repeat(KEY_LEN);
        assert_eq!(Key::from_hex(&hex).unwrap().to_bytes(), [0x11; KEY_LEN]);
        assert_eq!(
            PublicKey::from_hex(&hex).unwrap().to_bytes(),
            [0x11; KEY_LEN]
        );
    }

    #[test]
    fn hex_rejects_invalid_input() {
        assert_eq!(
            Key::from_hex("00"),
            Err(KeyError::InvalidLength {
                expected: 64,
                actual: 2
            })
        );
        assert_eq!(
            Key::from_hex(&"zz".repeat(KEY_LEN)),
            Err(KeyError::InvalidHex)
        );
    }

    #[test]
    fn generated_keys_differ() {
        let mut rng = FixedRng(0);
        let first = PrivateKey::generate(&mut rng);
        let second = PrivateKey::generate(&mut rng);
        assert_ne!(first.to_bytes(), second.to_bytes());
        assert_eq!(first.as_bytes()[0] & 7, 0);
    }

    #[test]
    fn rejects_low_order_public_key() {
        let private = PrivateKey::from_bytes([7; KEY_LEN]);
        let zero = PublicKey::from_bytes([0; KEY_LEN]);
        assert!(private.diffie_hellman(&zero).is_none());
    }

    fn decode_hex<const N: usize>(input: &str) -> [u8; N] {
        let bytes = input.as_bytes();
        let mut out = [0u8; N];
        for (index, slot) in out.iter_mut().enumerate() {
            let decode = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("invalid hex"),
            };
            *slot = (decode(bytes[index * 2]) << 4) | decode(bytes[index * 2 + 1]);
        }
        out
    }

    #[test]
    fn rfc7748_vectors() {
        let alice = PrivateKey::from_bytes_unclamped(decode_hex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        let bob = PrivateKey::from_bytes_unclamped(decode_hex(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        ));
        assert_eq!(
            alice.public_key().to_bytes(),
            decode_hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            bob.public_key().to_bytes(),
            decode_hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );
        let shared = alice.diffie_hellman(&bob.public_key()).unwrap();
        assert_eq!(
            shared.to_bytes(),
            decode_hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        );
        assert_eq!(
            shared.to_bytes(),
            bob.diffie_hellman(&alice.public_key()).unwrap().to_bytes()
        );
    }

    #[test]
    fn zero_key_detection() {
        assert!(Key::from_bytes([0; KEY_LEN]).is_zero());
        assert!(!Key::from_bytes([1; KEY_LEN]).is_zero());
        assert!(PublicKey::from_bytes([0; KEY_LEN]).is_zero());
    }
}
