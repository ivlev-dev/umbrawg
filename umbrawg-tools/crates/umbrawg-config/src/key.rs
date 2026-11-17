use std::fmt;
use std::io::Write;
use std::path::Path;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::Error;

pub const KEY_LEN: usize = 32;
pub const KEY_BASE64_LEN: usize = 44;
pub const KEY_HEX_LEN: usize = 64;

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Key([u8; KEY_LEN]);

impl Key {
    pub const LEN: usize = KEY_LEN;

    pub const fn zero() -> Self {
        Self([0u8; KEY_LEN])
    }

    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    pub fn to_bytes(&self) -> [u8; KEY_LEN] {
        self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }

    pub fn clamp(&mut self) {
        clamp_integer(&mut self.0);
    }

    pub fn public_key(&self) -> Self {
        let secret = StaticSecret::from(self.0);
        let public = X25519PublicKey::from(&secret);
        Self(public.to_bytes())
    }

    pub fn generate() -> Result<Self, Error> {
        let mut bytes = [0u8; KEY_LEN];
        getrandom::fill(&mut bytes).map_err(|error| Error::Random(error.to_string()))?;
        clamp_integer(&mut bytes);
        Ok(Self(bytes))
    }

    pub fn generate_unclamped() -> Result<Self, Error> {
        let mut bytes = [0u8; KEY_LEN];
        getrandom::fill(&mut bytes).map_err(|error| Error::Random(error.to_string()))?;
        Ok(Self(bytes))
    }

    pub fn to_base64(&self) -> String {
        BASE64.encode(self.0)
    }

    pub fn from_base64(value: &str) -> Result<Self, Error> {
        if value.len() != KEY_BASE64_LEN {
            return Err(Error::InvalidKey("expected 44 base64 characters"));
        }
        if !value.ends_with('=') {
            return Err(Error::InvalidKey("missing base64 padding"));
        }
        let decoded = BASE64
            .decode(value)
            .map_err(|_| Error::InvalidKey("not valid base64"))?;
        let bytes: [u8; KEY_LEN] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidKey("decoded key is not 32 bytes"))?;
        let key = Self(bytes);
        if key.to_base64() != value {
            return Err(Error::InvalidKey("non-canonical base64"));
        }
        Ok(key)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(value: &str) -> Result<Self, Error> {
        if value.len() != KEY_HEX_LEN {
            return Err(Error::InvalidKey("expected 64 hexadecimal characters"));
        }
        let decoded = hex::decode(value).map_err(|_| Error::InvalidKey("not valid hexadecimal"))?;
        let bytes: [u8; KEY_LEN] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidKey("decoded key is not 32 bytes"))?;
        Ok(Self(bytes))
    }

    pub fn from_bytes_slice(value: &[u8]) -> Result<Self, Error> {
        let bytes: [u8; KEY_LEN] = value
            .try_into()
            .map_err(|_| Error::InvalidKey("key is not 32 bytes"))?;
        Ok(Self(bytes))
    }

    pub fn from_file(path: &Path) -> Result<Self, Error> {
        let contents = std::fs::read(path)?;
        Self::from_file_contents(&contents)
    }

    pub fn from_file_contents(contents: &[u8]) -> Result<Self, Error> {
        let end = contents
            .iter()
            .rposition(|byte| !byte.is_ascii_whitespace())
            .map_or(0, |index| index + 1);
        if end == 0 {
            return Ok(Self::zero());
        }
        let text = std::str::from_utf8(&contents[..end])
            .map_err(|_| Error::InvalidKey("not valid UTF-8"))?;
        if text.len() != KEY_BASE64_LEN {
            return Err(Error::InvalidKey("invalid key length in key file"));
        }
        Self::from_base64(text)
    }

    pub fn write_base64<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writeln!(writer, "{}", self.to_base64())
    }
}

fn clamp_integer(bytes: &mut [u8; KEY_LEN]) {
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base64())
    }
}

impl From<[u8; KEY_LEN]> for Key {
    fn from(value: [u8; KEY_LEN]) -> Self {
        Self(value)
    }
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIVATE: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const PUBLIC: &str = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=";

    #[test]
    fn base64_round_trip() {
        let key = Key::from_base64(PRIVATE).expect("valid key");
        assert_eq!(key.to_base64(), PRIVATE);
        assert_eq!(Key::from_base64(&key.to_base64()).expect("round trip"), key);
    }

    #[test]
    fn hex_round_trip() {
        let key = Key::from_base64(PRIVATE).expect("valid key");
        let hex = key.to_hex();
        assert_eq!(hex.len(), KEY_HEX_LEN);
        assert_eq!(Key::from_hex(&hex).expect("round trip"), key);
        assert_eq!(Key::from_hex(&hex.to_uppercase()).expect("upper hex"), key);
    }

    #[test]
    fn public_key_vector() {
        let private = Key::from_base64(PRIVATE).expect("valid key");
        assert_eq!(private.public_key().to_base64(), PUBLIC);
    }

    #[test]
    fn clamping_matches_wireguard() {
        let mut key = Key::from_base64(PRIVATE).expect("valid key");
        key.clamp();
        assert_eq!(key.as_bytes()[0] & 0b0000_0111, 0);
        assert_eq!(key.as_bytes()[31] & 0b1000_0000, 0);
        assert_eq!(key.as_bytes()[31] & 0b0100_0000, 0b0100_0000);
    }

    #[test]
    fn rejects_bad_base64() {
        assert!(Key::from_base64("").is_err());
        assert!(Key::from_base64(&PRIVATE[..43]).is_err());
        assert!(Key::from_base64(&format!("{PRIVATE}A")).is_err());
        assert!(Key::from_base64(&PRIVATE.replace('=', "A")).is_err());
        assert!(Key::from_base64("!Anz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=").is_err());
    }

    #[test]
    fn rejects_bad_hex() {
        assert!(Key::from_hex("").is_err());
        assert!(Key::from_hex(&"0".repeat(63)).is_err());
        assert!(Key::from_hex(&"z".repeat(64)).is_err());
    }

    #[test]
    fn zero_is_detected() {
        assert!(Key::zero().is_zero());
        assert!(!Key::from_base64(PRIVATE).expect("valid key").is_zero());
    }

    #[test]
    fn key_file_contents() {
        let mut contents = PRIVATE.as_bytes().to_vec();
        contents.extend_from_slice(b"\r\n");
        assert_eq!(
            Key::from_file_contents(&contents).expect("valid"),
            Key::from_base64(PRIVATE).expect("valid")
        );
        assert!(Key::from_file_contents(b"").expect("empty").is_zero());
        assert!(Key::from_file_contents(b"short").is_err());
        assert!(Key::from_file_contents(&[PRIVATE.as_bytes(), b"x"].concat()).is_err());
    }

    #[test]
    fn generated_keys_have_expected_shape() {
        let private = Key::generate().expect("random");
        assert_eq!(private.as_bytes()[0] & 0b0000_0111, 0);
        assert_eq!(private.as_bytes()[31] & 0b1000_0000, 0);
        assert_eq!(private.as_bytes()[31] & 0b0100_0000, 0b0100_0000);
        let psk = Key::generate_unclamped().expect("random");
        assert_eq!(psk.to_base64().len(), KEY_BASE64_LEN);
    }
}
