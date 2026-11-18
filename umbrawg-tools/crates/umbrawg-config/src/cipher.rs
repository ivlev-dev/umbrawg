use std::fmt;
use std::str::FromStr;

use crate::error::Error;

/// Data cipher of a peer, the `Cipher` key of a `[Peer]` section.
///
/// The kernel selects the cipher per peer, so a single device can serve peers
/// using ChaCha20-Poly1305 and peers using AES-256-GCM at the same time. A
/// missing key means [`ChaCha20Poly1305`](Self::ChaCha20Poly1305), which keeps
/// old configurations working unchanged.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Cipher {
    /// ChaCha20-Poly1305, the default WireGuard cipher.
    #[default]
    ChaCha20Poly1305,
    /// AES-256-GCM.
    Aes256Gcm,
}

impl Cipher {
    /// Parses the textual representation (`chacha20-poly1305` or
    /// `aes-256-gcm`).
    ///
    /// The comparison is ASCII case-insensitive.
    pub fn parse(value: &str) -> Result<Self, Error> {
        if value.eq_ignore_ascii_case(Self::ChaCha20Poly1305.as_str()) {
            Ok(Self::ChaCha20Poly1305)
        } else if value.eq_ignore_ascii_case(Self::Aes256Gcm.as_str()) {
            Ok(Self::Aes256Gcm)
        } else {
            Err(Error::InvalidValue {
                line: 0,
                key: "Cipher".to_owned(),
                value: value.to_owned(),
            })
        }
    }

    /// Returns the canonical lowercase name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
            Self::Aes256Gcm => "aes-256-gcm",
        }
    }

    /// Returns the numeric `enum uwg_cipher` value of the kernel UAPI.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::ChaCha20Poly1305 => 0,
            Self::Aes256Gcm => 1,
        }
    }

    /// Converts a numeric `enum uwg_cipher` value.
    #[must_use]
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::ChaCha20Poly1305),
            1 => Some(Self::Aes256Gcm),
            _ => None,
        }
    }
}

impl fmt::Display for Cipher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Cipher {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_names() {
        assert_eq!(
            Cipher::parse("chacha20-poly1305").expect("valid"),
            Cipher::ChaCha20Poly1305
        );
        assert_eq!(
            Cipher::parse("aes-256-gcm").expect("valid"),
            Cipher::Aes256Gcm
        );
        assert_eq!(
            Cipher::parse("AES-256-GCM").expect("valid"),
            Cipher::Aes256Gcm
        );
        assert_eq!(
            "chacha20-poly1305".parse::<Cipher>().expect("valid"),
            Cipher::ChaCha20Poly1305
        );
    }

    #[test]
    fn rejects_unknown_names() {
        for value in ["", "aes", "chacha20poly1305", "aes256gcm", "gcm"] {
            assert!(Cipher::parse(value).is_err(), "{value}");
        }
    }

    #[test]
    fn formats_canonical_names() {
        assert_eq!(Cipher::ChaCha20Poly1305.to_string(), "chacha20-poly1305");
        assert_eq!(Cipher::Aes256Gcm.to_string(), "aes-256-gcm");
    }

    #[test]
    fn maps_wire_values() {
        assert_eq!(Cipher::default(), Cipher::ChaCha20Poly1305);
        assert_eq!(Cipher::ChaCha20Poly1305.as_u32(), 0);
        assert_eq!(Cipher::Aes256Gcm.as_u32(), 1);
        assert_eq!(Cipher::from_u32(0), Some(Cipher::ChaCha20Poly1305));
        assert_eq!(Cipher::from_u32(1), Some(Cipher::Aes256Gcm));
        assert_eq!(Cipher::from_u32(2), None);
    }
}
