// SPDX-License-Identifier: MIT

//! Data cipher of a peer, the payload of `UWGPEER_A_CIPHER`.

use std::fmt;

use crate::constants::{UWG_CIPHER_AES256GCM, UWG_CIPHER_CHACHA20POLY1305};

/// Data cipher negotiated for the transport packets of a peer.
///
/// The value mirrors `enum uwg_cipher` of the UmbraWG UAPI header. An absent
/// `UWGPEER_A_CIPHER` attribute means
/// [`ChaCha20Poly1305`](Self::ChaCha20Poly1305), so old configurations and
/// old userspace clients keep working unchanged.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum UmbrawgCipher {
    /// `UWG_CIPHER_CHACHA20POLY1305`: the default WireGuard cipher.
    #[default]
    ChaCha20Poly1305,
    /// `UWG_CIPHER_AES256GCM`: AES-256-GCM with a 96-bit nonce.
    Aes256Gcm,
}

impl UmbrawgCipher {
    /// Returns the numeric `enum uwg_cipher` value.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::ChaCha20Poly1305 => UWG_CIPHER_CHACHA20POLY1305,
            Self::Aes256Gcm => UWG_CIPHER_AES256GCM,
        }
    }

    /// Converts a numeric `enum uwg_cipher` value.
    ///
    /// Returns `None` for values the kernel does not accept.
    #[must_use]
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            UWG_CIPHER_CHACHA20POLY1305 => Some(Self::ChaCha20Poly1305),
            UWG_CIPHER_AES256GCM => Some(Self::Aes256Gcm),
            _ => None,
        }
    }

    /// Returns the canonical lowercase name used by the configuration files
    /// and by the userspace UAPI.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
            Self::Aes256Gcm => "aes-256-gcm",
        }
    }
}

impl fmt::Display for UmbrawgCipher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
