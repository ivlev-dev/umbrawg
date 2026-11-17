//! UmbraWG cryptographic primitives.
//!
//! The crate exposes the primitives required by the WireGuard/UmbraWG noise
//! handshake and transport data path: BLAKE2s, ChaCha20-Poly1305 in the
//! WireGuard nonce format, raw ChaCha20 keystream for header protection,
//! X25519, TAI64N timestamps and a CSPRNG facade.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod aead;
pub mod blake2s;
pub mod chacha20;
mod key;
pub mod random;
pub mod tai64n;

pub use key::{Key, KeyError, PrivateKey, PublicKey, KEY_LEN};
