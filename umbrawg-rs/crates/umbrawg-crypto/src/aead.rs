//! Transport AEAD ciphers in the WireGuard nonce format.
//!
//! WireGuard builds the 96-bit AEAD nonce as four zero bytes followed by the
//! 64-bit little-endian packet counter. All routines operate in place on a
//! caller-provided buffer and never allocate.
//!
//! The handshake and cookie messages always use ChaCha20-Poly1305 and
//! XChaCha20-Poly1305 respectively. Transport data may use either
//! ChaCha20-Poly1305 or AES-256-GCM, selected per peer; both use the same
//! 32-byte key and 16-byte tag, so the wire format does not change.

#[cfg(not(feature = "aes-ring"))]
use aes_gcm::Aes256Gcm;
#[cfg(any(feature = "aes-ring", feature = "ring-chacha"))]
use ring::aead::{Aad as RingAad, LessSafeKey as RingKey, Nonce as RingNonce};
use chacha20poly1305::aead::consts::{U12, U16, U24};
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, Tag, XChaCha20Poly1305, XNonce};

use crate::Key;

/// Length of an AEAD key in bytes.
pub const KEY_LEN: usize = 32;

/// Length of the Poly1305 authentication tag in bytes.
pub const TAG_LEN: usize = 16;

/// Length of the WireGuard AEAD nonce in bytes.
pub const NONCE_LEN: usize = 12;

/// Length of an XChaCha20-Poly1305 nonce in bytes.
pub const XNONCE_LEN: usize = 24;

/// Errors returned by the AEAD routines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The authentication tag did not verify.
    #[error("authentication failed")]
    Authentication,
    /// Encryption failed because the message is too large.
    #[error("encryption failed")]
    Encryption,
    /// The provided buffer is too small for the requested operation.
    #[error("buffer too small: required {required} bytes, available {available}")]
    BufferTooSmall {
        /// Number of bytes required.
        required: usize,
        /// Number of bytes available.
        available: usize,
    },
}

/// Builds the WireGuard AEAD nonce for `counter`.
#[must_use]
pub fn nonce(counter: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

fn seal_with<C: AeadInPlace<NonceSize = U12, TagSize = U16>>(
    cipher: &C,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &mut [u8],
) -> Result<(), Error> {
    if buffer.len() < TAG_LEN {
        return Err(Error::BufferTooSmall {
            required: TAG_LEN,
            available: buffer.len(),
        });
    }
    let plaintext_len = buffer.len() - TAG_LEN;
    let (plaintext, tag) = buffer.split_at_mut(plaintext_len);
    let computed = cipher
        .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, plaintext)
        .map_err(|_| Error::Encryption)?;
    tag.copy_from_slice(&computed);
    Ok(())
}

fn open_with<'a, C: AeadInPlace<NonceSize = U12, TagSize = U16>>(
    cipher: &C,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &'a mut [u8],
) -> Result<&'a mut [u8], Error> {
    if buffer.len() < TAG_LEN {
        return Err(Error::BufferTooSmall {
            required: TAG_LEN,
            available: buffer.len(),
        });
    }
    let plaintext_len = buffer.len() - TAG_LEN;
    let (plaintext, tag) = buffer.split_at_mut(plaintext_len);
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(nonce),
            aad,
            plaintext,
            Tag::from_slice(tag),
        )
        .map_err(|_| Error::Authentication)?;
    Ok(plaintext)
}

#[cfg(any(feature = "aes-ring", feature = "ring-chacha"))]
fn ring_seal(
    cipher: &RingKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &mut [u8],
) -> Result<(), Error> {
    if buffer.len() < TAG_LEN {
        return Err(Error::BufferTooSmall {
            required: TAG_LEN,
            available: buffer.len(),
        });
    }
    let plaintext_len = buffer.len() - TAG_LEN;
    let (plaintext, tag) = buffer.split_at_mut(plaintext_len);
    let computed = cipher
        .seal_in_place_separate_tag(
            RingNonce::assume_unique_for_key(*nonce),
            RingAad::from(aad),
            plaintext,
        )
        .map_err(|_| Error::Encryption)?;
    tag.copy_from_slice(computed.as_ref());
    Ok(())
}

#[cfg(any(feature = "aes-ring", feature = "ring-chacha"))]
fn ring_open<'a>(
    cipher: &RingKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &'a mut [u8],
) -> Result<&'a mut [u8], Error> {
    cipher
        .open_in_place(
            RingNonce::assume_unique_for_key(*nonce),
            RingAad::from(aad),
            buffer,
        )
        .map_err(|_| Error::Authentication)
}

#[cfg(any(feature = "aes-ring", feature = "ring-chacha"))]
fn ring_open_detached(
    cipher: &RingKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8],
) -> Result<(), Error> {
    if tag.len() != TAG_LEN {
        return Err(Error::BufferTooSmall {
            required: TAG_LEN,
            available: tag.len(),
        });
    }
    let mut combined = vec![0u8; buffer.len() + TAG_LEN];
    combined[..buffer.len()].copy_from_slice(buffer);
    combined[buffer.len()..].copy_from_slice(tag);
    let plaintext = ring_open(cipher, nonce, aad, &mut combined)?;
    if plaintext.len() != buffer.len() {
        return Err(Error::Authentication);
    }
    buffer.copy_from_slice(plaintext);
    Ok(())
}

#[cfg(any(not(feature = "aes-ring"), not(feature = "ring-chacha")))]
fn open_detached_with<C: AeadInPlace<NonceSize = U12, TagSize = U16>>(
    cipher: &C,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8],
) -> Result<(), Error> {
    let tag: &[u8; TAG_LEN] = tag.try_into().map_err(|_| Error::BufferTooSmall {
        required: TAG_LEN,
        available: tag.len(),
    })?;
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(nonce), aad, buffer, Tag::from_slice(tag))
        .map_err(|_| Error::Authentication)
}

fn xseal_with<C: AeadInPlace<NonceSize = U24, TagSize = U16>>(
    cipher: &C,
    nonce: &[u8; XNONCE_LEN],
    aad: &[u8],
    buffer: &mut [u8],
) -> Result<(), Error> {
    if buffer.len() < TAG_LEN {
        return Err(Error::BufferTooSmall {
            required: TAG_LEN,
            available: buffer.len(),
        });
    }
    let plaintext_len = buffer.len() - TAG_LEN;
    let (plaintext, tag) = buffer.split_at_mut(plaintext_len);
    let computed = cipher
        .encrypt_in_place_detached(XNonce::from_slice(nonce), aad, plaintext)
        .map_err(|_| Error::Encryption)?;
    tag.copy_from_slice(&computed);
    Ok(())
}

fn xopen_with<'a, C: AeadInPlace<NonceSize = U24, TagSize = U16>>(
    cipher: &C,
    nonce: &[u8; XNONCE_LEN],
    aad: &[u8],
    buffer: &'a mut [u8],
) -> Result<&'a mut [u8], Error> {
    if buffer.len() < TAG_LEN {
        return Err(Error::BufferTooSmall {
            required: TAG_LEN,
            available: buffer.len(),
        });
    }
    let plaintext_len = buffer.len() - TAG_LEN;
    let (plaintext, tag) = buffer.split_at_mut(plaintext_len);
    cipher
        .decrypt_in_place_detached(
            XNonce::from_slice(nonce),
            aad,
            plaintext,
            Tag::from_slice(tag),
        )
        .map_err(|_| Error::Authentication)?;
    Ok(plaintext)
}

/// Seals `buffer` in place with an explicit 96-bit nonce.
pub fn seal_with_nonce(
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &mut [u8],
) -> Result<(), Error> {
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
        .expect("ChaCha20-Poly1305 requires a 32-byte key");
    seal_with(&cipher, nonce, aad, buffer)
}

/// Opens `buffer` in place with an explicit 96-bit nonce.
pub fn open_with_nonce<'a>(
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buffer: &'a mut [u8],
) -> Result<&'a mut [u8], Error> {
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
        .expect("ChaCha20-Poly1305 requires a 32-byte key");
    open_with(&cipher, nonce, aad, buffer)
}

/// Seals a message in place using the WireGuard counter nonce.
///
/// `buffer` must contain the plaintext followed by [`TAG_LEN`] free bytes.
/// After the call the buffer contains the ciphertext followed by the tag.
pub fn seal_in_place(key: &Key, counter: u64, aad: &[u8], buffer: &mut [u8]) -> Result<(), Error> {
    seal_with_nonce(key, &nonce(counter), aad, buffer)
}

/// Opens a message in place using the WireGuard counter nonce.
///
/// `buffer` must contain the ciphertext followed by the tag. On success the
/// returned slice is the plaintext.
pub fn open_in_place<'a>(
    key: &Key,
    counter: u64,
    aad: &[u8],
    buffer: &'a mut [u8],
) -> Result<&'a mut [u8], Error> {
    open_with_nonce(key, &nonce(counter), aad, buffer)
}

/// Seals `plaintext` into `dst`, returning the ciphertext length.
pub fn seal_into(
    key: &Key,
    counter: u64,
    aad: &[u8],
    plaintext: &[u8],
    dst: &mut [u8],
) -> Result<usize, Error> {
    let total = plaintext.len() + TAG_LEN;
    if dst.len() < total {
        return Err(Error::BufferTooSmall {
            required: total,
            available: dst.len(),
        });
    }
    dst[..plaintext.len()].copy_from_slice(plaintext);
    seal_in_place(key, counter, aad, &mut dst[..total])?;
    Ok(total)
}

/// Opens `ciphertext` into `dst`, returning the plaintext length.
pub fn open_into(
    key: &Key,
    counter: u64,
    aad: &[u8],
    ciphertext: &[u8],
    dst: &mut [u8],
) -> Result<usize, Error> {
    if ciphertext.len() < TAG_LEN {
        return Err(Error::BufferTooSmall {
            required: TAG_LEN,
            available: ciphertext.len(),
        });
    }
    let plaintext_len = ciphertext.len() - TAG_LEN;
    if dst.len() < plaintext_len {
        return Err(Error::BufferTooSmall {
            required: plaintext_len,
            available: dst.len(),
        });
    }
    dst[..plaintext_len].copy_from_slice(&ciphertext[..plaintext_len]);
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
        .expect("ChaCha20-Poly1305 requires a 32-byte key");
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&nonce(counter)),
            aad,
            &mut dst[..plaintext_len],
            Tag::from_slice(&ciphertext[plaintext_len..]),
        )
        .map_err(|_| Error::Authentication)?;
    Ok(plaintext_len)
}

/// Seals `buffer` in place with an explicit 192-bit XChaCha nonce.
pub fn xseal_with_nonce(
    key: &Key,
    nonce: &[u8; XNONCE_LEN],
    aad: &[u8],
    buffer: &mut [u8],
) -> Result<(), Error> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .expect("XChaCha20-Poly1305 requires a 32-byte key");
    xseal_with(&cipher, nonce, aad, buffer)
}

/// Opens `buffer` in place with an explicit 192-bit XChaCha nonce.
pub fn xopen_with_nonce<'a>(
    key: &Key,
    nonce: &[u8; XNONCE_LEN],
    aad: &[u8],
    buffer: &'a mut [u8],
) -> Result<&'a mut [u8], Error> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .expect("XChaCha20-Poly1305 requires a 32-byte key");
    xopen_with(&cipher, nonce, aad, buffer)
}

/// Transport data cipher of a peer.
///
/// ChaCha20-Poly1305 is the default and is also used by the handshake; AES-256-GCM
/// is an opt-in per-peer alternative for transport packets. Both algorithms use
/// the same 32-byte key, 96-bit nonce and 16-byte tag.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// ChaCha20-Poly1305.
    #[default]
    ChaCha20Poly1305,
    /// AES-256-GCM.
    Aes256Gcm,
}

impl Algorithm {
    /// Returns the canonical lowercase name used by configuration files.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
            Self::Aes256Gcm => "aes-256-gcm",
        }
    }
}

enum Cipher {
    #[cfg(not(feature = "ring-chacha"))]
    ChaCha(ChaCha20Poly1305),
    #[cfg(not(feature = "aes-ring"))]
    Aes(Box<Aes256Gcm>),
    #[cfg(any(feature = "aes-ring", feature = "ring-chacha"))]
    Ring(Box<RingKey>),
}

impl Cipher {
    fn new(algorithm: Algorithm, key: &Key) -> Self {
        match algorithm {
            Algorithm::ChaCha20Poly1305 => {
                #[cfg(not(feature = "ring-chacha"))]
                {
                    Self::ChaCha(
                        ChaCha20Poly1305::new_from_slice(key.as_bytes())
                            .expect("ChaCha20-Poly1305 requires a 32-byte key"),
                    )
                }
                #[cfg(feature = "ring-chacha")]
                {
                    Self::Ring(Box::new(RingKey::new(
                        ring::aead::UnboundKey::new(
                            &ring::aead::CHACHA20_POLY1305,
                            key.as_bytes(),
                        )
                        .expect("ChaCha20-Poly1305 requires a 32-byte key"),
                    )))
                }
            }
            Algorithm::Aes256Gcm => {
                #[cfg(not(feature = "aes-ring"))]
                {
                    Self::Aes(Box::new(
                        Aes256Gcm::new_from_slice(key.as_bytes())
                            .expect("AES-256-GCM requires a 32-byte key"),
                    ))
                }
                #[cfg(feature = "aes-ring")]
                {
                    Self::Ring(Box::new(RingKey::new(
                        ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key.as_bytes())
                            .expect("AES-256-GCM requires a 32-byte key"),
                    )))
                }
            }
        }
    }

    fn seal(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<(), Error> {
        match self {
            #[cfg(not(feature = "ring-chacha"))]
            Self::ChaCha(cipher) => seal_with(cipher, nonce, aad, buffer),
            #[cfg(not(feature = "aes-ring"))]
            Self::Aes(cipher) => seal_with(cipher.as_ref(), nonce, aad, buffer),
            #[cfg(any(feature = "aes-ring", feature = "ring-chacha"))]
            Self::Ring(cipher) => ring_seal(cipher.as_ref(), nonce, aad, buffer),
        }
    }

    fn open<'a>(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &'a mut [u8],
    ) -> Result<&'a mut [u8], Error> {
        match self {
            #[cfg(not(feature = "ring-chacha"))]
            Self::ChaCha(cipher) => open_with(cipher, nonce, aad, buffer),
            #[cfg(not(feature = "aes-ring"))]
            Self::Aes(cipher) => open_with(cipher.as_ref(), nonce, aad, buffer),
            #[cfg(any(feature = "aes-ring", feature = "ring-chacha"))]
            Self::Ring(cipher) => ring_open(cipher.as_ref(), nonce, aad, buffer),
        }
    }

    fn open_detached(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), Error> {
        match self {
            #[cfg(not(feature = "ring-chacha"))]
            Self::ChaCha(cipher) => {
                open_detached_with(cipher, nonce, aad, buffer, tag)
            }
            #[cfg(not(feature = "aes-ring"))]
            Self::Aes(cipher) => open_detached_with(cipher.as_ref(), nonce, aad, buffer, tag),
            #[cfg(any(feature = "aes-ring", feature = "ring-chacha"))]
            Self::Ring(cipher) => ring_open_detached(cipher.as_ref(), nonce, aad, buffer, tag),
        }
    }
}

/// A reusable AEAD instance bound to one key and one transport cipher.
pub struct Aead {
    cipher: Cipher,
    algorithm: Algorithm,
}

impl Aead {
    /// Creates a ChaCha20-Poly1305 instance from a symmetric key.
    #[must_use]
    pub fn new(key: &Key) -> Self {
        Self::new_with(Algorithm::ChaCha20Poly1305, key)
    }

    /// Creates an instance of `algorithm` from a symmetric key.
    #[must_use]
    pub fn new_with(algorithm: Algorithm, key: &Key) -> Self {
        Self {
            cipher: Cipher::new(algorithm, key),
            algorithm,
        }
    }

    /// Returns the transport cipher of this instance.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Seals `buffer` in place with an explicit nonce.
    pub fn seal_with_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<(), Error> {
        self.cipher.seal(nonce, aad, buffer)
    }

    /// Opens `buffer` in place with an explicit nonce.
    pub fn open_with_nonce<'a>(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buffer: &'a mut [u8],
    ) -> Result<&'a mut [u8], Error> {
        self.cipher.open(nonce, aad, buffer)
    }

    /// Seals `buffer` in place using the WireGuard counter nonce.
    pub fn seal_in_place(&self, counter: u64, aad: &[u8], buffer: &mut [u8]) -> Result<(), Error> {
        self.seal_with_nonce(&nonce(counter), aad, buffer)
    }

    /// Opens `buffer` in place using the WireGuard counter nonce.
    pub fn open_in_place<'a>(
        &self,
        counter: u64,
        aad: &[u8],
        buffer: &'a mut [u8],
    ) -> Result<&'a mut [u8], Error> {
        self.open_with_nonce(&nonce(counter), aad, buffer)
    }

    /// Seals `plaintext` into `dst`, returning the ciphertext length.
    pub fn seal_into(
        &self,
        counter: u64,
        aad: &[u8],
        plaintext: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, Error> {
        let total = plaintext.len() + TAG_LEN;
        if dst.len() < total {
            return Err(Error::BufferTooSmall {
                required: total,
                available: dst.len(),
            });
        }
        dst[..plaintext.len()].copy_from_slice(plaintext);
        self.seal_in_place(counter, aad, &mut dst[..total])?;
        Ok(total)
    }

    /// Opens `ciphertext` into `dst`, returning the plaintext length.
    pub fn open_into(
        &self,
        counter: u64,
        aad: &[u8],
        ciphertext: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, Error> {
        if ciphertext.len() < TAG_LEN {
            return Err(Error::BufferTooSmall {
                required: TAG_LEN,
                available: ciphertext.len(),
            });
        }
        let plaintext_len = ciphertext.len() - TAG_LEN;
        if dst.len() < plaintext_len {
            return Err(Error::BufferTooSmall {
                required: plaintext_len,
                available: dst.len(),
            });
        }
        dst[..plaintext_len].copy_from_slice(&ciphertext[..plaintext_len]);
        self.cipher.open_detached(
            &nonce(counter),
            aad,
            &mut dst[..plaintext_len],
            &ciphertext[plaintext_len..],
        )?;
        Ok(plaintext_len)
    }
}

impl core::fmt::Debug for Aead {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Aead")
    }
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

    #[test]
    fn nonce_layout() {
        assert_eq!(nonce(7), [0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn go_wireguard_vector() {
        let key = Key::from_hex("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f")
            .unwrap();
        let aad = b"umbrawg-aad";
        let mut buffer = b"UmbraWG wire format test vector".to_vec();
        buffer.resize(buffer.len() + TAG_LEN, 0);
        seal_in_place(&key, 7, aad, &mut buffer).unwrap();
        assert_eq!(
            buffer,
            hex("dfd74256be43ec2fd28f1393abed6d953afc2d249f1814736ada0a42ec43e07f48f7e7dc53604398cb979cecb80694")
        );
    }

    #[test]
    fn rfc8439_vector() {
        let key = Key::from_bytes(core::array::from_fn(|index| 0x80 + index as u8));
        let nonce_bytes = hex("070000004041424344454647");
        let nonce: [u8; NONCE_LEN] = nonce_bytes.try_into().unwrap();
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let mut buffer = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();
        buffer.resize(buffer.len() + TAG_LEN, 0);
        seal_with_nonce(&key, &nonce, &aad, &mut buffer).unwrap();
        assert_eq!(
            buffer,
            hex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691")
        );
    }

    #[test]
    fn xchacha_vector() {
        let key = Key::from_bytes(core::array::from_fn(|index| 0x20 + index as u8));
        let nonce_bytes = hex("404142434445464748494a4b4c4d4e4f5051525354555657");
        let nonce: [u8; XNONCE_LEN] = nonce_bytes.try_into().unwrap();
        let aad = b"awg-cookie";
        let mut buffer = b"cookie secret".to_vec();
        buffer.resize(buffer.len() + TAG_LEN, 0);
        xseal_with_nonce(&key, &nonce, aad, &mut buffer).unwrap();
        assert_eq!(
            buffer,
            hex("594e02c24f03ddac121d9d5d900b58315a2b8468289df4d3cbb3944438")
        );
        let plaintext = xopen_with_nonce(&key, &nonce, aad, &mut buffer).unwrap();
        assert_eq!(plaintext, b"cookie secret");
    }

    #[test]
    fn roundtrip_and_tamper() {
        let key = Key::from_bytes([0x42; KEY_LEN]);
        let aad = b"aad";
        let mut buffer = b"payload".to_vec();
        buffer.resize(buffer.len() + TAG_LEN, 0);
        seal_in_place(&key, 1, aad, &mut buffer).unwrap();
        buffer[0] ^= 1;
        assert_eq!(
            open_in_place(&key, 1, aad, &mut buffer).unwrap_err(),
            Error::Authentication
        );
    }

    #[test]
    fn small_buffer_is_rejected() {
        let key = Key::from_bytes([0x42; KEY_LEN]);
        let mut buffer = [0u8; TAG_LEN - 1];
        assert_eq!(
            seal_in_place(&key, 0, &[], &mut buffer).unwrap_err(),
            Error::BufferTooSmall {
                required: TAG_LEN,
                available: TAG_LEN - 1
            }
        );
        assert_eq!(
            open_in_place(&key, 0, &[], &mut buffer).unwrap_err(),
            Error::BufferTooSmall {
                required: TAG_LEN,
                available: TAG_LEN - 1
            }
        );
    }

    #[test]
    fn into_helpers_roundtrip() {
        let key = Key::from_bytes([0x24; KEY_LEN]);
        let mut sealed = [0u8; 11 + TAG_LEN];
        let length = seal_into(&key, 9, b"", b"hello world", &mut sealed).unwrap();
        assert_eq!(length, 11 + TAG_LEN);
        let mut opened = [0u8; 11];
        let length = open_into(&key, 9, b"", &sealed[..length], &mut opened).unwrap();
        assert_eq!(&opened[..length], b"hello world");
    }

    #[test]
    fn reusable_aead_matches_free_functions() {
        let key = Key::from_bytes([0x55; KEY_LEN]);
        let aead = Aead::new(&key);
        let mut first = b"first".to_vec();
        first.resize(first.len() + TAG_LEN, 0);
        let mut second = first.clone();
        aead.seal_in_place(3, b"ad", &mut first).unwrap();
        seal_in_place(&key, 3, b"ad", &mut second).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn aes256gcm_nist_vector() {
        let key = Key::from_bytes([0u8; KEY_LEN]);
        let aead = Aead::new_with(Algorithm::Aes256Gcm, &key);
        let mut buffer = [0u8; 16 + TAG_LEN];
        aead.seal_in_place(0, &[], &mut buffer).unwrap();
        assert_eq!(
            &buffer[..16],
            hex("cea7403d4d606b6e074ec5d3baf39d18").as_slice()
        );
        assert_eq!(
            &buffer[16..],
            hex("d0d1c8a799996bf0265b98b5d48ab919").as_slice()
        );
        let plaintext = aead.open_in_place(0, &[], &mut buffer).unwrap();
        assert_eq!(plaintext, [0u8; 16]);
    }

    #[test]
    fn aes256gcm_round_trip_and_tamper() {
        let key = Key::from_bytes([0x42; KEY_LEN]);
        let aead = Aead::new_with(Algorithm::Aes256Gcm, &key);
        assert_eq!(aead.algorithm(), Algorithm::Aes256Gcm);
        let mut buffer = b"payload".to_vec();
        buffer.resize(buffer.len() + TAG_LEN, 0);
        aead.seal_in_place(1, b"aad", &mut buffer).unwrap();
        let mut tampered = buffer.clone();
        tampered[0] ^= 1;
        assert_eq!(
            aead.open_in_place(1, b"aad", &mut tampered).unwrap_err(),
            Error::Authentication
        );
        let plaintext = aead.open_in_place(1, b"aad", &mut buffer).unwrap();
        assert_eq!(plaintext, b"payload");
    }

    #[test]
    fn ciphers_do_not_interoperate() {
        let key = Key::from_bytes([0x33; KEY_LEN]);
        let chacha = Aead::new(&key);
        let aes = Aead::new_with(Algorithm::Aes256Gcm, &key);
        let mut sealed = b"secret".to_vec();
        sealed.resize(sealed.len() + TAG_LEN, 0);
        chacha.seal_in_place(5, b"", &mut sealed).unwrap();
        assert_eq!(
            aes.open_in_place(5, b"", &mut sealed).unwrap_err(),
            Error::Authentication
        );
    }
}
