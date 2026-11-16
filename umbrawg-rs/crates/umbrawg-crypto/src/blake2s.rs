//! BLAKE2s-256 hashing and keyed BLAKE2s MACs.

use core::fmt;

use blake2::digest::{consts::U16, KeyInit, Mac};
use blake2::{Blake2s256, Blake2sMac, Digest};

/// Length of a BLAKE2s-256 digest in bytes.
pub const HASH_LEN: usize = 32;

/// Length of the WireGuard `mac1`/`mac2` values in bytes.
pub const MAC_LEN: usize = 16;

/// BLAKE2s block size in bytes.
pub const BLOCK_LEN: usize = 64;

/// Incremental BLAKE2s-256 hasher.
#[derive(Clone)]
pub struct Blake2s(Blake2s256);

impl Blake2s {
    /// Creates an empty hasher.
    #[must_use]
    pub fn new() -> Self {
        Self(Blake2s256::new())
    }

    /// Feeds data into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.0, data);
    }

    /// Finalizes the hasher and returns the digest.
    #[must_use]
    pub fn finalize(self) -> [u8; HASH_LEN] {
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(&self.0.finalize());
        out
    }

    /// Finalizes the hasher and writes the digest into `out`.
    pub fn finalize_into(self, out: &mut [u8; HASH_LEN]) {
        out.copy_from_slice(&self.0.finalize());
    }
}

impl Default for Blake2s {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Blake2s {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Blake2s")
    }
}

/// Computes the BLAKE2s-256 digest of `data`.
#[must_use]
pub fn hash(data: &[u8]) -> [u8; HASH_LEN] {
    let mut out = [0u8; HASH_LEN];
    hash_into(data, &mut out);
    out
}

/// Computes the BLAKE2s-256 digest of `data` into `out`.
pub fn hash_into(data: &[u8], out: &mut [u8; HASH_LEN]) {
    out.copy_from_slice(&Blake2s256::digest(data));
}

/// Computes a keyed BLAKE2s MAC truncated to 16 bytes.
#[must_use]
pub fn keyed_16(key: &[u8], data: &[u8]) -> [u8; MAC_LEN] {
    let mut mac = <Blake2sMac<U16> as KeyInit>::new_from_slice(key)
        .expect("key length is bounded by the BLAKE2s block size");
    Mac::update(&mut mac, data);
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// Computes a keyed BLAKE2s MAC with the full 32-byte output.
#[must_use]
pub fn keyed_32(key: &[u8], data: &[u8]) -> [u8; HASH_LEN] {
    let mut mac = <Blake2sMac<blake2::digest::consts::U32> as KeyInit>::new_from_slice(key)
        .expect("key length is bounded by the BLAKE2s block size");
    Mac::update(&mut mac, data);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY: [u8; HASH_LEN] = [
        0x69, 0x21, 0x7a, 0x30, 0x79, 0x90, 0x80, 0x94, 0xe1, 0x11, 0x21, 0xd0, 0x42, 0x35, 0x4a,
        0x7c, 0x1f, 0x55, 0xb6, 0x48, 0x2c, 0xa1, 0xa5, 0x1e, 0x1b, 0x25, 0x0d, 0xfd, 0x1e, 0xd0,
        0xee, 0xf9,
    ];

    const ABC: [u8; HASH_LEN] = [
        0x50, 0x8c, 0x5e, 0x8c, 0x32, 0x7c, 0x14, 0xe2, 0xe1, 0xa7, 0x2b, 0xa3, 0x4e, 0xeb, 0x45,
        0x2f, 0x37, 0x45, 0x8b, 0x20, 0x9e, 0xd6, 0x3a, 0x29, 0x4d, 0x99, 0x9b, 0x4c, 0x86, 0x67,
        0x59, 0x82,
    ];

    #[test]
    fn rfc7693_empty_vector() {
        assert_eq!(hash(b""), EMPTY);
    }

    #[test]
    fn rfc7693_abc_vector() {
        assert_eq!(hash(b"abc"), ABC);
    }

    #[test]
    fn incremental_matches_one_shot() {
        let mut hasher = Blake2s::new();
        hasher.update(b"a");
        hasher.update(b"b");
        hasher.update(b"c");
        assert_eq!(hasher.finalize(), ABC);
    }

    #[test]
    fn go_keyed_vectors() {
        let key: [u8; 32] = core::array::from_fn(|index| index as u8);
        assert_eq!(
            keyed_16(&key, b"umbrawg test vector"),
            [
                0x28, 0x62, 0x2c, 0x01, 0x85, 0x79, 0x21, 0x91, 0x78, 0x25, 0x35, 0x47, 0xfa, 0x48,
                0x26, 0x83,
            ]
        );
        assert_eq!(
            keyed_32(&key, b"umbrawg test vector"),
            [
                0x8c, 0xd8, 0x17, 0xa3, 0x97, 0x3f, 0xd2, 0xfa, 0xfa, 0x33, 0xf4, 0x9c, 0x8f, 0xf8,
                0x96, 0x52, 0x71, 0x73, 0xc5, 0x4c, 0x22, 0x80, 0xe5, 0xec, 0xd9, 0x0b, 0xf4, 0x04,
                0x38, 0x72, 0x23, 0x6b,
            ]
        );
    }
}
