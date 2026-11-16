//! HKDF-based key derivation and transcript hashing for Noise IK.

use std::sync::OnceLock;

use umbrawg_crypto::blake2s::{self, Blake2s, HASH_LEN};
use zeroize::Zeroize;

/// Noise protocol construction name.
pub const NOISE_CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

/// WireGuard protocol identifier mixed into the initial hash.
pub const WG_IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";

/// Label used to derive the MAC1 key from a static public key.
pub const WG_LABEL_MAC1: &[u8] = b"mac1----";

/// Label used to derive the cookie key from a static public key.
pub const WG_LABEL_COOKIE: &[u8] = b"cookie--";

const BLOCK_LEN: usize = 64;
const ONE: &[u8] = &[0x01];
const TWO: &[u8] = &[0x02];
const THREE: &[u8] = &[0x03];

fn hmac(key: &[u8], chunks: &[&[u8]]) -> [u8; HASH_LEN] {
    let mut block = [0u8; BLOCK_LEN];
    if key.len() > BLOCK_LEN {
        let digest = blake2s::hash(key);
        block[..HASH_LEN].copy_from_slice(&digest);
        let mut digest = digest;
        digest.zeroize();
    } else {
        block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = block;
    for byte in &mut inner_pad {
        *byte ^= 0x36;
    }

    let mut inner = Blake2s::new();
    inner.update(&inner_pad);
    for chunk in chunks {
        inner.update(chunk);
    }
    let mut inner_digest = inner.finalize();
    inner_pad.zeroize();

    let mut outer_pad = block;
    for byte in &mut outer_pad {
        *byte ^= 0x5c;
    }
    block.zeroize();

    let mut outer = Blake2s::new();
    outer.update(&outer_pad);
    outer.update(&inner_digest);
    let digest = outer.finalize();

    outer_pad.zeroize();
    inner_digest.zeroize();
    digest
}

/// Derives one 32-byte key from `chaining_key` and `input` (KDF1).
#[must_use]
pub fn kdf1(chaining_key: &[u8; HASH_LEN], input: &[u8]) -> [u8; HASH_LEN] {
    let mut secret = hmac(chaining_key, &[input]);
    let output = hmac(&secret, &[ONE]);
    secret.zeroize();
    output
}

/// Derives two 32-byte keys from `chaining_key` and `input` (KDF2).
#[must_use]
pub fn kdf2(chaining_key: &[u8; HASH_LEN], input: &[u8]) -> ([u8; HASH_LEN], [u8; HASH_LEN]) {
    let mut secret = hmac(chaining_key, &[input]);
    let first = hmac(&secret, &[ONE]);
    let second = hmac(&secret, &[&first, TWO]);
    secret.zeroize();
    (first, second)
}

/// Derives three 32-byte keys from `chaining_key` and `input` (KDF3).
#[must_use]
pub fn kdf3(
    chaining_key: &[u8; HASH_LEN],
    input: &[u8],
) -> ([u8; HASH_LEN], [u8; HASH_LEN], [u8; HASH_LEN]) {
    let mut secret = hmac(chaining_key, &[input]);
    let first = hmac(&secret, &[ONE]);
    let second = hmac(&secret, &[&first, TWO]);
    let third = hmac(&secret, &[&second, THREE]);
    secret.zeroize();
    (first, second, third)
}

/// Returns the initial chaining key derived from the construction name.
#[must_use]
pub fn initial_chain_key() -> [u8; HASH_LEN] {
    static VALUE: OnceLock<[u8; HASH_LEN]> = OnceLock::new();
    *VALUE.get_or_init(|| blake2s::hash(NOISE_CONSTRUCTION))
}

/// Returns the initial transcript hash derived from the construction name and
/// the WireGuard identifier.
#[must_use]
pub fn initial_hash() -> [u8; HASH_LEN] {
    static VALUE: OnceLock<[u8; HASH_LEN]> = OnceLock::new();
    *VALUE.get_or_init(|| {
        let chaining_key = initial_chain_key();
        let mut hasher = Blake2s::new();
        hasher.update(&chaining_key);
        hasher.update(WG_IDENTIFIER);
        hasher.finalize()
    })
}

pub(crate) fn hash_update(hash: &mut [u8; HASH_LEN], data: &[u8]) {
    let mut hasher = Blake2s::new();
    hasher.update(hash);
    hasher.update(data);
    *hash = hasher.finalize();
}

pub(crate) fn labeled_hash(label: &[u8], data: &[u8]) -> [u8; HASH_LEN] {
    let mut hasher = Blake2s::new();
    hasher.update(label);
    hasher.update(data);
    hasher.finalize()
}
