//! Cookie validation and generation compatible with `cookie.c`.

use core::fmt;
use std::time::{Duration, Instant};

use rand_core::RngCore;
use subtle::ConstantTimeEq;
use umbrawg_crypto::aead;
use umbrawg_crypto::blake2s::{self, HASH_LEN, MAC_LEN};
use umbrawg_crypto::{Key, PublicKey, KEY_LEN};
use umbrawg_proto::messages::limits::{COOKIE_SECRET_LATENCY, COOKIE_SECRET_MAX_AGE};
use umbrawg_proto::messages::{
    COOKIE_LEN, COOKIE_NONCE_LEN, COOKIE_REPLY_SIZE, MESSAGE_HANDSHAKE_COOKIE,
};
use umbrawg_proto::CookieReply;
use zeroize::Zeroize;

use crate::error::{NoiseError, Result};
use crate::kdf::{labeled_hash, WG_LABEL_COOKIE, WG_LABEL_MAC1};
use crate::StaticIdentity;

const COOKIE_MAX_AGE: Duration = Duration::from_secs(COOKIE_SECRET_MAX_AGE);
const COOKIE_USE_AGE: Duration = Duration::from_secs(COOKIE_SECRET_MAX_AGE - COOKIE_SECRET_LATENCY);

fn split_macs(message: &[u8]) -> Option<(&[u8], &[u8])> {
    let mac2_start = message.len().checked_sub(MAC_LEN)?;
    let mac1_start = mac2_start.checked_sub(MAC_LEN)?;
    Some((&message[..mac1_start], &message[mac1_start..mac2_start]))
}

fn macs_equal(expected: &[u8; MAC_LEN], provided: &[u8]) -> bool {
    provided.len() == MAC_LEN && bool::from(expected.as_slice().ct_eq(provided))
}

/// Validates MAC1/MAC2 on incoming handshake messages and creates cookie
/// replies.
pub struct CookieChecker {
    mac1_key: [u8; HASH_LEN],
    cookie_encryption_key: Key,
    secret: Key,
    secret_birthdate: Instant,
}

impl CookieChecker {
    /// Creates a checker for the local static identity with a random secret.
    pub fn new(identity: &StaticIdentity, rng: &mut impl RngCore, now: Instant) -> Self {
        let mut secret = [0u8; KEY_LEN];
        rng.fill_bytes(&mut secret);
        Self::from_secret(identity, Key::from_bytes(secret), now)
    }

    /// Creates a checker with an explicit cookie secret.
    #[must_use]
    pub fn from_secret(identity: &StaticIdentity, secret: Key, now: Instant) -> Self {
        let public = identity.public_key();
        Self {
            mac1_key: labeled_hash(WG_LABEL_MAC1, public.as_bytes()),
            cookie_encryption_key: Key::from_bytes(labeled_hash(
                WG_LABEL_COOKIE,
                public.as_bytes(),
            )),
            secret,
            secret_birthdate: now,
        }
    }

    /// Verifies the MAC1 field of a handshake message.
    #[must_use]
    pub fn check_mac1(&self, message: &[u8]) -> bool {
        let Some((data, mac1)) = split_macs(message) else {
            return false;
        };
        let expected = blake2s::keyed_16(&self.mac1_key, data);
        macs_equal(&expected, mac1)
    }

    /// Verifies the MAC2 field of a handshake message against the source
    /// address bytes and the current cookie secret.
    #[must_use]
    pub fn check_mac2(&self, message: &[u8], source: &[u8], now: Instant) -> bool {
        if now.saturating_duration_since(self.secret_birthdate) > COOKIE_MAX_AGE {
            return false;
        }
        if split_macs(message).is_none() {
            return false;
        }
        let mac2_start = message.len() - MAC_LEN;
        let mut cookie = blake2s::keyed_16(self.secret.as_bytes(), source);
        let expected = blake2s::keyed_16(&cookie, &message[..mac2_start]);
        cookie.zeroize();
        macs_equal(&expected, &message[mac2_start..])
    }

    /// Creates a cookie reply for an incoming handshake message.
    ///
    /// `source` is the endpoint address encoded as in the Go implementation,
    /// and `message_type` is the obfuscated wire type chosen by the caller.
    pub fn create_reply(
        &mut self,
        message: &[u8],
        receiver_index: u32,
        source: &[u8],
        message_type: u32,
        rng: &mut impl RngCore,
        now: Instant,
    ) -> Result<[u8; COOKIE_REPLY_SIZE]> {
        let Some((_, mac1)) = split_macs(message) else {
            return Err(NoiseError::MessageTooShort(message.len()));
        };

        if now.saturating_duration_since(self.secret_birthdate) > COOKIE_MAX_AGE {
            let mut secret = [0u8; KEY_LEN];
            rng.fill_bytes(&mut secret);
            self.secret = Key::from_bytes(secret);
            self.secret_birthdate = now;
        }

        let mut cookie = blake2s::keyed_16(self.secret.as_bytes(), source);
        let mut nonce = [0u8; COOKIE_NONCE_LEN];
        rng.fill_bytes(&mut nonce);

        let mut raw = [0u8; COOKIE_REPLY_SIZE];
        {
            let mut reply = CookieReply::from_array(&mut raw);
            reply.set_message_type(message_type);
            reply.set_receiver_index(receiver_index);
            *reply.nonce_mut() = nonce;

            let encrypted = reply.encrypted_cookie_mut();
            encrypted[..COOKIE_LEN].copy_from_slice(&cookie);
            aead::xseal_with_nonce(&self.cookie_encryption_key, &nonce, mac1, encrypted)
                .map_err(|_| NoiseError::CookieAuthentication)?;
        }
        cookie.zeroize();
        Ok(raw)
    }

    /// Returns `true` when the secret was created no later than the maximum
    /// cookie age.
    #[must_use]
    pub fn secret_is_fresh(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.secret_birthdate) <= COOKIE_MAX_AGE
    }
}

impl fmt::Debug for CookieChecker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CookieChecker(<redacted>)")
    }
}

/// Adds MAC1/MAC2 to outgoing handshake messages and consumes cookie replies.
pub struct CookieGenerator {
    mac1_key: [u8; HASH_LEN],
    cookie_decryption_key: Key,
    cookie: [u8; COOKIE_LEN],
    cookie_set: Option<Instant>,
    last_mac1: [u8; MAC_LEN],
    has_last_mac1: bool,
}

impl CookieGenerator {
    /// Creates a generator for the remote static public key.
    #[must_use]
    pub fn new(remote_static: PublicKey) -> Self {
        Self {
            mac1_key: labeled_hash(WG_LABEL_MAC1, remote_static.as_bytes()),
            cookie_decryption_key: Key::from_bytes(labeled_hash(
                WG_LABEL_COOKIE,
                remote_static.as_bytes(),
            )),
            cookie: [0u8; COOKIE_LEN],
            cookie_set: None,
            last_mac1: [0u8; MAC_LEN],
            has_last_mac1: false,
        }
    }

    /// Writes MAC1 and, when a fresh cookie is available, MAC2 into the last
    /// 32 bytes of `message`.
    pub fn add_macs(&mut self, message: &mut [u8], now: Instant) -> Result<()> {
        let length = message.len();
        let Some((data, _)) = split_macs(message) else {
            return Err(NoiseError::MessageTooShort(length));
        };

        let mac1 = blake2s::keyed_16(&self.mac1_key, data);
        let mac1_start = length - 2 * MAC_LEN;
        message[mac1_start..mac1_start + MAC_LEN].copy_from_slice(&mac1);
        self.last_mac1 = mac1;
        self.has_last_mac1 = true;

        let mac2_start = length - MAC_LEN;
        if self.cookie_is_fresh(now) {
            let mac2 = blake2s::keyed_16(&self.cookie, &message[..mac2_start]);
            message[mac2_start..].copy_from_slice(&mac2);
        } else {
            message[mac2_start..].fill(0);
        }
        Ok(())
    }

    /// Decrypts a cookie reply and stores the resulting cookie.
    pub fn consume_reply(&mut self, reply: &CookieReply<'_>, now: Instant) -> Result<()> {
        if reply.message_type() != MESSAGE_HANDSHAKE_COOKIE {
            return Err(NoiseError::UnexpectedMessageType {
                expected: MESSAGE_HANDSHAKE_COOKIE,
                actual: reply.message_type(),
            });
        }
        if !self.has_last_mac1 {
            return Err(NoiseError::MissingMac1);
        }

        let mut encrypted = *reply.encrypted_cookie();
        let cookie = {
            let plaintext = aead::xopen_with_nonce(
                &self.cookie_decryption_key,
                reply.nonce(),
                &self.last_mac1,
                &mut encrypted,
            )
            .map_err(|_| NoiseError::CookieAuthentication)?;
            let mut cookie = [0u8; COOKIE_LEN];
            cookie.copy_from_slice(&plaintext[..COOKIE_LEN]);
            cookie
        };
        encrypted.zeroize();
        self.cookie = cookie;
        self.cookie_set = Some(now);
        self.has_last_mac1 = false;
        self.last_mac1.zeroize();
        Ok(())
    }

    /// Returns `true` when the stored cookie can still be used.
    #[must_use]
    pub fn has_cookie(&self, now: Instant) -> bool {
        self.cookie_is_fresh(now)
    }

    fn cookie_is_fresh(&self, now: Instant) -> bool {
        self.cookie_set
            .is_some_and(|set| now.saturating_duration_since(set) <= COOKIE_USE_AGE)
    }
}

impl fmt::Debug for CookieGenerator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CookieGenerator(<redacted>)")
    }
}
