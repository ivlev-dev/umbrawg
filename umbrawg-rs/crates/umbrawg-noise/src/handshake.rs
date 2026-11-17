//! Noise IK handshake state machine.

use core::fmt;

use rand_core::RngCore;
use subtle::ConstantTimeEq;
use umbrawg_crypto::aead;
use umbrawg_crypto::blake2s::HASH_LEN;
use umbrawg_crypto::tai64n::Tai64N;
use umbrawg_crypto::{Key, PrivateKey, PublicKey, KEY_LEN};
use umbrawg_proto::messages::{
    INITIATION_SIZE, MESSAGE_HANDSHAKE_INITIATION, MESSAGE_HANDSHAKE_RESPONSE, RESPONSE_SIZE,
    TIMESTAMP_LEN,
};
use umbrawg_proto::{HandshakeInitiation, HandshakeResponse};
use zeroize::Zeroize;

use crate::error::{NoiseError, Result};
use crate::kdf::{hash_update, initial_chain_key, initial_hash, kdf2, kdf3};

const ZERO_NONCE: [u8; aead::NONCE_LEN] = [0u8; aead::NONCE_LEN];

/// State of a Noise IK handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HandshakeState {
    /// No handshake in progress.
    Zeroed,
    /// An initiation message was created by the initiator.
    InitiationCreated,
    /// An initiation message was consumed by the responder.
    InitiationConsumed,
    /// A response message was created by the responder.
    ResponseCreated,
    /// A response message was consumed by the initiator.
    ResponseConsumed,
}

/// A static X25519 identity.
///
/// Only the private key is stored; the public key is derived on demand.
#[derive(Clone)]
pub struct StaticIdentity {
    private: PrivateKey,
}

impl StaticIdentity {
    /// Creates an identity from a private key.
    #[must_use]
    pub fn new(private: PrivateKey) -> Self {
        Self { private }
    }

    /// Creates an identity from raw private key bytes and clamps the scalar.
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self::new(PrivateKey::from_bytes(bytes))
    }

    /// Generates a new identity from a cryptographic random source.
    pub fn generate(rng: &mut impl RngCore) -> Self {
        Self::new(PrivateKey::generate(rng))
    }

    /// Returns the derived public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.private.public_key()
    }

    /// Decrypts the static key of an initiation message.
    ///
    /// This is the first half of [`Handshake::consume_initiation`] and allows
    /// the caller to look up the peer by its decrypted static key before
    /// committing any handshake state.
    pub fn decrypt_initiation(&self, message: &HandshakeInitiation<'_>) -> Result<Initiation> {
        let mut hash = initial_hash();
        hash_update(&mut hash, self.public_key().as_bytes());

        let ephemeral = PublicKey::from_bytes(*message.ephemeral());
        hash_update(&mut hash, ephemeral.as_bytes());
        let chaining_key = crate::kdf::kdf1(&initial_chain_key(), ephemeral.as_bytes());

        let (chaining_key, key) = {
            let shared = self
                .private
                .diffie_hellman(&ephemeral)
                .ok_or(NoiseError::InvalidPublicKey)?;
            let (chaining_key, key) = kdf2(&chaining_key, shared.as_bytes());
            (chaining_key, Key::from_bytes(key))
        };

        let mut encrypted_static = *message.encrypted_static();
        let peer_static = {
            let plaintext = aead::open_with_nonce(&key, &ZERO_NONCE, &hash, &mut encrypted_static)
                .map_err(|_| NoiseError::Authentication)?;
            let mut bytes = [0u8; KEY_LEN];
            bytes.copy_from_slice(&plaintext[..KEY_LEN]);
            PublicKey::from_bytes(bytes)
        };
        hash_update(&mut hash, message.encrypted_static());
        encrypted_static.zeroize();

        Ok(Initiation {
            peer_static,
            ephemeral,
            hash,
            chaining_key,
        })
    }
}

impl fmt::Debug for StaticIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StaticIdentity(<redacted>)")
    }
}

/// Result of decrypting the static key of an initiation message.
pub struct Initiation {
    peer_static: PublicKey,
    ephemeral: PublicKey,
    hash: [u8; HASH_LEN],
    chaining_key: [u8; HASH_LEN],
}

impl Initiation {
    /// Returns the decrypted static public key of the initiator.
    #[must_use]
    pub fn peer_static(&self) -> PublicKey {
        self.peer_static
    }

    /// Returns the initiator ephemeral public key.
    #[must_use]
    pub fn ephemeral(&self) -> PublicKey {
        self.ephemeral
    }
}

impl fmt::Debug for Initiation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Initiation")
            .field("peer_static", &self.peer_static)
            .field("ephemeral", &self.ephemeral)
            .finish_non_exhaustive()
    }
}

impl Drop for Initiation {
    fn drop(&mut self) {
        self.hash.zeroize();
        self.chaining_key.zeroize();
    }
}

/// A peer handshake.
pub struct Handshake {
    state: HandshakeState,
    hash: [u8; HASH_LEN],
    chaining_key: [u8; HASH_LEN],
    preshared_key: Key,
    local_ephemeral: PrivateKey,
    local_index: u32,
    remote_index: u32,
    remote_static: PublicKey,
    remote_ephemeral: PublicKey,
    precomputed_static_static: Option<Key>,
    latest_timestamp: Tai64N,
}

impl Handshake {
    /// Creates a handshake for `remote_static`.
    ///
    /// The static-static shared secret is precomputed immediately. `identity`
    /// must be the same identity that is later passed to the message creation
    /// routines.
    #[must_use]
    pub fn new(identity: &StaticIdentity, remote_static: PublicKey, preshared_key: Key) -> Self {
        let precomputed_static_static = identity.private.diffie_hellman(&remote_static);
        Self {
            state: HandshakeState::Zeroed,
            hash: [0u8; HASH_LEN],
            chaining_key: [0u8; HASH_LEN],
            preshared_key,
            local_ephemeral: PrivateKey::from_bytes_unclamped([0u8; KEY_LEN]),
            local_index: 0,
            remote_index: 0,
            remote_static,
            remote_ephemeral: PublicKey::from_bytes([0u8; KEY_LEN]),
            precomputed_static_static,
            latest_timestamp: Tai64N::from_raw([0u8; TIMESTAMP_LEN]),
        }
    }

    /// Returns the current handshake state.
    #[must_use]
    pub fn state(&self) -> HandshakeState {
        self.state
    }

    /// Returns the local index assigned to the last created message.
    #[must_use]
    pub fn local_index(&self) -> u32 {
        self.local_index
    }

    /// Returns the remote index received in the last consumed message.
    #[must_use]
    pub fn remote_index(&self) -> u32 {
        self.remote_index
    }

    /// Returns the remote static public key.
    #[must_use]
    pub fn remote_static(&self) -> PublicKey {
        self.remote_static
    }

    /// Returns the greatest TAI64N timestamp consumed for this peer.
    #[must_use]
    pub fn latest_timestamp(&self) -> Tai64N {
        self.latest_timestamp
    }

    /// Returns `true` when the static-static shared secret is available.
    #[must_use]
    pub fn has_precomputed_static_static(&self) -> bool {
        self.precomputed_static_static.is_some()
    }

    /// Returns the current transcript hash.
    #[must_use]
    pub fn hash(&self) -> &[u8; HASH_LEN] {
        &self.hash
    }

    /// Returns the current chaining key.
    #[must_use]
    pub fn chaining_key(&self) -> &[u8; HASH_LEN] {
        &self.chaining_key
    }

    /// Mixes `data` into the transcript hash.
    pub fn mix_hash(&mut self, data: &[u8]) {
        hash_update(&mut self.hash, data);
    }

    /// Mixes `data` into the chaining key with KDF1.
    pub fn mix_key(&mut self, data: &[u8]) {
        self.chaining_key = crate::kdf::kdf1(&self.chaining_key, data);
    }

    /// Creates a handshake initiation message.
    ///
    /// `message_type` is the obfuscated wire type chosen by the caller.
    pub fn create_initiation(
        &mut self,
        identity: &StaticIdentity,
        rng: &mut impl RngCore,
        message_type: u32,
        sender_index: u32,
        timestamp: Tai64N,
    ) -> Result<[u8; INITIATION_SIZE]> {
        if self.precomputed_static_static.is_none() {
            return Err(NoiseError::MissingStaticStatic);
        }

        self.hash = initial_hash();
        self.chaining_key = initial_chain_key();
        let remote_static = self.remote_static;
        self.mix_hash(remote_static.as_bytes());

        let mut raw = [0u8; INITIATION_SIZE];
        {
            let mut message = HandshakeInitiation::from_array(&mut raw);
            message.set_message_type(message_type);
            message.set_sender_index(sender_index);

            self.local_ephemeral = PrivateKey::generate(rng);
            let ephemeral = self.local_ephemeral.public_key();
            *message.ephemeral_mut() = *ephemeral.as_bytes();
            self.mix_hash(message.ephemeral());
            self.mix_key(message.ephemeral());

            let (chaining_key, key) = {
                let shared = self
                    .local_ephemeral
                    .diffie_hellman(&self.remote_static)
                    .ok_or(NoiseError::InvalidPublicKey)?;
                let (chaining_key, key) = kdf2(&self.chaining_key, shared.as_bytes());
                (chaining_key, Key::from_bytes(key))
            };
            self.chaining_key = chaining_key;

            let encrypted = message.encrypted_static_mut();
            encrypted[..KEY_LEN].copy_from_slice(identity.public_key().as_bytes());
            aead::seal_with_nonce(&key, &ZERO_NONCE, &self.hash, encrypted)
                .map_err(|_| NoiseError::Authentication)?;
            self.mix_hash(message.encrypted_static());

            let (chaining_key, key) = {
                let precomputed = self
                    .precomputed_static_static
                    .as_ref()
                    .ok_or(NoiseError::MissingStaticStatic)?;
                let (chaining_key, key) = kdf2(&self.chaining_key, precomputed.as_bytes());
                (chaining_key, Key::from_bytes(key))
            };
            self.chaining_key = chaining_key;

            let encrypted = message.encrypted_timestamp_mut();
            encrypted[..TIMESTAMP_LEN].copy_from_slice(timestamp.as_bytes());
            aead::seal_with_nonce(&key, &ZERO_NONCE, &self.hash, encrypted)
                .map_err(|_| NoiseError::Authentication)?;
            self.mix_hash(message.encrypted_timestamp());
        }

        self.local_index = sender_index;
        self.state = HandshakeState::InitiationCreated;
        Ok(raw)
    }

    /// Consumes a decrypted initiation message for this peer.
    ///
    /// The caller obtains [`Initiation`] from
    /// [`StaticIdentity::decrypt_initiation`] after looking up the peer.
    pub fn consume_initiation(
        &mut self,
        mut initiation: Initiation,
        message: &HandshakeInitiation<'_>,
    ) -> Result<()> {
        if message.message_type() != MESSAGE_HANDSHAKE_INITIATION {
            return Err(NoiseError::UnexpectedMessageType {
                expected: MESSAGE_HANDSHAKE_INITIATION,
                actual: message.message_type(),
            });
        }
        if !bool::from(self.remote_static.ct_eq(&initiation.peer_static)) {
            return Err(NoiseError::PeerMismatch);
        }

        let (mut chaining_key, key) = {
            let precomputed = self
                .precomputed_static_static
                .as_ref()
                .ok_or(NoiseError::MissingStaticStatic)?;
            let (chaining_key, key) = kdf2(&initiation.chaining_key, precomputed.as_bytes());
            (chaining_key, Key::from_bytes(key))
        };
        let mut hash = initiation.hash;

        let mut encrypted_timestamp = *message.encrypted_timestamp();
        let timestamp = {
            let plaintext =
                aead::open_with_nonce(&key, &ZERO_NONCE, &hash, &mut encrypted_timestamp)
                    .map_err(|_| NoiseError::Authentication)?;
            let mut bytes = [0u8; TIMESTAMP_LEN];
            bytes.copy_from_slice(plaintext);
            Tai64N::from_raw(bytes)
        };
        hash_update(&mut hash, message.encrypted_timestamp());

        if *timestamp.as_bytes() <= *self.latest_timestamp.as_bytes() {
            encrypted_timestamp.zeroize();
            initiation.hash.zeroize();
            initiation.chaining_key.zeroize();
            hash.zeroize();
            chaining_key.zeroize();
            return Err(NoiseError::Replay);
        }

        self.remote_ephemeral = initiation.ephemeral;
        self.hash = hash;
        self.chaining_key = chaining_key;
        self.remote_index = message.sender_index();
        self.latest_timestamp = timestamp;
        self.state = HandshakeState::InitiationConsumed;

        encrypted_timestamp.zeroize();
        initiation.hash.zeroize();
        initiation.chaining_key.zeroize();
        hash.zeroize();
        chaining_key.zeroize();
        Ok(())
    }

    /// Creates a handshake response message.
    ///
    /// Requires [`HandshakeState::InitiationConsumed`].
    pub fn create_response(
        &mut self,
        rng: &mut impl RngCore,
        message_type: u32,
        sender_index: u32,
    ) -> Result<[u8; RESPONSE_SIZE]> {
        if self.state != HandshakeState::InitiationConsumed {
            return Err(NoiseError::InvalidState {
                expected: HandshakeState::InitiationConsumed,
                actual: self.state,
            });
        }

        let mut raw = [0u8; RESPONSE_SIZE];
        {
            let mut message = HandshakeResponse::from_array(&mut raw);
            message.set_message_type(message_type);
            message.set_sender_index(sender_index);
            message.set_receiver_index(self.remote_index);

            self.local_ephemeral = PrivateKey::generate(rng);
            let ephemeral = self.local_ephemeral.public_key();
            *message.ephemeral_mut() = *ephemeral.as_bytes();
            self.mix_hash(message.ephemeral());
            self.mix_key(message.ephemeral());

            let shared = self
                .local_ephemeral
                .diffie_hellman(&self.remote_ephemeral)
                .ok_or(NoiseError::InvalidPublicKey)?;
            self.mix_key(shared.as_bytes());

            let shared = self
                .local_ephemeral
                .diffie_hellman(&self.remote_static)
                .ok_or(NoiseError::InvalidPublicKey)?;
            self.mix_key(shared.as_bytes());

            let (chaining_key, tau, key) = {
                let psk = self.preshared_key.as_bytes();
                let (chaining_key, tau, key) = kdf3(&self.chaining_key, psk);
                (chaining_key, tau, Key::from_bytes(key))
            };
            self.chaining_key = chaining_key;
            self.mix_hash(&tau);

            let encrypted = message.encrypted_nothing_mut();
            aead::seal_with_nonce(&key, &ZERO_NONCE, &self.hash, encrypted)
                .map_err(|_| NoiseError::Authentication)?;
            self.mix_hash(message.encrypted_nothing());
        }

        self.local_index = sender_index;
        self.state = HandshakeState::ResponseCreated;
        Ok(raw)
    }

    /// Consumes a handshake response message.
    ///
    /// Requires [`HandshakeState::InitiationCreated`] and a response that
    /// addresses the local index of the initiation message.
    pub fn consume_response(
        &mut self,
        identity: &StaticIdentity,
        message: &HandshakeResponse<'_>,
    ) -> Result<()> {
        if message.message_type() != MESSAGE_HANDSHAKE_RESPONSE {
            return Err(NoiseError::UnexpectedMessageType {
                expected: MESSAGE_HANDSHAKE_RESPONSE,
                actual: message.message_type(),
            });
        }
        if self.state != HandshakeState::InitiationCreated {
            return Err(NoiseError::InvalidState {
                expected: HandshakeState::InitiationCreated,
                actual: self.state,
            });
        }
        if message.receiver_index() != self.local_index {
            return Err(NoiseError::InvalidReceiverIndex {
                expected: self.local_index,
                actual: message.receiver_index(),
            });
        }

        let ephemeral = PublicKey::from_bytes(*message.ephemeral());
        self.mix_hash(ephemeral.as_bytes());
        self.mix_key(ephemeral.as_bytes());

        let shared = self
            .local_ephemeral
            .diffie_hellman(&ephemeral)
            .ok_or(NoiseError::InvalidPublicKey)?;
        self.mix_key(shared.as_bytes());

        let shared = identity
            .private
            .diffie_hellman(&ephemeral)
            .ok_or(NoiseError::InvalidPublicKey)?;
        self.mix_key(shared.as_bytes());

        let (chaining_key, tau, key) = {
            let psk = self.preshared_key.as_bytes();
            let (chaining_key, tau, key) = kdf3(&self.chaining_key, psk);
            (chaining_key, tau, Key::from_bytes(key))
        };
        self.chaining_key = chaining_key;
        self.mix_hash(&tau);

        let mut encrypted = *message.encrypted_nothing();
        aead::open_with_nonce(&key, &ZERO_NONCE, &self.hash, &mut encrypted)
            .map_err(|_| NoiseError::Authentication)?;
        self.mix_hash(message.encrypted_nothing());
        encrypted.zeroize();

        self.remote_index = message.sender_index();
        self.state = HandshakeState::ResponseConsumed;
        Ok(())
    }

    /// Derives transport keys from a completed handshake.
    ///
    /// The handshake is reset afterwards; the replay timestamp and the
    /// precomputed static-static secret are retained.
    pub fn begin_session(&mut self) -> Result<Keypair> {
        let (send, receive, is_initiator) = match self.state {
            HandshakeState::ResponseConsumed => {
                let (send, receive) = kdf2(&self.chaining_key, &[]);
                (send, receive, true)
            }
            HandshakeState::ResponseCreated => {
                let (receive, send) = kdf2(&self.chaining_key, &[]);
                (send, receive, false)
            }
            actual => {
                return Err(NoiseError::InvalidState {
                    expected: HandshakeState::ResponseConsumed,
                    actual,
                })
            }
        };

        let mut send = send;
        let mut receive = receive;
        let keypair = Keypair {
            send_key: Key::from_bytes(send),
            receive_key: Key::from_bytes(receive),
            local_index: self.local_index,
            remote_index: self.remote_index,
            is_initiator,
        };
        send.zeroize();
        receive.zeroize();
        self.reset();
        Ok(keypair)
    }

    /// Clears transient handshake state.
    ///
    /// The replay timestamp, remote static key and static-static shared secret
    /// are preserved, matching `handshake_zero` from the kernel module.
    pub fn clear(&mut self) {
        self.reset();
    }

    fn reset(&mut self) {
        self.local_ephemeral.zeroize();
        self.remote_ephemeral = PublicKey::from_bytes([0u8; KEY_LEN]);
        self.hash.zeroize();
        self.chaining_key.zeroize();
        self.local_index = 0;
        self.remote_index = 0;
        self.state = HandshakeState::Zeroed;
    }
}

impl fmt::Debug for Handshake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Handshake")
            .field("state", &self.state)
            .field("local_index", &self.local_index)
            .field("remote_index", &self.remote_index)
            .field("remote_static", &self.remote_static)
            .field("latest_timestamp", &self.latest_timestamp)
            .finish_non_exhaustive()
    }
}

impl Drop for Handshake {
    fn drop(&mut self) {
        self.hash.zeroize();
        self.chaining_key.zeroize();
        self.local_ephemeral.zeroize();
    }
}

/// Transport keys derived from a completed handshake.
pub struct Keypair {
    send_key: Key,
    receive_key: Key,
    local_index: u32,
    remote_index: u32,
    is_initiator: bool,
}

impl Keypair {
    /// Returns the key used to encrypt outgoing transport messages.
    #[must_use]
    pub fn send_key(&self) -> &Key {
        &self.send_key
    }

    /// Returns the key used to decrypt incoming transport messages.
    #[must_use]
    pub fn receive_key(&self) -> &Key {
        &self.receive_key
    }

    /// Returns the local index of the keypair.
    #[must_use]
    pub fn local_index(&self) -> u32 {
        self.local_index
    }

    /// Returns the remote index of the keypair.
    #[must_use]
    pub fn remote_index(&self) -> u32 {
        self.remote_index
    }

    /// Returns `true` when the local side initiated the handshake.
    #[must_use]
    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Keypair")
            .field("local_index", &self.local_index)
            .field("remote_index", &self.remote_index)
            .field("is_initiator", &self.is_initiator)
            .finish_non_exhaustive()
    }
}
