use umbrawg_proto::ProtoError;

use crate::HandshakeState;

/// Result type used by the noise handshake and cookie routines.
pub type Result<T> = core::result::Result<T, NoiseError>;

/// Errors produced while processing handshake or cookie messages.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NoiseError {
    /// A handshake operation requires a different state.
    #[error("invalid handshake state: expected {expected:?}, got {actual:?}")]
    InvalidState {
        /// State required by the operation.
        expected: HandshakeState,
        /// State the handshake is currently in.
        actual: HandshakeState,
    },
    /// A handshake message carries an unexpected canonical message type.
    #[error("unexpected message type {actual}, expected {expected}")]
    UnexpectedMessageType {
        /// Canonical type required by the operation.
        expected: u32,
        /// Type found in the message.
        actual: u32,
    },
    /// A handshake response addresses an unknown local index.
    #[error("invalid receiver index {actual}, expected {expected}")]
    InvalidReceiverIndex {
        /// Index stored in the handshake.
        expected: u32,
        /// Index found in the message.
        actual: u32,
    },
    /// The initiation names a static key that does not belong to the peer.
    #[error("handshake belongs to a different peer")]
    PeerMismatch,
    /// An ephemeral public key produced an all-zero shared secret.
    #[error("invalid public key")]
    InvalidPublicKey,
    /// The static-static shared secret is not available.
    #[error("static-static shared secret is not available")]
    MissingStaticStatic,
    /// AEAD authentication of a handshake payload failed.
    #[error("message authentication failed")]
    Authentication,
    /// The initiation timestamp is not newer than the stored timestamp.
    #[error("handshake replay detected")]
    Replay,
    /// A cookie reply arrived before any MAC1 was sent.
    #[error("no MAC1 has been sent for this peer")]
    MissingMac1,
    /// XChaCha20-Poly1305 authentication of a cookie reply failed.
    #[error("cookie authentication failed")]
    CookieAuthentication,
    /// A message is too short to contain the requested MAC fields.
    #[error("message is too short: {0} bytes")]
    MessageTooShort(usize),
    /// A buffered protocol message is malformed.
    #[error(transparent)]
    Proto(#[from] ProtoError),
}
