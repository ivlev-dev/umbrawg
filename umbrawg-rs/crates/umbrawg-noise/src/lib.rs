//! UmbraWG Noise IK handshake and cookie handling.
//!
//! The crate implements `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` exactly as the
//! UmbraWG kernel module and the Go userspace implementation. Messages are
//! written to and read from fixed-size stack buffers through the zero-copy
//! view types exported by [`umbrawg_proto`].
//!
//! ## Roles
//!
//! ```text
//! initiator                          responder
//! create_initiation  ------------------------>
//!                    <------------------------  consume_initiation
//!                                             create_response
//! consume_response   <------------------------
//! begin_session                         begin_session
//! ```
//!
//! Outgoing messages receive their wire message type from the obfuscator
//! (`Obfuscator::pick_header`) before they are handed to this crate.
//! Incoming messages must carry the canonical type (`1` for initiation, `2`
//! for response, `3` for cookie) after the obfuscation layer decoded them.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod cookie;
mod error;
mod handshake;
mod kdf;

pub use cookie::{CookieChecker, CookieGenerator};
pub use error::{NoiseError, Result};
pub use handshake::{Handshake, HandshakeState, Initiation, Keypair, StaticIdentity};
pub use kdf::{
    initial_chain_key, initial_hash, kdf1, kdf2, kdf3, NOISE_CONSTRUCTION, WG_IDENTIFIER,
    WG_LABEL_COOKIE, WG_LABEL_MAC1,
};
