//! Wire message layouts, sizes and limits.
//!
//! The byte layout mirrors `messages.h` from the UmbraWG kernel module. All
//! multi-byte fields are little-endian.

use core::ops::Range;

use crate::{ProtoError, Result};

/// Length of a public key in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Length of a symmetric key in bytes.
pub const SYMMETRIC_KEY_LEN: usize = 32;

/// Length of a TAI64N timestamp in bytes.
pub const TIMESTAMP_LEN: usize = 12;

/// Length of a BLAKE2s hash in bytes.
pub const HASH_LEN: usize = 32;

/// Length of `mac1` and `mac2` in bytes.
pub const MAC_LEN: usize = 16;

/// Length of a Poly1305 authentication tag in bytes.
pub const TAG_LEN: usize = 16;

/// Length of a cookie nonce in bytes.
pub const COOKIE_NONCE_LEN: usize = 24;

/// Length of a cookie in bytes.
pub const COOKIE_LEN: usize = 16;

/// Numeric type of a handshake initiation message.
pub const MESSAGE_HANDSHAKE_INITIATION: u32 = 1;

/// Numeric type of a handshake response message.
pub const MESSAGE_HANDSHAKE_RESPONSE: u32 = 2;

/// Numeric type of a cookie reply message.
pub const MESSAGE_HANDSHAKE_COOKIE: u32 = 3;

/// Numeric type of a transport data message.
pub const MESSAGE_DATA: u32 = 4;

/// Size of a handshake initiation message.
pub const INITIATION_SIZE: usize = 148;

/// Size of a handshake response message.
pub const RESPONSE_SIZE: usize = 92;

/// Size of a cookie reply message.
pub const COOKIE_REPLY_SIZE: usize = 64;

/// Size of the transport message header.
pub const TRANSPORT_HEADER_SIZE: usize = 16;

/// Minimum size of a transport message (header and empty payload tag).
pub const TRANSPORT_MIN_SIZE: usize = TRANSPORT_HEADER_SIZE + TAG_LEN;

/// Minimum length of any transport message, matching `MESSAGE_MINIMUM_LENGTH`.
pub const MESSAGE_MINIMUM_LENGTH: usize = TRANSPORT_MIN_SIZE;

/// Alignment used for content padding.
pub const MESSAGE_PADDING_MULTIPLE: usize = 16;

/// Largest datagram accepted by the protocol.
pub const MAX_PACKET_SIZE: usize = 65_535;

/// Offset of the receiver index in a transport message.
pub const TRANSPORT_OFFSET_RECEIVER: usize = 4;

/// Offset of the counter in a transport message.
pub const TRANSPORT_OFFSET_COUNTER: usize = 8;

/// Offset of the encrypted content in a transport message.
pub const TRANSPORT_OFFSET_CONTENT: usize = TRANSPORT_HEADER_SIZE;

/// Returns the encrypted length of `plain_len` bytes.
#[must_use]
pub const fn noise_encrypted_len(plain_len: usize) -> usize {
    plain_len + TAG_LEN
}

/// Returns the total transport message length for `plain_len` bytes.
#[must_use]
pub const fn message_data_len(plain_len: usize) -> usize {
    noise_encrypted_len(plain_len) + TRANSPORT_HEADER_SIZE
}

/// Protocol limits mirroring `messages.h`.
pub mod limits {
    /// Total size of the replay counter window.
    pub const COUNTER_BITS_TOTAL: u64 = 8192;

    /// Number of counter bits that are not tracked exactly.
    pub const COUNTER_REDUNDANT_BITS: u64 = usize::BITS as u64;

    /// Effective replay counter window.
    pub const COUNTER_WINDOW_SIZE: u64 = COUNTER_BITS_TOTAL - COUNTER_REDUNDANT_BITS;

    /// Number of messages after which a handshake is initiated.
    pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;

    /// Number of messages after which a keypair is rejected.
    pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - COUNTER_WINDOW_SIZE - 1;

    /// Handshake retransmission timeout in seconds.
    pub const REKEY_TIMEOUT: u64 = 5;

    /// Key lifetime after which a handshake is initiated, in seconds.
    pub const REKEY_AFTER_TIME: u64 = 120;

    /// Key lifetime after which traffic is rejected, in seconds.
    pub const REJECT_AFTER_TIME: u64 = 180;

    /// Maximum handshake initiations per second.
    pub const INITIATIONS_PER_SECOND: u64 = 50;

    /// Maximum number of peers per device.
    pub const MAX_PEERS_PER_DEVICE: u32 = 1 << 20;

    /// Keepalive timeout in seconds.
    pub const KEEPALIVE_TIMEOUT: u64 = 10;

    /// Maximum number of handshake attempts.
    pub const MAX_TIMER_HANDSHAKES: u64 = 90 / REKEY_TIMEOUT;

    /// Maximum number of queued incoming handshakes.
    pub const MAX_QUEUED_INCOMING_HANDSHAKES: usize = 4096;

    /// Maximum number of staged packets per peer.
    pub const MAX_STAGED_PACKETS: usize = 128;

    /// Maximum number of queued packets per peer.
    pub const MAX_QUEUED_PACKETS: usize = 1024;

    /// Default UDP window used for trailer sizing.
    pub const DEFAULT_UDP_WINDOW: u32 = 500;

    /// Maximum age of a cookie secret in seconds.
    pub const COOKIE_SECRET_MAX_AGE: u64 = 120;

    /// Cookie secret rotation latency in seconds.
    pub const COOKIE_SECRET_LATENCY: u64 = 5;

    /// Handshake DSCP value (`AF41`).
    pub const HANDSHAKE_DSCP: u8 = 0x88;

    /// Upper bound of the handshake retransmission jitter in milliseconds.
    pub const REKEY_TIMEOUT_JITTER_MAX_MILLIS: u64 = 334;
}

/// A decoded UmbraWG message type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum MessageType {
    /// Not a valid message type.
    Invalid = 0,
    /// Handshake initiation.
    HandshakeInitiation = 1,
    /// Handshake response.
    HandshakeResponse = 2,
    /// Cookie reply.
    CookieReply = 3,
    /// Transport data.
    Transport = 4,
}

impl MessageType {
    /// Maps a raw numeric type to a [`MessageType`].
    #[must_use]
    pub const fn from_u32(value: u32) -> Self {
        match value {
            1 => Self::HandshakeInitiation,
            2 => Self::HandshakeResponse,
            3 => Self::CookieReply,
            4 => Self::Transport,
            _ => Self::Invalid,
        }
    }

    /// Returns the numeric message type.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    /// Returns the fixed protected size for this type.
    ///
    /// Handshake and cookie messages have a fixed total size. Transport
    /// messages only have a fixed header size.
    #[must_use]
    pub const fn fixed_size(self) -> Option<usize> {
        match self {
            Self::HandshakeInitiation => Some(INITIATION_SIZE),
            Self::HandshakeResponse => Some(RESPONSE_SIZE),
            Self::CookieReply => Some(COOKIE_REPLY_SIZE),
            Self::Transport => Some(TRANSPORT_HEADER_SIZE),
            Self::Invalid => None,
        }
    }
}

impl TryFrom<u32> for MessageType {
    type Error = ProtoError;

    fn try_from(value: u32) -> Result<Self> {
        match Self::from_u32(value) {
            Self::Invalid => Err(ProtoError::InvalidMessageType(value)),
            message_type => Ok(message_type),
        }
    }
}

fn read_u32(buffer: &[u8], range: Range<usize>) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&buffer[range]);
    u32::from_le_bytes(bytes)
}

fn write_u32(buffer: &mut [u8], range: Range<usize>, value: u32) {
    buffer[range].copy_from_slice(&value.to_le_bytes());
}

fn read_u64(buffer: &[u8], range: Range<usize>) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buffer[range]);
    u64::from_le_bytes(bytes)
}

fn write_u64(buffer: &mut [u8], range: Range<usize>, value: u64) {
    buffer[range].copy_from_slice(&value.to_le_bytes());
}

fn array<const N: usize>(buffer: &[u8], range: Range<usize>) -> &[u8; N] {
    buffer[range]
        .try_into()
        .expect("message field has a fixed size")
}

fn array_mut<const N: usize>(buffer: &mut [u8], range: Range<usize>) -> &mut [u8; N] {
    (&mut buffer[range])
        .try_into()
        .expect("message field has a fixed size")
}

const TYPE: Range<usize> = 0..4;

/// A zero-copy view over a handshake initiation message.
#[derive(Debug)]
pub struct HandshakeInitiation<'a> {
    buffer: &'a mut [u8],
}

impl<'a> HandshakeInitiation<'a> {
    /// Message size in bytes.
    pub const SIZE: usize = INITIATION_SIZE;

    const SENDER: Range<usize> = 4..8;
    const EPHEMERAL: Range<usize> = 8..40;
    const ENCRYPTED_STATIC: Range<usize> = 40..88;
    const ENCRYPTED_TIMESTAMP: Range<usize> = 88..116;
    const MAC1: Range<usize> = 116..132;
    const MAC2: Range<usize> = 132..148;

    /// Wraps a buffer of exactly [`Self::SIZE`] bytes.
    pub fn parse(buffer: &'a mut [u8]) -> Result<Self> {
        if buffer.len() != Self::SIZE {
            return Err(ProtoError::InvalidLength {
                expected: Self::SIZE,
                actual: buffer.len(),
            });
        }
        Ok(Self { buffer })
    }

    /// Wraps a fixed-size array.
    pub fn from_array(buffer: &'a mut [u8; INITIATION_SIZE]) -> Self {
        Self {
            buffer: &mut buffer[..],
        }
    }

    /// Returns the whole message.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.buffer
    }

    /// Returns the mutable whole message.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        self.buffer
    }

    /// Returns the underlying buffer.
    #[must_use]
    pub fn into_inner(self) -> &'a mut [u8] {
        self.buffer
    }

    /// Returns the raw type field.
    #[must_use]
    pub fn message_type(&self) -> u32 {
        read_u32(self.buffer, TYPE)
    }

    /// Sets the raw type field.
    pub fn set_message_type(&mut self, value: u32) {
        write_u32(self.buffer, TYPE, value);
    }

    /// Returns the sender index.
    #[must_use]
    pub fn sender_index(&self) -> u32 {
        read_u32(self.buffer, Self::SENDER)
    }

    /// Sets the sender index.
    pub fn set_sender_index(&mut self, value: u32) {
        write_u32(self.buffer, Self::SENDER, value);
    }

    /// Returns the unencrypted ephemeral public key.
    #[must_use]
    pub fn ephemeral(&self) -> &[u8; PUBLIC_KEY_LEN] {
        array(self.buffer, Self::EPHEMERAL)
    }

    /// Returns the mutable unencrypted ephemeral public key.
    pub fn ephemeral_mut(&mut self) -> &mut [u8; PUBLIC_KEY_LEN] {
        array_mut(self.buffer, Self::EPHEMERAL)
    }

    /// Returns the encrypted static public key and its tag.
    #[must_use]
    pub fn encrypted_static(&self) -> &[u8; PUBLIC_KEY_LEN + TAG_LEN] {
        array(self.buffer, Self::ENCRYPTED_STATIC)
    }

    /// Returns the mutable encrypted static public key and its tag.
    pub fn encrypted_static_mut(&mut self) -> &mut [u8; PUBLIC_KEY_LEN + TAG_LEN] {
        array_mut(self.buffer, Self::ENCRYPTED_STATIC)
    }

    /// Returns the encrypted timestamp and its tag.
    #[must_use]
    pub fn encrypted_timestamp(&self) -> &[u8; TIMESTAMP_LEN + TAG_LEN] {
        array(self.buffer, Self::ENCRYPTED_TIMESTAMP)
    }

    /// Returns the mutable encrypted timestamp and its tag.
    pub fn encrypted_timestamp_mut(&mut self) -> &mut [u8; TIMESTAMP_LEN + TAG_LEN] {
        array_mut(self.buffer, Self::ENCRYPTED_TIMESTAMP)
    }

    /// Returns the first message authentication code.
    #[must_use]
    pub fn mac1(&self) -> &[u8; MAC_LEN] {
        array(self.buffer, Self::MAC1)
    }

    /// Returns the mutable first message authentication code.
    pub fn mac1_mut(&mut self) -> &mut [u8; MAC_LEN] {
        array_mut(self.buffer, Self::MAC1)
    }

    /// Returns the second message authentication code.
    #[must_use]
    pub fn mac2(&self) -> &[u8; MAC_LEN] {
        array(self.buffer, Self::MAC2)
    }

    /// Returns the mutable second message authentication code.
    pub fn mac2_mut(&mut self) -> &mut [u8; MAC_LEN] {
        array_mut(self.buffer, Self::MAC2)
    }

    /// Returns both mutable MAC fields.
    pub fn macs_mut(&mut self) -> (&mut [u8; MAC_LEN], &mut [u8; MAC_LEN]) {
        let (first, second) = self.buffer.split_at_mut(Self::MAC2.start);
        (array_mut(first, Self::MAC1), array_mut(second, 0..MAC_LEN))
    }
}

/// A zero-copy view over a handshake response message.
#[derive(Debug)]
pub struct HandshakeResponse<'a> {
    buffer: &'a mut [u8],
}

impl<'a> HandshakeResponse<'a> {
    /// Message size in bytes.
    pub const SIZE: usize = RESPONSE_SIZE;

    const SENDER: Range<usize> = 4..8;
    const RECEIVER: Range<usize> = 8..12;
    const EPHEMERAL: Range<usize> = 12..44;
    const EMPTY: Range<usize> = 44..60;
    const MAC1: Range<usize> = 60..76;
    const MAC2: Range<usize> = 76..92;

    /// Wraps a buffer of exactly [`Self::SIZE`] bytes.
    pub fn parse(buffer: &'a mut [u8]) -> Result<Self> {
        if buffer.len() != Self::SIZE {
            return Err(ProtoError::InvalidLength {
                expected: Self::SIZE,
                actual: buffer.len(),
            });
        }
        Ok(Self { buffer })
    }

    /// Wraps a fixed-size array.
    pub fn from_array(buffer: &'a mut [u8; RESPONSE_SIZE]) -> Self {
        Self {
            buffer: &mut buffer[..],
        }
    }

    /// Returns the whole message.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.buffer
    }

    /// Returns the mutable whole message.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        self.buffer
    }

    /// Returns the underlying buffer.
    #[must_use]
    pub fn into_inner(self) -> &'a mut [u8] {
        self.buffer
    }

    /// Returns the raw type field.
    #[must_use]
    pub fn message_type(&self) -> u32 {
        read_u32(self.buffer, TYPE)
    }

    /// Sets the raw type field.
    pub fn set_message_type(&mut self, value: u32) {
        write_u32(self.buffer, TYPE, value);
    }

    /// Returns the sender index.
    #[must_use]
    pub fn sender_index(&self) -> u32 {
        read_u32(self.buffer, Self::SENDER)
    }

    /// Sets the sender index.
    pub fn set_sender_index(&mut self, value: u32) {
        write_u32(self.buffer, Self::SENDER, value);
    }

    /// Returns the receiver index.
    #[must_use]
    pub fn receiver_index(&self) -> u32 {
        read_u32(self.buffer, Self::RECEIVER)
    }

    /// Sets the receiver index.
    pub fn set_receiver_index(&mut self, value: u32) {
        write_u32(self.buffer, Self::RECEIVER, value);
    }

    /// Returns the unencrypted ephemeral public key.
    #[must_use]
    pub fn ephemeral(&self) -> &[u8; PUBLIC_KEY_LEN] {
        array(self.buffer, Self::EPHEMERAL)
    }

    /// Returns the mutable unencrypted ephemeral public key.
    pub fn ephemeral_mut(&mut self) -> &mut [u8; PUBLIC_KEY_LEN] {
        array_mut(self.buffer, Self::EPHEMERAL)
    }

    /// Returns the encrypted empty payload tag.
    #[must_use]
    pub fn encrypted_nothing(&self) -> &[u8; TAG_LEN] {
        array(self.buffer, Self::EMPTY)
    }

    /// Returns the mutable encrypted empty payload tag.
    pub fn encrypted_nothing_mut(&mut self) -> &mut [u8; TAG_LEN] {
        array_mut(self.buffer, Self::EMPTY)
    }

    /// Returns the first message authentication code.
    #[must_use]
    pub fn mac1(&self) -> &[u8; MAC_LEN] {
        array(self.buffer, Self::MAC1)
    }

    /// Returns the mutable first message authentication code.
    pub fn mac1_mut(&mut self) -> &mut [u8; MAC_LEN] {
        array_mut(self.buffer, Self::MAC1)
    }

    /// Returns the second message authentication code.
    #[must_use]
    pub fn mac2(&self) -> &[u8; MAC_LEN] {
        array(self.buffer, Self::MAC2)
    }

    /// Returns the mutable second message authentication code.
    pub fn mac2_mut(&mut self) -> &mut [u8; MAC_LEN] {
        array_mut(self.buffer, Self::MAC2)
    }

    /// Returns both mutable MAC fields.
    pub fn macs_mut(&mut self) -> (&mut [u8; MAC_LEN], &mut [u8; MAC_LEN]) {
        let (first, second) = self.buffer.split_at_mut(Self::MAC2.start);
        (array_mut(first, Self::MAC1), array_mut(second, 0..MAC_LEN))
    }
}

/// A zero-copy view over a cookie reply message.
#[derive(Debug)]
pub struct CookieReply<'a> {
    buffer: &'a mut [u8],
}

impl<'a> CookieReply<'a> {
    /// Message size in bytes.
    pub const SIZE: usize = COOKIE_REPLY_SIZE;

    const RECEIVER: Range<usize> = 4..8;
    const NONCE: Range<usize> = 8..32;
    const ENCRYPTED_COOKIE: Range<usize> = 32..64;

    /// Wraps a buffer of exactly [`Self::SIZE`] bytes.
    pub fn parse(buffer: &'a mut [u8]) -> Result<Self> {
        if buffer.len() != Self::SIZE {
            return Err(ProtoError::InvalidLength {
                expected: Self::SIZE,
                actual: buffer.len(),
            });
        }
        Ok(Self { buffer })
    }

    /// Wraps a fixed-size array.
    pub fn from_array(buffer: &'a mut [u8; COOKIE_REPLY_SIZE]) -> Self {
        Self {
            buffer: &mut buffer[..],
        }
    }

    /// Returns the whole message.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.buffer
    }

    /// Returns the mutable whole message.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        self.buffer
    }

    /// Returns the underlying buffer.
    #[must_use]
    pub fn into_inner(self) -> &'a mut [u8] {
        self.buffer
    }

    /// Returns the raw type field.
    #[must_use]
    pub fn message_type(&self) -> u32 {
        read_u32(self.buffer, TYPE)
    }

    /// Sets the raw type field.
    pub fn set_message_type(&mut self, value: u32) {
        write_u32(self.buffer, TYPE, value);
    }

    /// Returns the receiver index.
    #[must_use]
    pub fn receiver_index(&self) -> u32 {
        read_u32(self.buffer, Self::RECEIVER)
    }

    /// Sets the receiver index.
    pub fn set_receiver_index(&mut self, value: u32) {
        write_u32(self.buffer, Self::RECEIVER, value);
    }

    /// Returns the cookie nonce.
    #[must_use]
    pub fn nonce(&self) -> &[u8; COOKIE_NONCE_LEN] {
        array(self.buffer, Self::NONCE)
    }

    /// Returns the mutable cookie nonce.
    pub fn nonce_mut(&mut self) -> &mut [u8; COOKIE_NONCE_LEN] {
        array_mut(self.buffer, Self::NONCE)
    }

    /// Returns the encrypted cookie and its tag.
    #[must_use]
    pub fn encrypted_cookie(&self) -> &[u8; COOKIE_LEN + TAG_LEN] {
        array(self.buffer, Self::ENCRYPTED_COOKIE)
    }

    /// Returns the mutable encrypted cookie and its tag.
    pub fn encrypted_cookie_mut(&mut self) -> &mut [u8; COOKIE_LEN + TAG_LEN] {
        array_mut(self.buffer, Self::ENCRYPTED_COOKIE)
    }
}

/// A zero-copy view over a transport data message.
#[derive(Debug)]
pub struct TransportPacket<'a> {
    buffer: &'a mut [u8],
}

impl<'a> TransportPacket<'a> {
    /// Minimum transport message size in bytes.
    pub const MIN_SIZE: usize = TRANSPORT_MIN_SIZE;

    const RECEIVER: Range<usize> = 4..8;
    const COUNTER: Range<usize> = 8..16;
    const HEADER: Range<usize> = 0..TRANSPORT_HEADER_SIZE;

    /// Wraps a buffer of at least [`Self::MIN_SIZE`] bytes.
    pub fn parse(buffer: &'a mut [u8]) -> Result<Self> {
        if buffer.len() < Self::MIN_SIZE {
            return Err(ProtoError::BufferTooSmall {
                required: Self::MIN_SIZE,
                available: buffer.len(),
            });
        }
        Ok(Self { buffer })
    }

    /// Returns the whole message.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.buffer
    }

    /// Returns the mutable whole message.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        self.buffer
    }

    /// Returns the underlying buffer.
    #[must_use]
    pub fn into_inner(self) -> &'a mut [u8] {
        self.buffer
    }

    /// Returns the raw type field.
    #[must_use]
    pub fn message_type(&self) -> u32 {
        read_u32(self.buffer, TYPE)
    }

    /// Sets the raw type field.
    pub fn set_message_type(&mut self, value: u32) {
        write_u32(self.buffer, TYPE, value);
    }

    /// Returns the receiver index.
    #[must_use]
    pub fn receiver_index(&self) -> u32 {
        read_u32(self.buffer, Self::RECEIVER)
    }

    /// Sets the receiver index.
    pub fn set_receiver_index(&mut self, value: u32) {
        write_u32(self.buffer, Self::RECEIVER, value);
    }

    /// Returns the packet counter.
    #[must_use]
    pub fn counter(&self) -> u64 {
        read_u64(self.buffer, Self::COUNTER)
    }

    /// Sets the packet counter.
    pub fn set_counter(&mut self, value: u64) {
        write_u64(self.buffer, Self::COUNTER, value);
    }

    /// Returns the protected transport header.
    #[must_use]
    pub fn header(&self) -> &[u8] {
        &self.buffer[Self::HEADER]
    }

    /// Returns the mutable protected transport header.
    pub fn header_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[Self::HEADER]
    }

    /// Returns the ciphertext and authentication tag.
    #[must_use]
    pub fn encrypted_content(&self) -> &[u8] {
        &self.buffer[TRANSPORT_HEADER_SIZE..]
    }

    /// Returns the mutable ciphertext and authentication tag.
    pub fn encrypted_content_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[TRANSPORT_HEADER_SIZE..]
    }

    /// Returns the decrypted payload length for a successful AEAD open.
    #[must_use]
    pub fn plaintext_len(&self) -> usize {
        self.encrypted_content().len().saturating_sub(TAG_LEN)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_sizes_match_messages_h() {
        assert_eq!(INITIATION_SIZE, 4 + 4 + 32 + 48 + 28 + 32);
        assert_eq!(RESPONSE_SIZE, 4 + 4 + 4 + 32 + 16 + 16 + 16);
        assert_eq!(COOKIE_REPLY_SIZE, 4 + 4 + 24 + 32);
        assert_eq!(TRANSPORT_MIN_SIZE, 32);
        assert_eq!(message_data_len(0), TRANSPORT_MIN_SIZE);
        assert_eq!(message_data_len(10), 42);
    }

    #[test]
    fn message_type_roundtrip() {
        for value in 1..=4 {
            let message_type = MessageType::try_from(value).unwrap();
            assert_eq!(message_type.as_u32(), value);
            assert!(message_type.fixed_size().is_some());
        }
        assert_eq!(MessageType::from_u32(0), MessageType::Invalid);
        assert_eq!(
            MessageType::try_from(9).unwrap_err(),
            ProtoError::InvalidMessageType(9)
        );
    }

    #[test]
    fn initiation_rejects_wrong_length() {
        let mut buffer = [0u8; INITIATION_SIZE - 1];
        assert!(matches!(
            HandshakeInitiation::parse(&mut buffer),
            Err(ProtoError::InvalidLength { .. })
        ));
    }

    #[test]
    fn transport_requires_minimum_length() {
        let mut buffer = [0u8; TRANSPORT_MIN_SIZE - 1];
        assert!(matches!(
            TransportPacket::parse(&mut buffer),
            Err(ProtoError::BufferTooSmall { .. })
        ));
    }

    #[test]
    fn limits_follow_word_size() {
        assert_eq!(limits::COUNTER_WINDOW_SIZE, 8192 - usize::BITS as u64);
        assert_eq!(
            limits::REJECT_AFTER_MESSAGES,
            u64::MAX - limits::COUNTER_WINDOW_SIZE - 1
        );
    }
}
