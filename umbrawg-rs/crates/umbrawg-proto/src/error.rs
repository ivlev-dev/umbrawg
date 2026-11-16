use umbrawg_crypto::KeyError;

/// Result type used by the protocol crate.
pub type Result<T> = core::result::Result<T, ProtoError>;

/// Errors produced while encoding, decoding or configuring UmbraWG messages.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProtoError {
    /// A fixed-size message has an unexpected length.
    #[error("invalid message length: expected {expected} bytes, got {actual}")]
    InvalidLength {
        /// Expected message length.
        expected: usize,
        /// Actual message length.
        actual: usize,
    },
    /// A buffer is shorter than the minimum required size.
    #[error("buffer too small: required {required} bytes, available {available}")]
    BufferTooSmall {
        /// Required number of bytes.
        required: usize,
        /// Available number of bytes.
        available: usize,
    },
    /// A numeric message type outside the valid range was used.
    #[error("invalid message type {0}")]
    InvalidMessageType(u32),
    /// A configuration parameter is unknown.
    #[error("unknown parameter: {0}")]
    UnknownParameter(String),
    /// A configuration parameter has an invalid value.
    #[error("invalid value for {name}: {value}")]
    InvalidValue {
        /// Parameter name.
        name: String,
        /// Rejected value.
        value: String,
    },
    /// A range has its start after its end.
    #[error("invalid range: {0}")]
    InvalidRange(String),
    /// A hexadecimal string is malformed.
    #[error("invalid hexadecimal string")]
    InvalidHex,
    /// A key string is malformed.
    #[error("invalid key: {0}")]
    InvalidKey(String),
    /// A special packet tag is malformed or unknown.
    #[error("invalid special packet tag <{tag}>: {reason}")]
    InvalidTag {
        /// Tag contents between the angle brackets.
        tag: String,
        /// Failure reason.
        reason: String,
    },
    /// A special packet exceeds the maximum datagram size.
    #[error("special packet is too large: {0} bytes (maximum 65535)")]
    SpecialPacketTooLarge(usize),
    /// Two message header ranges overlap.
    #[error("header ranges H{first} and H{second} overlap")]
    OverlappingHeaders {
        /// Index of the first overlapping range (1-based).
        first: u8,
        /// Index of the second overlapping range (1-based).
        second: u8,
    },
    /// Header protection is enabled but a junk prefix is shorter than the nonce.
    #[error("S{index}={value} is too small for header protection (minimum {minimum})")]
    HeaderProtectionPadding {
        /// Index of the padding parameter (1-based).
        index: u8,
        /// Configured padding length.
        value: u16,
        /// Minimum required length.
        minimum: u16,
    },
    /// Header protection cannot derive a nonce from a short prefix.
    #[error("header protection requires a {minimum}-byte junk prefix, got {padding}")]
    HeaderProtectionPrefixTooShort {
        /// Available prefix length.
        padding: usize,
        /// Minimum required prefix length.
        minimum: usize,
    },
    /// The junk size range is invalid.
    #[error("Jmin={min} exceeds Jmax={max}")]
    InvalidJunkRange {
        /// Configured minimum junk size.
        min: u16,
        /// Configured maximum junk size.
        max: u16,
    },
    /// A tag is not supported by the kernel module.
    #[error("tag <{tag}> is not supported by the kernel module")]
    TagNotSupportedByKernel {
        /// Tag name.
        tag: String,
    },
}

impl From<KeyError> for ProtoError {
    fn from(error: KeyError) -> Self {
        Self::InvalidKey(error.to_string())
    }
}
