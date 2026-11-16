//! Errors reported by the UmbraWG UAPI server.

use std::io;

use thiserror::Error;

/// `ENOANO`, the fallback errno used by the Go implementation for unexpected
/// failures.
const ERRNO_UNKNOWN: i64 = -55;

/// A control-plane error.
///
/// Every variant maps to the negative errno value written into the
/// `errno=` line of a UAPI reply.
#[derive(Debug, Error)]
pub enum UapiError {
    /// An I/O operation on the UAPI socket failed.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// The request is not valid UAPI syntax.
    #[error("invalid UAPI request: {0}")]
    Protocol(String),
    /// A textual value could not be decoded.
    #[error("invalid value for `{key}`: `{value}`")]
    InvalidValue {
        /// Name of the offending key.
        key: String,
        /// Rejected value.
        value: String,
    },
    /// The request used a key that the protocol does not define.
    #[error("unknown UAPI key: `{0}`")]
    UnknownKey(String),
    /// The request conflicts with the effective device configuration.
    #[error("invalid UAPI configuration: {0}")]
    InvalidConfiguration(String),
    /// The requested socket or listen port is already in use.
    #[error("address is already in use")]
    AddressInUse,
    /// The peer is not allowed to use the control socket.
    #[error("permission denied")]
    PermissionDenied,
    /// An unexpected internal failure.
    #[error("internal UAPI error: {0}")]
    Internal(String),
}

impl UapiError {
    /// Returns the negative errno value sent to the client.
    ///
    /// The values match the Go implementation and the Linux kernel, so
    /// `umbrawg-ctl` can translate them with `io::Error::from_raw_os_error`.
    pub fn code(&self) -> i64 {
        match self {
            Self::Io(_) => -i64::from(libc::EIO),
            Self::Protocol(_) => -i64::from(libc::EPROTO),
            Self::InvalidValue { .. }
            | Self::UnknownKey(_)
            | Self::InvalidConfiguration(_) => -i64::from(libc::EINVAL),
            Self::AddressInUse => -i64::from(libc::EADDRINUSE),
            Self::PermissionDenied => -i64::from(libc::EACCES),
            Self::Internal(_) => ERRNO_UNKNOWN,
        }
    }
}

pub(crate) fn invalid_value(key: &str, value: &str) -> UapiError {
    UapiError::InvalidValue {
        key: key.to_owned(),
        value: value.to_owned(),
    }
}
