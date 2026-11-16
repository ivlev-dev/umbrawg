//! Typed errors returned by the TUN API.

use std::io;

use crate::offload::GsoError;

/// Result alias for TUN operations.
pub type TunResult<T> = Result<T, TunError>;

/// Errors produced while opening or using a TUN device.
#[derive(Debug, thiserror::Error)]
pub enum TunError {
    /// An operating system call failed.
    #[error("TUN I/O error: {0}")]
    Io(#[from] io::Error),
    /// The configuration cannot be used to open a device.
    #[error("invalid TUN configuration: {0}")]
    InvalidConfig(&'static str),
    /// The kernel does not support a requested feature.
    #[error("unsupported TUN feature: {0}")]
    Unsupported(&'static str),
    /// The virtio-net header is shorter than expected.
    #[error("short virtio-net header: expected {expected} bytes, got {actual}")]
    ShortVirtioHeader {
        /// Required header length.
        expected: usize,
        /// Available header length.
        actual: usize,
    },
    /// A caller-provided packet buffer is too small.
    #[error("packet buffer too small: need {needed} bytes, have {available}")]
    BufferTooSmall {
        /// Required buffer length.
        needed: usize,
        /// Available buffer length.
        available: usize,
    },
    /// GSO packet processing failed.
    #[error("GSO error: {0}")]
    Gso(#[from] GsoError),
}

impl TunError {
    /// Returns the underlying I/O error, if any.
    pub fn as_io_error(&self) -> Option<&io::Error> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }

    /// Returns the OS error code, if the error originates from the kernel.
    pub fn raw_os_error(&self) -> Option<i32> {
        self.as_io_error()
            .and_then(io::Error::raw_os_error)
    }

    /// Returns the I/O error kind, if the error originates from the OS.
    pub fn io_kind(&self) -> Option<io::ErrorKind> {
        self.as_io_error().map(io::Error::kind)
    }
}

impl From<TunError> for io::Error {
    fn from(error: TunError) -> Self {
        match error {
            TunError::Io(error) => error,
            other => io::Error::other(other),
        }
    }
}
