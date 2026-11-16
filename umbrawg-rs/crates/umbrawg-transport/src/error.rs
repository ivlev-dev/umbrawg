//! Typed errors produced by the UDP transport.

use std::io;

/// Result type used by the transport crate.
pub type Result<T> = core::result::Result<T, TransportError>;

/// Errors produced while configuring sockets or moving datagrams.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// A system call failed.
    #[error("{operation}: {source}")]
    Io {
        /// Name of the failed system call.
        operation: &'static str,
        /// Underlying OS error.
        #[source]
        source: io::Error,
    },
    /// The socket has no more datagrams to receive or cannot accept more data.
    #[error("socket would block")]
    WouldBlock,
    /// GSO is not available on this kernel or socket.
    #[error("UDP GSO is not supported")]
    GsoUnsupported,
    /// A control message is malformed.
    #[error("invalid control message: {reason}")]
    InvalidControlMessage {
        /// Human readable reason.
        reason: &'static str,
    },
    /// A caller supplied buffer is too small.
    #[error("buffer too small: need {needed} bytes, have {available}")]
    BufferTooSmall {
        /// Required size in bytes.
        needed: usize,
        /// Available size in bytes.
        available: usize,
    },
    /// A batch exceeds the configured capacity.
    #[error("batch of {count} exceeds the maximum of {max}")]
    BatchTooLarge {
        /// Requested number of datagrams.
        count: usize,
        /// Maximum supported number of datagrams.
        max: usize,
    },
    /// An empty batch was passed to a batch operation.
    #[error("batch must contain at least one datagram")]
    EmptyBatch,
    /// A datagram exceeds the maximum UDP payload for the address family.
    #[error("datagram of {len} bytes exceeds the maximum of {max} bytes")]
    DatagramTooLarge {
        /// Datagram length in bytes.
        len: usize,
        /// Maximum payload length in bytes.
        max: usize,
    },
    /// A GSO/GRO segment size is invalid.
    #[error("invalid segment size {size}")]
    InvalidSegmentSize {
        /// Rejected segment size.
        size: usize,
    },
    /// Segment sizes do not form a valid GSO layout.
    #[error("inconsistent segment layout: {reason}")]
    InconsistentSegments {
        /// Human readable reason.
        reason: &'static str,
    },
    /// A payload was split into more segments than the kernel supports.
    #[error("{segments} segments exceed the kernel limit of {max}")]
    TooManySegments {
        /// Number of segments.
        segments: usize,
        /// Maximum number of segments.
        max: usize,
    },
    /// The GSO segment size exceeds the configured limit.
    #[error("segment size {size} exceeds the limit of {max}")]
    SegmentSizeTooLarge {
        /// Requested segment size.
        size: usize,
        /// Maximum segment size.
        max: usize,
    },
    /// An interface name is empty or contains an interior NUL byte.
    #[error("invalid interface name")]
    InvalidInterfaceName,
    /// An interface name does not fit into `IFNAMSIZ`.
    #[error("interface name of {len} bytes exceeds the maximum of {max}")]
    InterfaceNameTooLong {
        /// Name length in bytes.
        len: usize,
        /// Maximum name length in bytes.
        max: usize,
    },
    /// The interface reported a non-positive MTU.
    #[error("invalid MTU {mtu}")]
    InvalidMtu {
        /// Reported MTU value.
        mtu: u32,
    },
    /// The destination address belongs to another address family than the socket.
    #[error("endpoint address family does not match the socket family")]
    EndpointFamilyMismatch,
    /// A sticky source address belongs to another address family than the socket.
    #[error("source address family does not match the socket family")]
    SourceAddressMismatch,
    /// A feature is unavailable on this platform or kernel.
    #[error("unsupported: {feature}")]
    Unsupported {
        /// Feature name.
        feature: &'static str,
    },
}

impl TransportError {
    /// Wraps an OS error, mapping `EAGAIN`/`EWOULDBLOCK` to [`TransportError::WouldBlock`].
    pub(crate) fn from_io(operation: &'static str, source: io::Error) -> Self {
        if source.kind() == io::ErrorKind::WouldBlock {
            return Self::WouldBlock;
        }
        Self::Io { operation, source }
    }

    /// Builds an error from the current value of `errno`.
    pub(crate) fn last_io(operation: &'static str) -> Self {
        Self::from_io(operation, io::Error::last_os_error())
    }

    /// Returns `true` for [`TransportError::WouldBlock`].
    pub fn is_would_block(&self) -> bool {
        matches!(self, Self::WouldBlock)
    }

    /// Returns `true` if the failing call was interrupted by a signal.
    pub fn is_interrupted(&self) -> bool {
        matches!(self, Self::Io { source, .. } if source.kind() == io::ErrorKind::Interrupted)
    }

    /// Returns `true` if the error means GSO cannot be used on this path.
    ///
    /// The kernel reports `EIO` when the egress device lacks checksum offload and
    /// `EINVAL`/`EMSGSIZE` when a segment plus protocol headers exceeds the path MTU.
    pub(crate) fn should_disable_gso(&self) -> bool {
        matches!(
            self,
            Self::Io { source, .. }
                if matches!(
                    source.raw_os_error(),
                    Some(libc::EIO | libc::EINVAL | libc::EMSGSIZE)
                )
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn would_block_is_not_an_io_error() {
        let error = TransportError::from_io(
            "recvmmsg",
            io::Error::from(io::ErrorKind::WouldBlock),
        );
        assert!(error.is_would_block());
        assert!(!error.is_interrupted());
    }

    #[test]
    fn interrupted_is_detected() {
        let error =
            TransportError::from_io("sendmmsg", io::Error::from(io::ErrorKind::Interrupted));
        assert!(error.is_interrupted());
        assert!(!error.is_would_block());
    }

    #[test]
    fn gso_is_disabled_on_path_errors() {
        for errno in [libc::EIO, libc::EINVAL, libc::EMSGSIZE] {
            let error = TransportError::from_io("sendmmsg", io::Error::from_raw_os_error(errno));
            assert!(error.should_disable_gso(), "errno {errno}");
        }
        let error = TransportError::from_io("sendmmsg", io::Error::from_raw_os_error(libc::EPERM));
        assert!(!error.should_disable_gso());
    }
}
