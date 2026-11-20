// SPDX-License-Identifier: MIT

//! Typed errors returned by the configuration builders.

use std::{error::Error, fmt, net::IpAddr};

use crate::{allowedip::UmbrawgAddressFamily, device::UmbrawgMagicHeader};

/// Convenience alias for results of the configuration builders.
pub type UmbrawgConfigResult<T> = Result<T, UmbrawgConfigError>;

/// An error produced while assembling an
/// [`UmbrawgMessage`](crate::UmbrawgMessage)
/// or an [`UmbrawgPeer`](crate::UmbrawgPeer).
///
/// The builders never panic on invalid input: every constraint that the
/// UmbraWG kernel module (or the netlink attribute layout) enforces is
/// reported as one of these variants instead.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum UmbrawgConfigError {
    /// Neither an interface name nor an interface index was configured.
    MissingInterface,
    /// Both an interface name and an interface index were configured; the
    /// kernel accepts exactly one of them.
    ConflictingInterface,
    /// The interface name is longer than `IFNAMSIZ - 1` bytes or contains an
    /// interior NUL byte.
    InvalidInterfaceName {
        /// The rejected interface name.
        name: String,
    },
    /// A peer configuration was built without a public key.
    MissingPublicKey,
    /// A key has the wrong length.
    InvalidKeyLength {
        /// Name of the key attribute, e.g. `"private key"`.
        field: &'static str,
        /// Required length in bytes.
        expected: usize,
        /// Length of the supplied value in bytes.
        actual: usize,
    },
    /// A magic header spec string is not a valid decimal value or
    /// `"<lo>-<hi>"` pair.
    InvalidMagicHeaderSpec {
        /// The magic header the spec was configured for.
        header: UmbrawgMagicHeader,
        /// The rejected spec string.
        spec: String,
    },
    /// A magic header range has its lower bound above its upper bound.
    InvalidMagicHeaderRange {
        /// The magic header the range was configured for.
        header: UmbrawgMagicHeader,
        /// Lower bound, inclusive.
        lo: u32,
        /// Upper bound, inclusive.
        hi: u32,
    },
    /// Two magic header ranges overlap.
    OverlappingMagicHeaders {
        /// The first overlapping header.
        first: UmbrawgMagicHeader,
        /// The second overlapping header.
        second: UmbrawgMagicHeader,
    },
    /// A packed `u16` range has its lower bound above its upper bound.
    InvalidRange {
        /// Name of the attribute, e.g. `"rekey timeout"`.
        field: &'static str,
        /// Lower bound, inclusive.
        lo: u32,
        /// Upper bound, inclusive.
        hi: u32,
    },
    /// A padding value is too small for header protection.
    ///
    /// With a header protection key configured the kernel requires
    /// `S1`..`S4` to be at least the header protection nonce length.
    PaddingBelowHeaderProtectionNonce {
        /// Name of the attribute, e.g. `"S1"`.
        field: &'static str,
        /// The rejected padding value.
        value: u16,
        /// Minimal accepted value in bytes.
        min: u16,
    },
    /// An intermediate header descriptor contains an interior NUL byte.
    ///
    /// The wire format is a NUL-terminated string, so such a value would be
    /// truncated by the kernel and would not survive a round trip.
    IntermediateSpecContainsNul {
        /// Name of the attribute, e.g. `"I1"`.
        field: &'static str,
    },
    /// An intermediate header descriptor does not fit into a single netlink
    /// attribute.
    IntermediateSpecTooLong {
        /// Name of the attribute, e.g. `"I1"`.
        field: &'static str,
        /// Length of the supplied value in bytes.
        len: usize,
        /// Maximal accepted length in bytes.
        max: usize,
    },
    /// An allowed IP CIDR prefix length is out of range for its address
    /// family.
    InvalidCidr {
        /// The address the prefix was configured for.
        address: IpAddr,
        /// The rejected prefix length.
        cidr: u8,
        /// Maximal prefix length for the address family.
        max: u8,
    },
    /// An allowed IP spec string is not `"addr"` or `"addr/prefix"`.
    InvalidAllowedIpSpec {
        /// The rejected spec string.
        spec: String,
    },
    /// The address family attribute does not match the address payload.
    AddressFamilyMismatch {
        /// The family attribute value.
        family: UmbrawgAddressFamily,
        /// The address payload.
        address: IpAddr,
    },
    /// An allowed IP attribute group lacks a required attribute.
    IncompleteAllowedIp {
        /// Name of the missing attribute, e.g. `"UWGALLOWEDIP_A_IPADDR"`.
        field: &'static str,
    },
    /// A flags attribute contains bits that the kernel does not accept.
    UnsupportedFlags {
        /// Name of the flags attribute, e.g. `"UWGPEER_A_FLAGS"`.
        field: &'static str,
        /// The rejected flags.
        flags: u32,
    },
    /// A peer protocol version other than `1` was configured.
    UnsupportedProtocolVersion {
        /// The rejected protocol version.
        version: u32,
    },
    /// A BBR mode outside `0..=2` was parsed from a message.
    InvalidBbrMode {
        /// The rejected `UWGDEVICE_A_BBR` payload.
        value: u8,
    },
    /// An FEC payload is neither `0`, `1` nor a valid `(K << 8) | M` pair.
    InvalidFecValue {
        /// The rejected `UWGDEVICE_A_FEC` payload.
        value: u32,
    },
    /// Explicit FEC shard counts violate the kernel constraints.
    InvalidFecShards {
        /// Number of data shards.
        k: u8,
        /// Number of parity shards.
        m: u8,
    },
    /// The message carries a command that has no configuration
    /// representation, such as
    /// [`UmbrawgCmd::UnknownPeer`](crate::UmbrawgCmd::UnknownPeer).
    UnsupportedCommand {
        /// The rejected command number.
        command: u8,
    },
}

impl fmt::Display for UmbrawgConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingInterface => {
                write!(f, "either an interface name or index is required")
            }
            Self::ConflictingInterface => write!(
                f,
                "interface name and interface index are mutually exclusive"
            ),
            Self::InvalidInterfaceName { name } => write!(
                f,
                "invalid interface name {name:?}: expected at most 15 bytes \
                 without interior NUL"
            ),
            Self::MissingPublicKey => {
                write!(f, "peer public key is required")
            }
            Self::InvalidKeyLength {
                field,
                expected,
                actual,
            } => write!(
                f,
                "invalid {field} length {actual}: expected {expected} bytes"
            ),
            Self::InvalidMagicHeaderSpec { header, spec } => write!(
                f,
                "invalid {} spec {spec:?}: expected a decimal value or \
                 \"<lo>-<hi>\" with lo <= hi",
                header.name()
            ),
            Self::InvalidMagicHeaderRange { header, lo, hi } => write!(
                f,
                "invalid {} range {lo}-{hi}: lo must not exceed hi",
                header.name()
            ),
            Self::OverlappingMagicHeaders { first, second } => write!(
                f,
                "{} and {} ranges overlap",
                first.name(),
                second.name()
            ),
            Self::InvalidRange { field, lo, hi } => write!(
                f,
                "invalid {field} range {lo}-{hi}: lo must not exceed hi"
            ),
            Self::PaddingBelowHeaderProtectionNonce { field, value, min } => {
                write!(
                    f,
                    "{field} = {value} is below the header protection nonce \
                     length {min}"
                )
            }
            Self::IntermediateSpecContainsNul { field } => {
                write!(f, "{field} must not contain interior NUL bytes")
            }
            Self::IntermediateSpecTooLong { field, len, max } => write!(
                f,
                "{field} length {len} exceeds the attribute limit {max}"
            ),
            Self::InvalidCidr { address, cidr, max } => write!(
                f,
                "invalid CIDR prefix {cidr} for {address}: expected 0..={max}"
            ),
            Self::InvalidAllowedIpSpec { spec } => write!(
                f,
                "invalid allowed IP spec {spec:?}: expected \"addr\" or \
                 \"addr/prefix\""
            ),
            Self::AddressFamilyMismatch { family, address } => write!(
                f,
                "address family {family:?} does not match address {address}"
            ),
            Self::IncompleteAllowedIp { field } => {
                write!(f, "allowed IP is missing {field}")
            }
            Self::UnsupportedFlags { field, flags } => {
                write!(f, "unsupported {field} bits {flags:#x}")
            }
            Self::UnsupportedProtocolVersion { version } => write!(
                f,
                "unsupported peer protocol version {version}: only 1 is valid"
            ),
            Self::InvalidBbrMode { value } => write!(
                f,
                "invalid BBR mode {value}: expected 0 (off), 1 (monitor) or 2 \
                 (on)"
            ),
            Self::InvalidFecValue { value } => write!(
                f,
                "invalid FEC value {value}: expected 0 (off), 1 (adaptive) or \
                 a packed (K << 8) | M pair"
            ),
            Self::InvalidFecShards { k, m } => write!(
                f,
                "invalid FEC shards {k}:{m}: expected K >= 1, M >= 1 and K + \
                 M <= 255"
            ),
            Self::UnsupportedCommand { command } => write!(
                f,
                "command {command} has no configuration representation"
            ),
        }
    }
}

impl Error for UmbrawgConfigError {}
