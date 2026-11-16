//! Public data model shared with the device implementation.
//!
//! The types mirror the WireGuard/AmneziaWG UAPI contract but keep the Rust
//! control-plane representation strongly typed: keys are decoded once, ranges
//! are checked while parsing, and endpoints are resolved to numeric socket
//! addresses.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use umbrawg_crypto::{Key, PublicKey};
use umbrawg_proto::messages::{
    MESSAGE_DATA, MESSAGE_HANDSHAKE_COOKIE, MESSAGE_HANDSHAKE_INITIATION, MESSAGE_HANDSHAKE_RESPONSE,
};

use crate::error::UapiError;

/// Error produced when a textual UAPI value cannot be decoded.
#[derive(Debug, thiserror::Error)]
pub enum ValueError {
    /// A numeric range is malformed or overflowing.
    #[error("invalid range `{0}`")]
    Range(String),
    /// An allowed-IP prefix is malformed.
    #[error("invalid allowed IP `{0}`")]
    AllowedIp(String),
}

/// An inclusive `u16` range written as `lo`, `hi` or `lo-hi`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct U16Range {
    lo: u16,
    hi: u16,
}

impl U16Range {
    /// Creates a range without validating that `lo <= hi`.
    ///
    /// Prefer [`Self::from_lo_hi`] for untrusted input.
    #[must_use]
    pub const fn new(lo: u16, hi: u16) -> Self {
        Self { lo, hi }
    }

    /// Creates a range containing a single value.
    #[must_use]
    pub const fn single(value: u16) -> Self {
        Self {
            lo: value,
            hi: value,
        }
    }

    /// Creates a range, rejecting `lo > hi`.
    pub fn from_lo_hi(lo: u16, hi: u16) -> Result<Self, ValueError> {
        if lo > hi {
            return Err(ValueError::Range(format!("{lo}-{hi}")));
        }
        Ok(Self { lo, hi })
    }

    /// Returns the inclusive lower bound.
    #[must_use]
    pub const fn lo(self) -> u16 {
        self.lo
    }

    /// Returns the inclusive upper bound.
    #[must_use]
    pub const fn hi(self) -> u16 {
        self.hi
    }

    /// Returns `true` when both bounds are zero.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.lo == 0 && self.hi == 0
    }
}

impl fmt::Display for U16Range {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { lo, hi } = *self;
        if lo == hi {
            write!(formatter, "{lo}")
        } else {
            write!(formatter, "{lo}-{hi}")
        }
    }
}

impl FromStr for U16Range {
    type Err = ValueError;

    fn from_str(spec: &str) -> Result<Self, Self::Err> {
        let (lo, hi) = parse_range_parts(spec).ok_or_else(|| ValueError::Range(spec.to_owned()))?;
        let lo = u16::try_from(lo).map_err(|_| ValueError::Range(spec.to_owned()))?;
        let hi = u16::try_from(hi).map_err(|_| ValueError::Range(spec.to_owned()))?;
        Self::from_lo_hi(lo, hi)
    }
}

/// An inclusive `u32` range written as `lo`, `hi` or `lo-hi`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct U32Range {
    lo: u32,
    hi: u32,
}

impl U32Range {
    /// Creates a range without validating that `lo <= hi`.
    ///
    /// Prefer [`Self::from_lo_hi`] for untrusted input.
    #[must_use]
    pub const fn new(lo: u32, hi: u32) -> Self {
        Self { lo, hi }
    }

    /// Creates a range containing a single value.
    #[must_use]
    pub const fn single(value: u32) -> Self {
        Self {
            lo: value,
            hi: value,
        }
    }

    /// Creates a range, rejecting `lo > hi`.
    pub fn from_lo_hi(lo: u32, hi: u32) -> Result<Self, ValueError> {
        if lo > hi {
            return Err(ValueError::Range(format!("{lo}-{hi}")));
        }
        Ok(Self { lo, hi })
    }

    /// Returns the inclusive lower bound.
    #[must_use]
    pub const fn lo(self) -> u32 {
        self.lo
    }

    /// Returns the inclusive upper bound.
    #[must_use]
    pub const fn hi(self) -> u32 {
        self.hi
    }

    /// Returns `true` when both bounds are zero.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.lo == 0 && self.hi == 0
    }
}

impl fmt::Display for U32Range {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { lo, hi } = *self;
        if lo == hi {
            write!(formatter, "{lo}")
        } else {
            write!(formatter, "{lo}-{hi}")
        }
    }
}

impl FromStr for U32Range {
    type Err = ValueError;

    fn from_str(spec: &str) -> Result<Self, Self::Err> {
        let (lo, hi) = parse_range_parts(spec).ok_or_else(|| ValueError::Range(spec.to_owned()))?;
        let lo = u32::try_from(lo).map_err(|_| ValueError::Range(spec.to_owned()))?;
        let hi = u32::try_from(hi).map_err(|_| ValueError::Range(spec.to_owned()))?;
        Self::from_lo_hi(lo, hi)
    }
}

fn parse_range_parts(spec: &str) -> Option<(u64, u64)> {
    let mut parts = spec.splitn(2, '-');
    let lo = parts.next()?;
    if !is_decimal(lo) {
        return None;
    }
    let lo = lo.parse::<u64>().ok()?;
    let hi = match parts.next() {
        Some(text) => {
            if !is_decimal(text) {
                return None;
            }
            text.parse::<u64>().ok()?
        }
        None => lo,
    };
    Some((lo, hi))
}

fn is_decimal(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// An IP address and prefix length as used by `allowed_ip` lines.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AllowedIp {
    address: IpAddr,
    cidr: u8,
}

impl AllowedIp {
    /// Creates a prefix after validating the prefix length.
    pub fn new(address: IpAddr, cidr: u8) -> Result<Self, ValueError> {
        if cidr > max_prefix_len(address) {
            return Err(ValueError::AllowedIp(format!("{address}/{cidr}")));
        }
        Ok(Self { address, cidr })
    }

    /// Returns the network address.
    #[must_use]
    pub const fn address(self) -> IpAddr {
        self.address
    }

    /// Returns the prefix length.
    #[must_use]
    pub const fn cidr(self) -> u8 {
        self.cidr
    }

    /// Returns the maximum prefix length for the address family.
    #[must_use]
    pub const fn max_prefix_len(self) -> u8 {
        max_prefix_len(self.address)
    }
}

impl fmt::Display for AllowedIp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { address, cidr } = *self;
        write!(formatter, "{address}/{cidr}")
    }
}

impl FromStr for AllowedIp {
    type Err = ValueError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        let (address, cidr) = match value.split_once('/') {
            Some((address, cidr)) => {
                let address = address
                    .parse::<IpAddr>()
                    .map_err(|_| ValueError::AllowedIp(value.to_owned()))?;
                let cidr = parse_cidr(cidr, address, value)?;
                (address, cidr)
            }
            None => {
                let address = address_from_str(value)?;
                (address, max_prefix_len(address))
            }
        };
        Self::new(address, cidr).map_err(|_| ValueError::AllowedIp(value.to_owned()))
    }
}

fn address_from_str(value: &str) -> Result<IpAddr, ValueError> {
    value
        .parse::<IpAddr>()
        .map_err(|_| ValueError::AllowedIp(value.to_owned()))
}

fn parse_cidr(text: &str, address: IpAddr, original: &str) -> Result<u8, ValueError> {
    if !is_decimal(text) {
        return Err(ValueError::AllowedIp(original.to_owned()));
    }
    let cidr = text
        .parse::<u16>()
        .map_err(|_| ValueError::AllowedIp(original.to_owned()))?;
    if cidr > u16::from(max_prefix_len(address)) {
        return Err(ValueError::AllowedIp(original.to_owned()));
    }
    Ok(cidr as u8)
}

/// Returns the maximum prefix length for `address`.
#[must_use]
pub const fn max_prefix_len(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// Device obfuscation parameters as reported by `get=1`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObfuscationSnapshot {
    /// Number of junk packets sent before a handshake (`jc`).
    pub jc: u16,
    /// Minimum junk packet size (`jmin`).
    pub jmin: u16,
    /// Maximum junk packet size (`jmax`).
    pub jmax: u16,
    /// Junk prefix length for handshake initiations (`s1`).
    pub s1: u16,
    /// Junk prefix length for handshake responses (`s2`).
    pub s2: u16,
    /// Junk prefix length for cookie replies (`s3`).
    pub s3: u16,
    /// Junk prefix length for transport packets (`s4`).
    pub s4: u16,
    /// Magic header range for handshake initiations (`h1`).
    pub h1: U32Range,
    /// Magic header range for handshake responses (`h2`).
    pub h2: U32Range,
    /// Magic header range for cookie replies (`h3`).
    pub h3: U32Range,
    /// Magic header range for transport packets (`h4`).
    pub h4: U32Range,
    /// Special packet template `i1`.
    pub i1: Option<String>,
    /// Special packet template `i2`.
    pub i2: Option<String>,
    /// Special packet template `i3`.
    pub i3: Option<String>,
    /// Special packet template `i4`.
    pub i4: Option<String>,
    /// Special packet template `i5`.
    pub i5: Option<String>,
    /// Header protection key; `None` disables protection.
    pub header_protection_key: Option<Key>,
    /// Extra random content padding range (`content_padding_addition`).
    pub content_padding_addition: U16Range,
    /// Whether random trailers are appended to transport packets.
    pub random_trailers: bool,
    /// Whether cookie replies are disabled.
    pub disable_cookies: bool,
}

impl Default for ObfuscationSnapshot {
    fn default() -> Self {
        Self {
            jc: 0,
            jmin: 0,
            jmax: 0,
            s1: 0,
            s2: 0,
            s3: 0,
            s4: 0,
            h1: U32Range::single(MESSAGE_HANDSHAKE_INITIATION),
            h2: U32Range::single(MESSAGE_HANDSHAKE_RESPONSE),
            h3: U32Range::single(MESSAGE_HANDSHAKE_COOKIE),
            h4: U32Range::single(MESSAGE_DATA),
            i1: None,
            i2: None,
            i3: None,
            i4: None,
            i5: None,
            header_protection_key: None,
            content_padding_addition: U16Range::default(),
            random_trailers: false,
            disable_cookies: false,
        }
    }
}

/// Handshake timing parameters as reported by `get=1`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimingSnapshot {
    /// Time after which a rekey is attempted (`rekey_after_time`).
    pub rekey_after_time: U16Range,
    /// Retry interval during a rekey (`rekey_timeout`).
    pub rekey_timeout: U16Range,
    /// Time after which a handshake is rejected (`reject_after_time`).
    pub reject_after_time: U16Range,
    /// Keepalive timeout (`keepalive_timeout`).
    pub keepalive_timeout: U16Range,
    /// Maximum number of handshake attempts (`max_handshake_attempts`).
    pub max_handshake_attempts: U16Range,
}

/// Peer state as reported by `get=1`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerSnapshot {
    /// Peer public key.
    pub public_key: PublicKey,
    /// Preshared key; `None` means the all-zero key.
    pub preshared_key: Option<Key>,
    /// Last known endpoint.
    pub endpoint: Option<SocketAddr>,
    /// Seconds part of the last handshake timestamp.
    pub last_handshake_time_sec: i64,
    /// Nanoseconds part of the last handshake timestamp.
    pub last_handshake_time_nsec: i64,
    /// Number of bytes transmitted to the peer.
    pub tx_bytes: u64,
    /// Number of bytes received from the peer.
    pub rx_bytes: u64,
    /// Persistent keepalive interval range.
    pub persistent_keepalive_interval: U16Range,
    /// Allowed IP prefixes.
    pub allowed_ips: Vec<AllowedIp>,
}

impl Default for PeerSnapshot {
    fn default() -> Self {
        Self {
            public_key: PublicKey::from_bytes([0u8; 32]),
            preshared_key: None,
            endpoint: None,
            last_handshake_time_sec: 0,
            last_handshake_time_nsec: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            persistent_keepalive_interval: U16Range::default(),
            allowed_ips: Vec::new(),
        }
    }
}

/// Complete device state returned by [`DeviceControl::snapshot`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceSnapshot {
    /// Device private key; `None` means no key is configured.
    pub private_key: Option<Key>,
    /// UDP listen port; zero means "not configured".
    pub listen_port: u16,
    /// Firewall mark; zero means "not configured".
    pub fwmark: u32,
    /// Obfuscation 3.1 parameters.
    pub obfuscation: ObfuscationSnapshot,
    /// Handshake timing parameters.
    pub timings: TimingSnapshot,
    /// Configured peers.
    pub peers: Vec<PeerSnapshot>,
}

/// Obfuscation 3.1 fields present in a `set=1` request.
///
/// `None` means the field was not mentioned and must be left unchanged.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObfuscationRequest {
    /// Number of junk packets (`jc`).
    pub jc: Option<u16>,
    /// Minimum junk packet size (`jmin`).
    pub jmin: Option<u16>,
    /// Maximum junk packet size (`jmax`).
    pub jmax: Option<u16>,
    /// Junk prefix length for handshake initiations (`s1`).
    pub s1: Option<u16>,
    /// Junk prefix length for handshake responses (`s2`).
    pub s2: Option<u16>,
    /// Junk prefix length for cookie replies (`s3`).
    pub s3: Option<u16>,
    /// Junk prefix length for transport packets (`s4`).
    pub s4: Option<u16>,
    /// Magic header range for handshake initiations (`h1`).
    pub h1: Option<U32Range>,
    /// Magic header range for handshake responses (`h2`).
    pub h2: Option<U32Range>,
    /// Magic header range for cookie replies (`h3`).
    pub h3: Option<U32Range>,
    /// Magic header range for transport packets (`h4`).
    pub h4: Option<U32Range>,
    /// Special packet template `i1`.
    pub i1: Option<String>,
    /// Special packet template `i2`.
    pub i2: Option<String>,
    /// Special packet template `i3`.
    pub i3: Option<String>,
    /// Special packet template `i4`.
    pub i4: Option<String>,
    /// Special packet template `i5`.
    pub i5: Option<String>,
    /// Header protection key.
    pub header_protection_key: Option<Key>,
    /// Extra random content padding range.
    pub content_padding_addition: Option<U16Range>,
    /// Whether random trailers are appended to transport packets.
    pub random_trailers: Option<bool>,
    /// Whether cookie replies are disabled.
    pub disable_cookies: Option<bool>,
}

/// Handshake timing fields present in a `set=1` request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimingRequest {
    /// Time after which a rekey is attempted.
    pub rekey_after_time: Option<U16Range>,
    /// Retry interval during a rekey.
    pub rekey_timeout: Option<U16Range>,
    /// Time after which a handshake is rejected.
    pub reject_after_time: Option<U16Range>,
    /// Keepalive timeout.
    pub keepalive_timeout: Option<U16Range>,
    /// Maximum number of handshake attempts.
    pub max_handshake_attempts: Option<U16Range>,
}

/// A single allowed-IP modification from a `set=1` request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllowedIpChange {
    /// Route the prefix to the peer (`allowed_ip=<prefix>`).
    Add(AllowedIp),
    /// Stop routing the prefix to the peer (`allowed_ip=-<prefix>`).
    Remove(AllowedIp),
}

/// Peer configuration from a `set=1` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerRequest {
    /// Peer public key.
    pub public_key: PublicKey,
    /// Remove the peer instead of configuring it.
    pub remove: bool,
    /// Fail silently when the peer does not exist yet.
    pub update_only: bool,
    /// New preshared key; `Some` with the all-zero key clears it.
    pub preshared_key: Option<Key>,
    /// New endpoint.
    pub endpoint: Option<SocketAddr>,
    /// New persistent keepalive interval.
    pub persistent_keepalive_interval: Option<U16Range>,
    /// Drop all existing allowed IPs before applying [`Self::allowed_ips`].
    pub replace_allowed_ips: bool,
    /// Allowed-IP modifications in request order.
    pub allowed_ips: Vec<AllowedIpChange>,
    /// Protocol version mentioned in the request; only `1` is accepted.
    pub protocol_version: Option<u16>,
}

impl PeerRequest {
    /// Creates an empty peer request for `public_key`.
    #[must_use]
    pub const fn new(public_key: PublicKey) -> Self {
        Self {
            public_key,
            remove: false,
            update_only: false,
            preshared_key: None,
            endpoint: None,
            persistent_keepalive_interval: None,
            replace_allowed_ips: false,
            allowed_ips: Vec::new(),
            protocol_version: None,
        }
    }
}

/// A parsed `set=1` request.
///
/// `None` and empty values mean "not mentioned", so applying the request is a
/// patch operation. Requests are parsed completely before
/// [`DeviceControl::apply`] is called, which makes them transactional compared
/// to the incremental Go parser.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SetRequest {
    /// Device private key; applies only when present.
    pub private_key: Option<Key>,
    /// New UDP listen port.
    pub listen_port: Option<u16>,
    /// New firewall mark.
    pub fwmark: Option<u32>,
    /// Remove all peers before processing [`Self::peers`].
    pub replace_peers: bool,
    /// Obfuscation 3.1 parameters.
    pub obfuscation: ObfuscationRequest,
    /// Handshake timing parameters.
    pub timings: TimingRequest,
    /// Peer operations in request order.
    pub peers: Vec<PeerRequest>,
}

/// Control-plane interface implemented by the userspace device.
pub trait DeviceControl {
    /// Returns a consistent snapshot of the device and its peers.
    fn snapshot(&self) -> DeviceSnapshot;

    /// Applies a fully parsed `set=1` request.
    ///
    /// Implementations must not block the packet data path.
    fn apply(&self, request: SetRequest) -> Result<(), UapiError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_u16_ranges() {
        assert_eq!("25".parse::<U16Range>().expect("valid"), U16Range::single(25));
        assert_eq!(
            "0-100".parse::<U16Range>().expect("valid"),
            U16Range::new(0, 100)
        );
        assert_eq!(U16Range::new(0, 100).to_string(), "0-100");
        assert_eq!(U16Range::single(5).to_string(), "5");
    }

    #[test]
    fn rejects_bad_u16_ranges() {
        for spec in ["", "-5", "5-", "5-4", "65536", "1-2-3", " 5", "+5", "a"] {
            assert!(spec.parse::<U16Range>().is_err(), "{spec}");
        }
    }

    #[test]
    fn parses_u32_ranges() {
        let range = "61220074-118999195".parse::<U32Range>().expect("valid");
        assert_eq!(range.lo(), 61_220_074);
        assert_eq!(range.hi(), 118_999_195);
        assert_eq!(range.to_string(), "61220074-118999195");
        assert!(!U32Range::single(1).is_zero());
        assert!(U32Range::default().is_zero());
    }

    #[test]
    fn rejects_bad_u32_ranges() {
        for spec in ["10-5", "4294967296", "5-4294967296", "-1"] {
            assert!(spec.parse::<U32Range>().is_err(), "{spec}");
        }
    }

    #[test]
    fn parses_allowed_ips() {
        let ipv4 = "10.0.0.0/8".parse::<AllowedIp>().expect("valid");
        assert_eq!(ipv4.cidr(), 8);
        assert_eq!(ipv4.to_string(), "10.0.0.0/8");
        let ipv6 = "fd00::/64".parse::<AllowedIp>().expect("valid");
        assert_eq!(ipv6.cidr(), 64);
        assert_eq!(ipv6.to_string(), "fd00::/64");
        assert_eq!("10.1.2.3".parse::<AllowedIp>().expect("valid").cidr(), 32);
    }

    #[test]
    fn rejects_bad_allowed_ips() {
        for spec in [
            "",
            "10.0.0.0/33",
            "::/129",
            "10.0.0.0/x",
            "10.0.0.0/",
            "300.0.0.0/8",
            "10.0.0.0/8/9",
        ] {
            assert!(spec.parse::<AllowedIp>().is_err(), "{spec}");
        }
    }

    #[test]
    fn default_headers_match_wireguard_types() {
        let obfuscation = ObfuscationSnapshot::default();
        assert_eq!(obfuscation.h1, U32Range::single(1));
        assert_eq!(obfuscation.h2, U32Range::single(2));
        assert_eq!(obfuscation.h3, U32Range::single(3));
        assert_eq!(obfuscation.h4, U32Range::single(4));
    }
}
