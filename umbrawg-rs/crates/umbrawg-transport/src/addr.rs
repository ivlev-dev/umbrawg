//! Address families and peer endpoints.

use core::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::gso::{IPV4_HEADER_LEN, IPV6_HEADER_LEN, MAX_UDP_PAYLOAD_V4, MAX_UDP_PAYLOAD_V6, UDP_HEADER_LEN};
use crate::sticky::SourceAddr;

/// Address family of a UDP socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AddressFamily {
    /// `AF_INET`.
    Ipv4,
    /// `AF_INET6`, optionally dual-stack (see [`crate::OpenOptions::dual_stack`]).
    Ipv6,
}

impl AddressFamily {
    /// Returns the family of a socket address as delivered by the kernel.
    ///
    /// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are reported as [`AddressFamily::Ipv6`];
    /// use [`normalize_ipv4_mapped`] when the embedded IPv4 address is preferred.
    pub fn of(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(_) => Self::Ipv4,
            SocketAddr::V6(_) => Self::Ipv6,
        }
    }

    /// Returns `true` for [`AddressFamily::Ipv4`].
    pub fn is_ipv4(self) -> bool {
        matches!(self, Self::Ipv4)
    }

    /// Returns `true` for [`AddressFamily::Ipv6`].
    pub fn is_ipv6(self) -> bool {
        matches!(self, Self::Ipv6)
    }

    /// Maximum UDP payload the family can express in a single datagram.
    pub fn max_udp_payload(self) -> usize {
        match self {
            Self::Ipv4 => MAX_UDP_PAYLOAD_V4,
            Self::Ipv6 => MAX_UDP_PAYLOAD_V6,
        }
    }

    /// Bytes of IP and UDP headers prepended to the payload by the kernel.
    pub fn udp_overhead(self) -> usize {
        match self {
            Self::Ipv4 => IPV4_HEADER_LEN + UDP_HEADER_LEN,
            Self::Ipv6 => IPV6_HEADER_LEN + UDP_HEADER_LEN,
        }
    }

    /// The unspecified address of the family, used for wildcard binds.
    pub fn unspecified(self) -> IpAddr {
        match self {
            Self::Ipv4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            Self::Ipv6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        }
    }
}

/// Maps an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to its IPv4 form.
///
/// Every other address is returned unchanged.
pub fn normalize_ipv4_mapped(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::V4(SocketAddrV4::new(v4, v6.port())),
            None => addr,
        },
        SocketAddr::V4(_) => addr,
    }
}

/// Converts `addr` into an address usable on a socket of `family`.
///
/// IPv4 destinations are mapped into the IPv4-mapped IPv6 range when the socket is
/// an `AF_INET6` socket, which is what the kernel expects for dual-stack sends.
pub(crate) fn address_for_socket(addr: SocketAddr, family: AddressFamily) -> SocketAddr {
    match (family, addr) {
        (AddressFamily::Ipv6, SocketAddr::V4(v4)) => {
            SocketAddr::V6(SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0))
        }
        _ => addr,
    }
}

/// A peer endpoint: the destination address plus an optional sticky source address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    dst: SocketAddr,
    source: Option<SourceAddr>,
}

impl Endpoint {
    /// Creates an endpoint without a pinned source address.
    pub fn new(dst: SocketAddr) -> Self {
        Self { dst, source: None }
    }

    /// Creates an endpoint with a pinned source address.
    pub fn with_source(dst: SocketAddr, source: SourceAddr) -> Self {
        Self {
            dst,
            source: Some(source),
        }
    }

    /// Creates an endpoint, optionally pinning a source address.
    pub fn with_optional_source(dst: SocketAddr, source: Option<SourceAddr>) -> Self {
        Self { dst, source }
    }

    /// Destination address of the peer.
    pub fn dst(&self) -> SocketAddr {
        self.dst
    }

    /// Address family of the destination.
    pub fn family(&self) -> AddressFamily {
        AddressFamily::of(self.dst)
    }

    /// Pinned source address, if any.
    pub fn source(&self) -> Option<SourceAddr> {
        self.source
    }

    /// Replaces the pinned source address.
    pub fn set_source(&mut self, source: Option<SourceAddr>) {
        self.source = source;
    }

    /// Drops the pinned source address, letting the kernel choose one per packet.
    pub fn clear_source(&mut self) {
        self.source = None;
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.source {
            Some(source) => write!(formatter, "{} via {}", self.dst, source),
            None => write!(formatter, "{}", self.dst),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_of_address() {
        let v4: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let v6: SocketAddr = "[::1]:1".parse().unwrap();
        assert_eq!(AddressFamily::of(v4), AddressFamily::Ipv4);
        assert_eq!(AddressFamily::of(v6), AddressFamily::Ipv6);
        assert!(AddressFamily::Ipv4.is_ipv4());
        assert!(AddressFamily::Ipv6.is_ipv6());
        assert_eq!(AddressFamily::Ipv4.unspecified(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(AddressFamily::Ipv6.unspecified(), IpAddr::V6(Ipv6Addr::UNSPECIFIED));
    }

    #[test]
    fn payload_limits_match_headers() {
        assert_eq!(AddressFamily::Ipv4.max_udp_payload(), 65_507);
        assert_eq!(AddressFamily::Ipv6.max_udp_payload(), 65_527);
        assert_eq!(AddressFamily::Ipv4.udp_overhead(), 28);
        assert_eq!(AddressFamily::Ipv6.udp_overhead(), 48);
    }

    #[test]
    fn ipv4_mapped_is_normalized() {
        let mapped: SocketAddr = "[::ffff:192.0.2.1]:8080".parse().unwrap();
        assert_eq!(
            normalize_ipv4_mapped(mapped),
            "192.0.2.1:8080".parse::<SocketAddr>().unwrap()
        );
        let plain: SocketAddr = "[2001:db8::1]:80".parse().unwrap();
        assert_eq!(normalize_ipv4_mapped(plain), plain);
    }

    #[test]
    fn addresses_are_mapped_for_v6_sockets() {
        let v4: SocketAddr = "192.0.2.7:53".parse().unwrap();
        let mapped = address_for_socket(v4, AddressFamily::Ipv6);
        assert!(matches!(mapped, SocketAddr::V6(_)));
        assert_eq!(normalize_ipv4_mapped(mapped), v4);
        assert_eq!(address_for_socket(v4, AddressFamily::Ipv4), v4);
    }

    #[test]
    fn endpoint_source_can_be_replaced() {
        let dst: SocketAddr = "192.0.2.1:1".parse().unwrap();
        let source = SourceAddr::new("192.0.2.2".parse().unwrap(), 3);
        let mut endpoint = Endpoint::with_source(dst, source);
        assert_eq!(endpoint.dst(), dst);
        assert_eq!(endpoint.family(), AddressFamily::Ipv4);
        assert_eq!(endpoint.source(), Some(source));
        endpoint.clear_source();
        assert_eq!(endpoint.source(), None);
        assert_eq!(endpoint.to_string(), "192.0.2.1:1");
        endpoint.set_source(Some(source));
        assert_eq!(endpoint.to_string(), "192.0.2.1:1 via 192.0.2.2%3");
    }
}
