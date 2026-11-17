//! Sticky source addresses: `IP_PKTINFO` / `IPV6_PKTINFO` marshalling.
//!
//! WireGuard pins the local address and interface used towards a peer so that
//! replies leave through the same path the request arrived on. This module
//! implements the control-message part of that mechanism:
//!
//! * [`parse_pktinfo`] extracts the destination address and interface index from
//!   received control data;
//! * [`write_pktinfo`] emits the same information when sending.
//!
//! # TODO: full sticky sockets
//!
//! The kernel-side behaviour is complete, but the per-peer cache policy is not:
//! caching the source address per peer, invalidating it on `ENETUNREACH` /
//! `EINVAL`, blackholing families that are down and clearing the cache when the
//! endpoint changes all belong to the device layer and are tracked as a follow-up
//! for `umbrawg-device`.

use core::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::addr::AddressFamily;
use crate::cmsg::{CmsgWriter, ControlMessages};
use crate::{Result, TransportError};

const IPV4_PKTINFO_LEN: usize = 12;
const IPV6_PKTINFO_LEN: usize = 20;

/// Local source address and interface index pinned for a peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SourceAddr {
    ip: IpAddr,
    ifindex: u32,
}

impl SourceAddr {
    /// Creates a source address binding.
    pub fn new(ip: IpAddr, ifindex: u32) -> Self {
        Self { ip, ifindex }
    }

    /// Pinned local IP address.
    pub fn ip(self) -> IpAddr {
        self.ip
    }

    /// Interface index the packet arrived on.
    pub fn ifindex(self) -> u32 {
        self.ifindex
    }

    /// Address family of the pinned IP address.
    pub fn family(self) -> AddressFamily {
        match self.ip {
            IpAddr::V4(_) => AddressFamily::Ipv4,
            IpAddr::V6(_) => AddressFamily::Ipv6,
        }
    }

    /// Replaces the IP address, keeping the interface index.
    pub fn with_ip(self, ip: IpAddr) -> Self {
        Self { ip, ..self }
    }
}

impl fmt::Display for SourceAddr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.ifindex == 0 {
            write!(formatter, "{}", self.ip)
        } else {
            write!(formatter, "{}%{}", self.ip, self.ifindex)
        }
    }
}

/// Writes `IP_PKTINFO` or `IPV6_PKTINFO` control data for `source`.
pub(crate) fn write_pktinfo(writer: &mut CmsgWriter<'_>, source: SourceAddr) -> Result<()> {
    match source.ip {
        IpAddr::V4(ip) => {
            let mut data = [0u8; IPV4_PKTINFO_LEN];
            data[0..4].copy_from_slice(&source.ifindex.to_ne_bytes());
            data[4..8].copy_from_slice(&ip.octets());
            writer.push(libc::IPPROTO_IP, libc::IP_PKTINFO, &data)
        }
        IpAddr::V6(ip) => {
            let mut data = [0u8; IPV6_PKTINFO_LEN];
            data[0..16].copy_from_slice(&ip.octets());
            data[16..20].copy_from_slice(&source.ifindex.to_ne_bytes());
            writer.push(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, &data)
        }
    }
}

/// Parses the first `IP_PKTINFO`/`IPV6_PKTINFO` message of `control`.
///
/// Returns `Ok(None)` when the kernel did not attach packet information.
pub(crate) fn parse_pktinfo(control: &[u8], _family: AddressFamily) -> Result<Option<SourceAddr>> {
    for message in ControlMessages::new(control) {
        let message = message?;
        match (message.level, message.ty) {
            (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
                if message.data.len() < IPV4_PKTINFO_LEN {
                    return Err(TransportError::InvalidControlMessage {
                        reason: "IP_PKTINFO payload is too short",
                    });
                }
                let mut ifindex = [0u8; 4];
                ifindex.copy_from_slice(&message.data[0..4]);
                let mut address = [0u8; 4];
                address.copy_from_slice(&message.data[4..8]);
                return Ok(Some(SourceAddr::new(
                    IpAddr::V4(Ipv4Addr::from(address)),
                    u32::from_ne_bytes(ifindex),
                )));
            }
            (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                if message.data.len() < IPV6_PKTINFO_LEN {
                    return Err(TransportError::InvalidControlMessage {
                        reason: "IPV6_PKTINFO payload is too short",
                    });
                }
                let mut address = [0u8; 16];
                address.copy_from_slice(&message.data[0..16]);
                let mut ifindex = [0u8; 4];
                ifindex.copy_from_slice(&message.data[16..20]);
                return Ok(Some(SourceAddr::new(
                    IpAddr::V6(Ipv6Addr::from(address)),
                    u32::from_ne_bytes(ifindex),
                )));
            }
            _ => {}
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmsg::ControlBuffer;

    #[test]
    fn pktinfo_v4_round_trip() {
        let source = SourceAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)), 7);
        let mut buffer = ControlBuffer::new();
        let mut writer = CmsgWriter::new(&mut buffer);
        write_pktinfo(&mut writer, source).unwrap();
        let control = writer.finish().to_vec();

        let parsed = parse_pktinfo(&control, AddressFamily::Ipv4).unwrap();
        assert_eq!(parsed, Some(source));
    }

    #[test]
    fn pktinfo_v6_round_trip() {
        let source = SourceAddr::new("2001:db8::42".parse().unwrap(), 11);
        let mut buffer = ControlBuffer::new();
        let mut writer = CmsgWriter::new(&mut buffer);
        write_pktinfo(&mut writer, source).unwrap();
        let control = writer.finish().to_vec();

        let parsed = parse_pktinfo(&control, AddressFamily::Ipv6).unwrap();
        assert_eq!(parsed, Some(source));
        assert_eq!(parsed.unwrap().family(), AddressFamily::Ipv6);
    }

    #[test]
    fn no_pktinfo_yields_none() {
        assert_eq!(parse_pktinfo(&[], AddressFamily::Ipv4).unwrap(), None);
    }

    #[test]
    fn short_pktinfo_is_rejected() {
        let mut buffer = ControlBuffer::new();
        let mut writer = CmsgWriter::new(&mut buffer);
        writer
            .push(libc::IPPROTO_IP, libc::IP_PKTINFO, &[0u8; 4])
            .unwrap();
        let control = writer.finish().to_vec();
        assert!(matches!(
            parse_pktinfo(&control, AddressFamily::Ipv4),
            Err(TransportError::InvalidControlMessage { .. })
        ));
    }

    #[test]
    fn display_includes_interface_index() {
        let source = SourceAddr::new("127.0.0.1".parse().unwrap(), 1);
        assert_eq!(source.to_string(), "127.0.0.1%1");
        let source = SourceAddr::new("127.0.0.1".parse().unwrap(), 0);
        assert_eq!(source.to_string(), "127.0.0.1");
        assert_eq!(source.with_ip("192.0.2.1".parse().unwrap()).ifindex(), 0);
    }
}
