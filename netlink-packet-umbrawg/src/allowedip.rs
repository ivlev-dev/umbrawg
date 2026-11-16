// SPDX-License-Identifier: MIT

use std::{net::IpAddr, str::FromStr};

use netlink_packet_core::{
    emit_u16, emit_u32, parse_ip, parse_u16, parse_u32, DecodeError,
    DefaultNla, Emitable, ErrorContext, Nla, NlaBuffer, NlasIterator,
    Parseable, NLA_F_NESTED,
};

use crate::{
    constants::{
        UWGALLOWEDIP_A_CIDR_MASK, UWGALLOWEDIP_A_FAMILY, UWGALLOWEDIP_A_FLAGS,
        UWGALLOWEDIP_A_IPADDR, UWGALLOWEDIP_F_REMOVE_ME,
    },
    error::UmbrawgConfigError,
};

pub(crate) struct UmbrawgAllowedIps(pub(crate) Vec<UmbrawgAllowedIp>);

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for UmbrawgAllowedIps
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut ret = Vec::new();
        let nlas = NlasIterator::new(buf.value());
        for nla in nlas {
            let nla = nla?;
            ret.push(UmbrawgAllowedIp::parse(&nla)?);
        }
        Ok(Self(ret))
    }
}

impl std::ops::Deref for UmbrawgAllowedIps {
    type Target = Vec<UmbrawgAllowedIp>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// An entry of the `UWGPEER_A_ALLOWEDIPS` nested attribute list.
///
/// An allowed IP is a list of the `UWGALLOWEDIP_A_*` attributes of one
/// address: its family, the address itself, the CIDR prefix length and,
/// optionally, the [`Flags`](UmbrawgAllowedIpAttr::Flags) attribute with
/// [`UWGALLOWEDIP_F_REMOVE_ME`].
///
/// Use [`new`](Self::new), [`remove`](Self::remove) or
/// [`from_spec`](Self::from_spec) to build a well-formed entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UmbrawgAllowedIp(pub Vec<UmbrawgAllowedIpAttr>);

impl UmbrawgAllowedIp {
    /// Builds an allowed IP from an address and a CIDR prefix length.
    ///
    /// # Errors
    ///
    /// Returns [`UmbrawgConfigError::InvalidCidr`] when the prefix length
    /// exceeds 32 for IPv4 or 128 for IPv6.
    pub fn new(addr: IpAddr, cidr: u8) -> Result<Self, UmbrawgConfigError> {
        check_cidr(addr, cidr)?;
        Ok(Self(vec![
            UmbrawgAllowedIpAttr::Family(family_of(addr)),
            UmbrawgAllowedIpAttr::IpAddr(addr),
            UmbrawgAllowedIpAttr::Cidr(cidr),
        ]))
    }

    /// Builds an allowed IP that removes the route instead of adding it.
    ///
    /// The entry carries the same attributes as [`new`](Self::new) plus
    /// [`UmbrawgAllowedIpAttr::Flags`] set to
    /// [`UWGALLOWEDIP_F_REMOVE_ME`].
    ///
    /// # Errors
    ///
    /// Returns [`UmbrawgConfigError::InvalidCidr`] when the prefix length
    /// exceeds 32 for IPv4 or 128 for IPv6.
    pub fn remove(addr: IpAddr, cidr: u8) -> Result<Self, UmbrawgConfigError> {
        let mut allowed_ip = Self::new(addr, cidr)?;
        allowed_ip
            .0
            .push(UmbrawgAllowedIpAttr::Flags(UWGALLOWEDIP_F_REMOVE_ME));
        Ok(allowed_ip)
    }

    /// Parses an allowed IP spec of the form `"addr"` or `"addr/prefix"`.
    ///
    /// A spec without a prefix uses the full prefix length of the address
    /// family: 32 for IPv4 and 128 for IPv6.
    ///
    /// # Errors
    ///
    /// Returns [`UmbrawgConfigError::InvalidAllowedIpSpec`] for malformed
    /// input and [`UmbrawgConfigError::InvalidCidr`] for an out-of-range
    /// prefix length.
    pub fn from_spec(spec: &str) -> Result<Self, UmbrawgConfigError> {
        let (addr, cidr) = match spec.split_once('/') {
            Some((addr, cidr)) => (
                addr.parse::<IpAddr>().map_err(|_| invalid_spec(spec))?,
                cidr.parse::<u8>().map_err(|_| invalid_spec(spec))?,
            ),
            None => {
                let addr =
                    spec.parse::<IpAddr>().map_err(|_| invalid_spec(spec))?;
                (addr, full_prefix(addr))
            }
        };
        Self::new(addr, cidr)
    }

    /// Returns the address of this entry, if present.
    pub fn ip_addr(&self) -> Option<IpAddr> {
        self.0.iter().find_map(|attr| match attr {
            UmbrawgAllowedIpAttr::IpAddr(addr) => Some(*addr),
            _ => None,
        })
    }

    /// Returns the CIDR prefix length of this entry, if present.
    pub fn cidr(&self) -> Option<u8> {
        self.0.iter().find_map(|attr| match attr {
            UmbrawgAllowedIpAttr::Cidr(cidr) => Some(*cidr),
            _ => None,
        })
    }

    /// Returns the address family attribute of this entry, if present.
    pub fn family(&self) -> Option<UmbrawgAddressFamily> {
        self.0.iter().find_map(|attr| match attr {
            UmbrawgAllowedIpAttr::Family(family) => Some(*family),
            _ => None,
        })
    }

    /// Returns `true` when the entry asks the kernel to remove the route.
    pub fn is_remove(&self) -> bool {
        self.0.iter().any(|attr| {
            matches!(attr, UmbrawgAllowedIpAttr::Flags(flags)
                if flags & UWGALLOWEDIP_F_REMOVE_ME != 0)
        })
    }
}

impl FromStr for UmbrawgAllowedIp {
    type Err = UmbrawgConfigError;

    fn from_str(spec: &str) -> Result<Self, Self::Err> {
        Self::from_spec(spec)
    }
}

fn check_cidr(addr: IpAddr, cidr: u8) -> Result<(), UmbrawgConfigError> {
    let max = full_prefix(addr);
    if cidr > max {
        return Err(UmbrawgConfigError::InvalidCidr {
            address: addr,
            cidr,
            max,
        });
    }
    Ok(())
}

fn family_of(addr: IpAddr) -> UmbrawgAddressFamily {
    match addr {
        IpAddr::V4(_) => UmbrawgAddressFamily::Ipv4,
        IpAddr::V6(_) => UmbrawgAddressFamily::Ipv6,
    }
}

fn full_prefix(addr: IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn invalid_spec(spec: &str) -> UmbrawgConfigError {
    UmbrawgConfigError::InvalidAllowedIpSpec {
        spec: spec.to_string(),
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for UmbrawgAllowedIp
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut ret = Vec::new();
        let nlas = NlasIterator::new(buf.value());
        for nla in nlas {
            let nla = nla?;
            ret.push(UmbrawgAllowedIpAttr::parse(&nla)?);
        }
        Ok(Self(ret))
    }
}

impl Nla for UmbrawgAllowedIp {
    fn kind(&self) -> u16 {
        // linux kernel always set it to 0
        NLA_F_NESTED
    }

    fn value_len(&self) -> usize {
        self.0.as_slice().buffer_len()
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        self.0.as_slice().emit(buffer)
    }
}

impl std::ops::Deref for UmbrawgAllowedIp {
    type Target = Vec<UmbrawgAllowedIpAttr>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

const AF_INET6: u16 = 10;
const AF_INET: u16 = 2;

/// Address family of an allowed IP (`UWGALLOWEDIP_A_FAMILY`).
///
/// The variants map to the Linux `AF_INET` (2) and `AF_INET6` (10) values.
/// Any other value is preserved in [`Other`](Self::Other).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum UmbrawgAddressFamily {
    /// IPv4 (`AF_INET`).
    Ipv4,
    /// IPv6 (`AF_INET6`).
    Ipv6,
    /// Any other address family value.
    Other(u16),
}

impl From<u16> for UmbrawgAddressFamily {
    fn from(d: u16) -> Self {
        match d {
            AF_INET6 => Self::Ipv6,
            AF_INET => Self::Ipv4,
            _ => Self::Other(d),
        }
    }
}

impl From<UmbrawgAddressFamily> for u16 {
    fn from(v: UmbrawgAddressFamily) -> u16 {
        match v {
            UmbrawgAddressFamily::Ipv6 => AF_INET6,
            UmbrawgAddressFamily::Ipv4 => AF_INET,
            UmbrawgAddressFamily::Other(d) => d,
        }
    }
}

/// One `UWGALLOWEDIP_A_*` attribute of an [`UmbrawgAllowedIp`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum UmbrawgAllowedIpAttr {
    /// `UWGALLOWEDIP_A_FAMILY`: address family as a `u16`.
    Family(UmbrawgAddressFamily),
    /// `UWGALLOWEDIP_A_IPADDR`: the IPv4 or IPv6 address.
    IpAddr(IpAddr),
    /// `UWGALLOWEDIP_A_CIDR_MASK`: prefix length, `0..=32` for IPv4 and
    /// `0..=128` for IPv6.
    Cidr(u8),
    /// `UWGALLOWEDIP_A_FLAGS`: `0` or
    /// [`UWGALLOWEDIP_F_REMOVE_ME`](crate::constants::UWGALLOWEDIP_F_REMOVE_ME).
    ///
    /// Only meaningful in `UWG_CMD_SET_DEVICE` messages. Removing an address
    /// requires `Family`, `IpAddr`, `Cidr` and this attribute; without the
    /// flag the address is added if absent.
    Flags(u32),
    /// An attribute this crate does not know; kept verbatim.
    Other(DefaultNla),
}

impl Nla for UmbrawgAllowedIpAttr {
    fn value_len(&self) -> usize {
        match self {
            Self::Family(_) => 2,
            Self::IpAddr(v) => match *v {
                IpAddr::V4(_) => 4,
                IpAddr::V6(_) => 16,
            },
            Self::Cidr(_) => 1,
            Self::Flags(_) => 4,
            Self::Other(nla) => nla.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Family(_) => UWGALLOWEDIP_A_FAMILY,
            Self::IpAddr(_) => UWGALLOWEDIP_A_IPADDR,
            Self::Cidr(_) => UWGALLOWEDIP_A_CIDR_MASK,
            Self::Flags(_) => UWGALLOWEDIP_A_FLAGS,
            Self::Other(nla) => nla.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Family(v) => emit_u16(buffer, u16::from(*v)).unwrap(),
            Self::IpAddr(ip) => match ip {
                IpAddr::V4(ip) => buffer.copy_from_slice(&ip.octets()),
                IpAddr::V6(ip) => buffer.copy_from_slice(&ip.octets()),
            },
            Self::Cidr(v) => buffer[0] = *v,
            Self::Flags(v) => emit_u32(buffer, *v).unwrap(),
            Self::Other(nla) => nla.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for UmbrawgAllowedIpAttr
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            UWGALLOWEDIP_A_FAMILY => Self::Family(
                parse_u16(payload)
                    .context("invalid UWGALLOWEDIP_A_FAMILY value")?
                    .into(),
            ),
            UWGALLOWEDIP_A_IPADDR => Self::IpAddr(
                parse_ip(payload)
                    .context("invalid UWGALLOWEDIP_A_IPADDR value")?,
            ),
            UWGALLOWEDIP_A_CIDR_MASK => Self::Cidr(payload[0]),
            UWGALLOWEDIP_A_FLAGS => Self::Flags(
                parse_u32(payload)
                    .context("invalid UWGALLOWEDIP_A_FLAGS value")?,
            ),
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown NLA type {kind}"))?,
            ),
        })
    }
}
