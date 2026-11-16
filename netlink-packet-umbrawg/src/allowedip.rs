// SPDX-License-Identifier: MIT

use std::net::IpAddr;

use netlink_packet_core::{
    emit_u16, parse_ip, parse_u16, DecodeError, DefaultNla, Emitable,
    ErrorContext, Nla, NlaBuffer, NlasIterator, Parseable, NLA_F_NESTED,
};

const UWGALLOWEDIP_A_FAMILY: u16 = 1;
const UWGALLOWEDIP_A_IPADDR: u16 = 2;
const UWGALLOWEDIP_A_CIDR_MASK: u16 = 3;

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UmbrawgAllowedIp(pub Vec<UmbrawgAllowedIpAttr>);

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum UmbrawgAddressFamily {
    Ipv4,
    Ipv6,
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

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum UmbrawgAllowedIpAttr {
    Family(UmbrawgAddressFamily),
    IpAddr(IpAddr),
    Cidr(u8),
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
            Self::Other(nla) => nla.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Family(_) => UWGALLOWEDIP_A_FAMILY,
            Self::IpAddr(_) => UWGALLOWEDIP_A_IPADDR,
            Self::Cidr(_) => UWGALLOWEDIP_A_CIDR_MASK,
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
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown NLA type {kind}"))?,
            ),
        })
    }
}
