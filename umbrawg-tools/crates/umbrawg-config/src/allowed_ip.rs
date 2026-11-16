use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use crate::error::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AllowedIp {
    pub address: IpAddr,
    pub cidr: u8,
}

impl AllowedIp {
    pub fn new(address: IpAddr, cidr: u8) -> Result<Self, Error> {
        let max = max_prefix_len(address);
        if cidr > max {
            return Err(Error::InvalidAllowedIp {
                value: format!("{address}/{cidr}"),
            });
        }
        Ok(Self { address, cidr })
    }

    pub const fn max_prefix_len(&self) -> u8 {
        max_prefix_len(self.address)
    }
}

impl fmt::Display for AllowedIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.cidr)
    }
}

impl FromStr for AllowedIp {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        if value.is_empty() {
            return Err(Error::InvalidAllowedIp {
                value: value.to_owned(),
            });
        }
        let (address, cidr) = match value.split_once('/') {
            Some((address, cidr)) => {
                let address = address
                    .parse::<IpAddr>()
                    .map_err(|_| Error::InvalidAllowedIp {
                        value: value.to_owned(),
                    })?;
                let cidr = parse_cidr(cidr, address, value)?;
                (address, cidr)
            }
            None => {
                let address = value
                    .parse::<IpAddr>()
                    .map_err(|_| Error::InvalidAllowedIp {
                        value: value.to_owned(),
                    })?;
                (address, max_prefix_len(address))
            }
        };
        Self::new(address, cidr).map_err(|_| Error::InvalidAllowedIp {
            value: value.to_owned(),
        })
    }
}

fn parse_cidr(text: &str, address: IpAddr, original: &str) -> Result<u8, Error> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::InvalidAllowedIp {
            value: original.to_owned(),
        });
    }
    let cidr = text.parse::<u16>().map_err(|_| Error::InvalidAllowedIp {
        value: original.to_owned(),
    })?;
    if cidr > u16::from(max_prefix_len(address)) {
        return Err(Error::InvalidAllowedIp {
            value: original.to_owned(),
        });
    }
    Ok(cidr as u8)
}

pub const fn max_prefix_len(address: IpAddr) -> u8 {
    match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4() {
        let ip: AllowedIp = "10.0.0.0/8".parse().expect("valid");
        assert_eq!(ip.address, IpAddr::from([10, 0, 0, 0]));
        assert_eq!(ip.cidr, 8);
        assert_eq!(ip.to_string(), "10.0.0.0/8");
    }

    #[test]
    fn parses_ipv6() {
        let ip: AllowedIp = "fd00::/64".parse().expect("valid");
        assert_eq!(ip.cidr, 64);
        assert_eq!(ip.to_string(), "fd00::/64");
    }

    #[test]
    fn defaults_prefix() {
        assert_eq!("10.1.2.3".parse::<AllowedIp>().expect("valid").cidr, 32);
        assert_eq!("::1".parse::<AllowedIp>().expect("valid").cidr, 128);
    }

    #[test]
    fn rejects_invalid() {
        assert!("".parse::<AllowedIp>().is_err());
        assert!("10.0.0.0/33".parse::<AllowedIp>().is_err());
        assert!("::/129".parse::<AllowedIp>().is_err());
        assert!("10.0.0.0/x".parse::<AllowedIp>().is_err());
        assert!("10.0.0.0/".parse::<AllowedIp>().is_err());
        assert!("300.0.0.0/8".parse::<AllowedIp>().is_err());
        assert!("10.0.0.0/8/9".parse::<AllowedIp>().is_err());
    }
}
