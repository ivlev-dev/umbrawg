use std::net::{SocketAddr, ToSocketAddrs};

use crate::error::Error;

pub fn parse_endpoint(value: &str, resolve: bool) -> Result<SocketAddr, Error> {
    let value = value.trim();
    if value.is_empty() {
        return Err(Error::InvalidEndpoint {
            value: value.to_owned(),
        });
    }
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Ok(address);
    }
    let (host, port) = split_host_port(value)?;
    let port = port.parse::<u16>().map_err(|_| Error::InvalidEndpoint {
        value: value.to_owned(),
    })?;
    if !resolve {
        return Err(Error::InvalidEndpoint {
            value: value.to_owned(),
        });
    }
    let mut addresses = (host, port)
        .to_socket_addrs()
        .map_err(|_| Error::InvalidEndpoint {
            value: value.to_owned(),
        })?;
    addresses.next().ok_or_else(|| Error::InvalidEndpoint {
        value: value.to_owned(),
    })
}

pub fn format_endpoint(address: &SocketAddr) -> String {
    match address {
        SocketAddr::V4(address) => format!("{}:{}", address.ip(), address.port()),
        SocketAddr::V6(address) => format!("[{}]:{}", address.ip(), address.port()),
    }
}

fn split_host_port(value: &str) -> Result<(&str, &str), Error> {
    let error = || Error::InvalidEndpoint {
        value: value.to_owned(),
    };
    if let Some(rest) = value.strip_prefix('[') {
        let (host, tail) = rest.split_once(']').ok_or_else(error)?;
        let port = tail.strip_prefix(':').ok_or_else(error)?;
        if host.is_empty() || port.is_empty() {
            return Err(error());
        }
        Ok((host, port))
    } else {
        let (host, port) = value.rsplit_once(':').ok_or_else(error)?;
        if host.is_empty() || port.is_empty() || host.contains(':') {
            return Err(error());
        }
        Ok((host, port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_endpoints() {
        let address = parse_endpoint("10.0.0.1:51820", false).expect("valid");
        assert_eq!(format_endpoint(&address), "10.0.0.1:51820");
        let address = parse_endpoint("[fd00::1]:51820", false).expect("valid");
        assert_eq!(format_endpoint(&address), "[fd00::1]:51820");
    }

    #[test]
    fn rejects_invalid_endpoints() {
        assert!(parse_endpoint("", false).is_err());
        assert!(parse_endpoint("10.0.0.1", false).is_err());
        assert!(parse_endpoint("10.0.0.1:", false).is_err());
        assert!(parse_endpoint("[fd00::1]", false).is_err());
        assert!(parse_endpoint("[fd00::1]:", false).is_err());
        assert!(parse_endpoint(":51820", false).is_err());
        assert!(parse_endpoint("10.0.0.1:70000", false).is_err());
    }
}
