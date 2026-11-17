/// WireGuard/UmbraWG overhead subtracted from the discovered link MTU.
pub const TUNNEL_OVERHEAD: u32 = 80;

/// Link MTU assumed when the routing table does not report one.
pub const DEFAULT_LINK_MTU: u32 = 1500;

/// MTU decision for `set_mtu_up`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MtuDecision {
    Explicit(String),
    Auto(u32),
}

/// Extract the host from `wg show ... endpoints` output.
///
/// The shell version matches `^\[?([a-z0-9:.]+)\]?:[0-9]+$`.
pub fn parse_endpoint(line: &str) -> Option<&str> {
    let endpoint = line.split_ascii_whitespace().nth(1)?;
    parse_endpoint_host(endpoint)
}

pub fn parse_endpoint_host(endpoint: &str) -> Option<&str> {
    let (host, port) = endpoint.rsplit_once(':')?;
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let host = host.strip_prefix('[').unwrap_or(host);
    let host = host.strip_suffix(']').unwrap_or(host);
    if host.is_empty()
        || !host.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b':' | b'.')
        })
    {
        return None;
    }
    Some(host)
}

/// First `mtu N` value in `ip route`/`ip link` output.
pub fn extract_mtu(text: &str) -> Option<u32> {
    let mut tokens = text.split_ascii_whitespace();
    while let Some(token) = tokens.next() {
        if token == "mtu" {
            return tokens.next()?.parse::<u32>().ok();
        }
    }
    None
}

/// First `dev NAME` value in `ip route` output.
pub fn extract_dev(text: &str) -> Option<&str> {
    let mut tokens = text.split_ascii_whitespace();
    while let Some(token) = tokens.next() {
        if token == "dev" {
            return tokens.next();
        }
    }
    None
}

/// Automatic MTU: max endpoint-route MTU, else default-route MTU, else 1500,
/// minus the tunnel overhead.
pub fn auto_mtu(endpoint_mtus: &[u32], default_route_mtu: Option<u32>) -> u32 {
    let mut base = 0;
    for candidate in endpoint_mtus {
        if *candidate > base {
            base = *candidate;
        }
    }
    if base == 0 {
        if let Some(candidate) = default_route_mtu {
            if candidate > base {
                base = candidate;
            }
        }
    }
    if base == 0 {
        base = DEFAULT_LINK_MTU;
    }
    base.saturating_sub(TUNNEL_OVERHEAD)
}

/// Full decision, including an explicitly configured MTU.
pub fn decide_mtu(
    explicit: Option<&str>,
    endpoint_mtus: &[u32],
    default_route_mtu: Option<u32>,
) -> MtuDecision {
    match explicit {
        Some(value) => MtuDecision::Explicit(value.to_string()),
        None => MtuDecision::Auto(auto_mtu(endpoint_mtus, default_route_mtu)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_endpoint() {
        assert_eq!(
            parse_endpoint("peer-key\t192.0.2.1:51820"),
            Some("192.0.2.1")
        );
    }

    #[test]
    fn parses_bracketed_ipv6_endpoint() {
        assert_eq!(
            parse_endpoint("peer-key\t[2001:db8::1]:51820"),
            Some("2001:db8::1")
        );
    }

    #[test]
    fn parses_unbracketed_ipv6_endpoint() {
        assert_eq!(
            parse_endpoint("peer-key\t2001:db8::1:51820"),
            Some("2001:db8::1")
        );
    }

    #[test]
    fn rejects_invalid_endpoints() {
        assert_eq!(parse_endpoint("peer-key\t(none)"), None);
        assert_eq!(parse_endpoint("peer-key\t192.0.2.1"), None);
        assert_eq!(parse_endpoint("peer-key\t192.0.2.1:abc"), None);
        assert_eq!(parse_endpoint("peer-key\tLOCALHOST:80"), None);
        assert_eq!(parse_endpoint("only-one-column"), None);
    }

    #[test]
    fn extracts_mtu_and_device() {
        let route = "192.0.2.1 via 10.0.0.1 dev eth0 src 10.0.0.2 uid 0\n    cache mtu 1400";
        assert_eq!(extract_mtu(route), Some(1400));
        assert_eq!(extract_dev(route), Some("eth0"));
        assert_eq!(extract_mtu("no mtu here"), None);
        assert_eq!(extract_dev("no device here"), None);
    }

    #[test]
    fn uses_largest_endpoint_route_mtu() {
        assert_eq!(auto_mtu(&[1400, 9000, 1420], Some(1500)), 8920);
    }

    #[test]
    fn falls_back_to_default_route_mtu() {
        assert_eq!(auto_mtu(&[], Some(1500)), 1420);
        assert_eq!(auto_mtu(&[0], Some(9000)), 8920);
    }

    #[test]
    fn falls_back_to_ethernet_mtu() {
        assert_eq!(auto_mtu(&[], None), 1420);
        assert_eq!(auto_mtu(&[], Some(0)), 1420);
    }

    #[test]
    fn explicit_mtu_bypasses_detection() {
        assert_eq!(
            decide_mtu(Some("1280"), &[9000], Some(9000)),
            MtuDecision::Explicit("1280".to_string())
        );
        assert_eq!(decide_mtu(None, &[], Some(1500)), MtuDecision::Auto(1420));
    }
}
