/// `-4` or `-6`, mirroring the shell check `[[ $1 == *:* ]]`.
pub fn protocol_for(address: &str) -> &'static str {
    if address.contains(':') {
        "-6"
    } else {
        "-4"
    }
}

pub fn is_default_route(address: &str) -> bool {
    address.ends_with("/0")
}

/// The shell filter: `^[0-9a-z:.]+/[0-9]+$`.
pub fn is_valid_allowed_ip(token: &str) -> bool {
    let Some((address, prefix)) = token.rsplit_once('/') else {
        return false;
    };
    !address.is_empty()
        && address.bytes().all(|byte| {
            byte.is_ascii_digit() || byte.is_ascii_lowercase() || matches!(byte, b':' | b'.')
        })
        && !prefix.is_empty()
        && prefix.bytes().all(|byte| byte.is_ascii_digit())
}

/// Allowed IPs from `uwg show <iface> allowed-ips`.
pub fn parse_allowed_ips(output: &str) -> Vec<String> {
    let mut addresses = Vec::new();
    for line in output.lines() {
        for token in line.split_ascii_whitespace().skip(1) {
            if is_valid_allowed_ip(token) {
                addresses.push(token.to_string());
            }
        }
    }
    addresses
}

fn prefix_length(address: &str) -> u32 {
    address
        .rsplit_once('/')
        .and_then(|(_, prefix)| prefix.parse().ok())
        .unwrap_or(0)
}

/// `sort -nr -k 2 -t /`: prefix length descending, then whole line descending.
pub fn sort_allowed_ips(addresses: &mut [String]) {
    addresses.sort_by(|left, right| {
        prefix_length(right)
            .cmp(&prefix_length(left))
            .then_with(|| right.cmp(left))
    });
}

/// Matches `/0` followed by a space, newline or end of output.
pub fn contains_default_route(output: &str) -> bool {
    let bytes = output.as_bytes();
    let mut search = 0;
    while let Some(relative) = output[search..].find("/0") {
        let index = search + relative + 2;
        if matches!(bytes.get(index), None | Some(b' ') | Some(b'\n')) {
            return true;
        }
        search = index;
    }
    false
}

/// `ip <proto> rule add ...` arguments for a default route.
pub fn default_rule_args(protocol: &str, table: u32) -> [Vec<String>; 2] {
    let table_text = table.to_string();
    [
        vec![
            protocol.to_string(),
            "rule".to_string(),
            "add".to_string(),
            "not".to_string(),
            "fwmark".to_string(),
            table_text.clone(),
            "table".to_string(),
            table_text,
        ],
        vec![
            protocol.to_string(),
            "rule".to_string(),
            "add".to_string(),
            "table".to_string(),
            "main".to_string(),
            "suppress_prefixlength".to_string(),
            "0".to_string(),
        ],
    ]
}

pub fn default_route_args(
    protocol: &str,
    address: &str,
    interface: &str,
    table: u32,
) -> Vec<String> {
    vec![
        protocol.to_string(),
        "route".to_string(),
        "add".to_string(),
        address.to_string(),
        "dev".to_string(),
        interface.to_string(),
        "table".to_string(),
        table.to_string(),
    ]
}

pub fn route_add_args(protocol: &str, address: &str, interface: &str) -> Vec<String> {
    vec![
        protocol.to_string(),
        "route".to_string(),
        "add".to_string(),
        address.to_string(),
        "dev".to_string(),
        interface.to_string(),
    ]
}

pub fn route_lookup_args(protocol: &str, address: &str, interface: &str) -> Vec<String> {
    vec![
        protocol.to_string(),
        "route".to_string(),
        "show".to_string(),
        "dev".to_string(),
        interface.to_string(),
        "match".to_string(),
        address.to_string(),
    ]
}

pub fn rule_delete_args(protocol: &str, table: u32) -> Vec<String> {
    vec![
        protocol.to_string(),
        "rule".to_string(),
        "delete".to_string(),
        "table".to_string(),
        table.to_string(),
    ]
}

pub fn suppress_rule_delete_args(protocol: &str) -> Vec<String> {
    vec![
        protocol.to_string(),
        "rule".to_string(),
        "delete".to_string(),
        "table".to_string(),
        "main".to_string(),
        "suppress_prefixlength".to_string(),
        "0".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_protocol_by_address_family() {
        assert_eq!(protocol_for("10.0.0.0/24"), "-4");
        assert_eq!(protocol_for("2001:db8::/64"), "-6");
    }

    #[test]
    fn recognizes_default_routes() {
        assert!(is_default_route("0.0.0.0/0"));
        assert!(is_default_route("::/0"));
        assert!(!is_default_route("10.0.0.0/8"));
        assert!(!is_default_route("10.0.0.0/24"));
    }

    #[test]
    fn filters_allowed_ips_like_the_shell_regex() {
        let output = "\
peer-one\t10.0.0.0/24 0.0.0.0/0
peer-two\tfd00::/64 invalid 10.0.0.1 10.0.0.0/8
peer-three\t2001:db8::/32
";
        assert_eq!(
            parse_allowed_ips(output),
            [
                "10.0.0.0/24",
                "0.0.0.0/0",
                "fd00::/64",
                "10.0.0.0/8",
                "2001:db8::/32"
            ]
        );
    }

    #[test]
    fn sorts_by_prefix_length_descending_then_text() {
        let mut addresses = vec![
            "10.0.0.0/24".to_string(),
            "0.0.0.0/0".to_string(),
            "10.0.0.1/32".to_string(),
            "10.0.0.0/8".to_string(),
            "9.0.0.0/8".to_string(),
        ];
        sort_allowed_ips(&mut addresses);
        assert_eq!(
            addresses,
            [
                "10.0.0.1/32",
                "10.0.0.0/24",
                "9.0.0.0/8",
                "10.0.0.0/8",
                "0.0.0.0/0"
            ]
        );
    }

    #[test]
    fn detects_default_route_in_allowed_ips_output() {
        assert!(contains_default_route("key\t10.0.0.0/24 0.0.0.0/0"));
        assert!(contains_default_route("key\t::/0\nother\t10.0.0.0/8"));
        assert!(contains_default_route("key\tfd00::/0"));
        assert!(!contains_default_route("key\t10.0.0.0/24\n"));
        assert!(!contains_default_route("key\t10.0.0.0/05"));
        assert!(!contains_default_route(""));
    }

    #[test]
    fn builds_policy_rule_arguments() {
        assert_eq!(
            default_rule_args("-4", 51820),
            [
                vec!["-4", "rule", "add", "not", "fwmark", "51820", "table", "51820"]
                    .into_iter()
                    .map(str::to_string)
                    .collect::<Vec<_>>(),
                vec![
                    "-4",
                    "rule",
                    "add",
                    "table",
                    "main",
                    "suppress_prefixlength",
                    "0"
                ]
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>(),
            ]
        );
    }

    #[test]
    fn builds_route_arguments() {
        assert_eq!(
            default_route_args("-6", "::/0", "wg0", 7),
            ["-6", "route", "add", "::/0", "dev", "wg0", "table", "7"]
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            route_add_args("-4", "10.0.0.0/24", "wg0"),
            ["-4", "route", "add", "10.0.0.0/24", "dev", "wg0"]
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            route_lookup_args("-4", "10.0.0.0/24", "wg0"),
            ["-4", "route", "show", "dev", "wg0", "match", "10.0.0.0/24"]
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn builds_rule_delete_arguments() {
        assert_eq!(
            rule_delete_args("-4", 51820),
            ["-4", "rule", "delete", "table", "51820"]
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            suppress_rule_delete_args("-6"),
            [
                "-6",
                "rule",
                "delete",
                "table",
                "main",
                "suppress_prefixlength",
                "0"
            ]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>()
        );
    }
}
