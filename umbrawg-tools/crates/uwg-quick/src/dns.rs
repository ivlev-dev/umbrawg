/// Prefix from `/etc/resolvconf/interface-order` (`foo.`), or empty.
pub fn interface_prefix(interface_order: Option<&str>) -> String {
    let Some(contents) = interface_order else {
        return String::new();
    };
    for raw_line in contents.lines() {
        let line = raw_line.trim_matches(|character| character == ' ' || character == '\t');
        if line.is_empty() {
            continue;
        }
        let Some(name) = line.strip_suffix('*') else {
            continue;
        };
        if !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return format!("{name}.");
        }
    }
    String::new()
}

/// Payload piped to `resolvconf -a`.
pub fn payload(dns: &[String], search: &[String]) -> Vec<u8> {
    let mut text = String::new();
    for server in dns {
        text.push_str("nameserver ");
        text.push_str(server);
        text.push('\n');
    }
    if !search.is_empty() {
        text.push_str("search ");
        text.push_str(&search.join(" "));
        text.push('\n');
    }
    text.into_bytes()
}

/// Nameservers from `resolvconf -l` or its fallback file.
pub fn parse_nameservers(contents: &str) -> Vec<String> {
    let mut servers = Vec::new();
    for raw_line in contents.lines() {
        let line = raw_line.trim_matches(|character| character == ' ' || character == '\t');
        let Some(server) = line.strip_prefix("nameserver ") else {
            continue;
        };
        if is_valid_nameserver(server) {
            servers.push(server.to_string());
        }
    }
    servers
}

fn is_valid_nameserver(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'=' | b'+' | b':' | b'%' | b'.' | b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn takes_first_matching_interface_prefix() {
        let order = "# comment\nlo*\nwl*\ndocker*\n";
        assert_eq!(interface_prefix(Some(order)), "lo.");
    }

    #[test]
    fn ignores_non_matching_lines() {
        assert_eq!(interface_prefix(Some("foo\nbar?\n\n")), "");
        assert_eq!(interface_prefix(None), "");
    }

    #[test]
    fn allows_hyphen_and_alphanumerics() {
        assert_eq!(interface_prefix(Some("eth-0*\n")), "eth-0.");
    }

    #[test]
    fn builds_resolvconf_payload() {
        let dns = vec!["1.1.1.1".to_string(), "fd00::1".to_string()];
        let search = vec!["example.com".to_string(), "internal".to_string()];
        assert_eq!(
            String::from_utf8(payload(&dns, &search)).unwrap(),
            "nameserver 1.1.1.1\nnameserver fd00::1\nsearch example.com internal\n"
        );
        assert_eq!(
            String::from_utf8(payload(&dns, &[])).unwrap(),
            "nameserver 1.1.1.1\nnameserver fd00::1\n"
        );
    }

    #[test]
    fn parses_nameservers_and_ignores_other_lines() {
        let contents = "# resolv.conf\nnameserver 1.1.1.1\nsearch example.com\nnameserver fd00::1\nnameserver bad value\n";
        assert_eq!(parse_nameservers(contents), ["1.1.1.1", "fd00::1"]);
    }
}
