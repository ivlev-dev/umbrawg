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

/// Number of `resolvconf -a` attempts before `uwg-quick up` gives up.
pub const APPLY_ATTEMPTS: usize = 3;

/// Pause between two `resolvconf -a` attempts.
pub const APPLY_DELAY: std::time::Duration = std::time::Duration::from_millis(100);

/// Runs `apply` until it succeeds or `attempts` runs are used up.
///
/// `resolvconf` fails while another process holds its lock, so retrying the
/// whole `resolvconf -a` call is enough; the last error is reported when
/// every attempt fails.
pub fn apply_with_retries<F>(
    attempts: usize,
    delay: std::time::Duration,
    mut apply: F,
) -> crate::error::QuickResult<()>
where
    F: FnMut() -> crate::error::QuickResult<()>,
{
    let attempts = attempts.max(1);
    let mut last_error = None;
    for attempt in 0..attempts {
        match apply() {
            Ok(()) => return Ok(()),
            Err(error) => {
                last_error = Some(error);
                if attempt + 1 < attempts {
                    std::thread::sleep(delay);
                }
            }
        }
    }
    Err(crate::error::QuickError::die(format!(
        "Failed to apply DNS settings after {attempts} attempts: {}",
        last_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "unknown error".to_owned())
    )))
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

    #[test]
    fn retries_until_the_application_succeeds() {
        let mut attempts = 0;
        apply_with_retries(3, std::time::Duration::ZERO, || {
            attempts += 1;
            if attempts < 3 {
                Err(crate::error::QuickError::command("resolvconf", 1))
            } else {
                Ok(())
            }
        })
        .expect("eventually succeeds");
        assert_eq!(attempts, 3);
    }

    #[test]
    fn reports_the_last_error_after_all_attempts() {
        let mut attempts = 0;
        let error = apply_with_retries(2, std::time::Duration::ZERO, || {
            attempts += 1;
            Err(crate::error::QuickError::command("resolvconf", 4))
        })
        .expect_err("every attempt fails");
        assert_eq!(attempts, 2);
        assert_eq!(
            error.to_string(),
            "Failed to apply DNS settings after 2 attempts: command `resolvconf` failed with status 4"
        );
        assert_eq!(error.exit_code(), 1);
    }

    #[test]
    fn single_attempt_does_not_sleep() {
        let mut attempts = 0;
        apply_with_retries(0, std::time::Duration::from_secs(60), || {
            attempts += 1;
            Ok(())
        })
        .expect("succeeds immediately");
        assert_eq!(attempts, 1);
    }
}
