use std::ffi::OsStr;

pub fn is_help(argument: &OsStr) -> bool {
    matches!(argument.to_str(), Some("--help" | "-h" | "help"))
}

pub fn is_subcommand(argument: &OsStr) -> bool {
    matches!(argument.to_str(), Some("up" | "down" | "save" | "strip"))
}

/// Usage text of the reference implementation with UmbraWG names.
pub fn usage_text(program: &str) -> String {
    format!(
        "\
Usage: {program} [ up | down | save | strip ] [ CONFIG_FILE | INTERFACE ]

  CONFIG_FILE is a configuration file, whose filename is the interface name
  followed by `.conf'. Otherwise, INTERFACE is an interface name, with
  configuration found at /etc/umbrawg/INTERFACE.conf. It is to be readable
  by uwg(8)'s `setconf' sub-command, with the exception of the following additions
  to the [Interface] section, which are handled by {program}:

  - Address: may be specified one or more times and contains one or more
    IP addresses (with an optional CIDR mask) to be set for the interface.
  - DNS: an optional DNS server to use while the device is up.
  - MTU: an optional MTU for the interface; if unspecified, auto-calculated.
  - Table: an optional routing table to which routes will be added; if
    unspecified or `auto', the default table is used. If `off', no routes
    are added.
  - PreUp, PostUp, PreDown, PostDown: script snippets which will be executed
    by bash(1) at the corresponding phases of the link, most commonly used
    to configure DNS. The string `%i' is expanded to INTERFACE.
  - SaveConfig: if set to `true', the configuration is saved from the current
    state of the interface upon shutdown.

See uwg-quick(8) for more info and examples.
"
    )
}

pub fn print_usage(program: &str) {
    eprint!("{}", usage_text(program));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn recognizes_help_spellings() {
        for value in ["-h", "--help", "help"] {
            assert!(is_help(&OsString::from(value)));
        }
        assert!(!is_help(&OsString::from("up")));
    }

    #[test]
    fn recognizes_subcommands() {
        for value in ["up", "down", "save", "strip"] {
            assert!(is_subcommand(&OsString::from(value)));
        }
        assert!(!is_subcommand(&OsString::from("show")));
    }

    #[test]
    fn usage_mentions_renamed_tools() {
        let text = usage_text("uwg-quick");
        assert!(text.starts_with("Usage: uwg-quick [ up | down | save | strip ]"));
        assert!(text.contains("/etc/umbrawg/INTERFACE.conf"));
        assert!(text.contains("uwg(8)'s `setconf'"));
        assert!(text.contains("See uwg-quick(8)"));
    }
}
