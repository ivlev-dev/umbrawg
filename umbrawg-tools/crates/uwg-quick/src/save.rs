use umbrawg_config::{Document, Entry, Section, SectionKind};

/// Values written above the `uwg showconf` output.
pub struct SaveInputs<'a> {
    pub addresses: &'a [String],
    pub dns: &'a [String],
    pub mtu: Option<&'a str>,
    pub table: Option<&'a str>,
    pub save_config: bool,
    pub pre_up: &'a [String],
    pub post_up: &'a [String],
    pub pre_down: &'a [String],
    pub post_down: &'a [String],
}

/// Build the quick-specific `[Interface]` block.
pub fn build_saved_config(inputs: &SaveInputs<'_>) -> String {
    let mut section = Section {
        name: "Interface".to_owned(),
        kind: SectionKind::Interface,
        line: 0,
        entries: Vec::new(),
    };
    for address in inputs.addresses {
        push_entry(&mut section, "Address", address);
    }
    for server in inputs.dns {
        push_entry(&mut section, "DNS", server);
    }
    if let Some(mtu) = inputs.mtu {
        push_entry(&mut section, "MTU", mtu);
    }
    if let Some(table) = inputs.table {
        push_entry(&mut section, "Table", table);
    }
    if inputs.save_config {
        push_entry(&mut section, "SaveConfig", "true");
    }
    for hook in inputs.pre_up {
        push_entry(&mut section, "PreUp", hook);
    }
    for hook in inputs.post_up {
        push_entry(&mut section, "PostUp", hook);
    }
    for hook in inputs.pre_down {
        push_entry(&mut section, "PreDown", hook);
    }
    for hook in inputs.post_down {
        push_entry(&mut section, "PostDown", hook);
    }
    Document {
        sections: vec![section],
    }
    .to_string()
}

fn push_entry(section: &mut Section, key: &str, value: &str) {
    section.entries.push(Entry {
        key: key.to_owned(),
        value: value.to_owned(),
        line: 0,
    });
}

/// Replace the first `[Interface]\n` of `uwg showconf` with the quick block.
pub fn apply_saved_config(showconf: &str, quick_block: &str) -> String {
    showconf.replacen("[Interface]\n", quick_block, 1)
}

/// Addresses from `ip -all -brief address show dev <iface>`.
pub fn parse_brief_addresses(output: &str, interface: &str) -> Vec<String> {
    for line in output.lines() {
        let mut tokens = line.split_ascii_whitespace();
        if tokens.next() != Some(interface) {
            continue;
        }
        let Some(state) = tokens.next() else {
            continue;
        };
        if state.is_empty() || !state.bytes().all(|byte| byte.is_ascii_uppercase()) {
            continue;
        }
        return tokens.map(ToOwned::to_owned).collect();
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn writes_quick_keys_in_shell_order() {
        let addresses = strings(&["10.0.0.2/24", "fd00::2/64"]);
        let dns = strings(&["1.1.1.1", "8.8.8.8"]);
        let pre_up = strings(&["echo up"]);
        let post_up = strings(&["echo post"]);
        let pre_down = strings(&["echo down"]);
        let post_down = strings(&["echo postdown"]);
        let inputs = SaveInputs {
            addresses: &addresses,
            dns: &dns,
            mtu: Some("1400"),
            table: Some("custom"),
            save_config: true,
            pre_up: &pre_up,
            post_up: &post_up,
            pre_down: &pre_down,
            post_down: &post_down,
        };
        let expected = "\
[Interface]
Address = 10.0.0.2/24
Address = fd00::2/64
DNS = 1.1.1.1
DNS = 8.8.8.8
MTU = 1400
Table = custom
SaveConfig = true
PreUp = echo up
PostUp = echo post
PreDown = echo down
PostDown = echo postdown
";
        assert_eq!(build_saved_config(&inputs), expected);
    }

    #[test]
    fn omits_optional_keys() {
        let inputs = SaveInputs {
            addresses: &[],
            dns: &[],
            mtu: None,
            table: None,
            save_config: false,
            pre_up: &[],
            post_up: &[],
            pre_down: &[],
            post_down: &[],
        };
        assert_eq!(build_saved_config(&inputs), "[Interface]\n");
    }

    #[test]
    fn replaces_only_the_first_interface_header() {
        let showconf = "[Interface]\nPrivateKey=abc=\n[Peer]\nPublicKey=xyz=\n";
        let merged = apply_saved_config(showconf, "[Interface]\nAddress = 10.0.0.2/24\n");
        assert_eq!(
            merged,
            "[Interface]\nAddress = 10.0.0.2/24\nPrivateKey=abc=\n[Peer]\nPublicKey=xyz=\n"
        );
    }

    #[test]
    fn leaves_output_untouched_without_interface_header() {
        assert_eq!(
            apply_saved_config("garbage\n", "[Interface]\n"),
            "garbage\n"
        );
    }

    #[test]
    fn parses_brief_addresses() {
        let output = "wg0              UNKNOWN        10.0.0.2/24 fd00::2/64\n";
        assert_eq!(
            parse_brief_addresses(output, "wg0"),
            ["10.0.0.2/24", "fd00::2/64"]
        );
    }

    #[test]
    fn ignores_other_interfaces_and_non_uppercase_states() {
        assert!(
            parse_brief_addresses("wg1              UNKNOWN        10.0.0.2/24\n", "wg0")
                .is_empty()
        );
        assert!(
            parse_brief_addresses("wg0              no-carrier     10.0.0.2/24\n", "wg0")
                .is_empty()
        );
        assert!(parse_brief_addresses("", "wg0").is_empty());
    }
}
