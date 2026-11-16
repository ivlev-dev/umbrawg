use std::fmt::Write as _;

/// Prefix of the nftables table created for an interface.
pub const NFT_TABLE_PREFIX: &str = "uwg-quick-";

/// Comment used to recognize our iptables rules.
pub const FIREWALL_COMMENT: &str = "uwg-quick(8) rule for";

/// `-m comment --comment "uwg-quick(8) rule for IFACE"`.
pub fn marker(interface: &str) -> String {
    format!("-m comment --comment \"{FIREWALL_COMMENT} {interface}\"")
}

/// nftables table name for an interface.
pub fn nft_table(interface: &str) -> String {
    format!("{NFT_TABLE_PREFIX}{interface}")
}

/// Extract addresses from `ip -o <proto> addr show dev <iface>`.
pub fn parse_inet_addresses(output: &str) -> Vec<String> {
    let mut addresses = Vec::new();
    for line in output.lines() {
        let tokens: Vec<&str> = line.split_ascii_whitespace().collect();
        for (index, token) in tokens.iter().enumerate() {
            if *token != "inet" && *token != "inet6" {
                continue;
            }
            let Some(value) = tokens.get(index + 1) else {
                break;
            };
            let Some((address, prefix)) = value.split_once('/') else {
                break;
            };
            if !prefix.is_empty()
                && prefix.bytes().all(|byte| byte.is_ascii_digit())
                && !address.is_empty()
                && address
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() || matches!(byte, b':' | b'.'))
            {
                addresses.push(address.to_string());
            }
            break;
        }
    }
    addresses
}

/// Script passed to `nft -f`.
pub fn build_nft_commands(
    family: &str,
    interface: &str,
    addresses: &[String],
    table: u32,
) -> String {
    let nftable = nft_table(interface);
    let mut commands = String::new();
    let _ = writeln!(commands, "add table {family} {nftable}");
    let _ = writeln!(
        commands,
        "add chain {family} {nftable} preraw {{ type filter hook prerouting priority -300; }}"
    );
    let _ = writeln!(
        commands,
        "add chain {family} {nftable} premangle {{ type filter hook prerouting priority -150; }}"
    );
    let _ = writeln!(
        commands,
        "add chain {family} {nftable} postmangle {{ type filter hook postrouting priority -150; }}"
    );
    for address in addresses {
        let _ = writeln!(
            commands,
            "add rule {family} {nftable} preraw iifname != \"{interface}\" {family} daddr {address} fib saddr type != local drop"
        );
    }
    let _ = writeln!(
        commands,
        "add rule {family} {nftable} postmangle meta l4proto udp mark {table} ct mark set mark"
    );
    let _ = writeln!(
        commands,
        "add rule {family} {nftable} premangle meta l4proto udp meta mark set ct mark"
    );
    commands
}

/// Script passed to `iptables-restore -n`.
pub fn build_iptables_restore(
    marker: &str,
    interface: &str,
    addresses: &[String],
    table: u32,
) -> String {
    let mut restore = String::from("*raw\n");
    for address in addresses {
        let _ = writeln!(
            restore,
            "-I PREROUTING ! -i {interface} -d {address} -m addrtype ! --src-type LOCAL -j DROP {marker}"
        );
    }
    let _ = writeln!(restore, "COMMIT\n*mangle");
    let _ = writeln!(
        restore,
        "-I POSTROUTING -m mark --mark {table} -p udp -j CONNMARK --save-mark {marker}"
    );
    let _ = writeln!(
        restore,
        "-I PREROUTING -p udp -j CONNMARK --restore-mark {marker}"
    );
    let _ = writeln!(restore, "COMMIT");
    restore
}

/// Delete script built from `nft list tables`.
pub fn nft_delete_script(list_tables: &str, interface: &str) -> String {
    let suffix = format!(" {}{interface}", NFT_TABLE_PREFIX);
    let mut commands = String::new();
    for raw_line in list_tables.lines() {
        let line = raw_line.trim_matches(|character| character == ' ' || character == '\t');
        if line.ends_with(&suffix) {
            let _ = writeln!(commands, "delete {line}");
        }
    }
    commands
}

/// Restore script (with `-A` rewritten to `-D`) and whether anything matched.
pub fn iptables_delete_script(iptables_save: &str, interface: &str) -> (String, bool) {
    let marker = marker(interface);
    let mut restore = String::new();
    let mut found = false;
    for raw_line in iptables_save.lines() {
        let line = raw_line.trim_matches(|character| character == ' ' || character == '\t');
        let keep = line.starts_with('*')
            || line == "COMMIT"
            || (line.starts_with("-A ") && line.contains(&marker));
        if !keep {
            continue;
        }
        if line.starts_with("-A") {
            found = true;
        }
        match line.strip_prefix("-A") {
            Some(rest) => {
                restore.push_str("-D");
                restore.push_str(rest);
            }
            None => restore.push_str(line),
        }
        restore.push('\n');
    }
    (restore, found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_inet_addresses_from_ip_output() {
        let output = "\
4: wg0    inet 10.0.0.2/24 scope global wg0\\       valid_lft forever preferred_lft forever
4: wg0    inet6 fd00::2/64 scope global \\           valid_lft forever preferred_lft forever
";
        assert_eq!(parse_inet_addresses(output), ["10.0.0.2", "fd00::2"]);
    }

    #[test]
    fn ignores_lines_without_inet_tokens() {
        assert!(parse_inet_addresses("4: wg0    link/none\n").is_empty());
    }

    #[test]
    fn builds_nft_script() {
        let addresses = vec!["10.0.0.2".to_string(), "fd00::2".to_string()];
        let script = build_nft_commands("ip", "wg0", &addresses, 51820);
        let expected = "\
add table ip uwg-quick-wg0
add chain ip uwg-quick-wg0 preraw { type filter hook prerouting priority -300; }
add chain ip uwg-quick-wg0 premangle { type filter hook prerouting priority -150; }
add chain ip uwg-quick-wg0 postmangle { type filter hook postrouting priority -150; }
add rule ip uwg-quick-wg0 preraw iifname != \"wg0\" ip daddr 10.0.0.2 fib saddr type != local drop
add rule ip uwg-quick-wg0 preraw iifname != \"wg0\" ip daddr fd00::2 fib saddr type != local drop
add rule ip uwg-quick-wg0 postmangle meta l4proto udp mark 51820 ct mark set mark
add rule ip uwg-quick-wg0 premangle meta l4proto udp meta mark set ct mark
";
        assert_eq!(script, expected);
    }

    #[test]
    fn builds_iptables_script() {
        let addresses = vec!["10.0.0.2".to_string()];
        let script = build_iptables_restore(&marker("wg0"), "wg0", &addresses, 51820);
        let expected = "\
*raw
-I PREROUTING ! -i wg0 -d 10.0.0.2 -m addrtype ! --src-type LOCAL -j DROP -m comment --comment \"uwg-quick(8) rule for wg0\"
COMMIT
*mangle
-I POSTROUTING -m mark --mark 51820 -p udp -j CONNMARK --save-mark -m comment --comment \"uwg-quick(8) rule for wg0\"
-I PREROUTING -p udp -j CONNMARK --restore-mark -m comment --comment \"uwg-quick(8) rule for wg0\"
COMMIT
";
        assert_eq!(script, expected);
    }

    #[test]
    fn builds_nft_delete_script() {
        let tables = "\
table ip uwg-quick-wg0
table ip6 uwg-quick-wg0
table ip filter
";
        assert_eq!(
            nft_delete_script(tables, "wg0"),
            "delete table ip uwg-quick-wg0\ndelete table ip6 uwg-quick-wg0\n"
        );
    }

    #[test]
    fn rewrites_matching_iptables_rules_to_delete() {
        let save = "\
*raw
-A PREROUTING ! -i wg0 -d 10.0.0.2 -m addrtype ! --src-type LOCAL -j DROP -m comment --comment \"uwg-quick(8) rule for wg0\"
COMMIT
*mangle
-A POSTROUTING -m mark --mark 51820 -p udp -j CONNMARK --save-mark -m comment --comment \"uwg-quick(8) rule for wg0\"
-A PREROUTING -p udp -j CONNMARK --restore-mark -m comment --comment \"uwg-quick(8) rule for wg0\"
COMMIT
-A INPUT -j ACCEPT
";
        let (script, found) = iptables_delete_script(save, "wg0");
        assert!(found);
        let expected = "\
*raw
-D PREROUTING ! -i wg0 -d 10.0.0.2 -m addrtype ! --src-type LOCAL -j DROP -m comment --comment \"uwg-quick(8) rule for wg0\"
COMMIT
*mangle
-D POSTROUTING -m mark --mark 51820 -p udp -j CONNMARK --save-mark -m comment --comment \"uwg-quick(8) rule for wg0\"
-D PREROUTING -p udp -j CONNMARK --restore-mark -m comment --comment \"uwg-quick(8) rule for wg0\"
COMMIT
";
        assert_eq!(script, expected);
    }

    #[test]
    fn reports_when_no_iptables_rules_match() {
        let (script, found) = iptables_delete_script("*raw\nCOMMIT\n-A INPUT -j ACCEPT\n", "wg0");
        assert!(!found);
        assert_eq!(script, "*raw\nCOMMIT\n");
    }
}
