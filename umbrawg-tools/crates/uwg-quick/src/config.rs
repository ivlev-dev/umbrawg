use crate::error::{QuickError, QuickResult};
use crate::{CONFIG_DIR, CONFIG_SUFFIX};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

/// Parsed wg-quick configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuickConfig {
    pub config_file: PathBuf,
    pub interface: String,
    pub wg_config: String,
    pub addresses: Vec<String>,
    pub mtu: Option<String>,
    pub dns: Vec<String>,
    pub dns_search: Vec<String>,
    pub table: Option<String>,
    pub pre_up: Vec<String>,
    pub post_up: Vec<String>,
    pub pre_down: Vec<String>,
    pub post_down: Vec<String>,
    pub save_config: bool,
}

/// Result of resolving the `CONFIG_FILE | INTERFACE` command line argument.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedConfig {
    pub path: PathBuf,
    pub interface: String,
}

impl QuickConfig {
    pub fn load(argument: &str) -> QuickResult<Self> {
        let resolved = resolve_config(argument)?;
        let text = fs::read_to_string(&resolved.path).map_err(|error| {
            QuickError::die(format!(
                "`{}' could not be read: {error}",
                resolved.path.display()
            ))
        })?;
        Self::from_text(resolved.interface, resolved.path, &text)
    }

    pub fn from_text(
        interface: impl Into<String>,
        config_file: PathBuf,
        text: &str,
    ) -> QuickResult<Self> {
        let mut config = Self {
            config_file,
            interface: interface.into(),
            wg_config: String::new(),
            addresses: Vec::new(),
            mtu: None,
            dns: Vec::new(),
            dns_search: Vec::new(),
            table: None,
            pre_up: Vec::new(),
            post_up: Vec::new(),
            pre_down: Vec::new(),
            post_down: Vec::new(),
            save_config: false,
        };
        parse_into(&mut config, text)?;
        Ok(config)
    }

    /// Output of the `strip` subcommand (`echo "$WG_CONFIG"`).
    pub fn strip_output(&self) -> String {
        let mut output = self.wg_config.clone();
        output.push('\n');
        output
    }
}

/// Resolve a command line argument into a canonical path and interface name.
pub fn resolve_config(argument: &str) -> QuickResult<ResolvedConfig> {
    let candidate = if is_valid_interface_name(argument) {
        default_config_path(argument)
    } else {
        PathBuf::from(argument)
    };
    if !candidate.exists() {
        return Err(QuickError::die(format!(
            "`{}' does not exist",
            candidate.display()
        )));
    }
    let interface = interface_from_file_name(&candidate)?;
    let path = fs::canonicalize(&candidate).unwrap_or(candidate);
    warn_if_world_accessible(&path);
    Ok(ResolvedConfig { path, interface })
}

pub fn default_config_path(interface: &str) -> PathBuf {
    Path::new(CONFIG_DIR).join(format!("{interface}{CONFIG_SUFFIX}"))
}

pub fn is_valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'=' | b'+' | b'.' | b'-')
        })
}

fn interface_from_file_name(path: &Path) -> QuickResult<String> {
    let invalid =
        || QuickError::die("The config file must be a valid interface name, followed by .conf");
    let file_name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(invalid)?;
    let stem = file_name.strip_suffix(CONFIG_SUFFIX).ok_or_else(invalid)?;
    if !is_valid_interface_name(stem) {
        return Err(invalid());
    }
    Ok(stem.to_string())
}

pub fn is_world_accessible(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let Ok(file_metadata) = fs::metadata(path) else {
        return false;
    };
    let Some(parent) = path.parent() else {
        return false;
    };
    let Ok(directory_metadata) = fs::metadata(parent) else {
        return false;
    };
    let file_mode = file_metadata.permissions().mode();
    let directory_mode = directory_metadata.permissions().mode();
    (file_mode & directory_mode & 0o007) != 0
}

fn warn_if_world_accessible(path: &Path) {
    if is_world_accessible(path) {
        eprintln!("Warning: `{}' is world accessible", path.display());
    }
}

fn parse_into(config: &mut QuickConfig, text: &str) -> QuickResult<()> {
    let mut lines: Vec<&str> = text.split('\n').collect();
    if text.ends_with('\n') {
        lines.pop();
    }
    if text.is_empty() {
        lines.clear();
    }
    let mut interface_section = false;
    for raw_line in lines {
        let line = trim_ifs(raw_line);
        let stripped = match line.split_once('#') {
            Some((head, _)) => head,
            None => line,
        };
        let (raw_key, raw_value) = match stripped.split_once('=') {
            Some((key, value)) => (key, value),
            None => (stripped, stripped),
        };
        let key = trim_posix_space(raw_key);
        let value = trim_posix_space(raw_value);

        if key.starts_with('[') {
            interface_section = false;
        }
        if key.eq_ignore_ascii_case("[Interface]") {
            interface_section = true;
        }

        if interface_section {
            if key.eq_ignore_ascii_case("Address") {
                config
                    .addresses
                    .extend(split_value_tokens(value).map(ToOwned::to_owned));
                continue;
            }
            if key.eq_ignore_ascii_case("MTU") {
                config.mtu = non_empty(value);
                continue;
            }
            if key.eq_ignore_ascii_case("DNS") {
                for token in split_value_tokens(value) {
                    if is_dns_address(token) {
                        config.dns.push(token.to_string());
                    } else {
                        config.dns_search.push(token.to_string());
                    }
                }
                continue;
            }
            if key.eq_ignore_ascii_case("Table") {
                config.table = non_empty(value);
                continue;
            }
            if key.eq_ignore_ascii_case("PreUp") {
                config.pre_up.push(value.to_string());
                continue;
            }
            if key.eq_ignore_ascii_case("PreDown") {
                config.pre_down.push(value.to_string());
                continue;
            }
            if key.eq_ignore_ascii_case("PostUp") {
                config.post_up.push(value.to_string());
                continue;
            }
            if key.eq_ignore_ascii_case("PostDown") {
                config.post_down.push(value.to_string());
                continue;
            }
            if key.eq_ignore_ascii_case("SaveConfig") {
                config.save_config = parse_bool(value)?;
                continue;
            }
        }

        config.wg_config.push_str(line);
        config.wg_config.push('\n');
    }
    Ok(())
}

fn non_empty(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// Trim exactly the characters the shell `read` builtin strips from a line.
fn trim_ifs(value: &str) -> &str {
    value.trim_matches(|character| character == ' ' || character == '\t')
}

/// Trim the characters matched by `[[:space:]]` in the C locale.
fn trim_posix_space(value: &str) -> &str {
    value.trim_matches(|character| {
        matches!(
            character,
            ' ' | '\t' | '\n' | '\r' | '\u{000B}' | '\u{000C}'
        )
    })
}

fn split_value_tokens(value: &str) -> impl Iterator<Item = &str> {
    value
        .split([',', ' ', '\t', '\n'])
        .filter(|token| !token.is_empty())
}

fn is_dns_address(token: &str) -> bool {
    (!token.is_empty()
        && token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.'))
        || token.contains(':')
}

fn parse_bool(value: &str) -> QuickResult<bool> {
    if value.eq_ignore_ascii_case("true") {
        Ok(true)
    } else if value.eq_ignore_ascii_case("false") {
        Ok(false)
    } else {
        Err(QuickError::die(format!(
            "`{value}' is neither true nor false"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const SAMPLE: &str = "\
# leading comment
[Interface]
PrivateKey = abc=
Address = 10.0.0.2/24, fd00::2/64
Address = 10.0.0.3/32
DNS = 1.1.1.1, 8.8.8.8 , example.com
MTU = 1400
Table = custom
PreUp = echo pre %i
PostUp = echo post
PreDown = echo predown
PostDown = echo postdown
SaveConfig = TRUE
ListenPort = 51820
Jc = 3

[Peer]
PublicKey = xyz=
AllowedIPs = 10.0.0.0/24, 0.0.0.0/0
";

    fn parse(text: &str) -> QuickConfig {
        QuickConfig::from_text("wg0", PathBuf::from("/tmp/wg0.conf"), text).unwrap()
    }

    #[test]
    fn parses_quick_keys_case_insensitively() {
        let config = parse(SAMPLE);
        assert_eq!(config.interface, "wg0");
        assert_eq!(
            config.addresses,
            ["10.0.0.2/24", "fd00::2/64", "10.0.0.3/32"]
        );
        assert_eq!(config.mtu.as_deref(), Some("1400"));
        assert_eq!(config.dns, ["1.1.1.1", "8.8.8.8"]);
        assert_eq!(config.dns_search, ["example.com"]);
        assert_eq!(config.table.as_deref(), Some("custom"));
        assert_eq!(config.pre_up, ["echo pre %i"]);
        assert_eq!(config.post_up, ["echo post"]);
        assert_eq!(config.pre_down, ["echo predown"]);
        assert_eq!(config.post_down, ["echo postdown"]);
        assert!(config.save_config);
    }

    #[test]
    fn keeps_only_setconf_compatible_lines() {
        let config = parse(SAMPLE);
        let expected = "\
# leading comment
[Interface]
PrivateKey = abc=
ListenPort = 51820
Jc = 3

[Peer]
PublicKey = xyz=
AllowedIPs = 10.0.0.0/24, 0.0.0.0/0
";
        assert_eq!(config.wg_config, expected);
        assert_eq!(config.strip_output(), format!("{expected}\n"));
    }

    #[test]
    fn strips_inline_comments_and_trims_whitespace() {
        let text =
            "  # comment  \n\t[Interface]\t\n  Address = 10.0.0.2/24 # x\n  ListenPort = 1 # y  \n";
        let config = parse(text);
        assert_eq!(config.addresses, ["10.0.0.2/24"]);
        assert_eq!(
            config.wg_config,
            "# comment\n[Interface]\nListenPort = 1 # y\n"
        );
    }

    #[test]
    fn peer_keys_are_not_treated_as_quick_keys() {
        let text = "\
[Interface]
Address = 10.0.0.2/24
[Peer]
Address = 192.0.2.1/32
DNS = 1.1.1.1
";
        let config = parse(text);
        assert_eq!(config.addresses, ["10.0.0.2/24"]);
        assert!(config.dns.is_empty());
        assert_eq!(
            config.wg_config,
            "[Interface]\n[Peer]\nAddress = 192.0.2.1/32\nDNS = 1.1.1.1\n"
        );
    }

    #[test]
    fn empty_values_are_treated_as_unset_but_hooks_are_kept() {
        let text = "[Interface]\nMTU =\nTable =\nPreUp =\n";
        let config = parse(text);
        assert_eq!(config.mtu, None);
        assert_eq!(config.table, None);
        assert_eq!(config.pre_up, [""]);
    }

    #[test]
    fn save_config_rejects_other_values() {
        let error = QuickConfig::from_text(
            "wg0",
            PathBuf::from("/tmp/wg0.conf"),
            "[Interface]\nSaveConfig = yes\n",
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "`yes' is neither true nor false");
        assert_eq!(error.exit_code(), 1);
    }

    #[test]
    fn save_config_accepts_case_insensitive_false() {
        let config = parse("[Interface]\nSaveConfig = False\n");
        assert!(!config.save_config);
    }

    #[test]
    fn empty_config_strip_is_just_a_newline() {
        let config = parse("");
        assert_eq!(config.wg_config, "");
        assert_eq!(config.strip_output(), "\n");
    }

    #[test]
    fn validates_interface_names() {
        assert!(is_valid_interface_name("wg0"));
        assert!(is_valid_interface_name("a"));
        assert!(is_valid_interface_name("a_b=c+d-e.f"));
        assert!(is_valid_interface_name("012345678901234"));
        assert!(!is_valid_interface_name(""));
        assert!(!is_valid_interface_name("0123456789012345"));
        assert!(!is_valid_interface_name("wg 0"));
        assert!(!is_valid_interface_name("wg/0"));
    }

    #[test]
    fn default_path_uses_umbrawg_config_dir() {
        assert_eq!(
            default_config_path("wg0"),
            PathBuf::from("/etc/umbrawg/wg0.conf")
        );
    }

    #[test]
    fn resolves_interface_and_canonical_path() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wg0.conf");
        fs::write(&path, "[Interface]\n").unwrap();
        let resolved = resolve_config(path.to_str().unwrap()).unwrap();
        assert_eq!(resolved.interface, "wg0");
        assert_eq!(resolved.path, fs::canonicalize(&path).unwrap());
    }

    #[test]
    fn rejects_invalid_config_file_names() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("bad name.conf");
        fs::write(&path, "[Interface]\n").unwrap();
        let error = resolve_config(path.to_str().unwrap()).unwrap_err();
        assert_eq!(
            error.to_string(),
            "The config file must be a valid interface name, followed by .conf"
        );
    }

    #[test]
    fn missing_config_file_reports_path() {
        let error = resolve_config("/nonexistent/definitely-missing.conf").unwrap_err();
        assert_eq!(
            error.to_string(),
            "`/nonexistent/definitely-missing.conf' does not exist"
        );
    }

    #[test]
    fn world_accessibility_checks_file_and_directory() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wg0.conf");
        fs::write(&path, "[Interface]\n").unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!is_world_accessible(&path));
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o777)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(is_world_accessible(&path));
    }
}
