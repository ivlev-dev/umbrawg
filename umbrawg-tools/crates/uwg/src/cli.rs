use std::path::PathBuf;

use clap::{Args, CommandFactory, Parser, Subcommand};

pub const PROGRAM: &str = "uwg";

#[derive(Debug, Parser)]
#[command(
    name = PROGRAM,
    version = concat!("v", env!("CARGO_PKG_VERSION")),
    about = "UmbraWG configuration utility",
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(about = "Shows the current configuration and device information")]
    Show(ShowArgs),
    #[command(about = "Shows the configuration of an interface in INI format")]
    Showconf(InterfaceArgs),
    #[command(about = "Changes the current configuration, adds or removes peers")]
    Set(SetArgs),
    #[command(about = "Applies a configuration file to an interface")]
    Setconf(SetconfArgs),
    #[command(about = "Appends a configuration file to an interface")]
    Addconf(SetconfArgs),
    #[command(about = "Synchronizes a configuration file to an interface")]
    Syncconf(SetconfArgs),
    #[command(about = "Generates a new private key and writes it to stdout")]
    Genkey,
    #[command(about = "Generates a new preshared key and writes it to stdout")]
    Genpsk,
    #[command(about = "Reads a private key from stdin and writes a public key to stdout")]
    Pubkey,
    #[command(about = "Shows the version and exits")]
    Version,
    #[command(about = "Shows this help message and exits")]
    Help,
}

#[derive(Debug, Args)]
pub struct ShowArgs {
    #[arg(default_value = "all", value_name = "interface")]
    pub interface: String,
    #[arg(value_name = "parameter")]
    pub parameter: Option<String>,
}

#[derive(Debug, Args)]
pub struct InterfaceArgs {
    #[arg(value_name = "interface")]
    pub interface: String,
}

#[derive(Debug, Args)]
pub struct SetArgs {
    #[arg(value_name = "interface")]
    pub interface: String,
    #[arg(
        required = true,
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "argument"
    )]
    pub arguments: Vec<String>,
}

#[derive(Debug, Args)]
pub struct SetconfArgs {
    #[arg(value_name = "interface")]
    pub interface: String,
    #[arg(value_name = "configuration filename")]
    pub filename: PathBuf,
}

pub fn command() -> clap::Command {
    Cli::command().disable_version_flag(true).arg(
        clap::Arg::new("version_flag")
            .short('v')
            .long("version")
            .action(clap::ArgAction::Version)
            .help("Print version"),
    )
}

pub fn show_usage() -> String {
    format!(
        "Usage: {PROGRAM} show {{ <interface> | all | interfaces }} [public-key | private-key | listen-port | extra-ports | fwmark | peers | preshared-keys | endpoints | allowed-ips | latest-handshakes | transfer | persistent-keepalive | advanced-security | dump | jc | jmin | jmax | s1 | s2 | s3 | s4 | h1 | h2 | h3 | h4 | i1 | i2 | i3 | i4 | i5 | header-protection-key | content-padding-addition | rekey-after-time | rekey-timeout | reject-after-time | keepalive-timeout | max-handshake-attempts | max_handshake_attempts | random-trailers | disable-cookies]"
    )
}

pub fn setconf_usage(command: &str) -> String {
    format!("Usage: {PROGRAM} {command} <interface> <configuration filename>")
}

pub fn set_usage() -> String {
    format!(
        "Usage: {PROGRAM} set <interface> [listen-port <port>] [extra-ports <n>] [fwmark <mark>] [private-key <file path>] [jc <junk_count>] [jmin <min_value>] [jmax <max_value>] [s1 <init_junk>] [s2 <resp_junk>] [s3 <cookie_junk>] [s4 <trans_junk>] [h1 <init_header>] [h2 <resp_header>] [h3 <cookie_header>] [h4 <transp_header>] [i1 \"<taged_junk>\"] [i2 \"<taged_junk>\"] [i3 \"<taged_junk>\"] [i4 \"<taged_junk>\"] [i5 \"<taged_junk>\"] [header-protection-key \"<key>\"] [content-padding-addition \"<range>\"] [rekey-after-time \"<range>\"] [rekey-timeout \"<range>\"] [reject-after-time \"<range>\"] [keepalive-timeout \"<range>\"] [max-handshake-attempts \"<range>\"] [random-trailers <on|off>] [disable-cookies <on|off>] [peer <base64 public key> [remove] [preshared-key <file path>] [cipher chacha20-poly1305|aes-256-gcm] [endpoint <ip>:<port>] [persistent-keepalive <interval seconds>] [allowed-ips <ip1>/<cidr1>[,<ip2>/<cidr2>]...] [advanced-security <on|off>]]..."
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn usage_lists_extra_ports() {
        assert!(show_usage().contains("extra-ports"));
        assert!(set_usage().contains("[extra-ports <n>]"));
    }

    #[test]
    fn command_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn no_arguments_means_show_all() {
        let cli = Cli::try_parse_from(["uwg"]).expect("valid");
        assert!(cli.command.is_none());
    }

    #[test]
    fn parses_show_variants() {
        let cli = Cli::try_parse_from(["uwg", "show"]).expect("valid");
        match cli.command {
            Some(Command::Show(args)) => {
                assert_eq!(args.interface, "all");
                assert!(args.parameter.is_none());
            }
            other => panic!("unexpected: {other:?}"),
        }
        let cli = Cli::try_parse_from(["uwg", "show", "uwg0", "dump"]).expect("valid");
        match cli.command {
            Some(Command::Show(args)) => {
                assert_eq!(args.interface, "uwg0");
                assert_eq!(args.parameter.as_deref(), Some("dump"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn parses_set_arguments() {
        let cli = Cli::try_parse_from([
            "uwg",
            "set",
            "uwg0",
            "listen-port",
            "51820",
            "peer",
            "abc",
            "allowed-ips",
            "10.0.0.0/8",
        ])
        .expect("valid");
        match cli.command {
            Some(Command::Set(args)) => {
                assert_eq!(args.interface, "uwg0");
                assert_eq!(args.arguments.len(), 6);
                assert_eq!(args.arguments[0], "listen-port");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn set_requires_arguments() {
        assert!(Cli::try_parse_from(["uwg", "set", "uwg0"]).is_err());
        assert!(Cli::try_parse_from(["uwg", "set"]).is_err());
    }

    #[test]
    fn parses_setconf_and_showconf() {
        let cli = Cli::try_parse_from(["uwg", "showconf", "uwg0"]).expect("valid");
        match cli.command {
            Some(Command::Showconf(args)) => assert_eq!(args.interface, "uwg0"),
            other => panic!("unexpected: {other:?}"),
        }
        let cli = Cli::try_parse_from(["uwg", "setconf", "uwg0", "test.conf"]).expect("valid");
        match cli.command {
            Some(Command::Setconf(args)) => {
                assert_eq!(args.interface, "uwg0");
                assert_eq!(args.filename, PathBuf::from("test.conf"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn parses_addconf_and_syncconf() {
        let cli = Cli::try_parse_from(["uwg", "addconf", "uwg0", "test.conf"]).expect("valid");
        match cli.command {
            Some(Command::Addconf(args)) => {
                assert_eq!(args.interface, "uwg0");
                assert_eq!(args.filename, PathBuf::from("test.conf"));
            }
            other => panic!("unexpected: {other:?}"),
        }
        let cli = Cli::try_parse_from(["uwg", "syncconf", "uwg0", "/tmp/a.conf"]).expect("valid");
        match cli.command {
            Some(Command::Syncconf(args)) => {
                assert_eq!(args.interface, "uwg0");
                assert_eq!(args.filename, PathBuf::from("/tmp/a.conf"));
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert!(Cli::try_parse_from(["uwg", "addconf", "uwg0"]).is_err());
        assert!(Cli::try_parse_from(["uwg", "syncconf"]).is_err());
        assert_eq!(
            setconf_usage("addconf"),
            "Usage: uwg addconf <interface> <configuration filename>"
        );
    }

    #[test]
    fn parses_positional_version_and_help() {
        assert!(matches!(
            Cli::try_parse_from(["uwg", "version"])
                .expect("valid")
                .command,
            Some(Command::Version)
        ));
        assert!(matches!(
            Cli::try_parse_from(["uwg", "help"]).expect("valid").command,
            Some(Command::Help)
        ));
    }

    #[test]
    fn parses_key_commands() {
        assert!(matches!(
            Cli::try_parse_from(["uwg", "genkey"])
                .expect("valid")
                .command,
            Some(Command::Genkey)
        ));
        assert!(matches!(
            Cli::try_parse_from(["uwg", "genpsk"])
                .expect("valid")
                .command,
            Some(Command::Genpsk)
        ));
        assert!(matches!(
            Cli::try_parse_from(["uwg", "pubkey"])
                .expect("valid")
                .command,
            Some(Command::Pubkey)
        ));
        assert!(Cli::try_parse_from(["uwg", "genkey", "extra"]).is_err());
    }

    #[test]
    fn rejects_unknown_subcommand() {
        assert!(Cli::try_parse_from(["uwg", "bogus"]).is_err());
    }

    #[test]
    fn version_is_printed() {
        let error = Cli::try_parse_from(["uwg", "--version"]).expect_err("version exits");
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayVersion);
        assert!(error.to_string().contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn version_flag_uses_legacy_short_form() {
        let error = command()
            .try_get_matches_from(["uwg", "-v"])
            .expect_err("version exits");
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayVersion);
        assert!(command().try_get_matches_from(["uwg", "-V"]).is_err());
    }
}
