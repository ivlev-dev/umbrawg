mod cli;
mod keys;
mod output;

use std::process::ExitCode;

use clap::error::ErrorKind;
use clap::FromArgMatches;
use umbrawg_config::Config;
use umbrawg_ctl::SetDevice;

use crate::cli::{Cli, Command, ShowArgs};

type CommandResult = Result<(), String>;

#[tokio::main]
async fn main() -> ExitCode {
    let _ = env_logger::try_init();
    let parsed = match parse_cli() {
        Ok(parsed) => parsed,
        Err(error) => return report_parse_error(&error),
    };
    let result = match parsed.command {
        None => {
            run_show(&ShowArgs {
                interface: "all".to_owned(),
                parameter: None,
            })
            .await
        }
        Some(Command::Show(args)) => run_show(&args).await,
        Some(Command::Showconf(args)) => run_showconf(&args.interface).await,
        Some(Command::Set(args)) => run_set(&args.interface, &args.arguments).await,
        Some(Command::Setconf(args)) => {
            run_config_file("setconf", &args.interface, &args.filename).await
        }
        Some(Command::Addconf(args)) => {
            run_config_file("addconf", &args.interface, &args.filename).await
        }
        Some(Command::Syncconf(args)) => {
            run_config_file("syncconf", &args.interface, &args.filename).await
        }
        Some(Command::Genkey) => run_genkey(),
        Some(Command::Genpsk) => run_genpsk(),
        Some(Command::Pubkey) => run_pubkey(),
        Some(Command::Version) => run_version(),
        Some(Command::Help) => run_help(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            if !message.is_empty() {
                eprintln!("{message}");
            }
            ExitCode::FAILURE
        }
    }
}

fn parse_cli() -> Result<Cli, clap::Error> {
    let matches = cli::command().try_get_matches()?;
    Cli::from_arg_matches(&matches)
}

fn report_parse_error(error: &clap::Error) -> ExitCode {
    let code = match error.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => 0,
        _ => 1,
    };
    let _ = error.print();
    ExitCode::from(code)
}

async fn run_show(args: &ShowArgs) -> CommandResult {
    if args.interface == "interfaces" {
        if args.parameter.is_some() {
            return Err(cli::show_usage());
        }
        let interfaces = umbrawg_ctl::list_interfaces()
            .await
            .map_err(|error| format!("Unable to list interfaces: {error}"))?;
        if !interfaces.is_empty() {
            println!("{}", interfaces.join(" "));
        }
        return Ok(());
    }

    let color = output::color_enabled();
    if args.interface == "all" {
        let interfaces = umbrawg_ctl::list_interfaces()
            .await
            .map_err(|error| format!("Unable to list interfaces: {error}"))?;
        let mut success = false;
        let mut ugly_failed = false;
        let mut printed = false;
        for interface in &interfaces {
            let device = match umbrawg_ctl::get_device(interface).await {
                Ok(device) => device,
                Err(error) => {
                    eprintln!("Unable to access interface {interface}: {error}");
                    continue;
                }
            };
            match &args.parameter {
                Some(parameter) => match output::ugly(&device, parameter, true) {
                    Ok(text) => print!("{text}"),
                    Err(error) => {
                        eprintln!("{error}");
                        eprintln!("{}", cli::show_usage());
                        ugly_failed = true;
                        break;
                    }
                },
                None => {
                    if printed {
                        println!();
                    }
                    print!("{}", output::pretty(&device, color));
                    printed = true;
                }
            }
            success = true;
        }
        if !success || ugly_failed {
            return Err(String::new());
        }
        return Ok(());
    }

    let device = umbrawg_ctl::get_device(&args.interface)
        .await
        .map_err(|error| format!("Unable to access interface: {error}"))?;
    match &args.parameter {
        Some(parameter) => {
            let text = output::ugly(&device, parameter, false)
                .map_err(|error| format!("{error}\n{}", cli::show_usage()))?;
            print!("{text}");
        }
        None => print!("{}", output::pretty(&device, color)),
    }
    Ok(())
}

async fn run_showconf(interface: &str) -> CommandResult {
    let device = umbrawg_ctl::get_device(interface)
        .await
        .map_err(|error| format!("Unable to access interface: {error}"))?;
    print!("{}", output::showconf(&device));
    Ok(())
}

async fn run_set(interface: &str, arguments: &[String]) -> CommandResult {
    if arguments.is_empty() {
        return Err(cli::set_usage());
    }
    let config = Config::from_args(arguments).map_err(|error| error.to_string())?;
    warn_about_host_bits(&config);
    let set = SetDevice {
        name: interface.to_owned(),
        replace_peers: false,
        device: config.device,
        peers: config.peers,
    };
    umbrawg_ctl::set_device(&set)
        .await
        .map_err(|error| format!("Unable to modify interface: {error}"))
}

async fn run_config_file(
    command: &str,
    interface: &str,
    filename: &std::path::Path,
) -> CommandResult {
    let config = read_config(filename)?;
    warn_about_host_bits(&config);
    let result = match command {
        "setconf" => umbrawg_ctl::setconf(interface, &config).await,
        "addconf" => umbrawg_ctl::addconf(interface, &config).await,
        "syncconf" => umbrawg_ctl::syncconf(interface, &config).await,
        other => return Err(cli::setconf_usage(other)),
    };
    result.map_err(|error| format!("Unable to modify interface: {error}"))
}

fn read_config(filename: &std::path::Path) -> Result<Config, String> {
    let contents = std::fs::read_to_string(filename).map_err(|error| format!("fopen: {error}"))?;
    Config::parse(&contents).map_err(|error| format!("Configuration parsing error: {error}"))
}

fn warn_about_host_bits(config: &Config) {
    for allowed_ip in config.allowed_ips_with_host_bits() {
        eprintln!("Warning: AllowedIP has nonzero host part: {allowed_ip}");
    }
}

fn run_version() -> CommandResult {
    println!("{} v{}", cli::PROGRAM, env!("CARGO_PKG_VERSION"));
    Ok(())
}

fn run_help() -> CommandResult {
    let mut command = cli::command();
    command
        .print_help()
        .map_err(|error| format!("Unable to print help: {error}"))?;
    println!();
    Ok(())
}

fn run_genkey() -> CommandResult {
    keys::warn_world_accessible(1);
    let key = keys::generate_private_key()?;
    keys::write_stdout(&key)
}

fn run_genpsk() -> CommandResult {
    keys::warn_world_accessible(1);
    let key = keys::generate_preshared_key()?;
    keys::write_stdout(&key)
}

fn run_pubkey() -> CommandResult {
    let input = keys::read_stdin()?;
    let key = keys::public_key_from_stdin(&input)
        .map_err(|error| format!("{}: {error}", cli::PROGRAM))?;
    keys::write_stdout(&key)
}
