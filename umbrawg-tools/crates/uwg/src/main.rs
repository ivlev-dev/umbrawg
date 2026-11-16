mod cli;
mod keys;
mod output;

use std::process::ExitCode;

use clap::Parser;
use umbrawg_config::Config;
use umbrawg_ctl::SetDevice;

use crate::cli::{Cli, Command, ShowArgs};

type CommandResult = Result<(), String>;

#[tokio::main]
async fn main() -> ExitCode {
    let _ = env_logger::try_init();
    let parsed = Cli::parse();
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
        Some(Command::Setconf(args)) => run_setconf(&args.interface, &args.filename).await,
        Some(Command::Genkey) => run_genkey(),
        Some(Command::Genpsk) => run_genpsk(),
        Some(Command::Pubkey) => run_pubkey(),
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
            let text = output::ugly(&device, parameter, false)?;
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

async fn run_setconf(interface: &str, filename: &std::path::Path) -> CommandResult {
    let contents = std::fs::read_to_string(filename).map_err(|error| format!("fopen: {error}"))?;
    let config = Config::parse(&contents)
        .map_err(|error| format!("Configuration parsing error: {error}"))?;
    let set = SetDevice::from_config(interface, &config);
    umbrawg_ctl::set_device(&set)
        .await
        .map_err(|error| format!("Unable to modify interface: {error}"))
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
