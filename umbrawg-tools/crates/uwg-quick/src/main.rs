use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::path::Path;
use std::process::Command;
use uwg_quick::commands;
use uwg_quick::error::QuickError;
use uwg_quick::usage;

fn main() {
    prepend_executable_directory();
    let mut arguments = std::env::args_os();
    let argv0 = arguments
        .next()
        .unwrap_or_else(|| OsString::from("uwg-quick"));
    let program = program_name(&argv0);
    let rest: Vec<OsString> = arguments.collect();

    if rest.len() == 1 && usage::is_help(&rest[0]) {
        usage::print_usage(&program);
        std::process::exit(0);
    }
    if rest.len() != 2 || !usage::is_subcommand(&rest[0]) {
        usage::print_usage(&program);
        std::process::exit(1);
    }

    auto_su(&program, &argv0, &rest);

    let Some(subcommand) = rest[0].to_str() else {
        eprintln!("{program}: invalid subcommand");
        std::process::exit(1);
    };
    let Some(config_argument) = rest[1].to_str() else {
        eprintln!("{program}: invalid configuration path");
        std::process::exit(1);
    };

    match commands::run(subcommand, config_argument) {
        Ok(()) => {
            let _ = io::stdout().flush();
            std::process::exit(0);
        }
        Err(QuickError::Die(message)) => {
            eprintln!("{program}: {message}");
            std::process::exit(1);
        }
        Err(QuickError::Io(error)) => {
            eprintln!("{program}: {error}");
            std::process::exit(1);
        }
        Err(error) => std::process::exit(error.exit_code()),
    }
}

fn program_name(argv0: &OsStr) -> String {
    Path::new(argv0)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "uwg-quick".to_string())
}

fn prepend_executable_directory() {
    let Ok(executable) = std::env::current_exe() else {
        return;
    };
    let Some(directory) = executable.parent() else {
        return;
    };
    let mut entries = vec![directory.to_path_buf()];
    if let Some(path) = std::env::var_os("PATH") {
        entries.extend(std::env::split_paths(&path));
    }
    if let Ok(path) = std::env::join_paths(entries) {
        std::env::set_var("PATH", path);
    }
}

fn auto_su(program: &str, argv0: &OsStr, rest: &[OsString]) {
    if unsafe { libc::getuid() } == 0 {
        return;
    }
    use std::os::unix::process::CommandExt;

    let executable =
        std::fs::canonicalize(Path::new(argv0)).unwrap_or_else(|_| Path::new(argv0).to_path_buf());
    let prompt =
        format!("{program} must be run as root. Please enter the password for %u to continue: ");
    let error = Command::new("sudo")
        .arg("-p")
        .arg(prompt)
        .arg("--")
        .arg(executable)
        .args(rest)
        .exec();
    eprintln!("{program}: sudo: {error}");
    std::process::exit(127);
}
