use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::path::Path;
use std::process::Command;
use uwg_quick::commands;
use uwg_quick::error::QuickError;
use uwg_quick::usage;

fn main() {
    append_executable_directory();
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

    let Some(subcommand) = rest[0].to_str() else {
        eprintln!("{program}: invalid subcommand");
        std::process::exit(1);
    };
    if requires_root(subcommand) {
        auto_su(&program, &argv0, &rest);
    }
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

fn append_executable_directory() {
    let Ok(executable) = std::env::current_exe() else {
        return;
    };
    let Some(directory) = executable.parent() else {
        return;
    };
    let mut entries: Vec<std::path::PathBuf> = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect())
        .unwrap_or_default();
    if !entries.iter().any(|entry| entry == directory) {
        entries.push(directory.to_path_buf());
    }
    if let Ok(path) = std::env::join_paths(entries) {
        std::env::set_var("PATH", path);
    }
}

fn requires_root(subcommand: &str) -> bool {
    matches!(subcommand, "up" | "down" | "save")
}

fn auto_su(program: &str, argv0: &OsStr, rest: &[OsString]) {
    if unsafe { libc::getuid() } == 0 {
        return;
    }
    use std::os::unix::process::CommandExt;

    let _ = argv0;
    let executable = match std::env::current_exe() {
        Ok(executable) => executable,
        Err(error) => {
            eprintln!("{program}: cannot resolve own executable: {error}");
            std::process::exit(127);
        }
    };
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

#[cfg(test)]
mod tests {
    use super::requires_root;

    #[test]
    fn strip_never_asks_for_root() {
        assert!(!requires_root("strip"));
    }

    #[test]
    fn link_commands_require_root() {
        for subcommand in ["up", "down", "save"] {
            assert!(requires_root(subcommand), "{subcommand}");
        }
    }

    #[test]
    fn unknown_subcommands_do_not_require_root() {
        assert!(!requires_root("show"));
        assert!(!requires_root(""));
    }
}
