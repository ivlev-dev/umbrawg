use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use uwg_quick::command::SystemRunner;
use uwg_quick::commands;
use uwg_quick::QuickConfig;

fn temporary_directory() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("uwg-quick-setconf-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&directory).expect("temporary directory");
    directory
}

fn script(directory: &Path, name: &str, body: &str) -> PathBuf {
    let path = directory.join(name);
    fs::write(&path, body).expect("write script");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("executable script");
    path
}

fn config(directory: &Path, name: &str, body: &str) -> PathBuf {
    let path = directory.join(name);
    fs::write(&path, body).expect("write config");
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).expect("private directory");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private config");
    path
}

#[test]
fn up_runs_setconf_with_a_configuration_file_and_stdin() {
    let directory = temporary_directory();
    let tools = directory.join("tools");
    fs::create_dir_all(&tools).expect("tools directory");
    let log = directory.join("uwg.log");
    let stdin = directory.join("setconf.stdin");
    let log_text = log.display().to_string();
    let stdin_text = stdin.display().to_string();
    script(
        &tools,
        "uwg",
        &format!(
            "#!/bin/sh\nPATH=/usr/bin:/bin\nprintf '%s\\n' \"$*\" >> '{log_text}'\nif [ \"$1\" = setconf ]; then\n  cat > '{stdin_text}'\nfi\nexit 0\n"
        ),
    );
    script(
        &tools,
        "ip",
        "#!/bin/sh\nPATH=/usr/bin:/bin\nif [ \"$1\" = link ] && [ \"$2\" = show ]; then\n  exit 1\nfi\nexit 0\n",
    );
    let path = config(
        &directory,
        "wg0.conf",
        "[Interface]\nPrivateKey = abc=\nAddress = 10.0.0.2/24\nMTU = 1420\n",
    );

    std::env::set_var("PATH", &tools);
    let config = QuickConfig::load(path.to_str().expect("path")).expect("config");
    commands::up(&config, &SystemRunner).expect("up");

    let calls = fs::read_to_string(&log).expect("uwg log");
    assert!(
        calls.lines().any(|line| line == "setconf wg0 /dev/stdin"),
        "unexpected uwg calls: {calls}"
    );
    assert_eq!(
        fs::read_to_string(&stdin).expect("setconf stdin"),
        "[Interface]\nPrivateKey = abc=\n\n"
    );
    let _ = fs::remove_dir_all(&directory);
}
