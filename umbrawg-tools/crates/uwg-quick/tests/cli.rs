use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_uwg-quick"))
}

fn temporary_directory(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("uwg-quick-{name}-{}-{nanos}", std::process::id()));
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

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("utf-8 stderr")
}

#[test]
fn help_exits_zero_and_prints_usage_to_stderr() {
    let output = binary().arg("--help").output().expect("run uwg-quick");
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(stderr.starts_with("Usage: uwg-quick [ up | down | save | strip ]"));
    assert!(stderr.contains("/etc/umbrawg/INTERFACE.conf"));
}

#[test]
fn missing_arguments_prints_usage_and_fails() {
    let output = binary().output().expect("run uwg-quick");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(stderr.starts_with("Usage: uwg-quick"));
}

#[test]
fn unknown_subcommand_prints_usage_and_fails() {
    let output = binary()
        .arg("show")
        .arg("wg0")
        .output()
        .expect("run uwg-quick");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(stderr.starts_with("Usage: uwg-quick"));
}

#[test]
fn help_with_extra_argument_fails() {
    let output = binary()
        .arg("help")
        .arg("wg0")
        .output()
        .expect("run uwg-quick");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
    assert!(stderr.starts_with("Usage: uwg-quick"));
}

#[test]
fn strip_does_not_require_root() {
    let directory = temporary_directory("strip");
    let tools = directory.join("tools");
    fs::create_dir_all(&tools).expect("tools directory");
    let marker = directory.join("sudo-called");
    let marker_text = marker.display().to_string();
    script(
        &tools,
        "sudo",
        &format!("#!/bin/sh\nPATH=/usr/bin:/bin\ntouch '{marker_text}'\nexit 1\n"),
    );
    let path = config(
        &directory,
        "wg0.conf",
        "[Interface]\nPrivateKey = abc=\nAddress = 10.0.0.2/24\n",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_uwg-quick"))
        .arg("strip")
        .arg(&path)
        .env("PATH", &tools)
        .output()
        .expect("run uwg-quick strip");

    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    assert_eq!(stdout, "[Interface]\nPrivateKey = abc=\n\n");
    assert!(!marker.exists(), "strip must not ask for root");
    let _ = fs::remove_dir_all(&directory);
}
