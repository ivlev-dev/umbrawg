use std::process::Command;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_uwg-quick"))
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
