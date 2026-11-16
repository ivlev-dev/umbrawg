use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use uwg_quick::QuickConfig;

fn reference_script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../legacy-c/wg-quick/linux.bash")
}

fn patch_auto_su(script: &str) -> String {
    let start = script.find("auto_su() {").expect("auto_su function");
    let end = script[start..]
        .find("\n}")
        .map(|offset| start + offset + 2)
        .expect("auto_su function end");
    let mut patched = String::from(&script[..start]);
    patched.push_str("auto_su() { :; }");
    patched.push_str(&script[end..]);
    patched
}

fn bash_available() -> bool {
    Command::new("bash")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn bash_strip(script: &Path, config: &Path) -> String {
    let output = Command::new("bash")
        .arg(script)
        .arg("strip")
        .arg(config)
        .output()
        .expect("run reference strip");
    assert!(
        output.status.success(),
        "reference strip failed for {}: {}",
        config.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf-8 reference output")
}

fn compare(config: &Path, patched_script: &Path) {
    let expected = bash_strip(patched_script, config);
    let ours = QuickConfig::load(config.to_str().expect("utf-8 fixture path"))
        .expect("load fixture")
        .strip_output();
    assert_eq!(ours, expected, "strip mismatch for {}", config.display());
}

#[test]
fn strip_matches_reference_script_on_fixtures() {
    let script = reference_script();
    if !script.is_file() || !bash_available() {
        eprintln!("skipping: reference script or bash is unavailable");
        return;
    }
    let reference = fs::read_to_string(&script).expect("read reference script");
    let directory = tempfile::tempdir().expect("tempdir");
    let patched_script = directory.path().join("linux.bash");
    fs::write(&patched_script, patch_auto_su(&reference)).expect("write patched script");

    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut configs: Vec<PathBuf> = fs::read_dir(&fixtures)
        .expect("fixtures directory")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("conf"))
        .collect();
    configs.sort();
    assert!(!configs.is_empty(), "no fixtures found");

    for config in configs {
        compare(&config, &patched_script);
    }
}

#[test]
fn strip_matches_reference_script_with_crlf() {
    let script = reference_script();
    if !script.is_file() || !bash_available() {
        eprintln!("skipping: reference script or bash is unavailable");
        return;
    }
    let reference = fs::read_to_string(&script).expect("read reference script");
    let directory = tempfile::tempdir().expect("tempdir");
    let patched_script = directory.path().join("linux.bash");
    fs::write(&patched_script, patch_auto_su(&reference)).expect("write patched script");

    let config = directory.path().join("crlf.conf");
    fs::write(
        &config,
        "[Interface]\r\nPrivateKey = abc=\r\nAddress = 10.0.0.2/24\r\n",
    )
    .expect("write crlf config");

    compare(&config, &patched_script);
}
