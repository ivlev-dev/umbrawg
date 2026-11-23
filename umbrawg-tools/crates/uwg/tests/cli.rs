use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const PRIVATE: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
const PEER_ONE: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
const PEER_TWO: &str = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=";
const PEER_TWO_HEX: &str = "1c8828f7137324c58b2804928624ea2326f1674537c062e251e2753ca7fcca4c";
const RUNTIME_PEER_HEX: &str = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
const RUNTIME_PEER_BASE64: &str = "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8=";

fn runtime_dir() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("uwg-cli-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("runtime directory");
    directory
}

struct FakeUapi {
    directory: PathBuf,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    server: Option<JoinHandle<()>>,
}

impl FakeUapi {
    fn start(directory: &Path, get_response: String) -> Self {
        let path = directory.join("uwg0.sock");
        let listener = UnixListener::bind(&path).expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_requests = Arc::clone(&requests);
        let thread_stop = Arc::clone(&stop);
        let server = thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => handle(stream, &get_response, &thread_requests),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            directory: directory.to_path_buf(),
            requests,
            stop,
            server: Some(server),
        }
    }

    fn set_requests(&self) -> Vec<String> {
        self.requests
            .lock()
            .expect("requests")
            .iter()
            .filter(|request| request.starts_with("set=1\n"))
            .cloned()
            .collect()
    }
}

impl Drop for FakeUapi {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(server) = self.server.take() {
            let _ = server.join();
        }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn handle(mut stream: UnixStream, get_response: &str, requests: &Mutex<Vec<String>>) {
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("timeout");
    let mut request = String::new();
    let mut buffer = [0u8; 512];
    loop {
        let read = match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(_) => break,
        };
        request.push_str(&String::from_utf8_lossy(&buffer[..read]));
        if request.contains("\n\n") {
            break;
        }
    }
    if request.is_empty() {
        return;
    }
    requests.lock().expect("requests").push(request.clone());
    let response = if request.starts_with("get=1\n") {
        get_response.to_owned()
    } else {
        "errno=0\n\n".to_owned()
    };
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn get_response() -> String {
    format!(
        "listen_port=51820\n\
         public_key={RUNTIME_PEER_HEX}\n\
         endpoint=192.0.2.1:51820\n\
         allowed_ip=10.0.0.0/8\n\
         errno=0\n\n"
    )
}

fn get_response_with_advanced_security(value: &str) -> String {
    format!(
        "listen_port=51820\n\
         public_key={RUNTIME_PEER_HEX}\n\
         advanced_security={value}\n\
         endpoint=192.0.2.1:51820\n\
         allowed_ip=10.0.0.0/8\n\
         errno=0\n\n"
    )
}

fn get_response_with_cipher(value: &str) -> String {
    format!(
        "listen_port=51820\n\
         public_key={RUNTIME_PEER_HEX}\n\
         cipher={value}\n\
         endpoint=192.0.2.1:51820\n\
         allowed_ip=10.0.0.0/8\n\
         errno=0\n\n"
    )
}

fn get_response_with_fec(fec: &str) -> String {
    format!(
        "listen_port=51820\n\
         fec={fec}\n\
         public_key={RUNTIME_PEER_HEX}\n\
         endpoint=192.0.2.1:51820\n\
         allowed_ip=10.0.0.0/8\n\
         errno=0\n\n"
    )
}

fn write_config(directory: &Path, peers: &[(&str, &str)]) -> PathBuf {
    let mut text = format!("[Interface]\nPrivateKey = {PRIVATE}\n");
    for (key, allowed_ips) in peers {
        text.push_str(&format!("\n[Peer]\nPublicKey = {key}\n"));
        if !allowed_ips.is_empty() {
            text.push_str(&format!("AllowedIPs = {allowed_ips}\n"));
        }
    }
    let path = directory.join("uwg0.conf");
    std::fs::write(&path, text).expect("write config");
    path
}

fn run(directory: &Path, arguments: &[&str]) -> Output {
    run_env(directory, arguments, &[])
}

fn run_env(directory: &Path, arguments: &[&str], environment: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_uwg"));
    command
        .env("UWG_RUNTIME_DIR", directory)
        .env_remove("WG_COLOR_MODE")
        .env_remove("UWG_COLOR_MODE")
        .env_remove("WG_HIDE_KEYS")
        .env_remove("UWG_HIDE_KEYS")
        .args(arguments);
    for (key, value) in environment {
        command.env(key, value);
    }
    command.output().expect("run uwg")
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("utf-8 stderr")
}

#[test]
fn version_subcommand_prints_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_uwg"))
        .arg("version")
        .output()
        .expect("run uwg");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout.clone()).expect("utf-8"),
        format!("uwg v{}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(stderr(&output).is_empty());
}

#[test]
fn help_subcommand_prints_usage() {
    let output = Command::new(env!("CARGO_BIN_EXE_uwg"))
        .arg("help")
        .output()
        .expect("run uwg");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf-8");
    assert!(stdout.contains("Usage: uwg"));
    assert!(stdout.contains("addconf"));
    assert!(stdout.contains("syncconf"));
}

#[test]
fn addconf_keeps_peers_and_replaces_allowed_ips() {
    let directory = runtime_dir();
    let fake = FakeUapi::start(&directory, get_response());
    let config = write_config(&directory, &[(PEER_ONE, "10.1.0.0/16")]);

    let output = run(
        &directory,
        &["addconf", "uwg0", config.to_str().expect("path")],
    );
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let requests = fake.set_requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert!(!request.contains("replace_peers=true"));
    assert!(request.contains("replace_allowed_ips=true"));
    assert!(request.contains("allowed_ip=10.1.0.0/16"));
}

#[test]
fn addconf_does_not_touch_keys_absent_from_the_file() {
    let directory = runtime_dir();
    let fake = FakeUapi::start(&directory, get_response());
    let path = directory.join("peers-only.conf");
    std::fs::write(
        &path,
        format!("[Peer]\nPublicKey = {PEER_ONE}\nAllowedIPs = 10.1.0.0/16\n"),
    )
    .expect("write config");

    let output = run(
        &directory,
        &["addconf", "uwg0", path.to_str().expect("path")],
    );
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let requests = fake.set_requests();
    assert_eq!(requests.len(), 1);
    assert!(!requests[0].contains("private_key="));
    assert!(!requests[0].contains("fwmark="));
    assert!(!requests[0].contains("listen_port="));
}

#[test]
fn syncconf_removes_peers_missing_from_the_file() {
    let directory = runtime_dir();
    let fake = FakeUapi::start(&directory, get_response());
    let config = write_config(&directory, &[(PEER_TWO, "10.2.0.0/16")]);

    let output = run(
        &directory,
        &["syncconf", "uwg0", config.to_str().expect("path")],
    );
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let requests = fake.set_requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert!(!request.contains("replace_peers=true"));
    assert!(request.contains("replace_allowed_ips=true"));
    assert!(request.contains(&format!("public_key={RUNTIME_PEER_HEX}\nremove=true")));
    assert!(request.contains(&format!("public_key={PEER_TWO_HEX}\n")));
}

#[test]
fn syncconf_with_an_empty_runtime_replaces_all_peers() {
    let directory = runtime_dir();
    let fake = FakeUapi::start(&directory, "listen_port=51820\nerrno=0\n\n".to_owned());
    let config = write_config(&directory, &[(PEER_TWO, "10.2.0.0/16")]);

    let output = run(
        &directory,
        &["syncconf", "uwg0", config.to_str().expect("path")],
    );
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let requests = fake.set_requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].contains("replace_peers=true"));
}

#[test]
fn config_commands_send_advanced_security_to_userspace() {
    let directory = runtime_dir();
    let path = directory.join("uwg0.conf");
    std::fs::write(
        &path,
        format!(
            "[Interface]\nPrivateKey = {PRIVATE}\n\n[Peer]\nPublicKey = {PEER_ONE}\nAdvancedSecurity = on\nAllowedIPs = 10.1.0.0/16\n"
        ),
    )
    .expect("write config");
    for command in ["setconf", "addconf", "syncconf"] {
        let runtime = directory.join(command);
        std::fs::create_dir_all(&runtime).expect("runtime directory");
        let fake = FakeUapi::start(&runtime, get_response());
        let output = run(&runtime, &[command, "uwg0", path.to_str().expect("path")]);
        assert!(
            output.status.success(),
            "{command} stderr: {}",
            stderr(&output)
        );
        assert!(stderr(&output).is_empty(), "{command}");
        let requests = fake.set_requests();
        assert_eq!(requests.len(), 1, "{command}");
        assert!(requests[0].contains("advanced_security=1\n"), "{command}");
        assert!(requests[0].contains("allowed_ip=10.1.0.0/16"), "{command}");
    }
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn setconf_sends_explicit_advanced_security_off() {
    let directory = runtime_dir();
    let fake = FakeUapi::start(&directory, get_response());
    let path = directory.join("uwg0.conf");
    std::fs::write(
        &path,
        format!(
            "[Interface]\nPrivateKey = {PRIVATE}\n\n[Peer]\nPublicKey = {PEER_ONE}\nAdvancedSecurity = off\nAllowedIPs = 10.1.0.0/16\n"
        ),
    )
    .expect("write config");

    let output = run(
        &directory,
        &["setconf", "uwg0", path.to_str().expect("path")],
    );
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stderr(&output).is_empty());
    let requests = fake.set_requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].contains("advanced_security=0\n"));
}

#[test]
fn setconf_omits_advanced_security_when_unset() {
    let directory = runtime_dir();
    let fake = FakeUapi::start(&directory, get_response());
    let config = write_config(&directory, &[(PEER_ONE, "10.1.0.0/16")]);

    let output = run(
        &directory,
        &["setconf", "uwg0", config.to_str().expect("path")],
    );
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let requests = fake.set_requests();
    assert_eq!(requests.len(), 1);
    assert!(!requests[0].contains("advanced_security"));
}

#[test]
fn set_sends_advanced_security_to_userspace() {
    let directory = runtime_dir();
    let fake = FakeUapi::start(&directory, get_response());
    for (value, expected) in [
        ("on", "advanced_security=1\n"),
        ("off", "advanced_security=0\n"),
    ] {
        let output = run(
            &directory,
            &["set", "uwg0", "peer", PEER_ONE, "advanced-security", value],
        );
        assert!(output.status.success(), "stderr: {}", stderr(&output));
        assert!(stderr(&output).is_empty(), "{value}");
        let requests = fake.set_requests();
        let request = requests.last().expect("request");
        assert!(request.contains(expected), "{value}: {request}");
    }
}

#[test]
fn setconf_warns_about_host_bits() {
    let directory = runtime_dir();
    let fake = FakeUapi::start(&directory, get_response());
    let config = write_config(&directory, &[(PEER_ONE, "10.1.2.3/8")]);

    let output = run(
        &directory,
        &["setconf", "uwg0", config.to_str().expect("path")],
    );
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(
        stderr(&output),
        "Warning: AllowedIP has nonzero host part: 10.1.2.3/8\n"
    );
    assert_eq!(fake.set_requests().len(), 1);
}

#[test]
fn setconf_without_host_bits_stays_silent() {
    let directory = runtime_dir();
    let _fake = FakeUapi::start(&directory, get_response());
    let config = write_config(&directory, &[(PEER_ONE, "10.1.0.0/16")]);

    let output = run(
        &directory,
        &["setconf", "uwg0", config.to_str().expect("path")],
    );
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stderr(&output).is_empty());
}

#[test]
fn show_reports_unsupported_advanced_security_for_uapi() {
    let directory = runtime_dir();
    let _fake = FakeUapi::start(&directory, get_response());

    let output = run(&directory, &["show", "uwg0", "advanced-security"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = String::from_utf8(output.stdout).expect("utf-8");
    assert_eq!(stdout, format!("{RUNTIME_PEER_BASE64}\tunsupported\n"));
}

#[test]
fn show_reports_advanced_security_from_uapi() {
    for (value, expected) in [("1", "yes\n"), ("0", "no\n")] {
        let directory = runtime_dir();
        let _fake = FakeUapi::start(&directory, get_response_with_advanced_security(value));

        let output = run(&directory, &["show", "uwg0", "advanced-security"]);
        assert!(output.status.success(), "stderr: {}", stderr(&output));
        let stdout = String::from_utf8(output.stdout).expect("utf-8");
        assert_eq!(
            stdout,
            format!("{RUNTIME_PEER_BASE64}\t{expected}"),
            "{value}"
        );

        let output = run(&directory, &["show", "uwg0"]);
        assert!(output.status.success(), "stderr: {}", stderr(&output));
        let stdout = String::from_utf8(output.stdout).expect("utf-8");
        assert!(
            stdout.contains(&format!("  advanced security: {}", expected.trim_end())),
            "{value}: {stdout}"
        );
    }
}

#[test]
fn showconf_prints_cipher_from_uapi() {
    let directory = runtime_dir();
    let _fake = FakeUapi::start(&directory, get_response_with_cipher("aes-256-gcm"));

    let output = run(&directory, &["showconf", "uwg0"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = String::from_utf8(output.stdout).expect("utf-8");
    assert!(stdout.contains("Cipher = aes-256-gcm\n"), "{stdout}");
}

#[test]
fn showconf_omits_default_cipher() {
    let directory = runtime_dir();
    let _fake = FakeUapi::start(&directory, get_response_with_cipher("chacha20-poly1305"));

    let output = run(&directory, &["showconf", "uwg0"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = String::from_utf8(output.stdout).expect("utf-8");
    assert!(!stdout.contains("Cipher"), "{stdout}");
}

#[test]
fn showconf_prints_advanced_security_from_uapi() {
    for (value, expected) in [
        ("1", "AdvancedSecurity = on\n"),
        ("0", "AdvancedSecurity = off\n"),
    ] {
        let directory = runtime_dir();
        let _fake = FakeUapi::start(&directory, get_response_with_advanced_security(value));

        let output = run(&directory, &["showconf", "uwg0"]);
        assert!(output.status.success(), "stderr: {}", stderr(&output));
        let stdout = String::from_utf8(output.stdout).expect("utf-8");
        assert!(stdout.contains(expected), "{value}: {stdout}");
    }
}

#[test]
fn show_reports_fec_from_uapi() {
    let directory = runtime_dir();
    let _fake = FakeUapi::start(&directory, get_response_with_fec("8:2"));

    let output = run(&directory, &["show", "uwg0", "fec"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(String::from_utf8(output.stdout).expect("utf-8"), "8:2\n");
}

#[test]
fn show_rejects_removed_bbr_parameters() {
    let directory = runtime_dir();
    let _fake = FakeUapi::start(&directory, get_response_with_fec("8:2"));

    for parameter in ["bbr", "bbr-stats"] {
        let output = run(&directory, &["show", "uwg0", parameter]);
        assert_eq!(output.status.code(), Some(1), "{parameter}");
        let stderr = stderr(&output);
        assert!(
            stderr.contains("BBR удалён в 0.5.0, используйте fec"),
            "{parameter}: {stderr}"
        );
    }
}

#[test]
fn show_reports_missing_fec_as_none() {
    let directory = runtime_dir();
    let _fake = FakeUapi::start(&directory, get_response());

    let output = run(&directory, &["show", "uwg0", "fec"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(String::from_utf8(output.stdout).expect("utf-8"), "(none)\n");
}

#[test]
fn set_sends_fec_to_userspace() {
    let directory = runtime_dir();
    let fake = FakeUapi::start(&directory, get_response());

    let output = run(&directory, &["set", "uwg0", "fec", "8:2"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stderr(&output).is_empty());
    let requests = fake.set_requests();
    let request = requests.last().expect("request");
    assert!(request.contains("fec=8:2\n"), "{request}");
}

#[test]
fn set_rejects_removed_bbr() {
    let directory = runtime_dir();
    let fake = FakeUapi::start(&directory, get_response());

    let output = run(&directory, &["set", "uwg0", "bbr", "on"]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = stderr(&output);
    assert!(
        stderr.contains("BBR удалён в 0.5.0, используйте fec"),
        "{stderr}"
    );
    assert!(fake.set_requests().is_empty());
}

#[test]
fn set_sends_underlay_mtu_to_userspace() {
    let directory = runtime_dir();
    let fake = FakeUapi::start(&directory, get_response());

    let output = run(&directory, &["set", "uwg0", "underlay-mtu", "9000"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let requests = fake.set_requests();
    let request = requests.last().expect("request");
    assert!(request.contains("underlay_mtu=9000\n"), "{request}");

    for value in ["575", "65536", "abc"] {
        let output = run(&directory, &["set", "uwg0", "underlay-mtu", value]);
        assert_eq!(output.status.code(), Some(1), "{value}");
        assert!(!stderr(&output).is_empty(), "{value}");
    }
}

#[test]
fn show_prints_underlay_mtu_from_uapi() {
    let directory = runtime_dir();
    let _fake = FakeUapi::start(
        &directory,
        "private_key=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n\
         listen_port=51820\nunderlay_mtu=1280\nerrno=0\n\n"
            .to_owned(),
    );

    let output = run(&directory, &["show", "uwg0", "underlay-mtu"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(String::from_utf8(output.stdout).expect("utf-8"), "1280\n");

    let output = run(&directory, &["show", "uwg0"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = String::from_utf8(output.stdout).expect("utf-8");
    assert!(stdout.contains("underlay mtu: 1280"), "{stdout}");
}

#[test]
fn show_reports_daemon_fec_stats() {
    let directory = runtime_dir();
    let response = "listen_port=51820\n\
                    fec_stats=1\nfec_blocks_encoded=10\nfec_shards_sent=12\n\
                    fec_blocks_decoded=9\nfec_packets_recovered=1\nfec_decode_fail=2\n\
                    fec_dropped_bounds=3\nfec_dropped_disabled=4\nfec_dropped_control=5\nerrno=0\n\n";
    let _fake = FakeUapi::start(&directory, response.to_owned());

    let output = run(&directory, &["show", "uwg0", "fec-stats"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(
        String::from_utf8(output.stdout).expect("utf-8"),
        "blocks_encoded=10\nshards_sent=12\nblocks_decoded=9\npackets_recovered=1\n\
         decode_fail=2\ndropped_bounds=3\ndropped_disabled=4\ndropped_control=5\n"
    );
}

#[test]
fn legacy_uwg_environment_names_are_honored() {
    let directory = runtime_dir();
    let _fake = FakeUapi::start(&directory, get_response());

    let output = run_env(
        &directory,
        &["show", "uwg0"],
        &[("UWG_COLOR_MODE", "always")],
    );
    let stdout = String::from_utf8(output.stdout.clone()).expect("utf-8");
    assert!(stdout.contains('\u{1b}'), "legacy color mode was ignored");

    let output = run_env(
        &directory,
        &["show", "uwg0"],
        &[("UWG_COLOR_MODE", "always"), ("WG_COLOR_MODE", "never")],
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8");
    assert!(
        !stdout.contains('\u{1b}'),
        "WG_COLOR_MODE must win over the legacy name"
    );

    let directory = runtime_dir();
    let response = "private_key=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n\
                    errno=0\n\n";
    let _fake = FakeUapi::start(&directory, response.to_owned());
    let output = run_env(&directory, &["show", "uwg0"], &[("UWG_HIDE_KEYS", "never")]);
    let stdout = String::from_utf8(output.stdout).expect("utf-8");
    assert!(!stdout.contains("private key: (hidden)"), "{stdout}");

    let output = run_env(
        &directory,
        &["show", "uwg0"],
        &[("UWG_HIDE_KEYS", "never"), ("WG_HIDE_KEYS", "always")],
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8");
    assert!(stdout.contains("private key: (hidden)"), "{stdout}");
}

#[test]
fn show_all_without_interfaces_succeeds_with_empty_output() {
    let directory = runtime_dir();

    let output = run(&directory, &["show", "all"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    assert!(stderr(&output).is_empty(), "{}", stderr(&output));

    let output = run(&directory, &["show", "interfaces"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
}

#[test]
fn show_all_without_runtime_directory_shows_kernel_interfaces() {
    let directory = runtime_dir();
    let missing = directory.join("missing");
    assert!(!missing.exists());

    // A kernel-only host has no userspace runtime directory at all. The
    // command must still succeed and print the kernel interface list
    // (empty on a host without UmbraWG interfaces).
    let output = run(&missing, &["show", "all"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
    assert!(stderr(&output).is_empty(), "{}", stderr(&output));
}

#[test]
fn show_all_with_unreadable_runtime_directory_fails() {
    let directory = runtime_dir();
    // A regular file is not a readable runtime directory; `read_dir` fails
    // with ENOTDIR, which must not be swallowed like NotFound.
    let not_a_directory = directory.join("runtime-file");
    std::fs::write(&not_a_directory, b"not a directory").expect("write");

    let output = run(&not_a_directory, &["show", "all"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("Unable to list interfaces"),
        "{}",
        stderr(&output)
    );
    assert!(output.stdout.is_empty(), "{:?}", output.stdout);
}

#[test]
fn set_rejects_invalid_fec() {
    let directory = runtime_dir();
    let fake = FakeUapi::start(&directory, get_response());

    let output = run(&directory, &["set", "uwg0", "fec", "1:300"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(!stderr(&output).is_empty());
    assert!(fake.set_requests().is_empty());
}

#[test]
fn showconf_prints_fec_from_uapi() {
    let directory = runtime_dir();
    let _fake = FakeUapi::start(&directory, get_response_with_fec("adaptive"));

    let output = run(&directory, &["showconf", "uwg0"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = String::from_utf8(output.stdout).expect("utf-8");
    assert!(stdout.contains("FEC = adaptive\n"), "{stdout}");
    assert!(!stdout.contains("BBR"), "{stdout}");
}

#[test]
fn showconf_omits_unreported_fec() {
    let directory = runtime_dir();
    let _fake = FakeUapi::start(&directory, get_response());

    let output = run(&directory, &["showconf", "uwg0"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = String::from_utf8(output.stdout).expect("utf-8");
    assert!(!stdout.contains("BBR"), "{stdout}");
    assert!(!stdout.contains("FEC"), "{stdout}");
}

#[test]
fn show_rejects_unknown_parameters() {
    let directory = runtime_dir();
    let _fake = FakeUapi::start(&directory, get_response());

    let output = run(&directory, &["show", "uwg0", "bogus-parameter"]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = stderr(&output);
    assert!(stderr.contains("Invalid parameter: `bogus-parameter'"));
    assert!(stderr.contains("Usage: uwg show"));
}

fn run_without_runtime(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_uwg"))
        .env_remove("WG_COLOR_MODE")
        .env_remove("UWG_COLOR_MODE")
        .env_remove("WG_HIDE_KEYS")
        .env_remove("UWG_HIDE_KEYS")
        .args(arguments)
        .output()
        .expect("run uwg")
}

#[test]
fn usage_errors_exit_one_and_print_usage() {
    let cases: &[&[&str]] = &[
        &["bogus"],
        &["--unknown-flag"],
        &["-V"],
        &["--version", "extra"],
        &["-v", "extra"],
        &["--help", "extra"],
        &["-h", "extra"],
        &["show", "interfaces", "extra"],
        &["showconf"],
        &["setconf"],
        &["setconf", "uwg0"],
        &["addconf"],
        &["addconf", "uwg0"],
        &["syncconf"],
        &["syncconf", "uwg0"],
        &["set"],
        &["set", "uwg0"],
        &["genkey", "extra"],
        &["pubkey", "extra"],
        &["version", "extra"],
        &["help", "extra"],
    ];
    for arguments in cases {
        let output = run_without_runtime(arguments);
        let stderr = stderr(&output);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{arguments:?} exited with {:?}: {stderr}",
            output.status.code()
        );
        assert!(
            stderr.contains("Usage:"),
            "{arguments:?} printed no usage: {stderr}"
        );
    }
}

#[test]
fn help_forms_exit_zero_and_print_usage_to_stdout() {
    for arguments in [&["--help"][..], &["-h"][..], &["help"][..]] {
        let output = run_without_runtime(arguments);
        assert!(
            output.status.success(),
            "{arguments:?} failed: {}",
            stderr(&output)
        );
        let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
        assert!(stdout.contains("Usage: uwg"), "{arguments:?}: {stdout}");
        assert!(stdout.contains("addconf"), "{arguments:?}: {stdout}");
    }
}

#[test]
fn version_forms_exit_zero() {
    let expected = format!("uwg v{}\n", env!("CARGO_PKG_VERSION"));
    for arguments in [&["--version"][..], &["-v"][..], &["version"][..]] {
        let output = run_without_runtime(arguments);
        assert!(
            output.status.success(),
            "{arguments:?} failed: {}",
            stderr(&output)
        );
        assert_eq!(
            String::from_utf8(output.stdout).expect("utf-8 stdout"),
            expected,
            "{arguments:?}"
        );
    }
}
