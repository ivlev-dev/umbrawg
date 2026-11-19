#![cfg(unix)]

//! End-to-end tests for the UAPI listener, parser and serializer.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use umbrawg_crypto::{Key, PublicKey};
use umbrawg_uapi::{
    format_get_response, AllowedIp, AllowedIpChange, Cipher, DeviceControl, DeviceSnapshot,
    ObfuscationSnapshot, PeerSnapshot, ServerHandle, SetRequest, SpecialPacketUpdate,
    TimingSnapshot, U16Range, UapiError, UapiListener,
};

const SET_REQUEST: &str = "\
set=1
private_key=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
listen_port=51820
fwmark=4660
extra_ports=6
replace_peers=true
jc=4
jmin=40
jmax=70
s1=92
s2=115
s3=44
s4=16
h1=61220074-118999195
h2=605047389-945520346
h3=1477291385-1814368140
h4=1951993942-1997499713
i1=<b 0x01><c>
i2=<r 8>
i3=<rc 4>
i4=<rd 3>
i5=<t>
header_protection_key=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
content_padding_addition=0-100
rekey_after_time=120-180
rekey_timeout=5
reject_after_time=180
keepalive_timeout=10
max_handshake_attempts=7
random_trailers=1
disable_cookies=0
public_key=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
preshared_key=606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f
endpoint=[fd00::1]:51820
persistent_keepalive_interval=25
protocol_version=1
replace_allowed_ips=true
allowed_ip=10.0.0.0/8
allowed_ip=fd00::/64

";

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("umbrawg-uapi-{tag}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path).expect("temp directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn spawn_as_current_user<C>(listener: UapiListener, control: Arc<C>) -> ServerHandle
where
    C: DeviceControl + Send + Sync + 'static,
{
    // SAFETY: `geteuid` has no memory-safety preconditions.
    let uid = unsafe { libc::geteuid() };
    listener
        .spawn_with_authorizer(control, move |peer| peer == uid)
        .expect("spawn")
}

#[derive(Clone, Debug)]
struct MockPeer {
    public_key: PublicKey,
    preshared_key: Option<Key>,
    endpoint: Option<SocketAddr>,
    persistent_keepalive: U16Range,
    advanced_security: Option<bool>,
    cipher: Cipher,
    allowed_ips: Vec<AllowedIp>,
}

impl MockPeer {
    fn new(public_key: PublicKey) -> Self {
        Self {
            public_key,
            preshared_key: None,
            endpoint: None,
            persistent_keepalive: U16Range::default(),
            advanced_security: None,
            cipher: Cipher::ChaCha20Poly1305,
            allowed_ips: Vec::new(),
        }
    }
}

struct MockState {
    private_key: Option<Key>,
    listen_port: u16,
    fwmark: u32,
    extra_ports: u8,
    obfuscation: ObfuscationSnapshot,
    timings: TimingSnapshot,
    peers: Vec<MockPeer>,
}

impl Default for MockState {
    fn default() -> Self {
        Self {
            private_key: None,
            listen_port: 0,
            fwmark: 0,
            extra_ports: 4,
            obfuscation: ObfuscationSnapshot::default(),
            timings: TimingSnapshot::default(),
            peers: Vec::new(),
        }
    }
}

struct MockControl {
    state: Mutex<MockState>,
}

impl MockControl {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(MockState::default()),
        })
    }
}

impl DeviceControl for MockControl {
    fn snapshot(&self) -> DeviceSnapshot {
        let state = self.state.lock().expect("state");
        DeviceSnapshot {
            private_key: state.private_key.clone(),
            listen_port: state.listen_port,
            fwmark: state.fwmark,
            extra_ports: state.extra_ports,
            bbr: "off".to_owned(),
            fec: "off".to_owned(),
            obfuscation: state.obfuscation.clone(),
            timings: state.timings,
            peers: state
                .peers
                .iter()
                .map(|peer| PeerSnapshot {
                    public_key: peer.public_key,
                    preshared_key: peer.preshared_key.clone(),
                    endpoint: peer.endpoint,
                    last_handshake_time_sec: 0,
                    last_handshake_time_nsec: 0,
                    tx_bytes: 0,
                    rx_bytes: 0,
                    persistent_keepalive_interval: peer.persistent_keepalive,
                    advanced_security: peer.advanced_security,
                    cipher: peer.cipher,
                    allowed_ips: peer.allowed_ips.clone(),
                })
                .collect(),
        }
    }

    fn apply(&self, request: SetRequest) -> Result<(), UapiError> {
        let mut state = self.state.lock().expect("state");

        if let Some(key) = request.private_key {
            state.private_key = (!key.is_zero()).then_some(key);
        }
        if let Some(port) = request.listen_port {
            state.listen_port = port;
        }
        if let Some(mark) = request.fwmark {
            state.fwmark = mark;
        }
        if let Some(extra_ports) = request.extra_ports {
            state.extra_ports = extra_ports;
        }
        if request.replace_peers {
            state.peers.clear();
        }

        let obfuscation = request.obfuscation;
        if let Some(value) = obfuscation.jc {
            state.obfuscation.jc = value;
        }
        if let Some(value) = obfuscation.jmin {
            state.obfuscation.jmin = value;
        }
        if let Some(value) = obfuscation.jmax {
            state.obfuscation.jmax = value;
        }
        if let Some(value) = obfuscation.s1 {
            state.obfuscation.s1 = value;
        }
        if let Some(value) = obfuscation.s2 {
            state.obfuscation.s2 = value;
        }
        if let Some(value) = obfuscation.s3 {
            state.obfuscation.s3 = value;
        }
        if let Some(value) = obfuscation.s4 {
            state.obfuscation.s4 = value;
        }
        if let Some(value) = obfuscation.h1 {
            state.obfuscation.h1 = value;
        }
        if let Some(value) = obfuscation.h2 {
            state.obfuscation.h2 = value;
        }
        if let Some(value) = obfuscation.h3 {
            state.obfuscation.h3 = value;
        }
        if let Some(value) = obfuscation.h4 {
            state.obfuscation.h4 = value;
        }
        apply_special_packet(&mut state.obfuscation.i1, obfuscation.i1);
        apply_special_packet(&mut state.obfuscation.i2, obfuscation.i2);
        apply_special_packet(&mut state.obfuscation.i3, obfuscation.i3);
        apply_special_packet(&mut state.obfuscation.i4, obfuscation.i4);
        apply_special_packet(&mut state.obfuscation.i5, obfuscation.i5);
        if let Some(key) = obfuscation.header_protection_key {
            state.obfuscation.header_protection_key = (!key.is_zero()).then_some(key);
        }
        if let Some(value) = obfuscation.content_padding_addition {
            state.obfuscation.content_padding_addition = value;
        }
        if let Some(value) = obfuscation.random_trailers {
            state.obfuscation.random_trailers = value;
        }
        if let Some(value) = obfuscation.disable_cookies {
            state.obfuscation.disable_cookies = value;
        }

        let timings = request.timings;
        if let Some(value) = timings.rekey_after_time {
            state.timings.rekey_after_time = value;
        }
        if let Some(value) = timings.rekey_timeout {
            state.timings.rekey_timeout = value;
        }
        if let Some(value) = timings.reject_after_time {
            state.timings.reject_after_time = value;
        }
        if let Some(value) = timings.keepalive_timeout {
            state.timings.keepalive_timeout = value;
        }
        if let Some(value) = timings.max_handshake_attempts {
            state.timings.max_handshake_attempts = value;
        }

        for peer in request.peers {
            if peer.remove {
                state
                    .peers
                    .retain(|existing| existing.public_key != peer.public_key);
                continue;
            }
            let position = state
                .peers
                .iter()
                .position(|existing| existing.public_key == peer.public_key);
            if position.is_none() && peer.update_only {
                continue;
            }
            let slot = match position {
                Some(index) => &mut state.peers[index],
                None => {
                    state.peers.push(MockPeer::new(peer.public_key));
                    state.peers.last_mut().expect("peer was just pushed")
                }
            };
            if let Some(key) = peer.preshared_key {
                slot.preshared_key = (!key.is_zero()).then_some(key);
            }
            if let Some(endpoint) = peer.endpoint {
                slot.endpoint = Some(endpoint);
            }
            if let Some(interval) = peer.persistent_keepalive_interval {
                slot.persistent_keepalive = interval;
            }
            if let Some(value) = peer.advanced_security {
                slot.advanced_security = Some(value);
            }
            if let Some(cipher) = peer.cipher {
                slot.cipher = cipher;
            }
            if peer.replace_allowed_ips {
                slot.allowed_ips.clear();
            }
            for change in peer.allowed_ips {
                match change {
                    AllowedIpChange::Add(prefix) => {
                        if !slot.allowed_ips.contains(&prefix) {
                            slot.allowed_ips.push(prefix);
                        }
                    }
                    AllowedIpChange::Remove(prefix) => {
                        slot.allowed_ips.retain(|existing| *existing != prefix);
                    }
                }
            }
        }

        Ok(())
    }
}

fn apply_special_packet(slot: &mut Option<String>, update: SpecialPacketUpdate) {
    match update {
        SpecialPacketUpdate::Keep => {}
        SpecialPacketUpdate::Clear => *slot = None,
        SpecialPacketUpdate::Set(value) => *slot = Some(value),
    }
}

fn read_response(reader: &mut impl BufRead) -> String {
    let mut response = String::new();
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line).expect("read response");
        if read == 0 || line == "\n" {
            break;
        }
        response.push_str(&line);
    }
    response
}

#[test]
fn creates_private_socket_and_directory() {
    let directory = TempDir::new("permissions");
    let socket_directory = directory.path().join("runtime");
    let listener = UapiListener::bind(&socket_directory, "uwg0").expect("bind");
    let socket_path = listener.path().to_path_buf();

    let directory_mode = fs::metadata(&socket_directory)
        .expect("directory metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(directory_mode, 0o700);

    let socket_mode = fs::metadata(&socket_path)
        .expect("socket metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(socket_mode, 0o600);

    drop(listener);
    assert!(!socket_path.exists(), "socket must be removed on drop");
}

#[test]
fn removes_stale_socket() {
    let directory = TempDir::new("stale");
    let stale_path = directory.path().join("uwg0.sock");
    let stale = UnixListener::bind(&stale_path).expect("stale socket");
    drop(stale);
    assert!(stale_path.exists(), "stale socket file must survive bind");

    let listener = UapiListener::bind(directory.path(), "uwg0").expect("rebind");
    assert_eq!(listener.path(), stale_path);
}

#[test]
fn refuses_second_listener() {
    let directory = TempDir::new("in-use");
    let first = UapiListener::bind(directory.path(), "uwg0").expect("first bind");
    let error = UapiListener::bind(directory.path(), "uwg0").expect_err("second bind");
    assert!(matches!(error, UapiError::AddressInUse));
    drop(first);
}

#[test]
fn rejects_invalid_interface_names() {
    let directory = TempDir::new("names");
    assert!(UapiListener::bind(directory.path(), "").is_err());
    assert!(UapiListener::bind(directory.path(), "bad/name").is_err());
    let long_name = "x".repeat(libc::IFNAMSIZ);
    assert!(UapiListener::bind(directory.path(), &long_name).is_err());
}

#[test]
fn missing_socket_is_not_connectable() {
    let directory = TempDir::new("missing");
    let path = directory.path().join("uwg0.sock");
    assert!(UnixStream::connect(&path).is_err());
}

#[test]
fn round_trips_every_31_field() {
    let directory = TempDir::new("round-trip");
    let control = MockControl::new();
    let handle = spawn_as_current_user(
        UapiListener::bind(directory.path(), "uwg0").expect("bind"),
        Arc::clone(&control),
    );
    let socket_path = directory.path().join("uwg0.sock");

    let mut stream = UnixStream::connect(&socket_path).expect("connect");
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));

    stream.write_all(SET_REQUEST.as_bytes()).expect("set");
    let response = read_response(&mut reader);
    assert_eq!(response, "errno=0\n", "set must succeed: {response}");

    stream.write_all(b"get=1\n\n").expect("get");
    let response = read_response(&mut reader);
    let expected = [
        "private_key=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n",
        "listen_port=51820\n",
        "fwmark=4660\n",
        "extra_ports=6\n",
        "jc=4\n",
        "jmin=40\n",
        "jmax=70\n",
        "s1=92\n",
        "s2=115\n",
        "s3=44\n",
        "s4=16\n",
        "h1=61220074-118999195\n",
        "h2=605047389-945520346\n",
        "h3=1477291385-1814368140\n",
        "h4=1951993942-1997499713\n",
        "i1=<b 0x01><c>\n",
        "i2=<r 8>\n",
        "i3=<rc 4>\n",
        "i4=<rd 3>\n",
        "i5=<t>\n",
        "header_protection_key=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\n",
        "content_padding_addition=0-100\n",
        "rekey_after_time=120-180\n",
        "rekey_timeout=5\n",
        "reject_after_time=180\n",
        "keepalive_timeout=10\n",
        "max_handshake_attempts=7\n",
        "random_trailers=1\n",
        "disable_cookies=0\n",
        "public_key=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f\n",
        "preshared_key=606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\n",
        "protocol_version=1\n",
        "endpoint=[fd00::1]:51820\n",
        "last_handshake_time_sec=0\n",
        "last_handshake_time_nsec=0\n",
        "tx_bytes=0\n",
        "rx_bytes=0\n",
        "persistent_keepalive_interval=25\n",
        "allowed_ip=10.0.0.0/8\n",
        "allowed_ip=fd00::/64\n",
        "errno=0\n",
    ];
    for line in expected {
        assert!(response.contains(line), "missing `{line}` in:\n{response}");
    }
    assert_eq!(
        format!("{response}\n"),
        format_get_response(&control.snapshot()),
        "wire format must match the serializer"
    );

    drop(reader);
    drop(stream);
    handle.join().expect("listener thread");
    assert!(!socket_path.exists(), "socket must be removed on shutdown");
}

#[test]
fn round_trips_cipher_over_the_socket() {
    let directory = TempDir::new("cipher");
    let control = MockControl::new();
    let handle = spawn_as_current_user(
        UapiListener::bind(directory.path(), "uwg0").expect("bind"),
        control,
    );
    let socket_path = directory.path().join("uwg0.sock");

    let mut stream = UnixStream::connect(&socket_path).expect("connect");
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));

    stream
        .write_all(
            b"set=1\npublic_key=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\ncipher=aes-256-gcm\n\n",
        )
        .expect("set");
    assert_eq!(read_response(&mut reader), "errno=0\n");

    stream.write_all(b"get=1\n\n").expect("get");
    let response = read_response(&mut reader);
    assert!(response.contains("cipher=aes-256-gcm\n"), "{response}");

    stream
        .write_all(
            b"set=1\npublic_key=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\ncipher=chacha20-poly1305\n\n",
        )
        .expect("set");
    assert_eq!(read_response(&mut reader), "errno=0\n");

    stream.write_all(b"get=1\n\n").expect("get");
    let response = read_response(&mut reader);
    assert!(!response.contains("cipher="), "{response}");

    stream
        .write_all(
            b"set=1\npublic_key=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n\n",
        )
        .expect("set");
    assert_eq!(read_response(&mut reader), "errno=0\n");

    stream.write_all(b"get=1\n\n").expect("get");
    let response = read_response(&mut reader);
    assert!(!response.contains("cipher="), "{response}");

    drop(reader);
    drop(stream);
    handle.join().expect("listener thread");
}

#[test]
fn round_trips_advanced_security_over_the_socket() {
    let directory = TempDir::new("advanced-security");
    let control = MockControl::new();
    let handle = spawn_as_current_user(
        UapiListener::bind(directory.path(), "uwg0").expect("bind"),
        control,
    );
    let socket_path = directory.path().join("uwg0.sock");

    let mut stream = UnixStream::connect(&socket_path).expect("connect");
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));

    stream
        .write_all(
            b"set=1\npublic_key=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nadvanced_security=on\n\n",
        )
        .expect("set");
    assert_eq!(read_response(&mut reader), "errno=0\n");

    stream.write_all(b"get=1\n\n").expect("get");
    let response = read_response(&mut reader);
    assert!(response.contains("advanced_security=1\n"), "{response}");

    stream
        .write_all(
            b"set=1\npublic_key=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nadvanced_security=off\n\n",
        )
        .expect("set");
    assert_eq!(read_response(&mut reader), "errno=0\n");

    stream.write_all(b"get=1\n\n").expect("get");
    let response = read_response(&mut reader);
    assert!(response.contains("advanced_security=0\n"), "{response}");

    stream
        .write_all(
            b"set=1\npublic_key=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n\n",
        )
        .expect("set");
    assert_eq!(read_response(&mut reader), "errno=0\n");

    stream.write_all(b"get=1\n\n").expect("get");
    let response = read_response(&mut reader);
    assert_eq!(
        response.matches("advanced_security=").count(),
        1,
        "{response}"
    );

    drop(reader);
    drop(stream);
    handle.join().expect("listener thread");
}

#[test]
fn reports_protocol_errors_over_the_socket() {
    let directory = TempDir::new("errors");
    let control = MockControl::new();
    let handle = spawn_as_current_user(
        UapiListener::bind(directory.path(), "uwg0").expect("bind"),
        control,
    );
    let socket_path = directory.path().join("uwg0.sock");

    let mut stream = UnixStream::connect(&socket_path).expect("connect");
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));

    stream
        .write_all(b"set=1\nbogus=1\n\n")
        .expect("unknown key");
    assert_eq!(read_response(&mut reader), "errno=-22\n");

    stream
        .write_all(b"set=1\nbroken\n\n")
        .expect("malformed line");
    assert_eq!(read_response(&mut reader), "errno=-71\n");

    stream.write_all(b"get=1\nextra\n").expect("bad get");
    let response = read_response(&mut reader);
    assert_eq!(response, "errno=-71\n");

    drop(reader);
    drop(stream);
    handle.join().expect("listener thread");
}

#[test]
fn rejects_unauthorized_peer() {
    let directory = TempDir::new("auth");
    let control = MockControl::new();
    let listener = UapiListener::bind(directory.path(), "uwg0").expect("bind");
    let socket_path = listener.path().to_path_buf();
    let handle = listener.handle().expect("handle");

    let thread =
        std::thread::spawn(move || listener.run_with_authorizer(control.as_ref(), |_| false));

    let mut stream = UnixStream::connect(&socket_path).expect("connect");
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    stream.write_all(b"get=1\n\n").expect("get");
    assert_eq!(read_response(&mut reader), "errno=-13\n");

    drop(reader);
    drop(stream);
    handle.shutdown().expect("shutdown");
    thread.join().expect("listener thread").expect("listener");
}

#[test]
fn closes_on_unknown_operation() {
    let directory = TempDir::new("unknown-op");
    let control = MockControl::new();
    let handle = spawn_as_current_user(
        UapiListener::bind(directory.path(), "uwg0").expect("bind"),
        control,
    );
    let socket_path = directory.path().join("uwg0.sock");

    let mut stream = UnixStream::connect(&socket_path).expect("connect");
    stream.write_all(b"bogus\n").expect("write");
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    assert_eq!(reader.read_line(&mut line).expect("read"), 0);
    assert!(line.is_empty());

    drop(reader);
    handle.join().expect("listener thread");
}

#[test]
fn round_trips_boundary_values() {
    let request = "\
set=1
private_key=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
listen_port=65535
fwmark=4294967295
extra_ports=8
replace_peers=true
jc=65535
jmin=65535
jmax=65535
s1=65535
s2=65535
s3=65535
s4=65535
h1=0-1000000
h2=1000001-2000000
h3=2000001-3000000
h4=3000001-4294967295
i1=<b 0x00ff>
i2=<r 1>
i3=<rc 2>
i4=<rd 3>
i5=<t>
header_protection_key=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
content_padding_addition=0-65535
rekey_after_time=0-65535
rekey_timeout=0-65535
reject_after_time=0-65535
keepalive_timeout=0-65535
max_handshake_attempts=0-65535
random_trailers=1
disable_cookies=1
public_key=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
preshared_key=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
endpoint=[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535
persistent_keepalive_interval=0-65535
protocol_version=1
replace_allowed_ips=true
allowed_ip=0.0.0.0/0
allowed_ip=::/0

";
    let expected = [
        "private_key=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n",
        "listen_port=65535\n",
        "fwmark=4294967295\n",
        "extra_ports=8\n",
        "bbr=off\n",
        "fec=off\n",
        "jc=65535\n",
        "jmin=65535\n",
        "jmax=65535\n",
        "s1=65535\n",
        "s2=65535\n",
        "s3=65535\n",
        "s4=65535\n",
        "h1=0-1000000\n",
        "h2=1000001-2000000\n",
        "h3=2000001-3000000\n",
        "h4=3000001-4294967295\n",
        "i1=<b 0x00ff>\n",
        "i2=<r 1>\n",
        "i3=<rc 2>\n",
        "i4=<rd 3>\n",
        "i5=<t>\n",
        "header_protection_key=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n",
        "content_padding_addition=0-65535\n",
        "rekey_after_time=0-65535\n",
        "rekey_timeout=0-65535\n",
        "reject_after_time=0-65535\n",
        "keepalive_timeout=0-65535\n",
        "max_handshake_attempts=0-65535\n",
        "random_trailers=1\n",
        "disable_cookies=1\n",
        "public_key=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        "preshared_key=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
        "protocol_version=1\n",
        "endpoint=[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535\n",
        "last_handshake_time_sec=0\n",
        "last_handshake_time_nsec=0\n",
        "tx_bytes=0\n",
        "rx_bytes=0\n",
        "persistent_keepalive_interval=0-65535\n",
        "allowed_ip=0.0.0.0/0\n",
        "allowed_ip=::/0\n",
        "errno=0\n",
    ]
    .concat();

    let directory = TempDir::new("boundary");
    let control = MockControl::new();
    let handle = spawn_as_current_user(
        UapiListener::bind(directory.path(), "uwg0").expect("bind"),
        control,
    );
    let socket_path = directory.path().join("uwg0.sock");

    let mut stream = UnixStream::connect(&socket_path).expect("connect");
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    stream.write_all(request.as_bytes()).expect("set");
    assert_eq!(read_response(&mut reader), "errno=0\n");

    stream.write_all(b"get=1\n\n").expect("get");
    assert_eq!(read_response(&mut reader), expected);

    drop(reader);
    drop(stream);
    handle.join().expect("listener thread");
}

#[test]
fn clears_optional_fields() {
    let directory = TempDir::new("clear");
    let control = MockControl::new();
    let handle = spawn_as_current_user(
        UapiListener::bind(directory.path(), "uwg0").expect("bind"),
        control,
    );
    let socket_path = directory.path().join("uwg0.sock");

    let mut stream = UnixStream::connect(&socket_path).expect("connect");
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    stream.write_all(SET_REQUEST.as_bytes()).expect("set");
    assert_eq!(read_response(&mut reader), "errno=0\n");

    stream
        .write_all(
            b"set=1\nprivate_key=0000000000000000000000000000000000000000000000000000000000000000\ni1=\nheader_protection_key=0000000000000000000000000000000000000000000000000000000000000000\npublic_key=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f\npreshared_key=0000000000000000000000000000000000000000000000000000000000000000\npersistent_keepalive_interval=0\n\n",
        )
        .expect("clear");
    assert_eq!(read_response(&mut reader), "errno=0\n");

    stream.write_all(b"get=1\n\n").expect("get");
    let response = read_response(&mut reader);
    assert!(!response.contains("private_key="), "{response}");
    assert!(!response.contains("i1="), "{response}");
    assert!(!response.contains("header_protection_key="), "{response}");
    assert!(
        !response.contains("persistent_keepalive_interval="),
        "{response}"
    );
    assert!(response.contains("i2=<r 8>\n"), "{response}");
    assert!(
        response.contains(&format!("preshared_key={}\n", "00".repeat(32))),
        "{response}"
    );

    drop(reader);
    drop(stream);
    handle.join().expect("listener thread");
}

#[test]
fn rejects_invalid_merged_obfuscation() {
    let directory = TempDir::new("semantic");
    let control = MockControl::new();
    let handle = spawn_as_current_user(
        UapiListener::bind(directory.path(), "uwg0").expect("bind"),
        control,
    );
    let socket_path = directory.path().join("uwg0.sock");

    let mut stream = UnixStream::connect(&socket_path).expect("connect");
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));

    stream.write_all(b"set=1\nh1=1-2\n\n").expect("overlap");
    assert_eq!(read_response(&mut reader), "errno=-22\n");
    stream.write_all(b"get=1\n\n").expect("get");
    let response = read_response(&mut reader);
    assert!(response.contains("h1=1\n"), "{response}");
    assert!(!response.contains("h1=1-2\n"), "{response}");

    let key = "cc".repeat(32);
    let small = format!("set=1\nheader_protection_key={key}\ns1=12\ns2=12\ns3=12\ns4=11\n\n");
    stream.write_all(small.as_bytes()).expect("small padding");
    assert_eq!(read_response(&mut reader), "errno=-22\n");

    let valid = format!("set=1\nheader_protection_key={key}\ns1=12\ns2=12\ns3=12\ns4=12\n\n");
    stream.write_all(valid.as_bytes()).expect("valid padding");
    assert_eq!(read_response(&mut reader), "errno=0\n");

    stream.write_all(b"get=1\n\n").expect("get");
    let response = read_response(&mut reader);
    assert!(
        response.contains(&format!("header_protection_key={key}\n")),
        "{response}"
    );
    assert!(response.contains("s4=12\n"), "{response}");

    drop(reader);
    drop(stream);
    handle.join().expect("listener thread");
}

#[test]
fn shutdown_closes_idle_connection() {
    let directory = TempDir::new("shutdown");
    let control = MockControl::new();
    let handle = spawn_as_current_user(
        UapiListener::bind(directory.path(), "uwg0").expect("bind"),
        control,
    );
    let socket_path = directory.path().join("uwg0.sock");

    let mut stream = UnixStream::connect(&socket_path).expect("connect");
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    stream.write_all(b"get=1\n\n").expect("get");
    let _ = read_response(&mut reader);

    let (finished, wait) = mpsc::channel();
    let joiner = std::thread::spawn(move || {
        let _ = handle.join();
        let _ = finished.send(());
    });
    wait.recv_timeout(Duration::from_secs(5))
        .expect("listener must stop with an idle client");
    joiner.join().expect("joiner thread");

    drop(reader);
    drop(stream);
    assert!(!socket_path.exists(), "socket must be removed on shutdown");
}

#[test]
fn shutdown_after_listener_exit_is_ok() {
    let directory = TempDir::new("shutdown-again");
    let control = MockControl::new();
    let handle = spawn_as_current_user(
        UapiListener::bind(directory.path(), "uwg0").expect("bind"),
        control,
    );

    handle.shutdown().expect("first shutdown");
    std::thread::sleep(Duration::from_millis(200));
    handle.shutdown().expect("shutdown after listener exit");
}

#[test]
fn refuses_non_socket_path() {
    let directory = TempDir::new("non-socket");
    let socket_path = directory.path().join("uwg0.sock");
    fs::write(&socket_path, b"not a socket").expect("write");
    let error = UapiListener::bind(directory.path(), "uwg0").expect_err("must reject");
    assert!(matches!(error, UapiError::Protocol(_)));
    assert!(socket_path.exists(), "foreign file must not be removed");
}
