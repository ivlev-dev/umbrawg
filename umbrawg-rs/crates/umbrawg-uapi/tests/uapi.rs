//! End-to-end tests for the UAPI listener, parser and serializer.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use umbrawg_crypto::{Key, PublicKey};
use umbrawg_uapi::{
    format_get_response, AllowedIp, AllowedIpChange, DeviceControl, DeviceSnapshot,
    ObfuscationSnapshot, PeerSnapshot, SetRequest, TimingSnapshot, U16Range, UapiError,
    UapiListener,
};

const SET_REQUEST: &str = "\
set=1
private_key=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
listen_port=51820
fwmark=4660
replace_peers=true
jc=4
jmin=40
jmax=70
s1=92
s2=115
s3=44
s4=9
h1=61220074-118999195
h2=605047389-945520346
h3=1477291385-1814368140
h4=1951993942-1997499713
i1=<b 0x1><c>
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
        let path = std::env::temp_dir().join(format!(
            "umbrawg-uapi-{tag}-{}-{nanos}",
            std::process::id()
        ));
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

#[derive(Clone, Debug)]
struct MockPeer {
    public_key: PublicKey,
    preshared_key: Option<Key>,
    endpoint: Option<SocketAddr>,
    persistent_keepalive: U16Range,
    allowed_ips: Vec<AllowedIp>,
}

impl MockPeer {
    fn new(public_key: PublicKey) -> Self {
        Self {
            public_key,
            preshared_key: None,
            endpoint: None,
            persistent_keepalive: U16Range::default(),
            allowed_ips: Vec::new(),
        }
    }
}

#[derive(Default)]
struct MockState {
    private_key: Option<Key>,
    listen_port: u16,
    fwmark: u32,
    obfuscation: ObfuscationSnapshot,
    timings: TimingSnapshot,
    peers: Vec<MockPeer>,
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
        if let Some(value) = obfuscation.i1 {
            state.obfuscation.i1 = Some(value);
        }
        if let Some(value) = obfuscation.i2 {
            state.obfuscation.i2 = Some(value);
        }
        if let Some(value) = obfuscation.i3 {
            state.obfuscation.i3 = Some(value);
        }
        if let Some(value) = obfuscation.i4 {
            state.obfuscation.i4 = Some(value);
        }
        if let Some(value) = obfuscation.i5 {
            state.obfuscation.i5 = Some(value);
        }
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
    let handle = UapiListener::bind(directory.path(), "uwg0")
        .expect("bind")
        .spawn(Arc::clone(&control))
        .expect("spawn");
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
        "jc=4\n",
        "jmin=40\n",
        "jmax=70\n",
        "s1=92\n",
        "s2=115\n",
        "s3=44\n",
        "s4=9\n",
        "h1=61220074-118999195\n",
        "h2=605047389-945520346\n",
        "h3=1477291385-1814368140\n",
        "h4=1951993942-1997499713\n",
        "i1=<b 0x1><c>\n",
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
        response,
        format_get_response(&control.snapshot()),
        "wire format must match the serializer"
    );

    drop(reader);
    drop(stream);
    handle.join().expect("listener thread");
    assert!(!socket_path.exists(), "socket must be removed on shutdown");
}

#[test]
fn reports_protocol_errors_over_the_socket() {
    let directory = TempDir::new("errors");
    let control = MockControl::new();
    let handle = UapiListener::bind(directory.path(), "uwg0")
        .expect("bind")
        .spawn(control)
        .expect("spawn");
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

    stream.write_all(b"get=1\n\nextra\n").expect("bad get");
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

    let thread = std::thread::spawn(move || {
        listener.run_with_authorizer(control.as_ref(), |_| false)
    });

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
    let handle = UapiListener::bind(directory.path(), "uwg0")
        .expect("bind")
        .spawn(control)
        .expect("spawn");
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
