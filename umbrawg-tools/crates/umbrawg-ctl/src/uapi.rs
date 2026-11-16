use std::fmt::Write as _;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use umbrawg_config::{format_endpoint, parse_endpoint, AllowedIp, Key, U16Range, U32Range};

use crate::error::Error;
use crate::model::{Device, Peer, SetDevice};

pub const DEFAULT_SOCKET_DIR: &str = "/var/run/umbrawg";
pub const SOCKET_SUFFIX: &str = ".sock";

pub fn socket_dir() -> PathBuf {
    std::env::var_os("UWG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET_DIR))
}

pub fn validate_interface_name(name: &str) -> Result<(), Error> {
    if name.is_empty() || name.len() >= libc::IFNAMSIZ || name.contains('/') || name.contains('\0')
    {
        return Err(Error::InvalidInterfaceName(name.to_owned()));
    }
    Ok(())
}

pub fn socket_path_in(directory: &Path, iface: &str) -> Result<PathBuf, Error> {
    validate_interface_name(iface)?;
    Ok(directory.join(format!("{iface}{SOCKET_SUFFIX}")))
}

pub fn socket_path(iface: &str) -> Result<PathBuf, Error> {
    socket_path_in(&socket_dir(), iface)
}

pub async fn has_interface_in(directory: &Path, iface: &str) -> bool {
    let Ok(path) = socket_path_in(directory, iface) else {
        return false;
    };
    is_socket(&path) && connect(&path).await.is_ok()
}

pub async fn has_interface(iface: &str) -> bool {
    has_interface_in(&socket_dir(), iface).await
}

pub async fn list_interfaces_in(directory: &Path) -> Result<Vec<String>, Error> {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(Error::Io(error)),
    };
    let mut interfaces = Vec::new();
    for entry in entries {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if !file_type.is_socket() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        let Some(iface) = name.strip_suffix(SOCKET_SUFFIX) else {
            continue;
        };
        if iface.is_empty() || validate_interface_name(iface).is_err() {
            continue;
        }
        if has_interface_in(directory, iface).await {
            interfaces.push(iface.to_owned());
        }
    }
    interfaces.sort();
    interfaces.dedup();
    Ok(interfaces)
}

pub async fn list_interfaces() -> Result<Vec<String>, Error> {
    list_interfaces_in(&socket_dir()).await
}

pub async fn get_device(iface: &str) -> Result<Device, Error> {
    let path = socket_path(iface)?;
    get_device_at(&path, iface).await
}

pub async fn get_device_at(path: &Path, iface: &str) -> Result<Device, Error> {
    validate_interface_name(iface)?;
    let response = exchange(path, "get=1\n\n").await?;
    parse_get_response(&response, iface)
}

pub async fn set_device(config: &SetDevice) -> Result<(), Error> {
    let path = socket_path(&config.name)?;
    set_device_at(&path, config).await
}

pub async fn set_device_at(path: &Path, config: &SetDevice) -> Result<(), Error> {
    validate_interface_name(&config.name)?;
    let request = build_set_request(config)?;
    let response = exchange(path, &request).await?;
    parse_set_response(&response)
}

pub fn build_set_request(config: &SetDevice) -> Result<String, Error> {
    let mut output = String::new();
    output.push_str("set=1\n");
    let device = &config.device;
    if let Some(key) = &device.private_key {
        write_line(&mut output, "private_key", &key.to_hex())?;
    }
    if let Some(port) = device.listen_port {
        write_line(&mut output, "listen_port", &port.to_string())?;
    }
    if let Some(fwmark) = device.fwmark {
        write_line(&mut output, "fwmark", &fwmark.to_string())?;
    }
    if config.replace_peers {
        write_line(&mut output, "replace_peers", "true")?;
    }
    let obfuscation = &device.obfuscation;
    for (key, value) in [
        ("jc", obfuscation.jc),
        ("jmin", obfuscation.jmin),
        ("jmax", obfuscation.jmax),
        ("s1", obfuscation.s1),
        ("s2", obfuscation.s2),
        ("s3", obfuscation.s3),
        ("s4", obfuscation.s4),
    ] {
        if let Some(value) = value {
            write_line(&mut output, key, &value.to_string())?;
        }
    }
    for (key, value) in [
        ("h1", obfuscation.h1),
        ("h2", obfuscation.h2),
        ("h3", obfuscation.h3),
        ("h4", obfuscation.h4),
    ] {
        if let Some(value) = value {
            write_line(&mut output, key, &value.to_string())?;
        }
    }
    for (key, value) in [
        ("i1", &obfuscation.i1),
        ("i2", &obfuscation.i2),
        ("i3", &obfuscation.i3),
        ("i4", &obfuscation.i4),
        ("i5", &obfuscation.i5),
    ] {
        if let Some(value) = value {
            write_line(&mut output, key, value)?;
        }
    }
    if let Some(key) = &obfuscation.header_protection_key {
        write_line(&mut output, "header_protection_key", &key.to_hex())?;
    }
    for (key, value) in [
        (
            "content_padding_addition",
            obfuscation.content_padding_addition,
        ),
        ("rekey_after_time", obfuscation.rekey_after_time),
        ("rekey_timeout", obfuscation.rekey_timeout),
        ("reject_after_time", obfuscation.reject_after_time),
        ("keepalive_timeout", obfuscation.keepalive_timeout),
        ("max_handshake_attempts", obfuscation.max_handshake_attempts),
    ] {
        if let Some(value) = value {
            write_line(&mut output, key, &value.to_string())?;
        }
    }
    if let Some(value) = obfuscation.random_trailers {
        write_line(&mut output, "random_trailers", bool_number(value))?;
    }
    if let Some(value) = obfuscation.disable_cookies {
        write_line(&mut output, "disable_cookies", bool_number(value))?;
    }
    for peer in &config.peers {
        write_line(&mut output, "public_key", &peer.public_key.to_hex())?;
        if peer.remove {
            write_line(&mut output, "remove", "true")?;
            continue;
        }
        if let Some(key) = &peer.preshared_key {
            write_line(&mut output, "preshared_key", &key.to_hex())?;
        }
        if let Some(endpoint) = &peer.endpoint {
            write_line(&mut output, "endpoint", &format_endpoint(endpoint))?;
        }
        if let Some(keepalive) = peer.persistent_keepalive {
            write_line(
                &mut output,
                "persistent_keepalive_interval",
                &keepalive.to_string(),
            )?;
        }
        if let Some(allowed_ips) = &peer.allowed_ips {
            write_line(&mut output, "replace_allowed_ips", "true")?;
            for allowed_ip in allowed_ips {
                write_line(&mut output, "allowed_ip", &allowed_ip.to_string())?;
            }
        }
    }
    output.push('\n');
    Ok(output)
}

pub fn parse_get_response(response: &str, iface: &str) -> Result<Device, Error> {
    let mut device = Device::new(iface);
    let mut current: Option<Peer> = None;
    let mut errno = None;
    for line in response.lines() {
        if line.is_empty() {
            break;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| Error::Protocol(format!("invalid UAPI line without `=`: `{line}`")))?;
        if key == "errno" {
            errno = Some(parse_i64(key, value)?);
            continue;
        }
        if key == "public_key" {
            if let Some(peer) = current.take() {
                device.peers.push(peer);
            }
            current = Some(Peer {
                public_key: parse_key(value)?,
                ..Peer::default()
            });
            continue;
        }
        if let Some(peer) = current.as_mut() {
            apply_peer_line(peer, key, value)?;
        } else {
            apply_device_line(&mut device, key, value)?;
        }
    }
    if let Some(peer) = current {
        device.peers.push(peer);
    }
    let errno = errno.ok_or_else(|| Error::Protocol("missing errno in UAPI reply".to_owned()))?;
    if errno != 0 {
        return Err(Error::from_errno(errno));
    }
    Ok(device)
}

pub fn parse_set_response(response: &str) -> Result<(), Error> {
    let mut errno = None;
    for line in response.lines() {
        if line.is_empty() {
            break;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| Error::Protocol(format!("invalid UAPI line without `=`: `{line}`")))?;
        if key == "errno" {
            errno = Some(parse_i64(key, value)?);
        }
    }
    match errno.ok_or_else(|| Error::Protocol("missing errno in UAPI reply".to_owned()))? {
        0 => Ok(()),
        errno => Err(Error::from_errno(errno)),
    }
}

fn apply_device_line(device: &mut Device, key: &str, value: &str) -> Result<(), Error> {
    match key {
        "private_key" => {
            let key = parse_key(value)?;
            device.public_key = Some(key.public_key());
            device.private_key = Some(key);
        }
        "listen_port" => device.listen_port = parse_u16(key, value)?,
        "fwmark" => device.fwmark = parse_u32(key, value)?,
        "jc" => device.obfuscation.jc = Some(parse_u16(key, value)?),
        "jmin" => device.obfuscation.jmin = Some(parse_u16(key, value)?),
        "jmax" => device.obfuscation.jmax = Some(parse_u16(key, value)?),
        "s1" => device.obfuscation.s1 = Some(parse_u16(key, value)?),
        "s2" => device.obfuscation.s2 = Some(parse_u16(key, value)?),
        "s3" => device.obfuscation.s3 = Some(parse_u16(key, value)?),
        "s4" => device.obfuscation.s4 = Some(parse_u16(key, value)?),
        "h1" => device.obfuscation.h1 = Some(parse_u32_range(key, value)?),
        "h2" => device.obfuscation.h2 = Some(parse_u32_range(key, value)?),
        "h3" => device.obfuscation.h3 = Some(parse_u32_range(key, value)?),
        "h4" => device.obfuscation.h4 = Some(parse_u32_range(key, value)?),
        "i1" => device.obfuscation.i1 = Some(value.to_owned()),
        "i2" => device.obfuscation.i2 = Some(value.to_owned()),
        "i3" => device.obfuscation.i3 = Some(value.to_owned()),
        "i4" => device.obfuscation.i4 = Some(value.to_owned()),
        "i5" => device.obfuscation.i5 = Some(value.to_owned()),
        "header_protection_key" => {
            let key = parse_key(value)?;
            device.obfuscation.header_protection_key = (!key.is_zero()).then_some(key);
        }
        "content_padding_addition" => {
            device.obfuscation.content_padding_addition = Some(parse_u16_range(key, value)?);
        }
        "rekey_after_time" => {
            device.obfuscation.rekey_after_time = Some(parse_u16_range(key, value)?);
        }
        "rekey_timeout" => {
            device.obfuscation.rekey_timeout = Some(parse_u16_range(key, value)?);
        }
        "reject_after_time" => {
            device.obfuscation.reject_after_time = Some(parse_u16_range(key, value)?);
        }
        "keepalive_timeout" => {
            device.obfuscation.keepalive_timeout = Some(parse_u16_range(key, value)?);
        }
        "max_handshake_attempts" => {
            device.obfuscation.max_handshake_attempts = Some(parse_u16_range(key, value)?);
        }
        "random_trailers" => {
            device.obfuscation.random_trailers = Some(parse_bool(key, value)?);
        }
        "disable_cookies" => {
            device.obfuscation.disable_cookies = Some(parse_bool(key, value)?);
        }
        _ => {}
    }
    Ok(())
}

fn apply_peer_line(peer: &mut Peer, key: &str, value: &str) -> Result<(), Error> {
    match key {
        "preshared_key" => {
            let key = parse_key(value)?;
            peer.preshared_key = (!key.is_zero()).then_some(key);
        }
        "endpoint" => peer.endpoint = Some(parse_endpoint(value, true)?),
        "persistent_keepalive_interval" => {
            peer.persistent_keepalive = parse_u16_range(key, value)?;
        }
        "allowed_ip" | "allowed_ips" => {
            if !value.contains('/') {
                return Err(Error::Protocol(format!(
                    "allowed IP without a prefix length: `{value}`"
                )));
            }
            peer.allowed_ips.push(value.parse::<AllowedIp>()?);
        }
        "last_handshake_time_sec" => {
            peer.last_handshake_time.seconds = parse_i64_from_u64(key, value)?;
        }
        "last_handshake_time_nsec" => {
            peer.last_handshake_time.nanoseconds = parse_i64_from_u64(key, value)?;
        }
        "rx_bytes" => peer.rx_bytes = parse_u64(key, value)?,
        "tx_bytes" => peer.tx_bytes = parse_u64(key, value)?,
        _ => {}
    }
    Ok(())
}

async fn exchange(path: &Path, request: &str) -> Result<String, Error> {
    let mut stream = UnixStream::connect(path).await?;
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            break;
        }
        response.push_str(&line);
        if line == "\n" {
            break;
        }
    }
    Ok(response)
}

fn is_socket(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_socket())
        .unwrap_or(false)
}

async fn connect(path: &Path) -> Result<UnixStream, std::io::Error> {
    match UnixStream::connect(path).await {
        Ok(stream) => Ok(stream),
        Err(error) => {
            if error.kind() == std::io::ErrorKind::ConnectionRefused {
                let _ = std::fs::remove_file(path);
            }
            Err(error)
        }
    }
}

fn write_line(output: &mut String, key: &str, value: &str) -> Result<(), Error> {
    if value.contains(['\n', '\r']) {
        return Err(Error::Protocol(format!(
            "value for `{key}` contains a line break"
        )));
    }
    let _ = writeln!(output, "{key}={value}");
    Ok(())
}

fn bool_number(value: bool) -> &'static str {
    if value {
        "1"
    } else {
        "0"
    }
}

fn parse_key(value: &str) -> Result<Key, Error> {
    Key::from_hex(value).map_err(|error| Error::Protocol(format!("invalid key: {error}")))
}

fn parse_u16(key: &str, value: &str) -> Result<u16, Error> {
    value
        .parse::<u16>()
        .map_err(|_| Error::Protocol(format!("invalid {key}: `{value}`")))
}

fn parse_u32(key: &str, value: &str) -> Result<u32, Error> {
    value
        .parse::<u32>()
        .map_err(|_| Error::Protocol(format!("invalid {key}: `{value}`")))
}

fn parse_u64(key: &str, value: &str) -> Result<u64, Error> {
    value
        .parse::<u64>()
        .map_err(|_| Error::Protocol(format!("invalid {key}: `{value}`")))
}

fn parse_i64(key: &str, value: &str) -> Result<i64, Error> {
    value
        .parse::<i64>()
        .map_err(|_| Error::Protocol(format!("invalid {key}: `{value}`")))
}

fn parse_i64_from_u64(key: &str, value: &str) -> Result<i64, Error> {
    let parsed = parse_u64(key, value)?;
    i64::try_from(parsed).map_err(|_| Error::Protocol(format!("invalid {key}: `{value}`")))
}

fn parse_bool(key: &str, value: &str) -> Result<bool, Error> {
    match value {
        "1" | "true" | "on" => Ok(true),
        "0" | "false" | "off" => Ok(false),
        _ => value
            .parse::<u64>()
            .map(|number| number != 0)
            .map_err(|_| Error::Protocol(format!("invalid {key}: `{value}`"))),
    }
}

fn parse_u16_range(key: &str, value: &str) -> Result<U16Range, Error> {
    U16Range::parse(value).map_err(|error| Error::Protocol(format!("invalid {key}: {error}")))
}

fn parse_u32_range(key: &str, value: &str) -> Result<U32Range, Error> {
    U32Range::parse(value).map_err(|error| Error::Protocol(format!("invalid {key}: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ConfigApplication;
    use crate::model::TimeSpec;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::AsyncReadExt;

    const PRIVATE: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    const GET_RESPONSE: &str = "\
private_key=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
listen_port=51820
fwmark=4660
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
header_protection_key=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
content_padding_addition=0-100
rekey_after_time=120
rekey_timeout=5
reject_after_time=180
keepalive_timeout=10
max_handshake_attempts=7
random_trailers=1
disable_cookies=0
public_key=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
preshared_key=606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f
protocol_version=1
endpoint=192.0.2.1:51820
last_handshake_time_sec=1700000000
last_handshake_time_nsec=123
tx_bytes=1000
rx_bytes=2000
persistent_keepalive_interval=25
allowed_ip=10.0.0.0/8
allowed_ip=fd00::/64
errno=0

";

    fn set_device() -> SetDevice {
        let mut device = SetDevice::for_interface("test0", Default::default());
        device.replace_peers = true;
        device.device.private_key = Some(Key::from_hex(PRIVATE).expect("valid"));
        device.device.listen_port = Some(51820);
        device.device.fwmark = Some(0);
        device.device.obfuscation.jc = Some(4);
        device.device.obfuscation.jmin = Some(40);
        device.device.obfuscation.jmax = Some(70);
        device.device.obfuscation.s1 = Some(92);
        device.device.obfuscation.h1 = Some(U32Range::new(61_220_074, 118_999_195));
        device.device.obfuscation.i1 = Some("<b 0x1><c>".to_owned());
        device.device.obfuscation.header_protection_key = Some(
            Key::from_hex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
                .expect("valid"),
        );
        device.device.obfuscation.content_padding_addition = Some(U16Range::new(0, 100));
        device.device.obfuscation.random_trailers = Some(true);
        device.device.obfuscation.disable_cookies = Some(false);
        device.peers.push(umbrawg_config::PeerConfig {
            public_key: Key::from_hex(
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            )
            .expect("valid"),
            preshared_key: Some(
                Key::from_hex("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f")
                    .expect("valid"),
            ),
            allowed_ips: Some(vec![
                "10.0.0.0/8".parse().expect("valid"),
                "fd00::/64".parse().expect("valid"),
            ]),
            endpoint: Some("192.0.2.1:51820".parse().expect("valid")),
            persistent_keepalive: Some(U16Range::single(25)),
            remove: false,
        });
        device
    }

    #[test]
    fn parses_get_response() {
        let device = parse_get_response(GET_RESPONSE, "test0").expect("valid response");
        assert_eq!(device.name, "test0");
        assert_eq!(device.listen_port, 51820);
        assert_eq!(device.fwmark, 4660);
        assert_eq!(device.obfuscation.jc, Some(4));
        assert_eq!(
            device.obfuscation.h1,
            Some(U32Range::new(61_220_074, 118_999_195))
        );
        assert_eq!(device.obfuscation.i1.as_deref(), Some("<b 0x1><c>"));
        assert_eq!(device.obfuscation.random_trailers, Some(true));
        assert_eq!(device.obfuscation.disable_cookies, Some(false));
        assert!(device.private_key.is_some());
        assert!(device.public_key.is_some());
        assert_eq!(device.peers.len(), 1);
        let peer = &device.peers[0];
        assert_eq!(peer.allowed_ips.len(), 2);
        assert_eq!(peer.rx_bytes, 2000);
        assert_eq!(peer.tx_bytes, 1000);
        assert_eq!(peer.last_handshake_time, TimeSpec::new(1_700_000_000, 123));
        assert_eq!(peer.persistent_keepalive, U16Range::single(25));
        assert_eq!(
            peer.endpoint,
            Some("192.0.2.1:51820".parse().expect("valid"))
        );
    }

    #[test]
    fn parses_uapi_error() {
        let error = parse_get_response("errno=-22\n\n", "test0").expect_err("error");
        match error {
            Error::Uapi { errno, .. } => assert_eq!(errno, -22),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn rejects_broken_get_response() {
        assert!(parse_get_response("listen_port=51820\n\n", "test0").is_err());
        assert!(parse_get_response("broken\n\n", "test0").is_err());
        assert!(parse_get_response("listen_port=bad\nerrno=0\n\n", "test0").is_err());
    }

    #[test]
    fn builds_set_request() {
        let request = build_set_request(&set_device()).expect("valid request");
        assert!(request.starts_with("set=1\n"));
        assert!(request.contains(
            "private_key=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n"
        ));
        assert!(request.contains("listen_port=51820\n"));
        assert!(request.contains("fwmark=0\n"));
        assert!(request.contains("replace_peers=true\n"));
        assert!(request.contains("h1=61220074-118999195\n"));
        assert!(request.contains("i1=<b 0x1><c>\n"));
        assert!(request.contains("random_trailers=1\n"));
        assert!(request.contains("disable_cookies=0\n"));
        assert!(request.contains(
            "public_key=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f\n"
        ));
        assert!(request.contains("persistent_keepalive_interval=25\n"));
        assert!(request.contains("replace_allowed_ips=true\n"));
        assert!(request.contains("allowed_ip=10.0.0.0/8\n"));
        assert!(request.ends_with("\n\n"));
    }

    #[test]
    fn serializes_removed_peer() {
        let mut config = set_device();
        config.peers[0].remove = true;
        config.peers[0].allowed_ips = None;
        let request = build_set_request(&config).expect("valid");
        let peer_line = format!(
            "public_key={}\nremove=true\n",
            config.peers[0].public_key.to_hex()
        );
        assert!(request.contains(&peer_line));
        assert!(!request.contains("preshared_key="));
    }

    #[test]
    fn append_request_keeps_peers_and_replaces_allowed_ips() {
        let mut config = umbrawg_config::Config::default();
        config.peers.push(umbrawg_config::PeerConfig {
            public_key: Key::from_hex(
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            )
            .expect("valid"),
            preshared_key: None,
            allowed_ips: None,
            endpoint: None,
            persistent_keepalive: None,
            remove: false,
        });
        let set = SetDevice::from_config_file("test0", &config, ConfigApplication::Append);
        let request = build_set_request(&set).expect("valid");
        assert!(!request.contains("replace_peers=true\n"));
        assert!(request.contains("replace_allowed_ips=true\n"));
        assert!(!request.contains("allowed_ip="));
    }

    #[test]
    fn sync_request_removes_peers_missing_from_the_file() {
        let mut config = umbrawg_config::Config::default();
        config.peers.push(umbrawg_config::PeerConfig {
            public_key: Key::from_bytes([1u8; 32]),
            preshared_key: None,
            allowed_ips: Some(vec!["10.0.0.0/8".parse().expect("valid")]),
            endpoint: None,
            persistent_keepalive: None,
            remove: false,
        });
        let mut runtime = Device::new("test0");
        runtime.peers.push(Peer {
            public_key: Key::from_bytes([1u8; 32]),
            ..Peer::default()
        });
        runtime.peers.push(Peer {
            public_key: Key::from_bytes([2u8; 32]),
            ..Peer::default()
        });
        let set = SetDevice::synced_from("test0", &config, &runtime);
        let request = build_set_request(&set).expect("valid");
        assert!(!request.contains("replace_peers=true\n"));
        assert!(request.contains("allowed_ip=10.0.0.0/8\n"));
        assert!(request.contains(&format!(
            "public_key={}\nremove=true\n",
            Key::from_bytes([2u8; 32]).to_hex()
        )));
    }

    #[test]
    fn rejects_line_breaks_in_values() {
        let mut config = set_device();
        config.device.obfuscation.i1 = Some("bad\nvalue".to_owned());
        assert!(build_set_request(&config).is_err());
    }

    #[test]
    fn interface_name_validation() {
        assert!(validate_interface_name("uwg0").is_ok());
        assert!(validate_interface_name("").is_err());
        assert!(validate_interface_name("bad/name").is_err());
        assert!(validate_interface_name(&"x".repeat(libc::IFNAMSIZ)).is_err());
    }

    fn unique_directory() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("umbrawg-ctl-{}-{nanos}", std::process::id()))
    }

    #[tokio::test]
    async fn talks_to_fake_uapi_get() {
        let directory = unique_directory();
        std::fs::create_dir_all(&directory).expect("directory");
        let path = socket_path_in(&directory, "test0").expect("path");
        let listener = tokio::net::UnixListener::bind(&path).expect("bind");
        let response = GET_RESPONSE.to_owned();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request = String::new();
            let mut reader = BufReader::new(&mut stream);
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).await.expect("read") == 0 {
                    break;
                }
                request.push_str(&line);
                if line == "\n" {
                    break;
                }
            }
            assert_eq!(request, "get=1\n\n");
            stream.write_all(response.as_bytes()).await.expect("write");
            stream.flush().await.expect("flush");
        });
        let device = get_device_at(&path, "test0").await.expect("device");
        server.await.expect("server");
        assert_eq!(device.listen_port, 51820);
        std::fs::remove_dir_all(&directory).expect("cleanup");
    }

    #[tokio::test]
    async fn talks_to_fake_uapi_set() {
        let directory = unique_directory();
        std::fs::create_dir_all(&directory).expect("directory");
        let path = socket_path_in(&directory, "test0").expect("path");
        let listener = tokio::net::UnixListener::bind(&path).expect("bind");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request = String::new();
            let mut reader = BufReader::new(&mut stream);
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).await.expect("read") == 0 {
                    break;
                }
                if line == "\n" {
                    break;
                }
                request.push_str(&line);
            }
            assert!(request.starts_with("set=1\n"));
            assert!(request.contains("listen_port=51820\n"));
            stream.write_all(b"errno=0\n\n").await.expect("write");
            stream.flush().await.expect("flush");
        });
        let config = set_device();
        set_device_at(&path, &config).await.expect("set");
        server.await.expect("server");
        std::fs::remove_dir_all(&directory).expect("cleanup");
    }

    #[tokio::test]
    async fn reports_fake_uapi_errors() {
        let directory = unique_directory();
        std::fs::create_dir_all(&directory).expect("directory");
        let path = socket_path_in(&directory, "test0").expect("path");
        let listener = tokio::net::UnixListener::bind(&path).expect("bind");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buffer = [0u8; 64];
            let _ = stream.read(&mut buffer).await;
            stream.write_all(b"errno=-22\n\n").await.expect("write");
            stream.flush().await.expect("flush");
        });
        let error = get_device_at(&path, "test0").await.expect_err("error");
        match error {
            Error::Uapi { errno, .. } => assert_eq!(errno, -22),
            other => panic!("unexpected error: {other}"),
        }
        server.await.expect("server");
        std::fs::remove_dir_all(&directory).expect("cleanup");
    }

    #[tokio::test]
    async fn lists_only_sockets() {
        let directory = unique_directory();
        std::fs::create_dir_all(&directory).expect("directory");
        let path = socket_path_in(&directory, "test0").expect("path");
        let _listener = tokio::net::UnixListener::bind(&path).expect("bind");
        std::fs::write(directory.join("plain.sock"), b"x").expect("write");
        let interfaces = list_interfaces_in(&directory).await.expect("list");
        assert_eq!(interfaces, vec!["test0".to_owned()]);
        std::fs::remove_dir_all(&directory).expect("cleanup");
    }
}
