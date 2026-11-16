//! Serializer for UAPI replies.
//!
//! The output order and field selection match the Go implementation: zero
//! device fields are omitted, `random_trailers` and `disable_cookies` are
//! always printed, every peer prints its keys, counters and allowed IPs, and
//! the final line is `errno=0`.

use std::fmt::{self, Write as _};

use crate::types::{DeviceSnapshot, PeerSnapshot};

const ZERO_KEY: [u8; 32] = [0u8; 32];

/// Formats a `get=1` reply, including the trailing `errno=0` line.
#[must_use]
pub fn format_get_response(snapshot: &DeviceSnapshot) -> String {
    let mut output = String::with_capacity(1024);
    write_device(&mut output, snapshot);
    for peer in &snapshot.peers {
        write_peer(&mut output, peer);
    }
    output.push_str("errno=0\n\n");
    output
}

/// Formats a `set=1` reply.
///
/// `error` is `None` on success; otherwise its [`UapiError::code`] is written
/// as the errno.
///
/// [`UapiError::code`]: crate::UapiError::code
#[must_use]
pub fn format_errno_response(error: Option<&crate::UapiError>) -> String {
    match error {
        Some(error) => format_errno(error.code()),
        None => format_errno(0),
    }
}

/// Formats a reply that contains only an `errno` line.
#[must_use]
pub fn format_errno(errno: i64) -> String {
    format!("errno={errno}\n\n")
}

fn write_device(output: &mut String, snapshot: &DeviceSnapshot) {
    if let Some(key) = snapshot
        .private_key
        .as_ref()
        .filter(|key| !key.is_zero())
    {
        write_key(output, "private_key", key.as_bytes());
    }
    if snapshot.listen_port != 0 {
        write_field(output, "listen_port", snapshot.listen_port);
    }
    if snapshot.fwmark != 0 {
        write_field(output, "fwmark", snapshot.fwmark);
    }

    let obfuscation = &snapshot.obfuscation;
    for (name, value) in [
        ("jc", obfuscation.jc),
        ("jmin", obfuscation.jmin),
        ("jmax", obfuscation.jmax),
        ("s1", obfuscation.s1),
        ("s2", obfuscation.s2),
        ("s3", obfuscation.s3),
        ("s4", obfuscation.s4),
    ] {
        if value != 0 {
            write_field(output, name, value);
        }
    }
    for (name, range) in [
        ("h1", obfuscation.h1),
        ("h2", obfuscation.h2),
        ("h3", obfuscation.h3),
        ("h4", obfuscation.h4),
    ] {
        if !range.is_zero() {
            write_field(output, name, range);
        }
    }
    for (name, spec) in [
        ("i1", &obfuscation.i1),
        ("i2", &obfuscation.i2),
        ("i3", &obfuscation.i3),
        ("i4", &obfuscation.i4),
        ("i5", &obfuscation.i5),
    ] {
        if let Some(spec) = spec {
            write_field(output, name, spec);
        }
    }
    if let Some(key) = obfuscation
        .header_protection_key
        .as_ref()
        .filter(|key| !key.is_zero())
    {
        write_key(output, "header_protection_key", key.as_bytes());
    }
    if !obfuscation.content_padding_addition.is_zero() {
        write_field(
            output,
            "content_padding_addition",
            obfuscation.content_padding_addition,
        );
    }

    let timings = snapshot.timings;
    for (name, range) in [
        ("rekey_after_time", timings.rekey_after_time),
        ("rekey_timeout", timings.rekey_timeout),
        ("reject_after_time", timings.reject_after_time),
        ("keepalive_timeout", timings.keepalive_timeout),
        ("max_handshake_attempts", timings.max_handshake_attempts),
    ] {
        if !range.is_zero() {
            write_field(output, name, range);
        }
    }

    write_bool(output, "random_trailers", obfuscation.random_trailers);
    write_bool(output, "disable_cookies", obfuscation.disable_cookies);
}

fn write_peer(output: &mut String, peer: &PeerSnapshot) {
    write_key(output, "public_key", peer.public_key.as_bytes());
    match &peer.preshared_key {
        Some(key) => write_key(output, "preshared_key", key.as_bytes()),
        None => write_key(output, "preshared_key", &ZERO_KEY),
    }
    output.push_str("protocol_version=1\n");

    if let Some(endpoint) = peer.endpoint {
        write_field(output, "endpoint", endpoint);
    }
    write_field(output, "last_handshake_time_sec", peer.last_handshake_time_sec);
    write_field(
        output,
        "last_handshake_time_nsec",
        peer.last_handshake_time_nsec,
    );
    write_field(output, "tx_bytes", peer.tx_bytes);
    write_field(output, "rx_bytes", peer.rx_bytes);
    if !peer.persistent_keepalive_interval.is_zero() {
        write_field(
            output,
            "persistent_keepalive_interval",
            peer.persistent_keepalive_interval,
        );
    }
    for prefix in &peer.allowed_ips {
        write_field(output, "allowed_ip", prefix);
    }
}

fn write_field(output: &mut String, name: &str, value: impl fmt::Display) {
    let _ = writeln!(output, "{name}={value}");
}

fn write_bool(output: &mut String, name: &str, value: bool) {
    write_field(output, name, if value { "1" } else { "0" });
}

fn write_key(output: &mut String, name: &str, key: &[u8; 32]) {
    output.push_str(name);
    output.push('=');
    for byte in key {
        let _ = write!(output, "{byte:02x}");
    }
    output.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        AllowedIp, ObfuscationSnapshot, PeerSnapshot, TimingSnapshot, U32Range, U16Range,
    };
    use umbrawg_crypto::{Key, PublicKey};

    const PRIVATE_KEY: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const HEADER_PROTECTION_KEY: &str =
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
    const PEER_KEY: &str =
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
    const PRESHARED_KEY: &str =
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f";

    /// Reply parsed by the `umbrawg-ctl` test-suite
    /// (`umbrawg-tools/crates/umbrawg-ctl/src/uapi.rs`, `GET_RESPONSE`).
    const CTL_GET_RESPONSE: &str = "\
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

    #[test]
    fn matches_umbrawg_ctl_fixture() {
        let snapshot = sample_snapshot();
        assert_eq!(format_get_response(&snapshot), CTL_GET_RESPONSE);
    }

    #[test]
    fn omits_zero_device_fields() {
        let response = format_get_response(&DeviceSnapshot::default());
        assert_eq!(
            response,
            "h1=1\nh2=2\nh3=3\nh4=4\nrandom_trailers=0\ndisable_cookies=0\nerrno=0\n\n"
        );
    }

    #[test]
    fn prints_zero_preshared_key() {
        let peer = PeerSnapshot {
            public_key: PublicKey::from_hex(PEER_KEY).expect("valid"),
            ..PeerSnapshot::default()
        };
        let snapshot = DeviceSnapshot {
            peers: vec![peer],
            ..DeviceSnapshot::default()
        };
        let response = format_get_response(&snapshot);
        assert!(response.contains(&format!("preshared_key={}\n", "00".repeat(32))));
    }

    #[test]
    fn formats_errno_responses() {
        assert_eq!(format_errno_response(None), "errno=0\n\n");
        assert_eq!(
            format_errno_response(Some(&crate::UapiError::PermissionDenied)),
            "errno=-13\n\n"
        );
        assert_eq!(
            format_errno_response(Some(&crate::UapiError::UnknownKey("x".to_owned()))),
            "errno=-22\n\n"
        );
    }

    fn sample_snapshot() -> DeviceSnapshot {
        DeviceSnapshot {
            private_key: Some(Key::from_hex(PRIVATE_KEY).expect("valid")),
            listen_port: 51820,
            fwmark: 4660,
            obfuscation: ObfuscationSnapshot {
                jc: 4,
                jmin: 40,
                jmax: 70,
                s1: 92,
                s2: 115,
                s3: 44,
                s4: 9,
                h1: U32Range::new(61_220_074, 118_999_195),
                h2: U32Range::new(605_047_389, 945_520_346),
                h3: U32Range::new(1_477_291_385, 1_814_368_140),
                h4: U32Range::new(1_951_993_942, 1_997_499_713),
                i1: Some("<b 0x1><c>".to_owned()),
                i2: None,
                i3: None,
                i4: None,
                i5: None,
                header_protection_key: Some(
                    Key::from_hex(HEADER_PROTECTION_KEY).expect("valid"),
                ),
                content_padding_addition: U16Range::new(0, 100),
                random_trailers: true,
                disable_cookies: false,
            },
            timings: TimingSnapshot {
                rekey_after_time: U16Range::single(120),
                rekey_timeout: U16Range::single(5),
                reject_after_time: U16Range::single(180),
                keepalive_timeout: U16Range::single(10),
                max_handshake_attempts: U16Range::single(7),
            },
            peers: vec![PeerSnapshot {
                public_key: PublicKey::from_hex(PEER_KEY).expect("valid"),
                preshared_key: Some(Key::from_hex(PRESHARED_KEY).expect("valid")),
                endpoint: Some("192.0.2.1:51820".parse().expect("valid")),
                last_handshake_time_sec: 1_700_000_000,
                last_handshake_time_nsec: 123,
                tx_bytes: 1000,
                rx_bytes: 2000,
                persistent_keepalive_interval: U16Range::single(25),
                allowed_ips: vec![
                    "10.0.0.0/8".parse::<AllowedIp>().expect("valid"),
                    "fd00::/64".parse::<AllowedIp>().expect("valid"),
                ],
            }],
        }
    }
}
