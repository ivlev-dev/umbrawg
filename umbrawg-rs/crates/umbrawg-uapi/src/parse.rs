//! Parser for `set=1` requests.
//!
//! The parser accepts the Go/UmbraWG textual protocol and converts it into a
//! [`SetRequest`]. Unknown keys, malformed numbers and malformed ranges are
//! rejected with the same errno values as the Go implementation.

use std::io::{BufRead, Read};
use std::net::SocketAddr;

use umbrawg_crypto::{Key, PublicKey};
use umbrawg_proto::SpecialPacket;

use crate::error::{invalid_value, UapiError};
use crate::types::{
    AllowedIp, AllowedIpChange, Cipher, PeerRequest, SetRequest, SpecialPacketUpdate, U16Range,
    U32Range,
};

/// Maximum accepted length of a single UAPI line.
///
/// The largest legitimate line is a special-packet template, capped at 64 KiB
/// by the protocol itself, so 1 MiB leaves ample headroom while bounding
/// memory use for unauthenticated input.
pub(crate) const MAX_LINE_LENGTH: usize = 1 << 20;

/// Reads one line, stripping `\n` and a trailing `\r`.
///
/// Returns `Ok(None)` at end of stream.
pub(crate) fn read_line<R: BufRead>(reader: &mut R) -> Result<Option<String>, UapiError> {
    let mut buffer = Vec::new();
    let read = reader
        .by_ref()
        .take((MAX_LINE_LENGTH + 1) as u64)
        .read_until(b'\n', &mut buffer)?;
    if read == 0 {
        return Ok(None);
    }
    if buffer.len() > MAX_LINE_LENGTH {
        return Err(UapiError::Protocol(format!(
            "UAPI line exceeds {MAX_LINE_LENGTH} bytes"
        )));
    }
    if buffer.last() == Some(&b'\n') {
        buffer.pop();
    }
    if buffer.last() == Some(&b'\r') {
        buffer.pop();
    }
    let line = String::from_utf8(buffer)
        .map_err(|_| UapiError::Protocol("UAPI line is not valid UTF-8".to_owned()))?;
    Ok(Some(line))
}

/// Parses the body of a `set=1` request.
///
/// The operation line (`set=1`) must already be consumed. Lines are read until
/// an empty line or end of stream. The whole request is consumed even when a
/// line is invalid, so the caller can report an error and keep the connection
/// usable.
pub fn parse_set_request<R: BufRead>(reader: &mut R) -> Result<SetRequest, UapiError> {
    let mut request = SetRequest::default();
    let mut current: Option<PeerRequest> = None;
    let mut first_error: Option<UapiError> = None;

    while let Some(line) = read_line(reader)? {
        if line.is_empty() {
            break;
        }
        if first_error.is_some() {
            continue;
        }
        let result = parse_line(&mut request, &mut current, &line);
        if let Err(error) = result {
            first_error = Some(error);
        }
    }

    if let Some(peer) = current {
        request.peers.push(peer);
    }

    match first_error {
        Some(error) => Err(error),
        None => Ok(request),
    }
}

fn parse_line(
    request: &mut SetRequest,
    current: &mut Option<PeerRequest>,
    line: &str,
) -> Result<(), UapiError> {
    let (key, value) = line
        .split_once('=')
        .ok_or_else(|| UapiError::Protocol(format!("invalid UAPI line without `=`: `{line}`")))?;

    if key == "public_key" {
        if let Some(peer) = current.take() {
            request.peers.push(peer);
        }
        *current = Some(PeerRequest::new(parse_public_key(key, value)?));
        return Ok(());
    }

    match current.as_mut() {
        Some(peer) => apply_peer_line(peer, key, value),
        None => apply_device_line(request, key, value),
    }
}

fn apply_device_line(request: &mut SetRequest, key: &str, value: &str) -> Result<(), UapiError> {
    match key {
        "private_key" => request.private_key = Some(parse_key(key, value)?),
        "listen_port" => request.listen_port = Some(parse_u16(key, value)?),
        "fwmark" => request.fwmark = Some(parse_u32(key, value)?),
        "extra_ports" => request.extra_ports = Some(parse_extra_ports(key, value)?),
        "replace_peers" => {
            require_true(key, value)?;
            request.replace_peers = true;
        }
        "jc" => request.obfuscation.jc = Some(parse_u16(key, value)?),
        "jmin" => request.obfuscation.jmin = Some(parse_u16(key, value)?),
        "jmax" => request.obfuscation.jmax = Some(parse_u16(key, value)?),
        "s1" => request.obfuscation.s1 = Some(parse_u16(key, value)?),
        "s2" => request.obfuscation.s2 = Some(parse_u16(key, value)?),
        "s3" => request.obfuscation.s3 = Some(parse_u16(key, value)?),
        "s4" => request.obfuscation.s4 = Some(parse_u16(key, value)?),
        "h1" => request.obfuscation.h1 = Some(parse_u32_range(key, value)?),
        "h2" => request.obfuscation.h2 = Some(parse_u32_range(key, value)?),
        "h3" => request.obfuscation.h3 = Some(parse_u32_range(key, value)?),
        "h4" => request.obfuscation.h4 = Some(parse_u32_range(key, value)?),
        "i1" => request.obfuscation.i1 = parse_special_packet(key, value)?,
        "i2" => request.obfuscation.i2 = parse_special_packet(key, value)?,
        "i3" => request.obfuscation.i3 = parse_special_packet(key, value)?,
        "i4" => request.obfuscation.i4 = parse_special_packet(key, value)?,
        "i5" => request.obfuscation.i5 = parse_special_packet(key, value)?,
        "header_protection_key" => {
            request.obfuscation.header_protection_key = Some(parse_key(key, value)?);
        }
        "content_padding_addition" => {
            request.obfuscation.content_padding_addition = Some(parse_u16_range(key, value)?);
        }
        "rekey_after_time" => request.timings.rekey_after_time = Some(parse_u16_range(key, value)?),
        "rekey_timeout" => request.timings.rekey_timeout = Some(parse_u16_range(key, value)?),
        "reject_after_time" => {
            request.timings.reject_after_time = Some(parse_u16_range(key, value)?);
        }
        "keepalive_timeout" => {
            request.timings.keepalive_timeout = Some(parse_u16_range(key, value)?);
        }
        "max_handshake_attempts" => {
            request.timings.max_handshake_attempts = Some(parse_u16_range(key, value)?);
        }
        "random_trailers" => {
            request.obfuscation.random_trailers = Some(parse_bool(key, value)?);
        }
        "disable_cookies" => {
            request.obfuscation.disable_cookies = Some(parse_bool(key, value)?);
        }
        _ => return Err(UapiError::UnknownKey(key.to_owned())),
    }
    Ok(())
}

fn apply_peer_line(peer: &mut PeerRequest, key: &str, value: &str) -> Result<(), UapiError> {
    match key {
        "update_only" => {
            require_true(key, value)?;
            peer.update_only = true;
        }
        "remove" => {
            require_true(key, value)?;
            peer.remove = true;
        }
        "preshared_key" => peer.preshared_key = Some(parse_key(key, value)?),
        "endpoint" => peer.endpoint = Some(parse_endpoint(key, value)?),
        "persistent_keepalive_interval" => {
            peer.persistent_keepalive_interval = Some(parse_u16_range(key, value)?);
        }
        "advanced_security" => {
            peer.advanced_security = Some(parse_bool(key, value)?);
        }
        "cipher" => {
            peer.cipher = Some(
                value
                    .parse::<Cipher>()
                    .map_err(|_| invalid_value(key, value))?,
            );
        }
        "replace_allowed_ips" => {
            require_true(key, value)?;
            peer.replace_allowed_ips = true;
        }
        "allowed_ip" => {
            let (remove, spec) = match value.strip_prefix('-') {
                Some(spec) => (true, spec),
                None => (false, value),
            };
            if !spec.contains('/') {
                return Err(invalid_value(key, value));
            }
            let prefix = spec
                .parse::<AllowedIp>()
                .map_err(|_| invalid_value(key, value))?;
            peer.allowed_ips.push(if remove {
                AllowedIpChange::Remove(prefix)
            } else {
                AllowedIpChange::Add(prefix)
            });
        }
        "protocol_version" => {
            if value != "1" {
                return Err(invalid_value(key, value));
            }
            peer.protocol_version = Some(1);
        }
        _ => return Err(UapiError::UnknownKey(key.to_owned())),
    }
    Ok(())
}

fn require_true(key: &str, value: &str) -> Result<(), UapiError> {
    if value == "true" {
        Ok(())
    } else {
        Err(invalid_value(key, value))
    }
}

fn parse_key(key: &str, value: &str) -> Result<Key, UapiError> {
    Key::from_hex(value).map_err(|_| invalid_value(key, value))
}

fn parse_public_key(key: &str, value: &str) -> Result<PublicKey, UapiError> {
    PublicKey::from_hex(value).map_err(|_| invalid_value(key, value))
}

fn parse_u16(key: &str, value: &str) -> Result<u16, UapiError> {
    if !is_decimal(value) {
        return Err(invalid_value(key, value));
    }
    value.parse::<u16>().map_err(|_| invalid_value(key, value))
}

fn parse_u32(key: &str, value: &str) -> Result<u32, UapiError> {
    if !is_decimal(value) {
        return Err(invalid_value(key, value));
    }
    value.parse::<u32>().map_err(|_| invalid_value(key, value))
}

/// Верхняя граница `extra_ports`; совпадает с `MAX_EXTRA_PORTS` устройства.
const MAX_EXTRA_PORTS: u8 = 8;

fn parse_extra_ports(key: &str, value: &str) -> Result<u8, UapiError> {
    if !is_decimal(value) {
        return Err(invalid_value(key, value));
    }
    let count = value.parse::<u8>().map_err(|_| invalid_value(key, value))?;
    if count > MAX_EXTRA_PORTS {
        return Err(UapiError::InvalidConfiguration(format!(
            "`{key}` must be 0..={MAX_EXTRA_PORTS}, got {count}"
        )));
    }
    Ok(count)
}

fn parse_u16_range(key: &str, value: &str) -> Result<U16Range, UapiError> {
    value
        .parse::<U16Range>()
        .map_err(|_| invalid_value(key, value))
}

fn parse_u32_range(key: &str, value: &str) -> Result<U32Range, UapiError> {
    value
        .parse::<U32Range>()
        .map_err(|_| invalid_value(key, value))
}

fn parse_bool(key: &str, value: &str) -> Result<bool, UapiError> {
    umbrawg_proto::parse_bool(value).map_err(|_| invalid_value(key, value))
}

fn parse_endpoint(key: &str, value: &str) -> Result<SocketAddr, UapiError> {
    value
        .parse::<SocketAddr>()
        .map_err(|_| invalid_value(key, value))
}

fn parse_special_packet(key: &str, value: &str) -> Result<SpecialPacketUpdate, UapiError> {
    let packet = SpecialPacket::parse(value).map_err(|_| invalid_value(key, value))?;
    if packet.tags().is_empty() {
        Ok(SpecialPacketUpdate::Clear)
    } else {
        Ok(SpecialPacketUpdate::Set(value.to_owned()))
    }
}

fn is_decimal(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn parse(request: &str) -> Result<SetRequest, UapiError> {
        parse_set_request(&mut Cursor::new(request.as_bytes().to_vec()))
    }

    const FULL_REQUEST: &str = "\
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
s4=9
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
endpoint=192.0.2.1:51820
persistent_keepalive_interval=25
advanced_security=on
protocol_version=1
replace_allowed_ips=true
allowed_ip=10.0.0.0/8
allowed_ip=fd00::/64

";

    #[test]
    fn parses_every_field() {
        let request = parse(FULL_REQUEST).expect("valid request");
        assert!(request.private_key.is_some());
        assert_eq!(request.listen_port, Some(51820));
        assert_eq!(request.fwmark, Some(4660));
        assert_eq!(request.extra_ports, Some(6));
        assert!(request.replace_peers);

        let obfuscation = &request.obfuscation;
        assert_eq!(obfuscation.jc, Some(4));
        assert_eq!(obfuscation.jmin, Some(40));
        assert_eq!(obfuscation.jmax, Some(70));
        assert_eq!(obfuscation.s1, Some(92));
        assert_eq!(obfuscation.s2, Some(115));
        assert_eq!(obfuscation.s3, Some(44));
        assert_eq!(obfuscation.s4, Some(9));
        assert_eq!(obfuscation.h1, Some(U32Range::new(61_220_074, 118_999_195)));
        assert_eq!(
            obfuscation.h4,
            Some(U32Range::new(1_951_993_942, 1_997_499_713))
        );
        assert_eq!(
            obfuscation.i1,
            SpecialPacketUpdate::Set("<b 0x01><c>".to_owned())
        );
        assert_eq!(obfuscation.i5, SpecialPacketUpdate::Set("<t>".to_owned()));
        assert!(obfuscation.header_protection_key.is_some());
        assert_eq!(
            obfuscation.content_padding_addition,
            Some(U16Range::new(0, 100))
        );
        assert_eq!(obfuscation.random_trailers, Some(true));
        assert_eq!(obfuscation.disable_cookies, Some(false));

        assert_eq!(
            request.timings.rekey_after_time,
            Some(U16Range::new(120, 180))
        );
        assert_eq!(request.timings.rekey_timeout, Some(U16Range::single(5)));
        assert_eq!(
            request.timings.reject_after_time,
            Some(U16Range::single(180))
        );
        assert_eq!(
            request.timings.keepalive_timeout,
            Some(U16Range::single(10))
        );
        assert_eq!(
            request.timings.max_handshake_attempts,
            Some(U16Range::single(7))
        );

        assert_eq!(request.peers.len(), 1);
        let peer = &request.peers[0];
        assert!(peer.preshared_key.is_some());
        assert_eq!(
            peer.endpoint,
            Some("192.0.2.1:51820".parse().expect("valid"))
        );
        assert_eq!(
            peer.persistent_keepalive_interval,
            Some(U16Range::single(25))
        );
        assert_eq!(peer.advanced_security, Some(true));
        assert_eq!(peer.protocol_version, Some(1));
        assert!(peer.replace_allowed_ips);
        assert_eq!(peer.allowed_ips.len(), 2);
        assert_eq!(
            peer.allowed_ips[0],
            AllowedIpChange::Add("10.0.0.0/8".parse().expect("valid"))
        );
    }

    #[test]
    fn parses_removed_peer() {
        let request = parse(
            "public_key=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f\nremove=true\n\n",
        )
        .expect("valid request");
        assert_eq!(request.peers.len(), 1);
        assert!(request.peers[0].remove);
    }

    #[test]
    fn parses_allowed_ip_removal() {
        let request = parse(
            "public_key=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f\nallowed_ip=-10.0.0.0/8\n\n",
        )
        .expect("valid request");
        assert_eq!(
            request.peers[0].allowed_ips[0],
            AllowedIpChange::Remove("10.0.0.0/8".parse().expect("valid"))
        );
    }

    #[test]
    fn empty_request_is_valid() {
        assert_eq!(parse("").expect("valid"), SetRequest::default());
        assert_eq!(parse("\n").expect("valid"), SetRequest::default());
    }

    #[test]
    fn accepts_request_without_trailing_blank_line() {
        let request = parse("listen_port=1").expect("valid");
        assert_eq!(request.listen_port, Some(1));
    }

    #[test]
    fn rejects_unknown_device_key() {
        assert!(matches!(
            parse("bogus=1\n\n"),
            Err(UapiError::UnknownKey(key)) if key == "bogus"
        ));
    }

    #[test]
    fn rejects_unknown_peer_key() {
        let request =
            "public_key=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f\nbogus=1\n\n";
        assert!(matches!(
            parse(request),
            Err(UapiError::UnknownKey(key)) if key == "bogus"
        ));
    }

    #[test]
    fn rejects_malformed_line() {
        assert!(matches!(parse("broken\n\n"), Err(UapiError::Protocol(_))));
        assert_eq!(parse("broken\n\n").expect_err("error").code(), -71);
    }

    #[test]
    fn rejects_bad_values() {
        let cases = [
            "listen_port=70000\n\n",
            "listen_port=-1\n\n",
            "listen_port=+1\n\n",
            "fwmark=4294967296\n\n",
            "h1=10-5\n\n",
            "content_padding_addition=1-2-3\n\n",
            "rekey_after_time=999999\n\n",
            "random_trailers=maybe\n\n",
            "replace_peers=1\n\n",
            "private_key=00\n\n",
        ];
        for case in cases {
            assert!(parse(case).is_err(), "{case}");
        }
    }

    #[test]
    fn parses_extra_ports() {
        for (value, expected) in [("0", 0), ("4", 4), ("8", 8)] {
            let request = parse(&format!("extra_ports={value}\n\n")).expect("valid extra_ports");
            assert_eq!(request.extra_ports, Some(expected), "{value}");
        }
    }

    #[test]
    fn rejects_out_of_range_extra_ports() {
        let error = parse("extra_ports=9\n\n").expect_err("out of range");
        assert!(
            matches!(&error, UapiError::InvalidConfiguration(_)),
            "{error}"
        );
        assert_eq!(error.code(), -22);
        assert!(error.to_string().contains("0..=8"), "{error}");

        for value in ["", "-1", "+1", "abc", "4.0", "999", "0x4", " 4"] {
            assert!(
                parse(&format!("extra_ports={value}\n\n")).is_err(),
                "{value}"
            );
        }
    }

    #[test]
    fn parses_peer_cipher() {
        let key = "public_key=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f\n";
        let request = format!("{key}cipher=aes-256-gcm\n\n");
        let parsed = parse(&request).expect("valid cipher");
        assert_eq!(parsed.peers[0].cipher, Some(Cipher::Aes256Gcm));

        let request = format!("{key}cipher=CHACHA20-POLY1305\n\n");
        let parsed = parse(&request).expect("valid cipher");
        assert_eq!(parsed.peers[0].cipher, Some(Cipher::ChaCha20Poly1305));

        for value in ["aes", "", "gcm"] {
            let request = format!("{key}cipher={value}\n\n");
            assert!(parse(&request).is_err(), "{value}");
        }
    }

    #[test]
    fn parses_advanced_security_booleans() {
        let key = "public_key=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f\n";
        for value in ["on", "true", "1", "t", "T"] {
            let request = format!("{key}advanced_security={value}\n\n");
            let parsed = parse(&request).expect("valid advanced_security");
            assert_eq!(parsed.peers[0].advanced_security, Some(true), "{value}");
        }
        for value in ["off", "false", "0", "f", "F"] {
            let request = format!("{key}advanced_security={value}\n\n");
            let parsed = parse(&request).expect("valid advanced_security");
            assert_eq!(parsed.peers[0].advanced_security, Some(false), "{value}");
        }
        for value in ["maybe", "", "2", "-1"] {
            let request = format!("{key}advanced_security={value}\n\n");
            assert!(parse(&request).is_err(), "{value}");
        }
    }

    #[test]
    fn rejects_bad_peer_values() {
        let key = "public_key=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f\n";
        let cases = [
            "protocol_version=2\n\n",
            "remove=1\n\n",
            "update_only=false\n\n",
            "replace_allowed_ips=yes\n\n",
            "allowed_ip=10.0.0.0\n\n",
            "allowed_ip=10.0.0.0/33\n\n",
            "endpoint=10.0.0.1\n\n",
            "preshared_key=zz\n\n",
            "persistent_keepalive_interval=70000\n\n",
        ];
        for case in cases {
            let request = format!("{key}{case}");
            assert!(parse(&request).is_err(), "{case}");
        }
    }

    #[test]
    fn empty_special_packet_clears_slot() {
        let request = parse("i1=\n\n").expect("valid");
        assert_eq!(request.obfuscation.i1, SpecialPacketUpdate::Clear);
        let request = parse("i1=plain text\n\n").expect("valid");
        assert_eq!(request.obfuscation.i1, SpecialPacketUpdate::Clear);
    }

    #[test]
    fn rejects_invalid_special_packet() {
        assert!(parse("i1=<unknown>\n\n").is_err());
    }

    #[test]
    fn consumes_whole_request_after_error() {
        let mut cursor = Cursor::new(
            b"listen_port=bad\npublic_key=404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f\nremove=true\n\nlisten_port=7\n\n".to_vec(),
        );
        let error = parse_set_request(&mut cursor).expect_err("error");
        assert!(matches!(error, UapiError::InvalidValue { .. }));
        let next = parse_set_request(&mut cursor).expect("second request");
        assert_eq!(next.listen_port, Some(7));
    }

    #[test]
    fn rejects_overlong_line() {
        let request = format!("i1={}\n\n", "x".repeat(MAX_LINE_LENGTH + 1));
        let mut cursor = Cursor::new(request.into_bytes());
        assert!(matches!(
            parse_set_request(&mut cursor),
            Err(UapiError::Protocol(_))
        ));
    }

    #[test]
    fn rejects_non_utf8_line() {
        let mut cursor = Cursor::new(b"listen_port=\xff\n\n".to_vec());
        assert!(matches!(
            parse_set_request(&mut cursor),
            Err(UapiError::Protocol(_))
        ));
    }

    #[test]
    fn strips_carriage_returns() {
        let request = parse("listen_port=42\r\n\r\n").expect("valid");
        assert_eq!(request.listen_port, Some(42));
    }
}
