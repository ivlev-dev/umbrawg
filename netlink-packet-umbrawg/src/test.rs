// SPDX-License-Identifier: MIT

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    str::FromStr,
};

use netlink_packet_core::{Emitable, Parseable, ParseableParametrized};
use netlink_packet_generic::{GenlBuffer, GenlHeader};
use pretty_assertions::assert_eq;

use crate::{
    UmbrawgAddressFamily, UmbrawgAllowedIp, UmbrawgAllowedIpAttr,
    UmbrawgAttribute, UmbrawgCipher, UmbrawgCmd, UmbrawgDeviceConfig,
    UmbrawgMessage, UmbrawgPeer, UmbrawgPeerAttribute, UmbrawgTimeSpec,
};

fn roundtrip_msg(msg: UmbrawgMessage) -> UmbrawgMessage {
    let header = GenlHeader {
        cmd: msg.cmd.into(),
        version: 2,
    };
    let header_len = header.buffer_len();
    let mut buffer = vec![0; msg.buffer_len() + header_len];
    header.emit(&mut buffer);
    msg.emit(&mut buffer[header_len..]);
    UmbrawgMessage::parse_with_param(&buffer[header_len..], header).unwrap()
}

// nlmon capture of netlink packet sent by `sudo wg` command with netlink
// header purged(generic netlink command is first byte).
#[test]
fn test_query_request() {
    let raw: Vec<u8> = vec![
        0x00, 0x01, 0x00, 0x00, 0x07, 0x00, 0x02, 0x00, 0x63, 0x6e, 0x00, 0x00,
    ];

    let expected: UmbrawgMessage = UmbrawgMessage {
        cmd: UmbrawgCmd::GetDevice,
        attributes: vec![UmbrawgAttribute::IfName("cn".to_string())],
    };

    let header = GenlHeader::parse(&GenlBuffer::new(&raw)).unwrap();

    assert_eq!(
        expected,
        UmbrawgMessage::parse_with_param(&raw[4..], header).unwrap(),
    );
    let mut buffer = vec![0; expected.buffer_len() + header.buffer_len()];
    header.emit(&mut buffer);
    expected.emit(&mut buffer[4..]);
    assert_eq!(&buffer, &raw);
}

// nlmon capture of kernel netlink packet reply of `sudo wg` command with
// netlink header purged(generic netlink command is first byte).
//  * private key is masked to vec![01..31]
//  * ip address is masked to 1.1.1.1:1111
#[test]
fn test_query_reply() {
    let raw: Vec<u8> = vec![
        0x00, 0x01, 0x00, 0x00, 0x06, 0x00, 0x06, 0x00, 0x2c, 0x80, 0x00, 0x00,
        0x08, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x07, 0x00, 0x02, 0x00, 0x63, 0x6e, 0x00, 0x00,
        0x24, 0x00, 0x03, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x24, 0x00, 0x04, 0x00, 0xcc, 0xaf, 0x10, 0xe1, 0xa9, 0xd7, 0xd0, 0x5f,
        0xf2, 0xbd, 0xd2, 0xa0, 0xf1, 0x78, 0x2d, 0x97, 0x46, 0x9a, 0x1c, 0xf7,
        0xbe, 0x88, 0x0f, 0x68, 0x75, 0xa7, 0x79, 0x93, 0x5d, 0x1d, 0x21, 0x75,
        0xc0, 0x00, 0x08, 0x80, 0xbc, 0x00, 0x00, 0x80, 0x24, 0x00, 0x01, 0x00,
        0x77, 0xdc, 0x9a, 0xc0, 0xb3, 0xf0, 0xc5, 0xe7, 0x5b, 0xb8, 0xd3, 0x42,
        0x2d, 0x88, 0xec, 0x92, 0xd1, 0x3a, 0x34, 0x23, 0x22, 0x90, 0x87, 0x82,
        0x15, 0x51, 0x57, 0x19, 0x69, 0xde, 0xa0, 0x44, 0x24, 0x00, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x06, 0x00,
        0x9a, 0x24, 0x77, 0x69, 0x00, 0x00, 0x00, 0x00, 0x02, 0x0e, 0xa8, 0x0f,
        0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x05, 0x00, 0x19, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x08, 0x00, 0x80, 0x40, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x07, 0x00, 0x98, 0x44, 0xd0, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x00, 0x14, 0x00, 0x04, 0x00,
        0x02, 0x00, 0x04, 0x57, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x09, 0x80, 0x1c, 0x00, 0x00, 0x80,
        0x05, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x01, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let attributes = vec![
        UmbrawgAttribute::ListenPort(32812),
        UmbrawgAttribute::Fwmark(0),
        UmbrawgAttribute::IfIndex(3),
        UmbrawgAttribute::IfName("cn".to_string()),
        UmbrawgAttribute::PrivateKey([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
            19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        ]),
        UmbrawgAttribute::PublicKey([
            204, 175, 16, 225, 169, 215, 208, 95, 242, 189, 210, 160, 241, 120,
            45, 151, 70, 154, 28, 247, 190, 136, 15, 104, 117, 167, 121, 147,
            93, 29, 33, 117,
        ]),
        UmbrawgAttribute::Peers(vec![UmbrawgPeer(vec![
            UmbrawgPeerAttribute::PublicKey([
                119, 220, 154, 192, 179, 240, 197, 231, 91, 184, 211, 66, 45,
                136, 236, 146, 209, 58, 52, 35, 34, 144, 135, 130, 21, 81, 87,
                25, 105, 222, 160, 68,
            ]),
            UmbrawgPeerAttribute::PresharedKey([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
            UmbrawgPeerAttribute::LastHandshake(UmbrawgTimeSpec {
                seconds: 1769415834,
                nano_seconds: 262671874,
            }),
            UmbrawgPeerAttribute::PersistentKeepalive(25),
            UmbrawgPeerAttribute::TxBytes(1917056),
            UmbrawgPeerAttribute::RxBytes(30426264),
            UmbrawgPeerAttribute::ProtocolVersion(1),
            UmbrawgPeerAttribute::Endpoint(
                std::net::SocketAddr::from_str("1.1.1.1:1111").unwrap(),
            ),
            UmbrawgPeerAttribute::AllowedIps(vec![UmbrawgAllowedIp(vec![
                UmbrawgAllowedIpAttr::Cidr(0),
                UmbrawgAllowedIpAttr::Family(UmbrawgAddressFamily::Ipv4),
                UmbrawgAllowedIpAttr::IpAddr(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            ])]),
        ])]),
    ];

    let expected: UmbrawgMessage = UmbrawgMessage {
        cmd: UmbrawgCmd::GetDevice,
        attributes,
    };

    let header = GenlHeader::parse(&GenlBuffer::new(&raw)).unwrap();

    assert_eq!(
        expected,
        UmbrawgMessage::parse_with_param(&raw[4..], header).unwrap(),
    );

    let mut buffer = vec![0; expected.buffer_len() + header.buffer_len()];
    header.emit(&mut buffer);
    expected.emit(&mut buffer[4..]);
    assert_eq!(&buffer, &raw);
}

#[test]
fn test_umbra_junk_parameters() {
    // Message with Umbra Specific Junk params
    let msg: UmbrawgMessage = UmbrawgMessage {
        cmd: UmbrawgCmd::SetDevice,
        attributes: vec![
            UmbrawgAttribute::IfName("uwg0".into()),
            UmbrawgAttribute::JC(4),
            UmbrawgAttribute::Jmin(40),
            UmbrawgAttribute::Jmax(70),
        ],
    };

    let mut buffer = vec![0; msg.buffer_len()];
    msg.emit(&mut buffer);

    // Checking Umbra Specific bytes
    // JunkCount (JC) should be 11 (0x0b)
    // Netlink Attribute: [Length (2 bytes), Type (2 bytes), Value (n bytes)]

    assert!(
        buffer
            .windows(6)
            .any(|w| w == [0x06, 0x00, 0x09, 0x00, 0x04, 0x00]),
        "JC failed"
    );

    assert!(
        buffer
            .windows(6)
            .any(|w| w == [0x06, 0x00, 0x0a, 0x00, 0x28, 0x00]),
        "Jmin failed"
    );
}

#[test]
fn test_umbra_magic_headers() {
    let msg: UmbrawgMessage = UmbrawgMessage {
        cmd: UmbrawgCmd::SetDevice,
        attributes: vec![
            UmbrawgAttribute::H1("61220074".into()),
            UmbrawgAttribute::S1(0x5566),
        ],
    };

    let mut buffer = vec![0; msg.buffer_len()];
    msg.emit(&mut buffer);

    // H1 (type 14 / 0x0e): string "61220074" + null, total attr len = 13
    assert!(buffer
        .windows(13)
        .any(|w| w == b"\x0d\x00\x0e\x0061220074\x00"));

    // S1 (type 12 / 0x0c, length 6): [06, 00, 0c, 00, 66, 55]
    assert!(buffer
        .windows(6)
        .any(|w| w == [0x06, 0x00, 0x0c, 0x00, 0x66, 0x55]));
}

#[test]
fn test_set_device_roundtrip() {
    let msg = UmbrawgMessage {
        cmd: UmbrawgCmd::SetDevice,
        attributes: vec![
            UmbrawgAttribute::IfName("uwg0".into()),
            UmbrawgAttribute::ListenPort(51820),
            UmbrawgAttribute::Fwmark(1234),
            UmbrawgAttribute::Flags(1),
        ],
    };

    assert_eq!(msg, roundtrip_msg(msg.clone()));
}

#[test]
fn test_all_umbra_attributes_emit_and_roundtrip() {
    let msg = UmbrawgMessage {
        cmd: UmbrawgCmd::SetDevice,
        attributes: vec![
            UmbrawgAttribute::JC(1),
            UmbrawgAttribute::Jmin(10),
            UmbrawgAttribute::Jmax(100),
            UmbrawgAttribute::S1(0x0102),
            UmbrawgAttribute::S2(0x0304),
            UmbrawgAttribute::S3(0x0506),
            UmbrawgAttribute::S4(0x0708),
            UmbrawgAttribute::H1("61220074".into()),
            UmbrawgAttribute::H2("2351746464".into()),
            UmbrawgAttribute::H3("3053333659".into()),
            UmbrawgAttribute::H4("1789444460".into()),
            UmbrawgAttribute::I1("<r 2>".into()),
            UmbrawgAttribute::I2("".into()),
            UmbrawgAttribute::I3("".into()),
            UmbrawgAttribute::I4("".into()),
            UmbrawgAttribute::I5("".into()),
        ],
    };

    let parsed = roundtrip_msg(msg.clone());
    assert_eq!(msg, parsed);
}

#[test]
fn test_device_config_extra_ports() {
    let msg = UmbrawgDeviceConfig::by_name("uwg0")
        .extra_ports(6)
        .build()
        .expect("valid config");
    assert!(msg.attributes.contains(&UmbrawgAttribute::ExtraPorts(6)));
    let parsed = UmbrawgDeviceConfig::from_message(&msg).expect("parse");
    assert_eq!(parsed, UmbrawgDeviceConfig::by_name("uwg0").extra_ports(6));

    assert!(UmbrawgDeviceConfig::by_name("uwg0")
        .extra_ports(9)
        .build()
        .is_err());
}

#[test]
fn test_uwg31_device_attributes_roundtrip() {
    let msg = UmbrawgMessage {
        cmd: UmbrawgCmd::SetDevice,
        attributes: vec![
            UmbrawgAttribute::IfName("uwg0".into()),
            UmbrawgAttribute::RandomTrailers(true),
            UmbrawgAttribute::DisableCookies(false),
            UmbrawgAttribute::ExtraPorts(4),
        ],
    };

    assert_eq!(msg, roundtrip_msg(msg.clone()));
}

#[test]
fn test_extra_ports_wire_format() {
    use netlink_packet_core::NlaBuffer;

    let attr = UmbrawgAttribute::ExtraPorts(4);
    let mut buf = vec![0; attr.buffer_len()];
    attr.emit(&mut buf);
    // NLA header: len = 5 (4 header + 1 payload), kind = 35, then the u8
    // payload zero-padded to 4-byte alignment.
    assert_eq!(buf, vec![0x05, 0x00, 0x23, 0x00, 0x04, 0x00, 0x00, 0x00]);

    let parsed = UmbrawgAttribute::parse(&NlaBuffer::new(&buf)).unwrap();
    assert_eq!(parsed, UmbrawgAttribute::ExtraPorts(4));

    let attr = UmbrawgAttribute::ExtraPorts(8);
    let mut buf = vec![0; attr.buffer_len()];
    attr.emit(&mut buf);
    let parsed = UmbrawgAttribute::parse(&NlaBuffer::new(&buf)).unwrap();
    assert_eq!(parsed, UmbrawgAttribute::ExtraPorts(8));

    let attr = UmbrawgAttribute::ExtraPorts(0);
    let mut buf = vec![0; attr.buffer_len()];
    attr.emit(&mut buf);
    let parsed = UmbrawgAttribute::parse(&NlaBuffer::new(&buf)).unwrap();
    assert_eq!(parsed, UmbrawgAttribute::ExtraPorts(0));
}

#[test]
fn test_uwg31_attribute_wire_format() {
    use netlink_packet_core::NlaBuffer;

    let attr = UmbrawgAttribute::RandomTrailers(true);
    let mut buf = vec![0; attr.buffer_len()];
    attr.emit(&mut buf);
    // NLA header: len = 5 (4 header + 1 payload), kind = 33, then the u8
    // payload zero-padded to 4-byte alignment.
    assert_eq!(buf, vec![0x05, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00]);

    let parsed = UmbrawgAttribute::parse(&NlaBuffer::new(&buf)).unwrap();
    assert_eq!(parsed, UmbrawgAttribute::RandomTrailers(true));
}

#[test]
fn test_allowed_ips_ipv6_roundtrip() {
    let msg = UmbrawgMessage {
        cmd: UmbrawgCmd::SetDevice,
        attributes: vec![UmbrawgAttribute::Peers(vec![UmbrawgPeer(vec![
            UmbrawgPeerAttribute::PublicKey([42u8; 32]),
            UmbrawgPeerAttribute::AllowedIps(vec![UmbrawgAllowedIp(vec![
                UmbrawgAllowedIpAttr::Family(UmbrawgAddressFamily::Ipv6),
                UmbrawgAllowedIpAttr::IpAddr(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
                UmbrawgAllowedIpAttr::Cidr(0),
            ])]),
        ])])],
    };

    assert_eq!(msg, roundtrip_msg(msg.clone()));
}

#[test]
fn test_multiple_allowed_ips_per_peer() {
    let msg = UmbrawgMessage {
        cmd: UmbrawgCmd::SetDevice,
        attributes: vec![UmbrawgAttribute::Peers(vec![UmbrawgPeer(vec![
            UmbrawgPeerAttribute::PublicKey([7u8; 32]),
            UmbrawgPeerAttribute::AllowedIps(vec![
                UmbrawgAllowedIp(vec![
                    UmbrawgAllowedIpAttr::Family(UmbrawgAddressFamily::Ipv4),
                    UmbrawgAllowedIpAttr::IpAddr(IpAddr::V4(Ipv4Addr::new(
                        10, 0, 0, 0,
                    ))),
                    UmbrawgAllowedIpAttr::Cidr(8),
                ]),
                UmbrawgAllowedIp(vec![
                    UmbrawgAllowedIpAttr::Family(UmbrawgAddressFamily::Ipv6),
                    UmbrawgAllowedIpAttr::IpAddr(IpAddr::V6(Ipv6Addr::new(
                        0xfd00, 0, 0, 0, 0, 0, 0, 1,
                    ))),
                    UmbrawgAllowedIpAttr::Cidr(128),
                ]),
            ]),
        ])])],
    };

    assert_eq!(msg, roundtrip_msg(msg.clone()));
}

#[test]
fn test_peer_with_endpoint_keepalive_and_flags() {
    let msg = UmbrawgMessage {
        cmd: UmbrawgCmd::SetDevice,
        attributes: vec![UmbrawgAttribute::Peers(vec![UmbrawgPeer(vec![
            UmbrawgPeerAttribute::PublicKey([1u8; 32]),
            UmbrawgPeerAttribute::PresharedKey([2u8; 32]),
            UmbrawgPeerAttribute::Endpoint(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                51820,
                0,
                0,
            ))),
            UmbrawgPeerAttribute::PersistentKeepalive(25),
            UmbrawgPeerAttribute::Flags(
                crate::constants::UWGPEER_F_REPLACE_ALLOWEDIPS,
            ),
        ])])],
    };

    assert_eq!(msg, roundtrip_msg(msg.clone()));
}

#[test]
fn test_empty_peers_roundtrip() {
    let msg = UmbrawgMessage {
        cmd: UmbrawgCmd::SetDevice,
        attributes: vec![
            UmbrawgAttribute::IfName("uwg0".into()),
            UmbrawgAttribute::Peers(vec![]),
        ],
    };

    assert_eq!(msg, roundtrip_msg(msg.clone()));
}

#[test]
fn test_full_device_config_roundtrip() {
    let private_key: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
        20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    ];
    let public_key: [u8; 32] = [
        31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14,
        13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
    ];

    let msg = UmbrawgMessage {
        cmd: UmbrawgCmd::SetDevice,
        attributes: vec![
            UmbrawgAttribute::IfIndex(5),
            UmbrawgAttribute::IfName("uwg0".into()),
            UmbrawgAttribute::PrivateKey(private_key),
            UmbrawgAttribute::PublicKey(public_key),
            UmbrawgAttribute::ListenPort(51820),
            UmbrawgAttribute::Fwmark(0),
            UmbrawgAttribute::Flags(
                crate::constants::UWGDEVICE_F_REPLACE_PEERS,
            ),
            // Umbra parameters
            UmbrawgAttribute::JC(4),
            UmbrawgAttribute::Jmin(40),
            UmbrawgAttribute::Jmax(70),
            UmbrawgAttribute::S1(0x1234),
            UmbrawgAttribute::S2(0x5678),
            UmbrawgAttribute::H1("61220074".into()),
            UmbrawgAttribute::H2("6050999999".into()),
            UmbrawgAttribute::Peers(vec![UmbrawgPeer(vec![
                UmbrawgPeerAttribute::PublicKey([0xabu8; 32]),
                UmbrawgPeerAttribute::Endpoint(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                    51820,
                )),
                UmbrawgPeerAttribute::PersistentKeepalive(25),
                UmbrawgPeerAttribute::AllowedIps(vec![UmbrawgAllowedIp(vec![
                    UmbrawgAllowedIpAttr::Family(UmbrawgAddressFamily::Ipv4),
                    UmbrawgAllowedIpAttr::IpAddr(IpAddr::V4(Ipv4Addr::new(
                        0, 0, 0, 0,
                    ))),
                    UmbrawgAllowedIpAttr::Cidr(0),
                ])]),
            ])]),
        ],
    };

    assert_eq!(msg, roundtrip_msg(msg.clone()));
}

/// UmbraWG 3.0 encodes magic headers as packed u64 ranges and keepalive
/// as u32. Parsing must normalize these instead of failing.
#[test]
fn test_parse_v3_magic_headers_and_keepalive() {
    use netlink_packet_core::NlaBuffer;

    use crate::range::u32_range_pack;

    // Device-level: H1 as u64 range, H2 as u64 single value (lo == hi).
    let h1 = u32_range_pack(61220074, 118999195);
    let h2 = u32_range_pack(4, 4);
    let mut raw = Vec::new();
    for (kind, value) in [(14u16, h1), (15u16, h2)] {
        let len = (4 + 8) as u16;
        raw.extend_from_slice(&len.to_le_bytes());
        raw.extend_from_slice(&kind.to_le_bytes());
        raw.extend_from_slice(&value.to_le_bytes());
    }
    let header = GenlHeader {
        cmd: UmbrawgCmd::GetDevice.into(),
        version: 3,
    };
    let parsed = UmbrawgMessage::parse_with_param(&raw, header).unwrap();
    assert_eq!(
        parsed.attributes,
        vec![UmbrawgAttribute::H1Range(h1), UmbrawgAttribute::H2Range(h2),]
    );

    // Peer-level: keepalive as u32 (packed u16 range 25|25<<16).
    let mut peer_nla = Vec::new();
    let keepalive: u32 = 25 | (25 << 16);
    let attr_len = (4 + 4) as u16;
    peer_nla.extend_from_slice(&attr_len.to_le_bytes());
    peer_nla.extend_from_slice(&5u16.to_le_bytes()); // UWGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL
    peer_nla.extend_from_slice(&keepalive.to_le_bytes());
    let buf = NlaBuffer::new_checked(&peer_nla[..]).unwrap();
    let attr = UmbrawgPeerAttribute::parse(&buf).unwrap();
    assert_eq!(
        attr,
        UmbrawgPeerAttribute::PersistentKeepaliveRange(25 | (25 << 16))
    );
}

/// A 7-digit magic header string from a v1.0 module is also 8 bytes on the
/// wire; it must be parsed as a string, not as a u64 range.
#[test]
fn test_parse_v1_magic_header_string_8_bytes() {
    let mut raw = Vec::new();
    let len = (4 + 8) as u16;
    raw.extend_from_slice(&len.to_le_bytes());
    raw.extend_from_slice(&14u16.to_le_bytes()); // UWGDEVICE_A_H1
    raw.extend_from_slice(b"1234567\0");

    let header = GenlHeader {
        cmd: UmbrawgCmd::GetDevice.into(),
        version: 2,
    };
    let parsed = UmbrawgMessage::parse_with_param(&raw, header).unwrap();
    assert_eq!(
        parsed.attributes,
        vec![UmbrawgAttribute::H1("1234567".into())]
    );
}

/// The original UmbraWG (genl version 1) sent magic headers as bare u32.
#[test]
fn test_parse_legacy_magic_header_u32() {
    let mut raw = Vec::new();
    let len = (4 + 4) as u16;
    raw.extend_from_slice(&len.to_le_bytes());
    raw.extend_from_slice(&14u16.to_le_bytes()); // UWGDEVICE_A_H1
    raw.extend_from_slice(&123u32.to_le_bytes());

    let header = GenlHeader {
        cmd: UmbrawgCmd::GetDevice.into(),
        version: 1,
    };
    let parsed = UmbrawgMessage::parse_with_param(&raw, header).unwrap();
    assert_eq!(parsed.attributes, vec![UmbrawgAttribute::H1Legacy(123)]);
}

/// Range variants emit the UmbraWG 3.0 u64 wire format; parsing them back
/// keeps the range representation, so the bytes are unchanged.
#[test]
fn test_magic_header_range_emit() {
    use crate::range::u32_range_pack;

    let msg = UmbrawgMessage {
        cmd: UmbrawgCmd::SetDevice,
        attributes: vec![
            UmbrawgAttribute::H1Range(u32_range_pack(61220074, 118999195)),
            UmbrawgAttribute::H4Range(u32_range_pack(4, 4)),
        ],
    };

    let mut buffer = vec![0; msg.buffer_len()];
    msg.emit(&mut buffer);

    // H1 (type 14 / 0x0e): u64 LE 61220074 | 118999195 << 32
    let mut h1_bytes = vec![0x0c, 0x00, 0x0e, 0x00];
    h1_bytes
        .extend_from_slice(&u32_range_pack(61220074, 118999195).to_le_bytes());
    assert!(buffer
        .windows(h1_bytes.len())
        .any(|w| w == h1_bytes.as_slice()));

    let parsed = roundtrip_msg(msg);
    assert_eq!(
        parsed.attributes,
        vec![
            UmbrawgAttribute::H1Range(u32_range_pack(61220074, 118999195)),
            UmbrawgAttribute::H4Range(u32_range_pack(4, 4)),
        ]
    );
}

#[test]
fn test_magic_header_wire_formats_byte_roundtrip() {
    use crate::range::u32_range_pack;

    let cases = vec![
        UmbrawgAttribute::H1("61220074-118999195".into()),
        UmbrawgAttribute::H2("7".into()),
        UmbrawgAttribute::H3("0".into()),
        UmbrawgAttribute::H4("1234567".into()),
        UmbrawgAttribute::H1Range(u32_range_pack(61220074, 118999195)),
        UmbrawgAttribute::H2Range(u32_range_pack(7, 7)),
        UmbrawgAttribute::H3Range(u32_range_pack(0, 0)),
        UmbrawgAttribute::H4Range(u32_range_pack(1, 118999195)),
        UmbrawgAttribute::H1Legacy(61220074),
        UmbrawgAttribute::H2Legacy(7),
        UmbrawgAttribute::H3Legacy(0),
        UmbrawgAttribute::H4Legacy(u32::MAX),
    ];

    for attr in cases {
        let msg = UmbrawgMessage {
            cmd: UmbrawgCmd::SetDevice,
            attributes: vec![attr.clone()],
        };
        let mut buffer = vec![0; msg.buffer_len()];
        msg.emit(&mut buffer);

        let parsed = roundtrip_msg(msg);
        assert_eq!(parsed.attributes, vec![attr.clone()]);

        let mut reemitted = vec![0; parsed.buffer_len()];
        parsed.emit(&mut reemitted);
        assert_eq!(reemitted, buffer);
    }
}

#[test]
fn test_magic_header_inverted_range_rejected() {
    use crate::range::u32_range_pack;

    let mut raw = Vec::new();
    let len = (4 + 8) as u16;
    raw.extend_from_slice(&len.to_le_bytes());
    raw.extend_from_slice(&14u16.to_le_bytes());
    raw.extend_from_slice(&u32_range_pack(10, 5).to_le_bytes());

    let header = GenlHeader {
        cmd: UmbrawgCmd::GetDevice.into(),
        version: 3,
    };
    assert!(UmbrawgMessage::parse_with_param(&raw, header).is_err());
}

#[test]
fn test_allowed_ip_empty_cidr_payload_is_rejected() {
    use netlink_packet_core::NlaBuffer;

    let raw = [4u8, 0, 3, 0];
    let nla = NlaBuffer::new_checked(&raw[..]).unwrap();
    assert!(UmbrawgAllowedIpAttr::parse(&nla).is_err());
}

#[test]
fn test_v3_device_attributes_roundtrip() {
    let msg = UmbrawgMessage {
        cmd: UmbrawgCmd::SetDevice,
        attributes: vec![
            UmbrawgAttribute::HeaderProtectionKey([7u8; 32]),
            UmbrawgAttribute::ContentPaddingAddition(100),
            UmbrawgAttribute::RekeyAfterTime(120),
            UmbrawgAttribute::RekeyTimeout(5),
            UmbrawgAttribute::RejectAfterTime(180),
            UmbrawgAttribute::KeepaliveTimeout(10),
            UmbrawgAttribute::MaxHandshakeAttempts(3),
        ],
    };

    assert_eq!(msg, roundtrip_msg(msg.clone()));
}

#[test]
fn test_keepalive_range_roundtrip() {
    let msg = UmbrawgMessage {
        cmd: UmbrawgCmd::SetDevice,
        attributes: vec![UmbrawgAttribute::Peers(vec![UmbrawgPeer(vec![
            UmbrawgPeerAttribute::PublicKey([3u8; 32]),
            UmbrawgPeerAttribute::PersistentKeepaliveRange(25 | (30 << 16)),
        ])])],
    };

    assert_eq!(msg, roundtrip_msg(msg.clone()));
}

#[test]
fn test_peer_advanced_security_roundtrip() {
    let msg = UmbrawgMessage {
        cmd: UmbrawgCmd::SetDevice,
        attributes: vec![UmbrawgAttribute::Peers(vec![UmbrawgPeer(vec![
            UmbrawgPeerAttribute::PublicKey([9u8; 32]),
            UmbrawgPeerAttribute::AdvancedSecurity(true),
        ])])],
    };

    assert_eq!(msg, roundtrip_msg(msg.clone()));
}

#[test]
fn test_peer_advanced_security_wire_format() {
    use netlink_packet_core::NlaBuffer;

    let attr = UmbrawgPeerAttribute::AdvancedSecurity(true);
    let mut buf = vec![0xff; attr.buffer_len()];
    attr.emit(&mut buf);
    // NLA_FLAG: four-byte header, kind 11, empty payload.
    assert_eq!(buf, vec![0x04, 0x00, 0x0b, 0x00]);

    let parsed = UmbrawgPeerAttribute::parse(&NlaBuffer::new(&buf)).unwrap();
    assert_eq!(parsed, UmbrawgPeerAttribute::AdvancedSecurity(true));
}

#[test]
fn test_peer_advanced_security_false_is_not_emitted() {
    let with_flag = UmbrawgMessage {
        cmd: UmbrawgCmd::SetDevice,
        attributes: vec![UmbrawgAttribute::Peers(vec![UmbrawgPeer(vec![
            UmbrawgPeerAttribute::PublicKey([9u8; 32]),
            UmbrawgPeerAttribute::AdvancedSecurity(false),
        ])])],
    };
    let without_flag = UmbrawgMessage {
        cmd: UmbrawgCmd::SetDevice,
        attributes: vec![UmbrawgAttribute::Peers(vec![UmbrawgPeer(vec![
            UmbrawgPeerAttribute::PublicKey([9u8; 32]),
        ])])],
    };

    let mut buffer = vec![0; with_flag.buffer_len()];
    with_flag.emit(&mut buffer);
    assert!(!buffer.windows(4).any(|w| w == [0x04, 0x00, 0x0b, 0x00]));

    let mut expected = vec![0; without_flag.buffer_len()];
    without_flag.emit(&mut expected);
    assert_eq!(buffer, expected);
}

#[test]
fn test_peer_cipher_roundtrip() {
    let msg = UmbrawgMessage {
        cmd: UmbrawgCmd::SetDevice,
        attributes: vec![UmbrawgAttribute::Peers(vec![UmbrawgPeer(vec![
            UmbrawgPeerAttribute::PublicKey([9u8; 32]),
            UmbrawgPeerAttribute::Cipher(UmbrawgCipher::Aes256Gcm),
        ])])],
    };

    assert_eq!(msg, roundtrip_msg(msg.clone()));
}

#[test]
fn test_peer_cipher_wire_format() {
    use netlink_packet_core::NlaBuffer;

    let attr = UmbrawgPeerAttribute::Cipher(UmbrawgCipher::Aes256Gcm);
    let mut buf = vec![0xff; attr.buffer_len()];
    attr.emit(&mut buf);
    // NLA_U32: four-byte header, kind 12, little-endian payload 1.
    assert_eq!(buf, vec![0x08, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00]);

    let parsed = UmbrawgPeerAttribute::parse(&NlaBuffer::new(&buf)).unwrap();
    assert_eq!(parsed, attr);
}

#[test]
fn test_peer_cipher_rejects_unknown_value() {
    use netlink_packet_core::NlaBuffer;

    let raw = vec![0x08, 0x00, 0x0c, 0x00, 0x02, 0x00, 0x00, 0x00];
    assert!(UmbrawgPeerAttribute::parse(&NlaBuffer::new(&raw)).is_err());
}

#[test]
fn test_cipher_constants() {
    assert_eq!(UmbrawgCipher::ChaCha20Poly1305.as_u32(), 0);
    assert_eq!(UmbrawgCipher::Aes256Gcm.as_u32(), 1);
    assert_eq!(
        UmbrawgCipher::from_u32(0),
        Some(UmbrawgCipher::ChaCha20Poly1305)
    );
    assert_eq!(UmbrawgCipher::from_u32(1), Some(UmbrawgCipher::Aes256Gcm));
    assert_eq!(UmbrawgCipher::from_u32(2), None);
    assert_eq!(UmbrawgCipher::default(), UmbrawgCipher::ChaCha20Poly1305);
    assert_eq!(UmbrawgCipher::Aes256Gcm.to_string(), "aes-256-gcm");
}

#[test]
fn test_parse_get_device_reply_with_has_advanced_security() {
    let mut peer = Vec::new();
    // UWGPEER_A_FLAGS (kind 3) = UWGPEER_F_HAS_ADVANCED_SECURITY (8)
    peer.extend_from_slice(&[0x08, 0x00, 0x03, 0x00]);
    peer.extend_from_slice(&8u32.to_le_bytes());
    // UWGPEER_A_ADVANCED_SECURITY (kind 11), NLA_FLAG with empty payload
    peer.extend_from_slice(&[0x04, 0x00, 0x0b, 0x00]);

    // Peer element nested with type 0, as written by the kernel.
    let mut peers = Vec::new();
    peers.extend_from_slice(&((4 + peer.len()) as u16).to_le_bytes());
    peers.extend_from_slice(&0u16.to_le_bytes());
    peers.extend_from_slice(&peer);

    // UWGDEVICE_A_PEERS (kind 8) nested.
    let mut raw = Vec::new();
    raw.extend_from_slice(&((4 + peers.len()) as u16).to_le_bytes());
    raw.extend_from_slice(&(8u16 | 0x8000).to_le_bytes());
    raw.extend_from_slice(&peers);

    let header = GenlHeader {
        cmd: UmbrawgCmd::GetDevice.into(),
        version: 3,
    };
    let parsed = UmbrawgMessage::parse_with_param(&raw, header).unwrap();
    assert_eq!(
        parsed,
        UmbrawgMessage {
            cmd: UmbrawgCmd::GetDevice,
            attributes: vec![UmbrawgAttribute::Peers(vec![UmbrawgPeer(vec![
                UmbrawgPeerAttribute::Flags(
                    crate::constants::UWGPEER_F_HAS_ADVANCED_SECURITY
                ),
                UmbrawgPeerAttribute::AdvancedSecurity(true),
            ])])],
        }
    );
}

#[test]
fn test_allowed_ip_flags_remove_me_roundtrip() {
    use netlink_packet_core::NlaBuffer;

    let attr =
        UmbrawgAllowedIpAttr::Flags(crate::constants::UWGALLOWEDIP_F_REMOVE_ME);
    let mut buf = vec![0xff; attr.buffer_len()];
    attr.emit(&mut buf);
    // NLA header: len 8, kind 4, u32 little-endian 1.
    assert_eq!(buf, vec![0x08, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00]);

    let parsed = UmbrawgAllowedIpAttr::parse(&NlaBuffer::new(&buf)).unwrap();
    assert_eq!(
        parsed,
        UmbrawgAllowedIpAttr::Flags(crate::constants::UWGALLOWEDIP_F_REMOVE_ME)
    );

    let msg = UmbrawgMessage {
        cmd: UmbrawgCmd::SetDevice,
        attributes: vec![UmbrawgAttribute::Peers(vec![UmbrawgPeer(vec![
            UmbrawgPeerAttribute::PublicKey([5u8; 32]),
            UmbrawgPeerAttribute::AllowedIps(vec![UmbrawgAllowedIp(vec![
                UmbrawgAllowedIpAttr::Family(UmbrawgAddressFamily::Ipv4),
                UmbrawgAllowedIpAttr::IpAddr(IpAddr::V4(Ipv4Addr::new(
                    10, 0, 0, 1,
                ))),
                UmbrawgAllowedIpAttr::Cidr(32),
                UmbrawgAllowedIpAttr::Flags(
                    crate::constants::UWGALLOWEDIP_F_REMOVE_ME,
                ),
            ])]),
        ])])],
    };

    assert_eq!(msg, roundtrip_msg(msg.clone()));
}

#[test]
fn test_unknown_peer_parse_and_emit() {
    fn nla(kind: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = ((4 + payload.len()) as u16).to_le_bytes().to_vec();
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(payload);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }

    let ifindex: u32 = 7;
    let peer_key = [3u8; 32];
    let sockaddr: Vec<u8> =
        vec![0x02, 0x00, 0xca, 0x6c, 10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];

    let mut peer = Vec::new();
    peer.extend_from_slice(&nla(1, &peer_key));
    peer.extend_from_slice(&nla(4, &sockaddr));
    peer.extend_from_slice(&nla(11, &[]));

    let mut raw = Vec::new();
    raw.extend_from_slice(&nla(1, &ifindex.to_le_bytes()));
    raw.extend_from_slice(&nla(2, b"uwg0\0"));
    raw.extend_from_slice(&nla(0x8012, &peer));

    let expected = UmbrawgMessage {
        cmd: UmbrawgCmd::UnknownPeer,
        attributes: vec![
            UmbrawgAttribute::IfIndex(7),
            UmbrawgAttribute::IfName("uwg0".into()),
            UmbrawgAttribute::Peer(UmbrawgPeer(vec![
                UmbrawgPeerAttribute::PublicKey(peer_key),
                UmbrawgPeerAttribute::Endpoint(
                    "10.0.0.1:51820".parse().unwrap(),
                ),
                UmbrawgPeerAttribute::AdvancedSecurity(true),
            ])),
        ],
    };

    let header = GenlHeader {
        cmd: UmbrawgCmd::UnknownPeer.into(),
        version: 3,
    };
    assert_eq!(
        expected,
        UmbrawgMessage::parse_with_param(&raw, header).unwrap()
    );

    let mut buffer = vec![0; expected.buffer_len()];
    expected.emit(&mut buffer);
    assert_eq!(buffer, raw);
}

#[test]
fn test_unknown_peer_command_conversion() {
    assert_eq!(
        u8::from(UmbrawgCmd::UnknownPeer),
        crate::constants::UWG_CMD_UNKNOWN_PEER
    );
    assert_eq!(u8::from(UmbrawgCmd::UnknownPeer), 2);
    assert_eq!(UmbrawgCmd::from(2), UmbrawgCmd::UnknownPeer);
    assert_eq!(UmbrawgCmd::from(0), UmbrawgCmd::GetDevice);
    assert_eq!(UmbrawgCmd::from(1), UmbrawgCmd::SetDevice);
}
