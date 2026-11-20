// SPDX-License-Identifier: MIT

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    str::FromStr,
};

use netlink_packet_core::{DefaultNla, Emitable, ParseableParametrized};
use netlink_packet_generic::GenlHeader;
use netlink_packet_umbrawg::{
    constants::{
        UWGALLOWEDIP_F_REMOVE_ME, UWGDEVICE_F_REPLACE_PEERS,
        UWGPEER_F_HAS_ADVANCED_SECURITY, UWGPEER_F_REMOVE_ME,
        UWGPEER_F_REPLACE_ALLOWEDIPS, UWGPEER_F_UPDATE_ONLY,
    },
    range::{u16_range_pack, u32_range_pack},
    BbrMode, FecMode, UmbrawgAddressFamily, UmbrawgAllowedIp,
    UmbrawgAllowedIpAttr, UmbrawgAttribute, UmbrawgCipher, UmbrawgCmd,
    UmbrawgConfigError, UmbrawgDeviceConfig, UmbrawgMagicHeader,
    UmbrawgMessage, UmbrawgPeer, UmbrawgPeerAttribute, UmbrawgPeerConfig,
    UmbrawgTimeSpec, HEADER_PROTECTION_NONCE_LEN, INTERMEDIATE_SPEC_MAX_LEN,
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

fn full_device() -> UmbrawgDeviceConfig {
    UmbrawgDeviceConfig::by_name("uwg0")
        .private_key([1u8; 32])
        .listen_port(51820)
        .fwmark(0)
        .replace_peers()
        .junk(4, 40, 70)
        .padding(12, 12, 12, 12)
        .h1(61220074, 118999195)
        .h2(2351746464, 2351746464)
        .h3(3053333659, 3053333659)
        .h4(1789444460, 1789444460)
        .i1("<r 2>")
        .i2("<b 4>")
        .i3("")
        .i4("")
        .i5("")
        .header_protection_key([5u8; 32])
        .content_padding_addition(51, 197)
        .rekey_after_time(104, 149)
        .rekey_timeout(5, 8)
        .reject_after_time(184, 199)
        .keepalive_timeout(9, 12)
        .max_handshake_attempts(18, 23)
        .random_trailers(true)
        .disable_cookies(false)
}

fn full_peer() -> UmbrawgPeerConfig {
    UmbrawgPeerConfig::new([7u8; 32])
        .preshared_key([8u8; 32])
        .endpoint_v4(Ipv4Addr::new(10, 0, 0, 1), 51820)
        .persistent_keepalive(25)
        .replace_allowed_ips()
        .allowed_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        .unwrap()
        .allowed_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        .unwrap()
        .advanced_security(true)
        .cipher(UmbrawgCipher::Aes256Gcm)
}

#[test]
fn builds_full_device_message() {
    let msg = full_device().peer(full_peer()).build().unwrap();

    assert_eq!(msg.cmd, UmbrawgCmd::SetDevice);
    assert_eq!(
        msg.attributes,
        vec![
            UmbrawgAttribute::IfName("uwg0".into()),
            UmbrawgAttribute::PrivateKey([1u8; 32]),
            UmbrawgAttribute::ListenPort(51820),
            UmbrawgAttribute::Fwmark(0),
            UmbrawgAttribute::Flags(UWGDEVICE_F_REPLACE_PEERS),
            UmbrawgAttribute::H1Range(u32_range_pack(61220074, 118999195)),
            UmbrawgAttribute::H2Range(u32_range_pack(2351746464, 2351746464)),
            UmbrawgAttribute::H3Range(u32_range_pack(3053333659, 3053333659)),
            UmbrawgAttribute::H4Range(u32_range_pack(1789444460, 1789444460)),
            UmbrawgAttribute::JC(4),
            UmbrawgAttribute::Jmin(40),
            UmbrawgAttribute::Jmax(70),
            UmbrawgAttribute::S1(12),
            UmbrawgAttribute::S2(12),
            UmbrawgAttribute::S3(12),
            UmbrawgAttribute::S4(12),
            UmbrawgAttribute::I1("<r 2>".into()),
            UmbrawgAttribute::I2("<b 4>".into()),
            UmbrawgAttribute::I3("".into()),
            UmbrawgAttribute::I4("".into()),
            UmbrawgAttribute::I5("".into()),
            UmbrawgAttribute::HeaderProtectionKey([5u8; 32]),
            UmbrawgAttribute::ContentPaddingAddition(u16_range_pack(51, 197)),
            UmbrawgAttribute::RekeyAfterTime(u16_range_pack(104, 149)),
            UmbrawgAttribute::RekeyTimeout(u16_range_pack(5, 8)),
            UmbrawgAttribute::RejectAfterTime(u16_range_pack(184, 199)),
            UmbrawgAttribute::KeepaliveTimeout(u16_range_pack(9, 12)),
            UmbrawgAttribute::MaxHandshakeAttempts(u16_range_pack(18, 23)),
            UmbrawgAttribute::RandomTrailers(true),
            UmbrawgAttribute::DisableCookies(false),
            UmbrawgAttribute::Peers(vec![UmbrawgPeer(vec![
                UmbrawgPeerAttribute::PublicKey([7u8; 32]),
                UmbrawgPeerAttribute::PresharedKey([8u8; 32]),
                UmbrawgPeerAttribute::Flags(UWGPEER_F_REPLACE_ALLOWEDIPS),
                UmbrawgPeerAttribute::Endpoint(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    51820,
                )),
                UmbrawgPeerAttribute::PersistentKeepaliveRange(u16_range_pack(
                    25, 25
                )),
                UmbrawgPeerAttribute::AdvancedSecurity(true),
                UmbrawgPeerAttribute::Cipher(UmbrawgCipher::Aes256Gcm),
                UmbrawgPeerAttribute::AllowedIps(vec![
                    UmbrawgAllowedIp(vec![
                        UmbrawgAllowedIpAttr::Family(
                            UmbrawgAddressFamily::Ipv4
                        ),
                        UmbrawgAllowedIpAttr::IpAddr(IpAddr::V4(
                            Ipv4Addr::UNSPECIFIED
                        )),
                        UmbrawgAllowedIpAttr::Cidr(0),
                    ]),
                    UmbrawgAllowedIp(vec![
                        UmbrawgAllowedIpAttr::Family(
                            UmbrawgAddressFamily::Ipv6
                        ),
                        UmbrawgAllowedIpAttr::IpAddr(IpAddr::V6(
                            Ipv6Addr::UNSPECIFIED
                        )),
                        UmbrawgAllowedIpAttr::Cidr(0),
                    ]),
                ]),
            ])]),
        ]
    );
}

#[test]
fn full_device_message_survives_wire_roundtrip() {
    let msg = full_device().peer(full_peer()).build().unwrap();
    let parsed = roundtrip_msg(msg.clone());

    assert_eq!(parsed.cmd, msg.cmd);
    assert_eq!(parsed.attributes.len(), msg.attributes.len());
    assert_eq!(
        parsed
            .attributes
            .iter()
            .filter(|attr| matches!(attr, UmbrawgAttribute::Peers(_)))
            .count(),
        1
    );
}

#[test]
fn device_config_message_config_roundtrip() {
    let config = full_device().peer(full_peer());
    let first = config.clone().build().unwrap();
    let restored = UmbrawgDeviceConfig::from_message(&first).unwrap();
    let second = restored.clone().build().unwrap();

    assert_eq!(first, second);
    assert_eq!(restored, config);
}

#[test]
fn device_config_try_from_message() {
    let msg = full_device().build().unwrap();
    let config = UmbrawgDeviceConfig::try_from(&msg).unwrap();
    assert_eq!(config.clone().build().unwrap(), msg);
    assert_eq!(UmbrawgDeviceConfig::try_from(msg.clone()).unwrap(), config);
}

#[test]
fn device_by_index_emits_index_only() {
    let msg = UmbrawgDeviceConfig::by_index(5)
        .listen_port(0)
        .build()
        .unwrap();
    assert_eq!(
        msg.attributes,
        vec![
            UmbrawgAttribute::IfIndex(5),
            UmbrawgAttribute::ListenPort(0),
        ]
    );
}

#[test]
fn empty_peer_list_is_not_emitted() {
    let msg = UmbrawgDeviceConfig::by_name("uwg0").build().unwrap();
    assert_eq!(
        msg.attributes,
        vec![UmbrawgAttribute::IfName("uwg0".into())]
    );
}

#[test]
fn empty_allowed_ips_with_replace_flag_are_emitted() {
    let peer = UmbrawgPeerConfig::new([1u8; 32])
        .replace_allowed_ips()
        .build()
        .unwrap();
    assert_eq!(
        peer.0,
        vec![
            UmbrawgPeerAttribute::PublicKey([1u8; 32]),
            UmbrawgPeerAttribute::Flags(UWGPEER_F_REPLACE_ALLOWEDIPS),
            UmbrawgPeerAttribute::AllowedIps(vec![]),
        ]
    );
}

#[test]
fn peer_without_optional_attributes() {
    let peer = UmbrawgPeerConfig::new([1u8; 32]).build().unwrap();
    assert_eq!(peer.0, vec![UmbrawgPeerAttribute::PublicKey([1u8; 32])]);
}

#[test]
fn missing_interface_is_rejected() {
    assert_eq!(
        UmbrawgDeviceConfig::new().build(),
        Err(UmbrawgConfigError::MissingInterface)
    );
}

#[test]
fn conflicting_interface_is_rejected() {
    let result = UmbrawgDeviceConfig::by_name("uwg0").if_index(3).build();
    assert_eq!(result, Err(UmbrawgConfigError::ConflictingInterface));
}

#[test]
fn invalid_interface_names_are_rejected() {
    for name in ["", "abcdefghijklmnop", "uwg\0x"] {
        let result = UmbrawgDeviceConfig::by_name(name).build();
        assert_eq!(
            result,
            Err(UmbrawgConfigError::InvalidInterfaceName {
                name: name.to_string(),
            }),
            "name {name:?}"
        );
    }
}

#[test]
fn maximal_interface_name_is_accepted() {
    let msg = UmbrawgDeviceConfig::by_name("abcdefghijklmno")
        .build()
        .unwrap();
    assert_eq!(
        msg.attributes,
        vec![UmbrawgAttribute::IfName("abcdefghijklmno".into())]
    );
}

#[test]
fn private_key_length_is_validated() {
    assert_eq!(
        UmbrawgDeviceConfig::by_name("uwg0").try_private_key(&[0u8; 31]),
        Err(UmbrawgConfigError::InvalidKeyLength {
            field: "private key",
            expected: 32,
            actual: 31,
        })
    );
    assert_eq!(
        UmbrawgDeviceConfig::by_name("uwg0").try_private_key(&[0u8; 33]),
        Err(UmbrawgConfigError::InvalidKeyLength {
            field: "private key",
            expected: 32,
            actual: 33,
        })
    );
    let msg = UmbrawgDeviceConfig::by_name("uwg0")
        .try_private_key(&[3u8; 32])
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(msg.attributes[1], UmbrawgAttribute::PrivateKey([3u8; 32]));
}

#[test]
fn header_protection_key_length_is_validated() {
    assert_eq!(
        UmbrawgDeviceConfig::by_name("uwg0")
            .try_header_protection_key(&[0u8; 16]),
        Err(UmbrawgConfigError::InvalidKeyLength {
            field: "header protection key",
            expected: 32,
            actual: 16,
        })
    );
    assert!(UmbrawgDeviceConfig::by_name("uwg0")
        .try_header_protection_key(&[0u8; 32])
        .is_ok());
}

#[test]
fn peer_key_lengths_are_validated() {
    assert_eq!(
        UmbrawgPeerConfig::try_new(&[0u8; 31]),
        Err(UmbrawgConfigError::InvalidKeyLength {
            field: "peer public key",
            expected: 32,
            actual: 31,
        })
    );
    let config = UmbrawgPeerConfig::try_new(&[1u8; 32]).unwrap();
    assert_eq!(
        config.clone().try_preshared_key(&[0u8; 0]),
        Err(UmbrawgConfigError::InvalidKeyLength {
            field: "preshared key",
            expected: 32,
            actual: 0,
        })
    );
    let peer = config
        .try_preshared_key(&[2u8; 32])
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(peer.0[1], UmbrawgPeerAttribute::PresharedKey([2u8; 32]));
}

#[test]
fn cleared_preshared_key_emits_zeros() {
    let peer = UmbrawgPeerConfig::new([1u8; 32])
        .preshared_key([9u8; 32])
        .clear_preshared_key()
        .build()
        .unwrap();
    assert_eq!(peer.0[1], UmbrawgPeerAttribute::PresharedKey([0u8; 32]));
}

#[test]
fn junk_bounds_are_validated() {
    assert_eq!(
        UmbrawgDeviceConfig::by_name("uwg0").junk(1, 71, 70).build(),
        Err(UmbrawgConfigError::InvalidRange {
            field: "Jmin/Jmax",
            lo: 71,
            hi: 70,
        })
    );
    assert!(UmbrawgDeviceConfig::by_name("uwg0")
        .junk(0, 70, 70)
        .build()
        .is_ok());
    assert!(UmbrawgDeviceConfig::by_name("uwg0")
        .junk(u16::MAX, 0, u16::MAX)
        .build()
        .is_ok());
}

#[test]
fn inverted_magic_header_range_is_rejected() {
    assert_eq!(
        UmbrawgDeviceConfig::by_name("uwg0").h3(10, 9).build(),
        Err(UmbrawgConfigError::InvalidMagicHeaderRange {
            header: UmbrawgMagicHeader::H3,
            lo: 10,
            hi: 9,
        })
    );
    assert!(UmbrawgDeviceConfig::by_name("uwg0")
        .h3(9, 9)
        .build()
        .is_ok());
    assert!(UmbrawgDeviceConfig::by_name("uwg0")
        .h3(0, u32::MAX)
        .build()
        .is_ok());
}

#[test]
fn overlapping_magic_headers_are_rejected() {
    let result = UmbrawgDeviceConfig::by_name("uwg0")
        .h1(10, 20)
        .h2(20, 30)
        .build();
    assert_eq!(
        result,
        Err(UmbrawgConfigError::OverlappingMagicHeaders {
            first: UmbrawgMagicHeader::H1,
            second: UmbrawgMagicHeader::H2,
        })
    );

    let adjacent = UmbrawgDeviceConfig::by_name("uwg0")
        .h1(10, 20)
        .h2(21, 30)
        .h2(21, 30)
        .h3(31, 40)
        .h4(41, 50)
        .build();
    assert!(adjacent.is_ok());
}

#[test]
fn magic_header_spec_is_parsed() {
    let msg = UmbrawgDeviceConfig::by_name("uwg0")
        .magic_header_spec(UmbrawgMagicHeader::H1, "61220074-118999195")
        .unwrap()
        .magic_header_spec(UmbrawgMagicHeader::H2, "7")
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(
        msg.attributes[1..],
        [
            UmbrawgAttribute::H1Range(u32_range_pack(61220074, 118999195)),
            UmbrawgAttribute::H2Range(u32_range_pack(7, 7)),
        ]
    );

    for spec in ["", "abc", "10-5", "1-2-3"] {
        assert_eq!(
            UmbrawgDeviceConfig::by_name("uwg0")
                .magic_header_spec(UmbrawgMagicHeader::H4, spec),
            Err(UmbrawgConfigError::InvalidMagicHeaderSpec {
                header: UmbrawgMagicHeader::H4,
                spec: spec.to_string(),
            }),
            "spec {spec:?}"
        );
    }
}

#[test]
fn padding_below_header_protection_nonce_is_rejected() {
    let result = UmbrawgDeviceConfig::by_name("uwg0")
        .header_protection_key([1u8; 32])
        .s1(HEADER_PROTECTION_NONCE_LEN - 1)
        .build();
    assert_eq!(
        result,
        Err(UmbrawgConfigError::PaddingBelowHeaderProtectionNonce {
            field: "S1",
            value: HEADER_PROTECTION_NONCE_LEN - 1,
            min: HEADER_PROTECTION_NONCE_LEN,
        })
    );

    assert!(UmbrawgDeviceConfig::by_name("uwg0")
        .header_protection_key([1u8; 32])
        .padding(
            HEADER_PROTECTION_NONCE_LEN,
            HEADER_PROTECTION_NONCE_LEN,
            HEADER_PROTECTION_NONCE_LEN,
            HEADER_PROTECTION_NONCE_LEN,
        )
        .build()
        .is_ok());

    assert!(UmbrawgDeviceConfig::by_name("uwg0")
        .padding(0, 0, 0, 0)
        .build()
        .is_ok());
}

#[test]
fn intermediate_specs_are_validated() {
    assert_eq!(
        UmbrawgDeviceConfig::by_name("uwg0").i2("a\0b").build(),
        Err(UmbrawgConfigError::IntermediateSpecContainsNul { field: "I2" })
    );

    let too_long = "x".repeat(INTERMEDIATE_SPEC_MAX_LEN + 1);
    assert_eq!(
        UmbrawgDeviceConfig::by_name("uwg0")
            .i5(too_long.clone())
            .build(),
        Err(UmbrawgConfigError::IntermediateSpecTooLong {
            field: "I5",
            len: INTERMEDIATE_SPEC_MAX_LEN + 1,
            max: INTERMEDIATE_SPEC_MAX_LEN,
        })
    );

    let max = "x".repeat(INTERMEDIATE_SPEC_MAX_LEN);
    assert!(UmbrawgDeviceConfig::by_name("uwg0").i5(max).build().is_ok());
}

#[test]
fn inverted_tuning_ranges_are_rejected() {
    let cases: [(&str, UmbrawgDeviceConfig); 6] = [
        (
            "ContentPaddingAddition",
            UmbrawgDeviceConfig::by_name("uwg0")
                .content_padding_addition(10, 9),
        ),
        (
            "RekeyAfterTime",
            UmbrawgDeviceConfig::by_name("uwg0").rekey_after_time(10, 9),
        ),
        (
            "RekeyTimeout",
            UmbrawgDeviceConfig::by_name("uwg0").rekey_timeout(10, 9),
        ),
        (
            "RejectAfterTime",
            UmbrawgDeviceConfig::by_name("uwg0").reject_after_time(10, 9),
        ),
        (
            "KeepaliveTimeout",
            UmbrawgDeviceConfig::by_name("uwg0").keepalive_timeout(10, 9),
        ),
        (
            "MaxHandshakeAttempts",
            UmbrawgDeviceConfig::by_name("uwg0").max_handshake_attempts(10, 9),
        ),
    ];

    for (field, config) in cases {
        assert_eq!(
            config.build(),
            Err(UmbrawgConfigError::InvalidRange {
                field,
                lo: 10,
                hi: 9,
            }),
            "field {field}"
        );
    }
}

#[test]
fn unsupported_device_flags_are_rejected() {
    assert_eq!(
        UmbrawgDeviceConfig::by_name("uwg0").flags(1 << 1).build(),
        Err(UmbrawgConfigError::UnsupportedFlags {
            field: "UWGDEVICE_A_FLAGS",
            flags: 1 << 1,
        })
    );
    assert!(UmbrawgDeviceConfig::by_name("uwg0")
        .flags(UWGDEVICE_F_REPLACE_PEERS)
        .build()
        .is_ok());
}

#[test]
fn inverted_keepalive_range_is_rejected() {
    let result = UmbrawgPeerConfig::new([1u8; 32])
        .persistent_keepalive_range(30, 25)
        .build();
    assert_eq!(
        result,
        Err(UmbrawgConfigError::InvalidRange {
            field: "persistent keepalive",
            lo: 30,
            hi: 25,
        })
    );
    assert!(UmbrawgPeerConfig::new([1u8; 32])
        .persistent_keepalive_range(25, 30)
        .build()
        .is_ok());
}

#[test]
fn legacy_keepalive_uses_u16_wire_format() {
    let peer = UmbrawgPeerConfig::new([1u8; 32])
        .persistent_keepalive_legacy(25)
        .build()
        .unwrap();
    assert_eq!(peer.0[1], UmbrawgPeerAttribute::PersistentKeepalive(25));

    let msg = UmbrawgDeviceConfig::by_name("uwg0")
        .peer(UmbrawgPeerConfig::new([1u8; 32]).persistent_keepalive_legacy(25))
        .build()
        .unwrap();
    assert_eq!(roundtrip_msg(msg.clone()), msg);
}

#[test]
fn unsupported_peer_flags_are_rejected() {
    assert_eq!(
        UmbrawgPeerConfig::new([1u8; 32]).flags(1 << 5).build(),
        Err(UmbrawgConfigError::UnsupportedFlags {
            field: "UWGPEER_A_FLAGS",
            flags: 1 << 5,
        })
    );
    assert!(UmbrawgPeerConfig::new([1u8; 32])
        .flags(
            UWGPEER_F_REMOVE_ME
                | UWGPEER_F_REPLACE_ALLOWEDIPS
                | UWGPEER_F_UPDATE_ONLY,
        )
        .build()
        .is_ok());
}

#[test]
fn protocol_version_is_validated() {
    assert_eq!(
        UmbrawgPeerConfig::new([1u8; 32])
            .protocol_version(2)
            .build(),
        Err(UmbrawgConfigError::UnsupportedProtocolVersion { version: 2 })
    );
    assert!(UmbrawgPeerConfig::new([1u8; 32])
        .protocol_version(1)
        .build()
        .is_ok());
}

#[test]
fn remove_peer_sets_remove_flag() {
    let peer = UmbrawgPeerConfig::new([1u8; 32]).remove().build().unwrap();
    assert_eq!(
        peer.0,
        vec![
            UmbrawgPeerAttribute::PublicKey([1u8; 32]),
            UmbrawgPeerAttribute::Flags(UWGPEER_F_REMOVE_ME),
        ]
    );
}

#[test]
fn allowed_ip_cidr_bounds_are_validated() {
    assert_eq!(
        UmbrawgAllowedIp::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 33),
        Err(UmbrawgConfigError::InvalidCidr {
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            cidr: 33,
            max: 32,
        })
    );
    assert_eq!(
        UmbrawgAllowedIp::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 129),
        Err(UmbrawgConfigError::InvalidCidr {
            address: IpAddr::V6(Ipv6Addr::LOCALHOST),
            cidr: 129,
            max: 128,
        })
    );
    assert!(UmbrawgAllowedIp::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 32).is_ok());
    assert!(UmbrawgAllowedIp::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 128).is_ok());

    assert_eq!(
        UmbrawgPeerConfig::new([1u8; 32])
            .allowed_ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 64),
        Err(UmbrawgConfigError::InvalidCidr {
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            cidr: 64,
            max: 32,
        })
    );
}

#[test]
fn allowed_ip_spec_parsing() {
    let with_prefix = UmbrawgAllowedIp::from_spec("10.1.2.3/24").unwrap();
    assert_eq!(
        with_prefix,
        UmbrawgAllowedIp(vec![
            UmbrawgAllowedIpAttr::Family(UmbrawgAddressFamily::Ipv4),
            UmbrawgAllowedIpAttr::IpAddr("10.1.2.3".parse().unwrap()),
            UmbrawgAllowedIpAttr::Cidr(24),
        ])
    );
    assert_eq!(with_prefix.ip_addr(), Some("10.1.2.3".parse().unwrap()));
    assert_eq!(with_prefix.cidr(), Some(24));
    assert_eq!(with_prefix.family(), Some(UmbrawgAddressFamily::Ipv4));
    assert!(!with_prefix.is_remove());

    let v6 = UmbrawgAllowedIp::from_str("fd00::1").unwrap();
    assert_eq!(v6.cidr(), Some(128));
    assert_eq!(v6.family(), Some(UmbrawgAddressFamily::Ipv6));

    assert_eq!(
        UmbrawgAllowedIp::from_spec("10.0.0.0/33"),
        Err(UmbrawgConfigError::InvalidCidr {
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            cidr: 33,
            max: 32,
        })
    );
    for spec in ["", "10.0.0.0/", "10.0.0.0/x", "not-an-ip", "/24"] {
        assert_eq!(
            UmbrawgAllowedIp::from_spec(spec),
            Err(UmbrawgConfigError::InvalidAllowedIpSpec {
                spec: spec.to_string(),
            }),
            "spec {spec:?}"
        );
    }
}

#[test]
fn removed_allowed_ip_carries_flag() {
    let allowed_ip =
        UmbrawgAllowedIp::remove(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 32)
            .unwrap();
    assert!(allowed_ip.is_remove());
    assert_eq!(allowed_ip.0.len(), 4);
    assert_eq!(
        allowed_ip.0[3],
        UmbrawgAllowedIpAttr::Flags(UWGALLOWEDIP_F_REMOVE_ME)
    );

    let msg = UmbrawgDeviceConfig::by_name("uwg0")
        .peer(
            UmbrawgPeerConfig::new([1u8; 32])
                .remove_allowed_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 32)
                .unwrap(),
        )
        .build()
        .unwrap();
    assert_eq!(roundtrip_msg(msg.clone()), msg);
}

#[test]
fn ipv6_endpoints_roundtrip() {
    let endpoint = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 2, 3, 4),
        51820,
        0,
        3,
    ));
    let peer = UmbrawgPeerConfig::new([1u8; 32])
        .endpoint(endpoint)
        .build()
        .unwrap();
    assert_eq!(peer.0[1], UmbrawgPeerAttribute::Endpoint(endpoint));

    let msg = UmbrawgDeviceConfig::by_name("uwg0")
        .peer(UmbrawgPeerConfig::new([1u8; 32]).endpoint(endpoint));
    let parsed = roundtrip_msg(msg.build().unwrap());
    let peers = parsed
        .attributes
        .iter()
        .find_map(|attr| match attr {
            UmbrawgAttribute::Peers(peers) => Some(peers),
            _ => None,
        })
        .unwrap();
    assert_eq!(peers[0].0[1], UmbrawgPeerAttribute::Endpoint(endpoint));
}

#[test]
fn endpoint_helpers() {
    let v4 = UmbrawgPeerConfig::new([1u8; 32])
        .endpoint_v4(Ipv4Addr::new(192, 0, 2, 1), 1234)
        .build()
        .unwrap();
    assert_eq!(
        v4.0[1],
        UmbrawgPeerAttribute::Endpoint(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            1234
        ))
    );

    let v6 = UmbrawgPeerConfig::new([1u8; 32])
        .endpoint_v6_scoped(Ipv6Addr::LOCALHOST, 51820, 7)
        .build()
        .unwrap();
    assert_eq!(
        v6.0[1],
        UmbrawgPeerAttribute::Endpoint(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            51820,
            0,
            7
        )))
    );
}

#[test]
fn peer_from_peer_drops_read_only_attributes() {
    let peer = UmbrawgPeer(vec![
        UmbrawgPeerAttribute::PublicKey([1u8; 32]),
        UmbrawgPeerAttribute::PresharedKey([2u8; 32]),
        UmbrawgPeerAttribute::Flags(
            UWGPEER_F_HAS_ADVANCED_SECURITY | UWGPEER_F_REPLACE_ALLOWEDIPS,
        ),
        UmbrawgPeerAttribute::Endpoint(
            SocketAddr::from_str("10.0.0.1:51820").unwrap(),
        ),
        UmbrawgPeerAttribute::PersistentKeepaliveRange(u16_range_pack(25, 30)),
        UmbrawgPeerAttribute::LastHandshake(UmbrawgTimeSpec {
            seconds: 10,
            nano_seconds: 20,
        }),
        UmbrawgPeerAttribute::RxBytes(1),
        UmbrawgPeerAttribute::TxBytes(2),
        UmbrawgPeerAttribute::AllowedIps(vec![UmbrawgAllowedIp::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            8,
        )
        .unwrap()]),
        UmbrawgPeerAttribute::AdvancedSecurity(true),
    ]);

    let config = UmbrawgPeerConfig::from_peer(&peer).unwrap();
    let rebuilt = config.clone().build().unwrap();
    assert_eq!(
        rebuilt.0,
        vec![
            UmbrawgPeerAttribute::PublicKey([1u8; 32]),
            UmbrawgPeerAttribute::PresharedKey([2u8; 32]),
            UmbrawgPeerAttribute::Flags(UWGPEER_F_REPLACE_ALLOWEDIPS),
            UmbrawgPeerAttribute::Endpoint(
                SocketAddr::from_str("10.0.0.1:51820").unwrap()
            ),
            UmbrawgPeerAttribute::PersistentKeepaliveRange(u16_range_pack(
                25, 30
            )),
            UmbrawgPeerAttribute::AdvancedSecurity(true),
            UmbrawgPeerAttribute::AllowedIps(vec![UmbrawgAllowedIp::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                8,
            )
            .unwrap()]),
        ]
    );

    assert_eq!(UmbrawgPeerConfig::try_from(&peer).unwrap(), config);
}

#[test]
fn peer_from_peer_requires_public_key() {
    let peer =
        UmbrawgPeer(vec![UmbrawgPeerAttribute::Flags(UWGPEER_F_REMOVE_ME)]);
    assert_eq!(
        UmbrawgPeerConfig::from_peer(&peer),
        Err(UmbrawgConfigError::MissingPublicKey)
    );
}

#[test]
fn device_from_unknown_peer_message_is_rejected() {
    let msg = UmbrawgMessage {
        cmd: UmbrawgCmd::UnknownPeer,
        attributes: vec![],
    };
    assert_eq!(
        UmbrawgDeviceConfig::from_message(&msg),
        Err(UmbrawgConfigError::UnsupportedCommand { command: 2 })
    );
}

#[test]
fn device_from_message_ignores_read_only_attributes() {
    let msg = UmbrawgMessage {
        cmd: UmbrawgCmd::GetDevice,
        attributes: vec![
            UmbrawgAttribute::IfIndex(3),
            UmbrawgAttribute::IfName("uwg0".into()),
            UmbrawgAttribute::PrivateKey([0u8; 32]),
            UmbrawgAttribute::PublicKey([9u8; 32]),
            UmbrawgAttribute::ListenPort(51820),
            UmbrawgAttribute::H1("61220074-118999195".into()),
            UmbrawgAttribute::H2Range(u32_range_pack(7, 7)),
            UmbrawgAttribute::Peers(vec![UmbrawgPeer(vec![
                UmbrawgPeerAttribute::PublicKey([1u8; 32]),
                UmbrawgPeerAttribute::LastHandshake(UmbrawgTimeSpec {
                    seconds: 1,
                    nano_seconds: 2,
                }),
                UmbrawgPeerAttribute::RxBytes(3),
                UmbrawgPeerAttribute::TxBytes(4),
            ])]),
        ],
    };

    let config = UmbrawgDeviceConfig::from_message(&msg).unwrap();
    let rebuilt = config.build().unwrap();
    assert_eq!(
        rebuilt.attributes,
        vec![
            UmbrawgAttribute::IfName("uwg0".into()),
            UmbrawgAttribute::PrivateKey([0u8; 32]),
            UmbrawgAttribute::ListenPort(51820),
            UmbrawgAttribute::H1Range(u32_range_pack(61220074, 118999195)),
            UmbrawgAttribute::H2Range(u32_range_pack(7, 7)),
            UmbrawgAttribute::Peers(vec![UmbrawgPeer(vec![
                UmbrawgPeerAttribute::PublicKey([1u8; 32]),
            ])]),
        ]
    );
}

#[test]
fn device_from_message_keeps_index_without_name() {
    let msg = UmbrawgMessage {
        cmd: UmbrawgCmd::GetDevice,
        attributes: vec![UmbrawgAttribute::IfIndex(3)],
    };
    let config = UmbrawgDeviceConfig::from_message(&msg).unwrap();
    assert_eq!(
        config.build().unwrap().attributes,
        vec![UmbrawgAttribute::IfIndex(3)]
    );
}

#[test]
fn device_bbr_modes_roundtrip() {
    for (mode, wire) in
        [(BbrMode::Off, 0u8), (BbrMode::Monitor, 1), (BbrMode::On, 2)]
    {
        let config = UmbrawgDeviceConfig::by_name("uwg0").bbr(mode);
        let msg = config.clone().build().unwrap();

        assert_eq!(
            msg.attributes,
            vec![
                UmbrawgAttribute::IfName("uwg0".into()),
                UmbrawgAttribute::Bbr(wire),
            ]
        );
        assert_eq!(roundtrip_msg(msg.clone()), msg);

        let restored = UmbrawgDeviceConfig::from_message(&msg).unwrap();
        assert_eq!(restored, config);
        assert_eq!(restored.build().unwrap(), msg);
    }
}

#[test]
fn device_fec_modes_roundtrip() {
    for (mode, wire) in [
        (FecMode::Off, 0u32),
        (FecMode::Adaptive, 1),
        (FecMode::Fixed { k: 2, m: 1 }, 0x0201),
        (FecMode::Fixed { k: 8, m: 2 }, 0x0802),
    ] {
        let config = UmbrawgDeviceConfig::by_name("uwg0").fec(mode);
        let msg = config.clone().build().unwrap();

        assert_eq!(
            msg.attributes,
            vec![
                UmbrawgAttribute::IfName("uwg0".into()),
                UmbrawgAttribute::Fec(wire),
            ]
        );
        assert_eq!(roundtrip_msg(msg.clone()), msg);

        let restored = UmbrawgDeviceConfig::from_message(&msg).unwrap();
        assert_eq!(restored, config);
        assert_eq!(restored.build().unwrap(), msg);
    }
}

#[test]
fn device_rejects_invalid_fec_shards() {
    for (k, m) in [(0u8, 1u8), (1, 0), (255, 1), (200, 100)] {
        let error = UmbrawgDeviceConfig::by_name("uwg0")
            .fec(FecMode::Fixed { k, m })
            .build()
            .unwrap_err();
        assert_eq!(error, UmbrawgConfigError::InvalidFecShards { k, m });
    }

    assert_eq!(FecMode::fixed(0, 1), None);
    assert_eq!(FecMode::fixed(1, 0), None);
    assert_eq!(FecMode::fixed(255, 1), None);
    assert_eq!(
        FecMode::fixed(10, 3).and_then(FecMode::to_u32),
        Some(0x0a03)
    );
}

#[test]
fn device_from_message_ignores_unknown_attributes() {
    let msg = UmbrawgMessage {
        cmd: UmbrawgCmd::GetDevice,
        attributes: vec![
            UmbrawgAttribute::IfName("uwg0".into()),
            UmbrawgAttribute::Bbr(2),
            UmbrawgAttribute::Fec(1),
            UmbrawgAttribute::Other(DefaultNla::new(99, vec![1, 2, 3, 4])),
        ],
    };

    let config = UmbrawgDeviceConfig::from_message(&msg).unwrap();
    assert_eq!(
        config,
        UmbrawgDeviceConfig::by_name("uwg0")
            .bbr(BbrMode::On)
            .fec(FecMode::Adaptive)
    );
    assert_eq!(
        config.build().unwrap().attributes,
        vec![
            UmbrawgAttribute::IfName("uwg0".into()),
            UmbrawgAttribute::Bbr(2),
            UmbrawgAttribute::Fec(1),
        ]
    );
}

#[test]
fn device_from_message_rejects_invalid_bbr_and_fec() {
    let bbr = UmbrawgMessage {
        cmd: UmbrawgCmd::GetDevice,
        attributes: vec![
            UmbrawgAttribute::IfName("uwg0".into()),
            UmbrawgAttribute::Bbr(3),
        ],
    };
    assert_eq!(
        UmbrawgDeviceConfig::from_message(&bbr),
        Err(UmbrawgConfigError::InvalidBbrMode { value: 3 })
    );

    let fec = UmbrawgMessage {
        cmd: UmbrawgCmd::GetDevice,
        attributes: vec![
            UmbrawgAttribute::IfName("uwg0".into()),
            UmbrawgAttribute::Fec(2),
        ],
    };
    assert_eq!(
        UmbrawgDeviceConfig::from_message(&fec),
        Err(UmbrawgConfigError::InvalidFecValue { value: 2 })
    );
}

#[test]
fn magic_header_wire_format_is_u64_range() {
    let msg = UmbrawgDeviceConfig::by_name("uwg0")
        .h1(1, 2)
        .build()
        .unwrap();
    let mut buffer = vec![0; msg.buffer_len()];
    msg.emit(&mut buffer);

    let expected = {
        let mut bytes = vec![0x0c, 0x00, 0x0e, 0x00];
        bytes.extend_from_slice(&u32_range_pack(1, 2).to_le_bytes());
        bytes
    };
    assert!(buffer
        .windows(expected.len())
        .any(|window| window == expected.as_slice()));
}

#[test]
fn multiple_peers_and_empty_allowed_ips_are_supported() {
    let msg = UmbrawgDeviceConfig::by_name("uwg0")
        .peers([
            UmbrawgPeerConfig::new([1u8; 32]),
            UmbrawgPeerConfig::new([2u8; 32]).replace_allowed_ips(),
        ])
        .build()
        .unwrap();

    let peers = msg
        .attributes
        .iter()
        .find_map(|attr| match attr {
            UmbrawgAttribute::Peers(peers) => Some(peers.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(peers.len(), 2);
    assert_eq!(peers[0].0, vec![UmbrawgPeerAttribute::PublicKey([1u8; 32])]);
    assert_eq!(
        peers[1].0,
        vec![
            UmbrawgPeerAttribute::PublicKey([2u8; 32]),
            UmbrawgPeerAttribute::Flags(UWGPEER_F_REPLACE_ALLOWEDIPS),
            UmbrawgPeerAttribute::AllowedIps(vec![]),
        ]
    );
    assert_eq!(roundtrip_msg(msg.clone()), msg);
}

#[test]
fn error_display_is_informative() {
    let rendered = UmbrawgConfigError::InvalidKeyLength {
        field: "private key",
        expected: 32,
        actual: 3,
    }
    .to_string();
    assert!(rendered.contains("private key"));
    assert!(rendered.contains('3'));
    assert!(rendered.contains("32"));
}
