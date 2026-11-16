// SPDX-License-Identifier: MIT

use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6,
};

use netlink_packet_core::{Emitable, ParseableParametrized};
use netlink_packet_generic::GenlHeader;
use netlink_packet_umbrawg::{
    range::{u32_range_from_string, u32_range_pack, u32_range_unpack},
    UmbrawgAddressFamily, UmbrawgAllowedIp, UmbrawgAllowedIpAttr,
    UmbrawgAttribute, UmbrawgCmd, UmbrawgMessage, UmbrawgPeer,
    UmbrawgPeerAttribute, UmbrawgTimeSpec,
};
use proptest::prelude::*;

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

// ---- strategies ----

fn arb_bytes16() -> impl Strategy<Value = [u8; 16]> {
    prop::array::uniform(any::<u8>())
}

fn arb_bytes32() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform(any::<u8>())
}

fn arb_addr() -> impl Strategy<Value = SocketAddr> {
    prop_oneof![
        (any::<u32>(), any::<u16>()).prop_map(|(ip, port)| {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port))
        }),
        (arb_bytes16(), any::<u16>(), any::<u32>(), any::<u32>()).prop_map(
            |(ip, port, flow, scope)| {
                SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(ip),
                    port,
                    flow,
                    scope,
                ))
            }
        ),
    ]
}

fn arb_addr_family() -> impl Strategy<Value = UmbrawgAddressFamily> {
    prop_oneof![
        Just(UmbrawgAddressFamily::Ipv4),
        Just(UmbrawgAddressFamily::Ipv6),
        any::<u16>().prop_map(UmbrawgAddressFamily::Other),
    ]
}

fn arb_ipaddr() -> impl Strategy<Value = IpAddr> {
    prop_oneof![
        any::<u32>().prop_map(|v| IpAddr::V4(Ipv4Addr::from(v))),
        arb_bytes16().prop_map(|v| IpAddr::V6(Ipv6Addr::from(v))),
    ]
}

fn arb_timespec() -> impl Strategy<Value = UmbrawgTimeSpec> {
    (any::<i64>(), any::<i64>()).prop_map(|(s, n)| UmbrawgTimeSpec {
        seconds: s,
        nano_seconds: n,
    })
}

fn arb_allowed_ip_attr() -> impl Strategy<Value = UmbrawgAllowedIpAttr> {
    prop_oneof![
        arb_addr_family().prop_map(UmbrawgAllowedIpAttr::Family),
        arb_ipaddr().prop_map(UmbrawgAllowedIpAttr::IpAddr),
        any::<u8>().prop_map(UmbrawgAllowedIpAttr::Cidr),
    ]
}

fn arb_allowed_ip() -> impl Strategy<Value = UmbrawgAllowedIp> {
    prop::collection::vec(arb_allowed_ip_attr(), 1..6)
        .prop_map(UmbrawgAllowedIp)
}

fn magic_header_string() -> impl Strategy<Value = String> {
    // valid spec strings understood by parse_magic_header
    prop_oneof![
        (any::<u32>()).prop_map(|v| v.to_string()),
        (any::<u32>(), any::<u32>()).prop_filter_map("lo<=hi", |(a, b)| {
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            Some(format!("{lo}-{hi}"))
        }),
    ]
}

fn arb_peer_attr() -> impl Strategy<Value = UmbrawgPeerAttribute> {
    prop_oneof![
        arb_bytes32().prop_map(UmbrawgPeerAttribute::PublicKey),
        arb_bytes32().prop_map(UmbrawgPeerAttribute::PresharedKey),
        arb_addr().prop_map(UmbrawgPeerAttribute::Endpoint),
        any::<u16>().prop_map(UmbrawgPeerAttribute::PersistentKeepalive),
        any::<u32>().prop_map(UmbrawgPeerAttribute::PersistentKeepaliveRange),
        arb_timespec().prop_map(UmbrawgPeerAttribute::LastHandshake),
        any::<u64>().prop_map(UmbrawgPeerAttribute::RxBytes),
        any::<u64>().prop_map(UmbrawgPeerAttribute::TxBytes),
        prop::collection::vec(arb_allowed_ip(), 0..4)
            .prop_map(UmbrawgPeerAttribute::AllowedIps),
        any::<u32>().prop_map(UmbrawgPeerAttribute::ProtocolVersion),
        any::<u32>().prop_map(UmbrawgPeerAttribute::Flags),
    ]
}

fn arb_peer() -> impl Strategy<Value = UmbrawgPeer> {
    prop::collection::vec(arb_peer_attr(), 1..6).prop_map(UmbrawgPeer)
}

fn arb_attr() -> impl Strategy<Value = UmbrawgAttribute> {
    prop_oneof![
        any::<u32>().prop_map(UmbrawgAttribute::IfIndex),
        "[a-zA-Z0-9_]{0,16}".prop_map(UmbrawgAttribute::IfName),
        arb_bytes32().prop_map(UmbrawgAttribute::PrivateKey),
        arb_bytes32().prop_map(UmbrawgAttribute::PublicKey),
        any::<u16>().prop_map(UmbrawgAttribute::ListenPort),
        any::<u32>().prop_map(UmbrawgAttribute::Fwmark),
        prop::collection::vec(arb_peer(), 0..4)
            .prop_map(UmbrawgAttribute::Peers),
        any::<u32>().prop_map(UmbrawgAttribute::Flags),
        any::<u16>().prop_map(UmbrawgAttribute::JC),
        any::<u16>().prop_map(UmbrawgAttribute::Jmin),
        any::<u16>().prop_map(UmbrawgAttribute::Jmax),
        any::<u16>().prop_map(UmbrawgAttribute::S1),
        any::<u16>().prop_map(UmbrawgAttribute::S2),
        magic_header_string().prop_map(UmbrawgAttribute::H1),
        magic_header_string().prop_map(UmbrawgAttribute::H2),
        magic_header_string().prop_map(UmbrawgAttribute::H3),
        magic_header_string().prop_map(UmbrawgAttribute::H4),
        any::<u16>().prop_map(UmbrawgAttribute::S3),
        any::<u16>().prop_map(UmbrawgAttribute::S4),
        // I1-I5 as generic (possibly empty) strings; parse_string must accept.
        // Keep to ASCII subset that parse_string accepts.
        "[a-zA-Z0-9 <>!._-]{0,24}".prop_map(UmbrawgAttribute::I1),
        "[a-zA-Z0-9 <>!._-]{0,24}".prop_map(UmbrawgAttribute::I2),
        "[a-zA-Z0-9 <>!._-]{0,24}".prop_map(UmbrawgAttribute::I3),
        "[a-zA-Z0-9 <>!._-]{0,24}".prop_map(UmbrawgAttribute::I4),
        "[a-zA-Z0-9 <>!._-]{0,24}".prop_map(UmbrawgAttribute::I5),
        arb_bytes32().prop_map(UmbrawgAttribute::HeaderProtectionKey),
        any::<u32>().prop_map(UmbrawgAttribute::ContentPaddingAddition),
        any::<u32>().prop_map(UmbrawgAttribute::RekeyAfterTime),
        any::<u32>().prop_map(UmbrawgAttribute::RekeyTimeout),
        any::<u32>().prop_map(UmbrawgAttribute::RejectAfterTime),
        any::<u32>().prop_map(UmbrawgAttribute::KeepaliveTimeout),
        any::<u32>().prop_map(UmbrawgAttribute::MaxHandshakeAttempts),
        any::<bool>().prop_map(UmbrawgAttribute::RandomTrailers),
        any::<bool>().prop_map(UmbrawgAttribute::DisableCookies),
    ]
}

fn arb_msg() -> impl Strategy<Value = UmbrawgMessage> {
    (
        prop_oneof![
            Just(UmbrawgCmd::GetDevice),
            Just(UmbrawgCmd::SetDevice),
            any::<u8>()
                .prop_filter("not 0/1", |v| *v != 0 && *v != 1)
                .prop_map(UmbrawgCmd::Other)
        ],
        prop::collection::vec(arb_attr(), 0..8),
    )
        .prop_map(|(cmd, attrs)| UmbrawgMessage {
            cmd,
            attributes: attrs,
        })
}

// ---- tests ----

proptest! {
    #[test]
    fn prop_roundtrip_message(msg in arb_msg()) {
        let rt = roundtrip_msg(msg.clone());
        prop_assert_eq!(rt, msg);
    }

    #[test]
    fn prop_serialization_deterministic(msg in arb_msg()) {
        let header = GenlHeader { cmd: msg.cmd.into(), version: 2 };
        let hl = header.buffer_len();
        let mut b1 = vec![0u8; msg.buffer_len() + hl];
        header.emit(&mut b1);
        msg.emit(&mut b1[hl..]);
        let mut b2 = vec![0u8; msg.buffer_len() + hl];
        header.emit(&mut b2);
        msg.emit(&mut b2[hl..]);
        prop_assert_eq!(b1, b2);
    }

    #[test]
    fn prop_parse_garbage_no_panic(buf in prop::collection::vec(any::<u8>(), 0..256)) {
        let header = GenlHeader { cmd: 0, version: 2 };
        let res = std::panic::catch_unwind(|| {
            let _ = UmbrawgMessage::parse_with_param(&buf, header);
        });
        prop_assert!(res.is_ok(), "parse panicked");
    }

    #[test]
    fn prop_parse_truncated_no_panic(
        msg in arb_msg(),
        cut in 0usize..64,
    ) {
        let header = GenlHeader { cmd: msg.cmd.into(), version: 2 };
        let hl = header.buffer_len();
        let mut buf = vec![0u8; msg.buffer_len() + hl];
        header.emit(&mut buf);
        msg.emit(&mut buf[hl..]);
        let n = buf.len().saturating_sub(cut);
        let start = hl.min(buf.len());
        let end = n.max(start).min(buf.len());
        let slice = &buf[start..end]; // message payload (without header)
        let res = std::panic::catch_unwind(|| {
            let _ = UmbrawgMessage::parse_with_param(slice, header);
        });
        prop_assert!(res.is_ok(), "truncated parse panicked");
    }

    #[test]
    fn prop_boundary_u16_fields(v in any::<u16>()) {
        // h1..h4 are strings in range; s1..s4 u16 roundtrip via message
        let msg = UmbrawgMessage {
            cmd: UmbrawgCmd::SetDevice,
            attributes: vec![
                UmbrawgAttribute::S1(v),
                UmbrawgAttribute::S2(v),
                UmbrawgAttribute::S3(v),
                UmbrawgAttribute::S4(v),
                UmbrawgAttribute::JC(v),
                UmbrawgAttribute::Jmin(v),
                UmbrawgAttribute::Jmax(v),
            ],
        };
        let rt = roundtrip_msg(msg.clone());
        prop_assert_eq!(rt, msg);
    }

    #[test]
    fn prop_boundary_u32_fields(v in any::<u32>()) {
        let msg = UmbrawgMessage {
            cmd: UmbrawgCmd::SetDevice,
            attributes: vec![
                UmbrawgAttribute::ContentPaddingAddition(v),
                UmbrawgAttribute::RekeyAfterTime(v),
                UmbrawgAttribute::RekeyTimeout(v),
                UmbrawgAttribute::Fwmark(v),
                UmbrawgAttribute::IfIndex(v),
            ],
        };
        let rt = roundtrip_msg(msg.clone());
        prop_assert_eq!(rt, msg);
    }

    #[test]
    fn prop_magic_header_range_pack_unpack(lo in any::<u32>(), hi in any::<u32>()) {
        let (a, b) = if lo <= hi { (lo, hi) } else { (hi, lo) };
        let packed = u32_range_pack(a, b);
        prop_assert_eq!(u32_range_unpack(packed), (a, b));
        // from_string roundtrip for lo..hi when lo<=hi
        let spec = format!("{a}-{b}");
        prop_assert_eq!(u32_range_from_string(&spec), Some(u32_range_pack(a, b)));
    }
}

// u64 roundtrip for I1? no-op (strings)

// additional parse garbage on raw NLA buffers
#[test]
fn parse_random_buffers_never_panic() {
    use proptest::test_runner::Config;
    let mut runner = proptest::test_runner::TestRunner::new(Config::default());
    let strat = prop::collection::vec(any::<u8>(), 0..512);
    runner
        .run(&strat, |buf| {
            let header = GenlHeader { cmd: 0, version: 2 };
            let r = std::panic::catch_unwind(|| {
                let _ = UmbrawgMessage::parse_with_param(&buf, header);
            });
            prop_assert!(r.is_ok());
            Ok(())
        })
        .unwrap();
}

// ensure parse_string accepts subset; compile check
#[test]
fn compile_smoke() {
    let _ = u32_range_from_string("1-2");
}
