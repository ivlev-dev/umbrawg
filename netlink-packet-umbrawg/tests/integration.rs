// SPDX-License-Identifier: MIT

//! Integration tests that require a Linux kernel with the UmbraWG module
//! loaded and root privileges (CAP_NET_ADMIN).
//!
//! These tests are compiled only on Linux. They will soft-skip themselves
//! when the UmbraWG family is not available or the process lacks the
//! privileges to create network interfaces.

#![cfg(target_os = "linux")]

use std::{convert::TryInto, process::Command};

use futures::{lock::Mutex, StreamExt};
use genetlink::new_connection;
use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST,
};
use netlink_packet_generic::{
    ctrl::{nlas::GenlCtrlAttrs, GenlCtrl, GenlCtrlCmd},
    GenlMessage,
};
use netlink_packet_umbrawg::{
    range::u32_range_from_string, UmbrawgAttribute, UmbrawgCmd, UmbrawgMessage,
    UmbrawgPeer, UmbrawgPeerAttribute,
};

/// Serializes access to netlink interface creation/deletion across tests.
static TEST_MUTEX: Mutex<()> = Mutex::new(());

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn run_ip(args: &[&str]) -> Result<(), String> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| format!("failed to execute ip: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("ip {} failed: {}", args.join(" "), stderr))
    }
}

fn delete_interface(name: &str) {
    let _ = run_ip(&["link", "del", name]);
}

fn create_interface(name: &str) -> Result<(), String> {
    delete_interface(name);
    run_ip(&["link", "add", name, "type", "umbrawg"])
}

fn unique_ifname(prefix: &str) -> String {
    format!("{}_{}", prefix, std::process::id())
}

async fn family_available(handle: &mut genetlink::GenetlinkHandle) -> bool {
    handle.resolve_family::<UmbrawgMessage>().await.is_ok()
}

/// Queries the genl family version of the umbrawg module: 2 for the
/// v1.0 module, 3 for UmbraWG 3.0. The magic header wire format depends
/// on it (string vs packed u64 range).
async fn family_version(
    handle: &mut genetlink::GenetlinkHandle,
) -> Option<u32> {
    let genlmsg: GenlMessage<GenlCtrl> = GenlMessage::from_payload(GenlCtrl {
        cmd: GenlCtrlCmd::GetFamily,
        nlas: vec![GenlCtrlAttrs::FamilyName("umbrawg".to_string())],
    });
    let mut nlmsg = NetlinkMessage::from(genlmsg);
    nlmsg.header.flags = NLM_F_REQUEST | NLM_F_ACK;

    let mut stream = handle.request(nlmsg).await.ok()?;
    while let Some(result) = stream.next().await {
        if let Ok(rx) = result {
            if let NetlinkPayload::InnerMessage(genl) = rx.payload {
                for nla in &genl.payload.nlas {
                    if let GenlCtrlAttrs::Version(v) = nla {
                        return Some(*v);
                    }
                }
            }
        }
    }
    None
}

async fn send_request(
    handle: &mut genetlink::GenetlinkHandle,
    msg: UmbrawgMessage,
    flags: u16,
) -> Vec<UmbrawgMessage> {
    let genlmsg: GenlMessage<UmbrawgMessage> = GenlMessage::from_payload(msg);
    let mut nlmsg = NetlinkMessage::from(genlmsg);
    nlmsg.header.flags = flags;

    let mut responses = Vec::new();
    let mut stream = handle.request(nlmsg).await.unwrap();
    while let Some(result) = stream.next().await {
        let rx = result.unwrap();
        match rx.payload {
            NetlinkPayload::InnerMessage(genl) => {
                responses.push(genl.payload);
            }
            NetlinkPayload::Error(e) => {
                panic!("netlink error: {:?}", e.to_io());
            }
            _ => {}
        }
    }
    responses
}

async fn send_request_result(
    handle: &mut genetlink::GenetlinkHandle,
    msg: UmbrawgMessage,
    flags: u16,
) -> Result<Vec<UmbrawgMessage>, i32> {
    let genlmsg: GenlMessage<UmbrawgMessage> = GenlMessage::from_payload(msg);
    let mut nlmsg = NetlinkMessage::from(genlmsg);
    nlmsg.header.flags = flags;

    let mut responses = Vec::new();
    let mut stream = handle.request(nlmsg).await.unwrap();
    while let Some(result) = stream.next().await {
        let rx = result.unwrap();
        match rx.payload {
            NetlinkPayload::InnerMessage(genl) => {
                responses.push(genl.payload);
            }
            NetlinkPayload::Error(e) => {
                return Err(e.raw_code().abs());
            }
            _ => {}
        }
    }
    Ok(responses)
}

#[tokio::test]
async fn test_get_device_on_umbrawg_interface() {
    if !is_root() {
        eprintln!("Skipping integration test: not running as root");
        return;
    }

    let _guard = TEST_MUTEX.lock().await;

    let (connection, mut handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    if !family_available(&mut handle).await {
        eprintln!("Skipping integration test: umbrawg family not available");
        return;
    }

    let ifname = unique_ifname("uwg_get");
    create_interface(&ifname).expect("failed to create test interface");

    let get_msg = UmbrawgMessage {
        cmd: UmbrawgCmd::GetDevice,
        attributes: vec![UmbrawgAttribute::IfName(ifname.clone())],
    };

    let responses =
        send_request(&mut handle, get_msg, NLM_F_REQUEST | NLM_F_DUMP).await;

    assert!(
        !responses.is_empty(),
        "expected at least one response for get device"
    );

    let found_name = responses.iter().any(|r| {
        r.attributes.iter().any(
            |attr| matches!(attr, UmbrawgAttribute::IfName(n) if *n == ifname),
        )
    });
    assert!(found_name, "expected IfName attribute in get response");

    delete_interface(&ifname);
}

#[tokio::test]
async fn test_set_and_get_umbra_parameters() {
    if !is_root() {
        eprintln!("Skipping integration test: not running as root");
        return;
    }

    let _guard = TEST_MUTEX.lock().await;

    let (connection, mut handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    if !family_available(&mut handle).await {
        eprintln!("Skipping integration test: umbrawg family not available");
        return;
    }

    let ifname = unique_ifname("uwg_set");
    create_interface(&ifname).expect("failed to create test interface");

    // UmbraWG 3.0 (genl version 3) expects magic headers as packed u64
    // ranges; older modules expect spec strings.
    let version = family_version(&mut handle).await.unwrap_or(2);
    let (h1, h2, h3, h4) = if version >= 3 {
        (
            UmbrawgAttribute::H1Range(
                u32_range_from_string("61220074-118999195").unwrap(),
            ),
            UmbrawgAttribute::H2Range(
                u32_range_from_string("605047389-945520346").unwrap(),
            ),
            UmbrawgAttribute::H3Range(
                u32_range_from_string("1477291385-1814368140").unwrap(),
            ),
            UmbrawgAttribute::H4Range(
                u32_range_from_string("1951993942-1997499713").unwrap(),
            ),
        )
    } else {
        (
            UmbrawgAttribute::H1("61220074-118999195".into()),
            UmbrawgAttribute::H2("605047389-945520346".into()),
            UmbrawgAttribute::H3("1477291385-1814368140".into()),
            UmbrawgAttribute::H4("1951993942-1997499713".into()),
        )
    };

    // SetDevice with Umbra-specific parameters.
    let set_msg = UmbrawgMessage {
        cmd: UmbrawgCmd::SetDevice,
        attributes: vec![
            UmbrawgAttribute::IfName(ifname.clone()),
            UmbrawgAttribute::ListenPort(51820),
            UmbrawgAttribute::JC(4),
            UmbrawgAttribute::Jmin(40),
            UmbrawgAttribute::Jmax(70),
            UmbrawgAttribute::S1(92),
            UmbrawgAttribute::S2(115),
            UmbrawgAttribute::S3(44),
            UmbrawgAttribute::S4(9),
            h1,
            h2,
            h3,
            h4,
            UmbrawgAttribute::I1("<r 149>".into()),
        ],
    };

    let ack_responses =
        send_request(&mut handle, set_msg, NLM_F_REQUEST | NLM_F_ACK).await;
    assert!(
        ack_responses.is_empty(),
        "set device with NLM_F_ACK should return no payload on success"
    );

    let get_msg = UmbrawgMessage {
        cmd: UmbrawgCmd::GetDevice,
        attributes: vec![UmbrawgAttribute::IfName(ifname.clone())],
    };

    let responses =
        send_request(&mut handle, get_msg, NLM_F_REQUEST | NLM_F_DUMP).await;
    assert_eq!(
        responses.len(),
        1,
        "expected exactly one response for get device"
    );

    let attrs = &responses[0].attributes;
    let listen_port = attrs.iter().find_map(|a| {
        if let UmbrawgAttribute::ListenPort(p) = a {
            Some(*p)
        } else {
            None
        }
    });
    assert_eq!(listen_port, Some(51820), "listen port mismatch");

    let jc = attrs.iter().find_map(|a| {
        if let UmbrawgAttribute::JC(v) = a {
            Some(*v)
        } else {
            None
        }
    });
    assert_eq!(jc, Some(4), "JC mismatch");

    let jmin = attrs.iter().find_map(|a| {
        if let UmbrawgAttribute::Jmin(v) = a {
            Some(*v)
        } else {
            None
        }
    });
    assert_eq!(jmin, Some(40), "Jmin mismatch");

    let jmax = attrs.iter().find_map(|a| {
        if let UmbrawgAttribute::Jmax(v) = a {
            Some(*v)
        } else {
            None
        }
    });
    assert_eq!(jmax, Some(70), "Jmax mismatch");

    let s1 = attrs.iter().find_map(|a| {
        if let UmbrawgAttribute::S1(v) = a {
            Some(*v)
        } else {
            None
        }
    });
    assert_eq!(s1, Some(92), "S1 mismatch");

    let h1 = attrs.iter().find_map(|a| {
        if let UmbrawgAttribute::H1(v) = a {
            Some(v.clone())
        } else {
            None
        }
    });
    assert_eq!(h1, Some("61220074-118999195".into()), "H1 mismatch");

    delete_interface(&ifname);
}

#[tokio::test]
async fn test_family_not_available_soft_skip() {
    // This test exercises the soft-skip path on systems without UmbraWG.
    // When the family is available it still verifies that resolve works.
    let (connection, mut handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    let available = family_available(&mut handle).await;
    if !available {
        eprintln!("umbrawg family not available on this system");
    }
    // We cannot assert availability because it depends on the environment.
    // The test simply ensures the resolve call does not panic.
}

fn pack_u16_range(lo: u16, hi: u16) -> u32 {
    (hi as u32) << 16 | lo as u32
}

#[tokio::test]
async fn test_set_and_get_all_3_1_parameters() {
    if !is_root() {
        eprintln!("Skipping integration test: not running as root");
        return;
    }
    let _guard = TEST_MUTEX.lock().await;
    let (connection, mut handle, _) = new_connection().unwrap();
    tokio::spawn(connection);
    if !family_available(&mut handle).await {
        eprintln!("Skipping integration test: umbrawg family not available");
        return;
    }
    let ifname = unique_ifname("uwg_31");
    create_interface(&ifname).expect("failed to create test interface");

    let version = family_version(&mut handle).await.unwrap_or(2);
    let h1 = if version >= 3 {
        UmbrawgAttribute::H1Range(
            u32_range_from_string("712026294-712074283").unwrap(),
        )
    } else {
        UmbrawgAttribute::H1("712026294-712074283".into())
    };
    let h2 = if version >= 3 {
        UmbrawgAttribute::H2Range(
            u32_range_from_string("1504260570-1504277407").unwrap(),
        )
    } else {
        UmbrawgAttribute::H2("1504260570-1504277407".into())
    };
    let h3 = if version >= 3 {
        UmbrawgAttribute::H3Range(
            u32_range_from_string("2938347170-2938351405").unwrap(),
        )
    } else {
        UmbrawgAttribute::H3("2938347170-2938351405".into())
    };
    let h4 = if version >= 3 {
        UmbrawgAttribute::H4Range(
            u32_range_from_string("3916942126-3916960536").unwrap(),
        )
    } else {
        UmbrawgAttribute::H4("3916942126-3916960536".into())
    };

    let header_key: [u8; 32] =
        base64::decode("hj875O8KOzPqqrKI3FnA768294uWGdMDPh7ts49SzLU=")
            .unwrap()
            .try_into()
            .unwrap();

    let set_msg = UmbrawgMessage {
        cmd: UmbrawgCmd::SetDevice,
        attributes: vec![
            UmbrawgAttribute::IfName(ifname.clone()),
            UmbrawgAttribute::ListenPort(51820),
            UmbrawgAttribute::JC(6),
            UmbrawgAttribute::Jmin(292),
            UmbrawgAttribute::Jmax(1152),
            UmbrawgAttribute::S1(34),
            UmbrawgAttribute::S2(97),
            UmbrawgAttribute::S3(31),
            UmbrawgAttribute::S4(28),
            h1.clone(),
            h2.clone(),
            h3.clone(),
            h4.clone(),
            UmbrawgAttribute::I1("<b 0xc200000001087972af009f7ce47d04559703f31e174691922b896cb39e5ccdb74b8f6c46168d47652d74a98a2861c7349b5244b64eb876><rc 38><r 1000><r 161><t>".into()),
            UmbrawgAttribute::I2("<b 0xe300000001127362d0c517f5aae98388afaf2809110ccc5610ed5923abbcbd29ac5c31816261d0e7ae44bb7fc33941><rc 40><r 1000><r 163><t>".into()),
            UmbrawgAttribute::I3("<b 0xc30000000111bf75ad99b7b31b0d887c05054897ecd7d001911a53c4c9ab0067c318d6d5bf6519134da966559268219aca1fba4644b219ba2c84><rc 41><r 1000><r 153><t>".into()),
            UmbrawgAttribute::I4("<b 0xe100000001093adb1b6b0cde0531700ea127f7f956bc499a0ab59bd6b0dc44c43085><rc 38><r 1000><r 176><t>".into()),
            UmbrawgAttribute::I5("<b 0xe2000000010973760ff2b80f2c78420a91d8a812337b91c48c2844d7b63a2d><rc 40><r 1000><r 192><t>".into()),
            UmbrawgAttribute::HeaderProtectionKey(header_key),
            UmbrawgAttribute::ContentPaddingAddition(pack_u16_range(51, 197)),
            UmbrawgAttribute::RekeyAfterTime(pack_u16_range(104, 149)),
            UmbrawgAttribute::RekeyTimeout(pack_u16_range(5, 8)),
            UmbrawgAttribute::RejectAfterTime(pack_u16_range(184, 199)),
            UmbrawgAttribute::KeepaliveTimeout(pack_u16_range(9, 12)),
            UmbrawgAttribute::MaxHandshakeAttempts(pack_u16_range(18, 23)),
            UmbrawgAttribute::RandomTrailers(true),
            UmbrawgAttribute::DisableCookies(false),
        ],
    };
    let ack =
        send_request_result(&mut handle, set_msg, NLM_F_REQUEST | NLM_F_ACK)
            .await;
    assert!(ack.is_ok(), "set 3.1 failed: {:?}", ack);

    let get_msg = UmbrawgMessage {
        cmd: UmbrawgCmd::GetDevice,
        attributes: vec![UmbrawgAttribute::IfName(ifname.clone())],
    };
    let responses =
        send_request(&mut handle, get_msg, NLM_F_REQUEST | NLM_F_DUMP).await;
    assert_eq!(responses.len(), 1);
    let attrs = &responses[0].attributes;

    let jc = attrs.iter().find_map(|a| {
        if let UmbrawgAttribute::JC(v) = a {
            Some(*v)
        } else {
            None
        }
    });
    assert_eq!(jc, Some(6));
    let jmin = attrs.iter().find_map(|a| {
        if let UmbrawgAttribute::Jmin(v) = a {
            Some(*v)
        } else {
            None
        }
    });
    assert_eq!(jmin, Some(292));
    let jmax = attrs.iter().find_map(|a| {
        if let UmbrawgAttribute::Jmax(v) = a {
            Some(*v)
        } else {
            None
        }
    });
    assert_eq!(jmax, Some(1152));
    let s1 = attrs.iter().find_map(|a| {
        if let UmbrawgAttribute::S1(v) = a {
            Some(*v)
        } else {
            None
        }
    });
    assert_eq!(s1, Some(34));
    let s2 = attrs.iter().find_map(|a| {
        if let UmbrawgAttribute::S2(v) = a {
            Some(*v)
        } else {
            None
        }
    });
    assert_eq!(s2, Some(97));
    let s3 = attrs.iter().find_map(|a| {
        if let UmbrawgAttribute::S3(v) = a {
            Some(*v)
        } else {
            None
        }
    });
    assert_eq!(s3, Some(31));
    let s4 = attrs.iter().find_map(|a| {
        if let UmbrawgAttribute::S4(v) = a {
            Some(*v)
        } else {
            None
        }
    });
    assert_eq!(s4, Some(28));
    let has_h1 = attrs.iter().any(|a| {
        matches!(a, UmbrawgAttribute::H1(_) | UmbrawgAttribute::H1Range(_))
    });
    assert!(has_h1, "H1 missing");
    let i1 = attrs.iter().find_map(|a| {
        if let UmbrawgAttribute::I1(v) = a {
            Some(v.clone())
        } else {
            None
        }
    });
    assert!(i1.is_some() && i1.unwrap().contains("rc 38"));
    let cpa = attrs.iter().find_map(|a| {
        if let UmbrawgAttribute::ContentPaddingAddition(v) = a {
            Some(*v)
        } else {
            None
        }
    });
    assert_eq!(cpa, Some(pack_u16_range(51, 197)));
    let rat = attrs.iter().find_map(|a| {
        if let UmbrawgAttribute::RekeyAfterTime(v) = a {
            Some(*v)
        } else {
            None
        }
    });
    assert_eq!(rat, Some(pack_u16_range(104, 149)));
    let rt = attrs.iter().find_map(|a| {
        if let UmbrawgAttribute::RekeyTimeout(v) = a {
            Some(*v)
        } else {
            None
        }
    });
    assert_eq!(rt, Some(pack_u16_range(5, 8)));
    let rej = attrs.iter().find_map(|a| {
        if let UmbrawgAttribute::RejectAfterTime(v) = a {
            Some(*v)
        } else {
            None
        }
    });
    assert_eq!(rej, Some(pack_u16_range(184, 199)));
    let kt = attrs.iter().find_map(|a| {
        if let UmbrawgAttribute::KeepaliveTimeout(v) = a {
            Some(*v)
        } else {
            None
        }
    });
    assert_eq!(kt, Some(pack_u16_range(9, 12)));
    let mha = attrs.iter().find_map(|a| {
        if let UmbrawgAttribute::MaxHandshakeAttempts(v) = a {
            Some(*v)
        } else {
            None
        }
    });
    assert_eq!(mha, Some(pack_u16_range(18, 23)));
    let rtb = attrs.iter().find_map(|a| {
        if let UmbrawgAttribute::RandomTrailers(v) = a {
            Some(*v)
        } else {
            None
        }
    });
    assert_eq!(rtb, Some(true));
    let dc = attrs.iter().find_map(|a| {
        if let UmbrawgAttribute::DisableCookies(v) = a {
            Some(*v)
        } else {
            None
        }
    });
    assert_eq!(dc, Some(false));
    let hpk = attrs.iter().find_map(|a| {
        if let UmbrawgAttribute::HeaderProtectionKey(v) = a {
            Some(*v)
        } else {
            None
        }
    });
    assert_eq!(hpk, Some(header_key));

    delete_interface(&ifname);
}

#[tokio::test]
async fn test_no_peers_fresh_interface() {
    if !is_root() {
        eprintln!("Skipping integration test: not running as root");
        return;
    }
    let _guard = TEST_MUTEX.lock().await;
    let (connection, mut handle, _) = new_connection().unwrap();
    tokio::spawn(connection);
    if !family_available(&mut handle).await {
        eprintln!("Skipping integration test: umbrawg family not available");
        return;
    }
    let ifname = unique_ifname("npr");
    create_interface(&ifname).expect("failed to create test interface");
    let get_msg = UmbrawgMessage {
        cmd: UmbrawgCmd::GetDevice,
        attributes: vec![UmbrawgAttribute::IfName(ifname.clone())],
    };
    let responses =
        send_request(&mut handle, get_msg, NLM_F_REQUEST | NLM_F_DUMP).await;
    assert_eq!(responses.len(), 1);
    let has_peers = responses[0]
        .attributes
        .iter()
        .any(|a| matches!(a, UmbrawgAttribute::Peers(_)));
    assert!(
        !has_peers,
        "fresh interface should not have peers attribute"
    );
    delete_interface(&ifname);
}

#[tokio::test]
async fn test_invalid_values_return_errno() {
    if !is_root() {
        eprintln!("Skipping integration test: not running as root");
        return;
    }
    let _guard = TEST_MUTEX.lock().await;
    let (connection, mut handle, _) = new_connection().unwrap();
    tokio::spawn(connection);
    if !family_available(&mut handle).await {
        eprintln!("Skipping integration test: umbrawg family not available");
        return;
    }
    let ifname = unique_ifname("inv");
    create_interface(&ifname).expect("failed to create test interface");

    let hpk = [7u8; 32];
    // Header protection key with too-small S1 -> EINVAL
    let set_msg = UmbrawgMessage {
        cmd: UmbrawgCmd::SetDevice,
        attributes: vec![
            UmbrawgAttribute::IfName(ifname.clone()),
            UmbrawgAttribute::HeaderProtectionKey(hpk),
            UmbrawgAttribute::S1(1),
        ],
    };
    let res =
        send_request_result(&mut handle, set_msg, NLM_F_REQUEST | NLM_F_ACK)
            .await;
    eprintln!("header-protection invalid result: {:?}", res);
    assert_eq!(res.unwrap_err(), 22, "too-small S1 should be EINVAL");

    delete_interface(&ifname);
}

#[tokio::test]
async fn test_peer_replacement() {
    if !is_root() {
        eprintln!("Skipping integration test: not running as root");
        return;
    }
    let _guard = TEST_MUTEX.lock().await;
    let (connection, mut handle, _) = new_connection().unwrap();
    tokio::spawn(connection);
    if !family_available(&mut handle).await {
        eprintln!("Skipping integration test: umbrawg family not available");
        return;
    }
    let ifname = unique_ifname("prr");
    create_interface(&ifname).expect("failed to create test interface");

    let peer1 = [1u8; 32];
    let peer2 = [2u8; 32];
    let set1 = UmbrawgMessage {
        cmd: UmbrawgCmd::SetDevice,
        attributes: vec![
            UmbrawgAttribute::IfName(ifname.clone()),
            UmbrawgAttribute::Peers(vec![UmbrawgPeer(vec![
                UmbrawgPeerAttribute::PublicKey(peer1),
            ])]),
        ],
    };
    send_request_result(&mut handle, set1, NLM_F_REQUEST | NLM_F_ACK)
        .await
        .unwrap();

    let set2 = UmbrawgMessage {
        cmd: UmbrawgCmd::SetDevice,
        attributes: vec![
            UmbrawgAttribute::IfName(ifname.clone()),
            UmbrawgAttribute::Flags(1), // UWGDEVICE_F_REPLACE_PEERS
            UmbrawgAttribute::Peers(vec![UmbrawgPeer(vec![
                UmbrawgPeerAttribute::PublicKey(peer2),
            ])]),
        ],
    };
    let _ =
        send_request_result(&mut handle, set2, NLM_F_REQUEST | NLM_F_ACK).await;

    let get_msg = UmbrawgMessage {
        cmd: UmbrawgCmd::GetDevice,
        attributes: vec![UmbrawgAttribute::IfName(ifname.clone())],
    };
    let responses =
        send_request(&mut handle, get_msg, NLM_F_REQUEST | NLM_F_DUMP).await;
    assert!(!responses.is_empty());
    let mut found1 = false;
    let mut found2 = false;
    for r in &responses {
        for attr in &r.attributes {
            if let UmbrawgAttribute::Peers(peers) = attr {
                for p in peers {
                    for pa in p.0.iter() {
                        if let UmbrawgPeerAttribute::PublicKey(k) = pa {
                            if *k == peer1 {
                                found1 = true;
                            }
                            if *k == peer2 {
                                found2 = true;
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(found2, "replacement peer should be present");
    assert!(!found1, "old peer should be removed by replace");
    delete_interface(&ifname);
}
