// SPDX-License-Identifier: MIT

#[cfg(target_os = "linux")]
use std::env::args;

#[cfg(target_os = "linux")]
use futures::StreamExt;
#[cfg(target_os = "linux")]
use genetlink::new_connection;
#[cfg(target_os = "linux")]
use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST,
};
#[cfg(target_os = "linux")]
use netlink_packet_generic::GenlMessage;
#[cfg(target_os = "linux")]
use netlink_packet_umbrawg::{
    UmbrawgAllowedIp, UmbrawgAllowedIpAttr, UmbrawgAttribute, UmbrawgCmd,
    UmbrawgMessage, UmbrawgPeerAttribute,
};

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This example only works on Linux");
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    env_logger::init();

    let argv: Vec<String> = args().collect();
    if argv.len() < 2 {
        eprintln!("Usage: get_umbrawg_info <ifname>");
        return;
    }

    let (connection, mut handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    let msg = UmbrawgMessage {
        cmd: UmbrawgCmd::GetDevice,
        attributes: vec![UmbrawgAttribute::IfName(argv[1].clone())],
    };

    let genlmsg: GenlMessage<UmbrawgMessage> = GenlMessage::from_payload(msg);
    let mut nlmsg = NetlinkMessage::from(genlmsg);
    nlmsg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;

    let mut res = handle.request(nlmsg).await.unwrap();

    while let Some(result) = res.next().await {
        let rx_packet = result.unwrap();
        match rx_packet.payload {
            NetlinkPayload::InnerMessage(genlmsg) => {
                print_wg_payload(genlmsg.payload);
            }
            NetlinkPayload::Error(e) => {
                eprintln!("Error: {:?}", e.to_io());
            }
            _ => (),
        };
    }
}

#[cfg(target_os = "linux")]
fn print_wg_payload(wg: UmbrawgMessage) {
    for attr in &wg.attributes {
        match attr {
            UmbrawgAttribute::IfIndex(v) => println!("IfIndex: {}", v),
            UmbrawgAttribute::IfName(v) => println!("IfName: {}", v),
            UmbrawgAttribute::PrivateKey(_) => {
                println!("PrivateKey: (hidden)")
            }
            UmbrawgAttribute::PublicKey(v) => {
                println!("PublicKey: {}", base64::encode(v))
            }
            UmbrawgAttribute::ListenPort(v) => {
                println!("ListenPort: {}", v)
            }
            UmbrawgAttribute::Fwmark(v) => println!("Fwmark: {}", v),
            UmbrawgAttribute::Peers(peers) => {
                for peer in peers {
                    println!("Peer: ");
                    print_wg_peer(peer);
                }
            }
            UmbrawgAttribute::JC(v) => {
                println!("JunkCount: {}", v)
            }
            UmbrawgAttribute::Jmin(v) => {
                println!("JunkPacketMinSize: {}", v)
            }
            UmbrawgAttribute::Jmax(v) => {
                println!("JunkPacketMaxSize: {}", v)
            }
            UmbrawgAttribute::S3(v) => println!("S3: {}", v),
            UmbrawgAttribute::S4(v) => println!("S4: {}", v),
            UmbrawgAttribute::H1(v) => println!("H1: {}", v),
            UmbrawgAttribute::H1Range(v) => println!("H1: {}", v),
            UmbrawgAttribute::H2(v) => println!("H2: {}", v),
            UmbrawgAttribute::H2Range(v) => println!("H2: {}", v),
            UmbrawgAttribute::H3(v) => println!("H3: {}", v),
            UmbrawgAttribute::H3Range(v) => println!("H3: {}", v),
            UmbrawgAttribute::H4(v) => println!("H4: {}", v),
            UmbrawgAttribute::H4Range(v) => println!("H4: {}", v),
            UmbrawgAttribute::I1(v) => println!("I1: {}", v),
            UmbrawgAttribute::ContentPaddingAddition(v) => {
                println!("ContentPaddingAddition: {}", v)
            }
            UmbrawgAttribute::RekeyAfterTime(v) => {
                println!("RekeyAfterTime: {}", v)
            }
            UmbrawgAttribute::RekeyTimeout(v) => {
                println!("RekeyTimeout: {}", v)
            }
            UmbrawgAttribute::RejectAfterTime(v) => {
                println!("RejectAfterTime: {}", v)
            }
            UmbrawgAttribute::KeepaliveTimeout(v) => {
                println!("KeepaliveTimeout: {}", v)
            }
            UmbrawgAttribute::MaxHandshakeAttempts(v) => {
                println!("MaxHandshakeAttempts: {}", v)
            }
            UmbrawgAttribute::RandomTrailers(v) => {
                println!("RandomTrailers: {}", v)
            }
            UmbrawgAttribute::DisableCookies(v) => {
                println!("DisableCookies: {}", v)
            }
            UmbrawgAttribute::HeaderProtectionKey(_) => {
                println!("HeaderProtectionKey: (hidden)")
            }
            _ => (),
        }
    }
}

#[cfg(target_os = "linux")]
fn print_wg_peer(attrs: &[UmbrawgPeerAttribute]) {
    for attr in attrs {
        match attr {
            UmbrawgPeerAttribute::PublicKey(v) => {
                println!("  PublicKey: {}", base64::encode(v))
            }
            UmbrawgPeerAttribute::PresharedKey(_) => {
                println!("  PresharedKey: (hidden)")
            }
            UmbrawgPeerAttribute::Endpoint(v) => {
                println!("  Endpoint: {}", v)
            }
            UmbrawgPeerAttribute::PersistentKeepalive(v) => {
                println!("  PersistentKeepalive: {}", v)
            }
            UmbrawgPeerAttribute::LastHandshake(v) => {
                println!("  LastHandshake: {:?}", v)
            }
            UmbrawgPeerAttribute::RxBytes(v) => {
                println!("  RxBytes: {}", v)
            }
            UmbrawgPeerAttribute::TxBytes(v) => {
                println!("  TxBytes: {}", v)
            }
            UmbrawgPeerAttribute::AllowedIps(ips) => {
                for ip in ips {
                    print_wg_allowedip(ip);
                }
            }
            _ => (),
        }
    }
}

#[cfg(target_os = "linux")]
fn print_wg_allowedip(nlas: &UmbrawgAllowedIp) -> Option<()> {
    let ipaddr = nlas.iter().find_map(|nla| {
        if let UmbrawgAllowedIpAttr::IpAddr(addr) = nla {
            Some(*addr)
        } else {
            None
        }
    })?;
    let cidr = nlas.iter().find_map(|nla| {
        if let UmbrawgAllowedIpAttr::Cidr(cidr) = nla {
            Some(*cidr)
        } else {
            None
        }
    })?;
    println!("  AllowedIp: {}/{}", ipaddr, cidr);
    Some(())
}
