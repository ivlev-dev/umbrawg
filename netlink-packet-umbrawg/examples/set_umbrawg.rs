// SPDX-License-Identifier: MIT

#[cfg(target_os = "linux")]
use std::{
    convert::TryInto,
    env::args,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

#[cfg(target_os = "linux")]
use futures::StreamExt;
#[cfg(target_os = "linux")]
use genetlink::new_connection;
#[cfg(target_os = "linux")]
use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_REQUEST,
};
#[cfg(target_os = "linux")]
use netlink_packet_generic::GenlMessage;
#[cfg(target_os = "linux")]
use netlink_packet_umbrawg::{
    UmbrawgAddressFamily, UmbrawgAllowedIp, UmbrawgAllowedIpAttr,
    UmbrawgAttribute, UmbrawgCmd, UmbrawgMessage, UmbrawgPeer,
    UmbrawgPeerAttribute,
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
        eprintln!("Usage: set_umbrawg <ifname>");
        return;
    }

    // The umbrawg interface need to exist before executing this code.
    // This can be done with `ip link <name> type umbrawg` command.
    let name = argv[1].clone();
    let priv_key = generate_priv_key();
    let peer_pub_key: [u8; UmbrawgAttribute::UWG_KEY_LEN] =
        base64::decode("8bdQrVLqiw3ZoHCucNh1YfH0iCWuyStniRr8t7H24Fk=")
            .unwrap()
            .try_into()
            .unwrap();

    let (connection, mut handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    let attributes = vec![
        UmbrawgAttribute::IfName(name),
        UmbrawgAttribute::PrivateKey(priv_key),
        UmbrawgAttribute::ListenPort(51820),
        UmbrawgAttribute::Fwmark(0),
        // Umbra specific parameters
        UmbrawgAttribute::JC(4),
        UmbrawgAttribute::Jmin(40),
        UmbrawgAttribute::Jmax(70),
        UmbrawgAttribute::S1(0x5566),
        // Umbra obfuscation parameters (example)
        UmbrawgAttribute::H1Range(
            netlink_packet_umbrawg::range::u32_range_from_string(
                "712026294-712074283",
            )
            .unwrap(),
        ),
        UmbrawgAttribute::S3(31),
        UmbrawgAttribute::S4(28),
        UmbrawgAttribute::I1("<r 149>".into()),
        UmbrawgAttribute::ContentPaddingAddition(51 | (197 << 16)),
        UmbrawgAttribute::RekeyAfterTime(104 | (149 << 16)),
        UmbrawgAttribute::RekeyTimeout(5 | (8 << 16)),
        UmbrawgAttribute::RejectAfterTime(184 | (199 << 16)),
        UmbrawgAttribute::KeepaliveTimeout(9 | (12 << 16)),
        UmbrawgAttribute::MaxHandshakeAttempts(18 | (23 << 16)),
        UmbrawgAttribute::RandomTrailers(true),
        UmbrawgAttribute::DisableCookies(false),
        UmbrawgAttribute::Peers(vec![UmbrawgPeer(vec![
            UmbrawgPeerAttribute::PublicKey(peer_pub_key),
            UmbrawgPeerAttribute::Endpoint(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, 10, 10, 1)),
                51820,
            )),
            UmbrawgPeerAttribute::AllowedIps(vec![
                UmbrawgAllowedIp(vec![
                    // ipv4 0.0.0.0/0
                    UmbrawgAllowedIpAttr::Family(UmbrawgAddressFamily::Ipv4),
                    UmbrawgAllowedIpAttr::IpAddr("0.0.0.0".parse().unwrap()),
                    UmbrawgAllowedIpAttr::Cidr(0),
                ]),
                UmbrawgAllowedIp(vec![
                    // ipv6 ::/0
                    UmbrawgAllowedIpAttr::Family(UmbrawgAddressFamily::Ipv6),
                    UmbrawgAllowedIpAttr::IpAddr("::".parse().unwrap()),
                    UmbrawgAllowedIpAttr::Cidr(0),
                ]),
            ]),
        ])]),
    ];

    let msg = UmbrawgMessage {
        cmd: UmbrawgCmd::SetDevice,
        attributes,
    };

    let genlmsg: GenlMessage<UmbrawgMessage> = GenlMessage::from_payload(msg);

    let mut nlmsg = NetlinkMessage::from(genlmsg);
    nlmsg.header.flags = NLM_F_REQUEST | NLM_F_ACK;

    let mut res = handle.request(nlmsg).await.unwrap();

    if let Some(result) = res.next().await {
        let rx_packet = result.unwrap();
        if let NetlinkPayload::Error(e) = rx_packet.payload {
            eprintln!("Error: {:?}", e.to_io());
        }
    }
}

#[cfg(target_os = "linux")]
fn generate_priv_key() -> [u8; UmbrawgAttribute::UWG_KEY_LEN] {
    let mut key = [0u8; UmbrawgAttribute::UWG_KEY_LEN];
    getrandom::getrandom(&mut key).unwrap();
    // modify random bytes using algorithm described
    // at https://cr.yp.to/ecdh.html.
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
    key
}
