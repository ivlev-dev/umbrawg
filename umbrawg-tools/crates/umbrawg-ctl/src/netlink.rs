use futures::StreamExt;
use genetlink::{new_connection, GenetlinkHandle};
use netlink_packet_core::{
    Emitable, NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST,
};
use netlink_packet_generic::{
    ctrl::{nlas::GenlCtrlAttrs, GenlCtrl, GenlCtrlCmd},
    GenlMessage,
};
use netlink_packet_umbrawg::constants::UWGDEVICE_F_REPLACE_PEERS;
use netlink_packet_umbrawg::constants::{
    UWGPEER_F_HAS_ADVANCED_SECURITY, UWGPEER_F_REMOVE_ME, UWGPEER_F_REPLACE_ALLOWEDIPS,
};
use netlink_packet_umbrawg::{
    fec_pack, fec_unpack, UmbrawgAddressFamily, UmbrawgAllowedIp, UmbrawgAllowedIpAttr,
    UmbrawgAttribute, UmbrawgCipher, UmbrawgCmd, UmbrawgMessage, UmbrawgPeer, UmbrawgPeerAttribute,
    FEC_ADAPTIVE, FEC_MAX_K, FEC_MAX_M, FEC_OFF,
};
use umbrawg_config::{AllowedIp, Cipher, Key, U16Range, U32Range};

use crate::error::Error;
use crate::model::{Device, Peer, SetDevice, TimeSpec};

const MAX_MESSAGE_SIZE: usize = 60_000;

pub async fn get_device(name: &str) -> Result<Device, Error> {
    let (mut handle, _) = connect().await?;
    let message = UmbrawgMessage {
        cmd: UmbrawgCmd::GetDevice,
        attributes: vec![UmbrawgAttribute::IfName(name.to_owned())],
    };
    let genl = GenlMessage::from_payload(message);
    let mut netlink = NetlinkMessage::from(genl);
    netlink.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    let mut stream = handle
        .request(netlink)
        .await
        .map_err(|error| Error::Netlink(error.to_string()))?;
    let mut builder = DeviceBuilder::new(name);
    let mut found = false;
    while let Some(item) = stream.next().await {
        let received = item.map_err(|error| Error::Netlink(error.to_string()))?;
        match received.payload {
            NetlinkPayload::InnerMessage(genl) => {
                found = true;
                builder.apply(&genl.payload.attributes)?;
            }
            NetlinkPayload::Error(error) => {
                if error.raw_code() == 0 {
                    continue;
                }
                return Err(map_error(error, Some(name)));
            }
            NetlinkPayload::Done(_) => break,
            _ => {}
        }
    }
    if !found {
        return Err(Error::InterfaceNotFound(name.to_owned()));
    }
    Ok(builder.finish())
}

pub async fn set_device(config: &SetDevice) -> Result<(), Error> {
    let (mut handle, version) = connect().await?;
    let messages = build_set_messages(config, version)?;
    for message in messages {
        let genl = GenlMessage::from_payload(message);
        let mut netlink = NetlinkMessage::from(genl);
        netlink.header.flags = NLM_F_REQUEST | NLM_F_ACK;
        let mut stream = handle
            .request(netlink)
            .await
            .map_err(|error| Error::Netlink(error.to_string()))?;
        while let Some(item) = stream.next().await {
            let received = item.map_err(|error| Error::Netlink(error.to_string()))?;
            match received.payload {
                NetlinkPayload::Error(error) => {
                    if error.raw_code() != 0 {
                        return Err(map_error(error, None));
                    }
                }
                NetlinkPayload::Done(_) => break,
                _ => {}
            }
        }
    }
    Ok(())
}

async fn connect() -> Result<(GenetlinkHandle, u32), Error> {
    let (connection, mut handle, _) =
        new_connection().map_err(|error| Error::NoKernelSupport(error.to_string()))?;
    tokio::spawn(connection);
    handle
        .resolve_family::<UmbrawgMessage>()
        .await
        .map_err(|error| Error::NoKernelSupport(error.to_string()))?;
    let version = family_version(&mut handle).await?;
    Ok((handle, version))
}

async fn family_version(handle: &mut GenetlinkHandle) -> Result<u32, Error> {
    let genl = GenlMessage::from_payload(GenlCtrl {
        cmd: GenlCtrlCmd::GetFamily,
        nlas: vec![GenlCtrlAttrs::FamilyName("umbrawg".to_owned())],
    });
    let mut netlink = NetlinkMessage::from(genl);
    netlink.header.flags = NLM_F_REQUEST | NLM_F_ACK;
    let mut stream = handle
        .request(netlink)
        .await
        .map_err(|error| Error::NoKernelSupport(error.to_string()))?;
    while let Some(item) = stream.next().await {
        let received = item.map_err(|error| Error::Netlink(error.to_string()))?;
        if let NetlinkPayload::InnerMessage(genl) = received.payload {
            for nla in &genl.payload.nlas {
                if let GenlCtrlAttrs::Version(version) = nla {
                    return Ok(*version);
                }
            }
        }
    }
    Err(Error::NoKernelSupport(
        "kernel did not report the umbrawg family version".to_owned(),
    ))
}

fn map_error(error: netlink_packet_core::ErrorMessage, iface: Option<&str>) -> Error {
    let io = error.to_io();
    if io.raw_os_error() == Some(libc::ENODEV) {
        if let Some(name) = iface {
            return Error::InterfaceNotFound(name.to_owned());
        }
    }
    Error::Netlink(io.to_string())
}

pub(crate) fn build_set_messages(
    config: &SetDevice,
    version: u32,
) -> Result<Vec<UmbrawgMessage>, Error> {
    if version < 2 {
        return Err(Error::NoKernelSupport(format!(
            "unsupported umbrawg generic netlink version {version}"
        )));
    }
    let first_attributes = device_attributes(config, version)?;
    let next_attributes = vec![UmbrawgAttribute::IfName(config.name.clone())];
    let peers: Vec<UmbrawgPeer> = config
        .peers
        .iter()
        .map(|peer| peer_attributes(peer, version))
        .collect::<Result<_, _>>()?;

    let mut chunks: Vec<Vec<UmbrawgPeer>> = Vec::new();
    let mut current = Vec::new();
    let mut current_len = 0usize;
    for peer in peers {
        let length = peer.buffer_len();
        if !current.is_empty() && current_len + length > MAX_MESSAGE_SIZE {
            chunks.push(std::mem::take(&mut current));
            current_len = 0;
        }
        current.push(peer);
        current_len += length;
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    if chunks.is_empty() {
        return Ok(vec![make_message(first_attributes, Vec::new())]);
    }
    Ok(chunks
        .into_iter()
        .enumerate()
        .map(|(index, chunk)| {
            let attributes = if index == 0 {
                first_attributes.clone()
            } else {
                next_attributes.clone()
            };
            make_message(attributes, chunk)
        })
        .collect())
}

fn make_message(mut attributes: Vec<UmbrawgAttribute>, peers: Vec<UmbrawgPeer>) -> UmbrawgMessage {
    if !peers.is_empty() {
        attributes.push(UmbrawgAttribute::Peers(peers));
    }
    UmbrawgMessage {
        cmd: UmbrawgCmd::SetDevice,
        attributes,
    }
}

fn device_attributes(config: &SetDevice, version: u32) -> Result<Vec<UmbrawgAttribute>, Error> {
    let device = &config.device;
    let mut attributes = vec![UmbrawgAttribute::IfName(config.name.clone())];
    if config.replace_peers {
        attributes.push(UmbrawgAttribute::Flags(UWGDEVICE_F_REPLACE_PEERS));
    }
    if let Some(key) = &device.private_key {
        attributes.push(UmbrawgAttribute::PrivateKey(key.to_bytes()));
    }
    if let Some(port) = device.listen_port {
        attributes.push(UmbrawgAttribute::ListenPort(port));
    }
    if let Some(extra_ports) = device.extra_ports {
        attributes.push(UmbrawgAttribute::ExtraPorts(extra_ports));
    }
    if let Some(fec) = &device.fec {
        attributes.push(UmbrawgAttribute::Fec(fec_value(fec)?));
    }
    if let Some(underlay_mtu) = device.underlay_mtu {
        attributes.push(UmbrawgAttribute::UnderlayMtu(underlay_mtu));
    }
    if let Some(fwmark) = device.fwmark {
        attributes.push(UmbrawgAttribute::Fwmark(fwmark));
    }
    let obfuscation = &device.obfuscation;
    if let Some(value) = obfuscation.jc {
        attributes.push(UmbrawgAttribute::JC(value));
    }
    if let Some(value) = obfuscation.jmin {
        attributes.push(UmbrawgAttribute::Jmin(value));
    }
    if let Some(value) = obfuscation.jmax {
        attributes.push(UmbrawgAttribute::Jmax(value));
    }
    if let Some(value) = obfuscation.s1 {
        attributes.push(UmbrawgAttribute::S1(value));
    }
    if let Some(value) = obfuscation.s2 {
        attributes.push(UmbrawgAttribute::S2(value));
    }
    if let Some(value) = obfuscation.s3 {
        attributes.push(UmbrawgAttribute::S3(value));
    }
    if let Some(value) = obfuscation.s4 {
        attributes.push(UmbrawgAttribute::S4(value));
    }
    for (index, value) in [
        obfuscation.h1,
        obfuscation.h2,
        obfuscation.h3,
        obfuscation.h4,
    ]
    .into_iter()
    .enumerate()
    {
        if let Some(value) = value {
            attributes.push(header_attribute(index, value, version));
        }
    }
    for (index, value) in [
        &obfuscation.i1,
        &obfuscation.i2,
        &obfuscation.i3,
        &obfuscation.i4,
        &obfuscation.i5,
    ]
    .into_iter()
    .enumerate()
    {
        if let Some(value) = value {
            attributes.push(intermediate_attribute(index, value.clone()));
        }
    }
    if let Some(key) = &obfuscation.header_protection_key {
        attributes.push(UmbrawgAttribute::HeaderProtectionKey(key.to_bytes()));
    }
    if let Some(value) = obfuscation.content_padding_addition {
        attributes.push(UmbrawgAttribute::ContentPaddingAddition(value.pack()));
    }
    if let Some(value) = obfuscation.rekey_after_time {
        attributes.push(UmbrawgAttribute::RekeyAfterTime(value.pack()));
    }
    if let Some(value) = obfuscation.rekey_timeout {
        attributes.push(UmbrawgAttribute::RekeyTimeout(value.pack()));
    }
    if let Some(value) = obfuscation.reject_after_time {
        attributes.push(UmbrawgAttribute::RejectAfterTime(value.pack()));
    }
    if let Some(value) = obfuscation.keepalive_timeout {
        attributes.push(UmbrawgAttribute::KeepaliveTimeout(value.pack()));
    }
    if let Some(value) = obfuscation.max_handshake_attempts {
        attributes.push(UmbrawgAttribute::MaxHandshakeAttempts(value.pack()));
    }
    if let Some(value) = obfuscation.random_trailers {
        attributes.push(UmbrawgAttribute::RandomTrailers(value));
    }
    if let Some(value) = obfuscation.disable_cookies {
        attributes.push(UmbrawgAttribute::DisableCookies(value));
    }
    Ok(attributes)
}

fn header_attribute(index: usize, value: U32Range, version: u32) -> UmbrawgAttribute {
    if version >= 3 {
        match index {
            0 => UmbrawgAttribute::H1Range(value.pack()),
            1 => UmbrawgAttribute::H2Range(value.pack()),
            2 => UmbrawgAttribute::H3Range(value.pack()),
            _ => UmbrawgAttribute::H4Range(value.pack()),
        }
    } else {
        let text = value.to_string();
        match index {
            0 => UmbrawgAttribute::H1(text),
            1 => UmbrawgAttribute::H2(text),
            2 => UmbrawgAttribute::H3(text),
            _ => UmbrawgAttribute::H4(text),
        }
    }
}

fn intermediate_attribute(index: usize, value: String) -> UmbrawgAttribute {
    match index {
        0 => UmbrawgAttribute::I1(value),
        1 => UmbrawgAttribute::I2(value),
        2 => UmbrawgAttribute::I3(value),
        3 => UmbrawgAttribute::I4(value),
        _ => UmbrawgAttribute::I5(value),
    }
}

fn peer_attributes(peer: &umbrawg_config::PeerConfig, version: u32) -> Result<UmbrawgPeer, Error> {
    let mut flags = 0u32;
    if peer.remove {
        flags |= UWGPEER_F_REMOVE_ME;
    } else if peer.allowed_ips.is_some() {
        flags |= UWGPEER_F_REPLACE_ALLOWEDIPS;
    }
    let mut attributes = vec![UmbrawgPeerAttribute::PublicKey(peer.public_key.to_bytes())];
    if flags != 0 {
        attributes.push(UmbrawgPeerAttribute::Flags(flags));
    }
    if peer.remove {
        return Ok(UmbrawgPeer(attributes));
    }
    if let Some(key) = &peer.preshared_key {
        attributes.push(UmbrawgPeerAttribute::PresharedKey(key.to_bytes()));
    }
    if let Some(endpoint) = peer.endpoint {
        attributes.push(UmbrawgPeerAttribute::Endpoint(endpoint));
    }
    if let Some(keepalive) = peer.persistent_keepalive {
        if version >= 3 {
            attributes.push(UmbrawgPeerAttribute::PersistentKeepaliveRange(
                keepalive.pack(),
            ));
        } else {
            attributes.push(UmbrawgPeerAttribute::PersistentKeepalive(keepalive.lo()));
        }
    }
    if peer.advanced_security == Some(true) {
        attributes.push(UmbrawgPeerAttribute::AdvancedSecurity(true));
    }
    if let Some(cipher) = peer.cipher {
        attributes.push(UmbrawgPeerAttribute::Cipher(cipher_attributes(cipher)));
    }
    if let Some(allowed_ips) = &peer.allowed_ips {
        if !allowed_ips.is_empty() {
            attributes.push(UmbrawgPeerAttribute::AllowedIps(
                allowed_ips.iter().map(allowed_ip_attributes).collect(),
            ));
        }
    }
    Ok(UmbrawgPeer(attributes))
}

fn cipher_attributes(cipher: Cipher) -> UmbrawgCipher {
    match cipher {
        Cipher::ChaCha20Poly1305 => UmbrawgCipher::ChaCha20Poly1305,
        Cipher::Aes256Gcm => UmbrawgCipher::Aes256Gcm,
    }
}

fn allowed_ip_attributes(allowed_ip: &AllowedIp) -> UmbrawgAllowedIp {
    let family = match allowed_ip.address {
        std::net::IpAddr::V4(_) => UmbrawgAddressFamily::Ipv4,
        std::net::IpAddr::V6(_) => UmbrawgAddressFamily::Ipv6,
    };
    UmbrawgAllowedIp(vec![
        UmbrawgAllowedIpAttr::Family(family),
        UmbrawgAllowedIpAttr::IpAddr(allowed_ip.address),
        UmbrawgAllowedIpAttr::Cidr(allowed_ip.cidr),
    ])
}

struct DeviceBuilder {
    device: Device,
}

impl DeviceBuilder {
    fn new(name: &str) -> Self {
        Self {
            device: Device::new(name),
        }
    }

    fn apply(&mut self, attributes: &[UmbrawgAttribute]) -> Result<(), Error> {
        for attribute in attributes {
            match attribute {
                UmbrawgAttribute::IfIndex(value) => self.device.ifindex = Some(*value),
                UmbrawgAttribute::IfName(value) => self.device.name = value.clone(),
                UmbrawgAttribute::PrivateKey(value) => {
                    self.device.private_key = Some(Key::from_bytes(*value));
                }
                UmbrawgAttribute::PublicKey(value) => {
                    self.device.public_key = Some(Key::from_bytes(*value));
                }
                UmbrawgAttribute::ListenPort(value) => self.device.listen_port = *value,
                UmbrawgAttribute::ExtraPorts(value) => self.device.extra_ports = Some(*value),
                UmbrawgAttribute::Fec(value) => self.device.fec = Some(fec_text(*value)?),
                UmbrawgAttribute::UnderlayMtu(value) => {
                    self.device.underlay_mtu = Some(*value);
                }
                UmbrawgAttribute::FecStats(value) => {
                    self.device.fec_stats = Some((*value).into());
                }
                UmbrawgAttribute::Fwmark(value) => self.device.fwmark = *value,
                UmbrawgAttribute::JC(value) => self.device.obfuscation.jc = Some(*value),
                UmbrawgAttribute::Jmin(value) => self.device.obfuscation.jmin = Some(*value),
                UmbrawgAttribute::Jmax(value) => self.device.obfuscation.jmax = Some(*value),
                UmbrawgAttribute::S1(value) => self.device.obfuscation.s1 = Some(*value),
                UmbrawgAttribute::S2(value) => self.device.obfuscation.s2 = Some(*value),
                UmbrawgAttribute::S3(value) => self.device.obfuscation.s3 = Some(*value),
                UmbrawgAttribute::S4(value) => self.device.obfuscation.s4 = Some(*value),
                UmbrawgAttribute::H1(value) => {
                    self.device.obfuscation.h1 = Some(parse_header("H1", value)?);
                }
                UmbrawgAttribute::H2(value) => {
                    self.device.obfuscation.h2 = Some(parse_header("H2", value)?);
                }
                UmbrawgAttribute::H3(value) => {
                    self.device.obfuscation.h3 = Some(parse_header("H3", value)?);
                }
                UmbrawgAttribute::H4(value) => {
                    self.device.obfuscation.h4 = Some(parse_header("H4", value)?);
                }
                UmbrawgAttribute::H1Range(value) => {
                    self.device.obfuscation.h1 = Some(U32Range::unpack(*value));
                }
                UmbrawgAttribute::H2Range(value) => {
                    self.device.obfuscation.h2 = Some(U32Range::unpack(*value));
                }
                UmbrawgAttribute::H3Range(value) => {
                    self.device.obfuscation.h3 = Some(U32Range::unpack(*value));
                }
                UmbrawgAttribute::H4Range(value) => {
                    self.device.obfuscation.h4 = Some(U32Range::unpack(*value));
                }
                UmbrawgAttribute::I1(value) => self.device.obfuscation.i1 = Some(value.clone()),
                UmbrawgAttribute::I2(value) => self.device.obfuscation.i2 = Some(value.clone()),
                UmbrawgAttribute::I3(value) => self.device.obfuscation.i3 = Some(value.clone()),
                UmbrawgAttribute::I4(value) => self.device.obfuscation.i4 = Some(value.clone()),
                UmbrawgAttribute::I5(value) => self.device.obfuscation.i5 = Some(value.clone()),
                UmbrawgAttribute::HeaderProtectionKey(value) => {
                    self.device.obfuscation.header_protection_key = Some(Key::from_bytes(*value));
                }
                UmbrawgAttribute::ContentPaddingAddition(value) => {
                    self.device.obfuscation.content_padding_addition =
                        Some(U16Range::unpack(*value));
                }
                UmbrawgAttribute::RekeyAfterTime(value) => {
                    self.device.obfuscation.rekey_after_time = Some(U16Range::unpack(*value));
                }
                UmbrawgAttribute::RekeyTimeout(value) => {
                    self.device.obfuscation.rekey_timeout = Some(U16Range::unpack(*value));
                }
                UmbrawgAttribute::RejectAfterTime(value) => {
                    self.device.obfuscation.reject_after_time = Some(U16Range::unpack(*value));
                }
                UmbrawgAttribute::KeepaliveTimeout(value) => {
                    self.device.obfuscation.keepalive_timeout = Some(U16Range::unpack(*value));
                }
                UmbrawgAttribute::MaxHandshakeAttempts(value) => {
                    self.device.obfuscation.max_handshake_attempts = Some(U16Range::unpack(*value));
                }
                UmbrawgAttribute::RandomTrailers(value) => {
                    self.device.obfuscation.random_trailers = Some(*value);
                }
                UmbrawgAttribute::DisableCookies(value) => {
                    self.device.obfuscation.disable_cookies = Some(*value);
                }
                UmbrawgAttribute::Peers(peers) => {
                    for peer in peers {
                        self.apply_peer(peer)?;
                    }
                }
                UmbrawgAttribute::Peer(peer) => self.apply_peer(peer)?,
                _ => {}
            }
        }
        Ok(())
    }

    fn apply_peer(&mut self, peer: &UmbrawgPeer) -> Result<(), Error> {
        let public_key = peer.0.iter().find_map(|attribute| match attribute {
            UmbrawgPeerAttribute::PublicKey(value) => Some(Key::from_bytes(*value)),
            _ => None,
        });
        let public_key = public_key
            .ok_or_else(|| Error::Protocol("netlink peer without a public key".to_owned()))?;
        let index = self
            .device
            .peers
            .iter()
            .position(|existing| existing.public_key == public_key);
        let index = match index {
            Some(index) => index,
            None => {
                self.device.peers.push(Peer {
                    public_key: public_key.clone(),
                    ..Peer::default()
                });
                self.device.peers.len() - 1
            }
        };
        let target = &mut self.device.peers[index];
        for attribute in &peer.0 {
            match attribute {
                UmbrawgPeerAttribute::PresharedKey(value) => {
                    let key = Key::from_bytes(*value);
                    target.preshared_key = (!key.is_zero()).then_some(key);
                }
                UmbrawgPeerAttribute::Endpoint(value) => target.endpoint = Some(*value),
                UmbrawgPeerAttribute::PersistentKeepalive(value) => {
                    target.persistent_keepalive = U16Range::single(*value);
                }
                UmbrawgPeerAttribute::PersistentKeepaliveRange(value) => {
                    target.persistent_keepalive = U16Range::unpack(*value);
                }
                UmbrawgPeerAttribute::LastHandshake(value) => {
                    target.last_handshake_time = TimeSpec::new(value.seconds, value.nano_seconds);
                }
                UmbrawgPeerAttribute::RxBytes(value) => target.rx_bytes = *value,
                UmbrawgPeerAttribute::TxBytes(value) => target.tx_bytes = *value,
                UmbrawgPeerAttribute::AllowedIps(values) => {
                    for value in values {
                        target.allowed_ips.push(allowed_ip_from_netlink(value)?);
                    }
                }
                UmbrawgPeerAttribute::Flags(value) => {
                    if value & UWGPEER_F_HAS_ADVANCED_SECURITY != 0 {
                        target.advanced_security = Some(true);
                    } else if target.advanced_security.is_none() {
                        target.advanced_security = Some(false);
                    }
                }
                UmbrawgPeerAttribute::AdvancedSecurity(enabled) => {
                    if *enabled {
                        target.advanced_security = Some(true);
                    } else if target.advanced_security.is_none() {
                        target.advanced_security = Some(false);
                    }
                }
                UmbrawgPeerAttribute::Cipher(cipher) => {
                    target.cipher = match cipher {
                        UmbrawgCipher::ChaCha20Poly1305 => Some(Cipher::ChaCha20Poly1305),
                        UmbrawgCipher::Aes256Gcm => Some(Cipher::Aes256Gcm),
                    };
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn finish(self) -> Device {
        self.device
    }
}

fn allowed_ip_from_netlink(value: &UmbrawgAllowedIp) -> Result<AllowedIp, Error> {
    let mut address = None;
    let mut cidr = None;
    for attribute in &value.0 {
        match attribute {
            UmbrawgAllowedIpAttr::IpAddr(value) => address = Some(*value),
            UmbrawgAllowedIpAttr::Cidr(value) => cidr = Some(*value),
            _ => {}
        }
    }
    let address = address
        .ok_or_else(|| Error::Protocol("netlink allowed IP without an address".to_owned()))?;
    let cidr = cidr.unwrap_or_else(|| umbrawg_config::max_prefix_len(address));
    AllowedIp::new(address, cidr)
        .map_err(|error| Error::Protocol(format!("invalid netlink allowed IP: {error}")))
}

fn parse_header(name: &str, value: &str) -> Result<U32Range, Error> {
    U32Range::parse(value)
        .map_err(|error| Error::Protocol(format!("invalid {name} from kernel: {error}")))
}

fn fec_value(text: &str) -> Result<u32, Error> {
    let normalized = text.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "off" => return Ok(FEC_OFF),
        "adaptive" => return Ok(FEC_ADAPTIVE),
        _ => {}
    }
    let invalid = || Error::Protocol(format!("invalid FEC mode `{text}`"));
    let (shards, parity) = normalized.split_once(':').ok_or_else(invalid)?;
    if shards.is_empty()
        || parity.is_empty()
        || !shards.bytes().all(|byte| byte.is_ascii_digit())
        || !parity.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid());
    }
    let shards: u8 = shards.parse().map_err(|_| invalid())?;
    let parity: u8 = parity.parse().map_err(|_| invalid())?;
    if shards > FEC_MAX_K || parity > FEC_MAX_M {
        return Err(Error::Protocol(format!(
            "invalid FEC mode `{text}`: K must be 1..={FEC_MAX_K} and M must be 1..={FEC_MAX_M}"
        )));
    }
    fec_pack(shards, parity).ok_or_else(invalid)
}

fn fec_text(value: u32) -> Result<String, Error> {
    match value {
        FEC_OFF => Ok("off".to_owned()),
        FEC_ADAPTIVE => Ok("adaptive".to_owned()),
        _ => match fec_unpack(value) {
            Some((shards, parity)) => Ok(format!("{shards}:{parity}")),
            None => Err(Error::Protocol(format!(
                "invalid FEC value {value} from kernel"
            ))),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ConfigApplication;
    use netlink_packet_core::{Emitable, Nla, ParseableParametrized};
    use netlink_packet_generic::GenlHeader;

    fn config() -> SetDevice {
        let mut config = SetDevice::for_interface("test0", Default::default());
        config.replace_peers = true;
        config.device.listen_port = Some(51820);
        config.device.extra_ports = Some(4);
        config.device.obfuscation.jc = Some(4);
        config.device.obfuscation.h1 = Some(U32Range::new(61_220_074, 118_999_195));
        config.device.obfuscation.i1 = Some("<b 0x1><c>".to_owned());
        config.device.obfuscation.content_padding_addition = Some(U16Range::new(0, 100));
        config.device.obfuscation.random_trailers = Some(true);
        config.peers.push(umbrawg_config::PeerConfig {
            public_key: Key::from_hex(
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            )
            .expect("valid"),
            preshared_key: None,
            cipher: Some(Cipher::Aes256Gcm),
            advanced_security: None,
            allowed_ips: Some(vec!["10.0.0.0/8".parse().expect("valid")]),
            endpoint: Some("192.0.2.1:51820".parse().expect("valid")),
            persistent_keepalive: Some(U16Range::single(25)),
            remove: false,
        });
        config
    }

    fn file_config_without_allowed_ips() -> umbrawg_config::Config {
        let mut config = umbrawg_config::Config::default();
        config.peers.push(umbrawg_config::PeerConfig {
            public_key: Key::from_hex(
                "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
            )
            .expect("valid"),
            preshared_key: None,
            cipher: None,
            advanced_security: None,
            allowed_ips: None,
            endpoint: None,
            persistent_keepalive: None,
            remove: false,
        });
        config
    }

    #[test]
    fn version_three_uses_native_ranges() {
        let messages = build_set_messages(&config(), 3).expect("valid");
        assert_eq!(messages.len(), 1);
        let attributes = &messages[0].attributes;
        assert!(attributes.contains(&UmbrawgAttribute::Flags(UWGDEVICE_F_REPLACE_PEERS)));
        assert!(attributes.contains(&UmbrawgAttribute::ExtraPorts(4)));
        assert!(attributes.contains(&UmbrawgAttribute::H1Range(
            U32Range::new(61_220_074, 118_999_195).pack()
        )));
        let peers = attributes
            .iter()
            .find_map(|attribute| match attribute {
                UmbrawgAttribute::Peers(peers) => Some(peers),
                _ => None,
            })
            .expect("peers");
        assert!(peers[0]
            .0
            .contains(&UmbrawgPeerAttribute::PersistentKeepaliveRange(
                U16Range::single(25).pack()
            )));
        assert!(peers[0]
            .0
            .contains(&UmbrawgPeerAttribute::Flags(UWGPEER_F_REPLACE_ALLOWEDIPS)));
        assert!(peers[0]
            .0
            .contains(&UmbrawgPeerAttribute::Cipher(UmbrawgCipher::Aes256Gcm)));
    }

    #[test]
    fn version_two_uses_string_headers() {
        let messages = build_set_messages(&config(), 2).expect("valid");
        let attributes = &messages[0].attributes;
        assert!(attributes.contains(&UmbrawgAttribute::H1("61220074-118999195".to_owned())));
        let peers = attributes
            .iter()
            .find_map(|attribute| match attribute {
                UmbrawgAttribute::Peers(peers) => Some(peers),
                _ => None,
            })
            .expect("peers");
        assert!(peers[0]
            .0
            .contains(&UmbrawgPeerAttribute::PersistentKeepalive(25)));
    }

    #[test]
    fn removes_peer_with_flags_only() {
        let mut config = config();
        config.peers[0].remove = true;
        config.peers[0].allowed_ips = None;
        let messages = build_set_messages(&config, 3).expect("valid");
        let peers = messages[0]
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                UmbrawgAttribute::Peers(peers) => Some(peers),
                _ => None,
            })
            .expect("peers");
        assert!(peers[0]
            .0
            .contains(&UmbrawgPeerAttribute::Flags(UWGPEER_F_REMOVE_ME)));
        assert!(!peers[0]
            .0
            .iter()
            .any(|attribute| matches!(attribute, UmbrawgPeerAttribute::Endpoint(_))));
    }

    #[test]
    fn addconf_message_keeps_running_peers_and_replaces_allowed_ips() {
        let config = file_config_without_allowed_ips();
        let set = SetDevice::from_config_file("test0", &config, ConfigApplication::Append);
        let messages = build_set_messages(&set, 3).expect("valid");
        let attributes = &messages[0].attributes;
        assert!(!attributes
            .iter()
            .any(|attribute| matches!(attribute, UmbrawgAttribute::Flags(_))));
        let peers = attributes
            .iter()
            .find_map(|attribute| match attribute {
                UmbrawgAttribute::Peers(peers) => Some(peers),
                _ => None,
            })
            .expect("peers");
        assert!(peers[0]
            .0
            .contains(&UmbrawgPeerAttribute::Flags(UWGPEER_F_REPLACE_ALLOWEDIPS)));
        assert!(!peers[0]
            .0
            .iter()
            .any(|attribute| matches!(attribute, UmbrawgPeerAttribute::AllowedIps(_))));
    }

    #[test]
    fn syncconf_message_removes_missing_peers() {
        let config = file_config_without_allowed_ips();
        let mut runtime = Device::new("test0");
        runtime.peers.push(Peer {
            public_key: config.peers[0].public_key.clone(),
            ..Peer::default()
        });
        runtime.peers.push(Peer {
            public_key: Key::from_bytes([7u8; 32]),
            ..Peer::default()
        });
        let set = SetDevice::synced_from("test0", &config, &runtime);
        let messages = build_set_messages(&set, 3).expect("valid");
        let peers = messages[0]
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                UmbrawgAttribute::Peers(peers) => Some(peers),
                _ => None,
            })
            .expect("peers");
        assert_eq!(peers.len(), 2);
        let removed = peers
            .iter()
            .find(|peer| peer.0.contains(&UmbrawgPeerAttribute::PublicKey([7u8; 32])))
            .expect("removed peer");
        assert!(removed
            .0
            .contains(&UmbrawgPeerAttribute::Flags(UWGPEER_F_REMOVE_ME)));
    }

    #[test]
    fn rejects_old_family_version() {
        assert!(build_set_messages(&config(), 1).is_err());
    }

    #[test]
    fn sends_extra_ports_only_when_configured() {
        let mut config = config();
        config.device.extra_ports = None;
        let messages = build_set_messages(&config, 3).expect("valid");
        assert!(!messages[0]
            .attributes
            .iter()
            .any(|attribute| matches!(attribute, UmbrawgAttribute::ExtraPorts(_))));

        config.device.extra_ports = Some(8);
        let messages = build_set_messages(&config, 3).expect("valid");
        assert!(messages[0]
            .attributes
            .contains(&UmbrawgAttribute::ExtraPorts(8)));
    }

    #[test]
    fn splits_large_peer_lists() {
        let mut config = config();
        config.peers.clear();
        for index in 0..1000u16 {
            let mut key = [0u8; 32];
            key[..2].copy_from_slice(&index.to_le_bytes());
            key[2] = 1;
            config.peers.push(umbrawg_config::PeerConfig {
                public_key: Key::from_bytes(key),
                preshared_key: None,
                cipher: None,
                advanced_security: None,
                allowed_ips: Some(vec!["10.0.0.0/8".parse().expect("valid")]),
                endpoint: None,
                persistent_keepalive: None,
                remove: false,
            });
        }
        let messages = build_set_messages(&config, 3).expect("valid");
        assert!(messages.len() > 1);
        assert!(messages[0]
            .attributes
            .contains(&UmbrawgAttribute::Flags(UWGDEVICE_F_REPLACE_PEERS)));
        assert!(!messages[1]
            .attributes
            .iter()
            .any(|attribute| matches!(attribute, UmbrawgAttribute::Flags(_))));
    }

    #[test]
    fn netlink_round_trip() {
        let peer_key =
            Key::from_hex("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")
                .expect("valid");
        let message = UmbrawgMessage {
            cmd: UmbrawgCmd::GetDevice,
            attributes: vec![
                UmbrawgAttribute::IfName("test0".to_owned()),
                UmbrawgAttribute::IfIndex(7),
                UmbrawgAttribute::ListenPort(51820),
                UmbrawgAttribute::ExtraPorts(7),
                UmbrawgAttribute::Fec(0x0802),
                UmbrawgAttribute::Fwmark(0x12),
                UmbrawgAttribute::PrivateKey([1u8; 32]),
                UmbrawgAttribute::PublicKey([2u8; 32]),
                UmbrawgAttribute::JC(4),
                UmbrawgAttribute::Jmin(40),
                UmbrawgAttribute::Jmax(70),
                UmbrawgAttribute::S1(92),
                UmbrawgAttribute::S2(115),
                UmbrawgAttribute::S3(44),
                UmbrawgAttribute::S4(9),
                UmbrawgAttribute::H1Range(U32Range::new(10, 20).pack()),
                UmbrawgAttribute::H2Range(U32Range::single(2).pack()),
                UmbrawgAttribute::H3Range(U32Range::single(3).pack()),
                UmbrawgAttribute::H4Range(U32Range::single(4).pack()),
                UmbrawgAttribute::I1("<b 0x1><c>".to_owned()),
                UmbrawgAttribute::HeaderProtectionKey([3u8; 32]),
                UmbrawgAttribute::ContentPaddingAddition(U16Range::new(0, 100).pack()),
                UmbrawgAttribute::RekeyAfterTime(U16Range::single(120).pack()),
                UmbrawgAttribute::RekeyTimeout(U16Range::single(5).pack()),
                UmbrawgAttribute::RejectAfterTime(U16Range::single(180).pack()),
                UmbrawgAttribute::KeepaliveTimeout(U16Range::single(10).pack()),
                UmbrawgAttribute::MaxHandshakeAttempts(U16Range::single(7).pack()),
                UmbrawgAttribute::RandomTrailers(true),
                UmbrawgAttribute::DisableCookies(false),
                UmbrawgAttribute::Peers(vec![UmbrawgPeer(vec![
                    UmbrawgPeerAttribute::PublicKey(peer_key.to_bytes()),
                    UmbrawgPeerAttribute::PresharedKey([4u8; 32]),
                    UmbrawgPeerAttribute::Flags(UWGPEER_F_HAS_ADVANCED_SECURITY),
                    UmbrawgPeerAttribute::Endpoint("192.0.2.1:51820".parse().expect("valid")),
                    UmbrawgPeerAttribute::PersistentKeepaliveRange(U16Range::single(25).pack()),
                    UmbrawgPeerAttribute::AllowedIps(vec![UmbrawgAllowedIp(vec![
                        UmbrawgAllowedIpAttr::Family(UmbrawgAddressFamily::Ipv4),
                        UmbrawgAllowedIpAttr::IpAddr("10.0.0.0".parse().expect("valid")),
                        UmbrawgAllowedIpAttr::Cidr(8),
                    ])]),
                    UmbrawgPeerAttribute::LastHandshake(netlink_packet_umbrawg::UmbrawgTimeSpec {
                        seconds: 100,
                        nano_seconds: 5,
                    }),
                    UmbrawgPeerAttribute::RxBytes(10),
                    UmbrawgPeerAttribute::TxBytes(20),
                    UmbrawgPeerAttribute::Cipher(UmbrawgCipher::Aes256Gcm),
                ])]),
            ],
        };
        let mut buffer = vec![0u8; message.buffer_len()];
        message.emit(&mut buffer);
        let parsed = UmbrawgMessage::parse_with_param(&buffer, GenlHeader { cmd: 0, version: 2 })
            .expect("parse");
        let mut builder = DeviceBuilder::new("test0");
        builder.apply(&parsed.attributes).expect("apply");
        let device = builder.finish();
        assert_eq!(device.ifindex, Some(7));
        assert_eq!(device.listen_port, 51820);
        assert_eq!(device.extra_ports, Some(7));
        assert_eq!(device.fec.as_deref(), Some("8:2"));
        assert_eq!(device.fwmark, 0x12);
        assert_eq!(device.obfuscation.jc, Some(4));
        assert_eq!(device.obfuscation.h1, Some(U32Range::new(10, 20)));
        assert_eq!(device.obfuscation.i1.as_deref(), Some("<b 0x1><c>"));
        assert_eq!(
            device.obfuscation.content_padding_addition,
            Some(U16Range::new(0, 100))
        );
        assert_eq!(device.obfuscation.random_trailers, Some(true));
        assert_eq!(device.obfuscation.disable_cookies, Some(false));
        assert_eq!(device.peers.len(), 1);
        let peer = &device.peers[0];
        assert_eq!(peer.public_key, peer_key);
        assert_eq!(peer.persistent_keepalive, U16Range::single(25));
        assert_eq!(peer.allowed_ips.len(), 1);
        assert_eq!(peer.allowed_ips[0].to_string(), "10.0.0.0/8");
        assert_eq!(peer.last_handshake_time, TimeSpec::new(100, 5));
        assert_eq!(peer.rx_bytes, 10);
        assert_eq!(peer.tx_bytes, 20);
        assert_eq!(peer.advanced_security, Some(true));
        assert_eq!(peer.cipher, Some(Cipher::Aes256Gcm));
    }

    #[test]
    fn coalesces_split_peers() {
        let key = Key::from_bytes([9u8; 32]);
        let first = UmbrawgPeer(vec![
            UmbrawgPeerAttribute::PublicKey(key.to_bytes()),
            UmbrawgPeerAttribute::PersistentKeepaliveRange(25),
        ]);
        let second = UmbrawgPeer(vec![
            UmbrawgPeerAttribute::PublicKey(key.to_bytes()),
            UmbrawgPeerAttribute::AllowedIps(vec![UmbrawgAllowedIp(vec![
                UmbrawgAllowedIpAttr::Family(UmbrawgAddressFamily::Ipv6),
                UmbrawgAllowedIpAttr::IpAddr("fd00::".parse().expect("valid")),
                UmbrawgAllowedIpAttr::Cidr(64),
            ])]),
        ]);
        let mut builder = DeviceBuilder::new("test0");
        builder
            .apply(&[UmbrawgAttribute::Peers(vec![first, second])])
            .expect("apply");
        let device = builder.finish();
        assert_eq!(device.peers.len(), 1);
        assert_eq!(device.peers[0].allowed_ips.len(), 1);
    }

    fn peer_device(peer: UmbrawgPeer) -> Device {
        let mut builder = DeviceBuilder::new("test0");
        builder
            .apply(&[UmbrawgAttribute::Peers(vec![peer])])
            .expect("apply");
        builder.finish()
    }

    #[test]
    fn reads_advanced_security_from_peer_flags() {
        let key = Key::from_bytes([5u8; 32]);
        let device = peer_device(UmbrawgPeer(vec![
            UmbrawgPeerAttribute::PublicKey(key.to_bytes()),
            UmbrawgPeerAttribute::Flags(UWGPEER_F_HAS_ADVANCED_SECURITY),
        ]));
        assert_eq!(device.peers[0].advanced_security, Some(true));

        let device = peer_device(UmbrawgPeer(vec![
            UmbrawgPeerAttribute::PublicKey(key.to_bytes()),
            UmbrawgPeerAttribute::Flags(0),
        ]));
        assert_eq!(device.peers[0].advanced_security, Some(false));

        let device = peer_device(UmbrawgPeer(vec![UmbrawgPeerAttribute::PublicKey(
            key.to_bytes(),
        )]));
        assert_eq!(device.peers[0].advanced_security, None);
    }

    #[test]
    fn reads_advanced_security_from_the_flag_attribute() {
        let key = Key::from_bytes([6u8; 32]);
        let device = peer_device(UmbrawgPeer(vec![
            UmbrawgPeerAttribute::PublicKey(key.to_bytes()),
            UmbrawgPeerAttribute::AdvancedSecurity(true),
        ]));
        assert_eq!(device.peers[0].advanced_security, Some(true));
    }

    #[test]
    fn reads_cipher_from_peer_attribute() {
        let key = Key::from_bytes([7u8; 32]);
        let device = peer_device(UmbrawgPeer(vec![
            UmbrawgPeerAttribute::PublicKey(key.to_bytes()),
            UmbrawgPeerAttribute::Cipher(UmbrawgCipher::Aes256Gcm),
        ]));
        assert_eq!(device.peers[0].cipher, Some(Cipher::Aes256Gcm));

        let device = peer_device(UmbrawgPeer(vec![UmbrawgPeerAttribute::PublicKey(
            key.to_bytes(),
        )]));
        assert_eq!(device.peers[0].cipher, None);
    }

    #[test]
    fn sends_cipher_for_configured_peers_only() {
        let mut config = config();
        assert!(sent_peer_from(&config)
            .0
            .contains(&UmbrawgPeerAttribute::Cipher(UmbrawgCipher::Aes256Gcm)));

        config.peers[0].cipher = None;
        assert!(!sent_peer_from(&config)
            .0
            .iter()
            .any(|attribute| matches!(attribute, UmbrawgPeerAttribute::Cipher(_))));
    }

    fn sent_peer_from(config: &SetDevice) -> UmbrawgPeer {
        let messages = build_set_messages(config, 3).expect("valid");
        messages[0]
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                UmbrawgAttribute::Peers(peers) => Some(peers[0].clone()),
                _ => None,
            })
            .expect("peer")
    }

    fn sent_peer(advanced_security: Option<bool>) -> UmbrawgPeer {
        let mut config = config();
        config.peers[0].advanced_security = advanced_security;
        let messages = build_set_messages(&config, 3).expect("valid");
        messages[0]
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                UmbrawgAttribute::Peers(peers) => Some(peers[0].clone()),
                _ => None,
            })
            .expect("peer")
    }

    #[test]
    fn sends_advanced_security_for_enabled_peers_only() {
        assert!(sent_peer(Some(true))
            .0
            .contains(&UmbrawgPeerAttribute::AdvancedSecurity(true)));
        assert!(!sent_peer(Some(false))
            .0
            .iter()
            .any(|attribute| matches!(attribute, UmbrawgPeerAttribute::AdvancedSecurity(_))));
        assert!(!sent_peer(None)
            .0
            .iter()
            .any(|attribute| matches!(attribute, UmbrawgPeerAttribute::AdvancedSecurity(_))));
    }

    #[test]
    fn advanced_security_wire_format_is_a_presence_flag() {
        use netlink_packet_umbrawg::constants::UWGPEER_A_ADVANCED_SECURITY;
        let peer = sent_peer(Some(true));
        let attribute = peer
            .0
            .iter()
            .find(|attribute| matches!(attribute, UmbrawgPeerAttribute::AdvancedSecurity(_)))
            .expect("advanced security");
        assert_eq!(attribute.kind(), UWGPEER_A_ADVANCED_SECURITY);
        assert_eq!(attribute.value_len(), 0);
    }

    #[test]
    fn sends_fec_only_when_configured() {
        let mut config = config();
        assert_eq!(config.device.fec, None);
        let messages = build_set_messages(&config, 3).expect("valid");
        assert!(!messages[0]
            .attributes
            .iter()
            .any(|attribute| matches!(attribute, UmbrawgAttribute::Fec(_))));

        config.device.fec = Some("8:2".to_owned());
        let messages = build_set_messages(&config, 3).expect("valid");
        let attributes = &messages[0].attributes;
        assert!(attributes.contains(&UmbrawgAttribute::Fec(0x0802)));

        config.device.fec = Some("adaptive".to_owned());
        let messages = build_set_messages(&config, 3).expect("valid");
        let attributes = &messages[0].attributes;
        assert!(attributes.contains(&UmbrawgAttribute::Fec(1)));

        config.device.fec = Some("off".to_owned());
        let messages = build_set_messages(&config, 3).expect("valid");
        let attributes = &messages[0].attributes;
        assert!(attributes.contains(&UmbrawgAttribute::Fec(0)));
    }

    #[test]
    fn sends_and_reads_underlay_mtu() {
        let mut config = config();
        assert_eq!(config.device.underlay_mtu, None);
        let messages = build_set_messages(&config, 3).expect("valid");
        assert!(!messages[0]
            .attributes
            .iter()
            .any(|attribute| matches!(attribute, UmbrawgAttribute::UnderlayMtu(_))));

        config.device.underlay_mtu = Some(9000);
        let messages = build_set_messages(&config, 3).expect("valid");
        assert!(messages[0]
            .attributes
            .contains(&UmbrawgAttribute::UnderlayMtu(9000)));

        let builder = DeviceBuilder::new("test0");
        assert_eq!(builder.finish().underlay_mtu, None);
        let mut builder = DeviceBuilder::new("test0");
        builder
            .apply(&[UmbrawgAttribute::UnderlayMtu(1280)])
            .expect("apply");
        assert_eq!(builder.finish().underlay_mtu, Some(1280));
    }

    #[test]
    fn encodes_fec_modes() {
        assert_eq!(fec_value("off").expect("valid"), 0);
        assert_eq!(fec_value("adaptive").expect("valid"), 1);
        assert_eq!(fec_value("8:2").expect("valid"), 0x0802);
        assert_eq!(fec_value("1:1").expect("valid"), 0x0101);
        assert_eq!(fec_value("2:1").expect("valid"), 0x0201);
        assert_eq!(fec_value(" ADAPTIVE ").expect("valid"), 1);
        for value in [
            "", "0:0", "0:3", "3:0", "9:1", "1:3", "10:3", "255:1", "200:100", "10", "10:3:4",
            "-1:2", "a:b", "1:",
        ] {
            assert!(fec_value(value).is_err(), "{value}");
        }
        assert_eq!(fec_text(0).expect("valid"), "off");
        assert_eq!(fec_text(1).expect("valid"), "adaptive");
        assert_eq!(fec_text(0x0802).expect("valid"), "8:2");
        assert!(fec_text(0xfe01).is_err());
        assert!(fec_text(0x0901).is_err());
        assert!(fec_text(0x0103).is_err());
        assert!(fec_text(2).is_err());
        assert!(fec_text(0x0100).is_err());
    }

    #[test]
    fn rejects_invalid_fec_from_config() {
        let mut set = config();
        set.device.fec = Some("0:0".to_owned());
        assert!(build_set_messages(&set, 3).is_err());

        let mut set = config();
        set.device.fec = Some("200:100".to_owned());
        assert!(build_set_messages(&set, 3).is_err());
    }

    #[test]
    fn reads_fec_from_netlink() {
        let mut builder = DeviceBuilder::new("test0");
        builder
            .apply(&[UmbrawgAttribute::Fec(0x0802)])
            .expect("apply");
        let device = builder.finish();
        assert_eq!(device.fec.as_deref(), Some("8:2"));

        for (value, expected) in [(0u32, "off"), (1, "adaptive"), (0x0101, "1:1")] {
            let mut builder = DeviceBuilder::new("test0");
            builder
                .apply(&[UmbrawgAttribute::Fec(value)])
                .expect("apply");
            assert_eq!(builder.finish().fec.as_deref(), Some(expected));
        }

        let mut builder = DeviceBuilder::new("test0");
        assert!(builder.apply(&[UmbrawgAttribute::Fec(2)]).is_err());
    }

    #[test]
    fn reads_fec_stats() {
        let kernel_fec = netlink_packet_umbrawg::FecStats {
            blocks_encoded: 1,
            shards_sent: 2,
            blocks_decoded: 3,
            packets_recovered: 4,
            decode_fail: 5,
            dropped_bounds: 6,
            dropped_disabled: 7,
        };
        let mut builder = DeviceBuilder::new("test0");
        builder
            .apply(&[UmbrawgAttribute::FecStats(kernel_fec)])
            .expect("apply");
        let device = builder.finish();
        let expected = crate::FecStats::from(kernel_fec);
        assert_eq!(device.fec_stats, Some(expected));
        assert_eq!(
            device.fec_stats.expect("stats").dropped_control,
            0,
            "the kernel has no dropped_control counter"
        );
    }

    #[test]
    fn missing_stats_stay_none() {
        let mut builder = DeviceBuilder::new("test0");
        builder
            .apply(&[UmbrawgAttribute::IfName("test0".to_owned())])
            .expect("apply");
        let device = builder.finish();
        assert_eq!(device.fec_stats, None);
    }
}
