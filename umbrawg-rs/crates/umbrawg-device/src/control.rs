use std::fmt::Write as _;

use umbrawg_proto::special::{SpecialPacket, Tag};
use umbrawg_proto::ObfParams;
use umbrawg_uapi::{
    AllowedIp as UapiAllowedIp, AllowedIpChange, DeviceControl, DeviceSnapshot, ObfuscationRequest,
    ObfuscationSnapshot, PeerRequest, PeerSnapshot, SetRequest, SpecialPacketUpdate, TimingRequest,
    TimingSnapshot, U16Range, U32Range, UapiError,
};

use crate::allowedips::AllowedIp;
use crate::device::Device;
use crate::error::DeviceError;
use crate::peer::PeerConfig;
use crate::timers::{Range16, Timings};

impl DeviceControl for Device {
    fn snapshot(&self) -> DeviceSnapshot {
        let params = self.obfuscation();
        DeviceSnapshot {
            private_key: self.private_key(),
            listen_port: self.listen_port(),
            fwmark: self.fwmark(),
            obfuscation: obfuscation_snapshot(&params),
            timings: timings_snapshot(&self.timings()),
            peers: self
                .peers()
                .iter()
                .map(|peer| peer_snapshot(self, peer))
                .collect(),
        }
    }

    fn apply(&self, request: SetRequest) -> Result<(), UapiError> {
        if let Some(key) = request.private_key {
            let key = if key.is_zero() { None } else { Some(key) };
            self.set_private_key(key).map_err(internal)?;
        }
        if let Some(port) = request.listen_port {
            self.set_listen_port(port);
        }
        if let Some(mark) = request.fwmark {
            self.set_fwmark(mark);
        }
        if request.replace_peers {
            self.remove_all_peers();
        }
        apply_obfuscation(self, request.obfuscation)?;
        apply_timings(self, request.timings)?;
        for peer in request.peers {
            apply_peer(self, peer)?;
        }
        Ok(())
    }
}

fn internal(error: DeviceError) -> UapiError {
    UapiError::Internal(error.to_string())
}

fn peer_snapshot(device: &Device, peer: &std::sync::Arc<crate::peer::Peer>) -> PeerSnapshot {
    let nanos = peer.last_handshake_unix_nanos();
    let allowed_ips = device
        .allowed_ips()
        .entries_for_peer(peer.id())
        .into_iter()
        .filter_map(|prefix| UapiAllowedIp::new(prefix.address(), prefix.cidr()).ok())
        .collect();
    let preshared_key = {
        let key = peer.preshared_key();
        if key.is_zero() {
            None
        } else {
            Some(key)
        }
    };
    let persistent_keepalive_interval = peer
        .persistent_keepalive_range()
        .map_or_else(U16Range::default, |(lo, hi)| U16Range::new(lo, hi));
    PeerSnapshot {
        public_key: peer.public_key(),
        preshared_key,
        endpoint: peer.endpoint(),
        last_handshake_time_sec: (nanos / 1_000_000_000) as i64,
        last_handshake_time_nsec: (nanos % 1_000_000_000) as i64,
        tx_bytes: peer.tx_bytes(),
        rx_bytes: peer.rx_bytes(),
        persistent_keepalive_interval,
        advanced_security: peer.advanced_security(),
        allowed_ips,
    }
}

fn obfuscation_snapshot(params: &ObfParams) -> ObfuscationSnapshot {
    ObfuscationSnapshot {
        jc: params.jc,
        jmin: params.jmin,
        jmax: params.jmax,
        s1: params.s1,
        s2: params.s2,
        s3: params.s3,
        s4: params.s4,
        h1: U32Range::new(*params.h1.start(), *params.h1.end()),
        h2: U32Range::new(*params.h2.start(), *params.h2.end()),
        h3: U32Range::new(*params.h3.start(), *params.h3.end()),
        h4: U32Range::new(*params.h4.start(), *params.h4.end()),
        i1: params.i1.as_ref().map(render_special),
        i2: params.i2.as_ref().map(render_special),
        i3: params.i3.as_ref().map(render_special),
        i4: params.i4.as_ref().map(render_special),
        i5: params.i5.as_ref().map(render_special),
        header_protection_key: params
            .header_protection_key
            .as_ref()
            .filter(|key| !key.is_zero())
            .cloned(),
        content_padding_addition: U16Range::new(
            *params.content_padding_addition.start(),
            *params.content_padding_addition.end(),
        ),
        random_trailers: params.random_trailers,
        disable_cookies: params.disable_cookies,
    }
}

fn timings_snapshot(timings: &Timings) -> TimingSnapshot {
    TimingSnapshot {
        rekey_after_time: u16_range(timings.rekey_after_time),
        rekey_timeout: u16_range(timings.rekey_timeout),
        reject_after_time: u16_range(timings.reject_after_time),
        keepalive_timeout: u16_range(timings.keepalive_timeout),
        max_handshake_attempts: u16_range(timings.max_handshake_attempts),
    }
}

fn u16_range(range: Range16) -> U16Range {
    U16Range::new(range.lo(), range.hi())
}

fn apply_obfuscation(device: &Device, request: ObfuscationRequest) -> Result<(), UapiError> {
    let mut params = (*device.obfuscation()).clone();
    if let Some(value) = request.jc {
        params.jc = value;
    }
    if let Some(value) = request.jmin {
        params.jmin = value;
    }
    if let Some(value) = request.jmax {
        params.jmax = value;
    }
    if let Some(value) = request.s1 {
        params.s1 = value;
    }
    if let Some(value) = request.s2 {
        params.s2 = value;
    }
    if let Some(value) = request.s3 {
        params.s3 = value;
    }
    if let Some(value) = request.s4 {
        params.s4 = value;
    }
    if let Some(range) = request.h1 {
        params.h1 = range.lo()..=range.hi();
    }
    if let Some(range) = request.h2 {
        params.h2 = range.lo()..=range.hi();
    }
    if let Some(range) = request.h3 {
        params.h3 = range.lo()..=range.hi();
    }
    if let Some(range) = request.h4 {
        params.h4 = range.lo()..=range.hi();
    }
    apply_special(&mut params.i1, request.i1, "i1")?;
    apply_special(&mut params.i2, request.i2, "i2")?;
    apply_special(&mut params.i3, request.i3, "i3")?;
    apply_special(&mut params.i4, request.i4, "i4")?;
    apply_special(&mut params.i5, request.i5, "i5")?;
    if let Some(key) = request.header_protection_key {
        params.header_protection_key = Some(key);
    }
    if let Some(range) = request.content_padding_addition {
        params.content_padding_addition = range.lo()..=range.hi();
    }
    if let Some(value) = request.random_trailers {
        params.random_trailers = value;
    }
    if let Some(value) = request.disable_cookies {
        params.disable_cookies = value;
    }
    device.set_obfuscation(params).map_err(internal)
}

fn parse_special(spec: &str, key: &str) -> Result<Option<SpecialPacket>, UapiError> {
    if spec.is_empty() {
        return Ok(None);
    }
    SpecialPacket::parse(spec)
        .map(Some)
        .map_err(|error| UapiError::InvalidValue {
            key: key.to_owned(),
            value: error.to_string(),
        })
}

fn apply_special(
    target: &mut Option<SpecialPacket>,
    update: SpecialPacketUpdate,
    key: &str,
) -> Result<(), UapiError> {
    match update {
        SpecialPacketUpdate::Keep => Ok(()),
        SpecialPacketUpdate::Clear => {
            *target = None;
            Ok(())
        }
        SpecialPacketUpdate::Set(spec) => {
            *target = parse_special(&spec, key)?;
            Ok(())
        }
    }
}

fn apply_timings(device: &Device, request: TimingRequest) -> Result<(), UapiError> {
    let mut timings = device.timings();
    if let Some(range) = request.rekey_after_time {
        timings.rekey_after_time = Range16::new(range.lo(), range.hi());
    }
    if let Some(range) = request.rekey_timeout {
        timings.rekey_timeout = Range16::new(range.lo(), range.hi());
    }
    if let Some(range) = request.reject_after_time {
        timings.reject_after_time = Range16::new(range.lo(), range.hi());
    }
    if let Some(range) = request.keepalive_timeout {
        timings.keepalive_timeout = Range16::new(range.lo(), range.hi());
    }
    if let Some(range) = request.max_handshake_attempts {
        timings.max_handshake_attempts = Range16::new(range.lo(), range.hi());
    }
    device.set_timings(timings).map_err(internal)
}

fn apply_peer(device: &Device, request: PeerRequest) -> Result<(), UapiError> {
    if let Some(version) = request.protocol_version {
        if version != 1 {
            return Err(UapiError::InvalidValue {
                key: "protocol_version".to_owned(),
                value: version.to_string(),
            });
        }
    }
    if request.remove {
        device.remove_peer(request.public_key);
        return Ok(());
    }
    let peer = match device.peer_by_key(request.public_key) {
        Some(peer) => peer,
        None => {
            if request.update_only {
                return Ok(());
            }
            let mut config = PeerConfig::new(request.public_key);
            config.endpoint = request.endpoint;
            if let Some(key) = request.preshared_key.clone() {
                config.preshared_key = key;
            }
            if let Some(range) = request.persistent_keepalive_interval {
                config.persistent_keepalive = Some(range.lo());
            }
            device.add_peer(config).map_err(internal)?
        }
    };
    if request.preshared_key.is_some() {
        if let Some(key) = request.preshared_key {
            device
                .set_peer_preshared_key(&peer, key)
                .map_err(internal)?;
        }
    }
    if let Some(endpoint) = request.endpoint {
        device.set_peer_endpoint(&peer, Some(endpoint));
    }
    if let Some(range) = request.persistent_keepalive_interval {
        peer.set_persistent_keepalive_range(Some((range.lo(), range.hi())));
    }
    if let Some(value) = request.advanced_security {
        peer.set_advanced_security(Some(value));
    }
    if request.replace_allowed_ips {
        device.allowed_ips().remove_by_peer(peer.id());
    }
    for change in request.allowed_ips {
        match change {
            AllowedIpChange::Add(prefix) => {
                if let Some(prefix) = AllowedIp::new(prefix.address(), prefix.cidr()) {
                    device.allowed_ips().insert(prefix, peer.id());
                }
            }
            AllowedIpChange::Remove(prefix) => {
                if let Some(prefix) = AllowedIp::new(prefix.address(), prefix.cidr()) {
                    device.allowed_ips().remove_from_peer(prefix, peer.id());
                }
            }
        }
    }
    Ok(())
}

fn render_special(packet: &SpecialPacket) -> String {
    let mut output = String::new();
    for tag in packet.tags() {
        match tag {
            Tag::Bytes(bytes) => {
                output.push_str("<b 0x");
                for byte in bytes {
                    let _ = write!(output, "{byte:02x}");
                }
                output.push('>');
            }
            Tag::Random(length) => {
                let _ = write!(output, "<r {length}>");
            }
            Tag::RandomChars(length) => {
                let _ = write!(output, "<rc {length}>");
            }
            Tag::RandomDigits(length) => {
                let _ = write!(output, "<rd {length}>");
            }
            Tag::Timestamp => output.push_str("<t>"),
            Tag::Counter => output.push_str("<c>"),
            Tag::Data => output.push_str("<d>"),
            Tag::DataString => output.push_str("<ds>"),
            Tag::DataSize(length) => {
                let _ = write!(output, "<dz {length}>");
            }
        }
    }
    output
}
