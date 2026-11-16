use std::net::SocketAddr;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rand_core::RngCore;

use umbrawg_noise::CookieGenerator;
use umbrawg_proto::obf::{MessageKind, Obfuscator};
use umbrawg_proto::special::SpecialPacketContext;

use crate::error::{DeviceError, Result};
use crate::io::DatagramSink;
use crate::peer::Peer;

pub(crate) fn endpoint_bytes(endpoint: SocketAddr, out: &mut [u8; 18]) -> usize {
    match endpoint {
        SocketAddr::V4(address) => {
            out[..4].copy_from_slice(&address.ip().octets());
            out[4..6].copy_from_slice(&address.port().to_be_bytes());
            6
        }
        SocketAddr::V6(address) => {
            out[..16].copy_from_slice(&address.ip().octets());
            out[16..18].copy_from_slice(&address.port().to_be_bytes());
            18
        }
    }
}

pub(crate) fn unix_time_seconds() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
        .min(u64::from(u32::MAX)) as u32
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_fixed_message(
    obfuscator: &Obfuscator<'_>,
    kind: MessageKind,
    body: &[u8],
    macs: Option<&mut CookieGenerator>,
    now: Instant,
    rng: &mut impl RngCore,
    udp_window: usize,
    dst: &mut [u8],
) -> Result<usize> {
    if body.len() != kind.body_len() {
        return Err(DeviceError::InvalidParameter("fixed message size"));
    }
    let (_, layout) = obfuscator.begin_fixed(kind, rng, udp_window, dst)?;
    dst[layout.body.clone()].copy_from_slice(body);
    if let Some(generator) = macs {
        generator.add_macs(&mut dst[layout.body.clone()], now)?;
    }
    obfuscator.finish_fixed(kind, dst, &layout)?;
    Ok(layout.total)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn send_pre_handshake(
    obfuscator: &Obfuscator<'_>,
    rng: &mut impl RngCore,
    unix_time: u32,
    peer: &Peer,
    endpoint: SocketAddr,
    dst: &mut [u8],
    io: &mut impl DatagramSink,
) -> Result<()> {
    for packet in obfuscator.special_packets() {
        let context = SpecialPacketContext {
            unix_time,
            counter: peer.special_counter(),
        };
        let length = packet.encode(rng, &context, dst)?;
        if length > 0 {
            io.send_datagram(endpoint, Some(peer), &dst[..length], None);
            peer.add_tx(length as u64);
        }
    }
    let junk_count = obfuscator.junk_count();
    for _ in 0..junk_count {
        let length = obfuscator.write_junk(rng, dst)?;
        if length > 0 {
            io.send_datagram(endpoint, Some(peer), &dst[..length], None);
            peer.add_tx(length as u64);
        }
    }
    Ok(())
}
