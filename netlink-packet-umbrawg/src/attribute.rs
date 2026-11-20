// SPDX-License-Identifier: MIT

use std::convert::TryInto;

use netlink_packet_core::{
    emit_u16, emit_u32, emit_u64, parse_string, parse_u16, parse_u32,
    parse_u64, parse_u8, DecodeError, DefaultNla, Emitable, ErrorContext, Nla,
    NlaBuffer, Parseable, NLA_F_NESTED,
};

use super::peer::UmbrawgPeers;
use crate::{
    constants::{UWGDEVICE_A_BBR_STATS, UWGDEVICE_A_FEC_STATS, UWG_KEY_LEN},
    device::EXTRA_PORTS_MAX,
    range::u32_range_unpack,
    BbrStats, FecStats, UmbrawgPeer,
};

const UWGDEVICE_A_IFINDEX: u16 = 1;
const UWGDEVICE_A_IFNAME: u16 = 2;
const UWGDEVICE_A_PRIVATE_KEY: u16 = 3;
const UWGDEVICE_A_PUBLIC_KEY: u16 = 4;
const UWGDEVICE_A_FLAGS: u16 = 5;
const UWGDEVICE_A_LISTEN_PORT: u16 = 6;
const UWGDEVICE_A_FWMARK: u16 = 7;
const UWGDEVICE_A_PEERS: u16 = 8;

/// Umbra Flags
const UWGDEVICE_A_JC: u16 = 9;
const UWGDEVICE_A_JMIN: u16 = 10;
const UWGDEVICE_A_JMAX: u16 = 11;
const UWGDEVICE_A_S1: u16 = 12;
const UWGDEVICE_A_S2: u16 = 13;
const UWGDEVICE_A_H1: u16 = 14;
const UWGDEVICE_A_H2: u16 = 15;
const UWGDEVICE_A_H3: u16 = 16;
const UWGDEVICE_A_H4: u16 = 17;
const UWGDEVICE_A_PEER: u16 = 18;
const UWGDEVICE_A_S3: u16 = 19;
const UWGDEVICE_A_S4: u16 = 20;
const UWGDEVICE_A_I1: u16 = 21;
const UWGDEVICE_A_I2: u16 = 22;
const UWGDEVICE_A_I3: u16 = 23;
const UWGDEVICE_A_I4: u16 = 24;
const UWGDEVICE_A_I5: u16 = 25;
// UmbraWG 3.0 attributes
const UWGDEVICE_A_HEADER_PROTECTION_KEY: u16 = 26;
const UWGDEVICE_A_CONTENT_PADDING_ADDITION: u16 = 27;
const UWGDEVICE_A_REKEY_AFTER_TIME: u16 = 28;
const UWGDEVICE_A_REKEY_TIMEOUT: u16 = 29;
const UWGDEVICE_A_REJECT_AFTER_TIME: u16 = 30;
const UWGDEVICE_A_KEEPALIVE_TIMEOUT: u16 = 31;
const UWGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS: u16 = 32;
// UmbraWG 3.1 attributes
const UWGDEVICE_A_RANDOM_TRAILERS: u16 = 33;
const UWGDEVICE_A_DISABLE_COOKIES: u16 = 34;
// UmbraWG multi-port attributes
const UWGDEVICE_A_EXTRA_PORTS: u16 = 35;
// UmbraWG BBR/FEC attributes
const UWGDEVICE_A_BBR: u16 = 36;
const UWGDEVICE_A_FEC: u16 = 37;
const UWGDEVICE_A_UNDERLAY_MTU: u16 = 40;

const HEADER_PROTECTION_KEY_LEN: usize = 32;

/// Highest valid `UWGDEVICE_A_BBR` value (`on`).
pub const BBR_MAX: u8 = 2;

/// `UWGDEVICE_A_FEC` value that disables FEC.
pub const FEC_OFF: u32 = 0;

/// `UWGDEVICE_A_FEC` value that selects adaptive FEC.
pub const FEC_ADAPTIVE: u32 = 1;

/// Largest accepted total number of FEC shards (`K + M`).
pub const FEC_MAX_SHARDS: u16 = 255;

/// Packs explicit FEC shard counts into the `UWGDEVICE_A_FEC` payload
/// (`k << 8 | m`).
///
/// Returns `None` unless `k >= 1`, `m >= 1` and `k + m <= 255`.
pub const fn fec_pack(k: u8, m: u8) -> Option<u32> {
    if k == 0 || m == 0 || k as u16 + m as u16 > FEC_MAX_SHARDS {
        return None;
    }
    Some(((k as u32) << 8) | m as u32)
}

/// Unpacks explicit FEC shard counts from a `UWGDEVICE_A_FEC` payload.
///
/// Returns `None` for the `off`/`adaptive` modes and for payloads that do not
/// satisfy the `k >= 1`, `m >= 1`, `k + m <= 255` contract.
pub const fn fec_unpack(value: u32) -> Option<(u8, u8)> {
    if value == FEC_OFF || value == FEC_ADAPTIVE {
        return None;
    }
    let k = (value >> 8) as u8;
    let m = value as u8;
    if value >> 16 != 0
        || k == 0
        || m == 0
        || k as u16 + m as u16 > FEC_MAX_SHARDS
    {
        return None;
    }
    Some((k, m))
}

/// Returns `true` when `value` is a valid `UWGDEVICE_A_FEC` payload.
pub const fn fec_value_is_valid(value: u32) -> bool {
    value == FEC_OFF || value == FEC_ADAPTIVE || fec_unpack(value).is_some()
}

/// Wire representation of a magic header attribute.
enum MagicHeaderValue {
    Spec(String),
    Range(u64),
    Legacy(u32),
}

/// Parses a magic header attribute (`UWGDEVICE_A_H1`..`UWGDEVICE_A_H4`).
///
/// The wire format depends on the kernel module version:
/// - UmbraWG 3.0 (genl version 3): `u64` packing a `u32` range (`lo | hi <<
///   32`), returned as [`MagicHeaderValue::Range`];
/// - UmbraWG v1.0.20260725 (genl version 2): NUL-terminated decimal string,
///   `"<v>"` or `"<lo>-<hi>"`, returned as [`MagicHeaderValue::Spec`];
/// - original UmbraWG (genl version 1): bare `u32`, returned as
///   [`MagicHeaderValue::Legacy`].
///
/// The representation is kept so that a parsed message can be re-emitted
/// byte for byte, whatever module generation produced it.
fn parse_magic_header(
    kind: u16,
    payload: &[u8],
) -> Result<UmbrawgAttribute, DecodeError> {
    // A v1.0 string of exactly 7 digits plus NUL is also 8 bytes long, so
    // the string check must come first. Magic header specs only contain
    // decimal digits and at most one '-', which a valid binary range never
    // satisfies.
    let is_string = payload.last() == Some(&0)
        && payload[..payload.len() - 1]
            .iter()
            .all(|b| b.is_ascii_digit() || *b == b'-');
    let value = if is_string {
        MagicHeaderValue::Spec(
            parse_string(payload).context("invalid magic header string")?,
        )
    } else {
        match payload.len() {
            8 => {
                let range = parse_u64(payload)
                    .context("invalid u64 magic header value")?;
                let (lo, hi) = u32_range_unpack(range);
                if lo > hi {
                    return Err(DecodeError::from(format!(
                        "invalid magic header range {lo}-{hi}: start exceeds \
                         end"
                    )));
                }
                MagicHeaderValue::Range(range)
            }
            4 => MagicHeaderValue::Legacy(
                parse_u32(payload).context("invalid u32 magic header value")?,
            ),
            _ => {
                return Err(DecodeError::from(format!(
                    "invalid magic header payload length {}",
                    payload.len()
                )))
            }
        }
    };
    Ok(match (kind, value) {
        (UWGDEVICE_A_H1, MagicHeaderValue::Spec(v)) => UmbrawgAttribute::H1(v),
        (UWGDEVICE_A_H2, MagicHeaderValue::Spec(v)) => UmbrawgAttribute::H2(v),
        (UWGDEVICE_A_H3, MagicHeaderValue::Spec(v)) => UmbrawgAttribute::H3(v),
        (UWGDEVICE_A_H4, MagicHeaderValue::Spec(v)) => UmbrawgAttribute::H4(v),
        (UWGDEVICE_A_H1, MagicHeaderValue::Range(v)) => {
            UmbrawgAttribute::H1Range(v)
        }
        (UWGDEVICE_A_H2, MagicHeaderValue::Range(v)) => {
            UmbrawgAttribute::H2Range(v)
        }
        (UWGDEVICE_A_H3, MagicHeaderValue::Range(v)) => {
            UmbrawgAttribute::H3Range(v)
        }
        (UWGDEVICE_A_H4, MagicHeaderValue::Range(v)) => {
            UmbrawgAttribute::H4Range(v)
        }
        (UWGDEVICE_A_H1, MagicHeaderValue::Legacy(v)) => {
            UmbrawgAttribute::H1Legacy(v)
        }
        (UWGDEVICE_A_H2, MagicHeaderValue::Legacy(v)) => {
            UmbrawgAttribute::H2Legacy(v)
        }
        (UWGDEVICE_A_H3, MagicHeaderValue::Legacy(v)) => {
            UmbrawgAttribute::H3Legacy(v)
        }
        (UWGDEVICE_A_H4, MagicHeaderValue::Legacy(v)) => {
            UmbrawgAttribute::H4Legacy(v)
        }
        (kind, _) => {
            return Err(DecodeError::from(format!(
                "invalid magic header attribute kind {kind}"
            )))
        }
    })
}

/// One `UWGDEVICE_A_*` attribute of an
/// [`UmbrawgMessage`](crate::UmbrawgMessage).
///
/// The variants cover the attributes of every supported UmbraWG kernel
/// module generation. Attributes this crate does not know are preserved in
/// [`Other`](Self::Other) so that they can be re-emitted unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum UmbrawgAttribute {
    /// `UWGDEVICE_A_IFINDEX`: interface index (`u32`).
    IfIndex(u32),
    /// `UWGDEVICE_A_IFNAME`: interface name, a NUL-terminated string.
    IfName(String),
    /// `UWGDEVICE_A_PRIVATE_KEY`: static private key, 32 bytes.
    ///
    /// `UWG_CMD_GET_DEVICE` replies usually zero the key. On input an
    /// all-zero key removes the static key.
    PrivateKey([u8; UWG_KEY_LEN]),
    /// `UWGDEVICE_A_PUBLIC_KEY`: derived static public key, 32 bytes.
    ///
    /// Read-only: the kernel fills it in `UWG_CMD_GET_DEVICE` replies and
    /// ignores it in `UWG_CMD_SET_DEVICE` requests.
    PublicKey([u8; UWG_KEY_LEN]),
    /// `UWGDEVICE_A_LISTEN_PORT`: UDP listen port; `0` picks one randomly.
    ListenPort(u16),
    /// `UWGDEVICE_A_FWMARK`: firewall mark; `0` disables it.
    Fwmark(u32),
    /// `UWGDEVICE_A_PEERS`: nested list of peers.
    Peers(Vec<UmbrawgPeer>),
    /// `UWGDEVICE_A_FLAGS`: `u32` bit mask of `UWGDEVICE_F_*` flags.
    Flags(u32),
    /// `UWGDEVICE_A_PEER` (`NLA_NESTED`): a single peer.
    ///
    /// Used by `UWG_CMD_UNKNOWN_PEER` notifications. The peer attributes are
    /// nested directly, without the extra nesting level used by the
    /// [`Peers`](Self::Peers) list.
    Peer(UmbrawgPeer),
    /// `UWGDEVICE_A_JC`: number of junk packets (`u16`).
    JC(u16),
    /// `UWGDEVICE_A_JMIN`: minimal junk packet size (`u16`).
    Jmin(u16),
    /// `UWGDEVICE_A_JMAX`: maximal junk packet size (`u16`).
    Jmax(u16),
    /// `UWGDEVICE_A_S1`: padding added to handshake initiation messages
    /// (`u16`).
    S1(u16),
    /// `UWGDEVICE_A_S2`: padding added to handshake response messages
    /// (`u16`).
    S2(u16),
    /// Magic header spec, e.g. `"61220074"` or `"684141592-1751861769"`.
    ///
    /// Emitted as a NUL-terminated string, understood by kernel modules up
    /// to genl family version 2 (v1.0.20260725). Produced by parsing string
    /// payloads.
    H1(String),
    /// `UWGDEVICE_A_H2` magic header spec; see [`H1`](Self::H1).
    H2(String),
    /// `UWGDEVICE_A_H3` magic header spec; see [`H1`](Self::H1).
    H3(String),
    /// `UWGDEVICE_A_H4` magic header spec; see [`H1`](Self::H1).
    H4(String),
    /// Magic header as a packed `u64` range (`lo | hi << 32`), the wire
    /// format of the UmbraWG 3.0 kernel module (genl family version 3).
    /// Use [`crate::range::u32_range_from_string`] to build these from spec
    /// strings. Produced by parsing 8-byte payloads with `lo <= hi`.
    H1Range(u64),
    /// `UWGDEVICE_A_H2` as a packed `u64` range; see
    /// [`H1Range`](Self::H1Range).
    H2Range(u64),
    /// `UWGDEVICE_A_H3` as a packed `u64` range; see
    /// [`H1Range`](Self::H1Range).
    H3Range(u64),
    /// `UWGDEVICE_A_H4` as a packed `u64` range; see
    /// [`H1Range`](Self::H1Range).
    H4Range(u64),
    /// Magic header as a bare `u32`, the wire format of the original
    /// UmbraWG module (genl family version 1). Produced by parsing 4-byte
    /// payloads and emitted unchanged, so replies from older modules keep
    /// their format.
    H1Legacy(u32),
    /// `UWGDEVICE_A_H2` as a bare `u32`; see
    /// [`H1Legacy`](Self::H1Legacy).
    H2Legacy(u32),
    /// `UWGDEVICE_A_H3` as a bare `u32`; see
    /// [`H1Legacy`](Self::H1Legacy).
    H3Legacy(u32),
    /// `UWGDEVICE_A_H4` as a bare `u32`; see
    /// [`H1Legacy`](Self::H1Legacy).
    H4Legacy(u32),
    /// `UWGDEVICE_A_S3`: padding added to cookie reply messages (`u16`).
    S3(u16),
    /// `UWGDEVICE_A_S4`: padding added to transport data messages (`u16`).
    S4(u16),
    /// `UWGDEVICE_A_I1`: intermediate header descriptor, a NUL-terminated
    /// string.
    I1(String),
    /// `UWGDEVICE_A_I2` intermediate header descriptor.
    I2(String),
    /// `UWGDEVICE_A_I3` intermediate header descriptor.
    I3(String),
    /// `UWGDEVICE_A_I4` intermediate header descriptor.
    I4(String),
    /// `UWGDEVICE_A_I5` intermediate header descriptor.
    I5(String),
    /// `UWGDEVICE_A_HEADER_PROTECTION_KEY`: header protection key, 32 bytes
    /// (UmbraWG 3.0).
    HeaderProtectionKey([u8; HEADER_PROTECTION_KEY_LEN]),
    /// `UWGDEVICE_A_CONTENT_PADDING_ADDITION`: `u32` packing a `u16` range
    /// `lo | hi << 16` (UmbraWG 3.0). `0` disables the addition.
    ContentPaddingAddition(u32),
    /// `UWGDEVICE_A_REKEY_AFTER_TIME`: `u32` packing a `u16` range in
    /// seconds (UmbraWG 3.0). `0` disables it.
    RekeyAfterTime(u32),
    /// `UWGDEVICE_A_REKEY_TIMEOUT`: `u32` packing a `u16` range in seconds
    /// (UmbraWG 3.0). `0` disables it.
    RekeyTimeout(u32),
    /// `UWGDEVICE_A_REJECT_AFTER_TIME`: `u32` packing a `u16` range in
    /// seconds (UmbraWG 3.0). `0` disables it.
    RejectAfterTime(u32),
    /// `UWGDEVICE_A_KEEPALIVE_TIMEOUT`: `u32` packing a `u16` range in
    /// seconds (UmbraWG 3.0). `0` disables it.
    KeepaliveTimeout(u32),
    /// `UWGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS`: `u32` packing a `u16` range
    /// (UmbraWG 3.0).
    MaxHandshakeAttempts(u32),
    /// `UWGDEVICE_A_RANDOM_TRAILERS`: `u8` boolean (UmbraWG 3.1).
    RandomTrailers(bool),
    /// `UWGDEVICE_A_DISABLE_COOKIES`: `u8` boolean (UmbraWG 3.1).
    DisableCookies(bool),
    /// `UWGDEVICE_A_EXTRA_PORTS`: number of additional external UDP ports
    /// (`u8`, `0..=8`), `4` by default. The kernel opens one extra socket
    /// per port and sends over them round-robin.
    ExtraPorts(u8),
    /// `UWGDEVICE_A_BBR`: BBR congestion control mode (`u8`).
    ///
    /// `0` disables BBR, `1` only monitors it and `2` enables it. Values above
    /// [`BBR_MAX`] are rejected when parsing.
    Bbr(u8),
    /// `UWGDEVICE_A_FEC`: forward error correction mode (`u32`).
    ///
    /// `0` disables FEC, `1` selects adaptive FEC, and any other valid value
    /// packs explicit shard counts as `(K << 8) | M` with `K >= 1`, `M >= 1`
    /// and `K + M <= 255`. Use [`fec_pack`] and [`fec_unpack`] to convert
    /// between shard counts and the wire value.
    Fec(u32),
    /// `UWGDEVICE_A_UNDERLAY_MTU`: `u16` MTU of the path between the peers
    /// (`576..=65535`, `1500` by default).
    ///
    /// With FEC enabled the kernel derives the interface MTU from it so that
    /// a full-size packet still fits one shard datagram; parsing only checks
    /// the width, the range is enforced by
    /// [`UmbrawgDeviceConfig`](crate::UmbrawgDeviceConfig) and by the
    /// kernel.
    UnderlayMtu(u16),
    /// `UWGDEVICE_A_FEC_STATS`: nested device-wide FEC counters.
    ///
    /// Read-only: the kernel fills it in `UWG_CMD_GET_DEVICE` replies and
    /// ignores it in `UWG_CMD_SET_DEVICE` requests.
    FecStats(FecStats),
    /// `UWGDEVICE_A_BBR_STATS`: nested device-wide BBR state.
    ///
    /// Read-only: the kernel fills it in `UWG_CMD_GET_DEVICE` replies and
    /// ignores it in `UWG_CMD_SET_DEVICE` requests.
    BbrStats(BbrStats),
    /// An attribute this crate does not know; kept verbatim.
    Other(DefaultNla),
}

impl UmbrawgAttribute {
    /// Length of a Curve25519 key in bytes.
    pub const UWG_KEY_LEN: usize = UWG_KEY_LEN;
}

impl Nla for UmbrawgAttribute {
    fn value_len(&self) -> usize {
        match self {
            Self::IfName(v)
            | Self::H1(v)
            | Self::H2(v)
            | Self::H3(v)
            | Self::H4(v)
            | Self::I1(v)
            | Self::I2(v)
            | Self::I3(v)
            | Self::I4(v)
            | Self::I5(v) => v.len() + 1,
            Self::PrivateKey(_) | Self::PublicKey(_) => UWG_KEY_LEN,
            Self::HeaderProtectionKey(_) => HEADER_PROTECTION_KEY_LEN,
            Self::ListenPort(_) => 2,
            Self::Peers(v) => v.as_slice().buffer_len(),
            Self::Fwmark(_)
            | Self::IfIndex(_)
            | Self::Flags(_)
            | Self::H1Legacy(_)
            | Self::H2Legacy(_)
            | Self::H3Legacy(_)
            | Self::H4Legacy(_)
            | Self::ContentPaddingAddition(_)
            | Self::RekeyAfterTime(_)
            | Self::RekeyTimeout(_)
            | Self::RejectAfterTime(_)
            | Self::KeepaliveTimeout(_)
            | Self::MaxHandshakeAttempts(_) => 4,
            Self::H1Range(_)
            | Self::H2Range(_)
            | Self::H3Range(_)
            | Self::H4Range(_) => 8,
            Self::RandomTrailers(_)
            | Self::DisableCookies(_)
            | Self::ExtraPorts(_)
            | Self::Bbr(_) => 1,
            Self::Fec(_) => 4,
            Self::UnderlayMtu(_) => 2,
            Self::FecStats(v) => v.value_len(),
            Self::BbrStats(v) => v.value_len(),
            // Umbra Specific Fields
            Self::Peer(v) => v.attributes_len(),
            Self::JC(_)
            | Self::Jmax(_)
            | Self::Jmin(_)
            | Self::S1(_)
            | Self::S2(_)
            | Self::S3(_)
            | Self::S4(_) => 2,
            Self::Other(v) => v.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::IfIndex(_) => UWGDEVICE_A_IFINDEX,
            Self::IfName(_) => UWGDEVICE_A_IFNAME,
            Self::PrivateKey(_) => UWGDEVICE_A_PRIVATE_KEY,
            Self::PublicKey(_) => UWGDEVICE_A_PUBLIC_KEY,
            Self::ListenPort(_) => UWGDEVICE_A_LISTEN_PORT,
            Self::Fwmark(_) => UWGDEVICE_A_FWMARK,
            Self::Peers(_) => UWGDEVICE_A_PEERS | NLA_F_NESTED,
            Self::Flags(_) => UWGDEVICE_A_FLAGS,
            // Umbra Specific
            Self::Peer(_) => UWGDEVICE_A_PEER | NLA_F_NESTED,
            Self::JC(_) => UWGDEVICE_A_JC,
            Self::Jmin(_) => UWGDEVICE_A_JMIN,
            Self::Jmax(_) => UWGDEVICE_A_JMAX,
            Self::S1(_) => UWGDEVICE_A_S1,
            Self::S2(_) => UWGDEVICE_A_S2,
            Self::H1(_) | Self::H1Range(_) | Self::H1Legacy(_) => {
                UWGDEVICE_A_H1
            }
            Self::H2(_) | Self::H2Range(_) | Self::H2Legacy(_) => {
                UWGDEVICE_A_H2
            }
            Self::H3(_) | Self::H3Range(_) | Self::H3Legacy(_) => {
                UWGDEVICE_A_H3
            }
            Self::H4(_) | Self::H4Range(_) | Self::H4Legacy(_) => {
                UWGDEVICE_A_H4
            }
            Self::S3(_) => UWGDEVICE_A_S3,
            Self::S4(_) => UWGDEVICE_A_S4,
            Self::I1(_) => UWGDEVICE_A_I1,
            Self::I2(_) => UWGDEVICE_A_I2,
            Self::I3(_) => UWGDEVICE_A_I3,
            Self::I4(_) => UWGDEVICE_A_I4,
            Self::I5(_) => UWGDEVICE_A_I5,
            Self::HeaderProtectionKey(_) => UWGDEVICE_A_HEADER_PROTECTION_KEY,
            Self::ContentPaddingAddition(_) => {
                UWGDEVICE_A_CONTENT_PADDING_ADDITION
            }
            Self::RekeyAfterTime(_) => UWGDEVICE_A_REKEY_AFTER_TIME,
            Self::RekeyTimeout(_) => UWGDEVICE_A_REKEY_TIMEOUT,
            Self::RejectAfterTime(_) => UWGDEVICE_A_REJECT_AFTER_TIME,
            Self::KeepaliveTimeout(_) => UWGDEVICE_A_KEEPALIVE_TIMEOUT,
            Self::MaxHandshakeAttempts(_) => UWGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS,
            Self::RandomTrailers(_) => UWGDEVICE_A_RANDOM_TRAILERS,
            Self::DisableCookies(_) => UWGDEVICE_A_DISABLE_COOKIES,
            Self::ExtraPorts(_) => UWGDEVICE_A_EXTRA_PORTS,
            Self::Bbr(_) => UWGDEVICE_A_BBR,
            Self::Fec(_) => UWGDEVICE_A_FEC,
            Self::UnderlayMtu(_) => UWGDEVICE_A_UNDERLAY_MTU,
            Self::FecStats(_) => UWGDEVICE_A_FEC_STATS | NLA_F_NESTED,
            Self::BbrStats(_) => UWGDEVICE_A_BBR_STATS | NLA_F_NESTED,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::IfIndex(v) => emit_u32(buffer, *v).unwrap(),
            Self::IfName(s)
            | Self::H1(s)
            | Self::H2(s)
            | Self::H3(s)
            | Self::H4(s)
            | Self::I1(s)
            | Self::I2(s)
            | Self::I3(s)
            | Self::I4(s)
            | Self::I5(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            Self::PrivateKey(v) => buffer.copy_from_slice(v),
            Self::PublicKey(v) => buffer.copy_from_slice(v),
            Self::HeaderProtectionKey(v) => buffer.copy_from_slice(v),
            Self::ListenPort(v) => emit_u16(buffer, *v).unwrap(),
            Self::Fwmark(v) => emit_u32(buffer, *v).unwrap(),
            Self::Peers(v) => v.as_slice().emit(buffer),
            Self::Flags(v) => emit_u32(buffer, *v).unwrap(),
            // Umbra Specific
            Self::Peer(v) => v.emit_attributes(buffer),
            Self::H1Range(v)
            | Self::H2Range(v)
            | Self::H3Range(v)
            | Self::H4Range(v) => emit_u64(buffer, *v).unwrap(),
            Self::H1Legacy(v)
            | Self::H2Legacy(v)
            | Self::H3Legacy(v)
            | Self::H4Legacy(v) => emit_u32(buffer, *v).unwrap(),
            Self::ContentPaddingAddition(v)
            | Self::RekeyAfterTime(v)
            | Self::RekeyTimeout(v)
            | Self::RejectAfterTime(v)
            | Self::KeepaliveTimeout(v)
            | Self::MaxHandshakeAttempts(v) => emit_u32(buffer, *v).unwrap(),
            Self::JC(v)
            | Self::Jmin(v)
            | Self::Jmax(v)
            | Self::S1(v)
            | Self::S2(v)
            | Self::S3(v)
            | Self::S4(v) => emit_u16(buffer, *v).unwrap(),
            Self::RandomTrailers(v) | Self::DisableCookies(v) => {
                buffer[0] = u8::from(*v)
            }
            Self::ExtraPorts(v) => buffer[0] = *v,
            Self::Bbr(v) => buffer[0] = *v,
            Self::Fec(v) => emit_u32(buffer, *v).unwrap(),
            Self::UnderlayMtu(v) => emit_u16(buffer, *v).unwrap(),
            Self::FecStats(v) => v.emit_value(buffer),
            Self::BbrStats(v) => v.emit_value(buffer),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for UmbrawgAttribute
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            UWGDEVICE_A_IFINDEX => Self::IfIndex(
                parse_u32(payload)
                    .context("invalid UWGDEVICE_A_IFINDEX value")?,
            ),
            UWGDEVICE_A_IFNAME => Self::IfName(
                parse_string(payload)
                    .context("invalid UWGDEVICE_A_IFNAME value")?,
            ),
            UWGDEVICE_A_PRIVATE_KEY => Self::PrivateKey(
                payload
                    .try_into()
                    .map_err(|e: std::array::TryFromSliceError| {
                        DecodeError::from(e.to_string())
                    })
                    .context("invalid UWGDEVICE_A_PRIVATE_KEY value")?,
            ),
            UWGDEVICE_A_PUBLIC_KEY => Self::PublicKey(
                payload
                    .try_into()
                    .map_err(|e: std::array::TryFromSliceError| {
                        DecodeError::from(e.to_string())
                    })
                    .context("invalid UWGDEVICE_A_PUBLIC_KEY value")?,
            ),
            UWGDEVICE_A_LISTEN_PORT => Self::ListenPort(
                parse_u16(payload)
                    .context("invalid UWGDEVICE_A_LISTEN_PORT value")?,
            ),
            UWGDEVICE_A_FWMARK => Self::Fwmark(
                parse_u32(payload)
                    .context("invalid UWGDEVICE_A_FWMARK value")?,
            ),
            UWGDEVICE_A_PEERS => Self::Peers(UmbrawgPeers::parse(buf)?.0),
            UWGDEVICE_A_FLAGS => Self::Flags(
                parse_u32(payload)
                    .context("invalid UWGDEVICE_A_FLAGS value")?,
            ),
            UWGDEVICE_A_PEER => Self::Peer(UmbrawgPeer::parse(buf)?),
            UWGDEVICE_A_JC => Self::JC(
                parse_u16(payload).context("invalid UWGDEVICE_A_JC value")?,
            ),
            UWGDEVICE_A_JMIN => Self::Jmin(
                parse_u16(payload).context("invalid UWGDEVICE_A_JMIN value")?,
            ),
            UWGDEVICE_A_JMAX => Self::Jmax(
                parse_u16(payload).context("invalid UWGDEVICE_A_JMAX value")?,
            ),
            UWGDEVICE_A_S1 => Self::S1(
                parse_u16(payload).context("invalid UWGDEVICE_A_S1 value")?,
            ),
            UWGDEVICE_A_S2 => Self::S2(
                parse_u16(payload).context("invalid UWGDEVICE_A_S2 value")?,
            ),
            UWGDEVICE_A_H1 => parse_magic_header(UWGDEVICE_A_H1, payload)
                .context("invalid UWGDEVICE_A_H1 value")?,
            UWGDEVICE_A_H2 => parse_magic_header(UWGDEVICE_A_H2, payload)
                .context("invalid UWGDEVICE_A_H2 value")?,
            UWGDEVICE_A_H3 => parse_magic_header(UWGDEVICE_A_H3, payload)
                .context("invalid UWGDEVICE_A_H3 value")?,
            UWGDEVICE_A_H4 => parse_magic_header(UWGDEVICE_A_H4, payload)
                .context("invalid UWGDEVICE_A_H4 value")?,
            UWGDEVICE_A_S3 => Self::S3(
                parse_u16(payload).context("invalid UWGDEVICE_A_S3 value")?,
            ),
            UWGDEVICE_A_S4 => Self::S4(
                parse_u16(payload).context("invalid UWGDEVICE_A_S4 value")?,
            ),
            UWGDEVICE_A_I1 => Self::I1(
                parse_string(payload)
                    .context("invalid UWGDEVICE_A_I1 value")?,
            ),
            UWGDEVICE_A_I2 => Self::I2(
                parse_string(payload)
                    .context("invalid UWGDEVICE_A_I2 value")?,
            ),
            UWGDEVICE_A_I3 => Self::I3(
                parse_string(payload)
                    .context("invalid UWGDEVICE_A_I3 value")?,
            ),
            UWGDEVICE_A_I4 => Self::I4(
                parse_string(payload)
                    .context("invalid UWGDEVICE_A_I4 value")?,
            ),
            UWGDEVICE_A_I5 => Self::I5(
                parse_string(payload)
                    .context("invalid UWGDEVICE_A_I5 value")?,
            ),
            UWGDEVICE_A_HEADER_PROTECTION_KEY => Self::HeaderProtectionKey(
                payload
                    .try_into()
                    .map_err(|e: std::array::TryFromSliceError| {
                        DecodeError::from(e.to_string())
                    })
                    .context(
                        "invalid UWGDEVICE_A_HEADER_PROTECTION_KEY value",
                    )?,
            ),
            UWGDEVICE_A_CONTENT_PADDING_ADDITION => {
                Self::ContentPaddingAddition(parse_u32(payload).context(
                    "invalid UWGDEVICE_A_CONTENT_PADDING_ADDITION value",
                )?)
            }
            UWGDEVICE_A_REKEY_AFTER_TIME => Self::RekeyAfterTime(
                parse_u32(payload)
                    .context("invalid UWGDEVICE_A_REKEY_AFTER_TIME value")?,
            ),
            UWGDEVICE_A_REKEY_TIMEOUT => Self::RekeyTimeout(
                parse_u32(payload)
                    .context("invalid UWGDEVICE_A_REKEY_TIMEOUT value")?,
            ),
            UWGDEVICE_A_REJECT_AFTER_TIME => Self::RejectAfterTime(
                parse_u32(payload)
                    .context("invalid UWGDEVICE_A_REJECT_AFTER_TIME value")?,
            ),
            UWGDEVICE_A_KEEPALIVE_TIMEOUT => Self::KeepaliveTimeout(
                parse_u32(payload)
                    .context("invalid UWGDEVICE_A_KEEPALIVE_TIMEOUT value")?,
            ),
            UWGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS => {
                Self::MaxHandshakeAttempts(parse_u32(payload).context(
                    "invalid UWGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS value",
                )?)
            }
            UWGDEVICE_A_RANDOM_TRAILERS => Self::RandomTrailers(
                parse_u8(payload)
                    .context("invalid UWGDEVICE_A_RANDOM_TRAILERS value")?
                    != 0,
            ),
            UWGDEVICE_A_DISABLE_COOKIES => Self::DisableCookies(
                parse_u8(payload)
                    .context("invalid UWGDEVICE_A_DISABLE_COOKIES value")?
                    != 0,
            ),
            UWGDEVICE_A_EXTRA_PORTS => {
                let ports = parse_u8(payload)
                    .context("invalid UWGDEVICE_A_EXTRA_PORTS value")?;
                if ports > EXTRA_PORTS_MAX {
                    return Err(DecodeError::from(format!(
                        "UWGDEVICE_A_EXTRA_PORTS value {ports} exceeds \
                         {EXTRA_PORTS_MAX}"
                    )));
                }
                Self::ExtraPorts(ports)
            }
            UWGDEVICE_A_BBR => {
                let mode = parse_u8(payload)
                    .context("invalid UWGDEVICE_A_BBR value")?;
                if mode > BBR_MAX {
                    return Err(DecodeError::from(format!(
                        "UWGDEVICE_A_BBR value {mode} exceeds {BBR_MAX}"
                    )));
                }
                Self::Bbr(mode)
            }
            UWGDEVICE_A_FEC => {
                let value = parse_u32(payload)
                    .context("invalid UWGDEVICE_A_FEC value")?;
                if !fec_value_is_valid(value) {
                    return Err(DecodeError::from(format!(
                        "invalid UWGDEVICE_A_FEC value {value}"
                    )));
                }
                Self::Fec(value)
            }
            UWGDEVICE_A_UNDERLAY_MTU => Self::UnderlayMtu(
                parse_u16(payload)
                    .context("invalid UWGDEVICE_A_UNDERLAY_MTU value")?,
            ),
            UWGDEVICE_A_FEC_STATS => Self::FecStats(
                FecStats::parse(buf)
                    .context("invalid UWGDEVICE_A_FEC_STATS value")?,
            ),
            UWGDEVICE_A_BBR_STATS => Self::BbrStats(
                BbrStats::parse(buf)
                    .context("invalid UWGDEVICE_A_BBR_STATS value")?,
            ),
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown NLA type {kind}"))?,
            ),
        })
    }
}
