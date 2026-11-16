// SPDX-License-Identifier: MIT

use std::convert::TryInto;

use netlink_packet_core::{
    emit_u16, emit_u32, emit_u64, parse_string, parse_u16, parse_u32,
    parse_u64, parse_u8, DecodeError, DefaultNla, Emitable, ErrorContext, Nla,
    NlaBuffer, Parseable, NLA_F_NESTED,
};

use super::peer::UmbrawgPeers;
use crate::{range::u32_range_to_string, UmbrawgPeer};

const UWG_KEY_LEN: usize = 32;

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

const HEADER_PROTECTION_KEY_LEN: usize = 32;

/// Parses a magic header attribute (`UWGDEVICE_A_H1`..`UWGDEVICE_A_H4`).
///
/// The wire format depends on the kernel module version:
/// - UmbraWG 3.0 (genl version 3): `u64` packing a `u32` range (`lo | hi <<
///   32`);
/// - UmbraWG v1.0.20260725 (genl version 2): NUL-terminated decimal string,
///   `"<v>"` or `"<lo>-<hi>"`;
/// - original UmbraWG (genl version 1): bare `u32`.
///
/// All representations are normalized to the string form used by the v1.0
/// module and by `uwg`(8) config files.
fn parse_magic_header(payload: &[u8]) -> Result<String, DecodeError> {
    // A v1.0 string of exactly 7 digits plus NUL is also 8 bytes long, so
    // the string check must come first. Magic header specs only contain
    // decimal digits and at most one '-', which a binary range practically
    // never satisfies.
    let is_string = payload.last() == Some(&0)
        && payload[..payload.len() - 1]
            .iter()
            .all(|b| b.is_ascii_digit() || *b == b'-');
    if is_string {
        return parse_string(payload).context("invalid magic header string");
    }
    match payload.len() {
        8 => Ok(u32_range_to_string(
            parse_u64(payload).context("invalid u64 magic header value")?,
        )),
        4 => Ok(parse_u32(payload)
            .context("invalid u32 magic header value")?
            .to_string()),
        _ => Err(DecodeError::from(format!(
            "invalid magic header payload length {}",
            payload.len()
        ))),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum UmbrawgAttribute {
    IfIndex(u32),
    IfName(String),
    PrivateKey([u8; UWG_KEY_LEN]),
    PublicKey([u8; UWG_KEY_LEN]),
    ListenPort(u16),
    Fwmark(u32),
    Peers(Vec<UmbrawgPeer>),
    Flags(u32),
    // Umbra attributes
    Peer(UmbrawgPeer),
    JC(u16),   // JunkCount
    Jmin(u16), // JunkPacketMinSize
    Jmax(u16), // JunkPacketMaxSize
    S1(u16),
    S2(u16),
    /// Magic header spec, e.g. `"61220074"` or `"684141592-1751861769"`.
    ///
    /// Emitted as a NUL-terminated string, understood by kernel modules up
    /// to genl family version 2 (v1.0.20260725). When parsing, all wire
    /// formats (string, `u32`, packed `u64` range) are normalized into this
    /// variant.
    H1(String),
    H2(String),
    H3(String),
    H4(String),
    /// Magic header as a packed `u64` range (`lo | hi << 32`), the wire
    /// format of the UmbraWG 3.0 kernel module (genl family version 3).
    /// Use [`crate::range::u32_range_from_string`] to build these from spec
    /// strings. Never produced by parsing; see the `H1`..`H4` variants.
    H1Range(u64),
    H2Range(u64),
    H3Range(u64),
    H4Range(u64),
    S3(u16),
    S4(u16),
    /// Intermediate header descriptor string.
    I1(String),
    I2(String),
    I3(String),
    I4(String),
    I5(String),
    // UmbraWG 3.0 attributes
    HeaderProtectionKey([u8; HEADER_PROTECTION_KEY_LEN]),
    ContentPaddingAddition(u32),
    RekeyAfterTime(u32),
    RekeyTimeout(u32),
    RejectAfterTime(u32),
    KeepaliveTimeout(u32),
    MaxHandshakeAttempts(u32),
    // UmbraWG 3.1 attributes (genl family version is still 3; only the
    // 3.1+ kernel module accepts them).
    RandomTrailers(bool),
    DisableCookies(bool),
    Other(DefaultNla),
}

impl UmbrawgAttribute {
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
            Self::RandomTrailers(_) | Self::DisableCookies(_) => 1,
            // Umbra Specific Fields
            Self::Peer(v) => v.buffer_len(),
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
            Self::H1(_) | Self::H1Range(_) => UWGDEVICE_A_H1,
            Self::H2(_) | Self::H2Range(_) => UWGDEVICE_A_H2,
            Self::H3(_) | Self::H3Range(_) => UWGDEVICE_A_H3,
            Self::H4(_) | Self::H4Range(_) => UWGDEVICE_A_H4,
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
            Self::Peer(v) => v.emit(buffer),
            Self::H1Range(v)
            | Self::H2Range(v)
            | Self::H3Range(v)
            | Self::H4Range(v) => emit_u64(buffer, *v).unwrap(),
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
            UWGDEVICE_A_PEERS => {
                Self::Peers(UmbrawgPeers::parse(buf)?.0)
            }
            UWGDEVICE_A_FLAGS => Self::Flags(
                parse_u32(payload).context("invalid UWGDEVICE_A_FLAGS value")?,
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
            UWGDEVICE_A_H1 => Self::H1(
                parse_magic_header(payload)
                    .context("invalid UWGDEVICE_A_H1 value")?,
            ),
            UWGDEVICE_A_H2 => Self::H2(
                parse_magic_header(payload)
                    .context("invalid UWGDEVICE_A_H2 value")?,
            ),
            UWGDEVICE_A_H3 => Self::H3(
                parse_magic_header(payload)
                    .context("invalid UWGDEVICE_A_H3 value")?,
            ),
            UWGDEVICE_A_H4 => Self::H4(
                parse_magic_header(payload)
                    .context("invalid UWGDEVICE_A_H4 value")?,
            ),
            UWGDEVICE_A_S3 => Self::S3(
                parse_u16(payload).context("invalid UWGDEVICE_A_S3 value")?,
            ),
            UWGDEVICE_A_S4 => Self::S4(
                parse_u16(payload).context("invalid UWGDEVICE_A_S4 value")?,
            ),
            UWGDEVICE_A_I1 => Self::I1(
                parse_string(payload).context("invalid UWGDEVICE_A_I1 value")?,
            ),
            UWGDEVICE_A_I2 => Self::I2(
                parse_string(payload).context("invalid UWGDEVICE_A_I2 value")?,
            ),
            UWGDEVICE_A_I3 => Self::I3(
                parse_string(payload).context("invalid UWGDEVICE_A_I3 value")?,
            ),
            UWGDEVICE_A_I4 => Self::I4(
                parse_string(payload).context("invalid UWGDEVICE_A_I4 value")?,
            ),
            UWGDEVICE_A_I5 => Self::I5(
                parse_string(payload).context("invalid UWGDEVICE_A_I5 value")?,
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
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown NLA type {kind}"))?,
            ),
        })
    }
}
