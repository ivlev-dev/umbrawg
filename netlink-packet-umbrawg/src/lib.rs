// SPDX-License-Identifier: MIT

//! The `netlink-packet-umbrawg` crate is designed for parsing and
//! emitting generic netlink packets for Umbra WireGuard interface.
//!
//! UmbraWG is a fork of WireGuard that adds junk packets, magic headers and
//! extra padding to mask the protocol from deep packet inspection. The
//! crate mirrors `uapi/umbrawg.h` of the kernel module: protocol constants
//! live in [`constants`], the packed range helpers in [`range`], and the
//! attribute types are re-exported at the crate root.
//!
//! # Overview
//!
//! - [`UmbrawgMessage`] is a generic netlink message: a [`UmbrawgCmd`] plus a
//!   list of [`UmbrawgAttribute`]. It implements the `netlink_packet_generic`
//!   traits and can be used as a `GenlMessage` payload.
//! - [`UmbrawgAttribute`] covers all `UWGDEVICE_A_*` attributes, including the
//!   UmbraWG 3.0 header protection key, the UmbraWG 3.1
//!   `RandomTrailers`/`DisableCookies` switches and the FEC mode.
//! - [`FecStats`] carries the read-only device-wide FEC counters of
//!   `UWGDEVICE_A_FEC_STATS`.
//! - [`UmbrawgPeer`] and [`UmbrawgPeerAttribute`] describe the nested peer
//!   list, [`UmbrawgAllowedIp`] the nested allowed IP entries.
//! - [`UmbrawgDeviceConfig`] and [`UmbrawgPeerConfig`] are validated builders
//!   that assemble `UWG_CMD_SET_DEVICE` messages and never panic on invalid
//!   input.
//!
//! # Wire formats
//!
//! The attribute layout follows the kernel module, not this crate's type
//! names:
//!
//! - `H1`..`H4` are `u64` values packing a `u32` range (`lo | hi << 32`) in the
//!   UmbraWG 3.x module, a NUL-terminated string in genl family version 2, and
//!   a bare `u32` in the original module. The parser keeps the wire
//!   representation: strings become
//!   [`UmbrawgAttribute::H1`]..[`UmbrawgAttribute::H4`], packed ranges become
//!   the `*Range` variants, and 4-byte values become the `*Legacy` variants, so
//!   a parsed message can be re-emitted byte for byte.
//! - `ContentPaddingAddition`, `RekeyAfterTime`, `RekeyTimeout`,
//!   `RejectAfterTime`, `KeepaliveTimeout`, `MaxHandshakeAttempts` and the
//!   persistent keepalive interval are `u32` values packing a `u16` range (`lo
//!   | hi << 16`). Use [`range::u16_range_pack`] and
//!   [`range::u16_range_unpack`].
//! - `HeaderProtectionKey` is exactly 32 bytes.
//! - With a header protection key configured, the kernel requires `S1`..`S4` to
//!   be at least [`HEADER_PROTECTION_NONCE_LEN`] bytes.
//! - `Fec` is a `u32` payload (`0` off, `1` adaptive, otherwise
//!   `(K << 8) | M`). The builders accept [`FecMode`] and convert it to this
//!   payload.
//!
//! # Building a configuration
//!
//! ```
//! use std::net::{IpAddr, Ipv4Addr};
//!
//! use netlink_packet_umbrawg::{
//!     UmbrawgCmd, UmbrawgDeviceConfig, UmbrawgPeerConfig,
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let peer = UmbrawgPeerConfig::new([7u8; 32])
//!     .endpoint_v4(Ipv4Addr::new(10, 0, 0, 1), 51820)
//!     .persistent_keepalive(25)
//!     .allowed_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)?;
//!
//! let msg = UmbrawgDeviceConfig::by_name("uwg0")
//!     .private_key([1u8; 32])
//!     .listen_port(51820)
//!     .junk(4, 40, 70)
//!     .padding(12, 12, 12, 12)
//!     .h1(61220074, 118999195)
//!     .h2(2351746464, 2351746464)
//!     .h3(3053333659, 3053333659)
//!     .h4(1789444460, 1789444460)
//!     .i1("<r 2>")
//!     .header_protection_key([5u8; 32])
//!     .content_padding_addition(51, 197)
//!     .random_trailers(true)
//!     .fec(netlink_packet_umbrawg::FecMode::Adaptive)
//!     .peer(peer)
//!     .build()?;
//!
//! assert_eq!(msg.cmd, UmbrawgCmd::SetDevice);
//! # Ok(())
//! # }
//! ```
//!
//! # Parsing a reply
//!
//! ```
//! use netlink_packet_core::{Emitable, ParseableParametrized};
//! use netlink_packet_generic::GenlHeader;
//! use netlink_packet_umbrawg::{
//!     UmbrawgAttribute, UmbrawgCmd, UmbrawgMessage,
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let msg = UmbrawgMessage {
//!     cmd: UmbrawgCmd::GetDevice,
//!     attributes: vec![UmbrawgAttribute::IfName("uwg0".into())],
//! };
//! let header = GenlHeader {
//!     cmd: msg.cmd.into(),
//!     version: 3,
//! };
//! let mut buffer = vec![0; msg.buffer_len()];
//! msg.emit(&mut buffer);
//!
//! let parsed = UmbrawgMessage::parse_with_param(&buffer, header)?;
//! assert_eq!(parsed, msg);
//! # Ok(())
//! # }
//! ```
//!
//! [`Parseable`]: netlink_packet_core::Parseable

#![deny(missing_docs)]

pub mod constants;
pub mod range;

mod allowedip;
mod attribute;
mod cipher;
mod device;
mod error;
mod fec;
mod message;
mod peer;
mod peer_config;
mod socket_addr;
mod stats;

#[cfg(test)]
mod test;

pub use self::{
    allowedip::{UmbrawgAddressFamily, UmbrawgAllowedIp, UmbrawgAllowedIpAttr},
    attribute::{
        fec_pack, fec_unpack, UmbrawgAttribute, FEC_ADAPTIVE, FEC_MAX_K,
        FEC_MAX_M, FEC_MAX_SHARDS, FEC_OFF,
    },
    cipher::UmbrawgCipher,
    device::{
        UmbrawgDeviceConfig, UmbrawgMagicHeader, EXTRA_PORTS_MAX,
        HEADER_PROTECTION_NONCE_LEN, INTERMEDIATE_SPEC_MAX_LEN,
        UNDERLAY_MTU_MIN,
    },
    error::{UmbrawgConfigError, UmbrawgConfigResult},
    fec::FecMode,
    message::{UmbrawgCmd, UmbrawgMessage},
    peer::{UmbrawgPeer, UmbrawgPeerAttribute, UmbrawgTimeSpec},
    peer_config::UmbrawgPeerConfig,
    stats::FecStats,
};
