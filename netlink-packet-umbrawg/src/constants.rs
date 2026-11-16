// SPDX-License-Identifier: MIT

//! Numeric constants of the UmbraWG generic netlink UAPI.
//!
//! The values mirror `uapi/umbrawg.h` of the UmbraWG kernel module and are
//! verified by `scripts/check-uapi-parity.sh`.

/// Length of a Curve25519 key in bytes.
pub const UWG_KEY_LEN: usize = 32;

/// Dumps the state of a UmbraWG device.
pub const UWG_CMD_GET_DEVICE: u8 = 0;

/// Modifies the state of a UmbraWG device.
pub const UWG_CMD_SET_DEVICE: u8 = 1;

/// Multicast notification about an initiation message from an unknown peer.
pub const UWG_CMD_UNKNOWN_PEER: u8 = 2;

pub const UWGDEVICE_F_REPLACE_PEERS: u32 = 1 << 0;

pub const UWGPEER_F_REMOVE_ME: u32 = 1 << 0;
pub const UWGPEER_F_REPLACE_ALLOWEDIPS: u32 = 1 << 1;
pub const UWGPEER_F_UPDATE_ONLY: u32 = 1 << 2;

/// The peer uses UmbraWG advanced security.
///
/// The kernel reports this flag in `UWGPEER_A_FLAGS` of
/// `UWG_CMD_GET_DEVICE` replies; on input [`UWGPEER_A_ADVANCED_SECURITY`]
/// is used instead.
pub const UWGPEER_F_HAS_ADVANCED_SECURITY: u32 = 1 << 3;

pub const UWGPEER_A_UNSPEC: u16 = 0;
pub const UWGPEER_A_PUBLIC_KEY: u16 = 1;
pub const UWGPEER_A_PRESHARED_KEY: u16 = 2;
pub const UWGPEER_A_FLAGS: u16 = 3;
pub const UWGPEER_A_ENDPOINT: u16 = 4;
pub const UWGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: u16 = 5;
pub const UWGPEER_A_LAST_HANDSHAKE_TIME: u16 = 6;
pub const UWGPEER_A_RX_BYTES: u16 = 7;
pub const UWGPEER_A_TX_BYTES: u16 = 8;
pub const UWGPEER_A_ALLOWEDIPS: u16 = 9;
pub const UWGPEER_A_PROTOCOL_VERSION: u16 = 10;

/// `NLA_FLAG` requesting UmbraWG advanced security for the peer.
///
/// The payload is empty: only the presence of the attribute matters. The
/// kernel mirrors the setting in `UWGPEER_A_FLAGS`.
pub const UWGPEER_A_ADVANCED_SECURITY: u16 = 11;

pub const UWGALLOWEDIP_A_UNSPEC: u16 = 0;
pub const UWGALLOWEDIP_A_FAMILY: u16 = 1;
pub const UWGALLOWEDIP_A_IPADDR: u16 = 2;
pub const UWGALLOWEDIP_A_CIDR_MASK: u16 = 3;

/// `u32` flags of an allowed IP: either `0` or [`UWGALLOWEDIP_F_REMOVE_ME`].
pub const UWGALLOWEDIP_A_FLAGS: u16 = 4;

/// Removes the allowed IP instead of adding it.
pub const UWGALLOWEDIP_F_REMOVE_ME: u32 = 1 << 0;
