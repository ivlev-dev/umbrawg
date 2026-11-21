// SPDX-License-Identifier: MIT

//! Numeric constants of the UmbraWG generic netlink UAPI.
//!
//! The values mirror `uapi/umbrawg.h` of the UmbraWG kernel module and are
//! verified by `scripts/check-uapi-parity.sh`.

/// Length of a Curve25519 key in bytes.
///
/// Applies to `UWGDEVICE_A_PRIVATE_KEY`, `UWGDEVICE_A_PUBLIC_KEY`,
/// `UWGPEER_A_PUBLIC_KEY` and `UWGPEER_A_PRESHARED_KEY`, all of which are
/// `NLA_EXACT_LEN` attributes.
pub const UWG_KEY_LEN: usize = 32;

/// Version of the `umbrawg` generic netlink family (`UWG_GENL_VERSION`).
///
/// Mirrors the UmbraWG 3.x UAPI header; the wire format of the attributes
/// emitted by this crate (packed `u64` magic headers, `u32` keepalive ranges)
/// is the version 3 format.
pub const UWG_GENL_VERSION: u8 = 3;

/// Dumps the state of a UmbraWG device.
pub const UWG_CMD_GET_DEVICE: u8 = 0;

/// Modifies the state of a UmbraWG device.
pub const UWG_CMD_SET_DEVICE: u8 = 1;

/// Multicast notification about an initiation message from an unknown peer.
pub const UWG_CMD_UNKNOWN_PEER: u8 = 2;

/// Removes all existing peers before the peers of the message are added.
///
/// Device flag of `UWGDEVICE_A_FLAGS`; it is the only flag the kernel
/// accepts there.
pub const UWGDEVICE_F_REPLACE_PEERS: u32 = 1 << 0;

/// Removes the peer instead of adding or updating it.
///
/// Peer flag of `UWGPEER_A_FLAGS`.
pub const UWGPEER_F_REMOVE_ME: u32 = 1 << 0;

/// Removes all current allowed IPs of the peer before the allowed IPs of the
/// message are added.
///
/// Peer flag of `UWGPEER_A_FLAGS`.
pub const UWGPEER_F_REPLACE_ALLOWEDIPS: u32 = 1 << 1;

/// Only updates the peer when it already exists.
///
/// Peer flag of `UWGPEER_A_FLAGS`.
pub const UWGPEER_F_UPDATE_ONLY: u32 = 1 << 2;

/// The peer uses UmbraWG advanced security.
///
/// The kernel reports this flag in `UWGPEER_A_FLAGS` of
/// `UWG_CMD_GET_DEVICE` replies; on input [`UWGPEER_A_ADVANCED_SECURITY`]
/// is used instead.
pub const UWGPEER_F_HAS_ADVANCED_SECURITY: u32 = 1 << 3;

/// Placeholder peer attribute; never used on the wire.
pub const UWGPEER_A_UNSPEC: u16 = 0;

/// `UWGPEER_A_PUBLIC_KEY`: 32-byte Curve25519 public key.
pub const UWGPEER_A_PUBLIC_KEY: u16 = 1;

/// `UWGPEER_A_PRESHARED_KEY`: 32-byte pre-shared symmetric key.
pub const UWGPEER_A_PRESHARED_KEY: u16 = 2;

/// `UWGPEER_A_FLAGS`: `u32` bit mask of `UWGPEER_F_*` flags.
pub const UWGPEER_A_FLAGS: u16 = 3;

/// `UWGPEER_A_ENDPOINT`: `struct sockaddr_in` or `struct sockaddr_in6`.
pub const UWGPEER_A_ENDPOINT: u16 = 4;

/// `UWGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL`: persistent keepalive interval.
///
/// A `u16` in genl family version 2 and a `u32` packing a `u16` range in
/// the UmbraWG 3.x kernel module.
pub const UWGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: u16 = 5;

/// `UWGPEER_A_LAST_HANDSHAKE_TIME`: `struct __kernel_timespec`.
pub const UWGPEER_A_LAST_HANDSHAKE_TIME: u16 = 6;

/// `UWGPEER_A_RX_BYTES`: `u64` counter of received bytes.
pub const UWGPEER_A_RX_BYTES: u16 = 7;

/// `UWGPEER_A_TX_BYTES`: `u64` counter of transmitted bytes.
pub const UWGPEER_A_TX_BYTES: u16 = 8;

/// `UWGPEER_A_ALLOWEDIPS`: nested list of allowed IP entries.
pub const UWGPEER_A_ALLOWEDIPS: u16 = 9;

/// `UWGPEER_A_PROTOCOL_VERSION`: `u32` protocol version, `1` when set.
pub const UWGPEER_A_PROTOCOL_VERSION: u16 = 10;

/// `NLA_FLAG` requesting UmbraWG advanced security for the peer.
///
/// The payload is empty: only the presence of the attribute matters. The
/// kernel mirrors the setting in `UWGPEER_A_FLAGS`.
pub const UWGPEER_A_ADVANCED_SECURITY: u16 = 11;

/// `UWGPEER_A_CIPHER`: `u32` data cipher of the peer, one of the
/// `UWG_CIPHER_*` values.
///
/// An absent attribute means
/// [`UWG_CIPHER_CHACHA20POLY1305`].
pub const UWGPEER_A_CIPHER: u16 = 12;

/// `UWG_CIPHER_CHACHA20POLY1305`: ChaCha20-Poly1305 transport cipher, the
/// default.
pub const UWG_CIPHER_CHACHA20POLY1305: u32 = 0;

/// `UWG_CIPHER_AES256GCM`: AES-256-GCM transport cipher.
pub const UWG_CIPHER_AES256GCM: u32 = 1;

/// Placeholder allowed IP attribute; never used on the wire.
pub const UWGALLOWEDIP_A_UNSPEC: u16 = 0;

/// `UWGALLOWEDIP_A_FAMILY`: `u16` address family (`AF_INET`/`AF_INET6`).
pub const UWGALLOWEDIP_A_FAMILY: u16 = 1;

/// `UWGALLOWEDIP_A_IPADDR`: `struct in_addr` or `struct in6_addr`.
pub const UWGALLOWEDIP_A_IPADDR: u16 = 2;

/// `UWGALLOWEDIP_A_CIDR_MASK`: `u8` prefix length.
pub const UWGALLOWEDIP_A_CIDR_MASK: u16 = 3;

/// `u32` flags of an allowed IP: either `0` or [`UWGALLOWEDIP_F_REMOVE_ME`].
pub const UWGALLOWEDIP_A_FLAGS: u16 = 4;

/// Removes the allowed IP instead of adding it.
pub const UWGALLOWEDIP_F_REMOVE_ME: u32 = 1 << 0;

/// `UWGDEVICE_A_FEC_STATS`: nested device-wide FEC counters.
///
/// Read-only attribute of `UWG_CMD_GET_DEVICE` replies; see
/// [`FecStats`](crate::FecStats).
pub const UWGDEVICE_A_FEC_STATS: u16 = 38;

/// `UWGDEVICE_A_BBR_STATS`: nested device-wide BBR state.
///
/// Read-only attribute of `UWG_CMD_GET_DEVICE` replies; see
/// [`BbrStats`](crate::BbrStats).
pub const UWGDEVICE_A_BBR_STATS: u16 = 39;

/// `UWGDEVICE_A_UNDERLAY_MTU`: `u16` MTU of the path between the peers,
/// `576..=65535`, `1500` by default.
///
/// While FEC is enabled the kernel lowers the interface MTU so that one
/// full-size packet still fits a single FEC shard datagram on that path, and
/// restores it when FEC is turned off. The smallest accepted value is
/// [`UNDERLAY_MTU_MIN`](crate::UNDERLAY_MTU_MIN).
pub const UWGDEVICE_A_UNDERLAY_MTU: u16 = 40;

/// `UWGDEVICE_FEC_STATS_A_BLOCKS_ENCODED`: `u64` count of encoded blocks.
pub const UWGDEVICE_FEC_STATS_A_BLOCKS_ENCODED: u16 = 1;

/// `UWGDEVICE_FEC_STATS_A_SHARDS_SENT`: `u64` count of transmitted shards.
pub const UWGDEVICE_FEC_STATS_A_SHARDS_SENT: u16 = 2;

/// `UWGDEVICE_FEC_STATS_A_BLOCKS_DECODED`: `u64` count of decoded blocks.
pub const UWGDEVICE_FEC_STATS_A_BLOCKS_DECODED: u16 = 3;

/// `UWGDEVICE_FEC_STATS_A_PACKETS_RECOVERED`: `u64` count of data shards
/// restored from parity.
pub const UWGDEVICE_FEC_STATS_A_PACKETS_RECOVERED: u16 = 4;

/// `UWGDEVICE_FEC_STATS_A_DECODE_FAIL`: `u64` count of decoding failures.
pub const UWGDEVICE_FEC_STATS_A_DECODE_FAIL: u16 = 5;

/// `UWGDEVICE_FEC_STATS_A_DROPPED_BOUNDS`: `u64` count of shards dropped
/// because their geometry was out of bounds.
pub const UWGDEVICE_FEC_STATS_A_DROPPED_BOUNDS: u16 = 6;

/// `UWGDEVICE_FEC_STATS_A_DROPPED_DISABLED`: `u64` count of shards dropped
/// because FEC was disabled.
pub const UWGDEVICE_FEC_STATS_A_DROPPED_DISABLED: u16 = 7;

/// `UWGDEVICE_BBR_STATS_A_MODE`: `u8` BBR mode (`0` off, `1` monitor,
/// `2` on).
pub const UWGDEVICE_BBR_STATS_A_MODE: u16 = 1;

/// `UWGDEVICE_BBR_STATS_A_CWND`: `u64` congestion window in bytes.
pub const UWGDEVICE_BBR_STATS_A_CWND: u16 = 2;

/// `UWGDEVICE_BBR_STATS_A_INFLIGHT`: `u64` bytes in flight.
pub const UWGDEVICE_BBR_STATS_A_INFLIGHT: u16 = 3;

/// `UWGDEVICE_BBR_STATS_A_PACING_RATE`: `u64` pacing rate in bytes per
/// second.
pub const UWGDEVICE_BBR_STATS_A_PACING_RATE: u16 = 4;

/// `UWGDEVICE_BBR_STATS_A_BTL_BW`: `u64` bottleneck bandwidth estimate in
/// bytes per second.
pub const UWGDEVICE_BBR_STATS_A_BTL_BW: u16 = 5;

/// `UWGDEVICE_BBR_STATS_A_MIN_RTT_NS`: `u64` minimal round-trip time in
/// nanoseconds.
pub const UWGDEVICE_BBR_STATS_A_MIN_RTT_NS: u16 = 6;

/// `UWGDEVICE_BBR_STATS_A_ROUND_LOST`: `u32` packets lost in the current
/// round.
pub const UWGDEVICE_BBR_STATS_A_ROUND_LOST: u16 = 7;

/// `UWGDEVICE_BBR_STATS_A_PEERS`: `u32` number of peers tracked by BBR.
pub const UWGDEVICE_BBR_STATS_A_PEERS: u16 = 8;

/// `UWGDEVICE_BBR_STATS_A_PEERS_NO_ACK`: `u32` number of peers that do not
/// advertise ACK support in CAPS.
///
/// BBR is not applied to these peers and their state is excluded from the
/// aggregates above.
pub const UWGDEVICE_BBR_STATS_A_PEERS_NO_ACK: u16 = 9;
