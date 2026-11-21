// SPDX-License-Identifier: MIT

//! Read-only runtime counters reported by `UWG_CMD_GET_DEVICE`.
//!
//! The kernel exports the FEC and BBR state as nested
//! `UWGDEVICE_A_FEC_STATS` and `UWGDEVICE_A_BBR_STATS` attributes. This
//! module provides the corresponding [`FecStats`] and [`BbrStats`] types;
//! [`UmbrawgAttribute`](crate::UmbrawgAttribute) carries them as
//! [`FecStats`](crate::UmbrawgAttribute::FecStats) and
//! [`BbrStats`](crate::UmbrawgAttribute::BbrStats) variants.
//!
//! Unknown nested attributes are ignored, so a reply from a newer module
//! still parses. A known attribute with a malformed payload length yields a
//! [`DecodeError`](netlink_packet_core::DecodeError) instead of a panic.
//! Fields missing from an otherwise well-formed nested attribute default
//! to zero.

use netlink_packet_core::{
    parse_u32, parse_u64, parse_u8, DecodeError, ErrorContext, Nla, NlaBuffer,
    NlasIterator, Parseable, NLA_F_NESTED,
};

use crate::{
    attribute::BBR_MAX,
    constants::{
        UWGDEVICE_A_BBR_STATS, UWGDEVICE_A_FEC_STATS,
        UWGDEVICE_BBR_STATS_A_BTL_BW, UWGDEVICE_BBR_STATS_A_CWND,
        UWGDEVICE_BBR_STATS_A_INFLIGHT, UWGDEVICE_BBR_STATS_A_MIN_RTT_NS,
        UWGDEVICE_BBR_STATS_A_MODE, UWGDEVICE_BBR_STATS_A_PACING_RATE,
        UWGDEVICE_BBR_STATS_A_PEERS, UWGDEVICE_BBR_STATS_A_PEERS_NO_ACK,
        UWGDEVICE_BBR_STATS_A_ROUND_LOST, UWGDEVICE_FEC_STATS_A_BLOCKS_DECODED,
        UWGDEVICE_FEC_STATS_A_BLOCKS_ENCODED,
        UWGDEVICE_FEC_STATS_A_DECODE_FAIL,
        UWGDEVICE_FEC_STATS_A_DROPPED_BOUNDS,
        UWGDEVICE_FEC_STATS_A_DROPPED_DISABLED,
        UWGDEVICE_FEC_STATS_A_PACKETS_RECOVERED,
        UWGDEVICE_FEC_STATS_A_SHARDS_SENT,
    },
};

const NLA_HEADER_LEN: usize = 4;

fn nla_len(payload_len: usize) -> usize {
    (NLA_HEADER_LEN + payload_len + 3) & !3
}

fn emit_nla(buffer: &mut [u8], offset: &mut usize, kind: u16, payload: &[u8]) {
    let len = NLA_HEADER_LEN + payload.len();
    let padded = nla_len(payload.len());
    buffer[*offset..*offset + 2].copy_from_slice(&(len as u16).to_le_bytes());
    buffer[*offset + 2..*offset + 4].copy_from_slice(&kind.to_le_bytes());
    buffer[*offset + 4..*offset + len].copy_from_slice(payload);
    buffer[*offset + len..*offset + padded].fill(0);
    *offset += padded;
}

/// Device-wide forward error correction counters
/// (`UWGDEVICE_A_FEC_STATS`, `NLA_NESTED`).
///
/// The kernel reports the counters only in `UWG_CMD_GET_DEVICE` replies; a
/// device without the attribute has no [`FecStats`] value. Missing nested
/// counters default to zero.
///
/// # Example
///
/// ```
/// use netlink_packet_umbrawg::FecStats;
///
/// let stats = FecStats {
///     blocks_encoded: 10,
///     shards_sent: 12,
///     ..FecStats::default()
/// };
/// assert_eq!(stats.packets_recovered, 0);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FecStats {
    /// Blocks emitted by the encoder, including partial flushes.
    pub blocks_encoded: u64,
    /// Shards handed to the transport for transmission.
    pub shards_sent: u64,
    /// Blocks released by the decoder.
    pub blocks_decoded: u64,
    /// Data shards restored from parity during decoding.
    pub packets_recovered: u64,
    /// Shards rejected by the decoder or by header validation.
    pub decode_fail: u64,
    /// Shards rejected because their header or geometry was out of bounds.
    pub dropped_bounds: u64,
    /// Shards dropped because FEC was not negotiated or is disabled.
    pub dropped_disabled: u64,
}

impl Nla for FecStats {
    fn value_len(&self) -> usize {
        7 * nla_len(8)
    }

    fn kind(&self) -> u16 {
        UWGDEVICE_A_FEC_STATS | NLA_F_NESTED
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        let mut offset = 0;
        for (kind, value) in [
            (UWGDEVICE_FEC_STATS_A_BLOCKS_ENCODED, self.blocks_encoded),
            (UWGDEVICE_FEC_STATS_A_SHARDS_SENT, self.shards_sent),
            (UWGDEVICE_FEC_STATS_A_BLOCKS_DECODED, self.blocks_decoded),
            (
                UWGDEVICE_FEC_STATS_A_PACKETS_RECOVERED,
                self.packets_recovered,
            ),
            (UWGDEVICE_FEC_STATS_A_DECODE_FAIL, self.decode_fail),
            (UWGDEVICE_FEC_STATS_A_DROPPED_BOUNDS, self.dropped_bounds),
            (
                UWGDEVICE_FEC_STATS_A_DROPPED_DISABLED,
                self.dropped_disabled,
            ),
        ] {
            emit_nla(buffer, &mut offset, kind, &value.to_le_bytes());
        }
    }
}

impl<T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&T>> for FecStats {
    fn parse(buf: &NlaBuffer<&T>) -> Result<Self, DecodeError> {
        let mut stats = Self::default();
        for nla in NlasIterator::new(buf.value()) {
            let nla = nla?;
            let payload = nla.value();
            match nla.kind() {
                UWGDEVICE_FEC_STATS_A_BLOCKS_ENCODED => {
                    stats.blocks_encoded = parse_u64(payload).context(
                        "invalid UWGDEVICE_FEC_STATS_A_BLOCKS_ENCODED value",
                    )?;
                }
                UWGDEVICE_FEC_STATS_A_SHARDS_SENT => {
                    stats.shards_sent = parse_u64(payload).context(
                        "invalid UWGDEVICE_FEC_STATS_A_SHARDS_SENT value",
                    )?;
                }
                UWGDEVICE_FEC_STATS_A_BLOCKS_DECODED => {
                    stats.blocks_decoded = parse_u64(payload).context(
                        "invalid UWGDEVICE_FEC_STATS_A_BLOCKS_DECODED value",
                    )?;
                }
                UWGDEVICE_FEC_STATS_A_PACKETS_RECOVERED => {
                    stats.packets_recovered = parse_u64(payload).context(
                        "invalid UWGDEVICE_FEC_STATS_A_PACKETS_RECOVERED \
                         value",
                    )?;
                }
                UWGDEVICE_FEC_STATS_A_DECODE_FAIL => {
                    stats.decode_fail = parse_u64(payload).context(
                        "invalid UWGDEVICE_FEC_STATS_A_DECODE_FAIL value",
                    )?;
                }
                UWGDEVICE_FEC_STATS_A_DROPPED_BOUNDS => {
                    stats.dropped_bounds = parse_u64(payload).context(
                        "invalid UWGDEVICE_FEC_STATS_A_DROPPED_BOUNDS value",
                    )?;
                }
                UWGDEVICE_FEC_STATS_A_DROPPED_DISABLED => {
                    stats.dropped_disabled = parse_u64(payload).context(
                        "invalid UWGDEVICE_FEC_STATS_A_DROPPED_DISABLED value",
                    )?;
                }
                _ => {}
            }
        }
        Ok(stats)
    }
}

/// Device-wide BBR state (`UWGDEVICE_A_BBR_STATS`, `NLA_NESTED`).
///
/// The kernel reports the state only in `UWG_CMD_GET_DEVICE` replies; a
/// device without the attribute has no [`BbrStats`] value. Missing nested
/// values default to zero, which corresponds to [`mode`](Self::mode)
/// `off`.
///
/// # Example
///
/// ```
/// use netlink_packet_umbrawg::BbrStats;
///
/// let stats = BbrStats {
///     mode: 2,
///     cwnd: 131_072,
///     ..BbrStats::default()
/// };
/// assert_eq!(stats.inflight, 0);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BbrStats {
    /// Congestion control mode: `0` off, `1` monitor, `2` on.
    pub mode: u8,
    /// Congestion window in bytes.
    pub cwnd: u64,
    /// Bytes in flight.
    pub inflight: u64,
    /// Pacing rate in bytes per second.
    pub pacing_rate: u64,
    /// Bottleneck bandwidth estimate in bytes per second.
    pub btl_bw: u64,
    /// Minimal round-trip time in nanoseconds.
    pub min_rtt_ns: u64,
    /// Packets lost in the current round.
    pub round_lost: u32,
    /// Number of peers tracked by BBR.
    pub peers: u32,
    /// Number of peers that do not advertise ACK support in CAPS.
    ///
    /// BBR is not applied to these peers and their state is not part of the
    /// aggregates above.
    pub peers_no_ack: u32,
}

impl Nla for BbrStats {
    fn value_len(&self) -> usize {
        nla_len(1) + 5 * nla_len(8) + 3 * nla_len(4)
    }

    fn kind(&self) -> u16 {
        UWGDEVICE_A_BBR_STATS | NLA_F_NESTED
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        let mut offset = 0;
        emit_nla(
            buffer,
            &mut offset,
            UWGDEVICE_BBR_STATS_A_MODE,
            &[self.mode],
        );
        for (kind, value) in [
            (UWGDEVICE_BBR_STATS_A_CWND, self.cwnd),
            (UWGDEVICE_BBR_STATS_A_INFLIGHT, self.inflight),
            (UWGDEVICE_BBR_STATS_A_PACING_RATE, self.pacing_rate),
            (UWGDEVICE_BBR_STATS_A_BTL_BW, self.btl_bw),
            (UWGDEVICE_BBR_STATS_A_MIN_RTT_NS, self.min_rtt_ns),
        ] {
            emit_nla(buffer, &mut offset, kind, &value.to_le_bytes());
        }
        for (kind, value) in [
            (UWGDEVICE_BBR_STATS_A_ROUND_LOST, self.round_lost),
            (UWGDEVICE_BBR_STATS_A_PEERS, self.peers),
            (UWGDEVICE_BBR_STATS_A_PEERS_NO_ACK, self.peers_no_ack),
        ] {
            emit_nla(buffer, &mut offset, kind, &value.to_le_bytes());
        }
    }
}

impl<T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&T>> for BbrStats {
    fn parse(buf: &NlaBuffer<&T>) -> Result<Self, DecodeError> {
        let mut stats = Self::default();
        for nla in NlasIterator::new(buf.value()) {
            let nla = nla?;
            let payload = nla.value();
            match nla.kind() {
                UWGDEVICE_BBR_STATS_A_MODE => {
                    let mode = parse_u8(payload)
                        .context("invalid UWGDEVICE_BBR_STATS_A_MODE value")?;
                    if mode > BBR_MAX {
                        return Err(DecodeError::from(format!(
                            "UWGDEVICE_BBR_STATS_A_MODE value {mode} exceeds \
                             {BBR_MAX}"
                        )));
                    }
                    stats.mode = mode;
                }
                UWGDEVICE_BBR_STATS_A_CWND => {
                    stats.cwnd = parse_u64(payload)
                        .context("invalid UWGDEVICE_BBR_STATS_A_CWND value")?;
                }
                UWGDEVICE_BBR_STATS_A_INFLIGHT => {
                    stats.inflight = parse_u64(payload).context(
                        "invalid UWGDEVICE_BBR_STATS_A_INFLIGHT value",
                    )?;
                }
                UWGDEVICE_BBR_STATS_A_PACING_RATE => {
                    stats.pacing_rate = parse_u64(payload).context(
                        "invalid UWGDEVICE_BBR_STATS_A_PACING_RATE value",
                    )?;
                }
                UWGDEVICE_BBR_STATS_A_BTL_BW => {
                    stats.btl_bw = parse_u64(payload).context(
                        "invalid UWGDEVICE_BBR_STATS_A_BTL_BW value",
                    )?;
                }
                UWGDEVICE_BBR_STATS_A_MIN_RTT_NS => {
                    stats.min_rtt_ns = parse_u64(payload).context(
                        "invalid UWGDEVICE_BBR_STATS_A_MIN_RTT_NS value",
                    )?;
                }
                UWGDEVICE_BBR_STATS_A_ROUND_LOST => {
                    stats.round_lost = parse_u32(payload).context(
                        "invalid UWGDEVICE_BBR_STATS_A_ROUND_LOST value",
                    )?;
                }
                UWGDEVICE_BBR_STATS_A_PEERS => {
                    stats.peers = parse_u32(payload)
                        .context("invalid UWGDEVICE_BBR_STATS_A_PEERS value")?;
                }
                UWGDEVICE_BBR_STATS_A_PEERS_NO_ACK => {
                    stats.peers_no_ack = parse_u32(payload).context(
                        "invalid UWGDEVICE_BBR_STATS_A_PEERS_NO_ACK value",
                    )?;
                }
                _ => {}
            }
        }
        Ok(stats)
    }
}
