// SPDX-License-Identifier: MIT

//! Read-only runtime counters reported by `UWG_CMD_GET_DEVICE`.
//!
//! The kernel exports the FEC counters as a nested
//! `UWGDEVICE_A_FEC_STATS` attribute. This module provides the corresponding
//! [`FecStats`] type; [`UmbrawgAttribute`](crate::UmbrawgAttribute) carries it
//! as the [`FecStats`](crate::UmbrawgAttribute::FecStats) variant.
//!
//! Unknown nested attributes are ignored, so a reply from a newer module
//! still parses. A known attribute with a malformed payload length yields a
//! [`DecodeError`](netlink_packet_core::DecodeError) instead of a panic.
//! Fields missing from an otherwise well-formed nested attribute default
//! to zero.

use netlink_packet_core::{
    parse_u64, DecodeError, ErrorContext, Nla, NlaBuffer, NlasIterator,
    Parseable, NLA_F_NESTED,
};

use crate::constants::{
    UWGDEVICE_A_FEC_STATS, UWGDEVICE_FEC_STATS_A_BLOCKS_DECODED,
    UWGDEVICE_FEC_STATS_A_BLOCKS_ENCODED, UWGDEVICE_FEC_STATS_A_DECODE_FAIL,
    UWGDEVICE_FEC_STATS_A_DROPPED_BOUNDS,
    UWGDEVICE_FEC_STATS_A_DROPPED_DISABLED,
    UWGDEVICE_FEC_STATS_A_PACKETS_RECOVERED, UWGDEVICE_FEC_STATS_A_SHARDS_SENT,
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
                        "invalid UWGDEVICE_FEC_STATS_A_PACKETS_RECOVERED value",
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
