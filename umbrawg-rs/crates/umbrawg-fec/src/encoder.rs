use rand_core::RngCore;

use crate::gf;
use crate::matrix::RSCode;
use crate::{FecConfig, FecError};

/// Maximum random addition to the shard length of one block.
pub const MAX_SHARD_PADDING: usize = 31;

/// A complete or partial Reed-Solomon block produced by [`FecEncoder`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedBlock {
    /// Identifier of the block; increases by one for every emitted block.
    pub block_id: u32,
    /// Number of data shards `k`; for a partial flush it is the number of
    /// packets actually present (so a receiver can deliver immediately).
    pub k: u8,
    /// Number of parity shards in `shards`; `0` for a partial block sent to a
    /// peer that does not advertise partial-block parity support.
    pub m: u8,
    /// Length of every shard in bytes.
    pub shard_len: u16,
    /// Data shards followed by parity shards, each exactly `shard_len` bytes long.
    pub shards: Vec<Vec<u8>>,
}

/// Collects packets into systematic Reed-Solomon blocks.
pub struct FecEncoder {
    config: FecConfig,
    code: Result<RSCode, FecError>,
    max_shard_len: usize,
    block_id: u32,
    pending: Vec<Vec<u8>>,
}

impl FecEncoder {
    /// Creates an encoder for `config`.
    ///
    /// `max_shard_len` bounds the size of a shard payload including the
    /// 2-byte packet length prefix. Packets that do not fit are rejected with
    /// [`FecError::PacketTooLarge`].
    #[must_use]
    pub fn new(config: FecConfig, max_shard_len: usize) -> Self {
        Self::with_block_id(config, max_shard_len, 0)
    }

    /// Creates an encoder whose first emitted block carries `block_id`.
    ///
    /// A reconfigured encoder must not restart the sequence: peers keep the
    /// last `block_id` they accepted and reject a restart as an ancient
    /// duplicate. Callers therefore pass the id the previous encoder would
    /// have used next.
    #[must_use]
    pub fn with_block_id(config: FecConfig, max_shard_len: usize, block_id: u32) -> Self {
        Self {
            config,
            code: RSCode::try_new(config.k(), config.m()),
            max_shard_len,
            block_id,
            pending: Vec::with_capacity(config.k()),
        }
    }

    /// Returns the configuration of this encoder.
    #[must_use]
    pub fn config(&self) -> FecConfig {
        self.config
    }

    /// Identifier that will be assigned to the next emitted block.
    #[must_use]
    pub fn block_id(&self) -> u32 {
        self.block_id
    }

    /// Number of packets accumulated for the next block.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Adds a packet to the current block.
    ///
    /// Returns `Some(block)` once `k` packets have been accumulated. The block
    /// contains `k` data shards and `m` parity shards, and the encoder starts a
    /// new block.
    ///
    /// # Errors
    ///
    /// Returns [`FecError::PacketTooLarge`] when `packet.len() + 2` exceeds
    /// `max_shard_len` or does not fit into a 16-bit shard length. Returns a
    /// configuration error when the encoder was built from an unchecked
    /// [`FecConfig`] value.
    pub fn push(&mut self, packet: &[u8]) -> Result<Option<EncodedBlock>, FecError> {
        self.push_inner(packet, None)
    }

    /// Adds a packet to the current block with randomized shard padding.
    ///
    /// Behaves like [`Self::push`], but the emitted block gets an extra
    /// `0..=31` random bytes on top of the longest `packet.len() + 2` prefix.
    /// Every shard of the block keeps the same length, so the receiver's
    /// Reed-Solomon layout is unchanged and the length prefix still delimits
    /// the real payload.
    ///
    /// # Errors
    ///
    /// See [`Self::push`].
    pub fn push_with_rng(
        &mut self,
        packet: &[u8],
        rng: &mut impl RngCore,
    ) -> Result<Option<EncodedBlock>, FecError> {
        self.push_inner(packet, Some(rng))
    }

    fn push_inner(
        &mut self,
        packet: &[u8],
        rng: Option<&mut dyn RngCore>,
    ) -> Result<Option<EncodedBlock>, FecError> {
        let k = match &self.code {
            Ok(code) => code.k(),
            Err(error) => return Err(*error),
        };
        if packet
            .len()
            .checked_add(2)
            .is_none_or(|len| len > self.max_shard_len || len > usize::from(u16::MAX))
        {
            return Err(FecError::PacketTooLarge {
                packet_len: packet.len(),
                max_shard_len: self.max_shard_len,
            });
        }
        self.pending.push(packet.to_vec());
        if self.pending.len() < k {
            return Ok(None);
        }
        Ok(self.emit(usize::from(self.config.parity_shards), rng))
    }

    /// Emits the packets accumulated so far as a partial block without parity.
    ///
    /// Returns `None` when no packets are pending. The emitted block has
    /// `m == 0` and contains only data shards, matching the protocol rule that
    /// a block flushed before reaching `k` packets is sent without parity
    /// unless the peer advertised partial-block parity support.
    pub fn flush(&mut self) -> Option<EncodedBlock> {
        self.flush_with_parity(0)
    }

    /// Emits a partial block with randomized shard padding.
    ///
    /// Behaves like [`Self::flush`] but includes the extra `0..=31` random
    /// bytes described on [`Self::push_with_rng`].
    pub fn flush_with_rng(&mut self, rng: &mut impl RngCore) -> Option<EncodedBlock> {
        self.flush_with_parity_rng(0, rng)
    }

    /// Emits the packets accumulated so far as a partial block with parity.
    ///
    /// `parity` is clamped to the configured `m`, so a caller can request the
    /// full parity count without knowing whether the encoder was built for a
    /// `k + m` shape. The emitted block uses `k' = pending`, `m' = parity` and
    /// carries `k'` data shards followed by `m'` parity shards encoded for
    /// exactly that `(k', m')` code. `parity == 0` is equivalent to
    /// [`Self::flush`].
    pub fn flush_with_parity(&mut self, parity: u8) -> Option<EncodedBlock> {
        if self.pending.is_empty() {
            return None;
        }
        self.emit(usize::from(parity), None)
    }

    /// Emits a partial block with parity and randomized shard padding.
    ///
    /// Behaves like [`Self::flush_with_parity`] but includes the extra
    /// `0..=31` random bytes described on [`Self::push_with_rng`].
    pub fn flush_with_parity_rng(
        &mut self,
        parity: u8,
        rng: &mut impl RngCore,
    ) -> Option<EncodedBlock> {
        if self.pending.is_empty() {
            return None;
        }
        self.emit(usize::from(parity), Some(rng))
    }

    fn emit(&mut self, parity: usize, mut rng: Option<&mut dyn RngCore>) -> Option<EncodedBlock> {
        let Ok(code) = &self.code else {
            return None;
        };
        let config_k = code.k();
        let config_m = code.m();
        let k = self.pending.len();
        if k == 0 || k > config_k {
            return None;
        }
        let mut m = parity.min(config_m);
        // A full block reuses the encoder's code; a partial block has a
        // different `k`, so its systematic coefficient matrix is built for
        // `(k, m)`. If that ever fails, fall back to the legacy data-only
        // form instead of dropping the queued packets.
        let partial_code = if m > 0 && (k != config_k || m != config_m) {
            match RSCode::try_new(k, m) {
                Ok(partial) => Some(partial),
                Err(_) => {
                    m = 0;
                    None
                }
            }
        } else {
            None
        };
        let base_len = self
            .pending
            .iter()
            .map(|packet| packet.len() + 2)
            .max()
            .unwrap_or(0);
        let extra = match rng.as_mut() {
            Some(source) => random_shard_padding(&mut **source),
            None => 0,
        };
        let shard_len = base_len.saturating_add(extra);
        let shard_len = shard_len.min(self.max_shard_len).min(usize::from(u16::MAX));
        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(k + m);
        for packet in &self.pending {
            let mut shard = vec![0u8; shard_len];
            let packet_len = packet.len() as u16;
            shard[..2].copy_from_slice(&packet_len.to_le_bytes());
            shard[2..2 + packet.len()].copy_from_slice(packet);
            if let Some(source) = rng.as_mut() {
                source.fill_bytes(&mut shard[2 + packet.len()..]);
            }
            shards.push(shard);
        }
        if m > 0 {
            let code = partial_code.as_ref().unwrap_or(code);
            for row in 0..m {
                let mut parity = vec![0u8; shard_len];
                for (column, data) in shards.iter().take(k).enumerate() {
                    gf::mul_add_assign(&mut parity, data, code.coefficient(row, column));
                }
                shards.push(parity);
            }
        }
        let block = EncodedBlock {
            block_id: self.block_id,
            k: k as u8,
            m: m as u8,
            shard_len: shard_len as u16,
            shards,
        };
        self.block_id = self.block_id.wrapping_add(1);
        self.pending.clear();
        Some(block)
    }
}

fn random_shard_padding(rng: &mut dyn RngCore) -> usize {
    let span = u128::try_from(MAX_SHARD_PADDING + 1).unwrap_or(1);
    let value = (u128::from(rng.next_u64()) * span) >> 64;
    usize::try_from(value).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAX_TOTAL_SHARDS;

    fn config(k: u8, m: u8) -> FecConfig {
        FecConfig::new(k, m).expect("valid config")
    }

    #[test]
    fn emits_only_after_k_packets() {
        let mut encoder = FecEncoder::new(config(4, 2), 1500);
        assert_eq!(encoder.block_id(), 0);
        for index in 0..3u8 {
            assert_eq!(encoder.push(&[index; 10]), Ok(None));
        }
        assert_eq!(encoder.pending(), 3);
        let block = encoder.push(&[3u8; 10]).unwrap().expect("block");
        assert_eq!(block.block_id, 0);
        assert_eq!(block.k, 4);
        assert_eq!(block.m, 2);
        assert_eq!(block.shards.len(), 6);
        assert_eq!(block.shard_len, 12);
        assert_eq!(encoder.block_id(), 1);
        assert_eq!(encoder.pending(), 0);
        for shard in &block.shards {
            assert_eq!(shard.len(), usize::from(block.shard_len));
        }
        assert_eq!(encoder.push(&[9u8; 10]), Ok(None));
        assert_eq!(encoder.flush().unwrap().block_id, 1);
        assert_eq!(encoder.block_id(), 2);
    }

    #[test]
    fn with_block_id_continues_the_sequence() {
        let mut encoder = FecEncoder::with_block_id(config(2, 1), 1500, 7);
        assert_eq!(encoder.block_id(), 7);
        assert!(encoder.push(&[1u8; 10]).unwrap().is_none());
        let block = encoder.push(&[2u8; 10]).unwrap().expect("block");
        assert_eq!(block.block_id, 7);
        assert_eq!(encoder.block_id(), 8);
        assert!(encoder.push(&[3u8; 10]).unwrap().is_none());
        let partial = encoder.flush().expect("partial block");
        assert_eq!(partial.block_id, 8);
        assert_eq!(encoder.block_id(), 9);
    }

    #[test]
    fn data_shard_has_length_prefix_and_zero_padding() {
        let mut encoder = FecEncoder::new(config(2, 1), 64);
        assert!(encoder.push(&[1, 2, 3]).unwrap().is_none());
        let block = encoder.push(&[4, 5, 6, 7, 8]).unwrap().expect("block");
        assert_eq!(block.shard_len, 7);
        assert_eq!(block.shards[0], vec![3, 0, 1, 2, 3, 0, 0]);
        assert_eq!(block.shards[1], vec![5, 0, 4, 5, 6, 7, 8]);
        assert_eq!(block.shards[2].len(), 7);
    }

    #[test]
    fn flush_returns_partial_block_without_parity() {
        let mut encoder = FecEncoder::new(config(4, 2), 1500);
        assert_eq!(encoder.flush(), None);
        assert_eq!(encoder.push(&[1u8; 20]).unwrap(), None);
        assert_eq!(encoder.push(&[2u8; 30]).unwrap(), None);
        let block = encoder.flush().expect("partial block");
        assert_eq!(block.m, 0);
        assert_eq!(block.k, 2);
        assert_eq!(block.shards.len(), 2);
        assert_eq!(block.shard_len, 32);
        assert_eq!(encoder.flush(), None);
        assert_eq!(encoder.block_id(), 1);
    }

    #[test]
    fn partial_flush_with_parity_uses_the_partial_shape() {
        let mut encoder = FecEncoder::new(config(4, 2), 1500);
        assert_eq!(encoder.flush_with_parity(2), None);
        assert_eq!(encoder.push(&[1u8; 20]).unwrap(), None);
        let block = encoder.flush_with_parity(2).expect("partial block");
        assert_eq!(block.k, 1);
        assert_eq!(block.m, 2);
        assert_eq!(block.shards.len(), 3);
        assert_eq!(block.shard_len, 22);
        assert_eq!(encoder.block_id(), 1);
        assert_eq!(encoder.flush_with_parity(2), None);
    }

    #[test]
    fn partial_flush_clamps_parity_to_the_local_m() {
        let mut encoder = FecEncoder::new(config(2, 1), 64);
        assert_eq!(encoder.push(&[7u8; 4]).unwrap(), None);
        let block = encoder.flush_with_parity(u8::MAX).expect("partial block");
        assert_eq!(block.k, 1);
        assert_eq!(block.m, 1, "m' must never exceed the local m");
        assert_eq!(block.shards.len(), 2);
    }

    #[test]
    fn partial_blocks_with_parity_restore_a_lost_data_shard() {
        use crate::{FecDecoder, FecShard};
        for (pending, parity) in [(1usize, 1u8), (1, 2), (2, 1), (2, 2)] {
            let config = config(4, 2);
            let mut encoder = FecEncoder::new(config, 1500);
            let packets: Vec<Vec<u8>> = (0..pending)
                .map(|index| vec![u8::try_from(index).unwrap(); 24])
                .collect();
            for packet in &packets {
                assert!(encoder.push(packet).unwrap().is_none());
            }
            let block = encoder.flush_with_parity(parity).expect("partial block");
            assert_eq!(usize::from(block.k), pending);
            assert_eq!(usize::from(block.m), usize::from(parity).min(config.m()));
            assert_eq!(block.shards.len(), pending + usize::from(block.m));

            let mut decoder = FecDecoder::new(config);
            let now = std::time::Instant::now();
            let mut decoded = Vec::new();
            // Lose data shard 0; every parity shard must be able to restore it
            // with the advertised `(k', m')` shape.
            for index in 1..block.shards.len() {
                decoded.extend(
                    decoder
                        .push_at(
                            FecShard {
                                block_id: block.block_id,
                                index: u8::try_from(index).unwrap(),
                                k: block.k,
                                m: block.m,
                                shard_len: block.shard_len,
                                payload: &block.shards[index],
                            },
                            now,
                        )
                        .unwrap(),
                );
            }
            assert_eq!(decoded.len(), 1, "pending={pending} parity={parity}");
            assert_eq!(decoded[0].packets, packets);
            assert_eq!(decoded[0].recovered, 1);
        }
    }

    #[test]
    fn partial_blocks_without_parity_keep_the_legacy_shape() {
        let mut encoder = FecEncoder::new(config(4, 2), 1500);
        assert_eq!(encoder.push(&[1u8; 20]).unwrap(), None);
        let block = encoder.flush_with_parity(0).expect("partial block");
        assert_eq!((block.k, block.m), (1, 0));
        assert_eq!(block.shards.len(), 1);
    }

    #[test]
    fn allows_empty_packets() {
        let mut encoder = FecEncoder::new(config(1, 1), 4);
        let block = encoder.push(&[]).unwrap().expect("block");
        assert_eq!(block.shard_len, 2);
        assert_eq!(block.shards[0], vec![0, 0]);
        assert_eq!(block.shards[1], vec![0, 0]);
    }

    #[test]
    fn rejects_oversized_packets() {
        let mut encoder = FecEncoder::new(config(2, 1), 16);
        assert_eq!(
            encoder.push(&[0u8; 15]),
            Err(FecError::PacketTooLarge {
                packet_len: 15,
                max_shard_len: 16
            })
        );
        assert_eq!(encoder.pending(), 0);
        assert_eq!(encoder.push(&[0u8; 14]).unwrap(), None);
    }

    #[test]
    fn rejects_packets_above_u16_shard_length() {
        let mut encoder = FecEncoder::new(config(1, 1), usize::MAX);
        assert!(matches!(
            encoder.push(&vec![0u8; u16::MAX as usize]),
            Err(FecError::PacketTooLarge { .. })
        ));
        assert!(encoder
            .push(&vec![0u8; u16::MAX as usize - 2])
            .unwrap()
            .is_some());
    }

    #[test]
    fn supports_maximum_block_width() {
        let config = config(250, 5);
        assert_eq!(config.total_shards(), MAX_TOTAL_SHARDS);
        let mut encoder = FecEncoder::new(config, 8);
        let mut block = None;
        for index in 0..250u8 {
            block = encoder.push(&[index; 4]).unwrap().or(block);
        }
        let block = block.expect("block");
        assert_eq!(block.shards.len(), 255);
    }

    struct TestRng(u64);

    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            (self.next_u64() >> 32) as u32
        }

        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut value = self.0;
            value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            value ^ (value >> 31)
        }

        fn fill_bytes(&mut self, dst: &mut [u8]) {
            for chunk in dst.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                let length = chunk.len();
                chunk.copy_from_slice(&bytes[..length]);
            }
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> std::result::Result<(), rand_core::Error> {
            self.fill_bytes(dst);
            Ok(())
        }
    }

    #[test]
    fn randomized_shard_length_varies_within_bounds() {
        let mut encoder = FecEncoder::new(config(4, 2), 1500);
        let mut rng = TestRng(7);
        let mut lengths = Vec::new();
        for round in 0..64u8 {
            let mut block = None;
            for index in 0..4u8 {
                block = encoder
                    .push_with_rng(&[round.wrapping_add(index); 40], &mut rng)
                    .unwrap()
                    .or(block);
            }
            let block = block.expect("block");
            assert_eq!(block.shards.len(), 6);
            assert!(usize::from(block.shard_len) >= 42);
            assert!(usize::from(block.shard_len) <= 42 + MAX_SHARD_PADDING);
            for shard in &block.shards {
                assert_eq!(shard.len(), usize::from(block.shard_len));
            }
            lengths.push(block.shard_len);
        }
        lengths.sort_unstable();
        lengths.dedup();
        assert!(
            lengths.len() > 1,
            "shard length must not be constant across blocks"
        );
        assert!(
            lengths.iter().any(|len| usize::from(*len) > 42),
            "random padding must sometimes be added"
        );
    }

    #[test]
    fn randomized_shard_padding_respects_the_limit() {
        let mut encoder = FecEncoder::new(config(1, 1), 50);
        let mut rng = TestRng(11);
        for _ in 0..64 {
            let block = encoder.push_with_rng(&[0u8; 40], &mut rng).unwrap();
            let block = block.expect("block");
            assert!(usize::from(block.shard_len) <= 50);
        }
        let mut encoder = FecEncoder::new(config(1, 1), 2);
        let block = encoder.push_with_rng(&[], &mut rng).unwrap();
        assert_eq!(block.expect("block").shard_len, 2);
    }

    #[test]
    fn randomized_shards_roundtrip_through_the_decoder() {
        use crate::{FecDecoder, FecShard};
        use std::time::Instant;

        let mut encoder = FecEncoder::new(config(3, 1), 1500);
        let mut rng = TestRng(13);
        let packets: Vec<Vec<u8>> = (0..3u8).map(|index| vec![index; 32]).collect();
        let mut block = None;
        for packet in &packets {
            block = encoder.push_with_rng(packet, &mut rng).unwrap().or(block);
        }
        let block = block.expect("block");
        assert!(usize::from(block.shard_len) >= 34);
        let mut decoder = FecDecoder::new(config(3, 1));
        let mut decoded = Vec::new();
        let now = Instant::now();
        for index in [2usize, 0, 1] {
            decoded.extend(
                decoder
                    .push_at(
                        FecShard {
                            block_id: block.block_id,
                            index: u8::try_from(index).unwrap(),
                            k: block.k,
                            m: block.m,
                            shard_len: block.shard_len,
                            payload: &block.shards[index],
                        },
                        now,
                    )
                    .unwrap(),
            );
        }
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].packets, packets);
    }

    #[test]
    fn randomized_partial_flush_keeps_shards_equal() {
        let mut encoder = FecEncoder::new(config(4, 1), 1500);
        let mut rng = TestRng(17);
        assert_eq!(encoder.push_with_rng(&[1u8; 10], &mut rng).unwrap(), None);
        let block = encoder.flush_with_rng(&mut rng).expect("partial block");
        assert_eq!(block.m, 0);
        assert_eq!(block.shards.len(), 1);
        for shard in &block.shards {
            assert_eq!(shard.len(), usize::from(block.shard_len));
        }
        assert!(usize::from(block.shard_len) >= 12);
        assert!(usize::from(block.shard_len) <= 12 + MAX_SHARD_PADDING);
    }
}
