use std::collections::btree_map::BTreeMap;
use std::time::{Duration, Instant};

use crate::gf;
use crate::matrix::{invert, RSCode};
use crate::{FecConfig, FecError, DEFAULT_BLOCK_TIMEOUT, MAX_PENDING_BLOCKS, MAX_SHARD_LEN};

/// A single received shard passed to [`FecDecoder::push`].
#[derive(Clone, Copy, Debug)]
pub struct FecShard<'a> {
    /// Block identifier.
    pub block_id: u32,
    /// Shard index in `0..k+m`.
    pub index: u8,
    /// Number of data shards in the block.
    pub k: u8,
    /// Number of parity shards in the block.
    pub m: u8,
    /// Length of every shard in the block.
    pub shard_len: u16,
    /// Shard payload, exactly `shard_len` bytes.
    pub payload: &'a [u8],
}

/// A block whose packets are ready to be passed to the tunnel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedBlock {
    /// Identifier of the block.
    pub block_id: u32,
    /// Packets of the block in their original order.
    pub packets: Vec<Vec<u8>>,
    /// Number of data shards restored from parity shards.
    ///
    /// Zero when every data shard arrived intact and the block was merely
    /// released, and also when the block timed out and only the received data
    /// shards were returned.
    pub recovered: usize,
}

/// Reassembles packets from received Reed-Solomon shards.
///
/// Blocks are held until `k` shards are available or until the block timeout
/// expires, and are released in ascending block order. A block following a
/// missing `block_id` waits for the timeout at most. At most
/// [`MAX_PENDING_BLOCKS`] blocks are held at once; when the limit is exceeded
/// the oldest block is released early with the data shards received so far.
pub struct FecDecoder {
    config: FecConfig,
    code: Result<RSCode, FecError>,
    timeout: Duration,
    blocks: BTreeMap<u64, Block>,
    next_seq: Option<u64>,
    clock: BlockClock,
}

impl FecDecoder {
    /// Creates a decoder for `config` with the default 5 ms block timeout.
    #[must_use]
    pub fn new(config: FecConfig) -> Self {
        Self::with_timeout(config, DEFAULT_BLOCK_TIMEOUT)
    }

    /// Creates a decoder for `config` with a custom block timeout.
    #[must_use]
    pub fn with_timeout(config: FecConfig, timeout: Duration) -> Self {
        Self {
            config,
            code: RSCode::try_new(config.k(), config.m()),
            timeout,
            blocks: BTreeMap::new(),
            next_seq: None,
            clock: BlockClock::new(),
        }
    }

    /// Returns the configuration of this decoder.
    #[must_use]
    pub fn config(&self) -> FecConfig {
        self.config
    }

    /// Returns the block timeout.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Number of blocks currently held by the decoder.
    #[must_use]
    pub fn pending_blocks(&self) -> usize {
        self.blocks.len()
    }

    /// Adds a received shard, using the current instant as the arrival time.
    ///
    /// Returns the blocks that became ready as a result of this shard.
    ///
    /// # Errors
    ///
    /// Returns an error for shards whose `k`, `m`, `index`, `shard_len` or
    /// payload length is invalid, or that disagree with earlier shards of the
    /// same block. A shard for a block that has already been released is
    /// ignored.
    pub fn push(&mut self, shard: FecShard<'_>) -> Result<Vec<DecodedBlock>, FecError> {
        self.push_at(shard, Instant::now())
    }

    /// Adds a received shard with an explicit arrival time.
    ///
    /// This is the deterministic variant of [`FecDecoder::push`], useful for
    /// tests and for callers that already have a timestamp.
    ///
    /// # Errors
    ///
    /// See [`FecDecoder::push`].
    pub fn push_at(
        &mut self,
        shard: FecShard<'_>,
        now: Instant,
    ) -> Result<Vec<DecodedBlock>, FecError> {
        self.validate(&shard)?;
        if let Err(error) = &self.code {
            return Err(*error);
        }
        let Some(seq) = self.clock.extend(shard.block_id) else {
            return Ok(Vec::new());
        };
        if self.next_seq.is_some_and(|next| seq < next) {
            return Ok(Vec::new());
        }
        if self.next_seq.is_none() {
            self.next_seq = Some(seq);
        }
        if let Some(existing) = self.blocks.get(&seq) {
            if existing.k != shard.k || existing.m != shard.m {
                return Err(FecError::ConfigMismatch {
                    expected_k: existing.k,
                    expected_m: existing.m,
                    actual_k: shard.k,
                    actual_m: shard.m,
                });
            }
            if existing.shard_len != shard.shard_len {
                return Err(FecError::ShardLenMismatch {
                    block_id: shard.block_id,
                    expected: existing.shard_len,
                    actual: shard.shard_len,
                });
            }
        }
        let total = usize::from(shard.k) + usize::from(shard.m);
        let block = self.blocks.entry(seq).or_insert_with(|| Block {
            block_id: shard.block_id,
            k: shard.k,
            m: shard.m,
            shard_len: shard.shard_len,
            deadline: now + self.timeout,
            shards: vec![None; total],
            present: 0,
            packets: None,
            recovered: 0,
        });
        let index = usize::from(shard.index);
        let Some(slot) = block.shards.get_mut(index) else {
            return Err(FecError::InvalidIndex {
                index: shard.index,
                k: block.k,
                m: block.m,
            });
        };
        if slot.is_none() {
            block.present += 1;
        }
        *slot = Some(shard.payload.to_vec());
        let data_shards = usize::from(block.k);
        if block.packets.is_none() && block.present >= data_shards {
            if block.m == 0 {
                block.packets = Some(extract_packets(&block.shards, data_shards));
                block.recovered = 0;
            } else if let Ok(code) = &self.code {
                if let Some((packets, recovered)) = decode_block(code, &mut block.shards) {
                    block.packets = Some(packets);
                    block.recovered = recovered;
                }
            }
        }
        let mut output = self.evict_over_capacity();
        output.extend(self.drain(now));
        Ok(output)
    }

    /// Releases blocks that are ready or whose timeout has expired.
    ///
    /// Returns the blocks in ascending block order. A block is released when
    /// all its data shards are available, when it has been recovered from
    /// parity shards, or when its timeout expires; on timeout only the data
    /// shards actually received are returned, without recovery.
    pub fn poll(&mut self, now: Instant) -> Vec<DecodedBlock> {
        self.drain(now)
    }

    fn validate(&self, shard: &FecShard<'_>) -> Result<(), FecError> {
        let k_matches = shard.k == self.config.data_shards
            || (shard.m == 0 && shard.k >= 1 && shard.k <= self.config.data_shards);
        if !k_matches || (shard.m != self.config.parity_shards && shard.m != 0) {
            return Err(FecError::ConfigMismatch {
                expected_k: self.config.data_shards,
                expected_m: self.config.parity_shards,
                actual_k: shard.k,
                actual_m: shard.m,
            });
        }
        let total = usize::from(shard.k) + usize::from(shard.m);
        if usize::from(shard.index) >= total {
            return Err(FecError::InvalidIndex {
                index: shard.index,
                k: shard.k,
                m: shard.m,
            });
        }
        if shard.shard_len < 2 {
            return Err(FecError::InvalidShardLen {
                shard_len: shard.shard_len,
            });
        }
        if shard.shard_len > MAX_SHARD_LEN {
            return Err(FecError::ShardLenTooLarge {
                shard_len: shard.shard_len,
                max_shard_len: MAX_SHARD_LEN,
            });
        }
        if shard.payload.len() != usize::from(shard.shard_len) {
            return Err(FecError::PayloadLenMismatch {
                expected: shard.shard_len,
                actual: shard.payload.len(),
            });
        }
        if usize::from(shard.index) < usize::from(shard.k) {
            let packet_len = usize::from(u16::from_le_bytes([shard.payload[0], shard.payload[1]]));
            if packet_len + 2 > usize::from(shard.shard_len) {
                return Err(FecError::InvalidPacketLen {
                    packet_len: packet_len as u16,
                    shard_len: shard.shard_len,
                });
            }
        }
        Ok(())
    }

    fn finalize_expired(&mut self, now: Instant) {
        if self.code.is_err() {
            return;
        }
        let expired: Vec<u64> = self
            .blocks
            .iter()
            .filter(|(_, block)| now >= block.deadline && block.packets.is_none())
            .map(|(&seq, _)| seq)
            .collect();
        for seq in expired {
            if let Some(block) = self.blocks.get_mut(&seq) {
                let data_shards = usize::from(block.k);
                block.packets = Some(extract_packets(&block.shards, data_shards));
                block.recovered = 0;
            }
        }
    }

    fn evict_over_capacity(&mut self) -> Vec<DecodedBlock> {
        let mut output = Vec::new();
        while self.blocks.len() > MAX_PENDING_BLOCKS {
            let Some(seq) = self.blocks.keys().next().copied() else {
                break;
            };
            let Some(mut block) = self.blocks.remove(&seq) else {
                break;
            };
            if self.next_seq.is_some_and(|next| next <= seq) {
                self.next_seq = Some(seq.saturating_add(1));
            }
            let packets = block
                .packets
                .take()
                .unwrap_or_else(|| extract_packets(&block.shards, usize::from(block.k)));
            if !packets.is_empty() {
                output.push(DecodedBlock {
                    block_id: block.block_id,
                    packets,
                    recovered: block.recovered,
                });
            }
        }
        output
    }

    fn drain(&mut self, now: Instant) -> Vec<DecodedBlock> {
        self.finalize_expired(now);
        let mut output = Vec::new();
        while let Some(seq) = self.next_seq {
            if self
                .blocks
                .get(&seq)
                .is_some_and(|block| block.packets.is_some())
            {
                if let Some(block) = self.blocks.remove(&seq) {
                    let packets = block.packets.unwrap_or_default();
                    if !packets.is_empty() {
                        output.push(DecodedBlock {
                            block_id: block.block_id,
                            packets,
                            recovered: block.recovered,
                        });
                    }
                }
                self.next_seq = Some(seq.saturating_add(1));
                continue;
            }
            if self.blocks.contains_key(&seq) {
                break;
            }
            let Some((first, deadline)) = self
                .blocks
                .iter()
                .next()
                .map(|(&first, block)| (first, block.deadline))
            else {
                break;
            };
            if now >= deadline {
                self.next_seq = Some(first);
                continue;
            }
            break;
        }
        output
    }
}

struct Block {
    block_id: u32,
    k: u8,
    m: u8,
    shard_len: u16,
    deadline: Instant,
    shards: Vec<Option<Vec<u8>>>,
    present: usize,
    packets: Option<Vec<Vec<u8>>>,
    recovered: usize,
}

fn decode_block(code: &RSCode, shards: &mut [Option<Vec<u8>>]) -> Option<(Vec<Vec<u8>>, usize)> {
    let k = code.k();
    let recovered = shards[..k].iter().filter(|shard| shard.is_none()).count();
    if recovered > 0 && !recover(code, shards) {
        return None;
    }
    Some((extract_packets(shards, k), recovered))
}

fn recover(code: &RSCode, shards: &mut [Option<Vec<u8>>]) -> bool {
    let k = code.k();
    let m = code.m();
    let missing: Vec<usize> = (0..k).filter(|&index| shards[index].is_none()).collect();
    if missing.is_empty() {
        return true;
    }
    let missing_count = missing.len();
    if missing_count > m {
        return false;
    }
    let parity_rows: Vec<usize> = (k..k + m)
        .filter(|&index| shards[index].is_some())
        .take(missing_count)
        .collect();
    if parity_rows.len() < missing_count {
        return false;
    }
    let Some(shard_len) = shards.iter().flatten().next().map(Vec::len) else {
        return false;
    };
    let mut matrix = vec![0u8; missing_count * missing_count];
    for (row, &parity) in parity_rows.iter().enumerate() {
        for (column, &data) in missing.iter().enumerate() {
            matrix[row * missing_count + column] = code.coefficient(parity - k, data);
        }
    }
    let Some(inverse) = invert(&matrix, missing_count) else {
        return false;
    };
    let available_data: Vec<usize> = (0..k).filter(|&index| shards[index].is_some()).collect();
    let mut rhs = Vec::with_capacity(missing_count);
    for &parity in &parity_rows {
        let mut accumulator = shards[parity].clone().unwrap_or_default();
        for &data in &available_data {
            if let Some(shard) = &shards[data] {
                gf::mul_add_assign(&mut accumulator, shard, code.coefficient(parity - k, data));
            }
        }
        rhs.push(accumulator);
    }
    let mut recovered = vec![vec![0u8; shard_len]; missing_count];
    for (row, target) in recovered.iter_mut().enumerate() {
        for (column, source) in rhs.iter().enumerate() {
            gf::mul_add_assign(target, source, inverse[row * missing_count + column]);
        }
    }
    for (row, &index) in missing.iter().enumerate() {
        shards[index] = Some(std::mem::take(&mut recovered[row]));
    }
    true
}

fn extract_packets(shards: &[Option<Vec<u8>>], k: usize) -> Vec<Vec<u8>> {
    let mut packets = Vec::with_capacity(k);
    for shard in shards.iter().take(k).flatten() {
        if shard.len() < 2 {
            continue;
        }
        let packet_len = usize::from(u16::from_le_bytes([shard[0], shard[1]]));
        if packet_len + 2 > shard.len() {
            continue;
        }
        packets.push(shard[2..2 + packet_len].to_vec());
    }
    packets
}

#[derive(Clone, Copy)]
struct BlockClock {
    seen: bool,
    anchor_id: u32,
    anchor_seq: u64,
}

impl BlockClock {
    const fn new() -> Self {
        Self {
            seen: false,
            anchor_id: 0,
            anchor_seq: 0,
        }
    }

    fn extend(&mut self, id: u32) -> Option<u64> {
        if !self.seen {
            self.seen = true;
            self.anchor_id = id;
            self.anchor_seq = 0;
            return Some(0);
        }
        let diff = i64::from(id.wrapping_sub(self.anchor_id) as i32);
        if diff < -(1 << 30) {
            return None;
        }
        let seq = self.anchor_seq.checked_add_signed(diff)?;
        if seq > self.anchor_seq {
            self.anchor_id = id;
            self.anchor_seq = seq;
        }
        Some(seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_orders_wrapped_ids() {
        let mut clock = BlockClock::new();
        assert_eq!(clock.extend(u32::MAX - 1), Some(0));
        assert_eq!(clock.extend(u32::MAX), Some(1));
        assert_eq!(clock.extend(0), Some(2));
        assert_eq!(clock.extend(1), Some(3));
        assert_eq!(clock.extend(u32::MAX - 1), Some(0));
    }

    #[test]
    fn clock_handles_first_id_anywhere() {
        let mut clock = BlockClock::new();
        assert_eq!(clock.extend(0xffff_ffff), Some(0));
        assert_eq!(clock.extend(0), Some(1));
        assert_eq!(clock.extend(5), Some(6));
    }

    #[test]
    fn clock_rejects_ancient_ids() {
        let mut clock = BlockClock::new();
        assert_eq!(clock.extend(1 << 30), Some(0));
        assert_eq!(clock.extend(0), None);
    }

    #[test]
    fn inversion_of_zero_matrix_is_none() {
        assert_eq!(invert(&[0, 0, 0, 0], 2), None);
    }
}
