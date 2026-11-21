use std::time::{Duration, Instant};

use umbrawg_fec::{
    DecodedBlock, EncodedBlock, FecConfig, FecDecoder, FecEncoder, FecError, FecShard,
    MAX_PENDING_BLOCKS, MAX_SHARD_LEN,
};

const BLOCK_TIMEOUT: Duration = umbrawg_fec::DEFAULT_BLOCK_TIMEOUT;

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next_u64() % bound as u64) as usize
        }
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut output = vec![0u8; len];
        for chunk in output.chunks_mut(8) {
            let value = self.next_u64().to_le_bytes();
            let width = chunk.len();
            chunk.copy_from_slice(&value[..width]);
        }
        output
    }

    fn shuffle<T>(&mut self, items: &mut [T]) {
        for index in (1..items.len()).rev() {
            let other = self.below(index + 1);
            items.swap(index, other);
        }
    }
}

fn config(k: u8, m: u8) -> FecConfig {
    FecConfig::new(k, m).expect("valid config")
}

fn encode(config: FecConfig, max_shard_len: usize, packets: &[Vec<u8>]) -> Vec<EncodedBlock> {
    let mut encoder = FecEncoder::new(config, max_shard_len);
    let mut blocks = Vec::new();
    for packet in packets {
        if let Some(block) = encoder.push(packet).expect("packet fits") {
            blocks.push(block);
        }
    }
    if let Some(block) = encoder.flush() {
        blocks.push(block);
    }
    blocks
}

fn shards_of(block: &EncodedBlock) -> Vec<FecShard<'_>> {
    block
        .shards
        .iter()
        .enumerate()
        .map(|(index, payload)| FecShard {
            block_id: block.block_id,
            index: index as u8,
            k: block.k,
            m: block.m,
            shard_len: block.shard_len,
            payload,
        })
        .collect()
}

fn full_block_packets(k: u8, payload_len: usize) -> Vec<Vec<u8>> {
    (0..k)
        .map(|index| vec![index.wrapping_mul(17).wrapping_add(3); payload_len + usize::from(index)])
        .collect()
}

fn decode_with_erasures(
    config: FecConfig,
    block: &EncodedBlock,
    erased: &[usize],
) -> Vec<DecodedBlock> {
    let mut decoder = FecDecoder::new(config);
    let now = Instant::now();
    let mut output = Vec::new();
    for (index, shard) in shards_of(block).into_iter().enumerate() {
        if erased.contains(&index) {
            continue;
        }
        output.extend(decoder.push_at(shard, now).expect("valid shard"));
    }
    output.extend(decoder.poll(now + Duration::from_millis(20)));
    output
}

#[test]
fn roundtrip_without_loss() {
    for (k, m) in [
        (1, 1),
        (2, 1),
        (2, 2),
        (4, 2),
        (10, 3),
        (16, 4),
        (32, 8),
        (100, 10),
    ] {
        let config = config(k, m);
        let packets = full_block_packets(k, 200);
        let blocks = encode(config, 1500, &packets);
        assert_eq!(blocks.len(), 1, "k={k} m={m}");
        let block = &blocks[0];
        assert_eq!(block.shards.len(), usize::from(k + m));
        let decoded = decode_with_erasures(config, block, &[]);
        assert_eq!(decoded.len(), 1, "k={k} m={m}");
        assert_eq!(decoded[0].block_id, block.block_id);
        assert_eq!(decoded[0].recovered, 0, "k={k} m={m}");
        assert_eq!(decoded[0].packets, packets, "k={k} m={m}");
    }
}

#[test]
fn recovers_every_pattern_up_to_m_erasures_k4_m2() {
    check_all_erasure_patterns(4, 2);
}

#[test]
fn recovers_every_pattern_up_to_m_erasures_k10_m3() {
    check_all_erasure_patterns(10, 3);
}

fn check_all_erasure_patterns(k: u8, m: u8) {
    let config = config(k, m);
    let packets = full_block_packets(k, 24);
    let blocks = encode(config, 128, &packets);
    let block = &blocks[0];
    let total = usize::from(k + m);
    let mut checked = 0usize;
    for mask in 0u32..(1u32 << total) {
        if mask.count_ones() > u32::from(m) {
            continue;
        }
        let erased: Vec<usize> = (0..total)
            .filter(|index| mask & (1 << index) != 0)
            .collect();
        let decoded = decode_with_erasures(config, block, &erased);
        assert_eq!(decoded.len(), 1, "k={k} m={m} mask={mask:b}");
        let lost_data = erased
            .iter()
            .filter(|index| **index < usize::from(k))
            .count();
        assert_eq!(decoded[0].recovered, lost_data, "k={k} m={m} mask={mask:b}");
        assert_eq!(decoded[0].packets, packets, "k={k} m={m} mask={mask:b}");
        checked += 1;
    }
    let expected: usize = (0..=usize::from(m))
        .map(|erased| binomial(total, erased))
        .sum();
    assert_eq!(checked, expected, "k={k} m={m}");
}

fn binomial(n: usize, k: usize) -> usize {
    let mut result = 1usize;
    for index in 0..k {
        result = result * (n - index) / (index + 1);
    }
    result
}

#[test]
fn recovers_single_data_shard_for_k1_m1() {
    let config = config(1, 1);
    let packets = vec![vec![0xde, 0xad, 0xbe, 0xef]];
    let blocks = encode(config, 64, &packets);
    let decoded = decode_with_erasures(config, &blocks[0], &[0]);
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].recovered, 1);
    assert_eq!(decoded[0].packets, packets);
}

#[test]
fn partial_two_to_one_block_recovers_without_the_block_timeout() {
    // A sparse flow sends `k' = 1` with `m' = 1`. Losing the only data shard
    // must be repaired from the parity shard as soon as it arrives, with no
    // timer involved: the two-way RTT of a ping-sized flow must not include
    // (or wait for) the block timeout.
    let config = config(2, 1);
    let mut encoder = FecEncoder::new(config, 1500);
    assert!(encoder.push(&[0xab; 64]).unwrap().is_none());
    let block = encoder
        .flush_with_parity(1)
        .expect("partial block with parity");
    assert_eq!((block.k, block.m), (1, 1));

    let mut decoder = FecDecoder::new(config);
    let now = Instant::now();
    let shard = FecShard {
        block_id: block.block_id,
        index: 1,
        k: block.k,
        m: block.m,
        shard_len: block.shard_len,
        payload: &block.shards[1],
    };
    let decoded = decoder.push_at(shard, now).expect("valid shard");
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].recovered, 1);
    assert_eq!(decoded[0].packets, vec![vec![0xab; 64]]);
    assert_eq!(decoder.pending_blocks(), 0);
}

#[test]
fn default_block_timeout_is_generous_and_can_be_overridden() {
    let expected = Duration::from_millis(5);
    assert_eq!(umbrawg_fec::DEFAULT_BLOCK_TIMEOUT, expected);
    assert_eq!(FecDecoder::new(config(2, 1)).timeout(), expected);
    assert_eq!(
        FecDecoder::with_timeout(config(2, 1), Duration::from_millis(2)).timeout(),
        Duration::from_millis(2)
    );
    // The hard ceiling must be above the time a whole block needs on the
    // slowest supported link (8:2 of full-size shards at 10 Mbit/s ~ 11 ms).
    assert!(umbrawg_fec::MAX_BLOCK_HOLD >= Duration::from_millis(12));
    // Release of a block that cannot be completed must not wait longer than
    // the timeout, and must not happen before it either.
    let config = config(2, 1);
    let packets = full_block_packets(2, 16);
    let blocks = encode(config, 1500, &packets);
    let shards = shards_of(&blocks[0]);
    let mut decoder = FecDecoder::new(config);
    let now = Instant::now();
    assert!(decoder.push_at(shards[0], now).expect("valid").is_empty());
    assert!(decoder
        .poll(now + expected - Duration::from_micros(1))
        .is_empty());
    let released = decoder.poll(now + expected);
    assert_eq!(released.len(), 1);
    assert_eq!(released[0].packets, vec![packets[0].clone()]);
}

#[test]
fn slow_shard_stream_is_decoded_instead_of_cut_off() {
    // A 4:2 block spread over 5 ms (one shard per millisecond) is far longer
    // than the 2 ms stall timeout, but the deadline slides with every shard:
    // the block must be decoded, not finalized after the first two shards.
    let config = config(4, 2);
    let packets = full_block_packets(4, 24);
    let blocks = encode(config, 1500, &packets);
    let shards = shards_of(&blocks[0]);
    assert_eq!(shards.len(), 6);

    let mut decoder = FecDecoder::with_timeout(config, Duration::from_millis(2));
    let start = Instant::now();
    let mut output = Vec::new();
    for (index, shard) in shards.iter().enumerate() {
        let at = start + Duration::from_millis(u64::try_from(index).unwrap());
        output.extend(decoder.push_at(*shard, at).expect("valid shard"));
    }
    assert_eq!(decoder.pending_blocks(), 0);
    assert_eq!(output.len(), 1);
    assert_eq!(output[0].packets, packets);
    assert_eq!(output[0].recovered, 0);
}

#[test]
fn block_is_released_when_shard_progress_stops() {
    let config = config(4, 2);
    let packets = full_block_packets(4, 24);
    let blocks = encode(config, 1500, &packets);
    let shards = shards_of(&blocks[0]);

    let mut decoder = FecDecoder::with_timeout(config, Duration::from_millis(2));
    let start = Instant::now();
    assert!(decoder.push_at(shards[0], start).expect("valid").is_empty());
    assert!(decoder
        .push_at(shards[1], start + Duration::from_millis(1))
        .expect("valid")
        .is_empty());
    assert_eq!(decoder.pending_blocks(), 1);
    // The deadline is anchored to the last shard, not the first one.
    assert!(decoder.poll(start + Duration::from_millis(2)).is_empty());
    let released = decoder.poll(start + Duration::from_millis(3));
    assert_eq!(released.len(), 1);
    assert_eq!(
        released[0].packets,
        vec![packets[0].clone(), packets[1].clone()]
    );
    assert_eq!(released[0].recovered, 0);
}

#[test]
fn shard_trickle_is_capped_by_max_block_hold() {
    // 8:2 needs 8 data shards. A shard every 3 ms keeps sliding the 2 ms
    // deadline, so the hard ceiling from the first shard is what has to end
    // the block; without it the trickle could hold the in-order queue open
    // forever.
    let config = config(8, 2);
    let packets = full_block_packets(8, 24);
    let blocks = encode(config, 1500, &packets);
    let shards = shards_of(&blocks[0]);
    assert_eq!(shards.len(), 10);

    let mut decoder = FecDecoder::with_timeout(config, Duration::from_millis(2));
    let start = Instant::now();
    let mut output = Vec::new();
    for (index, shard) in shards.iter().enumerate().take(7) {
        let at = start + Duration::from_millis(3 * u64::try_from(index).unwrap());
        output.extend(decoder.push_at(*shard, at).expect("valid shard"));
    }
    assert!(
        output.is_empty(),
        "seven of eight data shards are not enough"
    );
    assert_eq!(decoder.pending_blocks(), 1);

    let hold = umbrawg_fec::MAX_BLOCK_HOLD;
    assert!(decoder
        .poll(start + hold - Duration::from_millis(1))
        .is_empty());
    let released = decoder.poll(start + hold);
    assert_eq!(released.len(), 1);
    assert_eq!(released[0].packets, packets[..7].to_vec());
    // A shard past the ceiling is late: the block has been released.
    assert!(decoder
        .push_at(shards[7], start + hold + Duration::from_millis(1))
        .expect("valid shard")
        .is_empty());
    assert_eq!(decoder.pending_blocks(), 0);
}

#[test]
fn shards_have_length_prefix_and_zero_padding() {
    let config = config(3, 1);
    let mut encoder = FecEncoder::new(config, 32);
    assert!(encoder.push(&[9, 8, 7]).unwrap().is_none());
    assert!(encoder.push(&[6]).unwrap().is_none());
    let block = encoder.push(&[]).unwrap().expect("block");
    assert_eq!(block.shard_len, 5);
    assert_eq!(block.shards[0], vec![3, 0, 9, 8, 7]);
    assert_eq!(block.shards[1], vec![1, 0, 6, 0, 0]);
    assert_eq!(block.shards[2], vec![0, 0, 0, 0, 0]);
    assert_eq!(block.shards.len(), 4);
    let decoded = decode_with_erasures(config, &block, &[]);
    assert_eq!(decoded[0].packets, vec![vec![9, 8, 7], vec![6], Vec::new()]);
}

#[test]
fn random_packets_and_sizes_roundtrip() {
    let mut rng = Rng::new(0x1234_5678_9abc_def0);
    for _ in 0..200 {
        let k = 1 + rng.below(16) as u8;
        let m = 1 + rng.below(6) as u8;
        let config = config(k, m);
        let max_shard_len = 2 + rng.below(400);
        let mut packets = Vec::new();
        for _ in 0..k {
            let len = rng.below(max_shard_len - 1);
            packets.push(rng.bytes(len));
        }
        let blocks = encode(config, max_shard_len, &packets);
        assert_eq!(blocks.len(), 1);
        let block = &blocks[0];
        let total = usize::from(k + m);
        let mut order: Vec<usize> = (0..total).collect();
        rng.shuffle(&mut order);
        let mut decoder = FecDecoder::new(config);
        let now = Instant::now();
        let mut output = Vec::new();
        for index in order {
            output.extend(
                decoder
                    .push_at(shards_of(block)[index], now)
                    .expect("valid shard"),
            );
        }
        output.extend(decoder.poll(now + Duration::from_millis(20)));
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].packets, packets);
    }
}

#[test]
fn partial_flush_produces_data_only_block() {
    let config = config(4, 2);
    let mut encoder = FecEncoder::new(config, 1500);
    assert_eq!(encoder.block_id(), 0);
    assert!(encoder.push(&[1u8; 30]).unwrap().is_none());
    assert!(encoder.push(&[2u8; 10]).unwrap().is_none());
    let block = encoder.flush().expect("partial block");
    assert_eq!(block.block_id, 0);
    assert_eq!(block.k, 2);
    assert_eq!(block.m, 0);
    assert_eq!(block.shard_len, 32);
    assert_eq!(block.shards.len(), 2);
    assert_eq!(encoder.block_id(), 1);
    assert!(encoder.flush().is_none());

    let mut decoder = FecDecoder::new(config);
    let now = Instant::now();
    let mut output = Vec::new();
    for shard in shards_of(&block) {
        output.extend(decoder.push_at(shard, now).expect("valid shard"));
    }
    assert_eq!(output.len(), 1);
    assert_eq!(output[0].packets, vec![vec![1u8; 30], vec![2u8; 10]]);
    let _ = BLOCK_TIMEOUT;
    assert_eq!(output[0].packets, vec![vec![1u8; 30], vec![2u8; 10]]);
}

#[test]
fn timeout_returns_received_data_shards_without_recovery() {
    let config = config(4, 2);
    let packets = full_block_packets(4, 20);
    let blocks = encode(config, 1500, &packets);
    let block = &blocks[0];
    let shards = shards_of(block);

    let mut decoder = FecDecoder::new(config);
    let now = Instant::now();
    let mut output = Vec::new();
    output.extend(decoder.push_at(shards[0], now).expect("valid shard"));
    output.extend(decoder.push_at(shards[2], now).expect("valid shard"));
    output.extend(decoder.push_at(shards[4], now).expect("valid shard"));
    assert!(output.is_empty());
    assert!(decoder.poll(now + BLOCK_TIMEOUT / 2).is_empty());
    let released = decoder.poll(now + BLOCK_TIMEOUT * 2);
    assert_eq!(released.len(), 1);
    assert_eq!(
        released[0].packets,
        vec![packets[0].clone(), packets[2].clone()]
    );
    assert!(decoder.poll(now + BLOCK_TIMEOUT * 4).is_empty());
}

#[test]
fn block_after_gap_waits_for_timeout() {
    let config = config(4, 2);
    let packets = (0..12u8)
        .map(|index| vec![index; 16 + usize::from(index)])
        .collect::<Vec<_>>();
    let blocks = encode(config, 1500, &packets);
    assert_eq!(blocks.len(), 3);

    let mut decoder = FecDecoder::new(config);
    let now = Instant::now();
    let first_shard = shards_of(&blocks[0])[0];
    assert!(decoder
        .push_at(first_shard, now)
        .expect("valid shard")
        .is_empty());
    for shard in shards_of(&blocks[2]) {
        assert!(decoder.push_at(shard, now).expect("valid shard").is_empty());
    }
    assert!(decoder.poll(now + BLOCK_TIMEOUT / 2).is_empty());
    let released = decoder.poll(now + BLOCK_TIMEOUT * 2);
    assert_eq!(released.len(), 2);
    assert_eq!(released[0].block_id, blocks[0].block_id);
    assert_eq!(released[0].packets, vec![packets[0].clone()]);
    assert_eq!(released[1].block_id, blocks[2].block_id);
    assert_eq!(released[1].packets, packets[8..12].to_vec());
}

#[test]
fn consecutive_gaps_release_within_one_timeout() {
    let config = config(2, 1);
    let packets = (0..8u8)
        .map(|index| vec![index; 10 + usize::from(index)])
        .collect::<Vec<_>>();
    let blocks = encode(config, 1500, &packets);
    assert_eq!(blocks.len(), 4);

    let mut decoder = FecDecoder::new(config);
    let now = Instant::now();
    assert!(decoder
        .push_at(shards_of(&blocks[0])[0], now)
        .expect("valid shard")
        .is_empty());
    for block in [&blocks[1], &blocks[3]] {
        for shard in shards_of(block) {
            assert!(decoder.push_at(shard, now).expect("valid shard").is_empty());
        }
    }
    assert!(decoder.poll(now + BLOCK_TIMEOUT / 2).is_empty());
    let released = decoder.poll(now + BLOCK_TIMEOUT * 2);
    let ids: Vec<u32> = released.iter().map(|block| block.block_id).collect();
    assert_eq!(ids, vec![0, 1, 3]);
    assert_eq!(released[0].packets, vec![packets[0].clone()]);
    assert_eq!(released[1].packets, packets[2..4].to_vec());
    assert_eq!(released[2].packets, packets[6..8].to_vec());
    assert!(decoder.poll(now + BLOCK_TIMEOUT * 4).is_empty());
}

#[test]
fn releases_blocks_in_order_and_packets_by_index() {
    let config = config(3, 2);
    let packets = (0..9u8)
        .map(|index| vec![index; 12 + usize::from(index)])
        .collect::<Vec<_>>();
    let blocks = encode(config, 1500, &packets);
    assert_eq!(blocks.len(), 3);

    let mut decoder = FecDecoder::new(config);
    let now = Instant::now();
    let mut output = Vec::new();
    let first = shards_of(&blocks[0]);
    let second = shards_of(&blocks[2]);
    let third = shards_of(&blocks[1]);
    output.extend(decoder.push_at(first[1], now).expect("valid shard"));
    assert!(output.is_empty());
    for shard in second.into_iter().chain(third) {
        output.extend(decoder.push_at(shard, now).expect("valid shard"));
    }
    assert!(output.is_empty());
    for shard in first.into_iter().filter(|shard| shard.index != 1) {
        output.extend(decoder.push_at(shard, now).expect("valid shard"));
    }
    let ids: Vec<u32> = output.iter().map(|block| block.block_id).collect();
    assert_eq!(ids, vec![0, 1, 2]);
    let actual: Vec<Vec<u8>> = output.into_iter().flat_map(|block| block.packets).collect();
    assert_eq!(actual, packets);
}

#[test]
fn block_ids_may_wrap_around() {
    let config = config(2, 1);
    let mut encoder = FecEncoder::new(config, 64);
    let mut blocks = Vec::new();
    for _ in 0..2 {
        assert!(encoder.push(&[1, 2, 3]).unwrap().is_none());
        blocks.push(encoder.push(&[4, 5]).unwrap().expect("block"));
    }
    let ids = [u32::MAX - 1, u32::MAX];
    for (block, id) in blocks.iter_mut().zip(ids) {
        block.block_id = id;
    }

    let mut decoder = FecDecoder::new(config);
    let now = Instant::now();
    let mut output = Vec::new();
    for block in &blocks {
        for shard in shards_of(block) {
            output.extend(decoder.push_at(shard, now).expect("valid shard"));
        }
    }
    assert_eq!(output.len(), 2);
    assert_eq!(output[0].block_id, u32::MAX - 1);
    assert_eq!(output[1].block_id, u32::MAX);

    let mut wrapping = FecDecoder::new(config);
    let mut last = blocks[1].clone();
    last.block_id = u32::MAX;
    let mut first = blocks[0].clone();
    first.block_id = 0;
    let wrap_blocks = [last, first];
    let mut wrap_output = Vec::new();
    for block in &wrap_blocks {
        for shard in shards_of(block) {
            wrap_output.extend(wrapping.push_at(shard, now).expect("valid shard"));
        }
    }
    assert_eq!(wrap_output.len(), 2);
    assert_eq!(wrap_output[0].block_id, u32::MAX);
    assert_eq!(wrap_output[1].block_id, 0);
}

#[test]
fn duplicate_and_reordered_shards_are_accepted() {
    let config = config(3, 2);
    let packets = full_block_packets(3, 30);
    let blocks = encode(config, 1500, &packets);
    let shards = shards_of(&blocks[0]);
    let mut decoder = FecDecoder::new(config);
    let now = Instant::now();
    let mut output = Vec::new();
    output.extend(decoder.push_at(shards[3], now).expect("valid shard"));
    output.extend(decoder.push_at(shards[3], now).expect("valid shard"));
    output.extend(decoder.push_at(shards[1], now).expect("valid shard"));
    output.extend(decoder.push_at(shards[0], now).expect("valid shard"));
    assert_eq!(output.len(), 1);
    assert_eq!(output[0].packets, packets);
}

#[test]
fn packet_too_large_is_rejected() {
    let config = config(2, 1);
    let mut encoder = FecEncoder::new(config, 10);
    assert_eq!(
        encoder.push(&[0u8; 9]),
        Err(FecError::PacketTooLarge {
            packet_len: 9,
            max_shard_len: 10
        })
    );
    assert_eq!(encoder.pending(), 0);
    assert!(encoder.push(&[0u8; 8]).unwrap().is_none());
    assert_eq!(
        encoder.push(&[0u8; 8]).unwrap().map(|b| b.shard_len),
        Some(10)
    );
}

#[test]
fn invalid_configurations_are_rejected() {
    assert_eq!(FecConfig::new(0, 1), Err(FecError::ZeroDataShards));
    assert_eq!(FecConfig::new(1, 0), Err(FecError::ZeroParityShards));
    assert!(matches!(
        FecConfig::new(200, 100),
        Err(FecError::TooManyShards { .. })
    ));
    assert!(matches!(
        FecConfig::new(255, 255),
        Err(FecError::TooManyShards { .. })
    ));
    assert_eq!(FecConfig::new(255, 0), Err(FecError::ZeroParityShards));
}

#[test]
fn invalid_shards_are_rejected() {
    let config = config(3, 2);
    let packets = full_block_packets(3, 20);
    let blocks = encode(config, 1500, &packets);
    let shards = shards_of(&blocks[0]);

    let mut decoder = FecDecoder::new(config);
    let now = Instant::now();

    let wrong_k = FecShard { k: 4, ..shards[0] };
    assert!(matches!(
        decoder.push_at(wrong_k, now),
        Err(FecError::ConfigMismatch { .. })
    ));

    let wrong_m = FecShard { m: 5, ..shards[0] };
    assert!(matches!(
        decoder.push_at(wrong_m, now),
        Err(FecError::ConfigMismatch { .. })
    ));

    let bad_index = FecShard {
        index: 5,
        ..shards[0]
    };
    assert!(matches!(
        decoder.push_at(bad_index, now),
        Err(FecError::InvalidIndex { .. })
    ));

    let short_len = FecShard {
        shard_len: 1,
        ..shards[0]
    };
    assert!(matches!(
        decoder.push_at(short_len, now),
        Err(FecError::InvalidShardLen { .. })
    ));

    let mismatched_payload = FecShard {
        payload: &shards[0].payload[..shards[0].payload.len() - 1],
        ..shards[0]
    };
    assert!(matches!(
        decoder.push_at(mismatched_payload, now),
        Err(FecError::PayloadLenMismatch { .. })
    ));

    let mut greedy = shards[0].payload.to_vec();
    greedy[0] = 0xff;
    greedy[1] = 0xff;
    let bad_packet_len = FecShard {
        payload: &greedy,
        ..shards[0]
    };
    assert!(matches!(
        decoder.push_at(bad_packet_len, now),
        Err(FecError::InvalidPacketLen { .. })
    ));

    assert_eq!(decoder.pending_blocks(), 0);

    let mut other = FecDecoder::new(config);
    other.push_at(shards[0], now).expect("valid shard");
    let longer_payload = vec![0u8; usize::from(shards[0].shard_len) + 1];
    let different_len = FecShard {
        shard_len: shards[0].shard_len + 1,
        payload: &longer_payload,
        ..shards[1]
    };
    assert!(matches!(
        other.push_at(different_len, now),
        Err(FecError::ShardLenMismatch { .. })
    ));
}

#[test]
fn accepts_any_valid_configuration_and_shard_layout() {
    let config = config(254, 1);
    let packets: Vec<Vec<u8>> = (0..254u16)
        .map(|value| value.to_le_bytes().to_vec())
        .collect();
    let blocks = encode(config, 4, &packets);
    assert_eq!(blocks[0].shards.len(), 255);
    let erased = [7usize];
    let decoded = decode_with_erasures(config, &blocks[0], &erased);
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].packets, packets);
}

#[test]
fn unchecked_configs_return_errors_instead_of_panicking() {
    let no_data = FecConfig {
        data_shards: 0,
        parity_shards: 1,
    };
    let mut encoder = FecEncoder::new(no_data, 1500);
    assert_eq!(encoder.push(&[1, 2, 3]), Err(FecError::ZeroDataShards));
    assert!(encoder.flush().is_none());

    let mut decoder = FecDecoder::new(no_data);
    let payload = [0u8; 4];
    let shard = FecShard {
        block_id: 0,
        index: 0,
        k: 0,
        m: 1,
        shard_len: 4,
        payload: &payload,
    };
    let now = Instant::now();
    assert_eq!(decoder.push_at(shard, now), Err(FecError::ZeroDataShards));
    assert!(decoder.poll(now).is_empty());

    let too_wide = FecConfig {
        data_shards: 255,
        parity_shards: 255,
    };
    let mut encoder = FecEncoder::new(too_wide, 1500);
    assert!(matches!(
        encoder.push(&[1, 2]),
        Err(FecError::TooManyShards { .. })
    ));

    let no_parity = FecConfig {
        data_shards: 2,
        parity_shards: 0,
    };
    let mut encoder = FecEncoder::new(no_parity, 1500);
    assert_eq!(encoder.push(&[1, 2]), Err(FecError::ZeroParityShards));
}

#[test]
fn fuzz_like_random_scenarios_are_consistent() {
    let mut rng = Rng::new(0xfeed_face_cafe_beef);
    for iteration in 0..1000 {
        let k = 1 + rng.below(8) as u8;
        let m = 1 + rng.below(4) as u8;
        let config = config(k, m);
        let max_shard_len = 2 + rng.below(180);
        let mut packets = Vec::new();
        for _ in 0..k {
            let len = rng.below(max_shard_len - 1);
            packets.push(rng.bytes(len));
        }
        let blocks = encode(config, max_shard_len, &packets);
        assert_eq!(blocks.len(), 1, "iteration {iteration}");
        let block = &blocks[0];
        let total = usize::from(k + m);
        let mut indices: Vec<usize> = (0..total).collect();
        rng.shuffle(&mut indices);
        let erasure_count = rng.below(usize::from(m) + 1);
        let erased: Vec<usize> = indices[..erasure_count].to_vec();
        let mut order: Vec<usize> = (0..total).collect();
        rng.shuffle(&mut order);

        let mut decoder = FecDecoder::new(config);
        let now = Instant::now();
        let mut output = Vec::new();
        for index in order {
            if erased.contains(&index) {
                continue;
            }
            output.extend(
                decoder
                    .push_at(shards_of(block)[index], now)
                    .expect("valid shard"),
            );
        }
        output.extend(decoder.poll(now + Duration::from_millis(20)));
        assert_eq!(output.len(), 1, "iteration {iteration}");
        assert_eq!(output[0].packets, packets, "iteration {iteration}");
    }
}

#[test]
fn conflicting_k_within_one_block_is_rejected() {
    let config = config(4, 2);
    let mut decoder = FecDecoder::new(config);
    let now = Instant::now();

    let head_payload = [1u8, 0, 7, 0, 0, 0, 0, 0];
    let head = FecShard {
        block_id: 0,
        index: 0,
        k: 4,
        m: 2,
        shard_len: 8,
        payload: &head_payload,
    };
    assert!(decoder.push_at(head, now).expect("valid shard").is_empty());

    let first_payload = [4u8, 0, 1, 2, 3, 0, 0, 0];
    let first = FecShard {
        block_id: 7,
        index: 0,
        k: 2,
        m: 0,
        shard_len: 8,
        payload: &first_payload,
    };
    assert!(decoder.push_at(first, now).expect("valid shard").is_empty());

    let conflicting_payload = [1u8, 0, 9, 0, 0, 0, 0, 0];
    let conflicting = FecShard {
        block_id: 7,
        index: 3,
        k: 4,
        m: 0,
        shard_len: 8,
        payload: &conflicting_payload,
    };
    assert_eq!(
        decoder.push_at(conflicting, now),
        Err(FecError::ConfigMismatch {
            expected_k: 2,
            expected_m: 0,
            actual_k: 4,
            actual_m: 0,
        })
    );
    assert_eq!(decoder.pending_blocks(), 2);

    let second_payload = [1u8, 0, 5, 0, 0, 0, 0, 0];
    let second = FecShard {
        block_id: 7,
        index: 1,
        k: 2,
        m: 0,
        shard_len: 8,
        payload: &second_payload,
    };
    assert!(decoder
        .push_at(second, now)
        .expect("valid shard")
        .is_empty());

    let released = decoder.poll(now + BLOCK_TIMEOUT * 2);
    assert_eq!(released.len(), 2);
    assert_eq!(released[0].block_id, 0);
    assert_eq!(released[0].packets, vec![vec![7]]);
    assert_eq!(released[1].block_id, 7);
    assert_eq!(released[1].packets, vec![vec![1, 2, 3, 0], vec![5]]);
    assert_eq!(decoder.pending_blocks(), 0);
}

#[test]
fn shard_len_above_limit_is_rejected() {
    let config = config(2, 1);
    let mut decoder = FecDecoder::new(config);
    let now = Instant::now();

    let oversized = vec![0u8; usize::from(MAX_SHARD_LEN) + 1];
    let shard = FecShard {
        block_id: 0,
        index: 0,
        k: 2,
        m: 1,
        shard_len: MAX_SHARD_LEN + 1,
        payload: &oversized,
    };
    assert_eq!(
        decoder.push_at(shard, now),
        Err(FecError::ShardLenTooLarge {
            shard_len: MAX_SHARD_LEN + 1,
            max_shard_len: MAX_SHARD_LEN,
        })
    );
    assert_eq!(decoder.pending_blocks(), 0);

    let boundary = vec![0u8; usize::from(MAX_SHARD_LEN)];
    let accepted = FecShard {
        block_id: 0,
        index: 0,
        k: 2,
        m: 1,
        shard_len: MAX_SHARD_LEN,
        payload: &boundary,
    };
    assert!(decoder
        .push_at(accepted, now)
        .expect("boundary length is accepted")
        .is_empty());
    assert_eq!(decoder.pending_blocks(), 1);
}

#[test]
fn pending_blocks_are_bounded_and_oldest_is_evicted() {
    let config = config(4, 2);
    let mut decoder = FecDecoder::new(config);
    let now = Instant::now();
    let payload = [0u8, 0, 0xaa, 0, 0, 0, 0, 0];
    let overflow = 8u32;
    let total = MAX_PENDING_BLOCKS as u32 + overflow;
    let mut output = Vec::new();

    for block_id in 0..total {
        let shard = FecShard {
            block_id,
            index: 0,
            k: 4,
            m: 2,
            shard_len: 8,
            payload: &payload,
        };
        output.extend(decoder.push_at(shard, now).expect("valid shard"));
        assert!(
            decoder.pending_blocks() <= MAX_PENDING_BLOCKS,
            "block {block_id} grew the decoder past the cap"
        );
    }

    let evicted: Vec<u32> = output.iter().map(|block| block.block_id).collect();
    assert_eq!(evicted, (0..overflow).collect::<Vec<_>>());
    assert_eq!(decoder.pending_blocks(), MAX_PENDING_BLOCKS);

    output.extend(decoder.poll(now + BLOCK_TIMEOUT * 2));
    assert_eq!(decoder.pending_blocks(), 0);
    let ids: Vec<u32> = output.iter().map(|block| block.block_id).collect();
    assert_eq!(ids, (0..total).collect::<Vec<_>>());
}

#[test]
fn garbage_shards_never_panic() {
    let mut rng = Rng::new(0x0bad_c0de_1234_5678);
    for _ in 0..1000 {
        let k = 1 + rng.below(6) as u8;
        let m = 1 + rng.below(3) as u8;
        let config = config(k, m);
        let mut decoder = FecDecoder::new(config);
        let mut now = Instant::now();
        for _ in 0..12 {
            let shard_len = rng.below(48) as u16;
            let mut payload = vec![0u8; usize::from(shard_len)];
            for byte in &mut payload {
                *byte = rng.next_u64() as u8;
            }
            let shard = FecShard {
                block_id: rng.next_u64() as u32 % 16,
                index: rng.below(16) as u8,
                k,
                m,
                shard_len,
                payload: &payload,
            };
            let _ = decoder.push_at(shard, now);
            now += Duration::from_micros(700);
            for block in decoder.poll(now) {
                assert!(block.packets.iter().all(|packet| packet.len() <= 65_533));
            }
        }
        for block in decoder.poll(now + Duration::from_millis(10)) {
            assert!(!block.packets.is_empty());
        }
    }
}
