//! TUN GSO split feeding FEC: a super-packet from the TUN device must become
//! independent full-size IP packets before FEC and encryption.
//!
//! The daemon reads the TUN queue with `Tun::read_batch_sizes`, which splits a
//! GSO packet on `gso_size` boundaries and completes the checksums. This test
//! drives the same pieces without a TUN device: split a TCP super-packet,
//! encode every segment as a data shard of a `2:1` block, lose one data shard
//! per block, and require the decoder to return the original segments in
//! order.

use std::time::{Duration, Instant};

use umbrawg_fec::{FecConfig, FecDecoder, FecEncoder, FecShard};
use umbrawg_tun::{split_gso, VirtioNetHdr, VIRTIO_NET_HDR_F_NEEDS_CSUM, VIRTIO_NET_HDR_GSO_TCPV4};

const IP_HEADER_LEN: usize = 20;
const TCP_HEADER_LEN: usize = 20;
const GSO_SIZE: usize = 1312;
const MAX_SHARD_LEN: usize = 1385;
const PAYLOAD_LEN: usize = 3000;

fn checksum(data: &[u8], mut sum: u64) -> u16 {
    let (chunks, remainder) = data.as_chunks::<2>();
    for chunk in chunks {
        sum += u64::from(u16::from_be_bytes(*chunk));
    }
    if let [tail] = remainder {
        sum += u64::from(*tail) << 8;
    }
    while sum > u64::from(u16::MAX) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16
}

/// Builds a TCP-over-IPv4 super-packet as the TUN stack would hand it over.
///
/// Both checksums are left at zero: the splitter zeroes and recomputes every
/// per-segment checksum, so a valid one is not required on the input.
fn gso_tcp4(payload: &[u8], seq: u32) -> Vec<u8> {
    let total_len = IP_HEADER_LEN + TCP_HEADER_LEN + payload.len();
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
    packet[6] = 0x40;
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
    packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
    packet[20..22].copy_from_slice(&1234u16.to_be_bytes());
    packet[22..24].copy_from_slice(&80u16.to_be_bytes());
    packet[24..28].copy_from_slice(&seq.to_be_bytes());
    packet[28..32].copy_from_slice(&1u32.to_be_bytes());
    packet[32] = 0x50;
    packet[IP_HEADER_LEN + 13] = 0x18;
    packet[34..36].copy_from_slice(&65535u16.to_be_bytes());
    packet[IP_HEADER_LEN + TCP_HEADER_LEN..].copy_from_slice(payload);
    packet
}

fn assert_valid_tcp4_checksum(segment: &[u8]) {
    let mut pseudo = u64::from(6u16) + u64::from((segment.len() - IP_HEADER_LEN) as u16);
    pseudo += u64::from(u16::from_be_bytes([segment[12], segment[13]]));
    pseudo += u64::from(u16::from_be_bytes([segment[14], segment[15]]));
    pseudo += u64::from(u16::from_be_bytes([segment[16], segment[17]]));
    pseudo += u64::from(u16::from_be_bytes([segment[18], segment[19]]));
    assert_eq!(checksum(&segment[IP_HEADER_LEN..], pseudo), 0xFFFF);
}

#[test]
fn gso_super_packet_is_split_before_fec_and_recovered_in_order() {
    let payload: Vec<u8> = (0..PAYLOAD_LEN).map(|value| (value % 251) as u8).collect();
    let super_packet = gso_tcp4(&payload, 10_000);
    let mut header = VirtioNetHdr {
        flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
        gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
        hdr_len: 0,
        gso_size: GSO_SIZE as u16,
        csum_start: IP_HEADER_LEN as u16,
        csum_offset: 16,
        num_buffers: 0,
    };
    let segment_cap = IP_HEADER_LEN + TCP_HEADER_LEN + GSO_SIZE;
    assert_eq!(segment_cap, 1352, "full TUN MTU under the FEC budget");
    let mut sizes = Vec::new();
    let mut remaining = PAYLOAD_LEN;
    while remaining > 0 {
        let body = remaining.min(GSO_SIZE);
        sizes.push(IP_HEADER_LEN + TCP_HEADER_LEN + body);
        remaining -= body;
    }
    let mut buffers: Vec<Vec<u8>> = sizes.iter().map(|_| vec![0u8; segment_cap]).collect();
    let mut slices: Vec<&mut [u8]> = buffers.iter_mut().map(Vec::as_mut_slice).collect();

    let count = split_gso(&super_packet, &mut header, &mut slices).expect("GSO split");
    assert_eq!(count, sizes.len(), "3000 payload bytes at 1312 per segment");
    let mut segments: Vec<Vec<u8>> = Vec::with_capacity(count);
    for (index, expected) in sizes.iter().enumerate() {
        let segment = &slices[index][..*expected];
        assert_eq!(
            usize::from(u16::from_be_bytes([segment[2], segment[3]])),
            *expected,
            "each segment is its own IP packet"
        );
        assert!(
            segment.len() + 2 <= MAX_SHARD_LEN,
            "a full-size segment must fit the FEC shard budget"
        );
        assert_valid_tcp4_checksum(segment);
        segments.push(segment.to_vec());
    }

    let mut encoder =
        FecEncoder::with_block_id(FecConfig::new(2, 1).expect("2:1 profile"), MAX_SHARD_LEN, 9);
    let mut blocks = Vec::new();
    for segment in &segments {
        if let Some(block) = encoder
            .push(segment)
            .expect("a full-size IP packet must be encodable as a data shard")
        {
            blocks.push(block);
        }
    }
    if let Some(block) = encoder.flush_with_parity(1) {
        blocks.push(block);
    }
    assert_eq!(blocks.len(), 2);
    assert_eq!((blocks[0].k, blocks[0].m), (2, 1));
    assert_eq!((blocks[1].k, blocks[1].m), (1, 1));
    assert!(
        usize::from(blocks[0].shard_len) >= segment_cap + 2,
        "shards carry the whole full-size packet plus its length prefix"
    );

    let mut decoder = FecDecoder::with_timeout(
        FecConfig::new(2, 1).expect("2:1 profile"),
        Duration::from_secs(5),
    );
    let now = Instant::now();
    let mut recovered = Vec::new();
    for block in &blocks {
        // Lose the first data shard of every block: parity must restore it.
        for index in 1..block.shards.len() {
            let decoded = decoder
                .push_at(
                    FecShard {
                        block_id: block.block_id,
                        index: index as u8,
                        k: block.k,
                        m: block.m,
                        shard_len: block.shard_len,
                        payload: &block.shards[index],
                    },
                    now,
                )
                .expect("shard decodes");
            for block in decoded {
                recovered.extend(block.packets);
            }
        }
    }
    assert_eq!(
        recovered, segments,
        "segments must reach the FEC decoder in TUN order"
    );
}
