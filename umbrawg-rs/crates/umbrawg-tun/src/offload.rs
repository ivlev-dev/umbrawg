//! GSO packet handling, checksums, and buffer sizing helpers.

use crate::virtio::{GsoType, VirtioNetHdr, VIRTIO_NET_HDR_GSO_ECN, VIRTIO_NET_HDR_GSO_NONE};

/// Maximum size of an IP packet that a TUN device can carry.
pub const MAX_PACKET_SIZE: usize = 65_535;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

const IPV4_SRC_ADDR_OFFSET: usize = 12;
const IPV6_SRC_ADDR_OFFSET: usize = 8;

const TCP_FLAGS_OFFSET: usize = 13;
const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_PSH: u8 = 0x08;

const UDP_HEADER_LEN: u16 = 8;

/// Errors produced while validating or splitting GSO packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GsoError {
    /// An output buffer cannot hold a segment.
    #[error("GSO segment buffer too small: need {needed} bytes, have {available}")]
    BufferTooSmall {
        /// Required buffer length.
        needed: usize,
        /// Available buffer length.
        available: usize,
    },
    /// Not enough output buffers were supplied for all segments.
    #[error("too many GSO segments: need {needed} buffers, have {available}")]
    TooManySegments {
        /// Number of segments the packet splits into.
        needed: usize,
        /// Number of output buffers supplied.
        available: usize,
    },
    /// The packet is shorter than one of its declared headers.
    #[error("GSO packet is too short: {0}")]
    PacketTooShort(&'static str),
    /// The packet is malformed.
    #[error("invalid GSO packet: {0}")]
    Invalid(&'static str),
    /// The segmentation offload type is not supported.
    #[error("unsupported GSO type {0}")]
    UnsupportedGsoType(u8),
    /// The segment size is zero or otherwise unusable.
    #[error("invalid GSO segment size {0}")]
    InvalidSegmentSize(u16),
    /// A split was requested for a packet without segmentation offload.
    #[error("GSO split requested for a non-GSO packet")]
    NotGso,
}

/// Returns the size of the raw read buffer required for one GSO read.
pub const fn read_buffer_size(vnet_hdr_len: usize) -> usize {
    MAX_PACKET_SIZE + vnet_hdr_len
}

/// Returns the size of a buffer that holds one packet plus a virtio header.
pub const fn packet_buffer_size(mtu: u32, vnet_hdr_len: usize) -> usize {
    mtu as usize + vnet_hdr_len
}

/// Returns the largest segment payload that fits into `mtu` bytes.
pub fn max_gso_size(mtu: u16, header_len: u16) -> u16 {
    mtu.saturating_sub(header_len)
}

/// Returns the number of GSO segments a packet of `input_len` bytes splits into.
///
/// `input_len` includes IP and transport headers. Returns zero when the packet
/// has no payload or when `gso_size` is zero.
pub fn gso_segment_count(input_len: usize, hdr_len: u16, gso_size: u16) -> usize {
    let hdr_len = hdr_len as usize;
    let gso_size = gso_size as usize;
    if gso_size == 0 || input_len <= hdr_len {
        return 0;
    }
    (input_len - hdr_len).div_ceil(gso_size)
}

/// Returns the maximum number of segments that fit into a packet of `mtu` bytes.
pub fn max_gso_segments(mtu: u16, hdr_len: u16, gso_size: u16) -> usize {
    gso_segment_count(mtu as usize, hdr_len, gso_size)
}

/// Returns the wire length of segment `index` for a packet of `input_len` bytes.
///
/// The header must already be normalized with [`prepare_gso`].
pub fn gso_segment_len(input_len: usize, hdr: &VirtioNetHdr, index: usize) -> Option<usize> {
    let hdr_len = hdr.hdr_len as usize;
    let gso_size = hdr.gso_size as usize;
    if gso_size == 0 || input_len <= hdr_len {
        return None;
    }
    let start = hdr_len.checked_add(index.checked_mul(gso_size)?)?;
    if start >= input_len {
        return None;
    }
    Some(hdr_len + (input_len - start).min(gso_size))
}

/// Validates a GSO header against `input` and normalizes `hdr_len`.
///
/// For TCP, the transport header length is recomputed from the TCP data offset
/// because the kernel may report the length of a whole forwarded packet. For
/// UDP segmentation offload, `hdr_len` is `csum_start + 8`.
pub fn prepare_gso(input: &[u8], hdr: &mut VirtioNetHdr) -> Result<(), GsoError> {
    if input.is_empty() {
        return Err(GsoError::PacketTooShort("empty IP packet"));
    }
    if input.len() > MAX_PACKET_SIZE {
        return Err(GsoError::Invalid("packet exceeds 65535 bytes"));
    }

    let raw_gso_type = hdr.gso_type;
    if raw_gso_type & !VIRTIO_NET_HDR_GSO_ECN == VIRTIO_NET_HDR_GSO_NONE {
        if raw_gso_type == VIRTIO_NET_HDR_GSO_NONE {
            return Ok(());
        }
        return Err(GsoError::UnsupportedGsoType(raw_gso_type));
    }
    if hdr.gso_size == 0 {
        return Err(GsoError::InvalidSegmentSize(0));
    }

    let kind = GsoType::from_u8(raw_gso_type).ok_or(GsoError::UnsupportedGsoType(raw_gso_type))?;
    let version = input[0] >> 4;
    if version != 4 && version != 6 {
        return Err(GsoError::Invalid("invalid IP version"));
    }
    match kind {
        GsoType::TcpV4 if version != 4 => {
            return Err(GsoError::Invalid("GSO type TCPv4 with a non-IPv4 packet"));
        }
        GsoType::TcpV6 if version != 6 => {
            return Err(GsoError::Invalid("GSO type TCPv6 with a non-IPv6 packet"));
        }
        GsoType::Udp => return Err(GsoError::UnsupportedGsoType(raw_gso_type)),
        _ => {}
    }

    let ip_header_len = hdr.csum_start as usize;
    let minimum_ip_header_len = if version == 4 { 20 } else { 40 };
    if ip_header_len < minimum_ip_header_len {
        return Err(GsoError::Invalid("checksum start precedes the IP header"));
    }

    match kind {
        GsoType::UdpL4 => {
            hdr.hdr_len = hdr
                .csum_start
                .checked_add(UDP_HEADER_LEN)
                .ok_or(GsoError::Invalid("GSO header length overflow"))?;
        }
        GsoType::TcpV4 | GsoType::TcpV6 => {
            let tcp_len_at = ip_header_len + 12;
            if input.len() <= tcp_len_at {
                return Err(GsoError::PacketTooShort("TCP header is truncated"));
            }
            let tcp_header_len = u16::from(input[tcp_len_at] >> 4) * 4;
            if !(20..=60).contains(&tcp_header_len) {
                return Err(GsoError::Invalid("invalid TCP header length"));
            }
            hdr.hdr_len = hdr
                .csum_start
                .checked_add(tcp_header_len)
                .ok_or(GsoError::Invalid("GSO header length overflow"))?;
        }
        GsoType::Udp => return Err(GsoError::UnsupportedGsoType(raw_gso_type)),
        GsoType::None => return Err(GsoError::NotGso),
    }

    let hdr_len = hdr.hdr_len as usize;
    if hdr_len > input.len() {
        return Err(GsoError::PacketTooShort(
            "GSO header length exceeds the packet",
        ));
    }
    if hdr_len < ip_header_len {
        return Err(GsoError::Invalid(
            "GSO header length precedes the transport header",
        ));
    }
    let csum_at = ip_header_len
        .checked_add(hdr.csum_offset as usize)
        .ok_or(GsoError::Invalid("checksum offset overflow"))?;
    if csum_at + 2 > hdr_len {
        return Err(GsoError::Invalid(
            "checksum offset lies outside the transport header",
        ));
    }
    if csum_at + 2 > input.len() {
        return Err(GsoError::PacketTooShort(
            "checksum offset exceeds the packet",
        ));
    }
    Ok(())
}

/// Splits a GSO packet into `out`, returning the number of segments written.
///
/// The header is normalized with [`prepare_gso`]. Transport checksums, IP
/// lengths, IPv4 identifiers and TCP sequence numbers are rewritten for every
/// segment.
pub fn split_gso(
    input: &[u8],
    hdr: &mut VirtioNetHdr,
    out: &mut [&mut [u8]],
) -> Result<usize, GsoError> {
    prepare_gso(input, hdr)?;
    if hdr.gso_type & !VIRTIO_NET_HDR_GSO_ECN == VIRTIO_NET_HDR_GSO_NONE {
        return Err(GsoError::NotGso);
    }

    let hdr_len = hdr.hdr_len as usize;
    if input.len() <= hdr_len {
        return Err(GsoError::PacketTooShort("GSO packet has no payload"));
    }
    let count = gso_segment_count(input.len(), hdr.hdr_len, hdr.gso_size);
    if count == 0 {
        return Err(GsoError::InvalidSegmentSize(hdr.gso_size));
    }
    if count > out.len() {
        return Err(GsoError::TooManySegments {
            needed: count,
            available: out.len(),
        });
    }
    for (index, slot) in out.iter().enumerate().take(count) {
        let needed = gso_segment_len(input.len(), hdr, index)
            .ok_or(GsoError::Invalid("segment index out of range"))?;
        if slot.len() < needed {
            return Err(GsoError::BufferTooSmall {
                needed,
                available: slot.len(),
            });
        }
    }

    let kind = hdr
        .gso()
        .ok_or(GsoError::UnsupportedGsoType(hdr.gso_type))?;
    let is_v6 = input[0] >> 4 == 6;
    let ip_header_len = hdr.csum_start as usize;
    let is_tcp = matches!(kind, GsoType::TcpV4 | GsoType::TcpV6);
    let protocol = if is_tcp { IPPROTO_TCP } else { IPPROTO_UDP };
    let src_offset = if is_v6 {
        IPV6_SRC_ADDR_OFFSET
    } else {
        IPV4_SRC_ADDR_OFFSET
    };
    let addr_len = if is_v6 { 16 } else { 4 };
    let csum_at = ip_header_len + hdr.csum_offset as usize;
    let first_seq = if is_tcp {
        u32::from_be_bytes([
            input[ip_header_len + 4],
            input[ip_header_len + 5],
            input[ip_header_len + 6],
            input[ip_header_len + 7],
        ])
    } else {
        0
    };

    for (index, dst_buf) in out.iter_mut().take(count).enumerate() {
        let total_len = gso_segment_len(input.len(), hdr, index)
            .ok_or(GsoError::Invalid("segment index out of range"))?;
        let segment_start = hdr_len + index * hdr.gso_size as usize;
        let segment_end = segment_start + (total_len - hdr_len);
        let dst = &mut dst_buf[..total_len];

        dst[..ip_header_len].copy_from_slice(&input[..ip_header_len]);
        if is_v6 {
            dst[4..6].copy_from_slice(&((total_len - ip_header_len) as u16).to_be_bytes());
        } else {
            if index > 0 {
                let id = u16::from_be_bytes([dst[4], dst[5]]).wrapping_add(index as u16);
                dst[4..6].copy_from_slice(&id.to_be_bytes());
            }
            dst[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
            dst[10..12].fill(0);
            let checksum = !checksum(&dst[..ip_header_len], 0);
            dst[10..12].copy_from_slice(&checksum.to_be_bytes());
        }

        dst[ip_header_len..hdr_len].copy_from_slice(&input[ip_header_len..hdr_len]);

        if is_tcp {
            let seq = first_seq.wrapping_add(hdr.gso_size as u32 * index as u32);
            dst[ip_header_len + 4..ip_header_len + 8].copy_from_slice(&seq.to_be_bytes());
            if segment_end != input.len() {
                dst[ip_header_len + TCP_FLAGS_OFFSET] &= !(TCP_FLAG_FIN | TCP_FLAG_PSH);
            }
        } else {
            let udp_len = ((hdr_len - ip_header_len) + (segment_end - segment_start)) as u16;
            dst[ip_header_len + 4..ip_header_len + 6].copy_from_slice(&udp_len.to_be_bytes());
        }

        dst[hdr_len..total_len].copy_from_slice(&input[segment_start..segment_end]);

        dst[csum_at..csum_at + 2].fill(0);
        let transport_len = ((hdr_len - ip_header_len) + (segment_end - segment_start)) as u16;
        let pseudo = pseudo_header_checksum_no_fold(
            protocol,
            &dst[src_offset..src_offset + addr_len],
            &dst[src_offset + addr_len..src_offset + addr_len * 2],
            transport_len,
        );
        let checksum = !checksum(&dst[ip_header_len..total_len], pseudo);
        dst[csum_at..csum_at + 2].copy_from_slice(&checksum.to_be_bytes());
    }

    Ok(count)
}

/// Completes a partial checksum for a packet without segmentation offload.
pub fn gso_none_checksum(
    packet: &mut [u8],
    csum_start: u16,
    csum_offset: u16,
) -> Result<(), GsoError> {
    let start = csum_start as usize;
    let at = start
        .checked_add(csum_offset as usize)
        .ok_or(GsoError::Invalid("checksum offset overflow"))?;
    if start > packet.len() {
        return Err(GsoError::PacketTooShort(
            "checksum start exceeds the packet",
        ));
    }
    if at + 2 > packet.len() {
        return Err(GsoError::PacketTooShort(
            "checksum offset exceeds the packet",
        ));
    }
    let initial = u16::from_be_bytes([packet[at], packet[at + 1]]);
    packet[at] = 0;
    packet[at + 1] = 0;
    let completed = !checksum(&packet[start..], u64::from(initial));
    packet[at..at + 2].copy_from_slice(&completed.to_be_bytes());
    Ok(())
}

fn checksum_no_fold(data: &[u8], initial: u64) -> u64 {
    let mut sum = initial;
    let (chunks, remainder) = data.as_chunks::<2>();
    for chunk in chunks {
        sum += u64::from(u16::from_be_bytes(*chunk));
    }
    if let [tail] = remainder {
        sum += u64::from(*tail) << 8;
    }
    sum
}

fn checksum(data: &[u8], initial: u64) -> u16 {
    let mut sum = checksum_no_fold(data, initial);
    while sum > u64::from(u16::MAX) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16
}

fn pseudo_header_checksum_no_fold(
    protocol: u8,
    src_addr: &[u8],
    dst_addr: &[u8],
    total_len: u16,
) -> u64 {
    let mut sum = checksum_no_fold(src_addr, 0);
    sum = checksum_no_fold(dst_addr, sum);
    sum = checksum_no_fold(&[0, protocol], sum);
    checksum_no_fold(&total_len.to_be_bytes(), sum)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::{
        GsoType, VIRTIO_NET_HDR_F_DATA_VALID, VIRTIO_NET_HDR_F_NEEDS_CSUM, VIRTIO_NET_HDR_GSO_ECN,
        VIRTIO_NET_HDR_GSO_TCPV4, VIRTIO_NET_HDR_GSO_TCPV6, VIRTIO_NET_HDR_GSO_UDP,
        VIRTIO_NET_HDR_GSO_UDP_L4,
    };

    fn ipv4_header(protocol: u8, payload_len: usize) -> Vec<u8> {
        let total_len = 20 + payload_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[4..6].copy_from_slice(&7u16.to_be_bytes());
        packet[6] = 0x40;
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[192, 0, 2, 2]);
        let checksum = !checksum(&packet[..20], 0);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn ipv6_header(protocol: u8, payload_len: usize) -> Vec<u8> {
        let mut packet = vec![0u8; 40 + payload_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
        packet[6] = protocol;
        packet[7] = 64;
        packet[8..24]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1]);
        packet[24..40]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2]);
        packet
    }

    fn tcp_header(payload_len: usize, seq: u32, flags: u8) -> Vec<u8> {
        let mut tcp = vec![0u8; 20 + payload_len];
        tcp[0..2].copy_from_slice(&1234u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&seq.to_be_bytes());
        tcp[8..12].copy_from_slice(&1u32.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = flags;
        tcp[14..16].copy_from_slice(&3000u16.to_be_bytes());
        for (index, byte) in tcp[20..].iter_mut().enumerate() {
            *byte = index as u8;
        }
        tcp
    }

    fn udp_header(payload_len: usize) -> Vec<u8> {
        let mut udp = vec![0u8; 8 + payload_len];
        udp[0..2].copy_from_slice(&1234u16.to_be_bytes());
        udp[2..4].copy_from_slice(&80u16.to_be_bytes());
        udp[4..6].copy_from_slice(&((8 + payload_len) as u16).to_be_bytes());
        for (index, byte) in udp[8..].iter_mut().enumerate() {
            *byte = index as u8;
        }
        udp
    }

    fn tcp4_packet(payload_len: usize, seq: u32, flags: u8) -> Vec<u8> {
        let mut packet = ipv4_header(IPPROTO_TCP, 20 + payload_len);
        packet[20..].copy_from_slice(&tcp_header(payload_len, seq, flags));
        packet
    }

    fn tcp6_packet(payload_len: usize, seq: u32, flags: u8) -> Vec<u8> {
        let mut packet = ipv6_header(IPPROTO_TCP, 20 + payload_len);
        packet[40..].copy_from_slice(&tcp_header(payload_len, seq, flags));
        packet
    }

    fn udp4_packet(payload_len: usize) -> Vec<u8> {
        let mut packet = ipv4_header(IPPROTO_UDP, 8 + payload_len);
        packet[20..].copy_from_slice(&udp_header(payload_len));
        packet
    }

    fn udp6_packet(payload_len: usize) -> Vec<u8> {
        let mut packet = ipv6_header(IPPROTO_UDP, 8 + payload_len);
        packet[40..].copy_from_slice(&udp_header(payload_len));
        packet
    }

    fn tcp4_header(gso_size: u16) -> VirtioNetHdr {
        VirtioNetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
            hdr_len: 0,
            gso_size,
            csum_start: 20,
            csum_offset: 16,
            num_buffers: 0,
        }
    }

    fn tcp6_header(gso_size: u16) -> VirtioNetHdr {
        VirtioNetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_TCPV6,
            hdr_len: 0,
            gso_size,
            csum_start: 40,
            csum_offset: 16,
            num_buffers: 0,
        }
    }

    fn udp4_header(gso_size: u16) -> VirtioNetHdr {
        VirtioNetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_UDP_L4,
            hdr_len: 0,
            gso_size,
            csum_start: 20,
            csum_offset: 6,
            num_buffers: 0,
        }
    }

    fn udp6_header(gso_size: u16) -> VirtioNetHdr {
        VirtioNetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_UDP_L4,
            hdr_len: 0,
            gso_size,
            csum_start: 40,
            csum_offset: 6,
            num_buffers: 0,
        }
    }

    fn assert_valid_transport_checksum(packet: &[u8], ip_header_len: usize, protocol: u8) {
        let (src_offset, addr_len) = match packet[0] >> 4 {
            4 => (IPV4_SRC_ADDR_OFFSET, 4),
            6 => (IPV6_SRC_ADDR_OFFSET, 16),
            version => panic!("unexpected IP version {version}"),
        };
        let pseudo = pseudo_header_checksum_no_fold(
            protocol,
            &packet[src_offset..src_offset + addr_len],
            &packet[src_offset + addr_len..src_offset + addr_len * 2],
            (packet.len() - ip_header_len) as u16,
        );
        assert_eq!(checksum(&packet[ip_header_len..], pseudo), 0xFFFF);
    }

    #[test]
    fn checksum_matches_known_values() {
        assert_eq!(checksum(&[], 0), 0);
        assert_eq!(
            pseudo_header_checksum_no_fold(IPPROTO_TCP, &[1, 2, 3, 4], &[5, 6, 7, 8], 20),
            0x102E
        );
        let header = ipv4_header(IPPROTO_TCP, 0);
        assert_eq!(checksum(&header[..20], 0), 0xFFFF);
    }

    #[test]
    fn completes_partial_checksum_for_non_gso_packet() {
        let mut packet = tcp4_packet(16, 1, TCP_FLAG_PSH | 0x10);
        let pseudo = pseudo_header_checksum_no_fold(
            IPPROTO_TCP,
            &packet[IPV4_SRC_ADDR_OFFSET..IPV4_SRC_ADDR_OFFSET + 4],
            &packet[IPV4_SRC_ADDR_OFFSET + 4..IPV4_SRC_ADDR_OFFSET + 8],
            (packet.len() - 20) as u16,
        );
        packet[36..38].copy_from_slice(&checksum(&[], pseudo).to_be_bytes());
        gso_none_checksum(&mut packet, 20, 16).unwrap();
        assert_eq!(checksum(&packet[20..], pseudo), 0xFFFF);
    }

    #[test]
    fn rejects_partial_checksum_outside_packet() {
        let mut packet = tcp4_packet(0, 1, 0x10);
        assert_eq!(
            gso_none_checksum(&mut packet, 20, 100),
            Err(GsoError::PacketTooShort(
                "checksum offset exceeds the packet"
            ))
        );
        assert_eq!(
            gso_none_checksum(&mut packet, 100, 16),
            Err(GsoError::PacketTooShort(
                "checksum start exceeds the packet"
            ))
        );
    }

    #[test]
    fn splits_tcp4_into_segments_with_valid_headers() {
        let packet = tcp4_packet(200, 1000, TCP_FLAG_PSH | 0x10);
        let mut header = tcp4_header(100);
        let mut first = [0u8; 200];
        let mut second = [0u8; 200];
        let mut bufs = [&mut first[..], &mut second[..]];
        let count = split_gso(&packet, &mut header, &mut bufs).unwrap();

        assert_eq!(count, 2);
        assert_eq!(header.hdr_len, 40);
        for segment in [&first[..140], &second[..140]] {
            assert_eq!(checksum(&segment[..20], 0), 0xFFFF);
            assert_valid_transport_checksum(segment, 20, IPPROTO_TCP);
        }
        assert_eq!(u16::from_be_bytes([first[2], first[3]]), 140);
        assert_eq!(u16::from_be_bytes([second[2], second[3]]), 140);
        assert_eq!(u16::from_be_bytes([first[4], first[5]]), 7);
        assert_eq!(u16::from_be_bytes([second[4], second[5]]), 8);
        assert_eq!(u32::from_be_bytes(first[24..28].try_into().unwrap()), 1000);
        assert_eq!(u32::from_be_bytes(second[24..28].try_into().unwrap()), 1100);
        assert_eq!(first[33] & TCP_FLAG_PSH, 0);
        assert_eq!(second[33] & TCP_FLAG_PSH, TCP_FLAG_PSH);
        assert_eq!(first[33] & TCP_FLAG_FIN, 0);
    }

    #[test]
    fn splits_tcp6_into_segments_with_valid_headers() {
        let packet = tcp6_packet(200, 5000, TCP_FLAG_PSH | 0x10);
        let mut header = tcp6_header(100);
        let mut first = [0u8; 200];
        let mut second = [0u8; 200];
        let mut bufs = [&mut first[..], &mut second[..]];
        let count = split_gso(&packet, &mut header, &mut bufs).unwrap();

        assert_eq!(count, 2);
        assert_eq!(header.hdr_len, 60);
        for segment in [&first[..160], &second[..160]] {
            assert_eq!(u16::from_be_bytes([segment[4], segment[5]]), 120);
            assert_valid_transport_checksum(segment, 40, IPPROTO_TCP);
        }
        assert_eq!(u32::from_be_bytes(first[44..48].try_into().unwrap()), 5000);
        assert_eq!(u32::from_be_bytes(second[44..48].try_into().unwrap()), 5100);
    }

    #[test]
    fn splits_udp4_into_segments_with_valid_headers() {
        let packet = udp4_packet(200);
        let mut header = udp4_header(100);
        let mut first = [0u8; 200];
        let mut second = [0u8; 200];
        let mut bufs = [&mut first[..], &mut second[..]];
        let count = split_gso(&packet, &mut header, &mut bufs).unwrap();

        assert_eq!(count, 2);
        assert_eq!(header.hdr_len, 28);
        for segment in [&first[..128], &second[..128]] {
            assert_eq!(u16::from_be_bytes([segment[24], segment[25]]), 108);
            assert_valid_transport_checksum(segment, 20, IPPROTO_UDP);
        }
    }

    #[test]
    fn splits_udp6_into_segments_with_valid_headers() {
        let packet = udp6_packet(200);
        let mut header = udp6_header(100);
        let mut first = [0u8; 200];
        let mut second = [0u8; 200];
        let mut bufs = [&mut first[..], &mut second[..]];
        let count = split_gso(&packet, &mut header, &mut bufs).unwrap();

        assert_eq!(count, 2);
        assert_eq!(header.hdr_len, 48);
        for segment in [&first[..148], &second[..148]] {
            assert_eq!(u16::from_be_bytes([segment[4], segment[5]]), 108);
            assert_eq!(u16::from_be_bytes([segment[44], segment[45]]), 108);
            assert_valid_transport_checksum(segment, 40, IPPROTO_UDP);
        }
    }

    #[test]
    fn splits_last_segment_when_payload_is_not_a_multiple() {
        let packet = tcp4_packet(150, 1, 0x10);
        let mut header = tcp4_header(100);
        let mut first = [0u8; 200];
        let mut second = [0u8; 200];
        let mut bufs = [&mut first[..], &mut second[..]];
        let count = split_gso(&packet, &mut header, &mut bufs).unwrap();

        assert_eq!(count, 2);
        assert_eq!(gso_segment_len(packet.len(), &header, 0), Some(140));
        assert_eq!(gso_segment_len(packet.len(), &header, 1), Some(90));
        assert_eq!(u16::from_be_bytes([second[2], second[3]]), 90);
        assert_valid_transport_checksum(&second[..90], 20, IPPROTO_TCP);
    }

    #[test]
    fn prepare_rejects_zero_gso_size() {
        let packet = tcp4_packet(100, 1, 0x10);
        let mut header = tcp4_header(0);
        assert_eq!(
            prepare_gso(&packet, &mut header),
            Err(GsoError::InvalidSegmentSize(0))
        );
    }

    #[test]
    fn prepare_rejects_header_longer_than_packet() {
        let packet = vec![0x45u8; 20];
        let mut header = udp4_header(100);
        assert_eq!(
            prepare_gso(&packet, &mut header),
            Err(GsoError::PacketTooShort(
                "GSO header length exceeds the packet"
            ))
        );
    }

    #[test]
    fn prepare_rejects_checksum_outside_transport_header() {
        let packet = tcp4_packet(0, 1, 0x10);
        let mut header = tcp4_header(100);
        header.csum_offset = 100;
        assert_eq!(
            prepare_gso(&packet, &mut header),
            Err(GsoError::Invalid(
                "checksum offset lies outside the transport header"
            ))
        );
    }

    #[test]
    fn prepare_rejects_truncated_tcp_header() {
        let packet = {
            let mut packet = ipv4_header(IPPROTO_TCP, 0);
            packet.resize(24, 0);
            packet
        };
        let mut header = tcp4_header(100);
        assert_eq!(
            prepare_gso(&packet, &mut header),
            Err(GsoError::PacketTooShort("TCP header is truncated"))
        );
    }

    #[test]
    fn prepare_rejects_invalid_tcp_header_length() {
        let mut packet = tcp4_packet(0, 1, 0x10);
        packet[32] = 0x10;
        let mut header = tcp4_header(100);
        assert_eq!(
            prepare_gso(&packet, &mut header),
            Err(GsoError::Invalid("invalid TCP header length"))
        );
    }

    #[test]
    fn prepare_rejects_ip_version_mismatch() {
        let packet = tcp6_packet(0, 1, 0x10);
        let mut header = tcp4_header(100);
        assert_eq!(
            prepare_gso(&packet, &mut header),
            Err(GsoError::Invalid("GSO type TCPv4 with a non-IPv4 packet"))
        );
    }

    #[test]
    fn prepare_rejects_legacy_udp_offload() {
        let packet = udp4_packet(100);
        let mut header = VirtioNetHdr {
            gso_type: VIRTIO_NET_HDR_GSO_UDP,
            hdr_len: 0,
            gso_size: 100,
            csum_start: 20,
            csum_offset: 6,
            ..VirtioNetHdr::new()
        };
        assert_eq!(
            prepare_gso(&packet, &mut header),
            Err(GsoError::UnsupportedGsoType(VIRTIO_NET_HDR_GSO_UDP))
        );
    }

    #[test]
    fn prepare_rejects_unknown_gso_type() {
        let packet = tcp4_packet(0, 1, 0x10);
        let mut header = tcp4_header(100);
        header.gso_type = 2;
        assert_eq!(
            prepare_gso(&packet, &mut header),
            Err(GsoError::UnsupportedGsoType(2))
        );
    }

    #[test]
    fn prepare_accepts_none_and_rejects_ecn_without_type() {
        let packet = tcp4_packet(0, 1, 0x10);
        let mut header = VirtioNetHdr::new();
        assert_eq!(prepare_gso(&packet, &mut header), Ok(()));

        header.gso_type = VIRTIO_NET_HDR_GSO_ECN;
        assert_eq!(
            prepare_gso(&packet, &mut header),
            Err(GsoError::UnsupportedGsoType(VIRTIO_NET_HDR_GSO_ECN))
        );
    }

    #[test]
    fn prepare_accepts_data_valid_without_offload() {
        let packet = tcp4_packet(0, 1, 0x10);
        let mut header = VirtioNetHdr {
            flags: VIRTIO_NET_HDR_F_DATA_VALID,
            ..VirtioNetHdr::new()
        };
        assert_eq!(prepare_gso(&packet, &mut header), Ok(()));
    }

    #[test]
    fn split_rejects_non_gso_packets() {
        let packet = tcp4_packet(0, 1, 0x10);
        let mut header = VirtioNetHdr::new();
        let mut out = [0u8; 128];
        let mut bufs = [&mut out[..]];
        assert_eq!(
            split_gso(&packet, &mut header, &mut bufs),
            Err(GsoError::NotGso)
        );
    }

    #[test]
    fn split_ignores_the_pseudo_header_checksum_field() {
        let mut packet = tcp4_packet(200, 1000, TCP_FLAG_PSH | 0x10);
        packet[36..38].copy_from_slice(&0x2F07u16.to_be_bytes());
        let mut header = tcp4_header(100);
        let mut first = [0u8; 200];
        let mut second = [0u8; 200];
        let mut bufs = [&mut first[..], &mut second[..]];
        let count = split_gso(&packet, &mut header, &mut bufs).unwrap();

        assert_eq!(count, 2);
        assert_valid_transport_checksum(&first[..140], 20, IPPROTO_TCP);
        assert_valid_transport_checksum(&second[..140], 20, IPPROTO_TCP);
    }

    #[test]
    fn split_udp_ignores_the_partial_checksum_field() {
        let mut packet = udp4_packet(200);
        packet[26..28].copy_from_slice(&0x1234u16.to_be_bytes());
        let mut header = udp4_header(100);
        let mut first = [0u8; 200];
        let mut second = [0u8; 200];
        let mut bufs = [&mut first[..], &mut second[..]];
        let count = split_gso(&packet, &mut header, &mut bufs).unwrap();

        assert_eq!(count, 2);
        for segment in [&first[..128], &second[..128]] {
            assert_valid_transport_checksum(segment, 20, IPPROTO_UDP);
        }
    }

    #[test]
    fn split_reports_too_many_segments() {
        let packet = tcp4_packet(300, 1, 0x10);
        let mut header = tcp4_header(100);
        let mut first = [0u8; 200];
        let mut second = [0u8; 200];
        let mut bufs = [&mut first[..], &mut second[..]];
        assert_eq!(
            split_gso(&packet, &mut header, &mut bufs),
            Err(GsoError::TooManySegments {
                needed: 3,
                available: 2,
            })
        );
    }

    #[test]
    fn split_handles_more_than_64_segments() {
        let packet = tcp4_packet(12_200, 1, 0x10);
        let mut header = tcp4_header(100);
        let mut storage = vec![vec![0u8; 200]; 128];
        let mut bufs: Vec<&mut [u8]> = storage.iter_mut().map(|buf| buf.as_mut_slice()).collect();
        let count = split_gso(&packet, &mut header, &mut bufs).unwrap();
        assert!(count > 64, "expected more than 64 segments, got {count}");
        assert!(count <= 128);
    }

    #[test]
    fn split_reports_small_output_buffer() {
        let packet = tcp4_packet(200, 1, 0x10);
        let mut header = tcp4_header(100);
        let mut first = [0u8; 200];
        let mut second = [0u8; 10];
        let mut bufs = [&mut first[..], &mut second[..]];
        assert_eq!(
            split_gso(&packet, &mut header, &mut bufs),
            Err(GsoError::BufferTooSmall {
                needed: 140,
                available: 10,
            })
        );
    }

    #[test]
    fn split_rejects_gso_packet_without_payload() {
        let packet = udp4_packet(0);
        let mut header = udp4_header(100);
        let mut out = [0u8; 128];
        let mut bufs = [&mut out[..]];
        assert_eq!(
            split_gso(&packet, &mut header, &mut bufs),
            Err(GsoError::PacketTooShort("GSO packet has no payload"))
        );
    }

    #[test]
    fn segment_sizing_helpers() {
        assert_eq!(max_gso_size(1500, 40), 1460);
        assert_eq!(max_gso_size(1500, 1500), 0);
        assert_eq!(max_gso_size(40, 1500), 0);

        assert_eq!(gso_segment_count(1400, 40, 100), 14);
        assert_eq!(gso_segment_count(1400, 40, 1360), 1);
        assert_eq!(gso_segment_count(1400, 40, 1361), 1);
        assert_eq!(gso_segment_count(1400, 40, 0), 0);
        assert_eq!(gso_segment_count(40, 40, 100), 0);
        assert_eq!(gso_segment_count(39, 40, 100), 0);

        assert_eq!(max_gso_segments(65_535, 40, 1000), 66);
        assert_eq!(max_gso_segments(1500, 40, 1460), 1);

        assert_eq!(read_buffer_size(10), 65_545);
        assert_eq!(read_buffer_size(12), 65_547);
        assert_eq!(packet_buffer_size(1420, 10), 1430);
        assert_eq!(packet_buffer_size(0, 12), 12);
    }

    #[test]
    fn segment_length_helper_rejects_out_of_range() {
        let header = tcp4_header(100);
        let mut header = header;
        prepare_gso(&tcp4_packet(200, 1, 0x10), &mut header).unwrap();
        assert_eq!(gso_segment_len(240, &header, 0), Some(140));
        assert_eq!(gso_segment_len(240, &header, 1), Some(140));
        assert_eq!(gso_segment_len(240, &header, 2), None);
        assert_eq!(gso_segment_len(40, &header, 0), None);

        let zero = tcp4_header(0);
        assert_eq!(gso_segment_len(240, &zero, 0), None);
    }

    #[test]
    fn prepare_accepts_ecn_modifier_and_preserves_it() {
        let packet = tcp4_packet(200, 1, 0x10);
        let mut header = tcp4_header(100);
        header.gso_type |= VIRTIO_NET_HDR_GSO_ECN;

        assert_eq!(prepare_gso(&packet, &mut header), Ok(()));
        assert_eq!(
            header.gso_type,
            VIRTIO_NET_HDR_GSO_TCPV4 | VIRTIO_NET_HDR_GSO_ECN
        );
        assert_eq!(header.gso(), Some(GsoType::TcpV4));
        assert!(header.ecn());
    }

    #[test]
    fn split_preserves_ecn_and_writes_valid_checksums() {
        let packet = tcp4_packet(200, 1000, TCP_FLAG_PSH | 0x10);
        let mut header = tcp4_header(100);
        header.gso_type |= VIRTIO_NET_HDR_GSO_ECN;
        let mut first = [0u8; 200];
        let mut second = [0u8; 200];
        let mut bufs = [&mut first[..], &mut second[..]];

        let count = split_gso(&packet, &mut header, &mut bufs).unwrap();

        assert_eq!(count, 2);
        assert!(header.ecn());
        assert_eq!(header.gso(), Some(GsoType::TcpV4));
        assert_valid_transport_checksum(&first[..140], 20, IPPROTO_TCP);
        assert_valid_transport_checksum(&second[..140], 20, IPPROTO_TCP);
    }

    #[test]
    fn prepare_uses_tcp_data_offset_for_hdr_len() {
        let mut packet = tcp4_packet(0, 1, 0x10);
        packet[32] = 0x60;
        packet.extend_from_slice(&[0, 0, 0, 0]);
        packet[2..4].copy_from_slice(&44u16.to_be_bytes());
        let mut header = tcp4_header(100);

        assert_eq!(prepare_gso(&packet, &mut header), Ok(()));
        assert_eq!(header.hdr_len, 44);
        assert_eq!(
            gso_segment_count(packet.len(), header.hdr_len, header.gso_size),
            0
        );
        assert_eq!(gso_segment_len(packet.len(), &header, 0), None);
    }

    #[test]
    fn segment_helpers_handle_gso_size_and_header_edges() {
        let mut header = tcp4_header(100);
        prepare_gso(&tcp4_packet(20, 1, 0x10), &mut header).unwrap();

        assert_eq!(header.hdr_len, 40);
        assert_eq!(gso_segment_len(60, &header, 0), Some(60));
        assert_eq!(gso_segment_count(60, 40, 100), 1);
        assert_eq!(gso_segment_len(41, &header, 0), Some(41));
        assert_eq!(gso_segment_count(41, 40, 1), 1);
        assert_eq!(gso_segment_count(42, 40, 1), 2);
        assert_eq!(gso_segment_count(40, 40, 1), 0);
        assert_eq!(gso_segment_len(40, &header, 0), None);
        assert_eq!(gso_segment_len(41, &tcp4_header(0), 0), None);
    }

    #[test]
    fn prepare_rejects_empty_input() {
        let mut header = tcp4_header(100);
        assert_eq!(
            prepare_gso(&[], &mut header),
            Err(GsoError::PacketTooShort("empty IP packet"))
        );
    }

    #[test]
    fn checksum_rejects_empty_packet() {
        let mut packet = [];
        assert_eq!(
            gso_none_checksum(&mut packet, 0, 0),
            Err(GsoError::PacketTooShort(
                "checksum offset exceeds the packet"
            ))
        );
    }
}
