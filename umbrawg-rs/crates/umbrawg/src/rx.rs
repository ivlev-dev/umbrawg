//! Накопитель расшифрованных пакетов с GSO-записью в TUN.
//!
//! Пакеты копятся в общем буфере, а при сбросе подряд идущие пакеты одинаковой
//! длины склеиваются в GSO-суперпакет с общим заголовком L3/L4. Склейка
//! выполняется только для цепочек с совпадающими заголовками и непрерывной
//! последовательностью TCP; всё остальное пишется поштучно.

use std::ops::Range;

use umbrawg_tun::{
    Tun, TunError, VirtioNetHdr, VIRTIO_NET_HDR_F_NEEDS_CSUM, VIRTIO_NET_HDR_GSO_TCPV4,
    VIRTIO_NET_HDR_GSO_TCPV6, VIRTIO_NET_HDR_GSO_UDP_L4,
};

/// Максимальное число пакетов в одном накопителе.
pub const RX_BATCH: usize = 64;

/// Максимальный размер IP-пакета и собранного GSO-суперпакета.
const MAX_IP_PACKET: usize = u16::MAX as usize;

/// Максимальное число сегментов в одном GSO-пакете (`GSO_MAX_SEGS`).
const MAX_GSO_SEGMENTS: usize = 64;

const IPV4_MIN_HEADER: usize = 20;
const IPV4_MAX_HEADER: usize = 60;
const IPV6_HEADER: usize = 40;
const UDP_HEADER: usize = 8;
const TCP_MIN_HEADER: usize = 20;
const TCP_MAX_HEADER: usize = 60;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPV6_VERSION: u8 = 6;

/// Источник записи пакетов в TUN.
pub(crate) trait PacketSink {
    /// Возвращает `true`, если доступна запись с virtio-заголовком.
    fn gso_supported(&self) -> bool;

    /// Пишет один пакет.
    fn write_packet(&self, packet: &[u8]) -> Result<(), TunError>;

    /// Пишет GSO-суперпакет с явным virtio-заголовком.
    fn write_gso(&self, header: &VirtioNetHdr, packet: &[u8]) -> Result<(), TunError>;
}

impl PacketSink for Tun {
    fn gso_supported(&self) -> bool {
        self.vnet_hdr()
    }

    fn write_packet(&self, packet: &[u8]) -> Result<(), TunError> {
        self.write(packet).map(|_| ())
    }

    fn write_gso(&self, header: &VirtioNetHdr, packet: &[u8]) -> Result<(), TunError> {
        self.write_with_header(header, packet).map(|_| ())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum L4 {
    Udp,
    Tcp,
}

#[derive(Clone, Copy, Debug)]
struct Segment {
    version: u8,
    ip_header_len: usize,
    l4_header_len: usize,
    payload_len: usize,
    l4: L4,
    gso_type: u8,
    csum_offset: u16,
}

impl Segment {
    fn header_len(&self) -> usize {
        self.ip_header_len + self.l4_header_len
    }
}

#[derive(Clone, Copy, Debug)]
struct Mutable {
    ranges: [(usize, usize); 5],
    len: usize,
}

impl Mutable {
    fn new(segment: &Segment) -> Self {
        let mut ranges = [(0usize, 0usize); 5];
        let mut len = 0;
        let mut keep = |range: Range<usize>| {
            ranges[len] = (range.start, range.end);
            len += 1;
        };
        if segment.version == IPV6_VERSION {
            keep(4..6);
        } else {
            keep(2..4);
            keep(4..6);
            keep(10..12);
        }
        let transport = segment.ip_header_len;
        match segment.l4 {
            L4::Udp => keep(transport + 4..transport + 8),
            L4::Tcp => {
                keep(transport + 4..transport + 8);
                keep(transport + 16..transport + 18);
            }
        }
        Self { ranges, len }
    }

    fn contains(&self, offset: usize, end: usize) -> bool {
        self.ranges[..self.len]
            .iter()
            .any(|(start, stop)| offset < *stop && end > *start)
    }
}

fn parse_segment(packet: &[u8]) -> Option<Segment> {
    if packet.len() < IPV4_MIN_HEADER {
        return None;
    }
    match packet[0] >> 4 {
        4 => parse_ipv4(packet),
        IPV6_VERSION => parse_ipv6(packet),
        _ => None,
    }
}

fn parse_ipv4(packet: &[u8]) -> Option<Segment> {
    let ip_header_len = usize::from(packet[0] & 0x0f) * 4;
    if !(IPV4_MIN_HEADER..=IPV4_MAX_HEADER).contains(&ip_header_len) || packet.len() < ip_header_len
    {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len != packet.len() {
        return None;
    }
    if u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0 {
        return None;
    }
    parse_transport(packet, ip_header_len, 4, packet[9])
}

fn parse_ipv6(packet: &[u8]) -> Option<Segment> {
    if packet.len() < IPV6_HEADER {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if IPV6_HEADER + payload_len != packet.len() {
        return None;
    }
    parse_transport(packet, IPV6_HEADER, IPV6_VERSION, packet[6])
}

fn parse_transport(
    packet: &[u8],
    ip_header_len: usize,
    version: u8,
    protocol: u8,
) -> Option<Segment> {
    let remaining = packet.len() - ip_header_len;
    let (l4_header_len, l4, gso_type, csum_offset) = match protocol {
        IPPROTO_UDP => {
            if remaining < UDP_HEADER {
                return None;
            }
            (UDP_HEADER, L4::Udp, VIRTIO_NET_HDR_GSO_UDP_L4, 6)
        }
        IPPROTO_TCP => {
            if remaining < TCP_MIN_HEADER {
                return None;
            }
            let l4_header_len = usize::from(packet[ip_header_len + 12] >> 4) * 4;
            if !(TCP_MIN_HEADER..=TCP_MAX_HEADER).contains(&l4_header_len) {
                return None;
            }
            let gso_type = if version == IPV6_VERSION {
                VIRTIO_NET_HDR_GSO_TCPV6
            } else {
                VIRTIO_NET_HDR_GSO_TCPV4
            };
            (l4_header_len, L4::Tcp, gso_type, 16)
        }
        _ => return None,
    };
    if remaining < l4_header_len {
        return None;
    }
    let segment = Segment {
        version,
        ip_header_len,
        l4_header_len,
        payload_len: remaining - l4_header_len,
        l4,
        gso_type,
        csum_offset,
    };
    (segment.payload_len > 0).then_some(segment)
}

fn headers_match(reference: &[u8], candidate: &[u8], segment: &Segment, mutable: &Mutable) -> bool {
    (0..segment.header_len())
        .all(|index| mutable.contains(index, index + 1) || reference[index] == candidate[index])
}

fn tcp_sequence(packet: &[u8], segment: &Segment) -> u32 {
    let at = segment.ip_header_len;
    u32::from_be_bytes([
        packet[at + 4],
        packet[at + 5],
        packet[at + 6],
        packet[at + 7],
    ])
}

fn chained(
    reference: &[u8],
    previous: &[u8],
    candidate: &[u8],
    segment: &Segment,
    mutable: &Mutable,
) -> bool {
    if !headers_match(reference, candidate, segment, mutable) {
        return false;
    }
    match segment.l4 {
        L4::Udp => true,
        L4::Tcp => {
            let expected = tcp_sequence(previous, segment).wrapping_add(segment.payload_len as u32);
            tcp_sequence(candidate, segment) == expected
        }
    }
}

fn add_bytes(sum: &mut u64, data: &[u8]) {
    let mut index = 0;
    while index + 8 <= data.len() {
        let word = u64::from_be_bytes([
            data[index],
            data[index + 1],
            data[index + 2],
            data[index + 3],
            data[index + 4],
            data[index + 5],
            data[index + 6],
            data[index + 7],
        ]);
        *sum += (word >> 32) + (word & 0xffff_ffff);
        index += 8;
    }
    while index + 2 <= data.len() {
        *sum += u64::from(u16::from_be_bytes([data[index], data[index + 1]]));
        index += 2;
    }
    if index < data.len() {
        *sum += u64::from(data[index]) << 8;
    }
}

fn fold(mut sum: u64) -> u16 {
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

fn checksum(data: &[u8], initial: u64) -> u16 {
    let mut sum = initial;
    add_bytes(&mut sum, data);
    !fold(sum)
}

fn pseudo_sum(version: u8, packet: &[u8], transport_len: usize) -> u64 {
    let mut sum = 0u64;
    let (addresses, protocol) = if version == IPV6_VERSION {
        (&packet[8..40], packet[6])
    } else {
        (&packet[12..20], packet[9])
    };
    add_bytes(&mut sum, addresses);
    sum + u64::from(protocol) + transport_len as u64
}

/// Накопитель входящих пакетов для одного рабочего потока.
pub(crate) struct RxBatch {
    buffer: Vec<u8>,
    gso_buffer: Vec<u8>,
    packets: [(usize, usize); RX_BATCH],
    count: usize,
    offset: usize,
    slot: usize,
    errors: usize,
}

impl RxBatch {
    /// Создаёт накопитель под пакеты размером не больше `slot` байт.
    pub fn new(slot: usize) -> Self {
        Self {
            buffer: vec![0u8; slot * RX_BATCH],
            gso_buffer: vec![0u8; MAX_IP_PACKET],
            packets: [(0, 0); RX_BATCH],
            count: 0,
            offset: 0,
            slot,
            errors: 0,
        }
    }

    pub fn take_errors(&mut self) -> usize {
        std::mem::take(&mut self.errors)
    }

    /// Добавляет пакет. Возвращает `false`, если накопитель переполнен.
    pub fn push(&mut self, packet: &[u8]) -> bool {
        if self.count == RX_BATCH || packet.len() > self.slot {
            return false;
        }
        if self.offset + packet.len() > self.buffer.len() {
            return false;
        }
        let offset = self.offset;
        self.buffer[offset..offset + packet.len()].copy_from_slice(packet);
        self.packets[self.count] = (offset, packet.len());
        self.count += 1;
        self.offset += packet.len();
        true
    }

    /// Записывает накопленное в `sink` и очищает накопитель.
    pub fn flush<S: PacketSink>(&mut self, sink: &S) {
        let mut index = 0;
        while index < self.count {
            let start = index;
            let length = self.packets[index].1;
            while index < self.count && self.packets[index].1 == length {
                index += 1;
            }
            if index - start == 1 {
                self.write_single(sink, start);
            } else {
                self.write_run(sink, start, index);
            }
        }
        self.count = 0;
        self.offset = 0;
    }

    fn write_run<S: PacketSink>(&mut self, sink: &S, start: usize, end: usize) {
        if !sink.gso_supported() {
            self.write_singles(sink, start, end);
            return;
        }
        let (offset, length) = self.packets[start];
        let Some(segment) = parse_segment(&self.buffer[offset..offset + length]) else {
            self.write_singles(sink, start, end);
            return;
        };
        let mutable = Mutable::new(&segment);
        let per_group = ((MAX_IP_PACKET - segment.header_len()) / segment.payload_len)
            .clamp(1, MAX_GSO_SEGMENTS);
        let mut cursor = start;
        while cursor < end {
            let limit = end.min(cursor + per_group);
            let count = self.chain(cursor, limit, &segment, &mutable);
            if count == 1 {
                self.write_single(sink, cursor);
                cursor += 1;
                continue;
            }
            if self.write_chain(sink, cursor, count, &segment).is_err() {
                self.write_singles(sink, cursor, cursor + count);
            }
            cursor += count;
        }
    }

    fn write_singles<S: PacketSink>(&mut self, sink: &S, start: usize, end: usize) {
        for index in start..end {
            self.write_single(sink, index);
        }
    }

    fn chain(&self, start: usize, limit: usize, segment: &Segment, mutable: &Mutable) -> usize {
        let (first_offset, first_len) = self.packets[start];
        let reference = &self.buffer[first_offset..first_offset + first_len];
        let mut previous = reference;
        let mut count = 1;
        while start + count < limit {
            let (offset, length) = self.packets[start + count];
            let candidate = &self.buffer[offset..offset + length];
            if !chained(reference, previous, candidate, segment, mutable) {
                break;
            }
            previous = candidate;
            count += 1;
        }
        count
    }

    fn write_chain<S: PacketSink>(
        &mut self,
        sink: &S,
        start: usize,
        count: usize,
        segment: &Segment,
    ) -> Result<(), TunError> {
        let header_len = segment.header_len();
        let payload_len = segment.payload_len;
        let total = header_len
            .checked_add(payload_len * count)
            .filter(|total| *total <= MAX_IP_PACKET && *total <= self.gso_buffer.len())
            .ok_or(TunError::InvalidConfig("gso packet is too large"))?;
        let (first_offset, first_len) = self.packets[start];
        {
            let first = &self.buffer[first_offset..first_offset + first_len];
            self.gso_buffer[..header_len].copy_from_slice(&first[..header_len]);
        }
        for index in 0..count {
            let (offset, _) = self.packets[start + index];
            let from = offset + header_len;
            let to = header_len + index * payload_len;
            self.gso_buffer[to..to + payload_len]
                .copy_from_slice(&self.buffer[from..from + payload_len]);
        }
        let transport_len = segment.l4_header_len + payload_len * count;
        if segment.version == IPV6_VERSION {
            self.gso_buffer[4..6].copy_from_slice(&((total - IPV6_HEADER) as u16).to_be_bytes());
        } else {
            self.gso_buffer[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            self.gso_buffer[10..12].fill(0);
            let header_checksum = checksum(&self.gso_buffer[..segment.ip_header_len], 0);
            self.gso_buffer[10..12].copy_from_slice(&header_checksum.to_be_bytes());
        }
        let transport = segment.ip_header_len;
        if segment.l4 == L4::Udp {
            self.gso_buffer[transport + 4..transport + 6]
                .copy_from_slice(&(transport_len as u16).to_be_bytes());
        }
        let checksum_at = transport + usize::from(segment.csum_offset);
        self.gso_buffer[checksum_at..checksum_at + 2].fill(0);
        let initial = pseudo_sum(segment.version, &self.gso_buffer, transport_len);
        let transport_checksum = checksum(&self.gso_buffer[transport..total], initial);
        self.gso_buffer[checksum_at..checksum_at + 2]
            .copy_from_slice(&transport_checksum.to_be_bytes());
        let header = VirtioNetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: segment.gso_type,
            hdr_len: header_len as u16,
            gso_size: payload_len as u16,
            csum_start: transport as u16,
            csum_offset: segment.csum_offset,
            num_buffers: 0,
        };
        sink.write_gso(&header, &self.gso_buffer[..total])
    }

    fn write_single<S: PacketSink>(&mut self, sink: &S, index: usize) {
        let (offset, length) = self.packets[index];
        if let Err(error) = sink.write_packet(&self.buffer[offset..offset + length]) {
            self.errors += 1;
            log::debug!("tun write failed: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Debug)]
    struct Write {
        header: Option<VirtioNetHdr>,
        packet: Vec<u8>,
    }

    struct RecordingSink {
        gso: bool,
        fail_gso: bool,
        writes: RefCell<Vec<Write>>,
    }

    impl RecordingSink {
        fn new(gso: bool) -> Self {
            Self {
                gso,
                fail_gso: false,
                writes: RefCell::new(Vec::new()),
            }
        }

        fn failing() -> Self {
            Self {
                gso: true,
                fail_gso: true,
                writes: RefCell::new(Vec::new()),
            }
        }

        fn take(&self) -> Vec<Write> {
            self.writes.borrow_mut().drain(..).collect()
        }
    }

    impl PacketSink for RecordingSink {
        fn gso_supported(&self) -> bool {
            self.gso
        }

        fn write_packet(&self, packet: &[u8]) -> Result<(), TunError> {
            self.writes.borrow_mut().push(Write {
                header: None,
                packet: packet.to_vec(),
            });
            Ok(())
        }

        fn write_gso(&self, header: &VirtioNetHdr, packet: &[u8]) -> Result<(), TunError> {
            if self.fail_gso {
                return Err(TunError::InvalidConfig("gso rejected"));
            }
            self.writes.borrow_mut().push(Write {
                header: Some(*header),
                packet: packet.to_vec(),
            });
            Ok(())
        }
    }

    fn ipv4_udp(id: u16, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 28 + payload.len()];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&((28 + payload.len()) as u16).to_be_bytes());
        packet[4..6].copy_from_slice(&id.to_be_bytes());
        packet[8] = 64;
        packet[9] = IPPROTO_UDP;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let header = checksum(&packet[..20], 0);
        packet[10..12].copy_from_slice(&header.to_be_bytes());
        packet[20..22].copy_from_slice(&sport.to_be_bytes());
        packet[22..24].copy_from_slice(&dport.to_be_bytes());
        packet[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        packet[28..].copy_from_slice(payload);
        let initial = pseudo_sum(4, &packet, 8 + payload.len());
        let transport = checksum(&packet[20..], initial);
        packet[26..28].copy_from_slice(&transport.to_be_bytes());
        packet
    }

    fn ipv6_udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 48 + payload.len()];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        packet[6] = IPPROTO_UDP;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&[0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        packet[24..40].copy_from_slice(&[0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[40..42].copy_from_slice(&sport.to_be_bytes());
        packet[42..44].copy_from_slice(&dport.to_be_bytes());
        packet[44..46].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        packet[48..].copy_from_slice(payload);
        let initial = pseudo_sum(IPV6_VERSION, &packet, 8 + payload.len());
        let transport = checksum(&packet[40..], initial);
        packet[46..48].copy_from_slice(&transport.to_be_bytes());
        packet
    }

    fn ipv4_tcp(seq: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 40 + payload.len()];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&((40 + payload.len()) as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = IPPROTO_TCP;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 1]);
        let header = checksum(&packet[..20], 0);
        packet[10..12].copy_from_slice(&header.to_be_bytes());
        packet[20..22].copy_from_slice(&40000u16.to_be_bytes());
        packet[22..24].copy_from_slice(&5201u16.to_be_bytes());
        packet[24..28].copy_from_slice(&seq.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = flags;
        packet[34..36].copy_from_slice(&65535u16.to_be_bytes());
        packet[40..].copy_from_slice(payload);
        let initial = pseudo_sum(4, &packet, 20 + payload.len());
        let transport = checksum(&packet[20..], initial);
        packet[36..38].copy_from_slice(&transport.to_be_bytes());
        packet
    }

    fn icmp4(payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 20 + payload.len()];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let header = checksum(&packet[..20], 0);
        packet[10..12].copy_from_slice(&header.to_be_bytes());
        packet[20..].copy_from_slice(payload);
        packet
    }

    fn fill(batch: &mut RxBatch, packets: &[Vec<u8>]) {
        for packet in packets {
            assert!(batch.push(packet));
        }
    }

    #[test]
    fn equal_udp_packets_become_one_gso_packet() {
        let packets: Vec<Vec<u8>> = (0..3)
            .map(|index| ipv4_udp(index as u16, 1000, 2000, &[b'A' + index as u8; 100]))
            .collect();
        let mut batch = RxBatch::new(256);
        fill(&mut batch, &packets);
        let sink = RecordingSink::new(true);
        batch.flush(&sink);
        let writes = sink.take();
        assert_eq!(writes.len(), 1);
        let write = &writes[0];
        let header = write.header.expect("gso header");
        assert_eq!(header.gso_type, VIRTIO_NET_HDR_GSO_UDP_L4);
        assert_eq!(header.flags, VIRTIO_NET_HDR_F_NEEDS_CSUM);
        assert_eq!(usize::from(header.gso_size), 100);
        assert_eq!(usize::from(header.csum_start), 20);
        assert_eq!(usize::from(header.csum_offset), 6);
        assert_eq!(usize::from(header.hdr_len), 28);
        assert_eq!(write.packet.len(), 28 + 300);
        assert_eq!(write.packet[28], b'A');
        assert_eq!(write.packet[128], b'B');
        assert_eq!(write.packet[228], b'C');
        assert_eq!(
            u16::from_be_bytes([write.packet[2], write.packet[3]]) as usize,
            write.packet.len()
        );
        assert_eq!(checksum(&write.packet[..20], 0), 0);
        let initial = pseudo_sum(4, &write.packet, 8 + 300);
        assert_eq!(checksum(&write.packet[20..], initial), 0);
    }

    #[test]
    fn ipv6_udp_packets_are_coalesced() {
        let packets: Vec<Vec<u8>> = (0..2)
            .map(|index| ipv6_udp(1000, 2000, &[b'A' + index as u8; 64]))
            .collect();
        let mut batch = RxBatch::new(256);
        fill(&mut batch, &packets);
        let sink = RecordingSink::new(true);
        batch.flush(&sink);
        let writes = sink.take();
        assert_eq!(writes.len(), 1);
        let header = writes[0].header.expect("gso header");
        assert_eq!(header.gso_type, VIRTIO_NET_HDR_GSO_UDP_L4);
        assert_eq!(usize::from(header.gso_size), 64);
        assert_eq!(usize::from(header.csum_start), 40);
        assert_eq!(writes[0].packet.len(), 48 + 128);
        assert_eq!(
            checksum(&writes[0].packet[40..], {
                let mut sum = 0u64;
                add_bytes(&mut sum, &writes[0].packet[8..40]);
                sum + 17 + 8 + 128
            }),
            0
        );
    }

    #[test]
    fn different_lengths_are_written_separately() {
        let packets = vec![
            ipv4_udp(1, 1000, 2000, &[b'A'; 100]),
            ipv4_udp(2, 1000, 2000, &[b'A'; 100]),
            ipv4_udp(3, 1000, 2000, &[b'B'; 120]),
            ipv4_udp(4, 1000, 2000, &[b'C'; 100]),
        ];
        let mut batch = RxBatch::new(256);
        fill(&mut batch, &packets);
        let sink = RecordingSink::new(true);
        batch.flush(&sink);
        let writes = sink.take();
        assert_eq!(writes.len(), 3);
        assert!(writes[0].header.is_some());
        assert!(writes[1].header.is_none());
        assert!(writes[2].header.is_none());
        assert_eq!(writes[1].packet.len(), 148);
        assert_eq!(writes[2].packet.len(), 128);
    }

    #[test]
    fn tcp_chain_requires_sequence_continuity() {
        let packets = vec![
            ipv4_tcp(1000, 0x10, &[b'A'; 100]),
            ipv4_tcp(1100, 0x10, &[b'B'; 100]),
            ipv4_tcp(1300, 0x10, &[b'C'; 100]),
        ];
        let mut batch = RxBatch::new(256);
        fill(&mut batch, &packets);
        let sink = RecordingSink::new(true);
        batch.flush(&sink);
        let writes = sink.take();
        assert_eq!(writes.len(), 2);
        let header = writes[0].header.expect("gso header");
        assert_eq!(header.gso_type, VIRTIO_NET_HDR_GSO_TCPV4);
        assert_eq!(usize::from(header.gso_size), 100);
        assert_eq!(usize::from(header.csum_offset), 16);
        assert_eq!(writes[0].packet.len(), 40 + 200);
        assert!(writes[1].header.is_none());
    }

    #[test]
    fn tcp_flags_break_the_chain() {
        let packets = vec![
            ipv4_tcp(1000, 0x10, &[b'A'; 100]),
            ipv4_tcp(1100, 0x18, &[b'B'; 100]),
        ];
        let mut batch = RxBatch::new(256);
        fill(&mut batch, &packets);
        let sink = RecordingSink::new(true);
        batch.flush(&sink);
        let writes = sink.take();
        assert_eq!(writes.len(), 2);
        assert!(writes.iter().all(|write| write.header.is_none()));
    }

    #[test]
    fn different_flows_are_not_coalesced() {
        let packets = vec![
            ipv4_udp(1, 1000, 2000, &[b'A'; 100]),
            ipv4_udp(2, 1000, 2001, &[b'B'; 100]),
        ];
        let mut batch = RxBatch::new(256);
        fill(&mut batch, &packets);
        let sink = RecordingSink::new(true);
        batch.flush(&sink);
        let writes = sink.take();
        assert_eq!(writes.len(), 2);
        assert!(writes.iter().all(|write| write.header.is_none()));
    }

    #[test]
    fn non_udp_and_non_tcp_packets_are_written_separately() {
        let packets = vec![icmp4(&[b'A'; 100]), icmp4(&[b'B'; 100])];
        let mut batch = RxBatch::new(256);
        fill(&mut batch, &packets);
        let sink = RecordingSink::new(true);
        batch.flush(&sink);
        assert_eq!(sink.take().len(), 2);
    }

    #[test]
    fn gso_failure_falls_back_to_single_writes_in_order() {
        let packets: Vec<Vec<u8>> = (0..3)
            .map(|index| ipv4_udp(1, 1000, 2000, &[b'A' + index as u8; 100]))
            .collect();
        let mut batch = RxBatch::new(256);
        fill(&mut batch, &packets);
        let sink = RecordingSink::failing();
        batch.flush(&sink);
        let writes = sink.take();
        assert_eq!(writes.len(), 3);
        assert!(writes.iter().all(|write| write.header.is_none()));
        for (write, packet) in writes.iter().zip(&packets) {
            assert_eq!(&write.packet, packet);
        }
    }

    #[test]
    fn missing_virtio_header_writes_every_packet() {
        let packets: Vec<Vec<u8>> = (0..2)
            .map(|index| ipv4_udp(1, 1000, 2000, &[b'A' + index as u8; 100]))
            .collect();
        let mut batch = RxBatch::new(256);
        fill(&mut batch, &packets);
        let sink = RecordingSink::new(false);
        batch.flush(&sink);
        assert_eq!(sink.take().len(), 2);
    }

    #[test]
    fn oversized_chain_is_split_into_several_gso_packets() {
        let packets: Vec<Vec<u8>> = (0..RX_BATCH)
            .map(|_| ipv4_udp(1, 1000, 2000, &[b'A'; 1200]))
            .collect();
        let mut batch = RxBatch::new(1400);
        fill(&mut batch, &packets);
        let sink = RecordingSink::new(true);
        batch.flush(&sink);
        let writes = sink.take();
        let per_group = (MAX_IP_PACKET - 28) / 1200;
        assert_eq!(writes.len(), RX_BATCH.div_ceil(per_group));
        assert!(writes.iter().all(|write| write.header.is_some()));
        assert!(writes
            .iter()
            .all(|write| write.packet.len() <= MAX_IP_PACKET));
        assert_eq!(
            writes.iter().map(|write| write.packet.len()).sum::<usize>(),
            28 * writes.len() + 1200 * RX_BATCH
        );
    }

    #[test]
    fn fragmented_packets_are_not_coalesced() {
        let mut first = ipv4_udp(1, 1000, 2000, &[b'A'; 100]);
        let second = ipv4_udp(2, 1000, 2000, &[b'B'; 100]);
        first[6] |= 0x20;
        let mut batch = RxBatch::new(256);
        fill(&mut batch, &[first, second]);
        let sink = RecordingSink::new(true);
        batch.flush(&sink);
        assert_eq!(sink.take().len(), 2);
    }

    struct TunSink {
        tun: Tun,
        gso_writes: std::cell::Cell<usize>,
        single_writes: std::cell::Cell<usize>,
    }

    impl PacketSink for TunSink {
        fn gso_supported(&self) -> bool {
            self.tun.vnet_hdr()
        }

        fn write_packet(&self, packet: &[u8]) -> Result<(), TunError> {
            self.single_writes.set(self.single_writes.get() + 1);
            self.tun.write(packet).map(|_| ())
        }

        fn write_gso(&self, header: &VirtioNetHdr, packet: &[u8]) -> Result<(), TunError> {
            self.gso_writes.set(self.gso_writes.get() + 1);
            self.tun.write_with_header(header, packet).map(|_| ())
        }
    }

    #[test]
    fn real_tun_accepts_udp_gso_packet() {
        use umbrawg_tun::{TunConfig, VirtioNetHdr as Header};

        let config = TunConfig::new("uwgrx%d")
            .with_offload(true)
            .with_vnet_hdr_size(Header::LEN);
        let Ok(tun) = Tun::open(&config) else {
            eprintln!("skipping: tun device is unavailable");
            return;
        };
        let up = std::process::Command::new("ip")
            .args(["link", "set", tun.name(), "up"])
            .status()
            .is_ok_and(|status| status.success());
        if !up {
            eprintln!("skipping: cannot bring {} up", tun.name());
            return;
        }
        let packets: Vec<Vec<u8>> = (0..3)
            .map(|index| ipv4_udp(index as u16, 1000, 2000, &[b'A' + index as u8; 128]))
            .collect();
        let mut batch = RxBatch::new(256);
        fill(&mut batch, &packets);
        let sink = TunSink {
            tun,
            gso_writes: std::cell::Cell::new(0),
            single_writes: std::cell::Cell::new(0),
        };
        batch.flush(&sink);
        assert_eq!(sink.gso_writes.get(), 1);
        assert_eq!(sink.single_writes.get(), 0);
    }

    #[test]
    fn batch_reports_overflow_and_resets() {
        let mut batch = RxBatch::new(64);
        assert!(batch.push(&[0u8; 64]));
        assert!(!batch.push(&[0u8; 65]));
        for _ in 0..RX_BATCH - 1 {
            assert!(batch.push(&[0u8; 64]));
        }
        assert!(!batch.push(&[0u8; 64]));
        let sink = RecordingSink::new(true);
        batch.flush(&sink);
        assert!(batch.push(&[0u8; 64]));
    }
}
