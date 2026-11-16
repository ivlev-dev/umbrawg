//! Накопитель исходящих датаграмм для одного рабочего потока.

use std::net::SocketAddr;

use umbrawg_device::{BatchLayout, GsoGroup};
use umbrawg_transport::{Endpoint, GsoSize, Outgoing, SendQueue, Socket, TransportError};

/// Максимальное число датаграмм в одном вызове `sendmmsg`.
pub const MAX_OUTGOING: usize = 64;

/// Максимальное число GSO-групп в одном накопителе.
pub const MAX_GROUPS: usize = 64;

const MAX_SEND_ATTEMPTS: usize = 8;
const SEND_POLL_TIMEOUT_MS: i32 = 1;

/// Ограничения сокета, влияющие на планировку GSO-датаграмм.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentLimits {
    /// Максимальный размер одной GSO-датаграммы.
    pub max_datagram_len: usize,
    /// Максимальное число сегментов в одной GSO-датаграмме.
    pub max_segments: usize,
    /// Максимальный размер одного сегмента.
    pub max_gso_size: usize,
}

impl SegmentLimits {
    /// Собирает ограничения из открытого сокета.
    pub fn from_socket(socket: &Socket) -> Self {
        Self {
            max_datagram_len: socket.max_datagram_len(),
            max_segments: socket.max_segments(),
            max_gso_size: socket.max_gso_size(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PeerBatch {
    endpoint: SocketAddr,
    first_group: usize,
    group_count: usize,
}

/// Накопитель зашифрованных датаграмм с группировкой по пиру.
pub struct TxBatch {
    queue: SendQueue,
    groups: Vec<GsoGroup>,
    peers: Vec<PeerBatch>,
    used: usize,
    dropped: usize,
}

impl TxBatch {
    /// Создаёт накопитель с очередью `sendmmsg` на `capacity` датаграмм.
    pub fn new(capacity: usize) -> Result<Self, TransportError> {
        Ok(Self {
            queue: SendQueue::new(capacity)?,
            groups: Vec::with_capacity(MAX_GROUPS),
            peers: Vec::new(),
            used: 0,
            dropped: 0,
        })
    }

    /// Сбрасывает накопленные группы, не трогая выделенную память.
    pub fn clear(&mut self) {
        self.groups.clear();
        self.peers.clear();
        self.used = 0;
        self.dropped = 0;
    }

    /// Возвращает `true`, если отправлять нечего.
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// Число байт, занятых под зашифрованные датаграммы.
    pub fn used(&self) -> usize {
        self.used
    }

    /// Добавляет группы `layout`, записанные в буфер начиная со смещения `base`.
    ///
    /// Возвращает `false`, если накопитель переполнен: вызывающий обязан
    /// отправить накопленное и повторить добавление.
    pub fn push(&mut self, endpoint: SocketAddr, base: usize, layout: &BatchLayout) -> bool {
        if layout.is_empty() {
            return true;
        }
        if self.groups.len() + layout.len() > MAX_GROUPS {
            return false;
        }
        let same_peer = self
            .peers
            .last()
            .is_some_and(|peer| peer.endpoint == endpoint);
        let mut pushed = 0;
        for group in layout.groups() {
            let start = group.start + base;
            let merged = same_peer
                && self.groups.last().is_some_and(|last| {
                    last.segment_len == group.segment_len && last.end() == start
                });
            if merged {
                if let Some(last) = self.groups.last_mut() {
                    last.segments += group.segments;
                }
                continue;
            }
            self.groups.push(GsoGroup {
                start,
                segment_len: group.segment_len,
                segments: group.segments,
            });
            pushed += 1;
        }
        if same_peer {
            if let Some(last) = self.peers.last_mut() {
                last.group_count += pushed;
            }
        } else {
            self.peers.push(PeerBatch {
                endpoint,
                first_group: self.groups.len() - pushed,
                group_count: pushed,
            });
        }
        self.used = self.used.max(base + layout.total_len());
        true
    }

    /// Отправляет накопленное одним `sendmmsg` на пира и очищает накопитель.
    ///
    /// Короткий результат `sendmmsg` досылается повтором остатка. Если сокет
    /// остаётся неготовым после нескольких попыток, остаток отбрасывается:
    /// дейтаграммы UDP и так не гарантируют доставку.
    pub fn flush(&mut self, socket: &Socket, buffer: &[u8]) -> usize {
        self.flush_tracked(socket, buffer).0
    }

    pub fn flush_tracked(&mut self, socket: &Socket, buffer: &[u8]) -> (usize, usize) {
        if self.groups.is_empty() {
            self.clear();
            return (0, 0);
        }
        let limits = SegmentLimits::from_socket(socket);
        let gso = socket.gso_enabled();
        let mut sent = 0;
        let mut outgoings = [Outgoing::new(&[]); MAX_OUTGOING];
        for index in 0..self.peers.len() {
            let peer = self.peers[index];
            let mut pending = 0usize;
            for offset in 0..peer.group_count {
                let group = self.groups[peer.first_group + offset];
                while !append_group(&mut outgoings, &mut pending, buffer, group, limits, gso) {
                    if pending == 0 {
                        break;
                    }
                    sent += self.send(socket, peer.endpoint, &outgoings[..pending]);
                    pending = 0;
                }
            }
            if pending > 0 {
                sent += self.send(socket, peer.endpoint, &outgoings[..pending]);
            }
        }
        let dropped = self.dropped;
        self.clear();
        (sent, dropped)
    }

    fn send(&mut self, socket: &Socket, endpoint: SocketAddr, outgoings: &[Outgoing<'_>]) -> usize {
        let mut sent = 0;
        let mut remaining = outgoings;
        let mut attempts = 0;
        while !remaining.is_empty() {
            match socket.send_batch(&mut self.queue, Endpoint::new(endpoint), remaining) {
                Ok(0) => {
                    attempts += 1;
                    if attempts > MAX_SEND_ATTEMPTS {
                        log::debug!("send batch made no progress to {endpoint}");
                        self.dropped += remaining.len();
                        break;
                    }
                }
                Ok(count) => {
                    attempts = 0;
                    sent += count;
                    remaining = &remaining[count..];
                }
                Err(error) if error.is_would_block() => {
                    attempts += 1;
                    if attempts > MAX_SEND_ATTEMPTS {
                        log::debug!("send batch is blocked on {endpoint}");
                        self.dropped += remaining.len();
                        break;
                    }
                    wait_writable(socket);
                }
                Err(error) => {
                    log::debug!("send batch to {endpoint} failed: {error}");
                    self.dropped += remaining.len();
                    break;
                }
            }
        }
        sent
    }
}

fn wait_writable(socket: &Socket) {
    let mut fd = libc::pollfd {
        fd: socket.fd(),
        events: libc::POLLOUT,
        revents: 0,
    };
    unsafe {
        libc::poll(&mut fd, 1, SEND_POLL_TIMEOUT_MS);
    }
}

fn append_group<'a>(
    out: &mut [Outgoing<'a>],
    pending: &mut usize,
    buffer: &'a [u8],
    group: GsoGroup,
    limits: SegmentLimits,
    gso: bool,
) -> bool {
    if group.is_empty() {
        return true;
    }
    let Some(data) = buffer.get(group.start..group.end()) else {
        return true;
    };
    let segment_len = group.segment_len;
    let (per_datagram, gso_size) = if gso && segment_len <= limits.max_gso_size {
        let per_datagram = limits
            .max_segments
            .min(limits.max_datagram_len / segment_len)
            .max(1);
        let gso_size = GsoSize::from_usize(segment_len).ok();
        match gso_size {
            Some(size) if per_datagram > 1 => (per_datagram, Some(size)),
            _ => (1, None),
        }
    } else {
        (1, None)
    };
    let count = group.segments.div_ceil(per_datagram);
    if *pending + count > out.len() {
        return false;
    }
    let mut index = 0;
    while index < group.segments {
        let chunk = per_datagram.min(group.segments - index);
        let start = index * segment_len;
        let slice = &data[start..start + chunk * segment_len];
        out[*pending] = match gso_size {
            Some(size) if chunk > 1 => Outgoing::segmented(slice, size),
            _ => Outgoing::new(slice),
        };
        *pending += 1;
        index += chunk;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use umbrawg_device::GsoGroup;

    const DATA: [u8; 4096] = [0x5a; 4096];

    fn limits(max_datagram_len: usize, max_segments: usize, max_gso_size: usize) -> SegmentLimits {
        SegmentLimits {
            max_datagram_len,
            max_segments,
            max_gso_size,
        }
    }

    #[test]
    fn equal_segments_become_one_gso_datagram() {
        let mut out = [Outgoing::new(&[]); MAX_OUTGOING];
        let mut pending = 0;
        let group = GsoGroup {
            start: 0,
            segment_len: 100,
            segments: 3,
        };
        assert!(append_group(
            &mut out,
            &mut pending,
            &DATA,
            group,
            limits(4000, 30, 1400),
            true
        ));
        assert_eq!(pending, 1);
        assert_eq!(out[0].len(), 300);
        assert_eq!(
            out[0].gso_size(),
            Some(GsoSize::new(100).expect("segment size is non-zero"))
        );
    }

    #[test]
    fn single_segment_groups_are_sent_plain() {
        let mut out = [Outgoing::new(&[]); MAX_OUTGOING];
        let mut pending = 0;
        let group = GsoGroup {
            start: 0,
            segment_len: 100,
            segments: 1,
        };
        assert!(append_group(
            &mut out,
            &mut pending,
            &DATA,
            group,
            limits(4000, 30, 1400),
            true
        ));
        assert_eq!(pending, 1);
        assert_eq!(out[0].gso_size(), None);
        assert_eq!(out[0].len(), 100);
    }

    #[test]
    fn max_datagram_len_splits_gso_groups() {
        let mut out = [Outgoing::new(&[]); MAX_OUTGOING];
        let mut pending = 0;
        let group = GsoGroup {
            start: 0,
            segment_len: 100,
            segments: 5,
        };
        assert!(append_group(
            &mut out,
            &mut pending,
            &DATA,
            group,
            limits(250, 30, 1400),
            true
        ));
        assert_eq!(pending, 3);
        assert_eq!(out[0].len(), 200);
        assert_eq!(out[0].gso_size(), Some(GsoSize::new(100).unwrap()));
        assert_eq!(out[1].len(), 200);
        assert_eq!(out[2].len(), 100);
        assert_eq!(out[2].gso_size(), None);
    }

    #[test]
    fn max_segments_splits_gso_groups() {
        let mut out = [Outgoing::new(&[]); MAX_OUTGOING];
        let mut pending = 0;
        let group = GsoGroup {
            start: 0,
            segment_len: 100,
            segments: 5,
        };
        assert!(append_group(
            &mut out,
            &mut pending,
            &DATA,
            group,
            limits(100_000, 2, 1400),
            true
        ));
        assert_eq!(pending, 3);
        assert_eq!(out[0].len(), 200);
        assert_eq!(out[1].len(), 200);
        assert_eq!(out[2].len(), 100);
    }

    #[test]
    fn disabled_gso_sends_every_segment_plain() {
        let mut out = [Outgoing::new(&[]); MAX_OUTGOING];
        let mut pending = 0;
        let group = GsoGroup {
            start: 0,
            segment_len: 100,
            segments: 4,
        };
        assert!(append_group(
            &mut out,
            &mut pending,
            &DATA,
            group,
            limits(100_000, 30, 1400),
            false
        ));
        assert_eq!(pending, 4);
        assert!(out[..4]
            .iter()
            .all(|outgoing| outgoing.gso_size().is_none()));
        assert_eq!(out[3].len(), 100);
    }

    #[test]
    fn oversized_segment_skips_gso() {
        let mut out = [Outgoing::new(&[]); MAX_OUTGOING];
        let mut pending = 0;
        let group = GsoGroup {
            start: 0,
            segment_len: 1500,
            segments: 2,
        };
        assert!(append_group(
            &mut out,
            &mut pending,
            &DATA,
            group,
            limits(6000, 30, 1400),
            true
        ));
        assert_eq!(pending, 2);
        assert!(out[..2]
            .iter()
            .all(|outgoing| outgoing.gso_size().is_none()));
    }

    #[test]
    fn append_group_reports_overflow() {
        let mut out = [Outgoing::new(&[]); 2];
        let mut pending = 0;
        let group = GsoGroup {
            start: 0,
            segment_len: 100,
            segments: 3,
        };
        assert!(!append_group(
            &mut out,
            &mut pending,
            &DATA,
            group,
            limits(100_000, 30, 1400),
            false
        ));
        assert_eq!(pending, 0);
    }

    #[test]
    fn append_group_skips_out_of_bounds_data() {
        let mut out = [Outgoing::new(&[]); MAX_OUTGOING];
        let mut pending = 0;
        let group = GsoGroup {
            start: 4000,
            segment_len: 100,
            segments: 3,
        };
        assert!(append_group(
            &mut out,
            &mut pending,
            &DATA,
            group,
            limits(4000, 30, 1400),
            true
        ));
        assert_eq!(pending, 0);
    }

    fn layout(segments: &[(usize, usize)]) -> BatchLayout {
        let mut layout = BatchLayout::new();
        let mut offset = 0;
        for (len, count) in segments {
            for _ in 0..*count {
                assert!(layout.push(offset, *len));
                offset += *len;
            }
        }
        layout
    }

    #[test]
    fn push_tracks_offsets_and_peers() {
        let mut batch = TxBatch::new(MAX_OUTGOING).unwrap();
        let first: SocketAddr = "10.0.0.1:1111".parse().unwrap();
        assert!(batch.push(first, 0, &layout(&[(100, 2)])));
        assert_eq!(batch.used(), 200);
        assert_eq!(batch.peers.len(), 1);
        assert_eq!(batch.groups.len(), 1);
        assert_eq!(batch.groups[0].start, 0);
        assert_eq!(batch.groups[0].segments, 2);

        assert!(batch.push(first, 200, &layout(&[(100, 2)])));
        assert_eq!(batch.used(), 400);
        assert_eq!(batch.peers.len(), 1);
        assert_eq!(batch.peers[0].group_count, 1);
        assert_eq!(batch.groups.len(), 1);
        assert_eq!(batch.groups[0].segments, 4);

        let second: SocketAddr = "10.0.0.2:2222".parse().unwrap();
        assert!(batch.push(second, 400, &layout(&[(100, 1)])));
        assert_eq!(batch.peers.len(), 2);
        assert_eq!(batch.groups.len(), 2);
        assert_eq!(batch.groups[1].start, 400);

        assert!(batch.push(second, 500, &layout(&[(100, 2)])));
        assert_eq!(batch.peers.len(), 2);
        assert_eq!(batch.groups.len(), 2);
        assert_eq!(batch.groups[1].segments, 3);

        batch.clear();
        assert!(batch.is_empty());
        assert_eq!(batch.used(), 0);
    }

    fn distinct_groups(count: usize) -> BatchLayout {
        let mut layout = BatchLayout::new();
        let mut offset = 0;
        for index in 0..count {
            let segment_len = index + 1;
            assert!(layout.push(offset, segment_len));
            offset += segment_len;
        }
        layout
    }

    #[test]
    fn push_keeps_different_lengths_in_separate_groups() {
        let mut batch = TxBatch::new(MAX_OUTGOING).unwrap();
        let endpoint: SocketAddr = "10.0.0.1:1111".parse().unwrap();
        assert!(batch.push(endpoint, 0, &layout(&[(100, 3)])));
        assert!(batch.push(endpoint, 300, &layout(&[(120, 2)])));
        assert!(batch.push(endpoint, 540, &layout(&[(100, 1)])));
        assert_eq!(batch.groups.len(), 3);
        assert_eq!(batch.peers[0].group_count, 3);
        assert_eq!(batch.groups[0].segment_len, 100);
        assert_eq!(batch.groups[0].segments, 3);
        assert_eq!(batch.groups[1].segment_len, 120);
        assert_eq!(batch.groups[2].segment_len, 100);
        assert_eq!(batch.groups[2].segments, 1);
    }

    #[test]
    fn push_does_not_merge_across_peers() {
        let mut batch = TxBatch::new(MAX_OUTGOING).unwrap();
        let first: SocketAddr = "10.0.0.1:1111".parse().unwrap();
        let second: SocketAddr = "10.0.0.2:2222".parse().unwrap();
        assert!(batch.push(first, 0, &layout(&[(100, 1)])));
        assert!(batch.push(second, 100, &layout(&[(100, 1)])));
        assert!(batch.push(first, 200, &layout(&[(100, 1)])));
        assert_eq!(batch.groups.len(), 3);
        assert_eq!(batch.peers.len(), 3);
        assert!(batch.groups.iter().all(|group| group.segments == 1));
    }

    #[test]
    fn push_rejects_overflow_without_partial_state() {
        let mut batch = TxBatch::new(MAX_OUTGOING).unwrap();
        let endpoint: SocketAddr = "10.0.0.1:1111".parse().unwrap();
        assert!(batch.push(endpoint, 0, &distinct_groups(MAX_GROUPS)));
        assert_eq!(batch.groups.len(), MAX_GROUPS);
        let used = batch.used();
        assert!(!batch.push(endpoint, used, &layout(&[(10, 1)])));
        assert_eq!(batch.groups.len(), MAX_GROUPS);
        assert_eq!(batch.used(), used);
    }
}
