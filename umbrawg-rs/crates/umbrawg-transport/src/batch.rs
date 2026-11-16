//! Batch receive/send scratch space.
//!
//! [`RecvQueue`] and [`SendQueue`] own every buffer the kernel needs
//! (`mmsghdr`, `iovec`, control buffers, address storage). Constructing them
//! allocates once; every subsequent `recv_batch`/`send_batch` call runs without
//! allocating.

use std::net::SocketAddr;
use std::os::fd::RawFd;

use crate::addr::{AddressFamily, Endpoint, normalize_ipv4_mapped};
use crate::cmsg;
use crate::gso::{GsoLayout, GsoSize};
use crate::sticky::{self, SourceAddr};
use crate::sys;
use crate::{Result, TransportError, MAX_BATCH_SIZE};

/// A single outgoing datagram.
///
/// `gso_size` marks the datagram as GSO super-packet: the kernel splits it into
/// segments of that size, and the last segment may be shorter.
#[derive(Clone, Copy, Debug)]
pub struct Outgoing<'a> {
    data: &'a [u8],
    gso_size: Option<GsoSize>,
}

impl<'a> Outgoing<'a> {
    /// Creates a plain datagram.
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            gso_size: None,
        }
    }

    /// Creates a GSO super-datagram split into `gso_size` segments.
    pub fn segmented(data: &'a [u8], gso_size: GsoSize) -> Self {
        Self {
            data,
            gso_size: Some(gso_size),
        }
    }

    /// Payload bytes.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Requested GSO segment size, if any.
    pub fn gso_size(&self) -> Option<GsoSize> {
        self.gso_size
    }

    /// Payload length in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` for a zero-length datagram.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// Metadata of a single received datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecvMeta {
    /// Number of payload bytes written into the destination buffer.
    pub size: usize,
    /// Peer address, if the kernel reported one.
    pub endpoint: Option<Endpoint>,
    /// GRO segment size reported through `UDP_GRO`.
    pub gro_size: Option<GsoSize>,
    /// Set when the datagram did not fit into the destination buffer.
    pub truncated: bool,
}

impl RecvMeta {
    /// Creates empty metadata.
    pub const fn new() -> Self {
        Self {
            size: 0,
            endpoint: None,
            gro_size: None,
            truncated: false,
        }
    }

    /// Resets the metadata to its initial state without deallocating.
    pub fn clear(&mut self) {
        *self = Self::new();
    }

    /// Returns `true` when the kernel coalesced several datagrams with `UDP_GRO`.
    pub fn is_gro(&self) -> bool {
        self.gro_size.is_some()
    }

    /// Number of UDP datagrams contained in the received buffer.
    ///
    /// A plain datagram reports one segment, a `UDP_GRO` super-datagram reports
    /// `ceil(size / gro_size)`. The value can be copied into the TUN
    /// `virtio_net_hdr` (`gso_type = VIRTIO_NET_HDR_GSO_UDP_L4`) together with
    /// [`RecvMeta::gro_size`] as the segment length.
    pub fn segments(&self) -> usize {
        if self.size == 0 {
            return 0;
        }
        match self.gro_size {
            Some(gso_size) => self.size.div_ceil(gso_size.as_usize()),
            None => 1,
        }
    }
}

impl Default for RecvMeta {
    fn default() -> Self {
        Self::new()
    }
}

/// Reusable receive batch.
pub struct RecvQueue {
    raw: sys::RecvBatchRaw,
    sizes: Vec<usize>,
    endpoints: Vec<Option<Endpoint>>,
    gro_sizes: Vec<Option<GsoSize>>,
    truncated: Vec<bool>,
    len: usize,
}

impl RecvQueue {
    /// Creates a queue that can hold up to `capacity` datagrams per call.
    ///
    /// The capacity must be in `1..=MAX_BATCH_SIZE`.
    pub fn new(capacity: usize) -> Result<Self> {
        validate_capacity(capacity)?;
        Ok(Self {
            raw: sys::RecvBatchRaw::with_capacity(capacity),
            sizes: vec![0; capacity],
            endpoints: vec![None; capacity],
            gro_sizes: vec![None; capacity],
            truncated: vec![false; capacity],
            len: 0,
        })
    }

    /// Maximum number of datagrams per call.
    pub fn capacity(&self) -> usize {
        self.raw.capacity()
    }

    /// Number of datagrams returned by the last successful receive.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the last receive returned no datagrams.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Number of payload bytes of datagram `index`.
    pub fn size(&self, index: usize) -> Option<usize> {
        self.sizes.get(index).copied().filter(|_| index < self.len)
    }

    /// Peer endpoint of datagram `index`.
    pub fn endpoint(&self, index: usize) -> Option<Endpoint> {
        if index >= self.len {
            return None;
        }
        self.endpoints[index]
    }

    /// GRO segment size of datagram `index`, when receive offload was used.
    pub fn gro_size(&self, index: usize) -> Option<GsoSize> {
        if index >= self.len {
            return None;
        }
        self.gro_sizes[index]
    }

    /// Whether datagram `index` was truncated by the destination buffer.
    pub fn is_truncated(&self, index: usize) -> bool {
        self.truncated.get(index).copied().unwrap_or(false) && index < self.len
    }

    /// Metadata of datagram `index` returned by the last receive.
    pub fn meta(&self, index: usize) -> Option<RecvMeta> {
        if index >= self.len {
            return None;
        }
        Some(RecvMeta {
            size: self.sizes[index],
            endpoint: self.endpoints[index],
            gro_size: self.gro_sizes[index],
            truncated: self.truncated[index],
        })
    }

    /// Forgets the metadata of the previous receive.
    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// Receives one batch into `buffers`.
    pub(crate) fn receive(
        &mut self,
        fd: RawFd,
        family: AddressFamily,
        buffers: &mut [&mut [u8]],
    ) -> Result<usize> {
        if buffers.is_empty() {
            return Err(TransportError::EmptyBatch);
        }
        let count = loop {
            match self.raw.recv(fd, buffers) {
                Ok(count) => break count,
                Err(error) if error.is_interrupted() => continue,
                Err(error) => return Err(error),
            }
        };
        self.len = 0;
        for index in 0..count {
            let control = self.raw.control(index);
            let control_truncated = self.raw.control_truncated(index);
            let (gro_size, source) = if control_truncated {
                (None, None)
            } else {
                (
                    cmsg::gro_size(control)?,
                    sticky::parse_pktinfo(control, family)?,
                )
            };
            self.sizes[index] = self.raw.len(index);
            self.truncated[index] = self.raw.truncated(index);
            self.gro_sizes[index] = gro_size;
            self.endpoints[index] = self
                .raw
                .peer(index)
                .map(|dst| Endpoint::with_optional_source(normalize_ipv4_mapped(dst), source));
        }
        self.len = count;
        Ok(count)
    }
}

/// Reusable send batch.
pub struct SendQueue {
    raw: sys::SendBatchRaw,
}

impl SendQueue {
    /// Creates a queue that can hold up to `capacity` datagrams per call.
    ///
    /// The capacity must be in `1..=MAX_BATCH_SIZE`.
    pub fn new(capacity: usize) -> Result<Self> {
        validate_capacity(capacity)?;
        Ok(Self {
            raw: sys::SendBatchRaw::with_capacity(capacity),
        })
    }

    /// Maximum number of datagrams per call.
    pub fn capacity(&self) -> usize {
        self.raw.capacity()
    }

    /// Sends `datagrams` to `peer` with at most one `sendmmsg` call.
    ///
    /// When `use_gso` is `false`, every GSO super-datagram is split into its
    /// segments and sent individually; this is the fallback used when the kernel
    /// or the egress device rejects `UDP_SEGMENT`. A short result means the
    /// socket started blocking and the caller may retry from that index.
    pub(crate) fn send(
        &mut self,
        fd: RawFd,
        peer: SocketAddr,
        source: Option<SourceAddr>,
        family: AddressFamily,
        datagrams: &[Outgoing<'_>],
        use_gso: bool,
    ) -> Result<usize> {
        if datagrams.is_empty() {
            return Err(TransportError::EmptyBatch);
        }
        if datagrams.len() > self.capacity() {
            return Err(TransportError::BatchTooLarge {
                count: datagrams.len(),
                max: self.capacity(),
            });
        }
        let max_payload = family.max_udp_payload();
        for datagram in datagrams {
            sys::check_datagram_size(datagram.len(), max_payload)?;
            if let Some(gso_size) = datagram.gso_size() {
                GsoLayout::for_payload(datagram.len(), gso_size)?;
            }
        }
        if !use_gso && datagrams.iter().any(|datagram| datagram.gso_size().is_some()) {
            return self.send_split(fd, peer, source, datagrams);
        }
        self.raw.send(fd, peer, source, datagrams)
    }

    /// Sends each GSO datagram as a sequence of individual segments.
    ///
    /// The segments are subslices of the original buffer, so this path does not
    /// copy or allocate. It is only used when `UDP_SEGMENT` is unavailable.
    fn send_split(
        &self,
        fd: RawFd,
        peer: SocketAddr,
        source: Option<SourceAddr>,
        datagrams: &[Outgoing<'_>],
    ) -> Result<usize> {
        let mut completed = 0usize;
        for datagram in datagrams {
            match datagram.gso_size() {
                Some(gso_size) => {
                    let layout = GsoLayout::for_payload(datagram.len(), gso_size)?;
                    for range in layout.ranges() {
                        let segment = &datagram.data()[range];
                        match sys::sendmsg_single(
                            fd,
                            peer,
                            sys::SendDatagram {
                                data: segment,
                                gso_size: None,
                                source,
                            },
                        ) {
                            Ok(_) => {}
                            Err(error) if error.is_would_block() => return Ok(completed),
                            Err(error) => return Err(error),
                        }
                    }
                }
                None => match sys::sendmsg_single(
                    fd,
                    peer,
                    sys::SendDatagram {
                        data: datagram.data(),
                        gso_size: None,
                        source,
                    },
                ) {
                    Ok(_) => {}
                    Err(error) if error.is_would_block() => return Ok(completed),
                    Err(error) => return Err(error),
                },
            }
            completed += 1;
        }
        Ok(completed)
    }
}

impl core::fmt::Debug for RecvQueue {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RecvQueue")
            .field("capacity", &self.capacity())
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for SendQueue {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SendQueue")
            .field("capacity", &self.capacity())
            .finish_non_exhaustive()
    }
}

fn validate_capacity(capacity: usize) -> Result<()> {
    if capacity == 0 {
        return Err(TransportError::EmptyBatch);
    }
    if capacity > MAX_BATCH_SIZE {
        return Err(TransportError::BatchTooLarge {
            count: capacity,
            max: MAX_BATCH_SIZE,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_is_validated() {
        assert!(matches!(
            RecvQueue::new(0),
            Err(TransportError::EmptyBatch)
        ));
        assert!(matches!(
            SendQueue::new(0),
            Err(TransportError::EmptyBatch)
        ));
        assert!(matches!(
            RecvQueue::new(MAX_BATCH_SIZE + 1),
            Err(TransportError::BatchTooLarge { .. })
        ));
        assert!(matches!(
            SendQueue::new(MAX_BATCH_SIZE + 1),
            Err(TransportError::BatchTooLarge { .. })
        ));
        let queue = RecvQueue::new(MAX_BATCH_SIZE).unwrap();
        assert_eq!(queue.capacity(), MAX_BATCH_SIZE);
        assert!(queue.is_empty());
        assert_eq!(queue.size(0), None);
        assert_eq!(queue.endpoint(0), None);
        assert_eq!(queue.gro_size(0), None);
        assert!(!queue.is_truncated(0));
    }

    #[test]
    fn outgoing_keeps_payload_description() {
        let data = [0u8; 32];
        let plain = Outgoing::new(&data);
        assert_eq!(plain.data(), &data);
        assert_eq!(plain.gso_size(), None);
        assert_eq!(plain.len(), 32);
        assert!(!plain.is_empty());

        let gso = GsoSize::new(16).unwrap();
        let segmented = Outgoing::segmented(&data, gso);
        assert_eq!(segmented.gso_size(), Some(gso));
        assert!(Outgoing::new(&[]).is_empty());
    }

    #[test]
    fn recv_meta_is_reset() {
        let mut meta = RecvMeta::new();
        meta.size = 10;
        meta.truncated = true;
        meta.clear();
        assert_eq!(meta, RecvMeta::default());
        assert_eq!(meta.size, 0);
    }
}
