//! UDP socket wrapper with dual-stack binding and GSO/GRO offload.
//!
//! [`Socket`] owns one `AF_INET` or `AF_INET6` datagram socket. It applies the
//! options the data path needs before exposing it: non-blocking mode, packet
//! information for sticky sockets, `SO_MARK`, `SO_BINDTODEVICE`, socket buffer
//! sizes, path MTU discovery, and the UDP segmentation/receive offloads.
//!
//! Sockets are always created with `SOCK_NONBLOCK | SOCK_CLOEXEC`. The batch
//! entry points additionally pass `MSG_DONTWAIT` so a caller can use the same
//! code with a descriptor it did not create.

use core::fmt;
use std::net::SocketAddr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::addr::{address_for_socket, normalize_ipv4_mapped, AddressFamily, Endpoint};
use crate::batch::{Outgoing, RecvQueue, SendQueue};
use crate::cmsg::{self, ControlBuffer};
use crate::consts::{
    IP_PMTUDISC_DO, IP_PMTUDISC_DONT, IP_PMTUDISC_OMIT, IP_PMTUDISC_PROBE, IP_PMTUDISC_WANT,
};
use crate::gso::{GsoLayout, GsoLimits, GsoSize, DEFAULT_MTU};
use crate::sticky::{self, SourceAddr};
use crate::sys;
use crate::{Result, TransportError};

/// Offload features available on an open socket.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Features {
    /// `UDP_SEGMENT` (transmit GSO) can be used on this socket.
    pub gso: bool,
    /// `UDP_GRO` (receive offload) is enabled on this socket.
    pub gro: bool,
}

/// Path MTU discovery policy for `IP_MTU_DISCOVER`/`IPV6_MTU_DISCOVER`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MtuDiscover {
    /// Use the `DF` bit only when the route asks for it.
    Want,
    /// Always set `DF`.
    Do,
    /// Never set `DF` and allow local fragmentation.
    Dont,
    /// Always set `DF`, ignoring the route MTU.
    Probe,
    /// Never set `DF`, leaving fragmentation to the network.
    Omit,
}

impl MtuDiscover {
    fn value(self) -> libc::c_int {
        match self {
            Self::Dont => IP_PMTUDISC_DONT,
            Self::Want => IP_PMTUDISC_WANT,
            Self::Do => IP_PMTUDISC_DO,
            Self::Probe => IP_PMTUDISC_PROBE,
            Self::Omit => IP_PMTUDISC_OMIT,
        }
    }
}

/// Builder for [`Socket::open`].
#[derive(Clone, Debug)]
pub struct OpenOptions {
    family: AddressFamily,
    port: u16,
    dual_stack: bool,
    reuse_address: bool,
    reuse_port: bool,
    mark: Option<u32>,
    bind_to_device: Option<String>,
    recv_buffer: Option<usize>,
    send_buffer: Option<usize>,
    mtu_discover: Option<MtuDiscover>,
    mtu: Option<u32>,
    gso_limits: Option<GsoLimits>,
    gro: bool,
    nonblocking: bool,
}

impl OpenOptions {
    /// Creates options for a socket of `family` bound to an ephemeral port.
    ///
    /// `SO_REUSEADDR` is enabled, the socket is non-blocking, and `UDP_GRO` is
    /// requested when the kernel supports it. `IPV6_V6ONLY` stays enabled for
    /// IPv6 sockets until [`OpenOptions::dual_stack`] is called.
    pub fn new(family: AddressFamily) -> Self {
        Self {
            family,
            port: 0,
            dual_stack: false,
            reuse_address: true,
            reuse_port: false,
            mark: None,
            bind_to_device: None,
            recv_buffer: None,
            send_buffer: None,
            mtu_discover: None,
            mtu: None,
            gso_limits: None,
            gro: true,
            nonblocking: true,
        }
    }

    /// Sets the UDP port to bind (`0` selects an ephemeral port).
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Allows an IPv6 socket to accept IPv4-mapped traffic by clearing
    /// `IPV6_V6ONLY`. Ignored for IPv4 sockets.
    pub fn dual_stack(mut self, dual_stack: bool) -> Self {
        self.dual_stack = dual_stack;
        self
    }

    /// Enables or disables `SO_REUSEADDR`.
    pub fn reuse_address(mut self, reuse_address: bool) -> Self {
        self.reuse_address = reuse_address;
        self
    }

    /// Enables `SO_REUSEPORT`, required to bind several queues to one port.
    pub fn reuse_port(mut self, reuse_port: bool) -> Self {
        self.reuse_port = reuse_port;
        self
    }

    /// Sets the `fwmark` through `SO_MARK`; requires `CAP_NET_ADMIN`.
    pub fn mark(mut self, mark: u32) -> Self {
        self.mark = Some(mark);
        self
    }

    /// Pins the socket to a network interface through `SO_BINDTODEVICE`.
    pub fn bind_to_device(mut self, interface: impl Into<String>) -> Self {
        self.bind_to_device = Some(interface.into());
        self
    }

    /// Sets the requested `SO_RCVBUF` size in bytes.
    pub fn receive_buffer(mut self, bytes: usize) -> Self {
        self.recv_buffer = Some(bytes);
        self
    }

    /// Sets the requested `SO_SNDBUF` size in bytes.
    pub fn send_buffer(mut self, bytes: usize) -> Self {
        self.send_buffer = Some(bytes);
        self
    }

    /// Selects a path MTU discovery policy.
    pub fn mtu_discover(mut self, mode: MtuDiscover) -> Self {
        self.mtu_discover = Some(mode);
        self
    }

    /// Overrides the MTU used for GSO limits when the socket is not bound to a
    /// device and the interface MTU is not otherwise known.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Overrides the GSO limits derived from the interface MTU.
    pub fn gso_limits(mut self, limits: GsoLimits) -> Self {
        self.gso_limits = Some(limits);
        self
    }

    /// Enables or disables `UDP_GRO` request.
    pub fn gro(mut self, gro: bool) -> Self {
        self.gro = gro;
        self
    }

    /// Enables or disables `O_NONBLOCK` (enabled by default).
    pub fn nonblocking(mut self, nonblocking: bool) -> Self {
        self.nonblocking = nonblocking;
        self
    }
}

/// An open, bound UDP socket with offload metadata.
pub struct Socket {
    fd: std::os::fd::OwnedFd,
    family: AddressFamily,
    local: SocketAddr,
    mtu: u32,
    limits: GsoLimits,
    gso_enabled: AtomicBool,
    max_segments_limit: AtomicUsize,
    gro: bool,
}

impl Socket {
    /// Opens and binds a socket according to `options`.
    pub fn open(options: OpenOptions) -> Result<Self> {
        let fd = sys::create_socket(options.family)?;
        let raw = fd.as_raw_fd();

        if options.family.is_ipv6() {
            sys::set_v6only(raw, !options.dual_stack)?;
        }
        if options.reuse_address {
            sys::set_reuse_address(raw)?;
        }
        if options.reuse_port {
            sys::set_reuse_port(raw)?;
        }
        if let Some(mark) = options.mark {
            sys::set_mark(raw, mark)?;
        }
        if let Some(interface) = options.bind_to_device.as_deref() {
            sys::bind_to_device(raw, interface)?;
        }
        if let Some(size) = options.recv_buffer {
            sys::set_receive_buffer(raw, size)?;
        }
        if let Some(size) = options.send_buffer {
            sys::set_send_buffer(raw, size)?;
        }

        let bind_address = match options.family {
            AddressFamily::Ipv4 => SocketAddr::from(([0, 0, 0, 0], options.port)),
            AddressFamily::Ipv6 => SocketAddr::from(([0u16; 8], options.port)),
        };
        sys::bind_socket(raw, bind_address)?;

        if !options.nonblocking {
            sys::set_nonblocking(raw, false)?;
        }
        if let Some(mode) = options.mtu_discover {
            sys::set_mtu_discover(raw, options.family, mode.value())?;
        }
        sys::enable_pktinfo(raw, options.family)?;

        let gro = options.gro && sys::enable_gro(raw);
        let gso = sys::supports_gso(raw);
        let local = sys::local_addr(raw)?;
        let mtu = match options.bind_to_device.as_deref() {
            Some(interface) => sys::interface_mtu(raw, interface).unwrap_or(DEFAULT_MTU),
            None => options.mtu.unwrap_or(DEFAULT_MTU),
        };
        let limits = options
            .gso_limits
            .unwrap_or_else(|| GsoLimits::from_mtu(mtu, options.family));

        Ok(Self {
            fd,
            family: options.family,
            local,
            mtu,
            limits,
            gso_enabled: AtomicBool::new(gso),
            max_segments_limit: AtomicUsize::new(usize::MAX),
            gro,
        })
    }

    /// Opens a socket of `family` bound to `port` with default options.
    pub fn bind(family: AddressFamily, port: u16) -> Result<Self> {
        Self::open(OpenOptions::new(family).port(port))
    }

    /// Address family of the socket.
    pub fn family(&self) -> AddressFamily {
        self.family
    }

    /// Bound local address, including the actual ephemeral port.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Raw descriptor, suitable for `poll(2)` or `epoll(7)`.
    pub fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Effective offload features after opening the socket.
    pub fn features(&self) -> Features {
        Features {
            gso: self.gso_enabled.load(Ordering::Relaxed),
            gro: self.gro,
        }
    }

    /// Returns `true` while transmit GSO is still enabled.
    pub fn gso_enabled(&self) -> bool {
        self.gso_enabled.load(Ordering::Relaxed)
    }

    /// Disables transmit GSO permanently for this socket.
    pub fn disable_gso(&self) {
        self.gso_enabled.store(false, Ordering::Relaxed);
    }

    /// Returns `true` when `UDP_GRO` was enabled at open time.
    pub fn gro_enabled(&self) -> bool {
        self.gro
    }

    /// MTU used to derive the GSO limits.
    pub fn mtu(&self) -> u32 {
        self.mtu
    }

    /// GSO limits for the socket address family.
    pub fn gso_limits(&self) -> GsoLimits {
        self.limits
    }

    /// GSO limits for a concrete peer family.
    ///
    /// A dual-stack IPv6 socket can carry IPv4-mapped traffic, whose headers are
    /// smaller, so the segment size differs from [`Socket::gso_limits`].
    pub fn gso_limits_for(&self, family: AddressFamily) -> GsoLimits {
        GsoLimits::from_mtu(self.mtu, family)
    }

    /// Replaces the GSO limits, for example with values probed from the path MTU.
    pub fn set_gso_limits(&mut self, limits: GsoLimits) {
        self.limits = limits;
    }

    /// Maximum GSO segment size in bytes.
    pub fn max_gso_size(&self) -> usize {
        self.limits.max_gso_size()
    }

    /// Maximum number of segments in one GSO super-datagram.
    pub fn max_segments(&self) -> usize {
        self.limits
            .max_segments()
            .min(self.max_segments_limit.load(Ordering::Relaxed))
    }

    /// Caps how many segments a single GSO datagram may carry.
    pub fn limit_gso_segments(&self, segments: usize) {
        self.max_segments_limit
            .store(segments.max(1), Ordering::Relaxed);
    }

    /// Maximum size of a GSO super-datagram in bytes.
    pub fn max_datagram_len(&self) -> usize {
        self.limits.max_datagram_len(self.family)
    }

    /// Reads the MTU of `interface` through this socket.
    pub fn interface_mtu(&self, interface: &str) -> Result<u32> {
        sys::interface_mtu(self.fd(), interface)
    }

    /// Applies a new `SO_MARK` to the socket.
    pub fn set_mark(&self, mark: u32) -> Result<()> {
        sys::set_mark(self.fd(), mark)
    }

    /// Pins the socket to `interface` through `SO_BINDTODEVICE`.
    pub fn bind_to_device(&self, interface: &str) -> Result<()> {
        sys::bind_to_device(self.fd(), interface)
    }

    /// Toggles `O_NONBLOCK` on the descriptor.
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        sys::set_nonblocking(self.fd(), nonblocking)
    }

    /// Receives up to `buffers.len()` datagrams with one `recvmmsg` call.
    ///
    /// On success the returned count is also available through
    /// [`RecvQueue::len`]; metadata for each datagram is read with
    /// [`RecvQueue::meta`]. A full batch means the caller should loop; an empty
    /// socket reports [`TransportError::WouldBlock`].
    pub fn recv_batch(&self, queue: &mut RecvQueue, buffers: &mut [&mut [u8]]) -> Result<usize> {
        if buffers.len() > queue.capacity() {
            return Err(TransportError::BatchTooLarge {
                count: buffers.len(),
                max: queue.capacity(),
            });
        }
        queue.receive(self.fd(), self.family, buffers)
    }

    /// Sends `datagrams` to `endpoint` with one `sendmmsg` call.
    ///
    /// When the kernel rejects `UDP_SEGMENT`, GSO is disabled for the socket and
    /// the batch is retried once with every super-datagram split into plain
    /// datagrams. The returned count is the number of leading `datagrams` fully
    /// accepted by the kernel; a short count is a partial send.
    pub fn send_batch(
        &self,
        queue: &mut SendQueue,
        endpoint: Endpoint,
        datagrams: &[Outgoing<'_>],
    ) -> Result<usize> {
        let peer = address_for_socket(endpoint.dst(), self.family);
        let family = AddressFamily::of(endpoint.dst());
        let use_gso = self.gso_enabled.load(Ordering::Relaxed)
            && datagrams.iter().all(|datagram| match datagram.gso_size() {
                Some(gso_size) => {
                    gso_size.get() as usize <= self.max_gso_size()
                        && datagram.len() <= self.max_datagram_len()
                }
                None => true,
            });
        let result = queue.send(
            self.fd(),
            peer,
            endpoint.source(),
            family,
            datagrams,
            use_gso,
        );
        match result {
            Ok(count) => Ok(count),
            Err(error)
                if use_gso
                    && error.should_disable_gso()
                    && datagrams
                        .iter()
                        .any(|datagram| datagram.gso_size().is_some()) =>
            {
                self.gso_enabled.store(false, Ordering::Relaxed);
                queue.send(self.fd(), peer, endpoint.source(), family, datagrams, false)
            }
            Err(error) => Err(error),
        }
    }

    /// Sends a single datagram, optionally as a GSO super-datagram.
    ///
    /// This is a convenience wrapper around `sendmsg` for control traffic and
    /// tests; the hot path uses [`Socket::send_batch`].
    pub fn send_to(
        &self,
        endpoint: Endpoint,
        data: &[u8],
        gso_size: Option<GsoSize>,
    ) -> Result<usize> {
        let peer = address_for_socket(endpoint.dst(), self.family);
        let family = AddressFamily::of(endpoint.dst());
        sys::check_datagram_size(data.len(), family.max_udp_payload())?;

        match gso_size {
            Some(gso_size)
                if !self.gso_enabled.load(Ordering::Relaxed)
                    || gso_size.get() as usize > self.max_gso_size()
                    || data.len() > self.max_datagram_len() =>
            {
                self.send_segments(peer, data, gso_size, endpoint.source())
            }
            Some(gso_size) => {
                GsoLayout::for_payload(data.len(), gso_size)?;
                let datagram = sys::SendDatagram {
                    data,
                    gso_size: Some(gso_size),
                    source: endpoint.source(),
                };
                match sys::sendmsg_single(self.fd(), peer, datagram) {
                    Ok(sent) => Ok(sent),
                    Err(error) if error.should_disable_gso() => {
                        self.gso_enabled.store(false, Ordering::Relaxed);
                        self.send_segments(peer, data, gso_size, endpoint.source())
                    }
                    Err(error) => Err(error),
                }
            }
            None => sys::sendmsg_single(
                self.fd(),
                peer,
                sys::SendDatagram {
                    data,
                    gso_size: None,
                    source: endpoint.source(),
                },
            ),
        }
    }

    /// Receives a single datagram, reporting GRO and sticky metadata.
    pub fn recv_from(&self, buffer: &mut [u8]) -> Result<Incoming> {
        let mut control = ControlBuffer::new();
        let received = sys::recvmsg_single(self.fd(), buffer, &mut control)?;
        let control = &control.as_slice()[..received.control_len];
        let (gro_size, source) = if received.control_truncated {
            (None, None)
        } else {
            (
                cmsg::gro_size(control)?,
                sticky::parse_pktinfo(control, self.family)?,
            )
        };
        let endpoint = received
            .peer
            .map(|dst| Endpoint::with_optional_source(normalize_ipv4_mapped(dst), source));
        Ok(Incoming {
            size: received.len,
            endpoint,
            gro_size,
            truncated: received.truncated,
        })
    }

    fn send_segments(
        &self,
        peer: SocketAddr,
        data: &[u8],
        gso_size: GsoSize,
        source: Option<SourceAddr>,
    ) -> Result<usize> {
        let layout = GsoLayout::for_payload(data.len(), gso_size)?;
        let mut sent = 0usize;
        for range in layout.ranges() {
            let segment = &data[range];
            sent += sys::sendmsg_single(
                self.fd(),
                peer,
                sys::SendDatagram {
                    data: segment,
                    gso_size: None,
                    source,
                },
            )?;
        }
        Ok(sent)
    }
}

impl AsRawFd for Socket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl AsFd for Socket {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl fmt::Debug for Socket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Socket")
            .field("family", &self.family)
            .field("local", &self.local)
            .field("mtu", &self.mtu)
            .field("gso", &self.gso_enabled.load(Ordering::Relaxed))
            .field("gro", &self.gro)
            .finish()
    }
}

/// A single received datagram with its offload metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Incoming {
    /// Number of payload bytes written into the destination buffer.
    pub size: usize,
    /// Peer address and pinned source, when the kernel reported them.
    pub endpoint: Option<Endpoint>,
    /// `UDP_GRO` segment size, when the datagram was receive-offloaded.
    pub gro_size: Option<GsoSize>,
    /// Set when the datagram did not fit into the destination buffer.
    pub truncated: bool,
}

impl Incoming {
    /// Number of UDP datagrams contained in the received buffer.
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

/// Reads the MTU of `interface` with a temporary socket.
pub fn interface_mtu(interface: &str) -> Result<u32> {
    let socket = sys::create_socket(AddressFamily::Ipv4)?;
    sys::interface_mtu(socket.as_raw_fd(), interface)
}

/// Source of outbound UDP sockets for the data path.
///
/// A single [`Socket`] and a [`SocketSet`] both implement it, so callers can
/// stay generic over the number of external UDP flows.
pub trait SocketSource: Send + Sync {
    /// Socket used for buffer limits, polling and the first datagram.
    fn primary(&self) -> &Socket;
    /// Next socket in round-robin order.
    fn next(&self) -> &Socket;
    /// All sockets, in bind order. Never empty.
    fn all(&self) -> &[Socket];
}

impl SocketSource for Socket {
    fn primary(&self) -> &Socket {
        self
    }

    fn next(&self) -> &Socket {
        self
    }

    fn all(&self) -> &[Socket] {
        std::slice::from_ref(self)
    }
}

/// Several external UDP sockets of one device.
///
/// Sending rotates over the set so a peer spreads across several 4-tuples and
/// RPS fans the receive softirq out over multiple CPUs. Receive paths iterate
/// [`SocketSource::all`] and drain every socket.
pub struct SocketSet {
    sockets: Vec<Socket>,
    next: AtomicUsize,
}

impl SocketSet {
    /// Builds a set from at least one socket.
    pub fn new(sockets: Vec<Socket>) -> Result<Self> {
        if sockets.is_empty() {
            return Err(TransportError::EmptySocketSet);
        }
        Ok(Self {
            sockets,
            next: AtomicUsize::new(0),
        })
    }

    /// Number of sockets in the set.
    pub fn len(&self) -> usize {
        self.sockets.len()
    }

    /// Always `false`: a set contains at least one socket.
    pub fn is_empty(&self) -> bool {
        self.sockets.is_empty()
    }

    /// Socket bound to the configured listen port.
    pub fn primary(&self) -> &Socket {
        &self.sockets[0]
    }
}

impl SocketSource for SocketSet {
    fn primary(&self) -> &Socket {
        &self.sockets[0]
    }

    fn next(&self) -> &Socket {
        let index = self.next.fetch_add(1, Ordering::Relaxed) % self.sockets.len();
        &self.sockets[index]
    }

    fn all(&self) -> &[Socket] {
        &self.sockets
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_set_round_robins_and_exposes_all() {
        let first = Socket::bind(AddressFamily::Ipv4, 0).unwrap();
        let second = Socket::bind(AddressFamily::Ipv4, 0).unwrap();
        let first_port = first.local_addr().port();
        let second_port = second.local_addr().port();
        let set = SocketSet::new(vec![first, second]).unwrap();
        assert_eq!(set.len(), 2);
        assert!(!set.is_empty());
        assert_eq!(set.all().len(), 2);
        assert_eq!(set.primary().local_addr().port(), first_port);
        let ports: Vec<u16> = (0..4).map(|_| set.next().local_addr().port()).collect();
        assert_eq!(
            ports,
            vec![first_port, second_port, first_port, second_port]
        );
    }

    #[test]
    fn socket_set_rejects_empty_input() {
        let Err(error) = SocketSet::new(Vec::new()) else {
            panic!("empty socket set must be rejected");
        };
        assert!(matches!(error, TransportError::EmptySocketSet));
        assert!(error.to_string().contains("at least one socket"));
    }

    #[test]
    fn single_socket_is_a_source_of_itself() {
        let socket = Socket::bind(AddressFamily::Ipv4, 0).unwrap();
        assert_eq!(
            socket.primary().local_addr().port(),
            socket.local_addr().port()
        );
        assert_eq!(socket.all().len(), 1);
        assert_eq!(
            socket.next().local_addr().port(),
            socket.local_addr().port()
        );
    }

    #[test]
    fn mtu_discover_values_match_uapi() {
        assert_eq!(MtuDiscover::Dont.value(), 0);
        assert_eq!(MtuDiscover::Want.value(), 1);
        assert_eq!(MtuDiscover::Do.value(), 2);
        assert_eq!(MtuDiscover::Probe.value(), 3);
        assert_eq!(MtuDiscover::Omit.value(), 5);
    }

    #[test]
    fn incoming_counts_segments() {
        let size = GsoSize::new(100).unwrap();
        let incoming = Incoming {
            size: 350,
            endpoint: None,
            gro_size: Some(size),
            truncated: false,
        };
        assert_eq!(incoming.segments(), 4);
        let plain = Incoming {
            size: 10,
            endpoint: None,
            gro_size: None,
            truncated: false,
        };
        assert_eq!(plain.segments(), 1);
        let empty = Incoming {
            size: 0,
            endpoint: None,
            gro_size: None,
            truncated: false,
        };
        assert_eq!(empty.segments(), 0);
    }
}
