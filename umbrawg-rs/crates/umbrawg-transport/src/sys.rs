//! Thin wrappers around the Linux system calls used by the transport.
//!
//! This is the only module of the crate that contains `unsafe` code. Every block
//! either marshals arguments for a syscall or copies a C structure into/out of a
//! caller-owned buffer, and is annotated with a `SAFETY` comment explaining why
//! the pointer and length invariants hold.

use core::mem;
use core::ptr;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

use crate::addr::AddressFamily;
use crate::batch::Outgoing;
use crate::cmsg::{CmsgWriter, ControlBuffer};
use crate::consts::{
    CONTROL_BUFFER_SIZE, IPV6_MTU_DISCOVER, IP_MTU_DISCOVER, SIOCGIFMTU, SO_BINDTODEVICE, SO_MARK,
    UDP_GRO, UDP_SEGMENT,
};
use crate::gso::GsoSize;
use crate::sticky::{self, SourceAddr};
use crate::{Result, TransportError};

/// Payload of a single send batch entry.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SendDatagram<'a> {
    pub(crate) data: &'a [u8],
    pub(crate) gso_size: Option<GsoSize>,
    pub(crate) source: Option<SourceAddr>,
}

/// Result of a single `recvmsg` call.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SingleRecv {
    pub(crate) len: usize,
    pub(crate) truncated: bool,
    pub(crate) control_len: usize,
    pub(crate) control_truncated: bool,
    pub(crate) peer: Option<SocketAddr>,
}

fn setsockopt(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: *const libc::c_void,
    length: usize,
) -> Result<()> {
    let length = libc::socklen_t::try_from(length).map_err(|_| TransportError::Unsupported {
        feature: "oversized socket option",
    })?;
    // SAFETY: `value` points to `length` readable bytes owned by the caller for
    // the duration of the call.
    let result = unsafe { libc::setsockopt(fd, level, name, value, length) };
    if result == 0 {
        Ok(())
    } else {
        Err(TransportError::last_io("setsockopt"))
    }
}

/// Sets an `int` socket option.
pub(crate) fn setsockopt_int(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> Result<()> {
    setsockopt(
        fd,
        level,
        name,
        (&value as *const libc::c_int).cast(),
        mem::size_of::<libc::c_int>(),
    )
}

/// Sets a `u32` socket option.
pub(crate) fn setsockopt_u32(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: u32,
) -> Result<()> {
    setsockopt(
        fd,
        level,
        name,
        (&value as *const u32).cast(),
        mem::size_of::<u32>(),
    )
}

/// Sets an opaque byte-string socket option.
pub(crate) fn setsockopt_bytes(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: &[u8],
) -> Result<()> {
    setsockopt(fd, level, name, value.as_ptr().cast(), value.len())
}

/// Reads an `int` socket option.
pub(crate) fn getsockopt_int(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
) -> Result<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut length = mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: both pointers refer to live local variables of the sizes passed.
    let result = unsafe {
        libc::getsockopt(
            fd,
            level,
            name,
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    if result == 0 {
        Ok(value)
    } else {
        Err(TransportError::last_io("getsockopt"))
    }
}

/// Creates a non-blocking, close-on-exec UDP socket.
pub(crate) fn create_socket(family: AddressFamily) -> Result<OwnedFd> {
    let domain = match family {
        AddressFamily::Ipv4 => libc::AF_INET,
        AddressFamily::Ipv6 => libc::AF_INET6,
    };
    // SAFETY: `socket` only creates a new descriptor and does not touch memory.
    let fd = unsafe {
        libc::socket(
            domain,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            libc::IPPROTO_UDP,
        )
    };
    if fd < 0 {
        return Err(TransportError::last_io("socket"));
    }
    // SAFETY: the descriptor was created above and is owned exclusively by us.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Enables or disables `O_NONBLOCK`.
pub(crate) fn set_nonblocking(fd: RawFd, nonblocking: bool) -> Result<()> {
    // SAFETY: `fcntl` with `F_GETFL`/`F_SETFL` only inspects and updates flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(TransportError::last_io("fcntl(F_GETFL)"));
    }
    let updated = if nonblocking {
        flags | libc::O_NONBLOCK
    } else {
        flags & !libc::O_NONBLOCK
    };
    // SAFETY: `updated` is a valid flag set for the descriptor.
    let result = unsafe { libc::fcntl(fd, libc::F_SETFL, updated) };
    if result < 0 {
        return Err(TransportError::last_io("fcntl(F_SETFL)"));
    }
    Ok(())
}

/// Binds `fd` to `address`.
pub(crate) fn bind_socket(fd: RawFd, address: SocketAddr) -> Result<()> {
    // SAFETY: `sockaddr_storage` is plain-old-data.
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let length = encode_sockaddr(address, &mut storage);
    // SAFETY: `storage` holds a valid socket address of `length` bytes.
    let result = unsafe {
        libc::bind(
            fd,
            (&storage as *const libc::sockaddr_storage).cast(),
            length,
        )
    };
    if result < 0 {
        return Err(TransportError::last_io("bind"));
    }
    Ok(())
}

/// Reads the local address of a bound socket.
pub(crate) fn local_addr(fd: RawFd) -> Result<SocketAddr> {
    // SAFETY: `sockaddr_storage` is plain-old-data.
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut length = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: `storage` is writable for `length` bytes and `length` is valid.
    let result = unsafe {
        libc::getsockname(
            fd,
            (&mut storage as *mut libc::sockaddr_storage).cast(),
            &mut length,
        )
    };
    if result < 0 {
        return Err(TransportError::last_io("getsockname"));
    }
    decode_sockaddr(&storage, length).ok_or_else(|| TransportError::Io {
        operation: "getsockname",
        source: io::Error::new(io::ErrorKind::InvalidData, "unknown address family"),
    })
}

/// Enables `SO_REUSEADDR`.
pub(crate) fn set_reuse_address(fd: RawFd) -> Result<()> {
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)
}

/// Restricts an `AF_INET6` socket to IPv6 only when `v6_only` is set.
pub(crate) fn set_v6only(fd: RawFd, v6_only: bool) -> Result<()> {
    setsockopt_int(
        fd,
        libc::IPPROTO_IPV6,
        libc::IPV6_V6ONLY,
        libc::c_int::from(v6_only),
    )
}

/// Requests `IP_PKTINFO`/`IPV6_RECVPKTINFO` so peer source addresses are reported.
pub(crate) fn enable_pktinfo(fd: RawFd, family: AddressFamily) -> Result<()> {
    match family {
        AddressFamily::Ipv4 => setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_PKTINFO, 1),
        AddressFamily::Ipv6 => setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, 1),
    }
}

/// Enables `UDP_GRO`; returns `false` when the kernel does not support it.
pub(crate) fn enable_gro(fd: RawFd) -> bool {
    setsockopt_int(fd, libc::IPPROTO_UDP, UDP_GRO, 1).is_ok()
}

/// Probes whether `UDP_SEGMENT` is available on this socket.
pub(crate) fn supports_gso(fd: RawFd) -> bool {
    getsockopt_int(fd, libc::IPPROTO_UDP, UDP_SEGMENT).is_ok()
}

/// Sets `IP_MTU_DISCOVER`/`IPV6_MTU_DISCOVER` to `value`.
pub(crate) fn set_mtu_discover(fd: RawFd, family: AddressFamily, value: libc::c_int) -> Result<()> {
    match family {
        AddressFamily::Ipv4 => setsockopt_int(fd, libc::IPPROTO_IP, IP_MTU_DISCOVER, value),
        AddressFamily::Ipv6 => setsockopt_int(fd, libc::IPPROTO_IPV6, IPV6_MTU_DISCOVER, value),
    }
}

/// Sets `SO_RCVBUF`, additionally attempting `SO_RCVBUFFORCE` when privileged.
pub(crate) fn set_receive_buffer(fd: RawFd, size: usize) -> Result<()> {
    let size = libc::c_int::try_from(size).map_err(|_| TransportError::Unsupported {
        feature: "oversized receive buffer",
    })?;
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, size)?;
    let _ = setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUFFORCE, size);
    Ok(())
}

/// Sets `SO_SNDBUF`, additionally attempting `SO_SNDBUFFORCE` when privileged.
pub(crate) fn set_send_buffer(fd: RawFd, size: usize) -> Result<()> {
    let size = libc::c_int::try_from(size).map_err(|_| TransportError::Unsupported {
        feature: "oversized send buffer",
    })?;
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, size)?;
    let _ = setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUFFORCE, size);
    Ok(())
}

/// Enables `SO_REUSEPORT`.
pub(crate) fn set_reuse_port(fd: RawFd) -> Result<()> {
    setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, 1)
}

/// Attaches a routing mark to the socket.
pub(crate) fn set_mark(fd: RawFd, mark: u32) -> Result<()> {
    setsockopt_u32(fd, libc::SOL_SOCKET, SO_MARK, mark)
}

/// Pins the socket to a network interface via `SO_BINDTODEVICE`.
pub(crate) fn bind_to_device(fd: RawFd, interface: &str) -> Result<()> {
    let name = interface.as_bytes();
    if name.is_empty() || name.contains(&0) {
        return Err(TransportError::InvalidInterfaceName);
    }
    if name.len() >= libc::IFNAMSIZ {
        return Err(TransportError::InterfaceNameTooLong {
            len: name.len(),
            max: libc::IFNAMSIZ - 1,
        });
    }
    let mut value = [0u8; libc::IFNAMSIZ];
    value[..name.len()].copy_from_slice(name);
    setsockopt_bytes(fd, libc::SOL_SOCKET, SO_BINDTODEVICE, &value[..=name.len()])
}

/// Reads the MTU of `interface` through `SIOCGIFMTU`.
pub(crate) fn interface_mtu(fd: RawFd, interface: &str) -> Result<u32> {
    let name = interface.as_bytes();
    if name.is_empty() || name.contains(&0) {
        return Err(TransportError::InvalidInterfaceName);
    }
    if name.len() >= libc::IFNAMSIZ {
        return Err(TransportError::InterfaceNameTooLong {
            len: name.len(),
            max: libc::IFNAMSIZ - 1,
        });
    }
    // SAFETY: `ifreq` is a plain-old-data structure; zeroing it is a valid state.
    let mut request: libc::ifreq = unsafe { mem::zeroed() };
    for (slot, byte) in request.ifr_name.iter_mut().zip(name.iter()) {
        *slot = libc::c_char::from_ne_bytes([*byte]);
    }
    // SAFETY: the request is a valid, writable `ifreq` and the ioctl does not
    // retain the pointer.
    let result = unsafe { libc::ioctl(fd, SIOCGIFMTU, &mut request) };
    if result < 0 {
        return Err(TransportError::last_io("ioctl(SIOCGIFMTU)"));
    }
    // SAFETY: the kernel filled `ifr_ifru.ifru_mtu` with a valid `c_int`.
    let mtu = unsafe { request.ifr_ifru.ifru_mtu };
    if mtu <= 0 {
        return Err(TransportError::InvalidMtu { mtu: 0 });
    }
    Ok(mtu as u32)
}

/// Encodes `addr` into `storage`, returning the `socklen_t` to pass to the kernel.
pub(crate) fn encode_sockaddr(
    addr: SocketAddr,
    storage: &mut libc::sockaddr_storage,
) -> libc::socklen_t {
    // SAFETY: `storage` is a valid, writable `sockaddr_storage`.
    unsafe {
        ptr::write_bytes(
            (storage as *mut libc::sockaddr_storage).cast::<u8>(),
            0,
            mem::size_of::<libc::sockaddr_storage>(),
        );
    }
    match addr {
        SocketAddr::V4(v4) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: `sockaddr_in` is smaller than `sockaddr_storage` and the
            // destination is 8-byte aligned, so an aligned write is sound.
            unsafe {
                (storage as *mut libc::sockaddr_storage)
                    .cast::<libc::sockaddr_in>()
                    .write(sin);
            }
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(v6) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            // SAFETY: `sockaddr_in6` fits into `sockaddr_storage`.
            unsafe {
                (storage as *mut libc::sockaddr_storage)
                    .cast::<libc::sockaddr_in6>()
                    .write(sin6);
            }
            mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    }
}

/// Decodes a `sockaddr_storage` written by the kernel.
pub(crate) fn decode_sockaddr(
    storage: &libc::sockaddr_storage,
    length: libc::socklen_t,
) -> Option<SocketAddr> {
    let length = length as usize;
    if length > mem::size_of::<libc::sockaddr_storage>() {
        return None;
    }
    // SAFETY: the family is the first field of every `sockaddr_*` structure and
    // `read_unaligned` accepts the caller-provided storage.
    let family = unsafe { ptr::read_unaligned(storage as *const _ as *const libc::sa_family_t) };
    match libc::c_int::from(family) {
        libc::AF_INET if length >= mem::size_of::<libc::sockaddr_in>() => {
            // SAFETY: the kernel wrote at least `sockaddr_in` bytes.
            let sin =
                unsafe { ptr::read_unaligned(storage as *const _ as *const libc::sockaddr_in) };
            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(sin.sin_port),
            )))
        }
        libc::AF_INET6 if length >= mem::size_of::<libc::sockaddr_in6>() => {
            // SAFETY: the kernel wrote at least `sockaddr_in6` bytes.
            let sin6 =
                unsafe { ptr::read_unaligned(storage as *const _ as *const libc::sockaddr_in6) };
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(sin6.sin6_addr.s6_addr),
                u16::from_be(sin6.sin6_port),
                sin6.sin6_flowinfo,
                sin6.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

/// Scratch space for `recvmmsg`.
pub(crate) struct RecvBatchRaw {
    msgs: Vec<libc::mmsghdr>,
    iovs: Vec<libc::iovec>,
    controls: Vec<ControlBuffer>,
    peers: Vec<libc::sockaddr_storage>,
    capacity: usize,
}

impl RecvBatchRaw {
    /// Allocates scratch space for up to `capacity` datagrams.
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        let mut msgs = Vec::with_capacity(capacity);
        let mut iovs = Vec::with_capacity(capacity);
        let mut controls = Vec::with_capacity(capacity);
        let mut peers = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            // SAFETY: `mmsghdr` and `sockaddr_storage` are plain-old-data; an
            // all-zero value is a valid initial state that is overwritten before
            // every system call.
            unsafe {
                msgs.push(mem::zeroed::<libc::mmsghdr>());
                peers.push(mem::zeroed::<libc::sockaddr_storage>());
            }
            iovs.push(libc::iovec {
                iov_base: ptr::null_mut(),
                iov_len: 0,
            });
            controls.push(ControlBuffer::new());
        }
        Self {
            msgs,
            iovs,
            controls,
            peers,
            capacity,
        }
    }

    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    /// Receives one batch, filling `buffers` and the per-datagram metadata.
    pub(crate) fn recv(&mut self, fd: RawFd, buffers: &mut [&mut [u8]]) -> Result<usize> {
        let count = buffers.len();
        if count == 0 || count > self.capacity {
            return Err(TransportError::BatchTooLarge {
                count,
                max: self.capacity,
            });
        }
        // SAFETY: every index is bounded by `self.capacity`, all arrays are owned
        // by `self`, and the pointers stored in the `msghdr` structures stay valid
        // for the duration of the `recvmmsg` call because neither the vectors nor
        // the caller buffers are reallocated in between.
        unsafe {
            let msgs = self.msgs.as_mut_ptr();
            let iovs = self.iovs.as_mut_ptr();
            let controls = self.controls.as_mut_ptr();
            let peers = self.peers.as_mut_ptr();
            for (index, buffer) in buffers.iter_mut().enumerate() {
                let iov = iovs.add(index);
                (*iov).iov_base = buffer.as_mut_ptr().cast();
                (*iov).iov_len = buffer.len();

                let peer = peers.add(index);
                ptr::write_bytes(
                    peer.cast::<u8>(),
                    0,
                    mem::size_of::<libc::sockaddr_storage>(),
                );

                let message = msgs.add(index);
                (*message).msg_hdr.msg_name = peer.cast();
                (*message).msg_hdr.msg_namelen =
                    mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                (*message).msg_hdr.msg_iov = iov;
                (*message).msg_hdr.msg_iovlen = 1;
                (*message).msg_hdr.msg_control = controls.add(index).cast();
                (*message).msg_hdr.msg_controllen = CONTROL_BUFFER_SIZE;
                (*message).msg_hdr.msg_flags = 0;
                (*message).msg_len = 0;
            }
            let result = libc::recvmmsg(
                fd,
                msgs,
                count as libc::c_uint,
                libc::MSG_DONTWAIT,
                ptr::null_mut(),
            );
            if result < 0 {
                return Err(TransportError::last_io("recvmmsg"));
            }
            Ok(result as usize)
        }
    }

    /// Number of bytes written into the buffer of datagram `index`.
    pub(crate) fn len(&self, index: usize) -> usize {
        self.msgs[index].msg_len as usize
    }

    /// Whether datagram `index` was truncated by the receive buffer.
    pub(crate) fn truncated(&self, index: usize) -> bool {
        self.msgs[index].msg_hdr.msg_flags & libc::MSG_TRUNC != 0
    }

    /// Whether the control buffer of datagram `index` was truncated.
    pub(crate) fn control_truncated(&self, index: usize) -> bool {
        self.msgs[index].msg_hdr.msg_flags & libc::MSG_CTRUNC != 0
    }

    /// Parsed peer address of datagram `index`.
    pub(crate) fn peer(&self, index: usize) -> Option<SocketAddr> {
        decode_sockaddr(&self.peers[index], self.msgs[index].msg_hdr.msg_namelen)
    }

    /// Control data of datagram `index`.
    pub(crate) fn control(&self, index: usize) -> &[u8] {
        let length = self.msgs[index]
            .msg_hdr
            .msg_controllen
            .min(CONTROL_BUFFER_SIZE);
        &self.controls[index].as_slice()[..length]
    }
}

/// Scratch space for `sendmmsg`.
pub(crate) struct SendBatchRaw {
    msgs: Vec<libc::mmsghdr>,
    iovs: Vec<libc::iovec>,
    controls: Vec<ControlBuffer>,
    peer: libc::sockaddr_storage,
    capacity: usize,
}

impl SendBatchRaw {
    /// Allocates scratch space for up to `capacity` datagrams.
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        let mut msgs = Vec::with_capacity(capacity);
        let mut iovs = Vec::with_capacity(capacity);
        let mut controls = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            // SAFETY: `mmsghdr` is plain-old-data; zero is a valid initial value.
            unsafe {
                msgs.push(mem::zeroed::<libc::mmsghdr>());
            }
            iovs.push(libc::iovec {
                iov_base: ptr::null_mut(),
                iov_len: 0,
            });
            controls.push(ControlBuffer::new());
        }
        // SAFETY: `sockaddr_storage` is plain-old-data.
        let peer = unsafe { mem::zeroed::<libc::sockaddr_storage>() };
        Self {
            msgs,
            iovs,
            controls,
            peer,
            capacity,
        }
    }

    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    /// Sends `datagrams` to `peer` with one `sendmmsg` call.
    ///
    /// `source` pins the local address and interface of every datagram in the
    /// batch, which is how sticky sockets keep replies on the ingress path.
    /// Returns the number of datagrams accepted by the kernel. A short result
    /// means the socket started blocking, which the caller must treat as a
    /// partial send rather than an error.
    pub(crate) fn send(
        &mut self,
        fd: RawFd,
        peer: SocketAddr,
        source: Option<SourceAddr>,
        datagrams: &[Outgoing<'_>],
    ) -> Result<usize> {
        let count = datagrams.len();
        if count == 0 || count > self.capacity {
            return Err(TransportError::BatchTooLarge {
                count,
                max: self.capacity,
            });
        }
        let peer_len = encode_sockaddr(peer, &mut self.peer);
        // SAFETY: indexes are bounded by `self.capacity`; control buffers, iovecs
        // and the peer address live in `self` and are not moved or resized during
        // the call; datagram payloads are borrowed from the caller.
        unsafe {
            let msgs = self.msgs.as_mut_ptr();
            let iovs = self.iovs.as_mut_ptr();
            let controls = self.controls.as_mut_ptr();
            let peer_ptr = ptr::addr_of_mut!(self.peer).cast::<libc::c_void>();

            for (index, datagram) in datagrams.iter().enumerate() {
                let control_len = {
                    let control = &mut *controls.add(index);
                    let mut writer = CmsgWriter::new(control);
                    if let Some(source) = source {
                        sticky::write_pktinfo(&mut writer, source)?;
                    }
                    if let Some(gso_size) = datagram.gso_size() {
                        writer.push_gso(gso_size)?;
                    }
                    writer.len()
                };

                let iov = iovs.add(index);
                (*iov).iov_base = datagram.data().as_ptr().cast_mut().cast();
                (*iov).iov_len = datagram.len();

                let message = msgs.add(index);
                (*message).msg_hdr.msg_name = peer_ptr;
                (*message).msg_hdr.msg_namelen = peer_len;
                (*message).msg_hdr.msg_iov = iov;
                (*message).msg_hdr.msg_iovlen = 1;
                (*message).msg_hdr.msg_control = if control_len == 0 {
                    ptr::null_mut()
                } else {
                    controls.add(index).cast()
                };
                (*message).msg_hdr.msg_controllen = control_len;
                (*message).msg_hdr.msg_flags = 0;
                (*message).msg_len = 0;
            }

            let result = libc::sendmmsg(fd, msgs, count as libc::c_uint, libc::MSG_DONTWAIT);
            if result < 0 {
                return Err(TransportError::last_io("sendmmsg"));
            }
            Ok(result as usize)
        }
    }
}

/// Sends a single datagram with `sendmsg`.
pub(crate) fn sendmsg_single(
    fd: RawFd,
    peer: SocketAddr,
    datagram: SendDatagram<'_>,
) -> Result<usize> {
    let mut control = ControlBuffer::new();
    // SAFETY: `sockaddr_storage` is plain-old-data.
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let peer_len = encode_sockaddr(peer, &mut storage);

    let control_len = {
        let mut writer = CmsgWriter::new(&mut control);
        if let Some(source) = datagram.source {
            sticky::write_pktinfo(&mut writer, source)?;
        }
        if let Some(gso_size) = datagram.gso_size {
            writer.push_gso(gso_size)?;
        }
        writer.len()
    };

    let mut iov = libc::iovec {
        iov_base: datagram.data.as_ptr().cast_mut().cast(),
        iov_len: datagram.data.len(),
    };
    let message = libc::msghdr {
        msg_name: (&mut storage as *mut libc::sockaddr_storage).cast(),
        msg_namelen: peer_len,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: if control_len == 0 {
            ptr::null_mut()
        } else {
            control.as_mut_ptr().cast()
        },
        msg_controllen: control_len,
        msg_flags: 0,
    };
    // SAFETY: every pointer in `message` refers to live stack data for the
    // duration of the call.
    let result = unsafe { libc::sendmsg(fd, &message, libc::MSG_DONTWAIT) };
    if result < 0 {
        return Err(TransportError::last_io("sendmsg"));
    }
    Ok(result as usize)
}

/// Receives a single datagram with `recvmsg`.
pub(crate) fn recvmsg_single(
    fd: RawFd,
    buffer: &mut [u8],
    control: &mut ControlBuffer,
) -> Result<SingleRecv> {
    // SAFETY: `sockaddr_storage` is plain-old-data.
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    let mut message = libc::msghdr {
        msg_name: (&mut storage as *mut libc::sockaddr_storage).cast(),
        msg_namelen: mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: control.as_mut_ptr().cast(),
        msg_controllen: CONTROL_BUFFER_SIZE,
        msg_flags: 0,
    };
    // SAFETY: every pointer in `message` refers to live data for the duration of
    // the call.
    let result = unsafe { libc::recvmsg(fd, &mut message, libc::MSG_DONTWAIT) };
    if result < 0 {
        return Err(TransportError::last_io("recvmsg"));
    }
    let peer = if message.msg_namelen == 0 {
        None
    } else {
        decode_sockaddr(&storage, message.msg_namelen)
    };
    Ok(SingleRecv {
        len: result as usize,
        truncated: message.msg_flags & libc::MSG_TRUNC != 0,
        control_len: message.msg_controllen.min(CONTROL_BUFFER_SIZE),
        control_truncated: message.msg_flags & libc::MSG_CTRUNC != 0,
        peer,
    })
}

/// Returns the number of payload bytes of a datagram, rejecting sizes the family
/// cannot express.
pub(crate) fn check_datagram_size(length: usize, max: usize) -> Result<()> {
    if length > max {
        return Err(TransportError::DatagramTooLarge { len: length, max });
    }
    Ok(())
}
