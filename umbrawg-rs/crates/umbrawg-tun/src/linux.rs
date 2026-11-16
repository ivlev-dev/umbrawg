//! Linux TUN device implementation.

use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, IoSlice, Read, Write};
use std::net::{Ipv4Addr, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;

use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};

use crate::error::{TunError, TunResult};
use crate::offload::{
    gso_none_checksum, gso_segment_count, gso_segment_len, prepare_gso, read_buffer_size,
    split_gso, GsoError,
};
use crate::virtio::{VirtioNetHdr, VIRTIO_NET_HDR_GSO_NONE};

/// Path of the Linux TUN clone device.
pub const TUN_DEVICE_PATH: &str = "/dev/net/tun";

/// Preferred number of packets per batch, matching WireGuard's `IdealBatchSize`.
pub const IDEAL_BATCH_SIZE: usize = 128;

const IFREQ_DATA_LEN: usize = if cfg!(target_pointer_width = "64") {
    24
} else {
    16
};

const SIOCGIFMTU: libc::Ioctl = 0x8921;
const SIOCSIFMTU: libc::Ioctl = 0x8922;
const SIOCGIFINDEX: libc::Ioctl = 0x8933;

#[repr(C, align(8))]
#[derive(Debug)]
struct IfReq {
    name: [libc::c_char; libc::IFNAMSIZ],
    data: [u8; IFREQ_DATA_LEN],
}

impl IfReq {
    const fn empty() -> Self {
        Self {
            name: [0; libc::IFNAMSIZ],
            data: [0; IFREQ_DATA_LEN],
        }
    }

    fn new(name: &str) -> TunResult<Self> {
        if name.len() >= libc::IFNAMSIZ {
            return Err(invalid_config("interface name is longer than 15 bytes"));
        }
        if name.as_bytes().contains(&0) {
            return Err(invalid_config("interface name contains a NUL byte"));
        }
        let mut ifreq = Self::empty();
        for (dst, src) in ifreq.name.iter_mut().zip(name.bytes()) {
            *dst = src as libc::c_char;
        }
        Ok(ifreq)
    }

    fn name_string(&self) -> io::Result<String> {
        let bytes: Vec<u8> = self
            .name
            .iter()
            .take_while(|byte| **byte != 0)
            .map(|byte| *byte as u8)
            .collect();
        String::from_utf8(bytes)
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "interface name is not UTF-8"))
    }

    #[cfg(test)]
    fn flags(&self) -> libc::c_short {
        i16::from_ne_bytes([self.data[0], self.data[1]])
    }

    fn set_flags(&mut self, flags: libc::c_short) {
        self.data[..2].copy_from_slice(&flags.to_ne_bytes());
    }

    fn mtu(&self) -> u32 {
        u32::from_ne_bytes([self.data[0], self.data[1], self.data[2], self.data[3]])
    }

    fn set_mtu(&mut self, mtu: u32) {
        self.data[..4].copy_from_slice(&mtu.to_ne_bytes());
    }

    fn ifindex(&self) -> u32 {
        self.mtu()
    }

    #[cfg(test)]
    fn set_ifindex(&mut self, index: u32) {
        self.set_mtu(index);
    }
}

/// Segmentation offload features enabled on a TUN queue.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Offload {
    /// Checksum offload (`TUN_F_CSUM`).
    pub csum: bool,
    /// TCP segmentation offload over IPv4 (`TUN_F_TSO4`).
    pub tso4: bool,
    /// TCP segmentation offload over IPv6 (`TUN_F_TSO6`).
    pub tso6: bool,
    /// Legacy UDP fragmentation offload (`TUN_F_UFO`).
    pub ufo: bool,
    /// UDP segmentation offload over IPv4 (`TUN_F_USO4`).
    pub uso4: bool,
    /// UDP segmentation offload over IPv6 (`TUN_F_USO6`).
    pub uso6: bool,
}

impl Offload {
    /// No offload features.
    pub const NONE: Self = Self {
        csum: false,
        tso4: false,
        tso6: false,
        ufo: false,
        uso4: false,
        uso6: false,
    };
    /// Checksum offload only.
    pub const CSUM: Self = Self {
        csum: true,
        ..Self::NONE
    };
    /// Checksum and TCP segmentation offload.
    pub const TCP: Self = Self {
        csum: true,
        tso4: true,
        tso6: true,
        ufo: false,
        uso4: false,
        uso6: false,
    };
    /// Legacy TCP and UDP fragmentation offload set requested from the kernel.
    pub const LEGACY_TCP: Self = Self {
        csum: true,
        tso4: true,
        tso6: true,
        ufo: true,
        uso4: false,
        uso6: false,
    };
    /// UDP segmentation offload.
    pub const USO: Self = Self {
        csum: false,
        tso4: false,
        tso6: false,
        ufo: false,
        uso4: true,
        uso6: true,
    };

    /// Returns the TUN feature bits for this set.
    pub fn bits(self) -> libc::c_uint {
        let mut bits: libc::c_uint = 0;
        if self.csum {
            bits |= libc::TUN_F_CSUM;
        }
        if self.tso4 {
            bits |= libc::TUN_F_TSO4;
        }
        if self.tso6 {
            bits |= libc::TUN_F_TSO6;
        }
        if self.ufo {
            bits |= libc::TUN_F_UFO;
        }
        if self.uso4 {
            bits |= libc::TUN_F_USO4;
        }
        if self.uso6 {
            bits |= libc::TUN_F_USO6;
        }
        bits
    }

    /// Builds an offload set from TUN feature bits.
    pub fn from_bits(bits: libc::c_uint) -> Self {
        Self {
            csum: bits & libc::TUN_F_CSUM != 0,
            tso4: bits & libc::TUN_F_TSO4 != 0,
            tso6: bits & libc::TUN_F_TSO6 != 0,
            ufo: bits & libc::TUN_F_UFO != 0,
            uso4: bits & libc::TUN_F_USO4 != 0,
            uso6: bits & libc::TUN_F_USO6 != 0,
        }
    }

    /// Returns a copy without the legacy UDP fragmentation bit.
    pub const fn without_ufo(self) -> Self {
        Self {
            csum: self.csum,
            tso4: self.tso4,
            tso6: self.tso6,
            ufo: false,
            uso4: self.uso4,
            uso6: self.uso6,
        }
    }

    /// Returns `true` when no feature is enabled.
    pub const fn is_empty(self) -> bool {
        !self.csum && !self.tso4 && !self.tso6 && !self.ufo && !self.uso4 && !self.uso6
    }
}

impl core::ops::BitOr for Offload {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self {
            csum: self.csum || rhs.csum,
            tso4: self.tso4 || rhs.tso4,
            tso6: self.tso6 || rhs.tso6,
            ufo: self.ufo || rhs.ufo,
            uso4: self.uso4 || rhs.uso4,
            uso6: self.uso6 || rhs.uso6,
        }
    }
}

/// Configuration for opening a TUN device.
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Interface name. `%d` is replaced with a free index by the kernel.
    pub name: String,
    /// Requested MTU. Zero leaves the MTU unchanged.
    pub mtu: u32,
    /// Requests `IFF_MULTI_QUEUE` support.
    pub multi_queue: bool,
    /// Enables `IFF_VNET_HDR` and segmentation offload.
    pub offload: bool,
    /// Virtio header size: 10 or 12 bytes.
    pub vnet_hdr_size: usize,
    /// Switches the file descriptor to non-blocking mode after opening.
    pub nonblocking: bool,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "umbrawg%d".to_owned(),
            mtu: 1420,
            multi_queue: false,
            offload: true,
            vnet_hdr_size: VirtioNetHdr::LEN,
            nonblocking: true,
        }
    }
}

impl TunConfig {
    /// Creates a configuration for an interface name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Self::default()
        }
    }

    /// Sets the requested MTU.
    pub fn with_mtu(mut self, mtu: u32) -> Self {
        self.mtu = mtu;
        self
    }

    /// Enables or disables multi-queue mode.
    pub fn with_multi_queue(mut self, enabled: bool) -> Self {
        self.multi_queue = enabled;
        self
    }

    /// Enables or disables virtio-net offload.
    pub fn with_offload(mut self, enabled: bool) -> Self {
        self.offload = enabled;
        self
    }

    /// Sets the virtio header size (10 or 12 bytes).
    pub fn with_vnet_hdr_size(mut self, size: usize) -> Self {
        self.vnet_hdr_size = size;
        self
    }

    /// Enables or disables non-blocking mode.
    pub fn with_nonblocking(mut self, enabled: bool) -> Self {
        self.nonblocking = enabled;
        self
    }
}

/// An open Linux TUN queue.
#[derive(Debug)]
pub struct Tun {
    file: File,
    name: String,
    ifindex: Option<u32>,
    mtu: u32,
    vnet_hdr: bool,
    vnet_hdr_len: usize,
    offload: Offload,
    batch_size: usize,
    read_buf: Vec<u8>,
}

impl Tun {
    /// Opens a single TUN queue.
    pub fn open(config: &TunConfig) -> TunResult<Self> {
        Self::open_queue(config, true)
    }

    fn open_queue(config: &TunConfig, apply_mtu: bool) -> TunResult<Self> {
        validate_config(config)?;

        let mut options = OpenOptions::new();
        options.read(true).write(true);
        if config.nonblocking {
            options.custom_flags(libc::O_NONBLOCK);
        }
        let file = options
            .open(TUN_DEVICE_PATH)
            .map_err(|error| {
                if error.kind() == ErrorKind::NotFound {
                    io::Error::new(
                        ErrorKind::NotFound,
                        format!("{TUN_DEVICE_PATH} does not exist: {error}"),
                    )
                } else {
                    error
                }
            })?;
        let fd = file.as_raw_fd();

        let features = get_features(fd)?;
        let mut flags = libc::IFF_TUN | libc::IFF_NO_PI;
        if config.offload {
            if features & libc::IFF_VNET_HDR == 0 {
                return Err(TunError::Unsupported("IFF_VNET_HDR"));
            }
            flags |= libc::IFF_VNET_HDR;
        }
        if config.multi_queue {
            if features & libc::IFF_MULTI_QUEUE == 0 {
                return Err(TunError::Unsupported("IFF_MULTI_QUEUE"));
            }
            flags |= libc::IFF_MULTI_QUEUE;
        }

        let mut ifreq = IfReq::new(&config.name)?;
        ifreq.set_flags(flags as libc::c_short);
        ioctl(
            fd,
            libc::TUNSETIFF,
            (&mut ifreq as *mut IfReq).cast::<libc::c_void>(),
        )?;

        let mut name_ifreq = IfReq::empty();
        ioctl(
            fd,
            libc::TUNGETIFF,
            (&mut name_ifreq as *mut IfReq).cast::<libc::c_void>(),
        )?;
        let name = name_ifreq.name_string()?;

        let (vnet_hdr, vnet_hdr_len, offload) = if config.offload {
            let vnet_hdr_len = set_vnet_hdr_size(fd, config.vnet_hdr_size)?;
            let enabled = enable_offload(fd)?;
            (true, vnet_hdr_len, enabled)
        } else {
            (false, 0, Offload::NONE)
        };

        if apply_mtu && config.mtu != 0 {
            set_mtu_by_name(&name, config.mtu)?;
        }
        let mtu = get_mtu_by_name(&name)?;
        let ifindex = interface_index_by_name(&name).ok();
        let batch_size = if vnet_hdr { IDEAL_BATCH_SIZE } else { 1 };
        let read_buf = vec![0u8; read_buffer_size(vnet_hdr_len)];

        Ok(Self {
            file,
            name,
            ifindex,
            mtu,
            vnet_hdr,
            vnet_hdr_len,
            offload,
            batch_size,
            read_buf,
        })
    }

    /// Returns the actual interface name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the interface index, if it could be queried.
    pub fn interface_index(&self) -> Option<u32> {
        self.ifindex
    }

    /// Returns the cached MTU.
    pub fn mtu(&self) -> u32 {
        self.mtu
    }

    /// Sets the interface MTU and refreshes the cached value.
    pub fn set_mtu(&mut self, mtu: u32) -> TunResult<()> {
        set_mtu_by_name(&self.name, mtu)?;
        self.mtu = get_mtu_by_name(&self.name)?;
        Ok(())
    }

    /// Returns the number of packets per batch supported by this queue.
    pub fn batch_size(&self) -> usize {
        self.batch_size
    }

    /// Returns `true` when the device uses a virtio-net header.
    pub fn vnet_hdr(&self) -> bool {
        self.vnet_hdr
    }

    /// Returns the virtio-net header length (0, 10 or 12 bytes).
    pub fn vnet_hdr_len(&self) -> usize {
        self.vnet_hdr_len
    }

    /// Returns the enabled offload features.
    pub fn offload(&self) -> Offload {
        self.offload
    }

    /// Changes the offload features requested from the kernel.
    pub fn set_offload(&mut self, offload: Offload) -> TunResult<()> {
        if !self.vnet_hdr {
            return Err(invalid_config(
                "offload requires a virtio-net header and offload support",
            ));
        }
        set_offload_fd(self.file.as_raw_fd(), offload)?;
        self.offload = offload;
        Ok(())
    }

    /// Returns the raw file descriptor for `poll(2)` and friends.
    pub fn fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    /// Returns the underlying file.
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Switches the file descriptor between blocking and non-blocking mode.
    pub fn set_nonblocking_mode(&self, nonblocking: bool) -> TunResult<()> {
        set_nonblocking(&self.file, nonblocking)
    }

    /// Reads a single packet into `buf`, returning its length.
    ///
    /// This method is intended for queues without offload. When a GSO packet
    /// that splits into multiple segments arrives, use [`Tun::read_batch`].
    pub fn read(&mut self, buf: &mut [u8]) -> TunResult<usize> {
        if !self.vnet_hdr {
            return Ok(read_file(&mut self.file, buf)?);
        }

        let len = self.read_raw()?;
        if len < self.vnet_hdr_len {
            return Err(short_virtio_header(self.vnet_hdr_len, len));
        }
        let header =
            VirtioNetHdr::decode_sized(&self.read_buf[..self.vnet_hdr_len], self.vnet_hdr_len)?;
        let start = self.vnet_hdr_len;

        if header.gso_type == VIRTIO_NET_HDR_GSO_NONE {
            if header.needs_csum() {
                gso_none_checksum(
                    &mut self.read_buf[start..len],
                    header.csum_start,
                    header.csum_offset,
                )?;
            }
            let payload = &self.read_buf[start..len];
            if payload.len() > buf.len() {
                return Err(buffer_too_small(payload.len(), buf.len()));
            }
            buf[..payload.len()].copy_from_slice(payload);
            return Ok(payload.len());
        }

        let mut header = header;
        prepare_gso(&self.read_buf[start..len], &mut header)?;
        let input_len = len - start;
        let count = gso_segment_count(input_len, header.hdr_len, header.gso_size);
        if count != 1 {
            return Err(invalid_gso(
                "GSO packet splits into multiple segments; use read_batch",
            ));
        }
        let segment_len = gso_segment_len(input_len, &header, 0)
            .ok_or_else(|| invalid_gso("invalid GSO segment"))?;
        if segment_len > buf.len() {
            return Err(buffer_too_small(segment_len, buf.len()));
        }
        let segment = &mut buf[..segment_len];
        let mut segments = [segment];
        split_gso(&self.read_buf[start..len], &mut header, &mut segments)?;
        Ok(segment_len)
    }

    /// Reads a packet and splits GSO segments into `bufs`.
    ///
    /// On success, each `bufs[i]` is truncated to the length of the packet it
    /// received. The returned value is the number of packets read.
    pub fn read_batch(&mut self, bufs: &mut [&mut [u8]]) -> TunResult<usize> {
        if bufs.is_empty() {
            return Err(invalid_config("no output buffers"));
        }

        if !self.vnet_hdr {
            let len = read_file(&mut self.file, bufs[0])?;
            truncate_buf(&mut bufs[0], len);
            return Ok(1);
        }

        let len = self.read_raw()?;
        if len < self.vnet_hdr_len {
            return Err(short_virtio_header(self.vnet_hdr_len, len));
        }
        let header =
            VirtioNetHdr::decode_sized(&self.read_buf[..self.vnet_hdr_len], self.vnet_hdr_len)?;
        let start = self.vnet_hdr_len;

        if header.gso_type == VIRTIO_NET_HDR_GSO_NONE {
            if header.needs_csum() {
                gso_none_checksum(
                    &mut self.read_buf[start..len],
                    header.csum_start,
                    header.csum_offset,
                )?;
            }
            let payload = &self.read_buf[start..len];
            if payload.len() > bufs[0].len() {
                return Err(buffer_too_small(payload.len(), bufs[0].len()));
            }
            bufs[0][..payload.len()].copy_from_slice(payload);
            truncate_buf(&mut bufs[0], payload.len());
            return Ok(1);
        }

        let mut header = header;
        let count = split_gso(&self.read_buf[start..len], &mut header, bufs)?;
        for (index, slot) in bufs.iter_mut().enumerate().take(count) {
            let segment_len = gso_segment_len(len - start, &header, index)
                .ok_or_else(|| invalid_gso("invalid GSO segment"))?;
            truncate_buf(slot, segment_len);
        }
        Ok(count)
    }

    /// Reads a packet into `bufs`, writing packet lengths into `sizes`.
    ///
    /// Unlike [`Tun::read_batch`], the buffers are not truncated.
    pub fn read_batch_sizes(
        &mut self,
        bufs: &mut [&mut [u8]],
        sizes: &mut [usize],
    ) -> TunResult<usize> {
        if bufs.is_empty() {
            return Err(invalid_config("no output buffers"));
        }
        if sizes.len() < bufs.len() {
            return Err(invalid_config("sizes slice is shorter than bufs"));
        }

        if !self.vnet_hdr {
            let len = read_file(&mut self.file, bufs[0])?;
            sizes[0] = len;
            return Ok(1);
        }

        let len = self.read_raw()?;
        if len < self.vnet_hdr_len {
            return Err(short_virtio_header(self.vnet_hdr_len, len));
        }
        let header =
            VirtioNetHdr::decode_sized(&self.read_buf[..self.vnet_hdr_len], self.vnet_hdr_len)?;
        let start = self.vnet_hdr_len;

        if header.gso_type == VIRTIO_NET_HDR_GSO_NONE {
            if header.needs_csum() {
                gso_none_checksum(
                    &mut self.read_buf[start..len],
                    header.csum_start,
                    header.csum_offset,
                )?;
            }
            let payload_len = len - start;
            if payload_len > bufs[0].len() {
                return Err(buffer_too_small(payload_len, bufs[0].len()));
            }
            bufs[0][..payload_len].copy_from_slice(&self.read_buf[start..len]);
            sizes[0] = payload_len;
            return Ok(1);
        }

        let mut header = header;
        let count = split_gso(&self.read_buf[start..len], &mut header, bufs)?;
        for (index, size) in sizes.iter_mut().enumerate().take(count) {
            *size = gso_segment_len(len - start, &header, index)
                .ok_or_else(|| invalid_gso("invalid GSO segment"))?;
        }
        Ok(count)
    }

    /// Writes a single packet.
    pub fn write(&self, buf: &[u8]) -> TunResult<usize> {
        if self.vnet_hdr {
            let header = [0u8; VirtioNetHdr::LEN_WITH_NUM_BUFFERS];
            write_packet(&self.file, &header[..self.vnet_hdr_len], buf)?;
        } else {
            write_all_file(&self.file, buf)?;
        }
        Ok(buf.len())
    }

    /// Writes a batch of packets, returning the number of packets written.
    ///
    /// A `WouldBlock` after at least one packet returns the committed count so
    /// the caller can retry the remainder.
    pub fn write_batch(&self, bufs: &[&[u8]]) -> TunResult<usize> {
        let header = [0u8; VirtioNetHdr::LEN_WITH_NUM_BUFFERS];
        let header = &header[..self.vnet_hdr_len];
        Ok(self.write_batch_inner(bufs, |packet| {
            if self.vnet_hdr {
                write_packet(&self.file, header, packet)
            } else {
                write_all_file(&self.file, packet)
            }
        })?)
    }

    /// Writes a packet with an explicit virtio-net header.
    pub fn write_with_header(&self, header: &VirtioNetHdr, buf: &[u8]) -> TunResult<usize> {
        if !self.vnet_hdr {
            return Err(invalid_config("virtio header requires offload support"));
        }
        let mut encoded = [0u8; VirtioNetHdr::LEN_WITH_NUM_BUFFERS];
        header.encode_sized(&mut encoded[..self.vnet_hdr_len], self.vnet_hdr_len)?;
        write_packet(&self.file, &encoded[..self.vnet_hdr_len], buf)?;
        Ok(buf.len())
    }

    /// Writes a batch of packets with explicit virtio-net headers.
    pub fn write_batch_with_headers(
        &self,
        headers: &[VirtioNetHdr],
        bufs: &[&[u8]],
    ) -> TunResult<usize> {
        if !self.vnet_hdr {
            return Err(invalid_config("virtio header requires offload support"));
        }
        if headers.len() != bufs.len() {
            return Err(invalid_config("headers and buffers have different lengths"));
        }

        let mut written = 0;
        for (header, packet) in headers.iter().zip(bufs) {
            let mut encoded = [0u8; VirtioNetHdr::LEN_WITH_NUM_BUFFERS];
            header.encode_sized(&mut encoded[..self.vnet_hdr_len], self.vnet_hdr_len)?;
            match write_packet(&self.file, &encoded[..self.vnet_hdr_len], packet) {
                Ok(()) => written += 1,
                Err(error) if error.kind() == ErrorKind::WouldBlock && written > 0 => {
                    return Ok(written);
                }
                Err(error) => return Err(TunError::Io(error)),
            }
        }
        Ok(written)
    }

    fn write_batch_inner<F>(&self, bufs: &[&[u8]], mut write: F) -> io::Result<usize>
    where
        F: FnMut(&[u8]) -> io::Result<()>,
    {
        let mut written = 0;
        for packet in bufs {
            match write(packet) {
                Ok(()) => written += 1,
                Err(error) if error.kind() == ErrorKind::WouldBlock && written > 0 => {
                    return Ok(written);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(written)
    }

    fn read_raw(&mut self) -> io::Result<usize> {
        read_file(&mut self.file, &mut self.read_buf)
    }
}

impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

/// A set of TUN queues that share one interface.
#[derive(Debug)]
pub struct TunSet {
    queues: Vec<Tun>,
}

impl TunSet {
    /// Opens `queues` queues, enabling multi-queue when more than one is requested.
    pub fn open(config: &TunConfig, queues: usize) -> TunResult<Self> {
        if queues == 0 {
            return Err(invalid_config("queue count must be at least 1"));
        }
        let mut queue_config = config.clone();
        if queues > 1 {
            queue_config.multi_queue = true;
        }

        let first = Tun::open(&queue_config)?;
        let name = first.name().to_owned();
        let mut opened = Vec::with_capacity(queues);
        opened.push(first);

        queue_config.name = name;
        for _ in 1..queues {
            opened.push(Tun::open_queue(&queue_config, false)?);
        }
        Ok(Self { queues: opened })
    }

    /// Returns the number of queues.
    pub fn len(&self) -> usize {
        self.queues.len()
    }

    /// Returns `true` when there are no queues.
    pub fn is_empty(&self) -> bool {
        self.queues.is_empty()
    }

    /// Returns the shared interface name.
    pub fn name(&self) -> &str {
        self.queues
            .first()
            .map_or("", |queue| queue.name())
    }

    /// Returns the batch size of the queues.
    pub fn batch_size(&self) -> usize {
        self.queues.first().map_or(1, Tun::batch_size)
    }

    /// Returns a queue by index.
    pub fn get(&self, index: usize) -> Option<&Tun> {
        self.queues.get(index)
    }

    /// Returns a mutable queue by index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut Tun> {
        self.queues.get_mut(index)
    }

    /// Iterates over the queues.
    pub fn iter(&self) -> impl Iterator<Item = &Tun> {
        self.queues.iter()
    }

    /// Iterates mutably over the queues.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Tun> {
        self.queues.iter_mut()
    }

    /// Returns the raw file descriptors for all queues.
    pub fn raw_fds(&self) -> Vec<RawFd> {
        self.queues.iter().map(Tun::fd).collect()
    }

    /// Consumes the set and returns its queues.
    pub fn into_queues(self) -> Vec<Tun> {
        self.queues
    }
}

impl IntoIterator for TunSet {
    type Item = Tun;
    type IntoIter = std::vec::IntoIter<Tun>;

    fn into_iter(self) -> Self::IntoIter {
        self.queues.into_iter()
    }
}

impl<'a> IntoIterator for &'a TunSet {
    type Item = &'a Tun;
    type IntoIter = std::slice::Iter<'a, Tun>;

    fn into_iter(self) -> Self::IntoIter {
        self.queues.iter()
    }
}

fn validate_config(config: &TunConfig) -> TunResult<()> {
    if config.name.len() >= libc::IFNAMSIZ {
        return Err(invalid_config("interface name is longer than 15 bytes"));
    }
    if config.name.as_bytes().contains(&0) {
        return Err(invalid_config("interface name contains a NUL byte"));
    }
    if config.offload
        && !matches!(
            config.vnet_hdr_size,
            VirtioNetHdr::LEN | VirtioNetHdr::LEN_WITH_NUM_BUFFERS
        )
    {
        return Err(invalid_config(
            "virtio-net header size must be 10 or 12 bytes",
        ));
    }
    Ok(())
}

fn ioctl(fd: RawFd, request: libc::Ioctl, arg: *mut libc::c_void) -> io::Result<()> {
    // SAFETY: the caller guarantees that `arg` points to a live object whose
    // layout matches the kernel ABI required by `request`.
    let result = unsafe { libc::ioctl(fd, request, arg) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn get_features(fd: RawFd) -> io::Result<libc::c_int> {
    let mut features: libc::c_int = 0;
    ioctl(
        fd,
        libc::TUNGETFEATURES,
        (&mut features as *mut libc::c_int).cast::<libc::c_void>(),
    )?;
    Ok(features)
}

fn set_vnet_hdr_size(fd: RawFd, size: usize) -> TunResult<usize> {
    if !matches!(size, VirtioNetHdr::LEN | VirtioNetHdr::LEN_WITH_NUM_BUFFERS) {
        return Err(invalid_config(
            "virtio-net header size must be 10 or 12 bytes",
        ));
    }
    let mut value = size as libc::c_int;
    match ioctl(
        fd,
        libc::TUNSETVNETHDRSZ,
        (&mut value as *mut libc::c_int).cast::<libc::c_void>(),
    ) {
        Ok(()) => {}
        Err(error) if size == VirtioNetHdr::LEN && is_unsupported(&error) => {
            log::debug!("TUNSETVNETHDRSZ is unsupported; using the default 10-byte header");
            return Ok(VirtioNetHdr::LEN);
        }
        Err(error) if is_unsupported(&error) => {
            return Err(TunError::Unsupported("12-byte virtio-net header"));
        }
        Err(error) => return Err(TunError::Io(error)),
    }

    match get_vnet_hdr_size(fd) {
        Ok(actual) if actual == VirtioNetHdr::LEN_WITH_NUM_BUFFERS => {
            Ok(VirtioNetHdr::LEN_WITH_NUM_BUFFERS)
        }
        Ok(actual) if actual == VirtioNetHdr::LEN => Ok(VirtioNetHdr::LEN),
        Ok(_) => Err(TunError::Unsupported("virtio-net header size")),
        Err(error) if is_unsupported(&error) => Ok(size),
        Err(error) => Err(TunError::Io(error)),
    }
}

fn get_vnet_hdr_size(fd: RawFd) -> io::Result<usize> {
    let mut value: libc::c_int = 0;
    ioctl(
        fd,
        libc::TUNGETVNETHDRSZ,
        (&mut value as *mut libc::c_int).cast::<libc::c_void>(),
    )?;
    usize::try_from(value)
        .map_err(|_| io::Error::new(ErrorKind::InvalidData, "negative virtio-net header size"))
}

fn set_offload_fd(fd: RawFd, offload: Offload) -> io::Result<()> {
    let mut bits = offload.bits() as libc::c_int;
    ioctl(
        fd,
        libc::TUNSETOFFLOAD,
        (&mut bits as *mut libc::c_int).cast::<libc::c_void>(),
    )
}

fn enable_offload(fd: RawFd) -> TunResult<Offload> {
    let candidates = [
        Offload::LEGACY_TCP,
        Offload::LEGACY_TCP.without_ufo(),
        Offload::CSUM,
    ];

    for candidate in candidates {
        match set_offload_fd(fd, candidate) {
            Ok(()) => {
                let with_uso = candidate | Offload::USO;
                let enabled = if set_offload_fd(fd, with_uso).is_ok() {
                    with_uso
                } else {
                    log::debug!("TUN UDP segmentation offload is unavailable");
                    candidate
                };
                return Ok(enabled);
            }
            Err(error) if is_unsupported(&error) => {}
            Err(error) => return Err(TunError::Io(error)),
        }
    }

    Err(TunError::Unsupported("TUN offload"))
}

fn set_nonblocking(file: &File, nonblocking: bool) -> TunResult<()> {
    let mut flags = fcntl_getfl(file).map_err(|error| TunError::Io(error.into()))?;
    if nonblocking {
        flags.insert(OFlags::NONBLOCK);
    } else {
        flags.remove(OFlags::NONBLOCK);
    }
    fcntl_setfl(file, flags).map_err(|error| TunError::Io(error.into()))?;
    Ok(())
}

fn interface_socket() -> io::Result<UdpSocket> {
    UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
}

fn set_mtu_by_name(name: &str, mtu: u32) -> TunResult<()> {
    if mtu > i32::MAX as u32 {
        return Err(invalid_config("MTU is out of range"));
    }
    let socket = interface_socket()?;
    let mut ifreq = IfReq::new(name)?;
    ifreq.set_mtu(mtu);
    ioctl(
        socket.as_raw_fd(),
        SIOCSIFMTU,
        (&mut ifreq as *mut IfReq).cast::<libc::c_void>(),
    )?;
    Ok(())
}

fn get_mtu_by_name(name: &str) -> TunResult<u32> {
    let socket = interface_socket()?;
    let mut ifreq = IfReq::new(name)?;
    ioctl(
        socket.as_raw_fd(),
        SIOCGIFMTU,
        (&mut ifreq as *mut IfReq).cast::<libc::c_void>(),
    )?;
    Ok(ifreq.mtu())
}

fn interface_index_by_name(name: &str) -> TunResult<u32> {
    let socket = interface_socket()?;
    let mut ifreq = IfReq::new(name)?;
    ioctl(
        socket.as_raw_fd(),
        SIOCGIFINDEX,
        (&mut ifreq as *mut IfReq).cast::<libc::c_void>(),
    )?;
    Ok(ifreq.ifindex())
}

fn read_file(file: &mut File, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        match file.read(buf) {
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

fn write_all_file(file: &File, mut buf: &[u8]) -> io::Result<()> {
    let mut file = file;
    while !buf.is_empty() {
        match file.write(buf) {
            Ok(0) => {
                return Err(io::Error::new(
                    ErrorKind::WriteZero,
                    "TUN write returned zero bytes",
                ));
            }
            Ok(written) => buf = &buf[written..],
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn write_packet(file: &File, header: &[u8], packet: &[u8]) -> io::Result<()> {
    let total = header.len() + packet.len();
    let mut file = file;
    loop {
        let slices = [IoSlice::new(header), IoSlice::new(packet)];
        match file.write_vectored(&slices) {
            Ok(0) => {
                return Err(io::Error::new(
                    ErrorKind::WriteZero,
                    "TUN write returned zero bytes",
                ));
            }
            Ok(written) if written == total => return Ok(()),
            Ok(written) if written < header.len() => {
                write_all_file(file, &header[written..])?;
                write_all_file(file, packet)?;
                return Ok(());
            }
            Ok(written) => {
                write_all_file(file, &packet[written - header.len()..])?;
                return Ok(());
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

fn truncate_buf(slot: &mut &mut [u8], len: usize) {
    let buffer = std::mem::take(slot);
    let (head, _) = buffer.split_at_mut(len);
    *slot = head;
}

fn is_unsupported(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(code)
            if code == libc::EINVAL
                || code == libc::ENOTTY
                || code == libc::EOPNOTSUPP
                || code == libc::ENOSYS
    )
}

fn invalid_config(message: &'static str) -> TunError {
    TunError::InvalidConfig(message)
}

fn invalid_gso(message: &'static str) -> TunError {
    TunError::Gso(GsoError::Invalid(message))
}

fn buffer_too_small(needed: usize, available: usize) -> TunError {
    TunError::BufferTooSmall { needed, available }
}

fn short_virtio_header(expected: usize, actual: usize) -> TunError {
    TunError::ShortVirtioHeader { expected, actual }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::offload::packet_buffer_size;

    #[test]
    fn ifreq_layout_matches_kernel_abi() {
        let expected = if cfg!(target_pointer_width = "64") { 40 } else { 32 };
        assert_eq!(core::mem::size_of::<IfReq>(), expected);
    }

    #[test]
    fn ifreq_roundtrips_fields() {
        let mut ifreq = IfReq::new("umbrawg0").unwrap();
        assert_eq!(ifreq.name_string().unwrap(), "umbrawg0");

        let flags = (libc::IFF_TUN | libc::IFF_NO_PI | libc::IFF_MULTI_QUEUE) as libc::c_short;
        ifreq.set_flags(flags);
        assert_eq!(ifreq.flags(), flags);

        ifreq.set_mtu(1420);
        assert_eq!(ifreq.mtu(), 1420);

        ifreq.set_ifindex(42);
        assert_eq!(ifreq.ifindex(), 42);
    }

    #[test]
    fn ifreq_accepts_empty_and_maximum_names() {
        assert!(IfReq::new("").is_ok());
        assert!(IfReq::new(&"a".repeat(libc::IFNAMSIZ - 1)).is_ok());
    }

    #[test]
    fn ifreq_rejects_invalid_names() {
        assert!(matches!(
            IfReq::new(&"a".repeat(libc::IFNAMSIZ)),
            Err(TunError::InvalidConfig(_))
        ));
        assert!(matches!(
            IfReq::new("bad\0name"),
            Err(TunError::InvalidConfig(_))
        ));
    }

    #[test]
    fn config_validation_runs_before_opening_the_device() {
        let long_name = TunConfig::new("a".repeat(libc::IFNAMSIZ));
        assert!(matches!(
            Tun::open(&long_name),
            Err(TunError::InvalidConfig(_))
        ));

        let bad_header = TunConfig::new("umbrawg0").with_vnet_hdr_size(11);
        assert!(matches!(
            Tun::open(&bad_header),
            Err(TunError::InvalidConfig(_))
        ));

        assert!(matches!(
            TunSet::open(&TunConfig::default(), 0),
            Err(TunError::InvalidConfig(_))
        ));
    }

    #[test]
    fn config_accepts_ten_and_twelve_byte_headers() {
        assert!(validate_config(&TunConfig::new("umbrawg0").with_vnet_hdr_size(10)).is_ok());
        assert!(validate_config(&TunConfig::new("umbrawg0").with_vnet_hdr_size(12)).is_ok());
        assert!(matches!(
            validate_config(&TunConfig::new("umbrawg0").with_vnet_hdr_size(11)),
            Err(TunError::InvalidConfig(_))
        ));
        assert!(validate_config(
            &TunConfig::new("umbrawg0")
                .with_offload(false)
                .with_vnet_hdr_size(11)
        )
        .is_ok());
    }

    #[test]
    fn offload_bit_conversion_roundtrips() {
        for offload in [
            Offload::NONE,
            Offload::CSUM,
            Offload::TCP,
            Offload::LEGACY_TCP,
            Offload::USO,
            Offload::LEGACY_TCP | Offload::USO,
        ] {
            assert_eq!(Offload::from_bits(offload.bits()), offload);
        }
        assert_eq!(Offload::NONE.bits(), 0);
        assert!(Offload::NONE.is_empty());
        assert!(!Offload::TCP.is_empty());
        assert_eq!(Offload::LEGACY_TCP.without_ufo(), Offload::TCP);
        assert_eq!(
            Offload::TCP | Offload::USO,
            Offload::from_bits(Offload::TCP.bits() | Offload::USO.bits())
        );
    }

    #[test]
    fn buffer_sizing_matches_header_mode() {
        assert_eq!(read_buffer_size(0), 65_535);
        assert_eq!(packet_buffer_size(1420, 10), 1430);
    }
}
