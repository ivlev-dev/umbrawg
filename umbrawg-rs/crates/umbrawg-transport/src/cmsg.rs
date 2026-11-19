//! Socket control message (`cmsg`) construction and parsing.
//!
//! Only the messages the transport needs are modelled: `UDP_SEGMENT` (GSO),
//! `UDP_GRO` (GRO) and the sticky-socket `IP_PKTINFO`/`IPV6_PKTINFO` pair.
//! Everything is build on aligned, caller-owned buffers; no control message
//! processing allocates.

use core::mem;
use core::ptr;

use crate::consts::{CONTROL_BUFFER_SIZE, SOL_UDP, UDP_GRO, UDP_SEGMENT};
use crate::gso::GsoSize;
use crate::{Result, TransportError};

/// Length of the data of a `UDP_SEGMENT` control message.
const SEGMENT_DATA_LEN: usize = 2;
/// Length of the data of a `UDP_GRO` control message: the kernel writes an `int`.
const GRO_DATA_LEN: usize = 4;

/// `CMSG_ALIGN`.
pub(crate) const fn cmsg_align(length: usize) -> usize {
    let align = mem::size_of::<usize>();
    (length + align - 1) & !(align - 1)
}

/// `CMSG_LEN`.
pub(crate) const fn cmsg_len(data_len: usize) -> usize {
    cmsg_align(mem::size_of::<libc::cmsghdr>()) + data_len
}

/// `CMSG_SPACE`.
pub(crate) const fn cmsg_space(data_len: usize) -> usize {
    cmsg_align(mem::size_of::<libc::cmsghdr>()) + cmsg_align(data_len)
}

/// Alignment of a single control message header.
const fn header_len() -> usize {
    cmsg_align(mem::size_of::<libc::cmsghdr>())
}

/// An aligned control buffer suitable for one `recvmsg`/`sendmsg` call.
///
/// The kernel writes `cmsghdr` structures into this buffer and expects them to be
/// naturally aligned, which a plain `[u8; N]` does not guarantee.
#[repr(align(8))]
#[derive(Clone)]
pub struct ControlBuffer {
    data: [u8; CONTROL_BUFFER_SIZE],
}

impl ControlBuffer {
    /// Creates a zeroed control buffer.
    pub const fn new() -> Self {
        Self {
            data: [0u8; CONTROL_BUFFER_SIZE],
        }
    }

    /// Returns the whole buffer, including unused trailing bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Returns the whole buffer mutably.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Returns the raw pointer to the start of the buffer.
    pub(crate) fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }

    /// Capacity of the buffer in bytes.
    pub const fn capacity(&self) -> usize {
        CONTROL_BUFFER_SIZE
    }
}

impl Default for ControlBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for ControlBuffer {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ControlBuffer")
            .field("capacity", &CONTROL_BUFFER_SIZE)
            .finish()
    }
}

/// A single parsed control message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlMessage<'a> {
    /// Protocol level (`SOL_UDP`, `IPPROTO_IP`, `IPPROTO_IPV6`, ...).
    pub level: libc::c_int,
    /// Message type (`UDP_SEGMENT`, `UDP_GRO`, `IP_PKTINFO`, ...).
    pub ty: libc::c_int,
    /// Message payload without the header.
    pub data: &'a [u8],
}

/// Iterator over the control messages in a `recvmsg` control buffer.
#[derive(Clone, Debug)]
pub struct ControlMessages<'a> {
    remaining: &'a [u8],
}

impl<'a> ControlMessages<'a> {
    /// Creates an iterator over `control`.
    ///
    /// Bytes shorter than a single header are ignored, mirroring the kernel's
    /// `CMSG_OK` check.
    pub fn new(control: &'a [u8]) -> Self {
        Self { remaining: control }
    }

    /// Returns the remaining unparsed bytes.
    pub fn remaining(&self) -> &'a [u8] {
        self.remaining
    }
}

impl<'a> Iterator for ControlMessages<'a> {
    type Item = Result<ControlMessage<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.len() < header_len() {
            self.remaining = &[];
            return None;
        }
        // SAFETY: at least `size_of::<cmsghdr>()` bytes are available and
        // `read_unaligned` does not require any alignment of the source.
        let header =
            unsafe { ptr::read_unaligned(self.remaining.as_ptr().cast::<libc::cmsghdr>()) };
        let total = header.cmsg_len;
        if total < header_len() || total > self.remaining.len() {
            self.remaining = &[];
            return Some(Err(TransportError::InvalidControlMessage {
                reason: "control message length is out of bounds",
            }));
        }
        let data = &self.remaining[header_len()..total];
        let message = ControlMessage {
            level: header.cmsg_level,
            ty: header.cmsg_type,
            data,
        };
        let advance = cmsg_align(total).min(self.remaining.len());
        self.remaining = &self.remaining[advance..];
        Some(Ok(message))
    }
}

/// Writes control messages into a [`ControlBuffer`].
#[derive(Debug)]
pub struct CmsgWriter<'a> {
    buffer: &'a mut [u8],
    used: usize,
}

impl<'a> CmsgWriter<'a> {
    /// Creates a writer over `buffer`.
    pub fn new(buffer: &'a mut ControlBuffer) -> Self {
        Self {
            buffer: buffer.as_mut_slice(),
            used: 0,
        }
    }

    /// Returns `true` if no message was written yet.
    pub fn is_empty(&self) -> bool {
        self.used == 0
    }

    /// Number of bytes occupied by control messages so far.
    pub fn len(&self) -> usize {
        self.used
    }

    /// Appends one control message with `data` as its payload.
    pub fn push(&mut self, level: libc::c_int, ty: libc::c_int, data: &[u8]) -> Result<()> {
        let space = cmsg_space(data.len());
        let available = self.buffer.len() - self.used;
        if available < space {
            return Err(TransportError::BufferTooSmall {
                needed: space,
                available,
            });
        }
        let start = self.used;
        let header = libc::cmsghdr {
            cmsg_len: cmsg_len(data.len()),
            cmsg_level: level,
            cmsg_type: ty,
        };
        // SAFETY: `space` bytes were reserved above, so both the header and the
        // payload fit into the buffer. `write_unaligned` handles the fact that the
        // buffer itself is only byte-addressed.
        unsafe {
            ptr::write_unaligned(
                self.buffer.as_mut_ptr().add(start).cast::<libc::cmsghdr>(),
                header,
            );
        }
        let data_start = start + header_len();
        let data_end = data_start + data.len();
        self.buffer[data_start..data_end].copy_from_slice(data);
        for byte in &mut self.buffer[data_end..start + space] {
            *byte = 0;
        }
        self.used = start + space;
        Ok(())
    }

    /// Appends a `UDP_SEGMENT` message describing the GSO segment size.
    pub fn push_gso(&mut self, gso_size: GsoSize) -> Result<()> {
        self.push(SOL_UDP, UDP_SEGMENT, &gso_size.get().to_ne_bytes())
    }

    /// Returns the control data written so far.
    pub fn finish(&self) -> &[u8] {
        &self.buffer[..self.used]
    }
}

fn segment_size(
    message: &ControlMessage<'_>,
    ty: libc::c_int,
    name: &'static str,
) -> Result<GsoSize> {
    if message.ty != ty {
        return Err(TransportError::InvalidControlMessage { reason: name });
    }
    if message.data.len() < SEGMENT_DATA_LEN {
        return Err(TransportError::InvalidControlMessage { reason: name });
    }
    let mut raw = [0u8; SEGMENT_DATA_LEN];
    raw.copy_from_slice(&message.data[..SEGMENT_DATA_LEN]);
    GsoSize::new(u16::from_ne_bytes(raw)).map_err(|_| TransportError::InvalidControlMessage {
        reason: "segment size is zero",
    })
}

/// Parses the `UDP_GRO` segment size reported by the kernel.
///
/// Returns `Ok(None)` when the datagram was not receive-offloaded.
pub fn gro_size(control: &[u8]) -> Result<Option<GsoSize>> {
    for message in ControlMessages::new(control) {
        let message = message?;
        if message.level == SOL_UDP && message.ty == UDP_GRO {
            if message.data.len() < GRO_DATA_LEN {
                return Err(TransportError::InvalidControlMessage {
                    reason: "UDP_GRO payload is invalid",
                });
            }
            let mut raw = [0u8; GRO_DATA_LEN];
            raw.copy_from_slice(&message.data[..GRO_DATA_LEN]);
            let size = u32::from_ne_bytes(raw);
            let size = u16::try_from(size).map_err(|_| TransportError::InvalidControlMessage {
                reason: "UDP_GRO segment size is too large",
            })?;
            return GsoSize::new(size).map(Some).map_err(|_| {
                TransportError::InvalidControlMessage {
                    reason: "UDP_GRO segment size is zero",
                }
            });
        }
    }
    Ok(None)
}

/// Parses the `UDP_SEGMENT` segment size of an outgoing datagram.
///
/// Returns `Ok(None)` when the control data does not request segmentation.
pub fn gso_size(control: &[u8]) -> Result<Option<GsoSize>> {
    for message in ControlMessages::new(control) {
        let message = message?;
        if message.level == SOL_UDP && message.ty == UDP_SEGMENT {
            return segment_size(&message, UDP_SEGMENT, "UDP_SEGMENT payload is invalid").map(Some);
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn control_of(message: ControlMessage<'_>) -> ControlBuffer {
        let mut buffer = ControlBuffer::new();
        let mut writer = CmsgWriter::new(&mut buffer);
        writer
            .push(message.level, message.ty, message.data)
            .unwrap();
        buffer
    }

    #[test]
    fn gso_round_trip() {
        let size = GsoSize::new(1420).unwrap();
        let mut buffer = ControlBuffer::new();
        let mut writer = CmsgWriter::new(&mut buffer);
        assert!(writer.is_empty());
        writer.push_gso(size).unwrap();
        assert_eq!(writer.len(), cmsg_space(2));
        let control = writer.finish().to_vec();

        assert_eq!(gso_size(&control).unwrap(), Some(size));
        assert_eq!(gro_size(&control).unwrap(), None);
    }

    #[test]
    fn gro_round_trip() {
        let size = GsoSize::new(1280).unwrap();
        let mut buffer = ControlBuffer::new();
        let mut writer = CmsgWriter::new(&mut buffer);
        writer
            .push(SOL_UDP, UDP_GRO, &u32::from(size.get()).to_ne_bytes())
            .unwrap();
        let control = writer.finish().to_vec();

        assert_eq!(gro_size(&control).unwrap(), Some(size));
        assert_eq!(gso_size(&control).unwrap(), None);
    }

    #[test]
    fn messages_are_aligned_and_parsed_in_order() {
        let mut buffer = ControlBuffer::new();
        let mut writer = CmsgWriter::new(&mut buffer);
        writer
            .push(libc::IPPROTO_IP, libc::IP_PKTINFO, &[1u8; 12])
            .unwrap();
        writer
            .push(SOL_UDP, UDP_SEGMENT, &1400u16.to_ne_bytes())
            .unwrap();
        let used = writer.len();
        assert_eq!(used, cmsg_space(12) + cmsg_space(2));

        let control = writer.finish().to_vec();
        let messages: Vec<_> = ControlMessages::new(&control)
            .collect::<Result<Vec<_>>>()
            .unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].level, libc::IPPROTO_IP);
        assert_eq!(messages[0].ty, libc::IP_PKTINFO);
        assert_eq!(messages[0].data, &[1u8; 12]);
        assert_eq!(messages[1].level, SOL_UDP);
        assert_eq!(messages[1].ty, UDP_SEGMENT);
        assert_eq!(messages[1].data, &1400u16.to_ne_bytes());
        assert_eq!(
            gso_size(&control).unwrap(),
            Some(GsoSize::new(1400).unwrap())
        );
    }

    #[test]
    fn buffer_exhaustion_is_reported() {
        let mut buffer = ControlBuffer::new();
        let mut writer = CmsgWriter::new(&mut buffer);
        writer
            .push(SOL_UDP, UDP_SEGMENT, &1400u16.to_ne_bytes())
            .unwrap();
        writer
            .push(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, &[0u8; 20])
            .unwrap();
        let mut exhausted = false;
        for _ in 0..8 {
            if writer
                .push(libc::IPPROTO_IP, libc::IP_PKTINFO, &[0u8; 12])
                .is_err()
            {
                exhausted = true;
                break;
            }
        }
        assert!(exhausted, "control buffer must report exhaustion");
    }

    #[test]
    fn truncated_control_data_is_ignored() {
        assert_eq!(gro_size(&[]).unwrap(), None);
        assert_eq!(gro_size(&[0u8; 4]).unwrap(), None);
        assert_eq!(gso_size(&[0u8; 4]).unwrap(), None);
        assert_eq!(ControlMessages::new(&[0u8; 4]).count(), 0);
    }

    #[test]
    fn undersized_cmsg_len_is_an_error() {
        let mut buffer = control_of(ControlMessage {
            level: SOL_UDP,
            ty: UDP_SEGMENT,
            data: &[0u8; 2],
        });
        buffer.as_mut_slice()[..mem::size_of::<usize>()]
            .copy_from_slice(&(header_len() - 1).to_ne_bytes());
        let control = buffer.as_slice().to_vec();
        assert!(matches!(
            gso_size(&control),
            Err(TransportError::InvalidControlMessage { .. })
        ));
        assert!(matches!(
            ControlMessages::new(&control).next(),
            Some(Err(TransportError::InvalidControlMessage { .. }))
        ));
    }

    #[test]
    fn oversized_cmsg_len_is_an_error() {
        let mut buffer = control_of(ControlMessage {
            level: SOL_UDP,
            ty: UDP_GRO,
            data: &[0u8; 2],
        });
        buffer.as_mut_slice()[..mem::size_of::<usize>()]
            .copy_from_slice(&(CONTROL_BUFFER_SIZE * 2).to_ne_bytes());
        let control = buffer.as_slice().to_vec();
        assert!(matches!(
            gro_size(&control),
            Err(TransportError::InvalidControlMessage { .. })
        ));
    }

    #[test]
    fn short_segment_payload_is_an_error() {
        let buffer = control_of(ControlMessage {
            level: SOL_UDP,
            ty: UDP_GRO,
            data: &[1u8],
        });
        assert!(matches!(
            gro_size(buffer.as_slice()),
            Err(TransportError::InvalidControlMessage { .. })
        ));
    }

    #[test]
    fn zero_segment_size_is_an_error() {
        let buffer = control_of(ControlMessage {
            level: SOL_UDP,
            ty: UDP_SEGMENT,
            data: &0u16.to_ne_bytes(),
        });
        assert!(matches!(
            gso_size(buffer.as_slice()),
            Err(TransportError::InvalidControlMessage { .. })
        ));
    }

    #[test]
    fn unknown_messages_are_skipped() {
        let mut buffer = ControlBuffer::new();
        let mut writer = CmsgWriter::new(&mut buffer);
        writer.push(libc::IPPROTO_IP, 1234, &[0u8; 4]).unwrap();
        writer
            .push(SOL_UDP, UDP_GRO, &512u32.to_ne_bytes())
            .unwrap();
        let control = writer.finish().to_vec();
        assert_eq!(
            gro_size(&control).unwrap(),
            Some(GsoSize::new(512).unwrap())
        );
    }

    #[test]
    fn cmsg_geometry_matches_libc() {
        let payload = 20;
        assert_eq!(cmsg_space(payload) as libc::c_uint, unsafe {
            libc::CMSG_SPACE(payload as libc::c_uint)
        });
        assert_eq!(cmsg_len(payload) as libc::c_uint, unsafe {
            libc::CMSG_LEN(payload as libc::c_uint)
        });
    }
}
