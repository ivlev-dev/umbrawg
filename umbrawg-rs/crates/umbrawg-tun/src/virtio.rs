//! `virtio_net_hdr` parsing and serialization.
//!
//! The layout follows `include/uapi/linux/virtio_net.h`. The first ten bytes are
//! the legacy `virtio_net_hdr`; kernels that support `TUNSETVNETHDRSZ` may also
//! use the twelve-byte `virtio_net_hdr_v1` variant with `num_buffers`.

use crate::error::{TunError, TunResult};

/// The checksum at `csum_start + csum_offset` is partial and must be completed.
pub const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 0x01;
/// The transport checksum has already been validated by the device.
pub const VIRTIO_NET_HDR_F_DATA_VALID: u8 = 0x02;
/// No segmentation offload.
pub const VIRTIO_NET_HDR_GSO_NONE: u8 = 0x00;
/// TCP segmentation offload over IPv4.
pub const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 0x01;
/// Legacy UDP fragmentation offload.
pub const VIRTIO_NET_HDR_GSO_UDP: u8 = 0x03;
/// TCP segmentation offload over IPv6.
pub const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 0x04;
/// UDP segmentation offload over IPv4 or IPv6.
pub const VIRTIO_NET_HDR_GSO_UDP_L4: u8 = 0x05;
/// Modifier bit: the TCP header carries ECN flags.
pub const VIRTIO_NET_HDR_GSO_ECN: u8 = 0x80;

/// Parsed segmentation offload type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GsoType {
    /// No segmentation offload.
    None,
    /// TCP over IPv4.
    TcpV4,
    /// Legacy UDP fragmentation offload.
    Udp,
    /// TCP over IPv6.
    TcpV6,
    /// UDP segmentation offload.
    UdpL4,
}

impl GsoType {
    /// Returns the raw `gso_type` value without the ECN modifier.
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::None => VIRTIO_NET_HDR_GSO_NONE,
            Self::TcpV4 => VIRTIO_NET_HDR_GSO_TCPV4,
            Self::Udp => VIRTIO_NET_HDR_GSO_UDP,
            Self::TcpV6 => VIRTIO_NET_HDR_GSO_TCPV6,
            Self::UdpL4 => VIRTIO_NET_HDR_GSO_UDP_L4,
        }
    }

    /// Parses a raw `gso_type` value, ignoring the ECN modifier.
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value & !VIRTIO_NET_HDR_GSO_ECN {
            VIRTIO_NET_HDR_GSO_NONE => Some(Self::None),
            VIRTIO_NET_HDR_GSO_TCPV4 => Some(Self::TcpV4),
            VIRTIO_NET_HDR_GSO_UDP => Some(Self::Udp),
            VIRTIO_NET_HDR_GSO_TCPV6 => Some(Self::TcpV6),
            VIRTIO_NET_HDR_GSO_UDP_L4 => Some(Self::UdpL4),
            _ => None,
        }
    }
}

/// A `virtio_net_hdr` as exposed by the Linux TUN driver.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VirtioNetHdr {
    /// `VIRTIO_NET_HDR_F_*` flags.
    pub flags: u8,
    /// Raw `VIRTIO_NET_HDR_GSO_*` value, including the optional ECN bit.
    pub gso_type: u8,
    /// Length of the packet headers before the payload.
    pub hdr_len: u16,
    /// Maximum payload size of a single segment.
    pub gso_size: u16,
    /// Offset of the transport header inside the packet.
    pub csum_start: u16,
    /// Offset of the checksum field inside the transport header.
    pub csum_offset: u16,
    /// Number of mergeable receive buffers (`num_buffers` in `virtio_net_hdr_v1`).
    pub num_buffers: u16,
}

impl VirtioNetHdr {
    /// Size of the legacy `virtio_net_hdr` in bytes.
    pub const LEN: usize = 10;
    /// Size of `virtio_net_hdr_v1` in bytes, including `num_buffers`.
    pub const LEN_WITH_NUM_BUFFERS: usize = 12;

    /// Creates a header with all fields zeroed, meaning no offload.
    pub const fn new() -> Self {
        Self {
            flags: 0,
            gso_type: 0,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 0,
            csum_offset: 0,
            num_buffers: 0,
        }
    }

    /// Decodes a header from `bytes`.
    ///
    /// Slices of ten or eleven bytes are decoded as the legacy header. Slices of
    /// twelve or more bytes are decoded as `virtio_net_hdr_v1` with
    /// `num_buffers`.
    pub fn decode(bytes: &[u8]) -> TunResult<Self> {
        let header_len = if bytes.len() >= Self::LEN_WITH_NUM_BUFFERS {
            Self::LEN_WITH_NUM_BUFFERS
        } else {
            Self::LEN
        };
        Self::decode_sized(bytes, header_len)
    }

    /// Decodes a header of exactly `header_len` bytes from the start of `bytes`.
    ///
    /// `header_len` must be either [`VirtioNetHdr::LEN`] or
    /// [`VirtioNetHdr::LEN_WITH_NUM_BUFFERS`].
    pub fn decode_sized(bytes: &[u8], header_len: usize) -> TunResult<Self> {
        if !matches!(header_len, Self::LEN | Self::LEN_WITH_NUM_BUFFERS) {
            return Err(TunError::InvalidConfig(
                "virtio-net header size must be 10 or 12 bytes",
            ));
        }
        if bytes.len() < header_len {
            return Err(TunError::ShortVirtioHeader {
                expected: header_len,
                actual: bytes.len(),
            });
        }
        let num_buffers = if header_len == Self::LEN_WITH_NUM_BUFFERS {
            u16::from_be_bytes([bytes[10], bytes[11]])
        } else {
            0
        };
        Ok(Self {
            flags: bytes[0],
            gso_type: bytes[1],
            hdr_len: u16::from_be_bytes([bytes[2], bytes[3]]),
            gso_size: u16::from_be_bytes([bytes[4], bytes[5]]),
            csum_start: u16::from_be_bytes([bytes[6], bytes[7]]),
            csum_offset: u16::from_be_bytes([bytes[8], bytes[9]]),
            num_buffers,
        })
    }

    /// Encodes the legacy ten-byte header into the start of `out`.
    pub fn encode(&self, out: &mut [u8]) -> TunResult<()> {
        self.encode_sized(out, Self::LEN)
    }

    /// Encodes the twelve-byte `virtio_net_hdr_v1` into the start of `out`.
    pub fn encode_v1(&self, out: &mut [u8]) -> TunResult<()> {
        self.encode_sized(out, Self::LEN_WITH_NUM_BUFFERS)
    }

    /// Encodes a header of exactly `header_len` bytes into the start of `out`.
    ///
    /// `header_len` must be either [`VirtioNetHdr::LEN`] or
    /// [`VirtioNetHdr::LEN_WITH_NUM_BUFFERS`].
    pub fn encode_sized(&self, out: &mut [u8], header_len: usize) -> TunResult<()> {
        if !matches!(header_len, Self::LEN | Self::LEN_WITH_NUM_BUFFERS) {
            return Err(TunError::InvalidConfig(
                "virtio-net header size must be 10 or 12 bytes",
            ));
        }
        if out.len() < header_len {
            return Err(TunError::BufferTooSmall {
                needed: header_len,
                available: out.len(),
            });
        }
        out[..Self::LEN].copy_from_slice(&self.to_bytes());
        if header_len == Self::LEN_WITH_NUM_BUFFERS {
            out[Self::LEN..Self::LEN_WITH_NUM_BUFFERS]
                .copy_from_slice(&self.num_buffers.to_be_bytes());
        }
        Ok(())
    }

    /// Returns the legacy wire representation of the header.
    pub const fn to_bytes(self) -> [u8; Self::LEN] {
        let hdr_len = self.hdr_len.to_be_bytes();
        let gso_size = self.gso_size.to_be_bytes();
        let csum_start = self.csum_start.to_be_bytes();
        let csum_offset = self.csum_offset.to_be_bytes();
        [
            self.flags,
            self.gso_type,
            hdr_len[0],
            hdr_len[1],
            gso_size[0],
            gso_size[1],
            csum_start[0],
            csum_start[1],
            csum_offset[0],
            csum_offset[1],
        ]
    }

    /// Returns the `virtio_net_hdr_v1` wire representation of the header.
    pub const fn to_bytes_v1(self) -> [u8; Self::LEN_WITH_NUM_BUFFERS] {
        let legacy = self.to_bytes();
        let num_buffers = self.num_buffers.to_be_bytes();
        [
            legacy[0],
            legacy[1],
            legacy[2],
            legacy[3],
            legacy[4],
            legacy[5],
            legacy[6],
            legacy[7],
            legacy[8],
            legacy[9],
            num_buffers[0],
            num_buffers[1],
        ]
    }

    /// Returns `true` when the transport checksum must be completed in software.
    pub const fn needs_csum(&self) -> bool {
        self.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM != 0
    }

    /// Returns `true` when the device marked the transport checksum as valid.
    pub const fn data_valid(&self) -> bool {
        self.flags & VIRTIO_NET_HDR_F_DATA_VALID != 0
    }

    /// Returns `true` when the ECN modifier bit is set.
    pub const fn ecn(&self) -> bool {
        self.gso_type & VIRTIO_NET_HDR_GSO_ECN != 0
    }

    /// Parses the segmentation offload type, ignoring the ECN modifier.
    pub const fn gso(&self) -> Option<GsoType> {
        GsoType::from_u8(self.gso_type)
    }

    /// Sets the segmentation offload type while preserving the ECN modifier.
    pub fn set_gso(&mut self, gso: GsoType) {
        let ecn = self.gso_type & VIRTIO_NET_HDR_GSO_ECN;
        self.gso_type = gso.as_u8() | ecn;
    }
}

impl From<VirtioNetHdr> for [u8; VirtioNetHdr::LEN] {
    fn from(header: VirtioNetHdr) -> Self {
        header.to_bytes()
    }
}

impl From<VirtioNetHdr> for [u8; VirtioNetHdr::LEN_WITH_NUM_BUFFERS] {
    fn from(header: VirtioNetHdr) -> Self {
        header.to_bytes_v1()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GSO_TYPES: [u8; 5] = [
        VIRTIO_NET_HDR_GSO_NONE,
        VIRTIO_NET_HDR_GSO_TCPV4,
        VIRTIO_NET_HDR_GSO_UDP,
        VIRTIO_NET_HDR_GSO_TCPV6,
        VIRTIO_NET_HDR_GSO_UDP_L4,
    ];

    #[test]
    fn roundtrips_every_gso_type_and_flag_combination() {
        for gso_type in GSO_TYPES {
            for flags in [
                0,
                VIRTIO_NET_HDR_F_NEEDS_CSUM,
                VIRTIO_NET_HDR_F_DATA_VALID,
                VIRTIO_NET_HDR_F_NEEDS_CSUM | VIRTIO_NET_HDR_F_DATA_VALID,
            ] {
                let header = VirtioNetHdr {
                    flags,
                    gso_type,
                    hdr_len: 60,
                    gso_size: 1440,
                    csum_start: 40,
                    csum_offset: 16,
                    num_buffers: 0,
                };
                let bytes = header.to_bytes();
                let mut encoded = [0xAAu8; VirtioNetHdr::LEN_WITH_NUM_BUFFERS];
                header.encode(&mut encoded).unwrap();
                assert_eq!(&encoded[..VirtioNetHdr::LEN], &bytes);
                assert_eq!(encoded[10..], [0xAA, 0xAA]);
                assert_eq!(VirtioNetHdr::decode(&bytes).unwrap(), header);

                let mut encoded_v1 = [0xAAu8; VirtioNetHdr::LEN_WITH_NUM_BUFFERS];
                header.encode_v1(&mut encoded_v1).unwrap();
                assert_eq!(encoded_v1, header.to_bytes_v1());
                assert_eq!(VirtioNetHdr::decode(&encoded_v1).unwrap(), header);
            }
        }
    }

    #[test]
    fn roundtrips_extreme_field_values() {
        let header = VirtioNetHdr {
            flags: u8::MAX,
            gso_type: u8::MAX,
            hdr_len: u16::MAX,
            gso_size: 0,
            csum_start: u16::MAX,
            csum_offset: u16::MAX,
            num_buffers: u16::MAX,
        };
        assert_eq!(
            VirtioNetHdr::decode(&header.to_bytes_v1()).unwrap(),
            header
        );
        assert_eq!(
            VirtioNetHdr::decode(&header.to_bytes()).unwrap().num_buffers,
            0
        );
    }

    #[test]
    fn decodes_all_known_gso_types() {
        assert_eq!(GsoType::from_u8(0), Some(GsoType::None));
        assert_eq!(GsoType::from_u8(1), Some(GsoType::TcpV4));
        assert_eq!(GsoType::from_u8(3), Some(GsoType::Udp));
        assert_eq!(GsoType::from_u8(4), Some(GsoType::TcpV6));
        assert_eq!(GsoType::from_u8(5), Some(GsoType::UdpL4));
        assert_eq!(GsoType::from_u8(2), None);
        assert_eq!(GsoType::from_u8(6), None);
        assert_eq!(GsoType::from_u8(u8::MAX), None);
    }

    #[test]
    fn ecn_bit_does_not_change_parsed_gso_type() {
        let header = VirtioNetHdr {
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4 | VIRTIO_NET_HDR_GSO_ECN,
            ..VirtioNetHdr::new()
        };
        assert!(header.ecn());
        assert_eq!(header.gso(), Some(GsoType::TcpV4));
        assert_eq!(
            VirtioNetHdr::decode(&header.to_bytes()).unwrap().gso_type,
            header.gso_type
        );
    }

    #[test]
    fn set_gso_preserves_ecn() {
        let mut header = VirtioNetHdr {
            gso_type: VIRTIO_NET_HDR_GSO_ECN,
            ..VirtioNetHdr::new()
        };
        header.set_gso(GsoType::UdpL4);
        assert_eq!(
            header.gso_type,
            VIRTIO_NET_HDR_GSO_UDP_L4 | VIRTIO_NET_HDR_GSO_ECN
        );
    }

    #[test]
    fn flag_helpers() {
        let header = VirtioNetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            ..VirtioNetHdr::new()
        };
        assert!(header.needs_csum());
        assert!(!header.data_valid());

        let header = VirtioNetHdr {
            flags: VIRTIO_NET_HDR_F_DATA_VALID,
            ..VirtioNetHdr::new()
        };
        assert!(!header.needs_csum());
        assert!(header.data_valid());
    }

    #[test]
    fn rejects_short_decode_and_encode_buffers() {
        let bytes = [0u8; VirtioNetHdr::LEN - 1];
        assert!(matches!(
            VirtioNetHdr::decode(&bytes),
            Err(TunError::ShortVirtioHeader {
                expected: VirtioNetHdr::LEN,
                actual,
            }) if actual == VirtioNetHdr::LEN - 1
        ));

        let mut out = [0u8; VirtioNetHdr::LEN - 1];
        assert!(matches!(
            VirtioNetHdr::new().encode(&mut out),
            Err(TunError::BufferTooSmall {
                needed: VirtioNetHdr::LEN,
                available,
            }) if available == VirtioNetHdr::LEN - 1
        ));

        let mut out_v1 = [0u8; VirtioNetHdr::LEN_WITH_NUM_BUFFERS - 1];
        assert!(matches!(
            VirtioNetHdr::new().encode_v1(&mut out_v1),
            Err(TunError::BufferTooSmall {
                needed: VirtioNetHdr::LEN_WITH_NUM_BUFFERS,
                available,
            }) if available == VirtioNetHdr::LEN_WITH_NUM_BUFFERS - 1
        ));
    }

    #[test]
    fn rejects_invalid_header_lengths() {
        let bytes = [0u8; VirtioNetHdr::LEN_WITH_NUM_BUFFERS];
        assert!(matches!(
            VirtioNetHdr::decode_sized(&bytes, VirtioNetHdr::LEN + 1),
            Err(TunError::InvalidConfig(_))
        ));
        assert!(matches!(
            VirtioNetHdr::decode_sized(&bytes[..VirtioNetHdr::LEN], VirtioNetHdr::LEN_WITH_NUM_BUFFERS),
            Err(TunError::ShortVirtioHeader {
                expected: VirtioNetHdr::LEN_WITH_NUM_BUFFERS,
                actual: VirtioNetHdr::LEN,
            })
        ));
        let mut out = [0u8; VirtioNetHdr::LEN_WITH_NUM_BUFFERS];
        assert!(matches!(
            VirtioNetHdr::new().encode_sized(&mut out, VirtioNetHdr::LEN + 1),
            Err(TunError::InvalidConfig(_))
        ));
    }

    #[test]
    fn decode_sized_respects_legacy_and_v1_layouts() {
        let header = VirtioNetHdr {
            num_buffers: 0x1234,
            ..VirtioNetHdr::new()
        };
        let bytes = header.to_bytes_v1();
        assert_eq!(
            VirtioNetHdr::decode_sized(&bytes, VirtioNetHdr::LEN)
                .unwrap()
                .num_buffers,
            0
        );
        assert_eq!(
            VirtioNetHdr::decode_sized(&bytes, VirtioNetHdr::LEN_WITH_NUM_BUFFERS)
                .unwrap()
                .num_buffers,
            0x1234
        );
    }

    #[test]
    fn encode_uses_network_byte_order() {
        let header = VirtioNetHdr {
            flags: 1,
            gso_type: 4,
            hdr_len: 0x1234,
            gso_size: 0x5678,
            csum_start: 0x9ABC,
            csum_offset: 0xDEF0,
            num_buffers: 0x0F1E,
        };
        assert_eq!(
            header.to_bytes(),
            [1, 4, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]
        );
        assert_eq!(
            header.to_bytes_v1(),
            [1, 4, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x0F, 0x1E]
        );
    }
}
