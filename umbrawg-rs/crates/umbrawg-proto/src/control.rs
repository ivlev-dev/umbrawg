//! Protocol extension frames carried inside authenticated transport payload.
//!
//! The handshake and the transport header are unchanged. Extension messages
//! start with a marker whose first byte is `0x00`, which is never a valid IP
//! version, so a peer without support drops them as malformed inner packets.

use crate::{ProtoError, Result};

/// Length of the extension prefix.
pub const EXTENSION_HEADER_LEN: usize = 8;
/// First byte of the extension marker (invalid as an IP version).
pub const EXTENSION_TAG: u8 = 0x00;
/// Magic bytes after the tag.
pub const EXTENSION_MAGIC: [u8; 3] = *b"UWG";
/// Supported extension version.
pub const EXTENSION_VERSION: u8 = 1;

const CAPS_LEN: usize = 12;
const ACK_HEADER_LEN: usize = 16;
/// Length of the fixed FEC shard body header that follows the extension prefix.
pub const FEC_HEADER_LEN: usize = 12;

/// Kind of an extension frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlKind {
    /// Capability exchange.
    Caps,
    /// Acknowledgement and delivery feedback.
    Ack,
    /// One Reed-Solomon shard.
    FecShard,
}

impl ControlKind {
    const fn code(self) -> u8 {
        match self {
            Self::Caps => 1,
            Self::Ack => 2,
            Self::FecShard => 3,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Caps),
            2 => Some(Self::Ack),
            3 => Some(Self::FecShard),
            _ => None,
        }
    }
}

/// Capability flags advertised by a peer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CapsFlags(u32);

impl CapsFlags {
    /// Peer supports BBR-style feedback.
    pub const BBR: Self = Self(1 << 0);
    /// Peer can send acknowledgements.
    pub const ACK: Self = Self(1 << 1);
    /// Peer can decode Reed-Solomon shards.
    pub const FEC: Self = Self(1 << 2);
    /// Peer wants adaptive FEC.
    pub const FEC_ADAPTIVE: Self = Self(1 << 3);
    /// Peer accepts partial blocks that carry parity shards.
    ///
    /// A partial block (`k' < k`) is otherwise sent with `m' = 0`, so a single
    /// lost shard loses the whole block. With this flag the sender may emit
    /// `k'` data shards plus up to `m` parity shards, and the receiver decodes
    /// the block with its advertised `(k', m')` shape.
    pub const FEC_PARTIAL: Self = Self(1 << 4);

    /// Creates flags from the wire value.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Returns the wire value.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns `true` if every flag in `other` is set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl core::ops::BitOr for CapsFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// Capability exchange frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caps {
    /// Advertised capabilities.
    pub flags: CapsFlags,
    /// Requested ACK interval in packets; `0` means the default of 2.
    pub ack_interval_packets: u16,
    /// Preferred number of data shards for FEC.
    pub fec_k: u8,
    /// Preferred number of parity shards for FEC.
    pub fec_m: u8,
}

impl Caps {
    /// Encodes the frame into `output`, returning the number of bytes written.
    pub fn encode(&self, output: &mut [u8]) -> Result<usize> {
        let total = EXTENSION_HEADER_LEN + CAPS_LEN;
        if output.len() < total {
            return Err(ProtoError::BufferTooSmall {
                required: total,
                available: output.len(),
            });
        }
        write_prefix(output, ControlKind::Caps, CAPS_LEN)?;
        output[8..12].copy_from_slice(&self.flags.bits().to_le_bytes());
        output[12..14].copy_from_slice(&self.ack_interval_packets.to_le_bytes());
        output[14] = self.fec_k;
        output[15] = self.fec_m;
        output[16..20].copy_from_slice(&0u32.to_le_bytes());
        Ok(total)
    }

    /// Decodes a complete capability frame.
    pub fn decode(frame: &[u8]) -> Result<Self> {
        let body = extension_body(frame, ControlKind::Caps)?;
        if body.len() != CAPS_LEN {
            return Err(ProtoError::InvalidLength {
                expected: CAPS_LEN,
                actual: body.len(),
            });
        }
        let flags = CapsFlags::from_bits(u32::from_le_bytes(
            body[0..4].try_into().expect("checked length"),
        ));
        let ack_interval_packets =
            u16::from_le_bytes(body[4..6].try_into().expect("checked length"));
        Ok(Self {
            flags,
            ack_interval_packets,
            fec_k: body[6],
            fec_m: body[7],
        })
    }
}

/// Acknowledgement and delivery feedback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ack {
    /// Highest received transport counter.
    pub largest_counter: u64,
    /// Delay between receiving `largest_counter` and sending this ACK.
    pub ack_delay_us: u32,
    /// ECN CE counter increased.
    pub ecn_ce: bool,
    /// Bitmap of received counters; bit 0 is `largest_counter`.
    ///
    /// Bits above the length carried by a short ACK are set ("covered"), like
    /// the kernel's `uwg_ext_ack_bitmap`, so they never look like holes.
    pub received: u64,
}

impl Ack {
    /// Encodes the frame into `output`, returning the number of bytes written.
    pub fn encode(&self, output: &mut [u8]) -> Result<usize> {
        let total = EXTENSION_HEADER_LEN + ACK_HEADER_LEN + 8;
        if output.len() < total {
            return Err(ProtoError::BufferTooSmall {
                required: total,
                available: output.len(),
            });
        }
        write_prefix(output, ControlKind::Ack, ACK_HEADER_LEN + 8)?;
        output[8..16].copy_from_slice(&self.largest_counter.to_le_bytes());
        output[16..20].copy_from_slice(&self.ack_delay_us.to_le_bytes());
        output[20] = u8::from(self.ecn_ce);
        output[21] = 8;
        output[22..24].copy_from_slice(&0u16.to_le_bytes());
        output[24..32].copy_from_slice(&self.received.to_le_bytes());
        Ok(total)
    }

    /// Decodes a complete acknowledgement frame.
    pub fn decode(frame: &[u8]) -> Result<Self> {
        let body = extension_body(frame, ControlKind::Ack)?;
        if body.len() < ACK_HEADER_LEN + 1 {
            return Err(ProtoError::InvalidLength {
                expected: ACK_HEADER_LEN + 1,
                actual: body.len(),
            });
        }
        let bitmap_len = usize::from(body[13]);
        if !(1..=8).contains(&bitmap_len) || body.len() != ACK_HEADER_LEN + bitmap_len {
            return Err(ProtoError::InvalidLength {
                expected: ACK_HEADER_LEN + bitmap_len,
                actual: body.len(),
            });
        }
        let mut bitmap = [0u8; 8];
        bitmap[..bitmap_len].copy_from_slice(&body[ACK_HEADER_LEN..ACK_HEADER_LEN + bitmap_len]);
        // Wire parity with the kernel: bits the sender did not include are
        // marked as covered (set), not as holes. A short bitmap is a
        // compatibility path; treating its absent high bits as losses would
        // inflate the BBR loss estimate by up to 63 counters.
        let mut received = u64::from_le_bytes(bitmap);
        let covered = bitmap_len * 8;
        if covered < 64 {
            received |= !0u64 << covered;
        }
        Ok(Self {
            largest_counter: u64::from_le_bytes(body[0..8].try_into().expect("checked length")),
            ack_delay_us: u32::from_le_bytes(body[8..12].try_into().expect("checked length")),
            ecn_ce: body[12] & 1 != 0,
            received,
        })
    }
}

/// Header of one Reed-Solomon shard frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FecShardHeader {
    /// Block identifier.
    pub block_id: u32,
    /// Shard index inside the block.
    pub index: u8,
    /// Number of data shards.
    pub k: u8,
    /// Number of parity shards.
    pub m: u8,
    /// `true` for a parity shard.
    pub parity: bool,
    /// Payload length of every shard in the block.
    pub shard_len: u16,
}

impl FecShardHeader {
    /// Encodes the header into `output`, returning the prefix length.
    ///
    /// The shard payload must be appended by the caller.
    pub fn encode(&self, output: &mut [u8]) -> Result<usize> {
        let total = EXTENSION_HEADER_LEN + FEC_HEADER_LEN + usize::from(self.shard_len);
        if output.len() < total {
            return Err(ProtoError::BufferTooSmall {
                required: total,
                available: output.len(),
            });
        }
        write_prefix(
            output,
            ControlKind::FecShard,
            FEC_HEADER_LEN + usize::from(self.shard_len),
        )?;
        output[8..12].copy_from_slice(&self.block_id.to_le_bytes());
        output[12] = self.index;
        output[13] = self.k;
        output[14] = self.m;
        output[15] = u8::from(self.parity);
        output[16..18].copy_from_slice(&self.shard_len.to_le_bytes());
        output[18..20].copy_from_slice(&0u16.to_le_bytes());
        Ok(EXTENSION_HEADER_LEN + FEC_HEADER_LEN)
    }

    /// Decodes the header and returns it with the shard payload.
    pub fn decode(frame: &[u8]) -> Result<(Self, &[u8])> {
        let body = extension_body(frame, ControlKind::FecShard)?;
        if body.len() < FEC_HEADER_LEN {
            return Err(ProtoError::InvalidLength {
                expected: FEC_HEADER_LEN,
                actual: body.len(),
            });
        }
        let shard_len = u16::from_le_bytes(body[8..10].try_into().expect("checked length"));
        let payload = &body[FEC_HEADER_LEN..];
        if payload.len() != usize::from(shard_len) {
            return Err(ProtoError::InvalidLength {
                expected: FEC_HEADER_LEN + usize::from(shard_len),
                actual: body.len(),
            });
        }
        Ok((
            Self {
                block_id: u32::from_le_bytes(body[0..4].try_into().expect("checked length")),
                index: body[4],
                k: body[5],
                m: body[6],
                parity: body[7] & 1 != 0,
                shard_len,
            },
            payload,
        ))
    }

    /// Validates the shard index against `k` and `m`.
    pub fn validate(&self) -> Result<()> {
        if self.k == 0 || u16::from(self.k) + u16::from(self.m) > 255 {
            return Err(ProtoError::InvalidValue {
                name: "fec_shards".to_owned(),
                value: format!("{}+{}", self.k, self.m),
            });
        }
        if self.index >= self.k.saturating_add(self.m) {
            return Err(ProtoError::InvalidValue {
                name: "fec_index".to_owned(),
                value: self.index.to_string(),
            });
        }
        if self.parity != (self.index >= self.k) {
            return Err(ProtoError::InvalidValue {
                name: "fec_parity".to_owned(),
                value: self.parity.to_string(),
            });
        }
        Ok(())
    }
}

/// Returns the extension kind if `payload` starts with a valid marker.
#[must_use]
pub fn extension_kind(payload: &[u8]) -> Option<ControlKind> {
    parse_prefix(payload).map(|(kind, _)| kind)
}

/// Returns the extension kind and body if `payload` starts with a valid marker.
pub fn extension_body(payload: &[u8], expected: ControlKind) -> Result<&[u8]> {
    let (kind, body) = parse_prefix(payload).ok_or_else(|| ProtoError::InvalidValue {
        name: "extension".to_owned(),
        value: "missing marker".to_owned(),
    })?;
    if kind != expected {
        return Err(ProtoError::InvalidValue {
            name: "extension_kind".to_owned(),
            value: format!("{kind:?}"),
        });
    }
    Ok(body)
}

fn parse_prefix(payload: &[u8]) -> Option<(ControlKind, &[u8])> {
    if payload.len() < EXTENSION_HEADER_LEN {
        return None;
    }
    if payload[0] != EXTENSION_TAG
        || payload[1..4] != EXTENSION_MAGIC
        || payload[4] != EXTENSION_VERSION
    {
        return None;
    }
    let kind = ControlKind::from_code(payload[5])?;
    let length = usize::from(u16::from_le_bytes([payload[6], payload[7]]));
    let body = payload.get(EXTENSION_HEADER_LEN..)?;
    if body.len() < length {
        return None;
    }
    Some((kind, &body[..length]))
}

fn write_prefix(output: &mut [u8], kind: ControlKind, body_len: usize) -> Result<()> {
    let body_len = u16::try_from(body_len).map_err(|_| ProtoError::InvalidValue {
        name: "extension_len".to_owned(),
        value: body_len.to_string(),
    })?;
    output[0] = EXTENSION_TAG;
    output[1..4].copy_from_slice(&EXTENSION_MAGIC);
    output[4] = EXTENSION_VERSION;
    output[5] = kind.code();
    output[6..8].copy_from_slice(&body_len.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_ip_packet_is_not_an_extension() {
        let mut packet = [0u8; 32];
        packet[0] = 0x45;
        assert_eq!(extension_kind(&packet), None);
        let mut v6 = [0u8; 32];
        v6[0] = 0x60;
        assert_eq!(extension_kind(&v6), None);
    }

    #[test]
    fn caps_round_trip() {
        let caps = Caps {
            flags: CapsFlags::ACK | CapsFlags::BBR | CapsFlags::FEC | CapsFlags::FEC_PARTIAL,
            ack_interval_packets: 2,
            fec_k: 10,
            fec_m: 2,
        };
        let mut buffer = [0u8; 20];
        let written = caps.encode(&mut buffer).unwrap();
        assert_eq!(written, 20);
        assert_eq!(Caps::decode(&buffer).unwrap(), caps);
        assert_eq!(extension_kind(&buffer), Some(ControlKind::Caps));
    }

    #[test]
    fn fec_partial_flag_has_its_own_bit() {
        // Wire contract: bit 4 is FEC_PARTIAL and every existing bit is kept.
        assert_eq!(CapsFlags::FEC_PARTIAL.bits(), 1 << 4);
        assert_eq!(
            (CapsFlags::FEC | CapsFlags::FEC_ADAPTIVE | CapsFlags::FEC_PARTIAL).bits(),
            (1 << 2) | (1 << 3) | (1 << 4)
        );
        assert!(!CapsFlags::FEC.contains(CapsFlags::FEC_PARTIAL));
        assert!((CapsFlags::FEC | CapsFlags::FEC_PARTIAL).contains(CapsFlags::FEC_PARTIAL));
    }

    #[test]
    fn ack_round_trip_with_gaps() {
        let ack = Ack {
            largest_counter: 0x0102_0304_0506_0708,
            ack_delay_us: 1234,
            ecn_ce: true,
            received: 0b1010_0000_0000_0000_0000_0000_0000_0101,
        };
        let mut buffer = [0u8; 32];
        let written = ack.encode(&mut buffer).unwrap();
        assert_eq!(written, 32);
        assert_eq!(Ack::decode(&buffer).unwrap(), ack);
    }

    #[test]
    fn short_ack_bitmap_is_decoded() {
        let ack = Ack {
            largest_counter: 7,
            ack_delay_us: 0,
            ecn_ce: false,
            received: 0b101,
        };
        let mut buffer = [0u8; 32];
        ack.encode(&mut buffer).unwrap();
        let body_len = (ACK_HEADER_LEN + 1) as u16;
        buffer[6..8].copy_from_slice(&body_len.to_le_bytes());
        buffer[21] = 1;
        buffer[24] = 0b101;
        // Parity with the kernel: the seven bytes the sender omitted are
        // covered (set), so their counters are not reported as holes.
        assert_eq!(Ack::decode(&buffer).unwrap().received, 0b101 | (!0u64 << 8));
    }

    #[test]
    fn full_ack_bitmap_keeps_the_wire_bits() {
        let ack = Ack {
            largest_counter: 7,
            ack_delay_us: 0,
            ecn_ce: false,
            received: 0b101,
        };
        let mut buffer = [0u8; 32];
        ack.encode(&mut buffer).unwrap();
        assert_eq!(Ack::decode(&buffer).unwrap().received, 0b101);
    }

    #[test]
    fn fec_header_round_trip() {
        let header = FecShardHeader {
            block_id: 42,
            index: 3,
            k: 10,
            m: 2,
            parity: false,
            shard_len: 1200,
        };
        header.validate().unwrap();
        let mut buffer = [0u8; 20 + 1200];
        let written = header.encode(&mut buffer).unwrap();
        assert_eq!(written, 20);
        buffer[20..].fill(0xaa);
        let (parsed, payload) = FecShardHeader::decode(&buffer).unwrap();
        assert_eq!(parsed, header);
        assert_eq!(payload.len(), 1200);
        assert!(payload.iter().all(|byte| *byte == 0xaa));
    }

    #[test]
    fn fec_index_and_parity_are_validated() {
        let mut header = FecShardHeader {
            block_id: 1,
            index: 0,
            k: 4,
            m: 2,
            parity: false,
            shard_len: 10,
        };
        header.validate().unwrap();
        header.index = 4;
        assert!(header.validate().is_err());
        header.index = 4;
        header.parity = true;
        header.validate().unwrap();
        header.index = 0;
        assert!(header.validate().is_err());
    }

    #[test]
    fn truncated_frames_are_rejected() {
        let caps = Caps {
            flags: CapsFlags::ACK,
            ack_interval_packets: 2,
            fec_k: 4,
            fec_m: 1,
        };
        let mut buffer = [0u8; 20];
        caps.encode(&mut buffer).unwrap();
        assert!(Caps::decode(&buffer[..19]).is_err());
        buffer[0] = 1;
        assert!(Caps::decode(&buffer).is_err());
        buffer[0] = EXTENSION_TAG;
        buffer[4] = 2;
        assert!(Caps::decode(&buffer).is_err());
        buffer[4] = EXTENSION_VERSION;
        buffer[6..8].copy_from_slice(&13u16.to_le_bytes());
        assert!(Caps::decode(&buffer).is_err());
    }
}
