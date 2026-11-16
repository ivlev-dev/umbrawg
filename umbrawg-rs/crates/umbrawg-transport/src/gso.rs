//! Segmentation arithmetic shared by UDP GSO (`UDP_SEGMENT`) and GRO (`UDP_GRO`).
//!
//! A GSO datagram is a single buffer that holds up to [`MAX_SEGMENTS`] datagrams
//! of exactly `gso_size` bytes plus an optional shorter tail. The same layout is
//! reported by the kernel through `UDP_GRO` control messages on receive, so the
//! helpers below are used in both directions.

use core::fmt;
use core::num::NonZeroU16;
use core::ops::Range;

use crate::addr::AddressFamily;
use crate::{Result, TransportError};

/// Hard limit on coalesced datagrams imposed by the kernel.
pub const MAX_SEGMENTS: usize = 64;

/// Length of a fixed IPv4 header without options.
pub const IPV4_HEADER_LEN: usize = 20;

/// Length of an IPv6 header without extension headers.
pub const IPV6_HEADER_LEN: usize = 40;

/// Length of a UDP header.
pub const UDP_HEADER_LEN: usize = 8;

/// Maximum UDP payload carried by a single IPv4 datagram.
pub const MAX_UDP_PAYLOAD_V4: usize = u16::MAX as usize - IPV4_HEADER_LEN - UDP_HEADER_LEN;

/// Maximum UDP payload carried by a single IPv6 datagram.
pub const MAX_UDP_PAYLOAD_V6: usize = u16::MAX as usize - UDP_HEADER_LEN;

/// MTU assumed when the interface MTU is not known yet.
pub const DEFAULT_MTU: u32 = 1500;

/// GSO segment size in bytes of UDP payload.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GsoSize(NonZeroU16);

impl GsoSize {
    /// Creates a segment size, rejecting zero.
    pub fn new(size: u16) -> Result<Self> {
        match NonZeroU16::new(size) {
            Some(size) => Ok(Self(size)),
            None => Err(TransportError::InvalidSegmentSize { size: 0 }),
        }
    }

    /// Creates a segment size from a `usize`, rejecting zero and values above `u16::MAX`.
    pub fn from_usize(size: usize) -> Result<Self> {
        match u16::try_from(size) {
            Ok(size) => Self::new(size),
            Err(_) => Err(TransportError::InvalidSegmentSize { size }),
        }
    }

    /// Returns the segment size in bytes.
    pub fn get(self) -> u16 {
        self.0.get()
    }

    /// Returns the segment size as a `usize`.
    pub fn as_usize(self) -> usize {
        usize::from(self.0.get())
    }
}

impl fmt::Debug for GsoSize {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "GsoSize({})", self.0)
    }
}

impl fmt::Display for GsoSize {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// Per-socket GSO bounds derived from the interface MTU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GsoLimits {
    max_gso_size: usize,
    max_segments: usize,
}

impl GsoLimits {
    /// Creates explicit limits, validating both values.
    pub fn new(max_gso_size: usize, max_segments: usize) -> Result<Self> {
        if max_gso_size == 0 || max_gso_size > usize::from(u16::MAX) {
            return Err(TransportError::InvalidSegmentSize { size: max_gso_size });
        }
        if max_segments == 0 {
            return Err(TransportError::TooManySegments {
                segments: max_segments,
                max: MAX_SEGMENTS,
            });
        }
        if max_segments > MAX_SEGMENTS {
            return Err(TransportError::TooManySegments {
                segments: max_segments,
                max: MAX_SEGMENTS,
            });
        }
        Ok(Self {
            max_gso_size,
            max_segments,
        })
    }

    /// Derives limits from an interface MTU.
    ///
    /// The maximum segment size is the MTU minus the IPv4/IPv6 and UDP headers,
    /// capped by the maximum UDP payload of the family. The number of segments is
    /// bounded by the kernel limit [`MAX_SEGMENTS`] and by the largest datagram
    /// the family can express.
    pub fn from_mtu(mtu: u32, family: AddressFamily) -> Self {
        let overhead = family.udp_overhead();
        let usable = (mtu as usize).saturating_sub(overhead).max(1);
        let max_gso_size = usable
            .min(family.max_udp_payload())
            .min(usize::from(u16::MAX));
        let max_segments = (family.max_udp_payload() / max_gso_size).clamp(1, MAX_SEGMENTS);
        Self {
            max_gso_size,
            max_segments,
        }
    }

    /// Returns limits for the default MTU ([`DEFAULT_MTU`]).
    pub fn default_for(family: AddressFamily) -> Self {
        Self::from_mtu(DEFAULT_MTU, family)
    }

    /// Maximum GSO segment size in bytes.
    pub fn max_gso_size(&self) -> usize {
        self.max_gso_size
    }

    /// Maximum number of segments per GSO datagram.
    pub fn max_segments(&self) -> usize {
        self.max_segments
    }

    /// Maximum size of a GSO super-datagram for the given address family.
    pub fn max_datagram_len(&self, family: AddressFamily) -> usize {
        self.max_gso_size
            .saturating_mul(self.max_segments)
            .min(family.max_udp_payload())
    }
}

/// Validated layout of a GSO/GRO datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GsoLayout {
    gso_size: GsoSize,
    total_len: usize,
    segments: usize,
}

impl GsoLayout {
    /// Validates a payload of `total_len` bytes split into `gso_size` segments.
    ///
    /// Every segment except the last is exactly `gso_size` bytes; the last one may
    /// be shorter. Empty payloads and more than [`MAX_SEGMENTS`] segments are rejected.
    pub fn for_payload(total_len: usize, gso_size: GsoSize) -> Result<Self> {
        if total_len == 0 {
            return Err(TransportError::InconsistentSegments {
                reason: "payload is empty",
            });
        }
        let segments = total_len.div_ceil(gso_size.as_usize());
        if segments > MAX_SEGMENTS {
            return Err(TransportError::TooManySegments {
                segments,
                max: MAX_SEGMENTS,
            });
        }
        Ok(Self {
            gso_size,
            total_len,
            segments,
        })
    }

    /// Validates a layout described by the lengths of its segments.
    ///
    /// The first length defines the segment size, all but the last length must
    /// equal it, and the last one must not exceed it.
    pub fn for_segments(sizes: &[usize]) -> Result<Self> {
        let first = match sizes.first() {
            Some(first) => *first,
            None => {
                return Err(TransportError::InconsistentSegments {
                    reason: "no segments",
                })
            }
        };
        Self::from_lengths(first, sizes.len(), |index| sizes[index])
    }

    /// Validates a layout described by the lengths of its buffers.
    pub fn for_parts(parts: &[&[u8]]) -> Result<Self> {
        let first = match parts.first() {
            Some(first) => first.len(),
            None => {
                return Err(TransportError::InconsistentSegments {
                    reason: "no segments",
                })
            }
        };
        Self::from_lengths(first, parts.len(), |index| parts[index].len())
    }

    fn from_lengths(first: usize, count: usize, size_at: impl Fn(usize) -> usize) -> Result<Self> {
        let gso_size = GsoSize::from_usize(first)?;
        if count > MAX_SEGMENTS {
            return Err(TransportError::TooManySegments {
                segments: count,
                max: MAX_SEGMENTS,
            });
        }
        for index in 1..count.saturating_sub(1) {
            if size_at(index) != first {
                return Err(TransportError::InconsistentSegments {
                    reason: "non-tail segment differs from the first segment",
                });
            }
        }
        if count > 1 {
            let last = size_at(count - 1);
            if last == 0 || last > first {
                return Err(TransportError::InconsistentSegments {
                    reason: "tail segment is empty or larger than the segment size",
                });
            }
        }
        let mut total_len = 0usize;
        for index in 0..count {
            total_len = total_len.checked_add(size_at(index)).ok_or(
                TransportError::InconsistentSegments {
                    reason: "total length overflows usize",
                },
            )?;
        }
        let segments = total_len.div_ceil(gso_size.as_usize());
        if segments != count {
            return Err(TransportError::InconsistentSegments {
                reason: "segment lengths do not match the segment size",
            });
        }
        Ok(Self {
            gso_size,
            total_len,
            segments: count,
        })
    }

    /// Segment size in bytes.
    pub fn gso_size(&self) -> GsoSize {
        self.gso_size
    }

    /// Total payload length in bytes.
    pub fn total_len(&self) -> usize {
        self.total_len
    }

    /// Number of segments in the datagram.
    pub fn segments(&self) -> usize {
        self.segments
    }

    /// Checks the layout against the socket limits and the family payload size.
    pub fn validate_limits(&self, limits: GsoLimits, family: AddressFamily) -> Result<()> {
        if self.gso_size.as_usize() > limits.max_gso_size() {
            return Err(TransportError::SegmentSizeTooLarge {
                size: self.gso_size.as_usize(),
                max: limits.max_gso_size(),
            });
        }
        if self.segments > limits.max_segments() {
            return Err(TransportError::TooManySegments {
                segments: self.segments,
                max: limits.max_segments(),
            });
        }
        let max_payload = family.max_udp_payload();
        if self.total_len > max_payload {
            return Err(TransportError::DatagramTooLarge {
                len: self.total_len,
                max: max_payload,
            });
        }
        Ok(())
    }

    /// Byte ranges of every segment inside the payload.
    pub fn ranges(&self) -> impl Iterator<Item = Range<usize>> + '_ {
        let gso_size = self.gso_size.as_usize();
        let total_len = self.total_len;
        (0..self.segments).map(move |index| {
            let start = index * gso_size;
            let end = (start + gso_size).min(total_len);
            start..end
        })
    }
}

/// Number of segments needed for `payload_len` bytes with the given segment size.
///
/// Returns zero for an empty payload.
pub fn segment_count(payload_len: usize, gso_size: GsoSize) -> usize {
    payload_len.div_ceil(gso_size.as_usize())
}

/// Splits `payload` into GSO segments, copying each segment into `out`.
///
/// Returns the number of buffers that were filled. The caller must provide at
/// least `segment_count(payload.len(), gso_size)` destinations; each destination
/// must be large enough for its segment.
pub fn split_into_segments(
    payload: &[u8],
    gso_size: GsoSize,
    out: &mut [&mut [u8]],
) -> Result<usize> {
    let layout = GsoLayout::for_payload(payload.len(), gso_size)?;
    if out.len() < layout.segments() {
        return Err(TransportError::BufferTooSmall {
            needed: layout.segments(),
            available: out.len(),
        });
    }
    let mut written = 0usize;
    for (index, range) in layout.ranges().enumerate() {
        let segment = &payload[range.clone()];
        let destination = &mut out[index];
        if destination.len() < segment.len() {
            return Err(TransportError::BufferTooSmall {
                needed: segment.len(),
                available: destination.len(),
            });
        }
        destination[..segment.len()].copy_from_slice(segment);
        written += 1;
    }
    Ok(written)
}

/// Coalesces `parts` into `out`, validating the resulting GSO layout.
///
/// Returns the layout that describes the coalesced datagram so it can be handed
/// to the TUN device or to `UDP_SEGMENT` as-is.
pub fn coalesce_into(parts: &[&[u8]], out: &mut [u8]) -> Result<GsoLayout> {
    let layout = GsoLayout::for_parts(parts)?;
    if out.len() < layout.total_len() {
        return Err(TransportError::BufferTooSmall {
            needed: layout.total_len(),
            available: out.len(),
        });
    }
    let mut offset = 0usize;
    for part in parts {
        let end = offset + part.len();
        out[offset..end].copy_from_slice(part);
        offset = end;
    }
    Ok(layout)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn size(value: u16) -> GsoSize {
        GsoSize::new(value).expect("test segment size is non-zero")
    }

    #[test]
    fn segment_size_rejects_zero_and_overflow() {
        assert!(matches!(
            GsoSize::new(0),
            Err(TransportError::InvalidSegmentSize { size: 0 })
        ));
        assert!(GsoSize::from_usize(0).is_err());
        assert!(GsoSize::from_usize(usize::from(u16::MAX) + 1).is_err());
        assert_eq!(GsoSize::from_usize(1400).unwrap().get(), 1400);
    }

    #[test]
    fn segment_count_rounds_up() {
        assert_eq!(segment_count(0, size(100)), 0);
        assert_eq!(segment_count(1, size(100)), 1);
        assert_eq!(segment_count(100, size(100)), 1);
        assert_eq!(segment_count(101, size(100)), 2);
        assert_eq!(segment_count(400, size(100)), 4);
    }

    #[test]
    fn layout_accepts_short_tail() {
        let layout = GsoLayout::for_payload(350, size(100)).unwrap();
        assert_eq!(layout.segments(), 4);
        assert_eq!(layout.total_len(), 350);
        let ranges: Vec<_> = layout.ranges().collect();
        assert_eq!(ranges, vec![0..100, 100..200, 200..300, 300..350]);
    }

    #[test]
    fn layout_rejects_empty_and_too_many_segments() {
        assert!(GsoLayout::for_payload(0, size(10)).is_err());
        let too_many = MAX_SEGMENTS * 10 + 1;
        assert!(matches!(
            GsoLayout::for_payload(too_many, size(10)),
            Err(TransportError::TooManySegments { .. })
        ));
    }

    #[test]
    fn layout_from_segments_validates_pattern() {
        let layout = GsoLayout::for_segments(&[100, 100, 40]).unwrap();
        assert_eq!(layout.gso_size(), size(100));
        assert_eq!(layout.total_len(), 240);
        assert_eq!(layout.segments(), 3);

        assert!(GsoLayout::for_segments(&[]).is_err());
        assert!(GsoLayout::for_segments(&[0]).is_err());
        assert!(GsoLayout::for_segments(&[100, 90, 100]).is_err());
        assert!(GsoLayout::for_segments(&[100, 101]).is_err());
        assert!(GsoLayout::for_segments(&[100, 0]).is_err());
    }

    #[test]
    fn layout_from_parts_matches_from_segments() {
        let first = [0u8; 100];
        let second = [0u8; 100];
        let tail = [0u8; 20];
        let parts: [&[u8]; 3] = [&first, &second, &tail];
        let layout = GsoLayout::for_parts(&parts).unwrap();
        assert_eq!(layout, GsoLayout::for_segments(&[100, 100, 20]).unwrap());
        assert!(GsoLayout::for_parts(&[]).is_err());
    }

    #[test]
    fn limits_from_mtu_are_sane() {
        let v4 = GsoLimits::from_mtu(1500, AddressFamily::Ipv4);
        assert_eq!(v4.max_gso_size(), 1472);
        assert!(v4.max_segments() >= 1);
        assert_eq!(v4.max_segments(), MAX_UDP_PAYLOAD_V4 / 1472);

        let v6 = GsoLimits::from_mtu(1500, AddressFamily::Ipv6);
        assert_eq!(v6.max_gso_size(), 1452);

        let jumbo = GsoLimits::from_mtu(9000, AddressFamily::Ipv4);
        assert_eq!(jumbo.max_gso_size(), 8972);
        assert_eq!(
            jumbo.max_datagram_len(AddressFamily::Ipv4),
            jumbo.max_gso_size() * jumbo.max_segments()
        );

        let tiny = GsoLimits::from_mtu(0, AddressFamily::Ipv4);
        assert_eq!(tiny.max_gso_size(), 1);
        assert_eq!(tiny.max_segments(), MAX_SEGMENTS);
    }

    #[test]
    fn limits_reject_invalid_values() {
        assert!(GsoLimits::new(0, 1).is_err());
        assert!(GsoLimits::new(1, 0).is_err());
        assert!(GsoLimits::new(1, MAX_SEGMENTS + 1).is_err());
        assert!(GsoLimits::new(usize::from(u16::MAX) + 1, 1).is_err());
        assert_eq!(GsoLimits::new(1400, 4).unwrap().max_segments(), 4);
    }

    #[test]
    fn validate_limits_reports_the_first_violation() {
        let limits = GsoLimits::new(1000, 4).unwrap();
        let layout = GsoLayout::for_payload(1200, size(1200)).unwrap();
        assert!(matches!(
            layout.validate_limits(limits, AddressFamily::Ipv4),
            Err(TransportError::SegmentSizeTooLarge { .. })
        ));

        let layout = GsoLayout::for_payload(500, size(100)).unwrap();
        assert!(matches!(
            layout.validate_limits(limits, AddressFamily::Ipv4),
            Err(TransportError::TooManySegments { .. })
        ));

        let layout = GsoLayout::for_payload(MAX_UDP_PAYLOAD_V6, size(1300)).unwrap();
        assert!(matches!(
            layout.validate_limits(
                GsoLimits::new(1400, MAX_SEGMENTS).unwrap(),
                AddressFamily::Ipv4
            ),
            Err(TransportError::DatagramTooLarge { .. })
        ));
    }

    #[test]
    fn split_into_segments_copies_payload() {
        let payload: Vec<u8> = (0..350).map(|value| value as u8).collect();
        let mut destinations = vec![vec![0u8; 100]; 4];
        let mut out: Vec<&mut [u8]> = destinations
            .iter_mut()
            .map(|buf| buf.as_mut_slice())
            .collect();

        let count = split_into_segments(&payload, size(100), &mut out).unwrap();
        assert_eq!(count, 4);
        assert_eq!(&destinations[0][..], &payload[0..100]);
        assert_eq!(&destinations[2][..], &payload[200..300]);
        assert_eq!(&destinations[3][..50], &payload[300..350]);
    }

    #[test]
    fn split_into_segments_validates_capacity() {
        let payload = [0u8; 250];
        let mut destinations = vec![vec![0u8; 100]; 2];
        let mut out: Vec<&mut [u8]> = destinations
            .iter_mut()
            .map(|buf| buf.as_mut_slice())
            .collect();
        assert!(matches!(
            split_into_segments(&payload, size(100), &mut out),
            Err(TransportError::BufferTooSmall { .. })
        ));

        let mut small = vec![vec![0u8; 10]; 3];
        let mut out: Vec<&mut [u8]> = small.iter_mut().map(|buf| buf.as_mut_slice()).collect();
        assert!(matches!(
            split_into_segments(&payload, size(100), &mut out),
            Err(TransportError::BufferTooSmall { .. })
        ));
        assert!(split_into_segments(&[], size(100), &mut out).is_err());
    }

    #[test]
    fn coalesce_into_round_trips_split() {
        let payload: Vec<u8> = (0..250).map(|value| value as u8).collect();
        let mut destinations = vec![vec![0u8; 100]; 3];
        let mut out: Vec<&mut [u8]> = destinations
            .iter_mut()
            .map(|buf| buf.as_mut_slice())
            .collect();
        let count = split_into_segments(&payload, size(100), &mut out).unwrap();
        assert_eq!(count, 3);

        let parts: [&[u8]; 3] = [&payload[0..100], &payload[100..200], &payload[200..250]];

        let mut coalesced = vec![0u8; 250];
        let layout = coalesce_into(&parts, &mut coalesced).unwrap();
        assert_eq!(layout.total_len(), 250);
        assert_eq!(count, layout.segments());
        assert_eq!(layout.gso_size(), size(100));
        assert_eq!(coalesced, payload);
    }

    #[test]
    fn coalesce_into_checks_output_capacity() {
        let parts: [&[u8]; 2] = [&[1u8; 100], &[2u8; 100]];
        let mut out = [0u8; 100];
        assert!(matches!(
            coalesce_into(&parts, &mut out),
            Err(TransportError::BufferTooSmall { .. })
        ));
    }

    #[test]
    fn coalesce_into_single_part() {
        let part = [7u8; 100];
        let parts: [&[u8]; 1] = [&part];
        let mut out = [0u8; 100];
        let layout = coalesce_into(&parts, &mut out).unwrap();
        assert_eq!(layout.segments(), 1);
        assert_eq!(layout.gso_size(), size(100));
        assert_eq!(out, part);
    }
}
