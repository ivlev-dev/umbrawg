// SPDX-License-Identifier: MIT

//! Forward error correction mode of `UWGDEVICE_A_FEC`.

use crate::attribute::{fec_pack, fec_unpack, FEC_ADAPTIVE, FEC_OFF};

/// Forward error correction mode (`UWGDEVICE_A_FEC`, `NLA_U32`).
///
/// `0` disables FEC, `1` selects the adaptive mode and every other valid
/// payload packs explicit shard counts as `(K << 8) | M` with `K >= 1`,
/// `M >= 1` and `K + M <= 255`.
///
/// [`Fixed`](Self::Fixed) can be built without validation; use
/// [`fixed`](Self::fixed) for checked construction. Invalid shard counts are
/// rejected by [`UmbrawgDeviceConfig::build`](crate::UmbrawgDeviceConfig::build)
/// with [`UmbrawgConfigError::InvalidFecShards`](crate::UmbrawgConfigError::InvalidFecShards).
///
/// # Example
///
/// ```
/// use netlink_packet_umbrawg::FecMode;
///
/// assert_eq!(FecMode::Adaptive.to_u32(), Some(1));
/// assert_eq!(FecMode::fixed(8, 2).map(FecMode::to_u32), Some(Some(0x0802)));
/// assert_eq!(FecMode::from_u32(0x0201), Some(FecMode::Fixed { k: 2, m: 1 }));
/// assert_eq!(FecMode::fixed(255, 1), None);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FecMode {
    /// FEC is disabled (`UWGDEVICE_A_FEC = 0`).
    Off,
    /// The kernel picks the shard counts automatically
    /// (`UWGDEVICE_A_FEC = 1`).
    Adaptive,
    /// Explicit shard counts: `K` data shards and `M` parity shards.
    ///
    /// The values are emitted as `(K << 8) | M`; the kernel requires
    /// `K >= 1`, `M >= 1` and `K + M <= 255`.
    Fixed {
        /// Number of data shards.
        k: u8,
        /// Number of parity shards.
        m: u8,
    },
}

impl FecMode {
    /// Creates a checked [`Fixed`](Self::Fixed) mode.
    ///
    /// Returns `None` unless `k >= 1`, `m >= 1` and `k + m <= 255`.
    pub const fn fixed(k: u8, m: u8) -> Option<Self> {
        if fec_pack(k, m).is_some() {
            Some(Self::Fixed { k, m })
        } else {
            None
        }
    }

    /// Returns the `UWGDEVICE_A_FEC` payload of the mode.
    ///
    /// Returns `None` for a [`Fixed`](Self::Fixed) mode whose shard counts
    /// violate the kernel constraints.
    pub const fn to_u32(self) -> Option<u32> {
        match self {
            Self::Off => Some(FEC_OFF),
            Self::Adaptive => Some(FEC_ADAPTIVE),
            Self::Fixed { k, m } => fec_pack(k, m),
        }
    }

    /// Converts a `UWGDEVICE_A_FEC` payload into a mode.
    ///
    /// Returns `None` for payloads that are neither `0`, `1` nor a valid
    /// `(K << 8) | M` pair.
    pub const fn from_u32(value: u32) -> Option<Self> {
        if value == FEC_OFF {
            Some(Self::Off)
        } else if value == FEC_ADAPTIVE {
            Some(Self::Adaptive)
        } else {
            match fec_unpack(value) {
                Some((k, m)) => Some(Self::Fixed { k, m }),
                None => None,
            }
        }
    }
}
