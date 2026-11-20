// SPDX-License-Identifier: MIT

//! BBR congestion control mode of `UWGDEVICE_A_BBR`.

use crate::attribute::BBR_MAX;

/// BBR congestion control mode (`UWGDEVICE_A_BBR`, `NLA_U8`).
///
/// The kernel interprets `0` as disabled, `1` as monitor-only and `2` as
/// enabled.
///
/// # Example
///
/// ```
/// use netlink_packet_umbrawg::BbrMode;
///
/// assert_eq!(BbrMode::On.as_u8(), 2);
/// assert_eq!(BbrMode::from_u8(1), Some(BbrMode::Monitor));
/// assert_eq!(BbrMode::from_u8(3), None);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BbrMode {
    /// BBR is disabled (`UWGDEVICE_A_BBR = 0`).
    Off,
    /// BBR only observes the congestion state (`UWGDEVICE_A_BBR = 1`).
    Monitor,
    /// BBR controls the congestion window (`UWGDEVICE_A_BBR = 2`).
    On,
}

impl BbrMode {
    /// Returns the `UWGDEVICE_A_BBR` payload of the mode.
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Off => 0,
            Self::Monitor => 1,
            Self::On => 2,
        }
    }

    /// Converts a `UWGDEVICE_A_BBR` payload into a mode.
    ///
    /// Returns `None` for values above [`BBR_MAX`], which the kernel rejects.
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Off),
            1 => Some(Self::Monitor),
            BBR_MAX => Some(Self::On),
            _ => None,
        }
    }
}

impl From<BbrMode> for u8 {
    fn from(mode: BbrMode) -> Self {
        mode.as_u8()
    }
}
