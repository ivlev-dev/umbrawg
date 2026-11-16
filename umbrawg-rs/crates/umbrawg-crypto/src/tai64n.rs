//! TAI64N timestamps used by the noise handshake.

use core::cmp::Ordering;
use core::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Length of a TAI64N timestamp in bytes.
pub const TIMESTAMP_LEN: usize = 12;

/// Offset between Unix time and TAI64 labels used by WireGuard.
pub const TAI64N_BASE: u64 = 0x4000_0000_0000_000a;

const NANOS_MASK: u32 = 0x00ff_ffff;

/// A 12-byte TAI64N timestamp.
///
/// Seconds are stored as a big-endian 64-bit TAI64 label and nanoseconds as a
/// big-endian 32-bit value. The low 24 bits of the nanosecond part are cleared
/// to bound handshake replay precision, matching the kernel module and the Go
/// implementation.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tai64N([u8; TIMESTAMP_LEN]);

impl Tai64N {
    /// Length of the encoded timestamp in bytes.
    pub const LEN: usize = TIMESTAMP_LEN;

    /// Returns the current wall-clock time.
    #[must_use]
    pub fn now() -> Self {
        let (seconds, nanos) = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or((0, 0), |duration| {
                (duration.as_secs(), duration.subsec_nanos())
            });
        Self::from_parts(seconds, nanos)
    }

    /// Builds a timestamp from Unix seconds and nanoseconds.
    #[must_use]
    pub fn from_parts(unix_seconds: u64, nanos: u32) -> Self {
        let seconds = TAI64N_BASE.wrapping_add(unix_seconds);
        let nanos = nanos & !NANOS_MASK;
        let mut raw = [0u8; TIMESTAMP_LEN];
        raw[..8].copy_from_slice(&seconds.to_be_bytes());
        raw[8..].copy_from_slice(&nanos.to_be_bytes());
        Self(raw)
    }

    /// Wraps already encoded timestamp bytes.
    #[must_use]
    pub const fn from_raw(raw: [u8; TIMESTAMP_LEN]) -> Self {
        Self(raw)
    }

    /// Returns the encoded timestamp bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; TIMESTAMP_LEN] {
        &self.0
    }

    /// Copies the encoded timestamp bytes out.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; TIMESTAMP_LEN] {
        self.0
    }

    /// Returns the raw TAI64 seconds label.
    #[must_use]
    pub fn seconds(&self) -> u64 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.0[..8]);
        u64::from_be_bytes(bytes)
    }

    /// Returns the Unix seconds represented by the timestamp.
    #[must_use]
    pub fn unix_seconds(&self) -> u64 {
        self.seconds().wrapping_sub(TAI64N_BASE)
    }

    /// Returns the nanosecond part with the low 24 bits cleared.
    #[must_use]
    pub fn nanos(&self) -> u32 {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&self.0[8..]);
        u32::from_be_bytes(bytes)
    }
}

impl PartialOrd for Tai64N {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Tai64N {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl fmt::Debug for Tai64N {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Tai64N({}, {})",
            self.unix_seconds(),
            self.nanos()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_fixed_vector() {
        let timestamp = Tai64N::from_parts(1_700_000_000, 123_456_789);
        assert_eq!(
            timestamp.to_bytes(),
            [0x40, 0x00, 0x00, 0x00, 0x65, 0x53, 0xf1, 0x0a, 0x07, 0x00, 0x00, 0x00,]
        );
        assert_eq!(timestamp.unix_seconds(), 1_700_000_000);
        assert_eq!(timestamp.nanos(), 0x0700_0000);
    }

    #[test]
    fn masks_low_nanosecond_bits() {
        let first = Tai64N::from_parts(10, 0x00ff_ffff);
        let second = Tai64N::from_parts(10, 0);
        assert_eq!(first.to_bytes(), second.to_bytes());
    }

    #[test]
    fn ordering_matches_time() {
        let early = Tai64N::from_parts(100, 0);
        let late = Tai64N::from_parts(101, 0);
        assert!(early < late);
        assert_eq!(Tai64N::from_raw(early.to_bytes()), early);
    }

    #[test]
    fn now_is_recent() {
        let now = Tai64N::now();
        assert!(now.unix_seconds() > 1_600_000_000);
        assert_eq!(now.nanos() & 0x00ff_ffff, 0);
    }
}
