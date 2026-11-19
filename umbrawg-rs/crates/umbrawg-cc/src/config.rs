//! Configuration of the congestion controller.

use core::time::Duration;

const MIN_MSS: u32 = 1;
const MIN_CWND_PACKETS: u32 = 1;
const MIN_INITIAL_RTT: Duration = Duration::from_micros(1);

/// Tunables for [`crate::Bbr`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BbrConfig {
    /// Maximum segment size in bytes. It is used for packet accounting and
    /// for the minimum congestion window. Zero is clamped to one byte.
    pub mss: u32,
    /// RTT assumed until the first measurement is available. Zero is
    /// clamped to one microsecond.
    pub initial_rtt: Duration,
    /// Minimum congestion window, expressed in packets.
    pub min_cwnd_packets: u32,
    /// Whether ECN-CE marks reported by [`crate::Ack::ecn_ce`] are used as a
    /// congestion signal.
    pub enable_ecn: bool,
}

impl Default for BbrConfig {
    fn default() -> Self {
        Self {
            mss: 1400,
            initial_rtt: Duration::from_millis(50),
            min_cwnd_packets: 4,
            enable_ecn: true,
        }
    }
}

impl BbrConfig {
    pub(crate) fn sanitized(self) -> Self {
        Self {
            mss: self.mss.max(MIN_MSS),
            initial_rtt: self.initial_rtt.max(MIN_INITIAL_RTT),
            min_cwnd_packets: self.min_cwnd_packets.max(MIN_CWND_PACKETS),
            enable_ecn: self.enable_ecn,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_specification() {
        let cfg = BbrConfig::default();
        assert_eq!(cfg.mss, 1400);
        assert_eq!(cfg.initial_rtt, Duration::from_millis(50));
        assert_eq!(cfg.min_cwnd_packets, 4);
    }

    #[test]
    fn zero_values_are_clamped() {
        let cfg = BbrConfig {
            mss: 0,
            initial_rtt: Duration::ZERO,
            min_cwnd_packets: 0,
            enable_ecn: false,
        }
        .sanitized();
        assert_eq!(cfg.mss, 1);
        assert_eq!(cfg.initial_rtt, Duration::from_micros(1));
        assert_eq!(cfg.min_cwnd_packets, 1);
    }
}
