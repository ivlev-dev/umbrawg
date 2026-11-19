//! Windowed estimators: bandwidth maximum and RTT minimum.

/// Length of the bandwidth filter in round trips.
pub(crate) const BW_WINDOW_ROUNDS: usize = 10;

/// Windowed maximum of the per-round delivery-rate maxima.
#[derive(Debug, Clone)]
pub(crate) struct BwWindow {
    slots: [u64; BW_WINDOW_ROUNDS],
    index: usize,
    rotations: u64,
}

impl BwWindow {
    pub(crate) fn new() -> Self {
        Self {
            slots: [0; BW_WINDOW_ROUNDS],
            index: 0,
            rotations: 0,
        }
    }

    /// Starts a new round. When `rotate` is false (an application-limited or
    /// otherwise unrepresentative round) the filter keeps its history, so a
    /// thin traffic period cannot erase a valid bandwidth estimate.
    pub(crate) fn on_round_start(&mut self, rotate: bool) {
        if rotate {
            self.index = (self.index + 1) % BW_WINDOW_ROUNDS;
            self.slots[self.index] = 0;
            self.rotations = self.rotations.saturating_add(1);
        }
    }

    pub(crate) fn add(&mut self, rate: u64) {
        let slot = &mut self.slots[self.index];
        *slot = (*slot).max(rate);
    }

    pub(crate) fn max(&self) -> u64 {
        self.slots.iter().copied().max().unwrap_or(0)
    }

    #[cfg(test)]
    pub(crate) fn rotations(&self) -> u64 {
        self.rotations
    }
}

/// Windowed minimum RTT with a timestamp of the last refresh.
#[derive(Debug, Clone)]
pub(crate) struct MinRtt {
    min_ns: u64,
    stamp_ns: u64,
    latest_ns: u64,
    seen_min: bool,
    seen_latest: bool,
}

impl MinRtt {
    pub(crate) fn new() -> Self {
        Self {
            min_ns: 0,
            stamp_ns: 0,
            latest_ns: 0,
            seen_min: false,
            seen_latest: false,
        }
    }

    pub(crate) fn sample(&mut self, rtt_ns: u64, now_ns: u64) {
        if rtt_ns == 0 {
            return;
        }
        self.latest_ns = rtt_ns;
        self.seen_latest = true;
        if !self.seen_min || rtt_ns < self.min_ns {
            self.min_ns = rtt_ns;
            self.stamp_ns = now_ns;
            self.seen_min = true;
        }
    }

    pub(crate) fn min(&self) -> Option<u64> {
        self.seen_min.then_some(self.min_ns)
    }

    pub(crate) fn latest(&self) -> Option<u64> {
        self.seen_latest.then_some(self.latest_ns)
    }

    #[cfg(test)]
    pub(crate) fn stamp(&self) -> u64 {
        self.stamp_ns
    }

    pub(crate) fn age(&self, now_ns: u64) -> u64 {
        now_ns.saturating_sub(self.stamp_ns)
    }

    /// Restarts the 10 second window, adopting the latest sample as the new
    /// floor. Called when `PROBE_RTT` completes.
    pub(crate) fn refresh(&mut self, now_ns: u64) {
        if self.seen_latest {
            self.min_ns = self.latest_ns;
            self.seen_min = true;
        }
        self.stamp_ns = now_ns;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bandwidth_window_keeps_maximum_for_ten_rounds() {
        let mut bw = BwWindow::new();
        bw.add(100);
        assert_eq!(bw.max(), 100);
        for _ in 0..BW_WINDOW_ROUNDS {
            bw.on_round_start(true);
            bw.add(10);
        }
        assert_eq!(bw.max(), 10);
        assert_eq!(bw.rotations(), BW_WINDOW_ROUNDS as u64);
    }

    #[test]
    fn frozen_window_preserves_estimate() {
        let mut bw = BwWindow::new();
        bw.add(100);
        bw.on_round_start(false);
        bw.add(1);
        assert_eq!(bw.max(), 100);
    }

    #[test]
    fn per_round_maximum_wins() {
        let mut bw = BwWindow::new();
        bw.add(10);
        bw.add(30);
        bw.add(20);
        assert_eq!(bw.max(), 30);
    }

    #[test]
    fn min_rtt_keeps_lowest_sample_and_stamp() {
        let mut rtt = MinRtt::new();
        assert_eq!(rtt.min(), None);
        rtt.sample(1000, 10);
        rtt.sample(800, 20);
        rtt.sample(900, 30);
        assert_eq!(rtt.min(), Some(800));
        assert_eq!(rtt.latest(), Some(900));
        assert_eq!(rtt.stamp(), 20);
        rtt.sample(0, 40);
        assert_eq!(rtt.latest(), Some(900));
    }

    #[test]
    fn refresh_adopts_latest_sample() {
        let mut rtt = MinRtt::new();
        rtt.sample(1000, 10);
        rtt.sample(3000, 20);
        rtt.refresh(30);
        assert_eq!(rtt.min(), Some(3000));
        assert_eq!(rtt.stamp(), 30);
        assert_eq!(rtt.age(35), 5);
    }
}
