//! Token-bucket pacer used to spread datagrams over time.

pub(crate) const NS_PER_SEC: u64 = 1_000_000_000;
/// Hard ceiling for any pacing rate (about 1 PB/s).
pub(crate) const MAX_RATE: u64 = 1 << 50;
const MAX_DELAY_NS: u64 = NS_PER_SEC;
const BURST_MS: u64 = 1;

/// Byte-oriented token bucket.
///
/// The allowance may become negative when the caller sends faster than the
/// configured rate; the debt is then repaid by the next refills. Nothing in
/// this type sleeps.
#[derive(Debug, Clone)]
pub(crate) struct Pacer {
    rate: u64,
    allowance: i128,
    remainder: u128,
    last_ns: u64,
    burst: u64,
    mss: u64,
    started: bool,
}

impl Pacer {
    pub(crate) fn new(mss: u64, rate: u64) -> Self {
        let burst = burst_for(rate.clamp(1, MAX_RATE), mss);
        Self {
            rate: rate.clamp(1, MAX_RATE),
            allowance: i128::from(burst),
            remainder: 0,
            last_ns: 0,
            burst,
            mss,
            started: false,
        }
    }

    pub(crate) fn set_rate(&mut self, rate: u64) {
        self.rate = rate.clamp(1, MAX_RATE);
        self.burst = burst_for(self.rate, self.mss);
        self.allowance = self.allowance.min(i128::from(self.burst));
    }

    pub(crate) fn refill(&mut self, now_ns: u64) {
        if !self.started {
            self.started = true;
            self.last_ns = now_ns;
            return;
        }
        let elapsed = now_ns.saturating_sub(self.last_ns);
        if elapsed == 0 {
            return;
        }
        self.last_ns = now_ns;
        let credit = u128::from(self.rate)
            .saturating_mul(u128::from(elapsed))
            .saturating_add(self.remainder);
        let whole = credit / u128::from(NS_PER_SEC);
        self.remainder = credit % u128::from(NS_PER_SEC);
        let whole = i128::try_from(whole).unwrap_or(i128::MAX);
        self.allowance = self
            .allowance
            .saturating_add(whole)
            .min(i128::from(self.burst));
    }

    pub(crate) fn consume(&mut self, len: u64) {
        self.allowance -= i128::from(len);
    }

    pub(crate) fn can_send(&self, len: u64) -> bool {
        self.allowance >= i128::from(len)
    }

    /// Delay until `len` bytes fit into the bucket. Uses a projection of the
    /// allowance and does not mutate the bucket.
    pub(crate) fn delay_ns(&self, len: u64, now_ns: u64) -> u64 {
        let mut allowance = self.allowance;
        if self.started {
            let elapsed = now_ns.saturating_sub(self.last_ns);
            if elapsed > 0 {
                let credit = u128::from(self.rate)
                    .saturating_mul(u128::from(elapsed))
                    .saturating_add(self.remainder);
                let whole = i128::try_from(credit / u128::from(NS_PER_SEC)).unwrap_or(i128::MAX);
                allowance = allowance.saturating_add(whole).min(i128::from(self.burst));
            }
        }
        let deficit = i128::from(len) - allowance;
        if deficit <= 0 {
            return 0;
        }
        let ns =
            (deficit as u128).saturating_mul(u128::from(NS_PER_SEC)) / u128::from(self.rate.max(1));
        u64::try_from(ns).unwrap_or(u64::MAX).min(MAX_DELAY_NS)
    }

    #[cfg(test)]
    pub(crate) fn rate(&self) -> u64 {
        self.rate
    }
}

fn burst_for(rate: u64, mss: u64) -> u64 {
    let by_time = rate.saturating_mul(BURST_MS) / 1000;
    by_time.max(mss.saturating_mul(2)).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_allows_initial_burst_then_limits() {
        let mut pacer = Pacer::new(1400, 1_000_000);
        pacer.refill(0);
        assert!(pacer.can_send(1400));
        pacer.consume(1400);
        assert!(pacer.can_send(1400));
        pacer.consume(1400);
        assert!(!pacer.can_send(1400));
        assert!(pacer.delay_ns(1400, 0) > 0);
    }

    #[test]
    fn refill_is_rate_limited() {
        let mut pacer = Pacer::new(1000, 1_000_000);
        pacer.refill(0);
        pacer.consume(pacer.burst);
        assert!(!pacer.can_send(1000));
        pacer.refill(NS_PER_SEC / 1000);
        assert!(pacer.can_send(1000));
    }

    #[test]
    fn delay_projection_matches_deficit() {
        let mut pacer = Pacer::new(1000, 1_000_000);
        pacer.refill(0);
        pacer.consume(pacer.burst);
        let delay = pacer.delay_ns(2000, 0);
        assert!((1_000_000..=2_000_000).contains(&delay));
        assert_eq!(pacer.delay_ns(0, 0), 0);
    }

    #[test]
    fn small_steps_accumulate_credit() {
        let mut pacer = Pacer::new(1400, 1_000_000);
        pacer.refill(0);
        pacer.consume(pacer.burst);
        assert!(!pacer.can_send(1400));
        for step in 1..=20_000u64 {
            pacer.refill(step * 100);
            if pacer.can_send(1400) {
                let micros = step * 100 / 1_000;
                assert!((1300..=1500).contains(&micros), "credit at {micros} us");
                return;
            }
        }
        panic!("credit never accumulated");
    }

    #[test]
    fn never_zero_rate() {
        let pacer = Pacer::new(1000, 0);
        assert!(pacer.rate() >= 1);
        assert!(pacer.delay_ns(1, 0) <= MAX_DELAY_NS);
    }
}
