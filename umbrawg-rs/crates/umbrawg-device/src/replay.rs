use umbrawg_proto::messages::limits::COUNTER_BITS_TOTAL;

const BLOCK_BITS: usize = 64;
const RING_BLOCKS: usize = (COUNTER_BITS_TOTAL as usize) / BLOCK_BITS;
const BLOCK_MASK: usize = RING_BLOCKS - 1;
const BIT_MASK: u64 = BLOCK_BITS as u64 - 1;
const WINDOW_SIZE: u64 = (RING_BLOCKS as u64 - 1) * BLOCK_BITS as u64;

pub const REPLAY_WINDOW_BITS: u64 = (RING_BLOCKS * BLOCK_BITS) as u64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayFilter {
    last: u64,
    ring: [u64; RING_BLOCKS],
}

impl ReplayFilter {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            last: 0,
            ring: [0; RING_BLOCKS],
        }
    }

    pub fn reset(&mut self) {
        self.last = 0;
        self.ring.fill(0);
    }

    #[must_use]
    pub const fn last(&self) -> u64 {
        self.last
    }

    pub fn validate(&mut self, counter: u64, limit: u64) -> bool {
        if counter >= limit {
            return false;
        }
        let index_block = counter >> BLOCK_BITS.trailing_zeros();
        if counter > self.last {
            let current = self.last >> BLOCK_BITS.trailing_zeros();
            let diff = (index_block - current).min(RING_BLOCKS as u64);
            let mut block = current + 1;
            while block <= current + diff {
                self.ring[block as usize & BLOCK_MASK] = 0;
                block += 1;
            }
            self.last = counter;
        } else if self.last - counter > WINDOW_SIZE {
            return false;
        }
        let block = index_block as usize & BLOCK_MASK;
        let bit = counter & BIT_MASK;
        let old = self.ring[block];
        let new = old | (1u64 << bit);
        self.ring[block] = new;
        old != new
    }
}

impl Default for ReplayFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_has_expected_size() {
        assert_eq!(REPLAY_WINDOW_BITS, 8192);
        assert_eq!(WINDOW_SIZE, 8128);
    }

    #[test]
    fn accepts_new_counters_once() {
        let mut filter = ReplayFilter::new();
        assert!(filter.validate(0, u64::MAX));
        assert!(!filter.validate(0, u64::MAX));
        assert!(filter.validate(1, u64::MAX));
        assert!(filter.validate(64, u64::MAX));
        assert!(!filter.validate(64, u64::MAX));
    }

    #[test]
    fn rejects_counters_behind_the_window() {
        let mut filter = ReplayFilter::new();
        assert!(filter.validate(WINDOW_SIZE + 64, u64::MAX));
        assert!(!filter.validate(0, u64::MAX));
        assert!(filter.validate(WINDOW_SIZE, u64::MAX));
    }

    #[test]
    fn out_of_order_within_window_is_accepted() {
        let mut filter = ReplayFilter::new();
        assert!(filter.validate(1000, u64::MAX));
        assert!(filter.validate(999, u64::MAX));
        assert!(filter.validate(1, u64::MAX));
        assert!(!filter.validate(999, u64::MAX));
        assert!(filter.validate(1001, u64::MAX));
    }

    #[test]
    fn rejects_counters_at_or_above_limit() {
        let mut filter = ReplayFilter::new();
        assert!(filter.validate(4, 5));
        assert!(!filter.validate(5, 5));
        assert!(!filter.validate(6, 5));
    }

    #[test]
    fn reset_clears_the_window() {
        let mut filter = ReplayFilter::new();
        assert!(filter.validate(10, u64::MAX));
        filter.reset();
        assert_eq!(filter.last(), 0);
        assert!(filter.validate(10, u64::MAX));
    }

    #[test]
    fn large_jump_clears_the_ring() {
        let mut filter = ReplayFilter::new();
        assert!(filter.validate(10, u64::MAX));
        assert!(filter.validate(WINDOW_SIZE * 4, u64::MAX));
        assert!(!filter.validate(10, u64::MAX));
        assert!(filter.validate(WINDOW_SIZE * 4 + 1, u64::MAX));
    }
}
