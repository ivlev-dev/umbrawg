use std::sync::atomic::{AtomicU64, Ordering};

use umbrawg_proto::messages::limits::COUNTER_BITS_TOTAL;

const BLOCK_BITS: usize = 64;
const RING_BLOCKS: usize = (COUNTER_BITS_TOTAL as usize) / BLOCK_BITS;
const BLOCK_MASK: usize = RING_BLOCKS - 1;
const BIT_MASK: u64 = BLOCK_BITS as u64 - 1;
const WINDOW_SIZE: u64 = (RING_BLOCKS as u64 - 1) * BLOCK_BITS as u64;

pub const REPLAY_WINDOW_BITS: u64 = (RING_BLOCKS * BLOCK_BITS) as u64;

/// Маркер «блок переинициализируется»: настоящий номер блока его не достигает.
const BLOCK_BUSY: u64 = u64::MAX;

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

#[derive(Debug)]
struct ReplayBlock {
    tag: AtomicU64,
    bits: AtomicU64,
}

impl ReplayBlock {
    const fn new() -> Self {
        Self {
            tag: AtomicU64::new(0),
            bits: AtomicU64::new(0),
        }
    }
}

/// Конкурентный фильтр повторов без блокировок.
///
/// Каждый блок окна хранит номер своего поколения (`tag`) и битовую карту
/// принятых счётчиков (`bits`). Поколение защищает от повторного приёма
/// счётчиков после переиспользования блока: биты блока, чьё поколение уже
/// сменилось, никогда не выдают себя за биты нового поколения.
#[derive(Debug)]
pub struct AtomicReplayFilter {
    last: AtomicU64,
    blocks: [ReplayBlock; RING_BLOCKS],
}

impl AtomicReplayFilter {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            last: AtomicU64::new(0),
            blocks: [const { ReplayBlock::new() }; RING_BLOCKS],
        }
    }

    pub fn reset(&self) {
        self.last.store(0, Ordering::Release);
        for block in &self.blocks {
            block.tag.store(0, Ordering::Release);
            block.bits.store(0, Ordering::Release);
        }
    }

    #[must_use]
    pub fn last(&self) -> u64 {
        self.last.load(Ordering::Acquire)
    }

    /// Проверяет счётчик и помечает его принятым. Возвращает `true` ровно один
    /// раз для каждого счётчика в пределах окна.
    pub fn validate(&self, counter: u64, limit: u64) -> bool {
        if counter >= limit {
            return false;
        }
        let last = self.last.load(Ordering::Acquire);
        if counter < last.saturating_sub(WINDOW_SIZE) {
            return false;
        }
        if counter > last {
            self.last.fetch_max(counter, Ordering::AcqRel);
        }
        let block = counter >> BLOCK_BITS.trailing_zeros();
        let entry = &self.blocks[block as usize & BLOCK_MASK];
        loop {
            let tag = entry.tag.load(Ordering::Acquire);
            if tag == block {
                break;
            }
            if tag == BLOCK_BUSY {
                std::hint::spin_loop();
                continue;
            }
            if block < tag {
                return false;
            }
            if entry
                .tag
                .compare_exchange(tag, BLOCK_BUSY, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                entry.bits.store(0, Ordering::Relaxed);
                entry.tag.store(block, Ordering::Release);
            }
        }
        let bit = counter & BIT_MASK;
        if entry.bits.fetch_or(1u64 << bit, Ordering::AcqRel) & (1u64 << bit) != 0 {
            return false;
        }
        counter
            >= self
                .last
                .load(Ordering::Acquire)
                .saturating_sub(WINDOW_SIZE)
    }
}

impl Default for AtomicReplayFilter {
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

    #[test]
    fn atomic_accepts_each_counter_once() {
        let filter = AtomicReplayFilter::new();
        assert!(filter.validate(0, u64::MAX));
        assert!(!filter.validate(0, u64::MAX));
        assert!(filter.validate(64, u64::MAX));
        assert!(!filter.validate(64, u64::MAX));
        assert_eq!(filter.last(), 64);
    }

    #[test]
    fn atomic_rejects_counters_behind_the_window() {
        let filter = AtomicReplayFilter::new();
        assert!(filter.validate(WINDOW_SIZE + 64, u64::MAX));
        assert!(!filter.validate(0, u64::MAX));
        assert!(filter.validate(WINDOW_SIZE, u64::MAX));
    }

    #[test]
    fn atomic_accepts_out_of_order_within_window() {
        let filter = AtomicReplayFilter::new();
        assert!(filter.validate(1000, u64::MAX));
        assert!(filter.validate(999, u64::MAX));
        assert!(filter.validate(1, u64::MAX));
        assert!(!filter.validate(999, u64::MAX));
        assert!(filter.validate(1001, u64::MAX));
    }

    #[test]
    fn atomic_rejects_counters_at_or_above_limit() {
        let filter = AtomicReplayFilter::new();
        assert!(filter.validate(4, 5));
        assert!(!filter.validate(5, 5));
        assert!(!filter.validate(6, 5));
    }

    #[test]
    fn atomic_reset_clears_the_window() {
        let filter = AtomicReplayFilter::new();
        assert!(filter.validate(10, u64::MAX));
        filter.reset();
        assert_eq!(filter.last(), 0);
        assert!(filter.validate(10, u64::MAX));
    }

    #[test]
    fn atomic_recycling_a_block_does_not_revive_old_counters() {
        let filter = AtomicReplayFilter::new();
        let old = 4096;
        assert!(filter.validate(old, u64::MAX));
        let fresh = old + RING_BLOCKS as u64 * 64;
        assert!(filter.validate(fresh, u64::MAX));
        assert!(!filter.validate(old, u64::MAX));
        assert!(!filter.validate(fresh, u64::MAX));
        assert!(filter.validate(fresh + 1, u64::MAX));
    }

    #[test]
    fn atomic_rejects_duplicates_from_many_threads() {
        use std::sync::Arc;

        let filter = Arc::new(AtomicReplayFilter::new());
        let mut handles = Vec::new();
        for _ in 0..8 {
            let filter = Arc::clone(&filter);
            handles.push(std::thread::spawn(move || {
                let mut accepted = 0u64;
                for counter in 0..4096u64 {
                    if filter.validate(counter, u64::MAX) {
                        accepted += 1;
                    }
                }
                accepted
            }));
        }
        let accepted: u64 = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .sum();
        assert_eq!(accepted, 4096);
    }

    #[test]
    fn atomic_accepts_concurrent_unique_counters() {
        use std::sync::atomic::AtomicU64;
        use std::sync::{Arc, Barrier};

        const THREADS: u64 = 4;
        const ROUNDS: u64 = 2000;
        let filter = Arc::new(AtomicReplayFilter::new());
        let barrier = Arc::new(Barrier::new(THREADS as usize));
        let accepted = Arc::new(AtomicU64::new(0));
        let rejected = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();
        for thread in 0..THREADS {
            let filter = Arc::clone(&filter);
            let barrier = Arc::clone(&barrier);
            let accepted = Arc::clone(&accepted);
            let rejected = Arc::clone(&rejected);
            handles.push(std::thread::spawn(move || {
                for round in 0..ROUNDS {
                    let counter = round * THREADS + thread;
                    if filter.validate(counter, u64::MAX) {
                        accepted.fetch_add(1, Ordering::Relaxed);
                    } else {
                        rejected.fetch_add(1, Ordering::Relaxed);
                    }
                    if !filter.validate(counter, u64::MAX) {
                        rejected.fetch_add(1, Ordering::Relaxed);
                    }
                    barrier.wait();
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(accepted.load(Ordering::Relaxed), THREADS * ROUNDS);
        assert_eq!(rejected.load(Ordering::Relaxed), THREADS * ROUNDS);
    }
}
