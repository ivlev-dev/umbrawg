//! Cryptographic random number helpers.
//!
//! The `*_with` functions accept any [`RngCore`] and are used throughout the
//! workspace so that tests and the data path can supply their own generator.
//! The remaining functions draw from the operating system CSPRNG.

use core::ops::RangeInclusive;

use rand_core::{OsRng, RngCore};

const U32_SPACE: u64 = 1u64 << 32;

/// Fills `dst` with cryptographically secure random bytes.
pub fn fill(dst: &mut [u8]) {
    fill_with(&mut OsRng, dst);
}

/// Fills `dst` with random bytes from `rng`.
pub fn fill_with(rng: &mut impl RngCore, dst: &mut [u8]) {
    rng.fill_bytes(dst);
}

/// Returns a random 16-bit value.
#[must_use]
pub fn u16() -> u16 {
    u16_with(&mut OsRng)
}

/// Returns a random 16-bit value from `rng`.
#[must_use]
pub fn u16_with(rng: &mut impl RngCore) -> u16 {
    (rng.next_u32() >> 16) as u16
}

/// Returns a random 32-bit value.
#[must_use]
pub fn u32() -> u32 {
    u32_with(&mut OsRng)
}

/// Returns a random 32-bit value from `rng`.
#[must_use]
pub fn u32_with(rng: &mut impl RngCore) -> u32 {
    rng.next_u32()
}

/// Returns a random 64-bit value.
#[must_use]
pub fn u64() -> u64 {
    u64_with(&mut OsRng)
}

/// Returns a random 64-bit value from `rng`.
#[must_use]
pub fn u64_with(rng: &mut impl RngCore) -> u64 {
    rng.next_u64()
}

/// Returns a uniformly distributed value in `0..upper`.
///
/// Returns zero when `upper` is zero.
#[must_use]
pub fn below(upper: u32) -> u32 {
    below_with(&mut OsRng, upper)
}

/// Returns a uniformly distributed value in `0..upper` from `rng`.
#[must_use]
pub fn below_with(rng: &mut impl RngCore, upper: u32) -> u32 {
    if upper <= 1 {
        return 0;
    }
    let span = u64::from(upper);
    let zone = U32_SPACE - U32_SPACE % span;
    loop {
        let value = u64::from(rng.next_u32());
        if value < zone {
            return (value % span) as u32;
        }
    }
}

/// Returns a uniformly distributed value inside `range`.
#[must_use]
pub fn u32_inclusive(range: &RangeInclusive<u32>) -> u32 {
    u32_inclusive_with(&mut OsRng, range)
}

/// Returns a uniformly distributed value inside `range` from `rng`.
#[must_use]
pub fn u32_inclusive_with(rng: &mut impl RngCore, range: &RangeInclusive<u32>) -> u32 {
    let low = *range.start();
    let high = *range.end();
    if low >= high {
        return low;
    }
    let span = u64::from(high) - u64::from(low) + 1;
    let zone = U32_SPACE - U32_SPACE % span;
    loop {
        let value = u64::from(rng.next_u32());
        if value < zone {
            return (u64::from(low) + value % span) as u32;
        }
    }
}

/// Returns a uniformly distributed `u16` inside `range`.
#[must_use]
pub fn u16_inclusive(range: &RangeInclusive<u16>) -> u16 {
    u16_inclusive_with(&mut OsRng, range)
}

/// Returns a uniformly distributed `u16` inside `range` from `rng`.
#[must_use]
pub fn u16_inclusive_with(rng: &mut impl RngCore, range: &RangeInclusive<u16>) -> u16 {
    let low = u32::from(*range.start());
    let high = u32::from(*range.end());
    u32_inclusive_with(rng, &(low..=high)) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SequenceRng {
        values: Vec<u32>,
        index: usize,
    }

    impl SequenceRng {
        fn new(values: &[u32]) -> Self {
            Self {
                values: values.to_vec(),
                index: 0,
            }
        }
    }

    impl RngCore for SequenceRng {
        fn next_u32(&mut self) -> u32 {
            let value = self.values[self.index % self.values.len()];
            self.index += 1;
            value
        }

        fn next_u64(&mut self) -> u64 {
            u64::from(self.next_u32()) << 32 | u64::from(self.next_u32())
        }

        fn fill_bytes(&mut self, dst: &mut [u8]) {
            for chunk in dst.chunks_mut(4) {
                let value = self.next_u32().to_le_bytes();
                let length = chunk.len();
                chunk.copy_from_slice(&value[..length]);
            }
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dst);
            Ok(())
        }
    }

    #[test]
    fn inclusive_range_covers_both_ends() {
        let mut low_rng = SequenceRng::new(&[0]);
        assert_eq!(u32_inclusive_with(&mut low_rng, &(7..=9)), 7);
        let mut high_rng = SequenceRng::new(&[2]);
        assert_eq!(u32_inclusive_with(&mut high_rng, &(7..=9)), 9);
    }

    #[test]
    fn inclusive_range_handles_full_space() {
        let mut rng = SequenceRng::new(&[0xdead_beef]);
        assert_eq!(u32_inclusive_with(&mut rng, &(0..=u32::MAX)), 0xdead_beef);
    }

    #[test]
    fn zero_span_returns_low() {
        let mut rng = SequenceRng::new(&[123]);
        assert_eq!(u32_inclusive_with(&mut rng, &(5..=5)), 5);
        assert_eq!(u16_inclusive_with(&mut rng, &(5..=5)), 5);
    }

    #[test]
    fn below_respects_upper_bound() {
        let mut rng = SequenceRng::new(&[u32::MAX, 11]);
        assert_eq!(below_with(&mut rng, 10), 1);
        assert_eq!(below_with(&mut rng, 0), 0);
        assert_eq!(below_with(&mut rng, 1), 0);
    }

    #[test]
    fn u16_range_is_bounded() {
        let mut rng = SequenceRng::new(&[u32::MAX, 300, 1]);
        let value = u16_inclusive_with(&mut rng, &(100..=200));
        assert!((100..=200).contains(&value));
    }

    #[test]
    fn os_random_bytes_are_not_constant() {
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        fill(&mut first);
        fill(&mut second);
        assert_ne!(first, second);
    }
}
