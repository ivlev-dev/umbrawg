//! Cryptographic random number helpers.
//!
//! The `*_with` functions accept any [`RngCore`] and are used throughout the
//! workspace so that tests and the data path can supply their own generator.
//! The remaining functions draw from the operating system CSPRNG.

use core::ops::RangeInclusive;

use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use crate::chacha20::{Keystream, NONCE_LEN};
use crate::{Key, KEY_LEN};

const U32_SPACE: u64 = 1u64 << 32;

/// Размер буфера одного перевыпуска ключа [`BufferedRng`].
pub const RESEED_BYTES: usize = 4096;

const SEED_LEN: usize = KEY_LEN + NONCE_LEN;

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

/// Буферизованный CSPRNG на ChaCha20-потоке.
///
/// Ключ и nonce берутся из источника (`OsRng` на горячем пути демона) раз в
/// [`RESEED_BYTES`] байт, всё остальное время байты выдаются из keystream.
pub struct BufferedRng<R: RngCore> {
    source: R,
    stream: Keystream,
    buffer: [u8; RESEED_BYTES],
    position: usize,
}

impl<R: RngCore> BufferedRng<R> {
    /// Создаёт генератор, засеянный из `source`.
    #[must_use]
    pub fn new(source: R) -> Self {
        let mut rng = Self {
            source,
            stream: Keystream::new(&Key::from_bytes([0u8; KEY_LEN]), &[0u8; NONCE_LEN]),
            buffer: [0u8; RESEED_BYTES],
            position: 0,
        };
        rng.reseed();
        rng
    }

    /// Возвращает ссылку на источник энтропии.
    #[must_use]
    pub fn get_ref(&self) -> &R {
        &self.source
    }

    fn reseed(&mut self) {
        let mut seed = [0u8; SEED_LEN];
        self.source.fill_bytes(&mut seed);
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&seed[..KEY_LEN]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&seed[KEY_LEN..]);
        self.stream = Keystream::new(&Key::from_bytes(key), &nonce);
        self.buffer = [0u8; RESEED_BYTES];
        self.stream.apply_keystream(&mut self.buffer);
        self.position = 0;
        key.zeroize();
        nonce.zeroize();
        seed.zeroize();
    }

    fn take(&mut self, dst: &mut [u8]) {
        let mut written = 0;
        while written < dst.len() {
            if self.position == self.buffer.len() {
                self.reseed();
            }
            let count = (dst.len() - written).min(self.buffer.len() - self.position);
            let end = self.position + count;
            dst[written..written + count].copy_from_slice(&self.buffer[self.position..end]);
            self.position = end;
            written += count;
        }
    }
}

impl<R: RngCore> RngCore for BufferedRng<R> {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.take(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.take(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.take(dst);
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rand_core::Error> {
        self.take(dst);
        Ok(())
    }
}

impl<R: RngCore> core::fmt::Debug for BufferedRng<R> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BufferedRng")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct CountingRng {
        seed: u64,
        fills: usize,
    }

    impl CountingRng {
        fn new(seed: u64) -> Self {
            Self { seed, fills: 0 }
        }

        fn word(&mut self) -> u64 {
            self.seed = self
                .seed
                .wrapping_add(0x9e37_79b9_7f4a_7c15)
                .rotate_left(17)
                .wrapping_mul(0xbf58_476d_1ce4_e5b9);
            self.seed ^ (self.seed >> 29)
        }
    }

    impl RngCore for CountingRng {
        fn next_u32(&mut self) -> u32 {
            self.word() as u32
        }

        fn next_u64(&mut self) -> u64 {
            self.word()
        }

        fn fill_bytes(&mut self, dst: &mut [u8]) {
            self.fills += 1;
            for chunk in dst.chunks_mut(8) {
                let bytes = self.word().to_le_bytes();
                let length = chunk.len();
                chunk.copy_from_slice(&bytes[..length]);
            }
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dst);
            Ok(())
        }
    }

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
    fn buffered_rng_is_deterministic_for_equal_seeds() {
        let mut first = BufferedRng::new(CountingRng::new(7));
        let mut second = BufferedRng::new(CountingRng::new(7));
        let mut left = [0u8; 1024];
        let mut right = [0u8; 1024];
        first.fill_bytes(&mut left);
        second.fill_bytes(&mut right);
        assert_eq!(left, right);
        assert_ne!(left[..8], left[8..16]);

        let mut other = BufferedRng::new(CountingRng::new(8));
        let mut third = [0u8; 1024];
        other.fill_bytes(&mut third);
        assert_ne!(left, third);
    }

    #[test]
    fn buffered_rng_reseeds_once_per_buffer() {
        let mut rng = BufferedRng::new(CountingRng::new(11));
        assert_eq!(
            rng.source.fills, 1,
            "the initial seed must come from the source"
        );
        let mut buffer = [0u8; RESEED_BYTES];
        rng.fill_bytes(&mut buffer);
        assert_eq!(rng.source.fills, 1, "a full buffer needs no reseed");
        rng.fill_bytes(&mut [0u8; 1]);
        assert_eq!(rng.source.fills, 2, "the exhausted buffer is reseeded");
        rng.fill_bytes(&mut [0u8; RESEED_BYTES - 1]);
        assert_eq!(rng.source.fills, 2);
    }

    #[test]
    fn buffered_rng_consumes_the_keystream_across_call_boundaries() {
        let mut split = BufferedRng::new(CountingRng::new(13));
        let mut whole = BufferedRng::new(CountingRng::new(13));
        let mut expected = [0u8; 300];
        whole.fill_bytes(&mut expected);
        let mut actual = [0u8; 300];
        split.fill_bytes(&mut actual[..1]);
        split.fill_bytes(&mut actual[1..17]);
        split.fill_bytes(&mut actual[17..]);
        assert_eq!(actual, expected);
    }

    #[test]
    fn buffered_rng_next_u32_matches_bytes() {
        let mut rng = BufferedRng::new(CountingRng::new(17));
        let value = rng.next_u32();
        let mut reference = BufferedRng::new(CountingRng::new(17));
        let mut bytes = [0u8; 4];
        reference.fill_bytes(&mut bytes);
        assert_eq!(value, u32::from_le_bytes(bytes));
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
