//! Детектор нагрузки по управляющим пакетам.
//!
//! Считает инициации рукопожатия в скользящем окне и переключает флаг
//! `under_load` с гистерезисом. Пока флаг установлен, обработчик инициаций
//! требует валидный MAC2 (cookie) и применяет rate limiter по адресу
//! отправителя, поэтому дорогая криптография не выполняется для каждого
//! пакета неаутентифицированного флуда.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// Порог по умолчанию: инициации в секунду, после которого включается
/// cookie-защита.
pub const DEFAULT_UNDER_LOAD_PPS: u32 = 100;

/// Минимальный порог: нулевое или отрицательное значение не имеет смысла.
pub const MIN_UNDER_LOAD_PPS: u32 = 1;

const WINDOW: Duration = Duration::from_secs(1);
const BUCKET: Duration = Duration::from_millis(100);
const BUCKETS: usize = (WINDOW.as_nanos() / BUCKET.as_nanos()) as usize;

/// Скользящее окно из отдельных корзин: окно сдвигается без обхода счётчиков.
#[derive(Debug)]
struct SlidingWindow {
    counts: [u32; BUCKETS],
    index: usize,
    bucket_start: Instant,
}

impl SlidingWindow {
    fn new(now: Instant) -> Self {
        Self {
            counts: [0; BUCKETS],
            index: 0,
            bucket_start: now,
        }
    }

    fn advance(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.bucket_start);
        let steps = elapsed.as_nanos() / BUCKET.as_nanos();
        if steps == 0 {
            return;
        }
        if steps >= BUCKETS as u128 {
            self.counts = [0; BUCKETS];
            self.index = 0;
            self.bucket_start = now;
            return;
        }
        let steps = steps as usize;
        for _ in 0..steps {
            self.index = (self.index + 1) % BUCKETS;
            self.counts[self.index] = 0;
        }
        let advance = BUCKET.saturating_mul(steps as u32);
        self.bucket_start = self.bucket_start.checked_add(advance).unwrap_or(now);
    }

    fn note(&mut self, now: Instant) {
        self.advance(now);
        let index = self.index;
        self.counts[index] = self.counts[index].saturating_add(1);
    }

    fn total(&self) -> u32 {
        self.counts
            .iter()
            .fold(0u32, |total, count| total.saturating_add(*count))
    }

    fn reset(&mut self, now: Instant) {
        self.counts = [0; BUCKETS];
        self.index = 0;
        self.bucket_start = now;
    }
}

/// Детектор управляющего флуда.
///
/// Порог задаётся в инициациях на секунду. Вход в состояние `under_load`
/// происходит при достижении порога, выход — при снижении частоты вдвое
/// (гистерезис), чтобы не дёргать cookie-режим на границе.
#[derive(Debug)]
pub struct UnderLoadDetector {
    threshold: AtomicU32,
    window: Mutex<SlidingWindow>,
}

impl UnderLoadDetector {
    /// Создаёт детектор с порогом `threshold` инициаций в секунду.
    #[must_use]
    pub fn new(threshold: u32) -> Self {
        Self {
            threshold: AtomicU32::new(threshold.max(MIN_UNDER_LOAD_PPS)),
            window: Mutex::new(SlidingWindow::new(Instant::now())),
        }
    }

    /// Возвращает действующий порог.
    #[must_use]
    pub fn threshold(&self) -> u32 {
        self.threshold.load(Ordering::Relaxed)
    }

    /// Устанавливает порог; значения ниже [`MIN_UNDER_LOAD_PPS`] поднимаются.
    pub fn set_threshold(&self, threshold: u32) {
        self.threshold
            .store(threshold.max(MIN_UNDER_LOAD_PPS), Ordering::Relaxed);
    }

    /// Учитывает инициацию и возвращает новое состояние флага.
    pub fn note(&self, now: Instant, under_load: bool) -> bool {
        let mut window = self.window.lock();
        window.note(now);
        decide(self.threshold(), window.total(), under_load)
    }

    /// Пересчитывает состояние без учёта новой инициации.
    pub fn refresh(&self, now: Instant, under_load: bool) -> bool {
        let mut window = self.window.lock();
        window.advance(now);
        decide(self.threshold(), window.total(), under_load)
    }

    /// Сбрасывает окно; используется при выключении детектора.
    pub fn reset(&self, now: Instant) {
        self.window.lock().reset(now);
    }

    #[cfg(test)]
    fn total(&self, now: Instant) -> u32 {
        let mut window = self.window.lock();
        window.advance(now);
        window.total()
    }
}

fn decide(threshold: u32, total: u32, under_load: bool) -> bool {
    if under_load {
        total.saturating_mul(2) > threshold
    } else {
        total >= threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trips_at_threshold() {
        let detector = UnderLoadDetector::new(4);
        let now = Instant::now();
        assert!(!detector.note(now, false));
        assert!(!detector.note(now, false));
        assert!(!detector.note(now, false));
        assert!(detector.note(now, false));
        assert_eq!(detector.total(now), 4);
    }

    #[test]
    fn threshold_is_clamped() {
        let detector = UnderLoadDetector::new(0);
        assert_eq!(detector.threshold(), MIN_UNDER_LOAD_PPS);
        let now = Instant::now();
        assert!(detector.note(now, false));
        detector.set_threshold(0);
        assert_eq!(detector.threshold(), MIN_UNDER_LOAD_PPS);
    }

    #[test]
    fn hysteresis_keeps_under_load_below_threshold() {
        let detector = UnderLoadDetector::new(20);
        let now = Instant::now();
        for _ in 0..19 {
            assert!(!detector.note(now, false));
        }
        assert!(detector.note(now, false));

        let later = now + Duration::from_millis(500);
        for _ in 0..12 {
            detector.note(later, true);
        }
        assert_eq!(detector.total(later), 32);
        assert!(detector.refresh(later, true));

        let after_first_bucket = now + Duration::from_millis(1050);
        assert!(detector.refresh(after_first_bucket, true));
        let total = detector.total(after_first_bucket);
        assert!(total < 20);
        assert!(detector.refresh(after_first_bucket, true));

        let after_second_bucket = now + Duration::from_millis(1550);
        assert!(!detector.refresh(after_second_bucket, true));
    }

    #[test]
    fn window_expires_completely() {
        let detector = UnderLoadDetector::new(2);
        let now = Instant::now();
        assert!(!detector.note(now, false));
        assert!(detector.note(now, false));
        assert_eq!(detector.total(now), 2);
        assert_eq!(detector.total(now + Duration::from_millis(999)), 2);
        assert_eq!(detector.total(now + Duration::from_secs(1)), 0);
    }

    #[test]
    fn reset_clears_window() {
        let detector = UnderLoadDetector::new(2);
        let now = Instant::now();
        detector.note(now, false);
        detector.note(now, false);
        assert!(detector.refresh(now, false));
        detector.reset(now);
        assert_eq!(detector.total(now), 0);
        assert!(!detector.refresh(now, true));
    }

    #[test]
    fn backwards_clock_does_not_panic_or_double_count() {
        let detector = UnderLoadDetector::new(2);
        let now = Instant::now();
        detector.note(now + Duration::from_secs(5), false);
        assert_eq!(detector.total(now), 1);
        assert_eq!(detector.total(now + Duration::from_secs(5)), 1);
    }

    #[test]
    fn boundary_values_are_stable() {
        let detector = UnderLoadDetector::new(1);
        let now = Instant::now();
        assert!(detector.note(now, false));
        assert!(!detector.refresh(now + Duration::from_secs(1), true));
        assert!(detector.note(now + Duration::from_secs(1), false));
    }
}
