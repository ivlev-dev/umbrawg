//! Ограниченное SPSC-кольцо без блокировок.
//!
//! У каждого кольца ровно один производитель и один потребитель, поэтому
//! достаточно пары атомарных индексов. Ёмкость фиксирована и является степенью
//! двойки, а переполнение возвращает элемент вызывающему: это и есть механизм
//! backpressure без блокировок и без роста памяти.

use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicUsize, Ordering};

#[repr(align(64))]
struct Padded<T>(T);

/// Кольцевая очередь фиксированной ёмкости.
pub(crate) struct SpscRing<T> {
    slots: Box<[UnsafeCell<MaybeUninit<T>>]>,
    mask: usize,
    head: Padded<AtomicUsize>,
    tail: Padded<AtomicUsize>,
}

// Безопасность: слоты читает только потребитель, пишет только производитель,
// а передача владения подтверждается парой Release/Acquire на индексах.
unsafe impl<T: Send> Send for SpscRing<T> {}
unsafe impl<T: Send> Sync for SpscRing<T> {}

impl<T> SpscRing<T> {
    /// Создаёт кольцо ёмкостью `capacity` элементов.
    ///
    /// Паникует, если `capacity` не степень двойки или меньше двух.
    pub fn new(capacity: usize) -> Self {
        assert!(
            capacity.is_power_of_two() && capacity >= 2,
            "ring capacity must be a power of two"
        );
        let slots = (0..capacity)
            .map(|_| UnsafeCell::new(MaybeUninit::uninit()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            slots,
            mask: capacity - 1,
            head: Padded(AtomicUsize::new(0)),
            tail: Padded(AtomicUsize::new(0)),
        }
    }

    /// Текущее число элементов (приблизительное при конкурентном доступе).
    pub fn len(&self) -> usize {
        self.tail
            .0
            .load(Ordering::Acquire)
            .wrapping_sub(self.head.0.load(Ordering::Acquire))
    }

    /// Возвращает `true`, если кольцо пусто.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Кладёт элемент. При переполнении возвращает его обратно.
    pub fn push(&self, value: T) -> Result<(), T> {
        let tail = self.tail.0.load(Ordering::Relaxed);
        let head = self.head.0.load(Ordering::Acquire);
        if tail.wrapping_sub(head) >= self.slots.len() {
            return Err(value);
        }
        unsafe {
            (*self.slots[tail & self.mask].get()).write(value);
        }
        self.tail.0.store(tail.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    /// Забирает элемент, если он есть.
    pub fn pop(&self) -> Option<T> {
        let head = self.head.0.load(Ordering::Relaxed);
        if head == self.tail.0.load(Ordering::Acquire) {
            return None;
        }
        let value = unsafe { (*self.slots[head & self.mask].get()).assume_init_read() };
        self.head.0.store(head.wrapping_add(1), Ordering::Release);
        Some(value)
    }
}

impl<T> Drop for SpscRing<T> {
    fn drop(&mut self) {
        while self.pop().is_some() {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    use std::sync::Arc;

    #[test]
    fn preserves_fifo_order() {
        let ring = SpscRing::new(4);
        for value in 0..4 {
            assert!(ring.push(value).is_ok());
        }
        assert_eq!(ring.pop(), Some(0));
        assert_eq!(ring.pop(), Some(1));
        assert!(ring.push(4).is_ok());
        assert_eq!(ring.pop(), Some(2));
        assert_eq!(ring.pop(), Some(3));
        assert_eq!(ring.pop(), Some(4));
        assert_eq!(ring.pop(), None);
    }

    #[test]
    fn reports_overflow_without_losing_items() {
        let ring = SpscRing::new(2);
        assert!(ring.push(1u64).is_ok());
        assert!(ring.push(2).is_ok());
        let rejected = ring.push(3);
        assert_eq!(rejected, Err(3));
        assert_eq!(ring.len(), 2);
        assert_eq!(ring.pop(), Some(1));
        assert!(ring.push(3).is_ok());
    }

    #[test]
    fn single_thread_push_pop_cycles() {
        let ring = SpscRing::new(2);
        for value in 0..1000u64 {
            assert!(ring.push(value).is_ok());
            assert_eq!(ring.pop(), Some(value));
        }
        assert!(ring.is_empty());
    }

    #[test]
    fn transfers_items_between_threads() {
        const COUNT: u64 = 100_000;
        let ring = Arc::new(SpscRing::new(64));
        let sum = Arc::new(AtomicU64::new(0));

        let consumer = {
            let ring = Arc::clone(&ring);
            let sum = Arc::clone(&sum);
            std::thread::spawn(move || {
                let mut received = 0u64;
                while received < COUNT {
                    match ring.pop() {
                        Some(value) => {
                            sum.fetch_add(value, Ordering::Relaxed);
                            received += 1;
                        }
                        None => std::hint::spin_loop(),
                    }
                }
                received
            })
        };

        let mut sent = 0u64;
        while sent < COUNT {
            if ring.push(sent).is_ok() {
                sent += 1;
            } else {
                std::hint::spin_loop();
            }
        }

        assert_eq!(consumer.join().unwrap(), COUNT);
        assert_eq!(sum.load(Ordering::Relaxed), COUNT * (COUNT - 1) / 2);
    }

    #[test]
    fn drop_drains_pending_items() {
        let ring = SpscRing::new(4);
        for value in 0..3 {
            assert!(ring.push(value).is_ok());
        }
        drop(ring);
    }
}
