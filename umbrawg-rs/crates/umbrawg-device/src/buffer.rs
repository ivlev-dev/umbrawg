use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use parking_lot::Mutex;

use umbrawg_proto::messages::MAX_PACKET_SIZE;

pub const DEFAULT_BUFFER_SIZE: usize = MAX_PACKET_SIZE;

pub struct BufferPool {
    size: usize,
    capacity: usize,
    free: Mutex<Vec<Box<[u8]>>>,
}

impl BufferPool {
    #[must_use]
    pub fn new(capacity: usize, size: usize) -> Self {
        let mut free = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            free.push(vec![0u8; size].into_boxed_slice());
        }
        Self {
            size,
            capacity,
            free: Mutex::new(free),
        }
    }

    #[must_use]
    pub fn with_default(capacity: usize) -> Self {
        Self::new(capacity, DEFAULT_BUFFER_SIZE)
    }

    #[must_use]
    pub fn size(&self) -> usize {
        self.size
    }

    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    #[must_use]
    pub fn available(&self) -> usize {
        self.free.lock().len()
    }

    #[must_use]
    pub fn acquire(self: &Arc<Self>) -> Buffer {
        let data = self
            .free
            .lock()
            .pop()
            .unwrap_or_else(|| vec![0u8; self.size].into_boxed_slice());
        Buffer {
            data: Some(data),
            pool: Arc::clone(self),
        }
    }

    fn release(&self, data: Box<[u8]>) {
        if data.len() != self.size {
            return;
        }
        let mut free = self.free.lock();
        if free.len() < self.capacity {
            free.push(data);
        }
    }
}

pub struct Buffer {
    data: Option<Box<[u8]>>,
    pool: Arc<BufferPool>,
}

impl Buffer {
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.data.as_deref().unwrap_or(&[])
    }

    #[must_use]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.data.as_deref_mut().unwrap_or(&mut [])
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.data.as_ref().map_or(0, |data| data.len())
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Deref for Buffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl DerefMut for Buffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        if let Some(data) = self.data.take() {
            self.pool.release(data);
        }
    }
}

impl core::fmt::Debug for Buffer {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Buffer")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_and_release_round_trip() {
        let pool = Arc::new(BufferPool::with_default(2));
        assert_eq!(pool.available(), 2);
        let mut first = pool.acquire();
        assert_eq!(first.len(), DEFAULT_BUFFER_SIZE);
        first[0] = 0xaa;
        assert_eq!(pool.available(), 1);
        drop(first);
        assert_eq!(pool.available(), 2);
        let second = pool.acquire();
        assert_eq!(second[0], 0xaa);
        drop(second);
        assert_eq!(pool.available(), 2);
    }

    #[test]
    fn pool_grows_on_demand() {
        let pool = Arc::new(BufferPool::new(1, 16));
        let first = pool.acquire();
        let second = pool.acquire();
        assert_eq!(pool.available(), 0);
        assert_eq!(first.len(), 16);
        assert_eq!(second.len(), 16);
        drop(first);
        drop(second);
        assert_eq!(pool.available(), 1);
    }

    #[test]
    fn foreign_buffers_are_dropped() {
        let pool = Arc::new(BufferPool::new(1, 8));
        let buffer = pool.acquire();
        drop(buffer);
        assert_eq!(pool.available(), 1);
        assert_eq!(pool.size(), 8);
        assert_eq!(pool.capacity(), 1);
    }
}
