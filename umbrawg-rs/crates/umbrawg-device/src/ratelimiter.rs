use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

const PACKETS_PER_SECOND: u64 = 20;
const PACKET_COST_NS: u64 = 1_000_000_000 / PACKETS_PER_SECOND;
const TOKEN_MAX_NS: u64 = PACKET_COST_NS * 5;
const TABLE_SIZE: usize = 8192;
const TABLE_MASK: usize = TABLE_SIZE - 1;
const ENTRY_TTL: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BucketKey {
    family: u8,
    bytes: [u8; 16],
}

impl BucketKey {
    fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(address) => Self {
                family: 4,
                bytes: v4_bytes(address),
            },
            IpAddr::V6(address) => {
                let mut bytes = [0u8; 16];
                bytes[..8].copy_from_slice(&address.octets()[..8]);
                Self { family: 6, bytes }
            }
        }
    }

    fn hash(self, state: &RandomState) -> usize {
        let mut hasher = state.build_hasher();
        self.family.hash(&mut hasher);
        self.bytes.hash(&mut hasher);
        hasher.finish() as usize & TABLE_MASK
    }
}

fn v4_bytes(address: Ipv4Addr) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[..4].copy_from_slice(&address.octets());
    bytes
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    key: BucketKey,
    occupied: bool,
    last: Instant,
    tokens_ns: u64,
}

impl Entry {
    fn empty() -> Self {
        Self {
            key: BucketKey {
                family: 0,
                bytes: [0; 16],
            },
            occupied: false,
            last: Instant::now(),
            tokens_ns: 0,
        }
    }
}

pub struct RateLimiter {
    table: Mutex<Vec<Entry>>,
    state: RandomState,
}

impl RateLimiter {
    #[must_use]
    pub fn new() -> Self {
        let empty = Entry::empty();
        Self {
            table: Mutex::new(vec![empty; TABLE_SIZE]),
            state: RandomState::new(),
        }
    }

    pub fn allow(&self, ip: IpAddr, now: Instant) -> bool {
        let key = BucketKey::from_ip(ip);
        let mut table = self.table.lock();
        let mut index = key.hash(&self.state);
        for _ in 0..TABLE_SIZE {
            let entry = &mut table[index];
            if entry.occupied {
                if entry.key == key {
                    return refill(entry, now);
                }
            } else {
                *entry = Entry {
                    key,
                    occupied: true,
                    last: now,
                    tokens_ns: TOKEN_MAX_NS - PACKET_COST_NS,
                };
                return true;
            }
            index = (index + 1) & TABLE_MASK;
        }
        false
    }

    pub fn gc(&self, now: Instant) {
        let mut table = self.table.lock();
        for entry in table.iter_mut() {
            if entry.occupied && now.saturating_duration_since(entry.last) > ENTRY_TTL {
                *entry = Entry::empty();
            }
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.table
            .lock()
            .iter()
            .filter(|entry| entry.occupied)
            .count()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

fn refill(entry: &mut Entry, now: Instant) -> bool {
    let elapsed = now.saturating_duration_since(entry.last).as_nanos();
    let elapsed = elapsed.min(u128::from(u64::MAX)) as u64;
    let tokens = entry.tokens_ns.saturating_add(elapsed).min(TOKEN_MAX_NS);
    entry.last = now;
    let allowed = tokens >= PACKET_COST_NS;
    entry.tokens_ns = if allowed {
        tokens - PACKET_COST_NS
    } else {
        tokens
    };
    allowed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

    #[test]
    fn burst_is_limited() {
        let limiter = RateLimiter::new();
        let now = Instant::now();
        for _ in 0..5 {
            assert!(limiter.allow(IP, now));
        }
        assert!(!limiter.allow(IP, now));
        assert_eq!(limiter.len(), 1);
    }

    #[test]
    fn tokens_refill_over_time() {
        let limiter = RateLimiter::new();
        let now = Instant::now();
        for _ in 0..5 {
            assert!(limiter.allow(IP, now));
        }
        assert!(!limiter.allow(IP, now));
        assert!(limiter.allow(IP, now + Duration::from_millis(50)));
        assert!(!limiter.allow(IP, now + Duration::from_millis(50)));
        for _ in 0..5 {
            assert!(limiter.allow(IP, now + Duration::from_millis(500)));
        }
        assert!(!limiter.allow(IP, now + Duration::from_millis(500)));
    }

    #[test]
    fn different_addresses_have_separate_buckets() {
        let limiter = RateLimiter::new();
        let now = Instant::now();
        let other = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        for _ in 0..5 {
            assert!(limiter.allow(IP, now));
        }
        assert!(!limiter.allow(IP, now));
        assert!(limiter.allow(other, now));
        assert_eq!(limiter.len(), 2);
    }

    #[test]
    fn ipv6_is_limited_per_slash_64() {
        let limiter = RateLimiter::new();
        let now = Instant::now();
        let first = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1));
        let second = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0xffff, 0, 0, 2));
        for _ in 0..5 {
            assert!(limiter.allow(first, now));
        }
        assert!(!limiter.allow(second, now));
        assert_eq!(limiter.len(), 1);
    }

    #[test]
    fn gc_removes_idle_entries() {
        let limiter = RateLimiter::new();
        let now = Instant::now();
        assert!(limiter.allow(IP, now));
        limiter.gc(now + Duration::from_secs(2));
        assert!(limiter.is_empty());
    }
}
