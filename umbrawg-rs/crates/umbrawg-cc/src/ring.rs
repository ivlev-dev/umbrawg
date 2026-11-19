//! Fixed-size bookkeeping ring for datagrams in flight.

/// Maximum number of tracked datagrams.
pub(crate) const RING_CAPACITY: usize = 8192;

/// Lifecycle state of a tracked datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum SlotState {
    #[default]
    Empty,
    InFlight,
    /// Removed from the in-flight accounting because the ACK bitmap can no
    /// longer cover it, but still tracked so that a late loss report can be
    /// classified correctly.
    Released,
    Acked,
    Lost,
}

/// Bookkeeping for one transmitted datagram.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SentPacket {
    pub(crate) counter: u64,
    pub(crate) len: u32,
    pub(crate) sent_at_ns: u64,
    pub(crate) delivered_at_send: u64,
    pub(crate) state: SlotState,
}

/// Open-addressed ring indexed by `counter % RING_CAPACITY`.
///
/// Counters are monotonically increasing per keypair, so the modulo index is
/// unique as long as fewer than [`RING_CAPACITY`] datagrams are outstanding.
/// Collisions are detected by comparing the stored counter.
#[derive(Debug, Clone)]
pub(crate) struct SentRing {
    slots: Vec<SentPacket>,
}

impl SentRing {
    pub(crate) fn new() -> Self {
        Self {
            slots: vec![SentPacket::default(); RING_CAPACITY],
        }
    }

    fn index(counter: u64) -> usize {
        (counter % RING_CAPACITY as u64) as usize
    }

    /// Inserts a datagram, returning the record it displaced when that record
    /// was still in flight.
    pub(crate) fn insert(&mut self, packet: SentPacket) -> Option<SentPacket> {
        let index = Self::index(packet.counter);
        let previous = self.slots[index];
        self.slots[index] = packet;
        if previous.state == SlotState::InFlight {
            Some(previous)
        } else {
            None
        }
    }

    pub(crate) fn mark_acked(&mut self, counter: u64) -> Option<SentPacket> {
        self.resolve(counter, SlotState::Acked)
    }

    /// Marks a datagram lost. Records that were already released from the
    /// in-flight accounting can still transition to `Lost`, which lets the
    /// controller distinguish a late real-loss report from a duplicate.
    pub(crate) fn mark_lost(&mut self, counter: u64) -> Option<SentPacket> {
        let index = Self::index(counter);
        let slot = self.slots[index];
        let resolvable = matches!(slot.state, SlotState::InFlight | SlotState::Released);
        if resolvable && slot.counter == counter {
            self.slots[index].state = SlotState::Lost;
            Some(slot)
        } else {
            None
        }
    }

    fn resolve(&mut self, counter: u64, state: SlotState) -> Option<SentPacket> {
        let index = Self::index(counter);
        let slot = self.slots[index];
        if slot.state == SlotState::InFlight && slot.counter == counter {
            self.slots[index].state = state;
            Some(slot)
        } else {
            None
        }
    }

    /// Releases records that the 64-bit ACK bitmap can no longer cover.
    /// Returns released bytes and packet count.
    pub(crate) fn release_unreachable(&mut self, largest: u64, window: u64) -> (u64, u64) {
        let mut bytes = 0u64;
        let mut packets = 0u64;
        for slot in &mut self.slots {
            if slot.state == SlotState::InFlight && largest.saturating_sub(slot.counter) > window {
                slot.state = SlotState::Released;
                bytes = bytes.saturating_add(u64::from(slot.len));
                packets = packets.saturating_add(1);
            }
        }
        (bytes, packets)
    }

    /// Releases records older than `max_age_ns`. Returns released bytes and
    /// packet count. Used as a safety net when the peer never reports a loss.
    pub(crate) fn sweep(&mut self, now_ns: u64, max_age_ns: u64) -> (u64, u64) {
        let mut bytes = 0u64;
        let mut packets = 0u64;
        for slot in &mut self.slots {
            if slot.state == SlotState::InFlight
                && now_ns.saturating_sub(slot.sent_at_ns) >= max_age_ns
            {
                slot.state = SlotState::Released;
                bytes = bytes.saturating_add(u64::from(slot.len));
                packets = packets.saturating_add(1);
            }
        }
        (bytes, packets)
    }

    #[cfg(test)]
    pub(crate) fn in_flight_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.state == SlotState::InFlight)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(counter: u64) -> SentPacket {
        SentPacket {
            counter,
            len: 1400,
            sent_at_ns: counter,
            delivered_at_send: 0,
            state: SlotState::InFlight,
        }
    }

    #[test]
    fn insert_and_resolve() {
        let mut ring = SentRing::new();
        assert!(ring.insert(packet(7)).is_none());
        assert_eq!(ring.in_flight_count(), 1);
        assert!(ring.mark_acked(7).is_some());
        assert!(ring.mark_acked(7).is_none());
        assert!(ring.mark_lost(7).is_none());
        assert_eq!(ring.in_flight_count(), 0);
    }

    #[test]
    fn collision_with_different_counter_releases_previous() {
        let mut ring = SentRing::new();
        ring.insert(packet(1));
        let evicted = ring.insert(packet(1 + RING_CAPACITY as u64));
        assert_eq!(evicted.map(|p| p.counter), Some(1));
        assert!(ring.mark_acked(1).is_none());
    }

    #[test]
    fn unreachable_records_are_released() {
        let mut ring = SentRing::new();
        for counter in 0..10 {
            ring.insert(packet(counter));
        }
        let (bytes, packets) = ring.release_unreachable(100, 63);
        assert_eq!(bytes, 10 * 1400);
        assert_eq!(packets, 10);
        assert!(ring
            .mark_lost(3)
            .is_some_and(|p| p.state == SlotState::Released));
        assert!(ring.mark_lost(3).is_none());
        let (bytes, packets) = ring.release_unreachable(60, 63);
        assert_eq!(bytes, 0);
        assert_eq!(packets, 0);
    }

    #[test]
    fn sweep_releases_old_records() {
        let mut ring = SentRing::new();
        ring.insert(packet(0));
        ring.insert(packet(1));
        let (bytes, packets) = ring.sweep(10, 5);
        assert_eq!(bytes, 2 * 1400);
        assert_eq!(packets, 2);
        assert_eq!(ring.in_flight_count(), 0);
    }

    #[test]
    fn sweep_keeps_young_records() {
        let mut ring = SentRing::new();
        ring.insert(packet(0));
        let (bytes, packets) = ring.sweep(999_999, 1_000_000);
        assert_eq!(bytes, 0);
        assert_eq!(packets, 0);
        assert_eq!(ring.in_flight_count(), 1);
    }
}
