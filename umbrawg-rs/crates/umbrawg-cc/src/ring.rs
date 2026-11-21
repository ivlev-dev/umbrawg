//! Fixed-size bookkeeping ring for datagrams in flight.

/// Maximum number of tracked datagrams.
pub(crate) const RING_CAPACITY: usize = 8192;

/// Lifecycle state of a tracked datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum SlotState {
    #[default]
    Empty,
    InFlight,
    Acked,
    /// Counted as a path loss, either by a bitmap hole, an explicit report or
    /// the watermark. Kept until the slot is reused so a late report for the
    /// same counter is not counted twice.
    Lost,
    /// Dropped locally (send error or queue overflow) after leaving the
    /// in-flight accounting. A local drop is not a congestion signal.
    Dropped,
}

/// How a loss report for one counter relates to the tracked state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LossOutcome {
    /// The record was in flight and must leave the accounting.
    InFlight(SentPacket),
    /// The loss was already counted; the report is a duplicate.
    AlreadyCounted,
    /// The datagram never reached the wire, so this is not a path loss.
    Dropped,
    /// No record (never tracked, evicted or acknowledged).
    Unknown,
}

/// Bookkeeping for one transmitted datagram.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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

    /// Marks a datagram lost and reports how it was tracked.
    ///
    /// A record that left the accounting through the watermark is already
    /// `Lost`, so a late bitmap hole for the same counter is classified as a
    /// duplicate instead of being counted a second time.
    pub(crate) fn mark_lost(&mut self, counter: u64) -> LossOutcome {
        let index = Self::index(counter);
        let slot = self.slots[index];
        if slot.counter != counter {
            return LossOutcome::Unknown;
        }
        match slot.state {
            SlotState::InFlight => {
                self.slots[index].state = SlotState::Lost;
                LossOutcome::InFlight(slot)
            }
            SlotState::Lost => LossOutcome::AlreadyCounted,
            SlotState::Dropped => LossOutcome::Dropped,
            SlotState::Acked | SlotState::Empty => LossOutcome::Unknown,
        }
    }

    /// Releases a locally dropped datagram from the in-flight accounting.
    ///
    /// Only records still marked `InFlight` qualify: an acknowledged, lost or
    /// already dropped slot has no bytes left to return.
    pub(crate) fn mark_dropped(&mut self, counter: u64) -> Option<SentPacket> {
        let index = Self::index(counter);
        let slot = self.slots[index];
        if slot.counter == counter && slot.state == SlotState::InFlight {
            self.slots[index].state = SlotState::Dropped;
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
    ///
    /// They left the window without being acknowledged, so the controller
    /// treats them as path losses. Returns released bytes and packet count;
    /// the records are marked `Lost` to keep a late report from counting the
    /// same datagram twice.
    pub(crate) fn release_unreachable(&mut self, largest: u64, window: u64) -> (u64, u64) {
        let mut bytes = 0u64;
        let mut packets = 0u64;
        for slot in &mut self.slots {
            if slot.state == SlotState::InFlight && largest.saturating_sub(slot.counter) > window {
                slot.state = SlotState::Lost;
                bytes = bytes.saturating_add(u64::from(slot.len));
                packets = packets.saturating_add(1);
            }
        }
        (bytes, packets)
    }

    /// Releases records older than `max_age_ns`, returning released bytes and
    /// packet count. Used as a safety net when the peer never reports a loss.
    ///
    /// A record that stayed in flight for longer than the sweep age was never
    /// acknowledged: it is a loss, not an orphan, and is counted as one.
    pub(crate) fn sweep(&mut self, now_ns: u64, max_age_ns: u64) -> (u64, u64) {
        let mut bytes = 0u64;
        let mut packets = 0u64;
        for slot in &mut self.slots {
            if slot.state == SlotState::InFlight
                && now_ns.saturating_sub(slot.sent_at_ns) >= max_age_ns
            {
                slot.state = SlotState::Lost;
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
        assert_eq!(ring.mark_lost(7), LossOutcome::Unknown);
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
    fn unreachable_records_are_released_as_losses() {
        let mut ring = SentRing::new();
        for counter in 0..10 {
            ring.insert(packet(counter));
        }
        let (bytes, packets) = ring.release_unreachable(100, 63);
        assert_eq!(bytes, 10 * 1400);
        assert_eq!(packets, 10);
        assert_eq!(ring.mark_lost(3), LossOutcome::AlreadyCounted);
        assert_eq!(ring.mark_lost(3), LossOutcome::AlreadyCounted);
        let (bytes, packets) = ring.release_unreachable(60, 63);
        assert_eq!(bytes, 0);
        assert_eq!(packets, 0);
    }

    #[test]
    fn dropped_records_leave_the_accounting_once() {
        let mut ring = SentRing::new();
        ring.insert(packet(4));
        assert!(ring.mark_dropped(4).is_some());
        assert!(ring.mark_dropped(4).is_none());
        assert_eq!(ring.mark_lost(4), LossOutcome::Dropped);
        assert_eq!(ring.in_flight_count(), 0);
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
