//! Упорядочивающий буфер для конвейерного приёма.
//!
//! Поток приёма выдаёт каждому транспортному сегменту пира монотонный номер в
//! порядке поступления с провода, а крипто-воркеры расшифровывают сегменты
//! параллельно в любом порядке. Расшифрованные пакеты попадают в слот своего
//! номера, а поток-владелец пира отдаёт их в TUN строго по номерам. Слот,
//! занятый дольше `capacity` номеров, означает переполнение: поток приёма
//! отбрасывает задание целиком, не дожидаясь освобождения буфера.
//!
//! Буфер ограничен, поэтому память на пира фиксирована, а переполнение одного
//! пира не блокирует остальных. Пропуски (неудачная расшифровка, повтор,
//! отброшенное задание) помечаются как `skip` и не задерживают доставку.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

/// Минимальная глубина упорядочивающего буфера.
pub(crate) const MIN_DEPTH: usize = 64;

/// Максимальная глубина упорядочивающего буфера.
pub(crate) const MAX_DEPTH: usize = 4096;

/// Глубина по умолчанию: 1024 слота.
pub(crate) const DEFAULT_DEPTH: usize = 1024;

/// Результат попытки положить пакет в буфер.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FillOutcome {
    /// Пакет занял свой слот.
    Filled,
    /// Номер уже доставлен или пакет не влезает в слот.
    Stale,
    /// Слот занят другим номером: буфер не успевает разгружаться.
    Overflow,
}

/// Итог одного прохода разгрузки.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DrainStats {
    /// Отдано пакетов.
    pub delivered: usize,
    /// Пропущено номеров.
    pub skipped: usize,
    /// Получатель не принял пакет: нужен сброс накопителя и повтор.
    pub blocked: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotState {
    Empty,
    Pending,
    Filled,
    Skipped,
}

#[derive(Clone, Copy, Debug)]
struct Slot {
    seq: u64,
    len: usize,
    state: SlotState,
}

struct State {
    head: u64,
    started: bool,
    outstanding: usize,
    slots: Vec<Slot>,
    buffers: Vec<u8>,
}

/// Ограниченный буфер переупорядочивания одного пира.
pub(crate) struct ReorderRing {
    state: Mutex<State>,
    next_seq: AtomicU64,
    ready: AtomicBool,
    capacity: usize,
    slot_len: usize,
    owner: usize,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn rw_read<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    match lock.read() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn rw_write<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    match lock.write() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl ReorderRing {
    /// Создаёт буфер на `capacity` номеров со слотами по `slot_len` байт.
    ///
    /// Паникует, если ёмкость не степень двойки.
    pub(crate) fn new(capacity: usize, slot_len: usize, owner: usize) -> Self {
        assert!(
            capacity.is_power_of_two() && capacity >= 2,
            "reorder capacity must be a power of two"
        );
        Self {
            state: Mutex::new(State {
                head: 0,
                started: false,
                outstanding: 0,
                slots: vec![
                    Slot {
                        seq: 0,
                        len: 0,
                        state: SlotState::Empty,
                    };
                    capacity
                ],
                buffers: vec![0u8; capacity * slot_len],
            }),
            next_seq: AtomicU64::new(0),
            ready: AtomicBool::new(false),
            capacity,
            slot_len,
            owner,
        }
    }

    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    #[cfg(test)]
    pub(crate) fn slot_len(&self) -> usize {
        self.slot_len
    }

    /// Индекс воркера, который разгружает буфер в TUN.
    pub(crate) fn owner(&self) -> usize {
        self.owner
    }

    /// Занятая буфером память в байтах.
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> usize {
        self.capacity * self.slot_len
    }

    /// Возвращает `true`, если головной номер готов к доставке.
    pub(crate) fn has_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    /// Число зарезервированных, но не доставленных номеров.
    #[cfg(test)]
    pub(crate) fn outstanding(&self) -> usize {
        lock(&self.state).outstanding
    }

    /// Резервирует `count` подряд идущих номеров и возвращает первый из них.
    ///
    /// `None` означает, что свободного места нет: вызывающий отбрасывает всё
    /// задание и сообщает о переполнении.
    #[must_use]
    pub(crate) fn claim(&self, count: usize) -> Option<u64> {
        if count == 0 {
            return Some(self.next_seq.load(Ordering::Relaxed));
        }
        let mut state = lock(&self.state);
        if count > self.capacity || state.outstanding + count > self.capacity {
            return None;
        }
        let base = self.next_seq.load(Ordering::Relaxed);
        if !state.started {
            state.head = base;
            state.started = true;
        }
        for index in 0..count as u64 {
            let seq = base + index;
            let slot = &mut state.slots[(seq % self.capacity as u64) as usize];
            slot.seq = seq;
            slot.len = 0;
            slot.state = SlotState::Pending;
        }
        state.outstanding += count;
        self.next_seq.store(base + count as u64, Ordering::Relaxed);
        drop(state);
        Some(base)
    }

    /// Кладёт расшифрованный пакет в слот зарезервированного номера.
    pub(crate) fn fill(&self, seq: u64, packet: &[u8]) -> FillOutcome {
        let mut state = lock(&self.state);
        if !state.started || seq < state.head || seq - state.head >= self.capacity as u64 {
            return FillOutcome::Stale;
        }
        if packet.len() > self.slot_len {
            return FillOutcome::Stale;
        }
        let index = (seq % self.capacity as u64) as usize;
        let head_index = (state.head % self.capacity as u64) as usize;
        if state.slots[index].state != SlotState::Pending || state.slots[index].seq != seq {
            return FillOutcome::Overflow;
        }
        let offset = index * self.slot_len;
        state.buffers[offset..offset + packet.len()].copy_from_slice(packet);
        state.slots[index].len = packet.len();
        state.slots[index].state = SlotState::Filled;
        if index == head_index {
            self.ready.store(true, Ordering::Release);
        }
        FillOutcome::Filled
    }

    /// Помечает номер пропущенным: доставлять его не будут.
    pub(crate) fn skip(&self, seq: u64) {
        self.skip_range(seq, 1);
    }

    /// Помечает пропущенными `count` номеров, начиная с `base`.
    pub(crate) fn skip_range(&self, base: u64, count: usize) {
        if count == 0 {
            return;
        }
        let mut state = lock(&self.state);
        if !state.started {
            return;
        }
        let head_index = (state.head % self.capacity as u64) as usize;
        let mut ready = false;
        for index in 0..count as u64 {
            let seq = base + index;
            if seq < state.head || seq - state.head >= self.capacity as u64 {
                continue;
            }
            let slot_index = (seq % self.capacity as u64) as usize;
            let slot = &mut state.slots[slot_index];
            if slot.state == SlotState::Pending && slot.seq == seq {
                slot.state = SlotState::Skipped;
                if slot_index == head_index {
                    ready = true;
                }
            }
        }
        if ready {
            self.ready.store(true, Ordering::Release);
        }
    }

    /// Отдаёт готовые пакеты по порядку номеров.
    ///
    /// `emit` возвращает `false`, если получатель переполнен: разгрузка
    /// останавливается на текущем пакете, и его нужно повторить после сброса.
    pub(crate) fn drain<F: FnMut(&[u8]) -> bool>(&self, mut emit: F) -> DrainStats {
        let mut state = lock(&self.state);
        let mut stats = DrainStats::default();
        loop {
            if state.outstanding == 0 {
                break;
            }
            let index = (state.head % self.capacity as u64) as usize;
            let slot = state.slots[index];
            if slot.seq != state.head {
                break;
            }
            match slot.state {
                SlotState::Filled => {
                    let offset = index * self.slot_len;
                    if !emit(&state.buffers[offset..offset + slot.len]) {
                        stats.blocked = true;
                        break;
                    }
                    stats.delivered += 1;
                }
                SlotState::Skipped => stats.skipped += 1,
                SlotState::Pending | SlotState::Empty => break,
            }
            state.slots[index].state = SlotState::Empty;
            state.head += 1;
            state.outstanding -= 1;
        }
        self.ready.store(stats.blocked, Ordering::Release);
        stats
    }
}

/// Хеш FNV-1a: стабильный между запусками и независимый от порядка пиров.
pub(crate) fn peer_hash(bytes: &[u8; 32]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Привязывает пира к воркеру: `hash(public_key) % workers`.
pub(crate) fn peer_worker(public_key: &[u8; 32], workers: usize) -> usize {
    debug_assert!(workers > 0, "there is at least one worker");
    (peer_hash(public_key) % workers as u64) as usize
}

struct RingSetState {
    rings: HashMap<[u8; 32], Arc<ReorderRing>>,
    owned: Vec<Vec<Arc<ReorderRing>>>,
}

/// Набор упорядочивающих буферов устройства.
pub(crate) struct RingSet {
    state: RwLock<RingSetState>,
    capacity: usize,
    slot_len: usize,
    workers: usize,
    created: AtomicUsize,
}

impl RingSet {
    /// Создаёт набор под `workers` воркеров.
    pub(crate) fn new(capacity: usize, slot_len: usize, workers: usize) -> Self {
        debug_assert!(workers > 0, "there is at least one worker");
        Self {
            state: RwLock::new(RingSetState {
                rings: HashMap::new(),
                owned: (0..workers).map(|_| Vec::new()).collect(),
            }),
            capacity,
            slot_len,
            workers,
            created: AtomicUsize::new(0),
        }
    }

    /// Ёмкость одного буфера.
    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    /// Число буферов, созданных с момента запуска.
    #[cfg(test)]
    pub(crate) fn created(&self) -> usize {
        self.created.load(Ordering::Relaxed)
    }

    /// Возвращает буфер пира, создавая его при первом пакете.
    pub(crate) fn ring(&self, key: &[u8; 32]) -> Arc<ReorderRing> {
        if let Some(ring) = rw_read(&self.state).rings.get(key) {
            return Arc::clone(ring);
        }
        let owner = peer_worker(key, self.workers);
        let mut state = rw_write(&self.state);
        if let Some(ring) = state.rings.get(key) {
            return Arc::clone(ring);
        }
        let ring = Arc::new(ReorderRing::new(self.capacity, self.slot_len, owner));
        state.rings.insert(*key, Arc::clone(&ring));
        state.owned[owner].push(Arc::clone(&ring));
        self.created.fetch_add(1, Ordering::Relaxed);
        ring
    }

    /// Вызывает `visit` для каждого буфера воркера.
    pub(crate) fn for_each_owned<F: FnMut(&Arc<ReorderRing>)>(&self, worker: usize, mut visit: F) {
        let state = rw_read(&self.state);
        let Some(rings) = state.owned.get(worker) else {
            return;
        };
        for ring in rings {
            visit(ring);
        }
    }

    /// Возвращает `true`, если у воркера есть готовые к доставке пакеты.
    pub(crate) fn has_ready(&self, worker: usize) -> bool {
        let state = rw_read(&self.state);
        state
            .owned
            .get(worker)
            .is_some_and(|rings| rings.iter().any(|ring| ring.has_ready()))
    }

    /// Суммарная память всех созданных буферов в байтах.
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> usize {
        let state = rw_read(&self.state);
        state.rings.values().map(|ring| ring.bytes()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SLOT: usize = 64;

    fn ring(depth: usize) -> ReorderRing {
        ReorderRing::new(depth, SLOT, 0)
    }

    fn packet(marker: u8) -> Vec<u8> {
        vec![marker; SLOT]
    }

    fn drain_all(ring: &ReorderRing) -> Vec<u8> {
        let mut seen = Vec::new();
        let stats = ring.drain(|packet| {
            seen.push(packet[0]);
            true
        });
        assert_eq!(stats.delivered, seen.len());
        seen
    }

    #[test]
    fn in_order_fill_drains_in_order() {
        let ring = ring(8);
        let base = ring.claim(4).expect("claim fits");
        assert_eq!(base, 0);
        for index in 0..4u8 {
            assert_eq!(ring.fill(u64::from(index), &packet(index)), FillOutcome::Filled);
        }
        assert!(ring.has_ready());
        assert_eq!(drain_all(&ring), vec![0, 1, 2, 3]);
        assert_eq!(ring.outstanding(), 0);
        assert!(!ring.has_ready());
    }

    #[test]
    fn shuffled_completion_restores_wire_order() {
        let ring = ring(8);
        let base = ring.claim(8).expect("claim fits");
        assert_eq!(base, 0);
        for seq in [5u64, 2, 7, 0, 3, 1, 6, 4] {
            assert_eq!(
                ring.fill(seq, &packet(seq as u8)),
                FillOutcome::Filled,
                "seq {seq}"
            );
        }
        assert_eq!(drain_all(&ring), (0..8u8).collect::<Vec<_>>());
    }

    #[test]
    fn gap_holds_later_packets_until_it_is_filled() {
        let ring = ring(8);
        ring.claim(3).expect("claim fits");
        assert_eq!(ring.fill(0, &packet(0)), FillOutcome::Filled);
        assert_eq!(ring.fill(2, &packet(2)), FillOutcome::Filled);
        assert_eq!(drain_all(&ring), vec![0]);
        assert_eq!(ring.outstanding(), 2);
        assert_eq!(ring.fill(1, &packet(1)), FillOutcome::Filled);
        assert_eq!(drain_all(&ring), vec![1, 2]);
        assert_eq!(ring.outstanding(), 0);
    }

    #[test]
    fn skipped_number_does_not_stall_delivery() {
        let ring = ring(8);
        ring.claim(4).expect("claim fits");
        assert_eq!(ring.fill(0, &packet(0)), FillOutcome::Filled);
        ring.skip(1);
        assert_eq!(ring.fill(2, &packet(2)), FillOutcome::Filled);
        assert_eq!(ring.fill(3, &packet(3)), FillOutcome::Filled);
        let mut seen = Vec::new();
        let stats = ring.drain(|packet| {
            seen.push(packet[0]);
            true
        });
        assert_eq!(seen, vec![0, 2, 3]);
        assert_eq!(stats.skipped, 1);
        assert_eq!(stats.delivered, 3);
    }

    #[test]
    fn skip_range_advances_head() {
        let ring = ring(8);
        ring.claim(4).expect("claim fits");
        ring.skip_range(0, 3);
        assert_eq!(ring.fill(3, &packet(9)), FillOutcome::Filled);
        let mut seen = Vec::new();
        let stats = ring.drain(|packet| {
            seen.push(packet[0]);
            true
        });
        assert_eq!(seen, vec![9]);
        assert_eq!(stats.skipped, 3);
        assert_eq!(ring.outstanding(), 0);
    }

    #[test]
    fn claim_reports_backpressure_at_depth() {
        let ring = ring(4);
        assert_eq!(ring.claim(4), Some(0));
        assert_eq!(ring.claim(1), None);
        assert_eq!(ring.outstanding(), 4);
        ring.skip_range(0, 4);
        assert_eq!(ring.drain(|_| true).skipped, 4);
        assert_eq!(ring.claim(4), Some(4));
        assert_eq!(ring.outstanding(), 4);
    }

    #[test]
    fn claim_of_more_than_depth_is_rejected() {
        let ring = ring(4);
        assert_eq!(ring.claim(5), None);
        assert_eq!(ring.outstanding(), 0);
        assert_eq!(ring.claim(1), Some(0));
    }

    #[test]
    fn fill_before_claim_is_stale() {
        let ring = ring(4);
        assert_eq!(ring.fill(0, &packet(0)), FillOutcome::Stale);
        assert!(!ring.has_ready());
    }

    #[test]
    fn fill_after_delivery_is_stale() {
        let ring = ring(4);
        ring.claim(2).expect("claim fits");
        assert_eq!(ring.fill(0, &packet(0)), FillOutcome::Filled);
        ring.skip(1);
        assert_eq!(drain_all(&ring), vec![0]);
        assert_eq!(ring.fill(0, &packet(0)), FillOutcome::Stale);
        assert_eq!(ring.outstanding(), 0);
    }

    #[test]
    fn refilled_slot_is_overflow() {
        let ring = ring(4);
        ring.claim(2).expect("claim fits");
        assert_eq!(ring.fill(0, &packet(0)), FillOutcome::Filled);
        assert_eq!(ring.fill(0, &packet(1)), FillOutcome::Overflow);
        ring.skip(1);
        assert_eq!(drain_all(&ring), vec![0]);
        assert_eq!(ring.outstanding(), 0);
    }

    #[test]
    fn oversized_packet_is_stale_and_needs_skip() {
        let ring = ring(4);
        ring.claim(1).expect("claim fits");
        assert_eq!(ring.fill(0, &vec![0u8; SLOT + 1]), FillOutcome::Stale);
        assert_eq!(ring.outstanding(), 1);
        ring.skip(0);
        assert_eq!(ring.outstanding(), 1);
        let stats = ring.drain(|_| true);
        assert_eq!(stats.skipped, 1);
        assert_eq!(ring.outstanding(), 0);
    }

    #[test]
    fn blocked_emit_keeps_packet_for_retry() {
        let ring = ring(4);
        ring.claim(3).expect("claim fits");
        for seq in 0..3u64 {
            assert_eq!(ring.fill(seq, &packet(seq as u8)), FillOutcome::Filled);
        }
        let mut budget = 1;
        let stats = ring.drain(|_| {
            if budget == 0 {
                return false;
            }
            budget -= 1;
            true
        });
        assert_eq!(stats.delivered, 1);
        assert!(stats.blocked);
        assert!(ring.has_ready());
        assert_eq!(drain_all(&ring), vec![1, 2]);
        assert!(!ring.has_ready());
    }

    #[test]
    fn wrap_around_reuses_slots() {
        let ring = ring(4);
        for round in 0..100u64 {
            let base = ring.claim(1).expect("claim fits");
            assert_eq!(base, round);
            assert_eq!(ring.fill(base, &packet(round as u8)), FillOutcome::Filled);
            assert_eq!(drain_all(&ring), vec![round as u8]);
        }
        assert_eq!(ring.outstanding(), 0);
    }

    #[test]
    fn stale_fill_beyond_window_is_dropped() {
        let ring = ring(4);
        ring.claim(4).expect("claim fits");
        ring.skip_range(0, 4);
        drain_all(&ring);
        let base = ring.claim(4).expect("claim fits");
        assert_eq!(base, 4);
        assert_eq!(ring.fill(0, &packet(0)), FillOutcome::Stale);
        assert_eq!(ring.fill(4, &packet(4)), FillOutcome::Filled);
    }

    #[test]
    fn sixty_four_mib_is_delivered_without_loss() {
        const TOTAL: usize = 64 * 1024 * 1024;
        let packet_len = 1400usize;
        let total_packets = TOTAL / packet_len;
        let depth = MIN_DEPTH;
        let ring = ReorderRing::new(depth, packet_len, 0);

        let mut payload = vec![0u8; packet_len];
        let mut produced = 0u64;
        let mut expected = 0u64;
        let mut delivered = 0usize;

        while (produced as usize) < total_packets {
            let window = (total_packets - produced as usize).min(depth);
            let base = ring
                .claim(window)
                .unwrap_or_else(|| panic!("claim {window} at {produced}"));
            assert_eq!(base, produced);
            for offset in 0..window {
                let seq = base + offset as u64;
                payload[0] = seq as u8;
                payload[packet_len - 1] = (seq >> 8) as u8;
                assert_eq!(ring.fill(seq, &payload), FillOutcome::Filled);
            }
            produced += window as u64;
            let mut drained = 0usize;
            let stats = ring.drain(|packet| {
                assert_eq!(packet.len(), packet_len);
                assert_eq!(u64::from(packet[0]), expected & 0xff);
                assert_eq!(u64::from(packet[packet_len - 1]), (expected >> 8) & 0xff);
                expected += 1;
                drained += 1;
                true
            });
            assert_eq!(stats.delivered, drained);
            assert_eq!(stats.skipped, 0);
            delivered += drained * packet_len;
        }
        assert_eq!(expected, total_packets as u64);
        assert_eq!(delivered, TOTAL - TOTAL % packet_len);
        assert_eq!(ring.outstanding(), 0);
    }

    #[test]
    fn shuffled_batches_keep_order_and_lose_nothing() {
        let depth = 64usize;
        let ring = ReorderRing::new(depth, 8, 0);
        let total = 5_000u64;
        let mut expected = 0u64;
        let mut pending_base = 0u64;
        let mut payload = [0u8; 8];
        while expected < total {
            let window = (total - expected).min(32) as usize;
            let base = ring.claim(window).expect("claim fits");
            assert_eq!(base, pending_base);
            let mut seqs: Vec<u64> = (0..window as u64).map(|offset| base + offset).collect();
            seqs.rotate_left(window / 2);
            seqs.reverse();
            for seq in seqs {
                payload[0] = (seq % 251) as u8;
                assert_eq!(ring.fill(seq, &payload), FillOutcome::Filled);
            }
            pending_base += window as u64;
            ring.drain(|packet| {
                assert_eq!(packet[0] as u64, expected % 251);
                expected += 1;
                true
            });
        }
        assert_eq!(expected, total);
        assert_eq!(ring.outstanding(), 0);
    }

    #[test]
    fn concurrent_producers_keep_order() {
        let depth = 128usize;
        let ring = Arc::new(ReorderRing::new(depth, 8, 0));
        let total = 20_000u64;
        let producers: Vec<_> = (0..4)
            .map(|_| {
                let ring = Arc::clone(&ring);
                std::thread::spawn(move || {
                    let mut next = 0u64;
                    while next < total {
                        let mut window = (total - next).min(4) as usize;
                        let base = loop {
                            if let Some(base) = ring.claim(window) {
                                break base;
                            }
                            window = 1;
                            std::thread::yield_now();
                        };
                        for offset in 0..window {
                            let seq = base + offset as u64;
                            let mut packet = [0u8; 8];
                            packet[..8].copy_from_slice(&seq.to_le_bytes());
                            assert_eq!(ring.fill(seq, &packet), FillOutcome::Filled);
                        }
                        next += window as u64;
                    }
                })
            })
            .collect();
        let consumer = {
            let ring = Arc::clone(&ring);
            std::thread::spawn(move || {
                let mut expected = 0u64;
                while expected < total {
                    ring.drain(|packet| {
                        let mut bytes = [0u8; 8];
                        bytes.copy_from_slice(packet);
                        assert_eq!(u64::from_le_bytes(bytes), expected);
                        expected += 1;
                        true
                    });
                }
                expected
            })
        };
        for producer in producers {
            producer.join().unwrap();
        }
        assert_eq!(consumer.join().unwrap(), total);
        assert_eq!(ring.outstanding(), 0);
    }

    #[test]
    fn dropped_ring_with_pending_slots_is_safe() {
        let ring = ring(8);
        ring.claim(4).expect("claim fits");
        assert_eq!(ring.fill(0, &packet(0)), FillOutcome::Filled);
        assert_eq!(ring.fill(2, &packet(2)), FillOutcome::Filled);
        assert_eq!(drain_all(&ring), vec![0]);
        drop(ring);
    }

    #[test]
    fn peer_worker_is_stable_and_bounded() {
        for workers in 1..=8 {
            let mut key = [0u8; 32];
            key[0] = 7;
            let worker = peer_worker(&key, workers);
            assert!(worker < workers);
            for _ in 0..16 {
                assert_eq!(peer_worker(&key, workers), worker);
            }
        }
    }

    #[test]
    fn ring_set_shares_one_ring_per_peer() {
        let set = RingSet::new(16, 32, 2);
        let first = set.ring(&[1u8; 32]);
        let second = set.ring(&[1u8; 32]);
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(set.created(), 1);
        let other = set.ring(&[2u8; 32]);
        assert!(!Arc::ptr_eq(&first, &other));
        assert_eq!(set.created(), 2);
        assert_eq!(set.bytes(), 2 * 16 * 32);
    }

    #[test]
    fn ring_set_assigns_owner_by_key() {
        let set = RingSet::new(16, 32, 3);
        let mut owners = [0usize; 3];
        for seed in 0..32u8 {
            let mut key = [0u8; 32];
            key[0] = seed;
            let ring = set.ring(&key);
            assert_eq!(ring.owner(), peer_worker(&key, 3));
            owners[ring.owner()] += 1;
        }
        assert!(owners.iter().all(|count| *count > 0));
    }

    #[test]
    fn ring_set_visits_only_owned_rings() {
        let set = RingSet::new(16, 32, 4);
        let mut counts = [0usize; 4];
        for seed in 0..16u8 {
            let mut key = [0u8; 32];
            key[0] = seed;
            let ring = set.ring(&key);
            counts[ring.owner()] += 1;
        }
        for worker in 0..4 {
            let mut visited = 0;
            set.for_each_owned(worker, |_| visited += 1);
            assert_eq!(visited, counts[worker]);
        }
        let mut out_of_range = 0;
        set.for_each_owned(9, |_| out_of_range += 1);
        assert_eq!(out_of_range, 0);
        assert!(!set.has_ready(9));
    }

    #[test]
    fn capacity_must_be_power_of_two() {
        assert!(std::panic::catch_unwind(|| ReorderRing::new(100, 64, 0)).is_err());
        assert!(std::panic::catch_unwind(|| ReorderRing::new(1, 64, 0)).is_err());
    }
}
