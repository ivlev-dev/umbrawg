use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use umbrawg_crypto::aead::Aead;
use umbrawg_noise::Keypair as NoiseKeypair;
use umbrawg_proto::messages::limits::{REJECT_AFTER_MESSAGES, REKEY_AFTER_MESSAGES};

use crate::replay::AtomicReplayFilter;

pub struct Keypair {
    created: Instant,
    local_index: u32,
    remote_index: u32,
    is_initiator: bool,
    send: Aead,
    receive: Aead,
    send_nonce: AtomicU64,
    replay: AtomicReplayFilter,
}

impl Keypair {
    #[must_use]
    pub fn from_noise(keys: &NoiseKeypair, created: Instant) -> Self {
        Self {
            created,
            local_index: keys.local_index(),
            remote_index: keys.remote_index(),
            is_initiator: keys.is_initiator(),
            send: Aead::new(keys.send_key()),
            receive: Aead::new(keys.receive_key()),
            send_nonce: AtomicU64::new(0),
            replay: AtomicReplayFilter::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_keys(
        created: Instant,
        local_index: u32,
        remote_index: u32,
        is_initiator: bool,
        send: &umbrawg_crypto::Key,
        receive: &umbrawg_crypto::Key,
    ) -> Self {
        Self {
            created,
            local_index,
            remote_index,
            is_initiator,
            send: Aead::new(send),
            receive: Aead::new(receive),
            send_nonce: AtomicU64::new(0),
            replay: AtomicReplayFilter::new(),
        }
    }

    #[must_use]
    pub const fn created(&self) -> Instant {
        self.created
    }

    #[must_use]
    pub const fn local_index(&self) -> u32 {
        self.local_index
    }

    #[must_use]
    pub const fn remote_index(&self) -> u32 {
        self.remote_index
    }

    #[must_use]
    pub const fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    #[must_use]
    pub fn age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.created)
    }

    #[must_use]
    pub fn is_expired(&self, now: Instant, lifetime: Duration) -> bool {
        self.age(now) >= lifetime
    }

    #[must_use]
    pub fn send_nonce(&self) -> u64 {
        self.send_nonce.load(Ordering::Relaxed)
    }

    pub fn next_send_nonce(&self) -> Option<u64> {
        let nonce = self.send_nonce.fetch_add(1, Ordering::Relaxed);
        if nonce >= REJECT_AFTER_MESSAGES {
            None
        } else {
            Some(nonce)
        }
    }

    #[must_use]
    pub fn needs_rekey(&self) -> bool {
        self.send_nonce() > REKEY_AFTER_MESSAGES
    }

    pub fn seal(&self, counter: u64, plaintext: &[u8], dst: &mut [u8]) -> Option<usize> {
        self.send.seal_into(counter, &[], plaintext, dst).ok()
    }

    pub fn seal_in_place(&self, counter: u64, buffer: &mut [u8]) -> Option<()> {
        self.send.seal_in_place(counter, &[], buffer).ok()
    }

    pub fn open<'a>(&self, counter: u64, buffer: &'a mut [u8]) -> Option<&'a mut [u8]> {
        self.receive.open_in_place(counter, &[], buffer).ok()
    }

    pub fn validate_replay(&self, counter: u64) -> bool {
        self.replay.validate(counter, REJECT_AFTER_MESSAGES)
    }

    pub fn exhaust(&self) {
        self.send_nonce
            .store(REJECT_AFTER_MESSAGES, Ordering::Relaxed);
    }
}

impl core::fmt::Debug for Keypair {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Keypair")
            .field("local_index", &self.local_index)
            .field("remote_index", &self.remote_index)
            .field("is_initiator", &self.is_initiator)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RemovedIndexes {
    items: [u32; 4],
    len: u8,
}

impl RemovedIndexes {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            items: [0; 4],
            len: 0,
        }
    }

    pub fn push(&mut self, index: u32) {
        if index != 0 && usize::from(self.len) < self.items.len() {
            self.items[usize::from(self.len)] = index;
            self.len += 1;
        }
    }

    pub fn extend(&mut self, other: &Self) {
        for index in other.iter() {
            self.push(index);
        }
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u32] {
        &self.items[..usize::from(self.len)]
    }

    pub fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.as_slice().iter().copied()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for RemovedIndexes {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Default)]
pub struct Keypairs {
    current: Option<Arc<Keypair>>,
    previous: Option<Arc<Keypair>>,
    next: Option<Arc<Keypair>>,
}

impl Keypairs {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn current(&self) -> Option<&Arc<Keypair>> {
        self.current.as_ref()
    }

    #[must_use]
    pub fn previous(&self) -> Option<&Arc<Keypair>> {
        self.previous.as_ref()
    }

    #[must_use]
    pub fn next(&self) -> Option<&Arc<Keypair>> {
        self.next.as_ref()
    }

    pub fn install(&mut self, keypair: Arc<Keypair>, is_initiator: bool) -> RemovedIndexes {
        let mut removed = RemovedIndexes::new();
        if is_initiator {
            let old_previous = self.previous.take();
            if let Some(next) = self.next.take() {
                removed.push(next.local_index());
                self.previous = Some(next);
            } else if let Some(current) = self.current.take() {
                self.previous = Some(current);
            }
            if let Some(previous) = old_previous {
                removed.push(previous.local_index());
            }
            self.current = Some(keypair);
        } else {
            if let Some(next) = self.next.take() {
                removed.push(next.local_index());
            }
            if let Some(previous) = self.previous.take() {
                removed.push(previous.local_index());
            }
            self.next = Some(keypair);
        }
        removed
    }

    #[must_use]
    pub fn is_next(&self, keypair: &Arc<Keypair>) -> bool {
        self.next
            .as_ref()
            .is_some_and(|next| Arc::ptr_eq(next, keypair))
    }

    pub fn received_with(&mut self, keypair: &Arc<Keypair>) -> Option<RemovedIndexes> {
        if !self.is_next(keypair) {
            return None;
        }
        let mut removed = RemovedIndexes::new();
        if let Some(previous) = self.previous.take() {
            removed.push(previous.local_index());
        }
        self.previous = self.current.take();
        self.current = self.next.take();
        Some(removed)
    }

    pub fn zero(&mut self) -> RemovedIndexes {
        let mut removed = RemovedIndexes::new();
        for keypair in [self.current.take(), self.previous.take(), self.next.take()]
            .into_iter()
            .flatten()
        {
            removed.push(keypair.local_index());
        }
        removed
    }

    pub fn exhaust(&self) {
        for keypair in [&self.current, &self.previous, &self.next]
            .into_iter()
            .flatten()
        {
            keypair.exhaust();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umbrawg_crypto::aead;
    use umbrawg_crypto::Key;

    fn keypair(local: u32, initiator: bool) -> Arc<Keypair> {
        Arc::new(Keypair::from_keys(
            Instant::now(),
            local,
            0,
            initiator,
            &Key::from_bytes([local as u8; 32]),
            &Key::from_bytes([local as u8 ^ 0xff; 32]),
        ))
    }

    #[test]
    fn initiator_rotates_previous_and_current() {
        let mut keypairs = Keypairs::new();
        let first = keypair(1, true);
        assert!(keypairs.install(Arc::clone(&first), true).is_empty());
        assert!(Arc::ptr_eq(keypairs.current().unwrap(), &first));

        let second = keypair(2, true);
        let removed = keypairs.install(Arc::clone(&second), true);
        assert_eq!(removed.as_slice(), &[]);
        assert!(Arc::ptr_eq(keypairs.current().unwrap(), &second));
        assert!(Arc::ptr_eq(keypairs.previous().unwrap(), &first));
    }

    #[test]
    fn initiator_replaces_previous_and_drops_old_current() {
        let mut keypairs = Keypairs::new();
        let first = keypair(1, true);
        let second = keypair(2, true);
        keypairs.install(Arc::clone(&first), true);
        keypairs.install(Arc::clone(&second), true);

        let third = keypair(3, true);
        let removed = keypairs.install(Arc::clone(&third), true);
        assert_eq!(removed.as_slice(), &[1]);
        assert!(Arc::ptr_eq(keypairs.current().unwrap(), &third));
        assert!(Arc::ptr_eq(keypairs.previous().unwrap(), &second));
    }

    #[test]
    fn responder_installs_next_and_keeps_current() {
        let mut keypairs = Keypairs::new();
        let current = keypair(1, true);
        keypairs.install(Arc::clone(&current), true);

        let next = keypair(2, false);
        let removed = keypairs.install(Arc::clone(&next), false);
        assert!(removed.is_empty());
        assert!(Arc::ptr_eq(keypairs.current().unwrap(), &current));
        assert!(Arc::ptr_eq(keypairs.next().unwrap(), &next));

        let promoted = keypairs.received_with(&next).unwrap();
        assert_eq!(promoted.as_slice(), &[]);
        assert!(Arc::ptr_eq(keypairs.current().unwrap(), &next));
        assert!(Arc::ptr_eq(keypairs.previous().unwrap(), &current));
        assert!(keypairs.next().is_none());
    }

    #[test]
    fn received_with_ignores_unknown_keypairs() {
        let mut keypairs = Keypairs::new();
        let next = keypair(2, false);
        keypairs.install(Arc::clone(&next), false);
        assert!(keypairs.received_with(&keypair(9, false)).is_none());
    }

    #[test]
    fn zero_returns_every_index() {
        let mut keypairs = Keypairs::new();
        keypairs.install(keypair(1, true), true);
        keypairs.install(keypair(2, false), false);
        let removed = keypairs.zero();
        let mut indexes = removed.as_slice().to_vec();
        indexes.sort_unstable();
        assert_eq!(indexes, vec![1, 2]);
        assert!(keypairs.current().is_none());
        assert!(keypairs.previous().is_none());
        assert!(keypairs.next().is_none());
    }

    #[test]
    fn nonce_limit_is_enforced() {
        let keypair = keypair(1, true);
        assert_eq!(keypair.send_nonce(), 0);
        assert_eq!(keypair.next_send_nonce(), Some(0));
        assert_eq!(keypair.next_send_nonce(), Some(1));
        keypair.exhaust();
        assert!(keypair.next_send_nonce().is_none());
    }

    #[test]
    fn aead_round_trip_and_replay() {
        let now = Instant::now();
        let send_key = Key::from_bytes([0x11; 32]);
        let receive_key = Key::from_bytes([0x22; 32]);
        let sender = Keypair::from_keys(now, 1, 2, true, &send_key, &receive_key);
        let receiver = Keypair::from_keys(now, 2, 1, false, &receive_key, &send_key);
        let mut sealed = [0u8; 32 + aead::TAG_LEN];
        let length = sender.seal(0, b"payload", &mut sealed).unwrap();
        let mut opened = sealed;
        let plaintext = receiver.open(0, &mut opened[..length]).unwrap();
        assert_eq!(plaintext, b"payload");
        assert!(receiver.validate_replay(0));
        assert!(!receiver.validate_replay(0));
    }
}
