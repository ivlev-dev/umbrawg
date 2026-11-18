use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};

use umbrawg_crypto::{Key, PublicKey};
use umbrawg_noise::{CookieGenerator, Handshake, HandshakeState, StaticIdentity};
use umbrawg_proto::messages::limits::{DEFAULT_UDP_WINDOW, MAX_STAGED_PACKETS};
use umbrawg_uapi::Cipher;

use crate::allowedips::{AllowedIp, PeerId};
use crate::buffer::Buffer;
use crate::error::{DeviceError, Result};
use crate::keypair::{Keypair, Keypairs, RemovedIndexes};
use crate::timers::Timers;

pub struct PeerConfig {
    pub public_key: PublicKey,
    pub preshared_key: Key,
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive: Option<u16>,
    pub allowed_ips: Vec<AllowedIp>,
    pub cipher: Cipher,
}

impl PeerConfig {
    #[must_use]
    pub fn new(public_key: PublicKey) -> Self {
        Self {
            public_key,
            preshared_key: Key::from_bytes([0u8; 32]),
            endpoint: None,
            persistent_keepalive: None,
            allowed_ips: Vec::new(),
            cipher: Cipher::ChaCha20Poly1305,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerState {
    Down,
    Handshake,
    Established,
    Expired,
}

impl PeerState {
    #[must_use]
    pub const fn is_established(self) -> bool {
        matches!(self, Self::Established)
    }
}

static TIMER_EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

const NO_DEADLINE: u64 = u64::MAX;

const ADVANCED_SECURITY_UNKNOWN: u8 = 0;
const ADVANCED_SECURITY_DISABLED: u8 = 1;
const ADVANCED_SECURITY_ENABLED: u8 = 2;

fn encode_deadline(deadline: Option<Instant>) -> u64 {
    match deadline {
        Some(instant) => instant.saturating_duration_since(*TIMER_EPOCH).as_nanos() as u64,
        None => NO_DEADLINE,
    }
}

fn decode_deadline(value: u64) -> Option<Instant> {
    (value != NO_DEADLINE).then(|| *TIMER_EPOCH + Duration::from_nanos(value))
}

pub(crate) struct PeerHandshake {
    pub noise: Option<Handshake>,
    pub last_sent: Option<Instant>,
    pub last_initiation_consumed: Option<Instant>,
}

pub(crate) struct StagedPacket {
    pub buffer: Buffer,
    pub len: usize,
}

pub(crate) struct StagedQueue {
    items: VecDeque<StagedPacket>,
    limit: usize,
}

impl StagedQueue {
    fn new(limit: usize) -> Self {
        Self {
            items: VecDeque::with_capacity(limit),
            limit,
        }
    }

    fn push_back(&mut self, packet: StagedPacket) -> Result<()> {
        if self.items.len() >= self.limit {
            return Err(DeviceError::StagingFull);
        }
        self.items.push_back(packet);
        Ok(())
    }

    fn push_front(&mut self, packet: StagedPacket) {
        if self.items.len() < self.limit {
            self.items.push_front(packet);
        }
    }

    fn pop_front(&mut self) -> Option<StagedPacket> {
        self.items.pop_front()
    }

    fn clear(&mut self) {
        self.items.clear();
    }

    fn len(&self) -> usize {
        self.items.len()
    }
}

pub struct Peer {
    id: PeerId,
    public_key: PublicKey,
    preshared_key: RwLock<Key>,
    running: AtomicBool,
    disable_roaming: AtomicBool,
    endpoint: RwLock<Option<SocketAddr>>,
    udp_window: AtomicU32,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    last_handshake_ns: AtomicU64,
    persistent_keepalive: AtomicU32,
    advanced_security: AtomicU8,
    cipher: AtomicU8,
    special_counter: AtomicU32,
    pub(crate) handshake: Mutex<PeerHandshake>,
    pub(crate) keypairs: RwLock<Keypairs>,
    pub(crate) cookie_generator: Mutex<CookieGenerator>,
    pub(crate) timers: Mutex<Timers>,
    next_deadline: AtomicU64,
    pub(crate) staged: Mutex<StagedQueue>,
}

impl Peer {
    pub(crate) fn new(id: PeerId, config: PeerConfig, identity: Option<&StaticIdentity>) -> Self {
        let public_key = config.public_key;
        let preshared_key = config.preshared_key.clone();
        let noise =
            identity.map(|identity| Handshake::new(identity, public_key, preshared_key.clone()));
        let persistent_keepalive = config
            .persistent_keepalive
            .filter(|value| *value != 0)
            .map_or(0, |value| (u32::from(value) << 16) | u32::from(value));
        let cipher = config.cipher.as_u32() as u8;
        Self {
            id,
            public_key,
            preshared_key: RwLock::new(preshared_key),
            running: AtomicBool::new(true),
            disable_roaming: AtomicBool::new(false),
            endpoint: RwLock::new(config.endpoint),
            udp_window: AtomicU32::new(DEFAULT_UDP_WINDOW),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            last_handshake_ns: AtomicU64::new(0),
            persistent_keepalive: AtomicU32::new(persistent_keepalive),
            advanced_security: AtomicU8::new(ADVANCED_SECURITY_UNKNOWN),
            cipher: AtomicU8::new(cipher),
            special_counter: AtomicU32::new(0),
            handshake: Mutex::new(PeerHandshake {
                noise,
                last_sent: None,
                last_initiation_consumed: None,
            }),
            keypairs: RwLock::new(Keypairs::new()),
            cookie_generator: Mutex::new(CookieGenerator::new(public_key)),
            timers: Mutex::new(Timers::new()),
            next_deadline: AtomicU64::new(NO_DEADLINE),
            staged: Mutex::new(StagedQueue::new(MAX_STAGED_PACKETS)),
        }
    }

    #[must_use]
    pub const fn id(&self) -> PeerId {
        self.id
    }

    #[must_use]
    pub const fn public_key(&self) -> PublicKey {
        self.public_key
    }

    #[must_use]
    pub fn preshared_key(&self) -> Key {
        self.preshared_key.read().clone()
    }

    pub fn set_preshared_key(&self, key: Key) {
        *self.preshared_key.write() = key;
    }

    #[must_use]
    pub fn running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn endpoint(&self) -> Option<SocketAddr> {
        *self.endpoint.read()
    }

    pub fn set_endpoint(&self, endpoint: Option<SocketAddr>) {
        *self.endpoint.write() = endpoint;
        self.udp_window.store(DEFAULT_UDP_WINDOW, Ordering::Relaxed);
    }

    pub fn set_endpoint_from_packet(&self, endpoint: SocketAddr) -> bool {
        if self.disable_roaming.load(Ordering::Relaxed) {
            return false;
        }
        if *self.endpoint.read() == Some(endpoint) {
            return false;
        }
        let mut current = self.endpoint.write();
        if *current == Some(endpoint) {
            return false;
        }
        *current = Some(endpoint);
        self.udp_window.store(DEFAULT_UDP_WINDOW, Ordering::Relaxed);
        true
    }

    pub(crate) fn with_timers<R>(&self, update: impl FnOnce(&mut Timers) -> R) -> R {
        let mut timers = self.timers.lock();
        let result = update(&mut timers);
        self.next_deadline
            .store(encode_deadline(timers.next_deadline()), Ordering::Relaxed);
        result
    }

    #[must_use]
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        decode_deadline(self.next_deadline.load(Ordering::Relaxed))
    }

    #[must_use]
    pub(crate) fn promote_keypair(&self, keypair: &Arc<Keypair>) -> Option<RemovedIndexes> {
        if !self.keypairs.read().is_next(keypair) {
            return None;
        }
        self.keypairs.write().received_with(keypair)
    }

    #[must_use]
    pub fn roaming_disabled(&self) -> bool {
        self.disable_roaming.load(Ordering::Relaxed)
    }

    pub fn set_roaming_disabled(&self, disabled: bool) {
        self.disable_roaming.store(disabled, Ordering::Relaxed);
    }

    #[must_use]
    pub fn udp_window(&self) -> u32 {
        self.udp_window.load(Ordering::Relaxed)
    }

    pub fn observe_udp_window(&self, window: u32) {
        self.udp_window.fetch_max(window, Ordering::Relaxed);
    }

    #[must_use]
    pub fn tx_bytes(&self) -> u64 {
        self.tx_bytes.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn rx_bytes(&self) -> u64 {
        self.rx_bytes.load(Ordering::Relaxed)
    }

    pub fn add_tx(&self, bytes: u64) {
        self.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_rx(&self, bytes: u64) {
        self.rx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    #[must_use]
    pub fn last_handshake_unix_nanos(&self) -> u64 {
        self.last_handshake_ns.load(Ordering::Relaxed)
    }

    pub fn mark_handshake_complete(&self, now: SystemTime) {
        let nanos = now
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        self.last_handshake_ns.store(nanos, Ordering::Relaxed);
    }

    #[must_use]
    pub fn special_counter(&self) -> u32 {
        self.special_counter.fetch_add(1, Ordering::Relaxed)
    }

    #[must_use]
    pub fn persistent_keepalive_range(&self) -> Option<(u16, u16)> {
        let packed = self.persistent_keepalive.load(Ordering::Relaxed);
        if packed == 0 {
            return None;
        }
        let lo = (packed >> 16) as u16;
        let hi = (packed & 0xffff) as u16;
        Some((lo.min(hi), lo.max(hi)))
    }

    pub fn set_persistent_keepalive_range(&self, range: Option<(u16, u16)>) {
        let packed = match range {
            Some((lo, hi)) if hi != 0 || lo != 0 => {
                let lo = lo.min(hi);
                let hi = lo.max(hi);
                (u32::from(lo) << 16) | u32::from(hi)
            }
            _ => 0,
        };
        self.persistent_keepalive.store(packed, Ordering::Relaxed);
    }

    /// Returns the reported advanced-security flag.
    ///
    /// `None` means the flag was never configured. The userspace daemon stores
    /// the value for UAPI compatibility but does not enforce advanced security.
    #[must_use]
    pub fn advanced_security(&self) -> Option<bool> {
        match self.advanced_security.load(Ordering::Relaxed) {
            ADVANCED_SECURITY_ENABLED => Some(true),
            ADVANCED_SECURITY_DISABLED => Some(false),
            _ => None,
        }
    }

    /// Stores the reported advanced-security flag without enforcing it.
    pub fn set_advanced_security(&self, value: Option<bool>) {
        let encoded = match value {
            Some(true) => ADVANCED_SECURITY_ENABLED,
            Some(false) => ADVANCED_SECURITY_DISABLED,
            None => ADVANCED_SECURITY_UNKNOWN,
        };
        self.advanced_security.store(encoded, Ordering::Relaxed);
    }

    /// Returns the data cipher configured for the peer.
    #[must_use]
    pub fn cipher(&self) -> Cipher {
        Cipher::from_u32(u32::from(self.cipher.load(Ordering::Relaxed))).unwrap_or_default()
    }

    /// Stores the data cipher of the peer.
    ///
    /// The transport keypair layer reads this value when it selects the AEAD
    /// algorithm; until then the setting only round-trips through the UAPI.
    pub fn set_cipher(&self, cipher: Cipher) {
        self.cipher.store(cipher.as_u32() as u8, Ordering::Relaxed);
    }

    #[must_use]
    pub fn state(&self, now: Instant, keychain_expire: Duration) -> PeerState {
        if !self.running() {
            return PeerState::Down;
        }
        {
            let keypairs = self.keypairs.read();
            if let Some(current) = keypairs.current() {
                if current.is_expired(now, keychain_expire) {
                    return PeerState::Expired;
                }
                return PeerState::Established;
            }
        }
        let handshake = self.handshake.lock();
        match handshake.noise.as_ref().map(Handshake::state) {
            Some(HandshakeState::Zeroed) | None => PeerState::Down,
            Some(_) => PeerState::Handshake,
        }
    }

    pub fn stage(&self, buffer: Buffer, len: usize) -> Result<()> {
        self.staged.lock().push_back(StagedPacket { buffer, len })
    }

    pub(crate) fn take_staged(&self) -> Option<StagedPacket> {
        self.staged.lock().pop_front()
    }

    pub(crate) fn requeue_staged(&self, packet: StagedPacket) {
        self.staged.lock().push_front(packet);
    }

    pub fn staged_len(&self) -> usize {
        self.staged.lock().len()
    }

    pub fn flush_staged_drop(&self) {
        self.staged.lock().clear();
    }

    pub(crate) fn rebuild_handshake(&self, identity: Option<&StaticIdentity>) -> RemovedIndexes {
        let psk = self.preshared_key.read().clone();
        let mut handshake = self.handshake.lock();
        let mut removed = RemovedIndexes::new();
        if let Some(noise) = handshake.noise.as_ref() {
            removed.push(noise.local_index());
        }
        handshake.noise = identity.map(|identity| Handshake::new(identity, self.public_key, psk));
        handshake.last_sent = None;
        handshake.last_initiation_consumed = None;
        removed
    }

    pub(crate) fn clear_session(&self) -> RemovedIndexes {
        let mut removed = RemovedIndexes::new();
        {
            let mut handshake = self.handshake.lock();
            if let Some(noise) = handshake.noise.as_ref() {
                removed.push(noise.local_index());
            }
            if let Some(noise) = handshake.noise.as_mut() {
                noise.clear();
            }
            handshake.last_sent = None;
        }
        {
            let mut keypairs = self.keypairs.write();
            let keys = keypairs.zero();
            removed.extend(&keys);
        }
        removed
    }

    pub(crate) fn zero_and_flush(&self) -> RemovedIndexes {
        let removed = self.clear_session();
        self.flush_staged_drop();
        self.with_timers(Timers::reset);
        removed
    }

    pub(crate) fn stop(&self) -> RemovedIndexes {
        self.running.store(false, Ordering::Release);
        self.zero_and_flush()
    }

    #[must_use]
    pub fn current_keypair(&self) -> Option<Arc<Keypair>> {
        self.keypairs.read().current().cloned()
    }
}

impl core::fmt::Debug for Peer {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Peer")
            .field("id", &self.id)
            .field("public_key", &self.public_key)
            .field("running", &self.running())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allowedips::PeerId;
    use crate::timers::TimerKind;

    fn peer() -> Peer {
        Peer::new(
            PeerId::new_unchecked(1),
            PeerConfig::new(PublicKey::from_bytes([7u8; 32])),
            None,
        )
    }

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
    fn next_deadline_follows_timer_updates() {
        let peer = peer();
        assert_eq!(peer.next_deadline(), None);
        let deadline = Instant::now() + Duration::from_secs(5);
        peer.with_timers(|timers| timers.arm(TimerKind::SendKeepalive, deadline));
        assert_eq!(peer.next_deadline(), Some(deadline));
        let later = deadline + Duration::from_secs(5);
        peer.with_timers(|timers| timers.arm(TimerKind::NewHandshake, later));
        assert_eq!(peer.next_deadline(), Some(deadline));
        peer.with_timers(|timers| timers.disarm(TimerKind::SendKeepalive));
        assert_eq!(peer.next_deadline(), Some(later));
        peer.with_timers(Timers::reset);
        assert_eq!(peer.next_deadline(), None);
    }

    #[test]
    fn promote_keypair_only_accepts_the_next_keypair() {
        let peer = peer();
        let unknown = keypair(1, true);
        assert!(peer.promote_keypair(&unknown).is_none());
        assert!(peer.current_keypair().is_none());

        let next = keypair(2, false);
        peer.keypairs.write().install(Arc::clone(&next), false);
        assert!(peer.current_keypair().is_none());
        assert!(peer.promote_keypair(&unknown).is_none());
        assert!(peer.current_keypair().is_none());
        assert!(peer.promote_keypair(&next).is_some());
        assert!(peer
            .current_keypair()
            .is_some_and(|pair| Arc::ptr_eq(&pair, &next)));
        assert!(peer.promote_keypair(&next).is_none());
    }

    #[test]
    fn advanced_security_is_stored_without_enforcement() {
        let peer = peer();
        assert_eq!(peer.advanced_security(), None);
        peer.set_advanced_security(Some(true));
        assert_eq!(peer.advanced_security(), Some(true));
        peer.set_advanced_security(Some(false));
        assert_eq!(peer.advanced_security(), Some(false));
        peer.set_advanced_security(None);
        assert_eq!(peer.advanced_security(), None);
    }

    #[test]
    fn cipher_defaults_to_chacha_and_is_stored() {
        let peer = peer();
        assert_eq!(peer.cipher(), Cipher::ChaCha20Poly1305);
        peer.set_cipher(Cipher::Aes256Gcm);
        assert_eq!(peer.cipher(), Cipher::Aes256Gcm);
        peer.set_cipher(Cipher::ChaCha20Poly1305);
        assert_eq!(peer.cipher(), Cipher::ChaCha20Poly1305);
    }

    #[test]
    fn peer_uses_configured_cipher() {
        let mut config = PeerConfig::new(PublicKey::from_bytes([8u8; 32]));
        config.cipher = Cipher::Aes256Gcm;
        let peer = Peer::new(PeerId::new_unchecked(2), config, None);
        assert_eq!(peer.cipher(), Cipher::Aes256Gcm);
    }

    #[test]
    fn endpoint_updates_only_on_change() {
        let peer = peer();
        let first: SocketAddr = "10.0.0.1:51820".parse().unwrap();
        let second: SocketAddr = "10.0.0.2:51820".parse().unwrap();
        assert!(peer.set_endpoint_from_packet(first));
        assert_eq!(peer.endpoint(), Some(first));
        assert!(!peer.set_endpoint_from_packet(first));
        peer.observe_udp_window(9000);
        assert!(!peer.set_endpoint_from_packet(first));
        assert_eq!(peer.udp_window(), 9000);
        assert!(peer.set_endpoint_from_packet(second));
        assert_eq!(peer.udp_window(), DEFAULT_UDP_WINDOW);
        peer.set_roaming_disabled(true);
        assert!(!peer.set_endpoint_from_packet(first));
        assert_eq!(peer.endpoint(), Some(second));
    }
}
