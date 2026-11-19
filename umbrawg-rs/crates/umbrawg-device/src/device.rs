use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use arc_swap::ArcSwap;
use parking_lot::{Mutex, RwLock};
use rand_core::{OsRng, RngCore};

use umbrawg_crypto::tai64n::Tai64N;
use umbrawg_crypto::{aead, Key, PrivateKey, PublicKey};
use umbrawg_noise::{CookieChecker, StaticIdentity};
use umbrawg_proto::messages::limits::{
    DEFAULT_UDP_WINDOW, INITIATIONS_PER_SECOND, MAX_PEERS_PER_DEVICE,
};
use umbrawg_proto::messages::{
    COOKIE_REPLY_SIZE, INITIATION_SIZE, MAX_PACKET_SIZE, MESSAGE_HANDSHAKE_COOKIE,
    MESSAGE_HANDSHAKE_INITIATION, MESSAGE_HANDSHAKE_RESPONSE, MESSAGE_MINIMUM_LENGTH,
    RESPONSE_SIZE, TRANSPORT_HEADER_SIZE,
};
use umbrawg_proto::obf::{DetectedPacket, MessageKind, Obfuscator};
use umbrawg_proto::{CookieReply, HandshakeInitiation, HandshakeResponse, ObfParams};

use crate::allowedips::PeerId;
use crate::buffer::{BufferPool, DEFAULT_BUFFER_SIZE};
use crate::error::{DeviceError, Result};
use crate::gso::BatchLayout;
use crate::index::IndexTable;
use crate::io::{
    DatagramSink, IncomingDropCounters, IncomingMeta, IncomingOutcome, IoContext, PacketIo,
};
use crate::keypair::Keypair;
use crate::obf::{build_fixed_message, endpoint_bytes, send_pre_handshake, unix_time_seconds};
use crate::peer::{Peer, PeerConfig, PeerState};
use crate::ratelimiter::RateLimiter;
use crate::timers::{Range16, TimerKind, Timings};
use crate::underload::{UnderLoadDetector, DEFAULT_UNDER_LOAD_PPS};
use crate::{DEFAULT_EXTRA_PORTS, MAX_EXTRA_PORTS};

const TRANSPORT_FLOOD_INTERVAL: Duration = Duration::from_millis(1000 / INITIATIONS_PER_SECOND);

/// Настройки обфускации и таймеров, снятые один раз на батч приёма.
#[derive(Clone)]
pub struct IncomingSnapshot {
    params: Arc<ObfParams>,
    timings: Timings,
}

/// Транспортный сегмент, разобранный до расшифровки.
///
/// Содержит результаты классификации сообщения и поиска сессии, но не
/// расшифрованные данные: `keypair.open` и проверка повтора выполняются позже,
/// возможно, в другом потоке.
#[derive(Clone)]
pub struct PreparedTransport {
    peer: Arc<Peer>,
    keypair: Arc<Keypair>,
    padding: usize,
    header_end: usize,
}

impl PreparedTransport {
    /// Возвращает пира, которому принадлежит сегмент.
    #[must_use]
    pub fn peer(&self) -> &Peer {
        &self.peer
    }

    /// Возвращает публичный ключ пира — стабильный идентификатор для раскладки по потокам.
    #[must_use]
    pub fn peer_public_key(&self) -> PublicKey {
        self.peer.public_key()
    }
}

/// Результат подготовки входящего сегмента к обработке.
#[derive(Clone)]
pub enum PreparedIncoming {
    /// Транспортный пакет с известной сессией.
    Transport(PreparedTransport),
    /// Управляющий пакет (рукопожатие, cookie).
    Control(DetectedPacket),
    /// Пакет отброшен на этапе классификации.
    Dropped,
}

pub struct DeviceConfig {
    pub private_key: Option<Key>,
    pub listen_port: u16,
    pub fwmark: u32,
    pub extra_ports: u8,
    pub mtu: u16,
    pub obfuscation: ObfParams,
    pub timings: Timings,
    pub staged_pool_capacity: usize,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            private_key: None,
            listen_port: 0,
            fwmark: 0,
            extra_ports: DEFAULT_EXTRA_PORTS,
            mtu: 1420,
            obfuscation: ObfParams::default(),
            timings: Timings::new(),
            staged_pool_capacity: 128,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimerEvent {
    pub peer: PeerId,
    pub kind: TimerKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendOutcome {
    Sent(usize),
    Staged,
}

/// Результат батч-шифрования и отправки.
#[derive(Clone, Debug)]
pub struct SentBatch {
    /// Раскладка зашифрованных датаграмм в буфере назначения.
    pub layout: BatchLayout,
    /// Сколько пакетов ушло в очередь staged из-за отсутствия ключа.
    pub staged: usize,
    /// Сколько пакетов зашифровано.
    pub sent: usize,
    /// Нужно ли инициировать рукопожатие после отправки управления.
    pub needs_handshake: bool,
    /// Адрес пира, если он известен.
    pub endpoint: Option<SocketAddr>,
}

pub struct Device {
    private_key: RwLock<Option<Key>>,
    identity: RwLock<Option<StaticIdentity>>,
    cookie_checker: RwLock<Option<CookieChecker>>,
    peers: ArcSwap<HashMap<[u8; 32], Arc<Peer>>>,
    peers_by_id: ArcSwap<HashMap<u32, Arc<Peer>>>,
    peers_update: Mutex<()>,
    allowed_ips: crate::allowedips::AllowedIps,
    obfuscation: ArcSwap<ObfParams>,
    timings: RwLock<Timings>,
    index: IndexTable,
    rate_limiter: RateLimiter,
    up: AtomicBool,
    under_load: AtomicBool,
    under_load_detection: AtomicBool,
    under_load_detector: UnderLoadDetector,
    listen_port: AtomicU16,
    fwmark: AtomicU32,
    extra_ports: AtomicU8,
    mtu: AtomicU16,
    next_peer_id: AtomicU32,
    staging_pool: Arc<BufferPool>,
    incoming_drops: IncomingDropCounters,
}

impl Device {
    pub fn new(config: DeviceConfig) -> Result<Self> {
        config.obfuscation.validate()?;
        if !config.timings.validate() {
            return Err(DeviceError::InvalidParameter("timings"));
        }
        let private_key = config
            .private_key
            .filter(|key| !key.is_zero())
            .map(normalize_private_key);
        let identity = private_key
            .as_ref()
            .map(|key| StaticIdentity::from_bytes(key.to_bytes()));
        let cookie_checker = identity
            .as_ref()
            .map(|identity| CookieChecker::new(identity, &mut OsRng, Instant::now()));
        Ok(Self {
            private_key: RwLock::new(private_key),
            identity: RwLock::new(identity),
            cookie_checker: RwLock::new(cookie_checker),
            peers: ArcSwap::from_pointee(HashMap::new()),
            peers_by_id: ArcSwap::from_pointee(HashMap::new()),
            peers_update: Mutex::new(()),
            allowed_ips: crate::allowedips::AllowedIps::new(),
            obfuscation: ArcSwap::from_pointee(config.obfuscation),
            timings: RwLock::new(config.timings),
            index: IndexTable::new(),
            rate_limiter: RateLimiter::new(),
            up: AtomicBool::new(true),
            under_load: AtomicBool::new(false),
            under_load_detection: AtomicBool::new(true),
            under_load_detector: UnderLoadDetector::new(DEFAULT_UNDER_LOAD_PPS),
            listen_port: AtomicU16::new(config.listen_port),
            fwmark: AtomicU32::new(config.fwmark),
            extra_ports: AtomicU8::new(config.extra_ports.min(MAX_EXTRA_PORTS)),
            mtu: AtomicU16::new(config.mtu),
            next_peer_id: AtomicU32::new(1),
            staging_pool: Arc::new(BufferPool::new(
                config.staged_pool_capacity,
                DEFAULT_BUFFER_SIZE,
            )),
            incoming_drops: IncomingDropCounters::default(),
        })
    }

    #[must_use]
    pub fn private_key(&self) -> Option<Key> {
        self.private_key.read().clone()
    }

    #[must_use]
    pub fn public_key(&self) -> Option<PublicKey> {
        self.identity
            .read()
            .as_ref()
            .map(StaticIdentity::public_key)
    }

    pub fn set_private_key(&self, key: Option<Key>) -> Result<()> {
        let key = key
            .filter(|value| !value.is_zero())
            .map(normalize_private_key);
        let identity = key
            .as_ref()
            .map(|value| StaticIdentity::from_bytes(value.to_bytes()));
        let checker = identity
            .as_ref()
            .map(|identity| CookieChecker::new(identity, &mut OsRng, Instant::now()));
        *self.private_key.write() = key;
        *self.identity.write() = identity;
        *self.cookie_checker.write() = checker;
        let identity = self.identity.read();
        let peers: Vec<Arc<Peer>> = self.peers.load().values().cloned().collect();
        for peer in peers {
            let mut removed = peer.clear_session();
            let handshake = peer.rebuild_handshake(identity.as_ref());
            removed.extend(&handshake);
            self.index.remove_many(&removed);
        }
        Ok(())
    }

    #[must_use]
    pub fn is_up(&self) -> bool {
        self.up.load(Ordering::Acquire)
    }

    pub fn up(&self) {
        self.up.store(true, Ordering::Release);
    }

    pub fn down(&self) {
        self.up.store(false, Ordering::Release);
    }

    #[must_use]
    pub fn under_load(&self) -> bool {
        self.under_load.load(Ordering::Relaxed)
    }

    pub fn set_under_load(&self, value: bool) {
        self.transition_under_load(value);
    }

    fn transition_under_load(&self, next: bool) {
        let mut current = self.under_load.load(Ordering::Relaxed);
        while current != next {
            match self.under_load.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }

    /// Возвращает порог детектора флуда в инициациях на секунду.
    #[must_use]
    pub fn under_load_threshold(&self) -> u32 {
        self.under_load_detector.threshold()
    }

    /// Устанавливает порог детектора флуда в инициациях на секунду.
    pub fn set_under_load_threshold(&self, threshold: u32) {
        self.under_load_detector.set_threshold(threshold);
    }

    /// Возвращает `true`, если автоматический детектор флуда включён.
    #[must_use]
    pub fn under_load_detection_enabled(&self) -> bool {
        self.under_load_detection.load(Ordering::Relaxed)
    }

    /// Включает или выключает автоматический детектор флуда.
    ///
    /// При выключении окно сбрасывается и флаг `under_load` снимается: вызывающий
    /// код может управлять флагом вручную через [`Device::set_under_load`].
    pub fn set_under_load_detection(&self, enabled: bool) {
        self.under_load_detection.store(enabled, Ordering::Relaxed);
        self.under_load_detector.reset(Instant::now());
        if !enabled {
            self.transition_under_load(false);
        }
    }

    /// Учитывает валидную по MAC1 инициацию и обновляет флаг `under_load`.
    pub fn note_initiation(&self, now: Instant) {
        if !self.under_load_detection_enabled() {
            return;
        }
        let next = self.under_load_detector.note(now, self.under_load());
        self.transition_under_load(next);
    }

    /// Пересчитывает `under_load` по скользящему окну без новой инициации.
    pub fn refresh_under_load(&self, now: Instant) {
        if !self.under_load_detection_enabled() {
            return;
        }
        let next = self.under_load_detector.refresh(now, self.under_load());
        self.transition_under_load(next);
    }

    #[must_use]
    pub fn listen_port(&self) -> u16 {
        self.listen_port.load(Ordering::Relaxed)
    }

    pub fn set_listen_port(&self, port: u16) {
        self.listen_port.store(port, Ordering::Relaxed);
    }

    #[must_use]
    pub fn fwmark(&self) -> u32 {
        self.fwmark.load(Ordering::Relaxed)
    }

    pub fn set_fwmark(&self, mark: u32) {
        self.fwmark.store(mark, Ordering::Relaxed);
    }

    /// Возвращает число дополнительных внешних UDP-портов.
    #[must_use]
    pub fn extra_ports(&self) -> u8 {
        self.extra_ports.load(Ordering::Relaxed)
    }

    /// Устанавливает число дополнительных внешних UDP-портов.
    ///
    /// Значение ограничивается [`MAX_EXTRA_PORTS`].
    pub fn set_extra_ports(&self, extra_ports: u8) {
        self.extra_ports
            .store(extra_ports.min(MAX_EXTRA_PORTS), Ordering::Relaxed);
    }

    #[must_use]
    pub fn mtu(&self) -> u16 {
        self.mtu.load(Ordering::Relaxed)
    }

    pub fn set_mtu(&self, mtu: u16) {
        self.mtu.store(mtu, Ordering::Relaxed);
    }

    #[must_use]
    pub fn obfuscation(&self) -> Arc<ObfParams> {
        self.obfuscation.load_full()
    }

    pub fn set_obfuscation(&self, params: ObfParams) -> Result<()> {
        params.validate()?;
        self.obfuscation.store(Arc::new(params));
        Ok(())
    }

    #[must_use]
    pub fn timings(&self) -> Timings {
        *self.timings.read()
    }

    pub fn set_timings(&self, timings: Timings) -> Result<()> {
        if !timings.validate() {
            return Err(DeviceError::InvalidParameter("timings"));
        }
        *self.timings.write() = timings;
        Ok(())
    }

    #[must_use]
    pub fn allowed_ips(&self) -> &crate::allowedips::AllowedIps {
        &self.allowed_ips
    }

    #[must_use]
    pub fn incoming_drop_counters(&self) -> &IncomingDropCounters {
        &self.incoming_drops
    }

    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peers.load().len()
    }

    pub fn for_each_peer(&self, mut visit: impl FnMut(&Arc<Peer>)) {
        let peers = self.peers.load();
        for peer in peers.values() {
            visit(peer);
        }
    }

    #[must_use]
    pub fn peers(&self) -> Vec<Arc<Peer>> {
        let mut peers: Vec<Arc<Peer>> = self.peers.load().values().cloned().collect();
        peers.sort_by_key(|peer| peer.public_key().to_bytes());
        peers
    }

    pub fn add_peer(&self, config: PeerConfig) -> Result<Arc<Peer>> {
        let _guard = self.peers_update.lock();
        let key = config.public_key.to_bytes();
        if self.peers.load().contains_key(&key) {
            return Err(DeviceError::PeerExists);
        }
        if self.peers.load().len() >= MAX_PEERS_PER_DEVICE as usize {
            return Err(DeviceError::TooManyPeers);
        }
        let prefixes = config.allowed_ips.clone();
        let id = self.allocate_peer_id();
        let identity = self.identity.read();
        let peer = Arc::new(Peer::new(id, config, identity.as_ref()));
        drop(identity);
        let mut by_key = (**self.peers.load()).clone();
        by_key.insert(key, Arc::clone(&peer));
        let mut by_id = (**self.peers_by_id.load()).clone();
        by_id.insert(id.get(), Arc::clone(&peer));
        self.peers.store(Arc::new(by_key));
        self.peers_by_id.store(Arc::new(by_id));
        self.allowed_ips.insert_many(&prefixes, id);
        Ok(peer)
    }

    fn allocate_peer_id(&self) -> PeerId {
        loop {
            let value = self.next_peer_id.fetch_add(1, Ordering::Relaxed);
            if value != 0 && !self.peers_by_id.load().contains_key(&value) {
                return PeerId::new_unchecked(value);
            }
        }
    }

    pub fn remove_peer(&self, public_key: PublicKey) -> bool {
        let _guard = self.peers_update.lock();
        let key = public_key.to_bytes();
        let peer = {
            let mut by_key = (**self.peers.load()).clone();
            let peer = by_key.remove(&key);
            if peer.is_some() {
                self.peers.store(Arc::new(by_key));
            }
            peer
        };
        let Some(peer) = peer else {
            return false;
        };
        {
            let mut by_id = (**self.peers_by_id.load()).clone();
            by_id.remove(&peer.id().get());
            self.peers_by_id.store(Arc::new(by_id));
        }
        let removed = peer.stop();
        self.index.remove_many(&removed);
        self.allowed_ips.remove_by_peer(peer.id());
        true
    }

    pub fn remove_all_peers(&self) {
        let keys: Vec<PublicKey> = self
            .peers
            .load()
            .values()
            .map(|peer| peer.public_key())
            .collect();
        for key in keys {
            self.remove_peer(key);
        }
    }

    #[must_use]
    pub fn peer_by_key(&self, public_key: PublicKey) -> Option<Arc<Peer>> {
        self.peers.load().get(&public_key.to_bytes()).cloned()
    }

    #[must_use]
    pub fn peer_by_id(&self, id: PeerId) -> Option<Arc<Peer>> {
        self.peers_by_id.load().get(&id.get()).cloned()
    }

    #[must_use]
    pub fn route(&self, address: IpAddr) -> Option<Arc<Peer>> {
        let id = self.allowed_ips.lookup(address)?;
        self.peer_by_id(id)
    }

    #[must_use]
    pub fn peer_state(&self, peer: &Peer, now: Instant) -> PeerState {
        peer.state(now, self.timings().keychain_expire())
    }

    pub fn set_peer_preshared_key(&self, peer: &Arc<Peer>, key: Key) -> Result<()> {
        peer.set_preshared_key(key);
        let mut removed = peer.clear_session();
        let identity = self.identity.read();
        let handshake = peer.rebuild_handshake(identity.as_ref());
        removed.extend(&handshake);
        self.index.remove_many(&removed);
        Ok(())
    }

    pub fn set_peer_endpoint(&self, peer: &Peer, endpoint: Option<SocketAddr>) {
        peer.set_endpoint(endpoint);
    }

    pub fn initiate_handshake<R: RngCore, S: DatagramSink>(
        &self,
        peer: &Arc<Peer>,
        ctx: &mut IoContext<'_, R, S>,
    ) -> Result<()> {
        self.send_handshake_initiation(peer, false, ctx)
    }

    fn send_handshake_initiation<R: RngCore, S: DatagramSink>(
        &self,
        peer: &Arc<Peer>,
        retry: bool,
        ctx: &mut IoContext<'_, R, S>,
    ) -> Result<()> {
        if !peer.running() {
            return Ok(());
        }
        let Some(endpoint) = peer.endpoint() else {
            return Err(DeviceError::NoEndpoint);
        };
        let timings = self.timings();
        let min_timeout = timings.rekey_min_timeout();
        if !retry {
            let max = timings.max_handshake_attempts(ctx.rng);
            peer.with_timers(|timers| {
                timers.handshake_attempts = 0;
                timers.max_handshake_attempts = max;
                timers.sent_last_minute_handshake = false;
            });
        }
        let identity = self.identity.read();
        let Some(identity_ref) = identity.as_ref() else {
            return Err(DeviceError::NoPrivateKey);
        };
        let raw = {
            let mut handshake = peer.handshake.lock();
            if let Some(last) = handshake.last_sent {
                if ctx.now.saturating_duration_since(last) < min_timeout {
                    return Ok(());
                }
            }
            let Some(noise) = handshake.noise.as_mut() else {
                return Err(DeviceError::NoPrivateKey);
            };
            let previous_index = noise.local_index();
            let index = self.index.allocate(ctx.rng, peer);
            if previous_index != 0 && previous_index != index {
                self.index.remove(previous_index);
            }
            let header = {
                let params = self.obfuscation.load();
                Obfuscator::new(&params).pick_header(MessageKind::Initiation, ctx.rng)
            };
            let mut os_rng = OsRng;
            match noise.create_initiation(identity_ref, &mut os_rng, header, index, Tai64N::now()) {
                Ok(raw) => {
                    handshake.last_sent = Some(ctx.now);
                    raw
                }
                Err(error) => {
                    self.index.remove(index);
                    return Err(error.into());
                }
            }
        };
        let context = unix_time_seconds();
        let params = self.obfuscation.load();
        let obfuscator = Obfuscator::new(&params);
        send_pre_handshake(
            &obfuscator,
            ctx.rng,
            context,
            peer,
            endpoint,
            ctx.scratch,
            ctx.io,
        )?;
        let total = {
            let mut macs = peer.cookie_generator.lock();
            build_fixed_message(
                &obfuscator,
                MessageKind::Initiation,
                &raw,
                Some(&mut *macs),
                ctx.now,
                ctx.rng,
                peer.udp_window() as usize,
                ctx.scratch,
            )?
        };
        ctx.io
            .send_datagram(endpoint, Some(peer), &ctx.scratch[..total], None);
        peer.add_tx(total as u64);
        self.timers_handshake_initiated(peer, &timings, ctx.rng, ctx.now);
        self.timers_any_authenticated_packet_traversal(peer, ctx.rng, ctx.now);
        self.timers_any_authenticated_packet_sent(peer);
        Ok(())
    }

    fn send_handshake_response<R: RngCore, S: DatagramSink>(
        &self,
        peer: &Arc<Peer>,
        ctx: &mut IoContext<'_, R, S>,
    ) -> Result<()> {
        let Some(endpoint) = peer.endpoint() else {
            return Err(DeviceError::NoEndpoint);
        };
        let identity = self.identity.read();
        if identity.is_none() {
            return Err(DeviceError::NoPrivateKey);
        }
        let (raw, keys) = {
            let mut handshake = peer.handshake.lock();
            let Some(noise) = handshake.noise.as_mut() else {
                return Err(DeviceError::NoPrivateKey);
            };
            let previous_index = noise.local_index();
            let index = self.index.allocate(ctx.rng, peer);
            if previous_index != 0 && previous_index != index {
                self.index.remove(previous_index);
            }
            let header = {
                let params = self.obfuscation.load();
                Obfuscator::new(&params).pick_header(MessageKind::Response, ctx.rng)
            };
            let mut os_rng = OsRng;
            let raw = match noise.create_response(&mut os_rng, header, index) {
                Ok(raw) => raw,
                Err(error) => {
                    self.index.remove(index);
                    return Err(error.into());
                }
            };
            let keys = match noise.begin_session() {
                Ok(keys) => keys,
                Err(error) => {
                    self.index.remove(index);
                    return Err(error.into());
                }
            };
            handshake.last_sent = Some(ctx.now);
            (raw, keys)
        };
        drop(identity);
        let keypair = Arc::new(Keypair::from_noise_with(
            &keys,
            ctx.now,
            peer.aead_algorithm(),
        ));
        self.install_keypair(peer, &keypair, false);
        let timings = self.timings();
        self.timers_session_derived(peer, &timings, ctx.now);
        let params = self.obfuscation.load();
        let obfuscator = Obfuscator::new(&params);
        let total = {
            let mut macs = peer.cookie_generator.lock();
            build_fixed_message(
                &obfuscator,
                MessageKind::Response,
                &raw,
                Some(&mut *macs),
                ctx.now,
                ctx.rng,
                peer.udp_window() as usize,
                ctx.scratch,
            )?
        };
        ctx.io
            .send_datagram(endpoint, Some(peer), &ctx.scratch[..total], None);
        peer.add_tx(total as u64);
        self.timers_any_authenticated_packet_traversal(peer, ctx.rng, ctx.now);
        self.timers_any_authenticated_packet_sent(peer);
        Ok(())
    }

    fn send_cookie_reply<R: RngCore, S: DatagramSink>(
        &self,
        request: &[u8],
        sender: u32,
        source: SocketAddr,
        ctx: &mut IoContext<'_, R, S>,
    ) -> Result<()> {
        let mut address = [0u8; 18];
        let length = endpoint_bytes(source, &mut address);
        let params = self.obfuscation.load();
        let obfuscator = Obfuscator::new(&params);
        let header = obfuscator.pick_header(MessageKind::Cookie, ctx.rng);
        let reply = {
            let mut checker = self.cookie_checker.write();
            let Some(checker) = checker.as_mut() else {
                return Err(DeviceError::NoPrivateKey);
            };
            checker.create_reply(
                request,
                sender,
                &address[..length],
                header,
                ctx.rng,
                ctx.now,
            )?
        };
        let total = build_fixed_message(
            &obfuscator,
            MessageKind::Cookie,
            &reply,
            None,
            ctx.now,
            ctx.rng,
            DEFAULT_UDP_WINDOW as usize,
            ctx.scratch,
        )?;
        ctx.io
            .send_datagram(source, None, &ctx.scratch[..total], None);
        Ok(())
    }

    fn install_keypair(&self, peer: &Arc<Peer>, keypair: &Arc<Keypair>, is_initiator: bool) {
        let removed = {
            let mut keypairs = peer.keypairs.write();
            keypairs.install(Arc::clone(keypair), is_initiator)
        };
        self.index.replace_keypair(&removed, peer, keypair);
    }

    pub fn send_keepalive<R: RngCore, S: DatagramSink>(
        &self,
        peer: &Arc<Peer>,
        ctx: &mut IoContext<'_, R, S>,
    ) -> Result<()> {
        if !peer.running() {
            return Ok(());
        }
        let Some(keypair) = peer.current_keypair() else {
            return self.send_handshake_initiation(peer, false, ctx);
        };
        let Some(endpoint) = peer.endpoint() else {
            return Err(DeviceError::NoEndpoint);
        };
        let length =
            self.encrypt_with_keypair(peer, &keypair, &[], ctx.scratch, ctx.rng, ctx.now)?;
        ctx.io
            .send_datagram(endpoint, Some(peer), &ctx.scratch[..length], None);
        peer.add_tx(length as u64);
        self.timers_any_authenticated_packet_traversal(peer, ctx.rng, ctx.now);
        self.timers_any_authenticated_packet_sent(peer);
        Ok(())
    }

    pub fn encrypt_packet<R: RngCore>(
        &self,
        peer: &Peer,
        plaintext: &[u8],
        dst: &mut [u8],
        rng: &mut R,
        now: Instant,
    ) -> Result<usize> {
        let Some(keypair) = peer.current_keypair() else {
            return Err(DeviceError::NoKeypair);
        };
        self.encrypt_with_keypair(peer, &keypair, plaintext, dst, rng, now)
    }

    #[allow(clippy::too_many_arguments)]
    fn encrypt_with_keypair<R: RngCore>(
        &self,
        peer: &Peer,
        keypair: &Keypair,
        plaintext: &[u8],
        dst: &mut [u8],
        rng: &mut R,
        now: Instant,
    ) -> Result<usize> {
        let timings = self.timings();
        let params = self.obfuscation.load();
        self.encrypt_with_keypair_ctx(peer, keypair, &params, &timings, plaintext, dst, rng, now)
    }

    #[allow(clippy::too_many_arguments)]
    fn encrypt_with_keypair_ctx<R: RngCore>(
        &self,
        peer: &Peer,
        keypair: &Keypair,
        params: &ObfParams,
        timings: &Timings,
        plaintext: &[u8],
        dst: &mut [u8],
        rng: &mut R,
        now: Instant,
    ) -> Result<usize> {
        if keypair.is_expired(now, timings.keychain_expire()) {
            return Err(DeviceError::KeypairExpired);
        }
        let obfuscator = Obfuscator::new(params);
        let padding = usize::from(params.s4);
        let header_end = padding + TRANSPORT_HEADER_SIZE;
        if dst.len() < header_end {
            return Err(DeviceError::BufferTooSmall {
                required: header_end,
                available: dst.len(),
            });
        }
        let base_len = header_end
            .saturating_add(plaintext.len())
            .saturating_add(aead::TAG_LEN);
        let udp_window = (peer.udp_window() as usize).max(base_len);
        let content_padding = if params.content_padding_addition_enabled() {
            params.content_padding_len(rng, base_len, udp_window)
        } else if params.random_trailers {
            params.random_trailer_len(rng, base_len, udp_window)
        } else {
            ObfParams::mtu_padding(plaintext.len(), usize::from(self.mtu()))
        };
        let total = base_len.saturating_add(content_padding);
        if total > MAX_PACKET_SIZE {
            return Err(DeviceError::PacketTooLarge);
        }
        if dst.len() < total {
            return Err(DeviceError::BufferTooSmall {
                required: total,
                available: dst.len(),
            });
        }
        let nonce = keypair
            .next_send_nonce()
            .ok_or(DeviceError::KeypairExhausted)?;
        obfuscator.begin_transport(rng, dst, keypair.remote_index(), nonce)?;
        let content_end = header_end + plaintext.len();
        dst[header_end..content_end].copy_from_slice(plaintext);
        dst[content_end..total - aead::TAG_LEN].fill(0);
        keypair
            .seal_in_place(nonce, &mut dst[header_end..total])
            .ok_or(DeviceError::PacketTooLarge)?;
        peer.observe_udp_window(total as u32);
        Ok(total)
    }

    pub fn send_data<R: RngCore, S: DatagramSink>(
        &self,
        peer: &Arc<Peer>,
        plaintext: &[u8],
        dst: &mut [u8],
        ctx: &mut IoContext<'_, R, S>,
    ) -> Result<usize> {
        let length = self.encrypt_packet(peer, plaintext, dst, ctx.rng, ctx.now)?;
        let Some(endpoint) = peer.endpoint() else {
            return Err(DeviceError::NoEndpoint);
        };
        ctx.io
            .send_datagram(endpoint, Some(peer), &dst[..length], None);
        peer.add_tx(length as u64);
        self.after_data_sent(peer, ctx)?;
        Ok(length)
    }

    pub fn send_packet<R: RngCore, S: DatagramSink>(
        &self,
        peer: &Arc<Peer>,
        plaintext: &[u8],
        dst: &mut [u8],
        ctx: &mut IoContext<'_, R, S>,
    ) -> Result<SendOutcome> {
        match self.encrypt_packet(peer, plaintext, dst, ctx.rng, ctx.now) {
            Ok(length) => {
                let Some(endpoint) = peer.endpoint() else {
                    return Err(DeviceError::NoEndpoint);
                };
                ctx.io
                    .send_datagram(endpoint, Some(peer), &dst[..length], None);
                peer.add_tx(length as u64);
                self.after_data_sent(peer, ctx)?;
                Ok(SendOutcome::Sent(length))
            }
            Err(DeviceError::NoKeypair | DeviceError::KeypairExpired) => {
                let mut buffer = self.staging_pool.acquire();
                if plaintext.len() > buffer.len() {
                    return Err(DeviceError::BufferTooSmall {
                        required: plaintext.len(),
                        available: buffer.len(),
                    });
                }
                buffer[..plaintext.len()].copy_from_slice(plaintext);
                peer.stage(buffer, plaintext.len())?;
                self.send_handshake_initiation(peer, false, ctx)?;
                Ok(SendOutcome::Staged)
            }
            Err(error) => Err(error),
        }
    }

    pub fn flush_staged<R: RngCore, S: DatagramSink>(
        &self,
        peer: &Arc<Peer>,
        ctx: &mut IoContext<'_, R, S>,
    ) -> Result<usize> {
        let mut sent = 0;
        loop {
            let Some(packet) = peer.take_staged() else {
                break;
            };
            let plaintext = &packet.buffer[..packet.len];
            match self.encrypt_packet(peer, plaintext, ctx.scratch, ctx.rng, ctx.now) {
                Ok(length) => {
                    let Some(endpoint) = peer.endpoint() else {
                        peer.requeue_staged(packet);
                        return Err(DeviceError::NoEndpoint);
                    };
                    ctx.io
                        .send_datagram(endpoint, Some(peer), &ctx.scratch[..length], None);
                    peer.add_tx(length as u64);
                    sent += 1;
                }
                Err(DeviceError::NoKeypair | DeviceError::KeypairExpired) => {
                    peer.requeue_staged(packet);
                    break;
                }
                Err(_) => {}
            }
        }
        if sent > 0 {
            let timings = self.timings();
            self.timers_any_authenticated_packet_traversal(peer, ctx.rng, ctx.now);
            self.timers_any_authenticated_packet_sent(peer);
            self.timers_data_sent(peer, &timings, ctx.rng, ctx.now);
        }
        Ok(sent)
    }

    pub fn encrypt_batch<R: RngCore>(
        &self,
        peer: &Arc<Peer>,
        plaintexts: &[&[u8]],
        dst: &mut [u8],
        rng: &mut R,
        now: Instant,
    ) -> Result<BatchLayout> {
        let mut layout = BatchLayout::new();
        let mut offset = 0;
        for plaintext in plaintexts {
            if offset >= dst.len() {
                return Err(DeviceError::BufferTooSmall {
                    required: offset + 1,
                    available: dst.len(),
                });
            }
            let length = self.encrypt_packet(peer, plaintext, &mut dst[offset..], rng, now)?;
            if !layout.push(offset, length) {
                return Err(DeviceError::PacketTooLarge);
            }
            offset += length;
        }
        Ok(layout)
    }

    pub fn send_batch<R: RngCore, S: DatagramSink>(
        &self,
        peer: &Arc<Peer>,
        plaintexts: &[&[u8]],
        dst: &mut [u8],
        ctx: &mut IoContext<'_, R, S>,
    ) -> Result<SentBatch> {
        let endpoint = peer.endpoint();
        let mut layout = BatchLayout::new();
        if plaintexts.is_empty() {
            return Ok(SentBatch {
                layout,
                staged: 0,
                sent: 0,
                needs_handshake: false,
                endpoint,
            });
        }
        if endpoint.is_none() {
            return Err(DeviceError::NoEndpoint);
        }
        let timings = self.timings();
        let params = self.obfuscation.load();
        let keypair = peer
            .current_keypair()
            .filter(|keypair| !keypair.is_expired(ctx.now, timings.keychain_expire()));
        let Some(keypair) = keypair else {
            let mut staged = 0;
            for plaintext in plaintexts {
                let mut buffer = self.staging_pool.acquire();
                if plaintext.len() > buffer.len() {
                    return Err(DeviceError::BufferTooSmall {
                        required: plaintext.len(),
                        available: buffer.len(),
                    });
                }
                buffer[..plaintext.len()].copy_from_slice(plaintext);
                peer.stage(buffer, plaintext.len())?;
                staged += 1;
            }
            return Ok(SentBatch {
                layout,
                staged,
                sent: 0,
                needs_handshake: staged > 0,
                endpoint,
            });
        };
        let mut offset = 0;
        let mut total = 0;
        for plaintext in plaintexts {
            if offset >= dst.len() {
                return Err(DeviceError::BufferTooSmall {
                    required: offset + 1,
                    available: dst.len(),
                });
            }
            let length = self.encrypt_with_keypair_ctx(
                peer,
                &keypair,
                &params,
                &timings,
                plaintext,
                &mut dst[offset..],
                ctx.rng,
                ctx.now,
            )?;
            if !layout.push(offset, length) {
                return Err(DeviceError::PacketTooLarge);
            }
            offset += length;
            total += length;
        }
        peer.add_tx(total as u64);
        Ok(SentBatch {
            layout,
            staged: 0,
            sent: plaintexts.len(),
            needs_handshake: false,
            endpoint,
        })
    }

    pub fn after_batch_sent<R: RngCore, S: DatagramSink>(
        &self,
        peer: &Arc<Peer>,
        ctx: &mut IoContext<'_, R, S>,
    ) -> Result<()> {
        self.after_data_sent(peer, ctx)
    }

    fn after_data_sent<R: RngCore, S: DatagramSink>(
        &self,
        peer: &Arc<Peer>,
        ctx: &mut IoContext<'_, R, S>,
    ) -> Result<()> {
        let timings = self.timings();
        self.timers_any_authenticated_packet_traversal(peer, ctx.rng, ctx.now);
        self.timers_any_authenticated_packet_sent(peer);
        self.timers_data_sent(peer, &timings, ctx.rng, ctx.now);
        let Some(keypair) = peer.current_keypair() else {
            return Ok(());
        };
        if keypair.needs_rekey()
            || (keypair.is_initiator()
                && keypair.age(ctx.now) > timings.key_refresh_sending(ctx.rng))
        {
            self.send_handshake_initiation(peer, false, ctx)?;
        }
        Ok(())
    }

    /// Снимает снимок настроек обфускации и таймеров для батча приёма.
    #[must_use]
    pub fn incoming_snapshot(&self) -> IncomingSnapshot {
        IncomingSnapshot {
            params: self.obfuscation.load_full(),
            timings: self.timings(),
        }
    }

    pub fn handle_incoming<R: RngCore, S: PacketIo>(
        &self,
        packet: &mut [u8],
        meta: IncomingMeta,
        ctx: &mut IoContext<'_, R, S>,
    ) -> Result<IncomingOutcome> {
        let snapshot = self.incoming_snapshot();
        self.handle_incoming_with(packet, meta, &snapshot, ctx)
    }

    pub fn handle_incoming_with<R: RngCore, S: PacketIo>(
        &self,
        packet: &mut [u8],
        meta: IncomingMeta,
        snapshot: &IncomingSnapshot,
        ctx: &mut IoContext<'_, R, S>,
    ) -> Result<IncomingOutcome> {
        let Some(gro_size) = meta.gro_size else {
            return self.handle_segment(packet, meta.source, snapshot, ctx);
        };
        if gro_size == 0 {
            return Ok(IncomingOutcome::Dropped);
        }
        let mut outcome = IncomingOutcome::Dropped;
        let mut offset = 0;
        while offset < packet.len() {
            let end = (offset + gro_size).min(packet.len());
            let result =
                self.handle_segment(&mut packet[offset..end], meta.source, snapshot, ctx)?;
            if !result.is_dropped() {
                outcome = result;
            }
            offset = end;
        }
        Ok(outcome)
    }

    fn handle_segment<R: RngCore, S: PacketIo>(
        &self,
        packet: &mut [u8],
        source: SocketAddr,
        snapshot: &IncomingSnapshot,
        ctx: &mut IoContext<'_, R, S>,
    ) -> Result<IncomingOutcome> {
        let prepared = self.prepare_incoming(packet, snapshot, ctx.now);
        self.handle_prepared(packet, prepared, source, snapshot, ctx)
    }

    /// Классифицирует сегмент и находит сессию, не расшифровывая данные.
    ///
    /// Может выполняться в отдельном потоке приёма: результат передаётся в
    /// [`Device::handle_prepared`] вместе с буфером пакета.
    #[must_use]
    pub fn prepare_incoming(
        &self,
        packet: &mut [u8],
        snapshot: &IncomingSnapshot,
        now: Instant,
    ) -> PreparedIncoming {
        if packet.len() < MESSAGE_MINIMUM_LENGTH {
            return PreparedIncoming::Dropped;
        }
        let obfuscator = Obfuscator::new(&snapshot.params);
        let Some(detected) = obfuscator.open_incoming(packet) else {
            return PreparedIncoming::Dropped;
        };
        if detected.kind != MessageKind::Transport {
            return PreparedIncoming::Control(detected);
        }
        let padding = detected.padding;
        let Some(header_end) = padding.checked_add(TRANSPORT_HEADER_SIZE) else {
            return PreparedIncoming::Dropped;
        };
        if packet.len() < header_end + aead::TAG_LEN {
            return PreparedIncoming::Dropped;
        }
        let receiver = read_u32(packet, padding + 4);
        let Some(entry) = self.index.lookup(receiver) else {
            return PreparedIncoming::Dropped;
        };
        let Some(keypair) = entry.keypair else {
            return PreparedIncoming::Dropped;
        };
        if keypair.is_expired(now, snapshot.timings.keychain_expire()) {
            return PreparedIncoming::Dropped;
        }
        PreparedIncoming::Transport(PreparedTransport {
            peer: entry.peer,
            keypair,
            padding,
            header_end,
        })
    }

    /// Обрабатывает сегмент, подготовленный [`Device::prepare_incoming`].
    pub fn handle_prepared<R: RngCore, S: PacketIo>(
        &self,
        packet: &mut [u8],
        prepared: PreparedIncoming,
        source: SocketAddr,
        snapshot: &IncomingSnapshot,
        ctx: &mut IoContext<'_, R, S>,
    ) -> Result<IncomingOutcome> {
        match prepared {
            PreparedIncoming::Transport(prepared) => {
                self.handle_transport_prepared(packet, prepared, source, snapshot, ctx)
            }
            PreparedIncoming::Control(detected) => match detected.kind {
                MessageKind::Initiation => {
                    self.handle_initiation(packet, detected.padding, source, ctx)
                }
                MessageKind::Response => {
                    self.handle_response(packet, detected.padding, source, ctx)
                }
                MessageKind::Cookie => self.handle_cookie(packet, detected.padding, ctx),
                MessageKind::Transport => Ok(IncomingOutcome::Dropped),
            },
            PreparedIncoming::Dropped => Ok(IncomingOutcome::Dropped),
        }
    }

    fn handle_transport_prepared<R: RngCore, S: PacketIo>(
        &self,
        packet: &mut [u8],
        prepared: PreparedTransport,
        source: SocketAddr,
        snapshot: &IncomingSnapshot,
        ctx: &mut IoContext<'_, R, S>,
    ) -> Result<IncomingOutcome> {
        let PreparedTransport {
            peer,
            keypair,
            padding,
            header_end,
        } = prepared;
        let timings = &snapshot.timings;
        let counter = read_u64(packet, padding + 8);
        let Some(plaintext) = keypair.open(counter, &mut packet[header_end..]) else {
            self.incoming_drops.note_open_failed();
            return Ok(IncomingOutcome::Dropped);
        };
        if !keypair.validate_replay(counter) {
            self.incoming_drops.note_replay();
            return Ok(IncomingOutcome::Dropped);
        }
        if !peer.running() {
            return Ok(IncomingOutcome::Dropped);
        }
        let plaintext_len = plaintext.len();
        peer.observe_udp_window((header_end + plaintext_len) as u32);
        peer.add_rx((plaintext_len + MESSAGE_MINIMUM_LENGTH) as u64);
        let promoted = peer.promote_keypair(&keypair);
        let promoted = if let Some(removed) = promoted {
            self.index.remove_many(&removed);
            peer.set_endpoint_from_packet(source);
            self.timers_handshake_complete(&peer);
            true
        } else {
            peer.set_endpoint_from_packet(source);
            false
        };
        if promoted {
            self.flush_staged(&peer, ctx)?;
        }
        self.timers_any_authenticated_packet_traversal(&peer, ctx.rng, ctx.now);
        self.timers_any_authenticated_packet_received(&peer);
        self.keep_key_fresh_receiving(&peer, timings, ctx)?;
        if plaintext.is_empty() || plaintext[0] == 0 {
            return Ok(IncomingOutcome::Keepalive);
        }
        let Some((length, address)) = ip_packet_info(plaintext) else {
            return Ok(IncomingOutcome::Dropped);
        };
        if self.allowed_ips.lookup(address) != Some(peer.id()) {
            self.incoming_drops.note_allowed_ips();
            return Ok(IncomingOutcome::Dropped);
        }
        self.timers_data_received(&peer, timings, ctx.rng, ctx.now);
        ctx.io.deliver(&peer, &plaintext[..length]);
        Ok(IncomingOutcome::Delivered(length))
    }

    fn handle_initiation<R: RngCore, S: PacketIo>(
        &self,
        packet: &mut [u8],
        padding: usize,
        source: SocketAddr,
        ctx: &mut IoContext<'_, R, S>,
    ) -> Result<IncomingOutcome> {
        let Some(end) = padding.checked_add(INITIATION_SIZE) else {
            return Ok(IncomingOutcome::Dropped);
        };
        if packet.len() < end {
            return Ok(IncomingOutcome::Dropped);
        }
        let body = &mut packet[padding..end];
        {
            let identity = self.identity.read();
            if identity.is_none() {
                return Ok(IncomingOutcome::Dropped);
            }
            let checker = self.cookie_checker.read();
            let Some(checker) = checker.as_ref() else {
                return Ok(IncomingOutcome::Dropped);
            };
            if !checker.check_mac1(body) {
                return Ok(IncomingOutcome::Dropped);
            }
        }
        self.note_initiation(ctx.now);
        let mut address = [0u8; 18];
        let address_len = endpoint_bytes(source, &mut address);
        let params = self.obfuscation.load();
        if self.under_load() && !params.disable_cookies {
            let valid = {
                let checker = self.cookie_checker.read();
                let Some(checker) = checker.as_ref() else {
                    return Ok(IncomingOutcome::Dropped);
                };
                checker.check_mac2(body, &address[..address_len], ctx.now)
            };
            if !valid {
                let sender = read_u32(body, 4);
                self.send_cookie_reply(body, sender, source, ctx)?;
                return Ok(IncomingOutcome::Cookie);
            }
            if !self.rate_limiter.allow(source.ip(), ctx.now) {
                return Ok(IncomingOutcome::Dropped);
            }
        }
        let mut message = HandshakeInitiation::parse(body)?;
        message.set_message_type(MESSAGE_HANDSHAKE_INITIATION);
        let decrypted = {
            let identity = self.identity.read();
            match identity.as_ref() {
                Some(identity) => identity.decrypt_initiation(&message),
                None => return Ok(IncomingOutcome::Dropped),
            }
        };
        let initiation = match decrypted {
            Ok(initiation) => initiation,
            Err(_) => return Ok(IncomingOutcome::Dropped),
        };
        let public_key = initiation.peer_static().to_bytes();
        let Some(peer) = self.peers.load().get(&public_key).cloned() else {
            return Ok(IncomingOutcome::Dropped);
        };
        if !peer.running() {
            return Ok(IncomingOutcome::Dropped);
        }
        {
            let handshake = peer.handshake.lock();
            if handshake.last_initiation_consumed.is_some_and(|last| {
                ctx.now.saturating_duration_since(last) < TRANSPORT_FLOOD_INTERVAL
            }) {
                return Ok(IncomingOutcome::Dropped);
            }
        }
        let consumed = {
            let mut handshake = peer.handshake.lock();
            if handshake.last_initiation_consumed.is_some_and(|last| {
                ctx.now.saturating_duration_since(last) < TRANSPORT_FLOOD_INTERVAL
            }) {
                return Ok(IncomingOutcome::Dropped);
            }
            let Some(noise) = handshake.noise.as_mut() else {
                return Ok(IncomingOutcome::Dropped);
            };
            match noise.consume_initiation(initiation, &message) {
                Ok(()) => {
                    handshake.last_initiation_consumed = Some(ctx.now);
                    true
                }
                Err(_) => false,
            }
        };
        if !consumed {
            return Ok(IncomingOutcome::Dropped);
        }
        peer.add_rx(INITIATION_SIZE as u64);
        peer.set_endpoint_from_packet(source);
        self.timers_any_authenticated_packet_traversal(&peer, ctx.rng, ctx.now);
        self.timers_any_authenticated_packet_received(&peer);
        self.send_handshake_response(&peer, ctx)?;
        Ok(IncomingOutcome::Handshake)
    }

    fn handle_response<R: RngCore, S: PacketIo>(
        &self,
        packet: &mut [u8],
        padding: usize,
        source: SocketAddr,
        ctx: &mut IoContext<'_, R, S>,
    ) -> Result<IncomingOutcome> {
        let Some(end) = padding.checked_add(RESPONSE_SIZE) else {
            return Ok(IncomingOutcome::Dropped);
        };
        if packet.len() < end {
            return Ok(IncomingOutcome::Dropped);
        }
        let body = &mut packet[padding..end];
        {
            let checker = self.cookie_checker.read();
            let Some(checker) = checker.as_ref() else {
                return Ok(IncomingOutcome::Dropped);
            };
            if !checker.check_mac1(body) {
                return Ok(IncomingOutcome::Dropped);
            }
        }
        let mut message = HandshakeResponse::parse(body)?;
        message.set_message_type(MESSAGE_HANDSHAKE_RESPONSE);
        let Some(entry) = self.index.lookup(message.receiver_index()) else {
            return Ok(IncomingOutcome::Dropped);
        };
        if entry.keypair.is_some() {
            return Ok(IncomingOutcome::Dropped);
        }
        let peer = entry.peer;
        if !peer.running() {
            return Ok(IncomingOutcome::Dropped);
        }
        let keys = {
            let identity = self.identity.read();
            let Some(identity) = identity.as_ref() else {
                return Ok(IncomingOutcome::Dropped);
            };
            let mut handshake = peer.handshake.lock();
            let Some(noise) = handshake.noise.as_mut() else {
                return Ok(IncomingOutcome::Dropped);
            };
            match noise.consume_response(identity, &message) {
                Ok(()) => noise.begin_session().ok(),
                Err(_) => None,
            }
        };
        let Some(keys) = keys else {
            return Ok(IncomingOutcome::Dropped);
        };
        let keypair = Arc::new(Keypair::from_noise_with(
            &keys,
            ctx.now,
            peer.aead_algorithm(),
        ));
        self.install_keypair(&peer, &keypair, true);
        peer.set_endpoint_from_packet(source);
        peer.add_rx(RESPONSE_SIZE as u64);
        let timings = self.timings();
        self.timers_session_derived(&peer, &timings, ctx.now);
        self.timers_handshake_complete(&peer);
        self.timers_any_authenticated_packet_traversal(&peer, ctx.rng, ctx.now);
        self.timers_any_authenticated_packet_received(&peer);
        self.send_keepalive(&peer, ctx)?;
        self.flush_staged(&peer, ctx)?;
        Ok(IncomingOutcome::Handshake)
    }

    fn handle_cookie<R: RngCore, S: PacketIo>(
        &self,
        packet: &mut [u8],
        padding: usize,
        ctx: &mut IoContext<'_, R, S>,
    ) -> Result<IncomingOutcome> {
        let Some(end) = padding.checked_add(COOKIE_REPLY_SIZE) else {
            return Ok(IncomingOutcome::Dropped);
        };
        if packet.len() < end {
            return Ok(IncomingOutcome::Dropped);
        }
        let body = &mut packet[padding..end];
        let mut message = CookieReply::parse(body)?;
        message.set_message_type(MESSAGE_HANDSHAKE_COOKIE);
        let Some(entry) = self.index.lookup(message.receiver_index()) else {
            return Ok(IncomingOutcome::Dropped);
        };
        let peer = entry.peer;
        if !peer.running() {
            return Ok(IncomingOutcome::Dropped);
        }
        let mut generator = peer.cookie_generator.lock();
        match generator.consume_reply(&message, ctx.now) {
            Ok(()) => Ok(IncomingOutcome::Cookie),
            Err(_) => Ok(IncomingOutcome::Dropped),
        }
    }

    pub fn tick<R: RngCore, S: DatagramSink>(
        &self,
        ctx: &mut IoContext<'_, R, S>,
    ) -> Result<usize> {
        if !self.is_up() {
            return Ok(0);
        }
        let peers = self.peers.load();
        let mut handled = 0;
        let mut kinds = [TimerKind::RetransmitHandshake; 5];
        for peer in peers.values() {
            if !peer.running() {
                continue;
            }
            let count = peer.with_timers(|timers| timers.expire(ctx.now, &mut kinds));
            for kind in kinds[..count].iter().copied() {
                self.handle_timer(peer, kind, ctx)?;
                handled += 1;
            }
        }
        self.rate_limiter.gc(ctx.now);
        Ok(handled)
    }

    fn handle_timer<R: RngCore, S: DatagramSink>(
        &self,
        peer: &Arc<Peer>,
        kind: TimerKind,
        ctx: &mut IoContext<'_, R, S>,
    ) -> Result<()> {
        if !self.timers_active(peer) {
            return Ok(());
        }
        let timings = self.timings();
        match kind {
            TimerKind::RetransmitHandshake => {
                let (attempts, maximum) = peer.with_timers(|timers| {
                    (timers.handshake_attempts, timers.max_handshake_attempts)
                });
                if attempts > maximum {
                    peer.with_timers(|timers| timers.disarm(TimerKind::SendKeepalive));
                    peer.flush_staged_drop();
                    peer.with_timers(|timers| {
                        if !timers.is_pending(TimerKind::ZeroKeyMaterial) {
                            timers.arm(
                                TimerKind::ZeroKeyMaterial,
                                ctx.now + timings.keychain_expire() * 3,
                            );
                        }
                    });
                } else {
                    peer.with_timers(|timers| timers.handshake_attempts = attempts + 1);
                    self.send_handshake_initiation(peer, true, ctx)?;
                }
            }
            TimerKind::SendKeepalive => {
                self.send_keepalive(peer, ctx)?;
                let again = peer.with_timers(|timers| {
                    let again = timers.need_another_keepalive;
                    timers.need_another_keepalive = false;
                    again
                });
                if again && self.timers_active(peer) {
                    let deadline = ctx.now + timings.send_keepalive(ctx.rng);
                    peer.with_timers(|timers| timers.arm(TimerKind::SendKeepalive, deadline));
                }
            }
            TimerKind::NewHandshake => {
                self.send_handshake_initiation(peer, false, ctx)?;
            }
            TimerKind::ZeroKeyMaterial => {
                let removed = peer.zero_and_flush();
                self.index.remove_many(&removed);
            }
            TimerKind::PersistentKeepalive => {
                if peer.persistent_keepalive_range().is_some() {
                    self.send_keepalive(peer, ctx)?;
                }
            }
        }
        Ok(())
    }

    pub fn poll_timers(&self, now: Instant, out: &mut [TimerEvent]) -> usize {
        if !self.is_up() {
            return 0;
        }
        let mut count = 0;
        let mut kinds = [TimerKind::RetransmitHandshake; 5];
        for peer in self.peers.load().values() {
            if !peer.running() {
                continue;
            }
            let expired = peer.with_timers(|timers| timers.expire(now, &mut kinds));
            for kind in kinds[..expired].iter().copied() {
                if count == out.len() {
                    return count;
                }
                out[count] = TimerEvent {
                    peer: peer.id(),
                    kind,
                };
                count += 1;
            }
        }
        count
    }

    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        if !self.is_up() {
            return None;
        }
        let mut next: Option<Instant> = None;
        let peers = self.peers.load();
        for peer in peers.values() {
            if !peer.running() {
                continue;
            }
            if let Some(deadline) = peer.next_deadline() {
                next = Some(match next {
                    Some(current) if current <= deadline => current,
                    _ => deadline,
                });
            }
        }
        next
    }

    fn handle_peer<R: RngCore, S: DatagramSink>(
        &self,
        peer: &Arc<Peer>,
        ctx: &mut IoContext<'_, R, S>,
    ) -> Result<()> {
        let timings = self.timings();
        let Some(keypair) = peer.current_keypair() else {
            return Ok(());
        };
        if keypair.needs_rekey()
            || (keypair.is_initiator()
                && keypair.age(ctx.now) > timings.key_refresh_sending(ctx.rng))
        {
            self.send_handshake_initiation(peer, false, ctx)?;
        }
        Ok(())
    }

    fn keep_key_fresh_receiving<R: RngCore, S: DatagramSink>(
        &self,
        peer: &Arc<Peer>,
        timings: &Timings,
        ctx: &mut IoContext<'_, R, S>,
    ) -> Result<()> {
        let sent = peer.with_timers(|timers| timers.sent_last_minute_handshake);
        if sent {
            return Ok(());
        }
        let Some(keypair) = peer.current_keypair() else {
            return Ok(());
        };
        if keypair.is_initiator() && keypair.age(ctx.now) > timings.key_refresh_receiving() {
            peer.with_timers(|timers| timers.sent_last_minute_handshake = true);
            self.send_handshake_initiation(peer, false, ctx)?;
        }
        Ok(())
    }

    fn timers_active(&self, peer: &Peer) -> bool {
        self.is_up() && peer.running()
    }

    fn timers_any_authenticated_packet_traversal<R: RngCore>(
        &self,
        peer: &Peer,
        rng: &mut R,
        now: Instant,
    ) {
        if !self.timers_active(peer) {
            return;
        }
        if let Some((lo, hi)) = peer.persistent_keepalive_range() {
            let seconds = Range16::new(lo, hi).pick(rng);
            if seconds > 0 {
                peer.with_timers(|timers| {
                    timers.arm(
                        TimerKind::PersistentKeepalive,
                        now + Duration::from_secs(u64::from(seconds)),
                    );
                });
            }
        }
    }

    fn timers_any_authenticated_packet_sent(&self, peer: &Peer) {
        if self.timers_active(peer) {
            peer.with_timers(|timers| timers.disarm(TimerKind::SendKeepalive));
        }
    }

    fn timers_any_authenticated_packet_received(&self, peer: &Peer) {
        if self.timers_active(peer) {
            peer.with_timers(|timers| timers.disarm(TimerKind::NewHandshake));
        }
    }

    fn timers_data_sent<R: RngCore>(
        &self,
        peer: &Peer,
        timings: &Timings,
        rng: &mut R,
        now: Instant,
    ) {
        if !self.timers_active(peer) {
            return;
        }
        peer.with_timers(|timers| {
            if !timers.is_pending(TimerKind::NewHandshake) {
                let deadline = now + timings.new_handshake(rng);
                timers.arm(TimerKind::NewHandshake, deadline);
            }
        });
    }

    fn timers_data_received<R: RngCore>(
        &self,
        peer: &Peer,
        timings: &Timings,
        rng: &mut R,
        now: Instant,
    ) {
        if !self.timers_active(peer) {
            return;
        }
        peer.with_timers(|timers| {
            if timers.is_pending(TimerKind::SendKeepalive) {
                timers.need_another_keepalive = true;
            } else {
                let deadline = now + timings.send_keepalive(rng);
                timers.arm(TimerKind::SendKeepalive, deadline);
            }
        });
    }

    fn timers_handshake_initiated<R: RngCore>(
        &self,
        peer: &Peer,
        timings: &Timings,
        rng: &mut R,
        now: Instant,
    ) {
        if self.timers_active(peer) {
            let deadline = now + timings.retransmit_handshake(rng);
            peer.with_timers(|timers| timers.arm(TimerKind::RetransmitHandshake, deadline));
        }
    }

    fn timers_handshake_complete(&self, peer: &Peer) {
        if self.timers_active(peer) {
            peer.with_timers(|timers| timers.disarm(TimerKind::RetransmitHandshake));
        }
        peer.with_timers(|timers| {
            timers.handshake_attempts = 0;
            timers.sent_last_minute_handshake = false;
        });
        peer.mark_handshake_complete(SystemTime::now());
    }

    fn timers_session_derived(&self, peer: &Peer, timings: &Timings, now: Instant) {
        if self.timers_active(peer) {
            peer.with_timers(|timers| {
                timers.arm(
                    TimerKind::ZeroKeyMaterial,
                    now + timings.keychain_expire() * 3,
                );
            });
        }
    }

    pub fn poll_peer<R: RngCore, S: DatagramSink>(
        &self,
        peer: &Arc<Peer>,
        ctx: &mut IoContext<'_, R, S>,
    ) -> Result<()> {
        self.handle_peer(peer, ctx)
    }
}

fn normalize_private_key(key: Key) -> Key {
    Key::from_bytes(PrivateKey::from_bytes(key.to_bytes()).to_bytes())
}

fn read_u32(buffer: &[u8], offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    if let Some(slice) = buffer.get(offset..offset + 4) {
        bytes.copy_from_slice(slice);
    }
    u32::from_le_bytes(bytes)
}

fn read_u64(buffer: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    if let Some(slice) = buffer.get(offset..offset + 8) {
        bytes.copy_from_slice(slice);
    }
    u64::from_le_bytes(bytes)
}

fn ip_packet_info(packet: &[u8]) -> Option<(usize, IpAddr)> {
    match packet.first()? >> 4 {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            if total < 20 || total > packet.len() {
                return None;
            }
            Some((
                total,
                IpAddr::V4(Ipv4Addr::new(
                    packet[12], packet[13], packet[14], packet[15],
                )),
            ))
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            let total = 40 + usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            if total > packet.len() {
                return None;
            }
            let mut address = [0u8; 16];
            address.copy_from_slice(&packet[8..24]);
            Some((total, IpAddr::V6(Ipv6Addr::from(address))))
        }
        _ => None,
    }
}
