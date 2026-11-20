use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use arc_swap::ArcSwap;
use log::warn;
use parking_lot::{Mutex, RwLock};
use rand_core::{OsRng, RngCore};

use umbrawg_crypto::tai64n::Tai64N;
use umbrawg_crypto::{aead, random, Key, PrivateKey, PublicKey};
use umbrawg_fec::{EncodedBlock, FecShard};
use umbrawg_noise::{CookieChecker, StaticIdentity};
use umbrawg_proto::control::{Ack, Caps, ControlKind, FecShardHeader};
use umbrawg_proto::messages::limits::{
    DEFAULT_UDP_WINDOW, INITIATIONS_PER_SECOND, MAX_PEERS_PER_DEVICE,
};
use umbrawg_proto::messages::{
    COOKIE_REPLY_SIZE, INITIATION_SIZE, MAX_PACKET_SIZE, MESSAGE_HANDSHAKE_COOKIE,
    MESSAGE_HANDSHAKE_INITIATION, MESSAGE_HANDSHAKE_RESPONSE, MESSAGE_MINIMUM_LENGTH,
    MESSAGE_PADDING_MULTIPLE, RESPONSE_SIZE, TRANSPORT_HEADER_SIZE,
};
use umbrawg_proto::obf::{DetectedPacket, MessageKind, Obfuscator};
use umbrawg_proto::{CookieReply, HandshakeInitiation, HandshakeResponse, ObfParams};

use crate::allowedips::PeerId;
use crate::buffer::{BufferPool, DEFAULT_BUFFER_SIZE};
use crate::error::{DeviceError, Result};
pub use crate::ext::BbrBatch;
use crate::ext::FecStats;
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
    pub ext: crate::ExtConfig,
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
            ext: crate::ExtConfig::default(),
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
    ext_config: RwLock<crate::ExtConfig>,
    cookies_disabled_logged: AtomicBool,
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
        let device = Self {
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
            ext_config: RwLock::new(config.ext),
            cookies_disabled_logged: AtomicBool::new(false),
        };
        device.note_cookie_policy();
        Ok(device)
    }

    fn note_cookie_policy(&self) {
        if self.obfuscation().disable_cookies {
            if !self.cookies_disabled_logged.swap(true, Ordering::Relaxed) {
                warn!(
                    "disable_cookies is enabled: cookie challenges are skipped, \
                     but the per-IP initiation rate limit stays active"
                );
            }
        } else {
            self.cookies_disabled_logged.store(false, Ordering::Relaxed);
        }
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
    pub fn fec_gso_segments(&self) -> Option<usize> {
        let config = self.ext_config();
        match config.fec {
            crate::FecMode::Off => None,
            crate::FecMode::Fixed { .. } => config.fec.config().map(|fec| fec.m().max(1)),
            crate::FecMode::Adaptive => self
                .peers
                .load()
                .values()
                .any(|peer| peer.extension().fec_active())
                .then(|| config.fec.config().map(|fec| fec.m().max(1)))
                .flatten(),
        }
    }

    #[must_use]
    pub fn fec_enabled(&self) -> bool {
        self.ext_config.read().fec != crate::FecMode::Off
    }

    pub fn ext_config(&self) -> crate::ExtConfig {
        *self.ext_config.read()
    }

    pub fn set_ext_config(&self, config: crate::ExtConfig) {
        if self.ext_config() == config {
            return;
        }
        *self.ext_config.write() = config;
        for peer in self.peers.load().values() {
            peer.configure_extension(config);
        }
    }

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
        self.note_cookie_policy();
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
        peer.configure_extension(self.ext_config());
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
    fn send_fec_block_direct<R: RngCore, S: DatagramSink>(
        &self,
        peer: &Arc<Peer>,
        block: &EncodedBlock,
        ctx: &mut IoContext<'_, R, S>,
    ) -> Result<usize> {
        let Some(endpoint) = peer.endpoint() else {
            return Err(DeviceError::NoEndpoint);
        };
        let mut frame = [0u8; 4096];
        let mut dst = [0u8; 4096];
        let mut sent = 0usize;
        let block_padding = ObfParams::random_reserve_len(ctx.rng, MESSAGE_PADDING_MULTIPLE - 1);
        for index in shard_order(block.shards.len(), ctx.rng) {
            let shard = block.shards.get(index).ok_or(DeviceError::PacketTooLarge)?;
            let header = umbrawg_proto::control::FecShardHeader {
                block_id: block.block_id,
                index: u8::try_from(index).map_err(|_| DeviceError::PacketTooLarge)?,
                k: block.k,
                m: block.m,
                parity: index >= usize::from(block.k),
                shard_len: block.shard_len,
            };
            let header_len = header
                .encode(&mut frame)
                .map_err(|_| DeviceError::PacketTooLarge)?;
            let end = header_len + shard.len();
            if end > frame.len() {
                return Err(DeviceError::PacketTooLarge);
            }
            frame[header_len..end].copy_from_slice(shard);
            let length = self.encrypt_control_inner(
                peer,
                &frame[..end],
                &mut dst,
                ctx.rng,
                ctx.now,
                Some(block_padding),
            )?;
            ctx.io
                .send_datagram(endpoint, Some(peer), &dst[..length], None);
            peer.add_tx(length as u64);
            peer.extension().note_fec_shard_sent();
            sent += 1;
        }
        Ok(sent)
    }

    #[allow(clippy::too_many_arguments)]
    fn encode_fec_block<R: RngCore>(
        &self,
        peer: &Arc<Peer>,
        keypair: &Keypair,
        params: &ObfParams,
        timings: &Timings,
        block: &EncodedBlock,
        dst: &mut [u8],
        mut offset: usize,
        rng: &mut R,
        now: Instant,
        layout: &mut BatchLayout,
    ) -> Result<usize> {
        let mut frame = [0u8; 2048];
        let block_padding = ObfParams::random_reserve_len(rng, MESSAGE_PADDING_MULTIPLE - 1);
        for index in shard_order(block.shards.len(), rng) {
            let shard = block.shards.get(index).ok_or(DeviceError::PacketTooLarge)?;
            let header = umbrawg_proto::control::FecShardHeader {
                block_id: block.block_id,
                index: u8::try_from(index).map_err(|_| DeviceError::PacketTooLarge)?,
                k: block.k,
                m: block.m,
                parity: index >= usize::from(block.k),
                shard_len: block.shard_len,
            };
            let header_len = header
                .encode(&mut frame)
                .map_err(|_| DeviceError::PacketTooLarge)?;
            let end = header_len + shard.len();
            if end > frame.len() {
                return Err(DeviceError::PacketTooLarge);
            }
            frame[header_len..end].copy_from_slice(shard);
            if offset >= dst.len() {
                return Err(DeviceError::BufferTooSmall {
                    required: offset + 1,
                    available: dst.len(),
                });
            }
            let length = self.encrypt_with_keypair_ctx(
                peer,
                keypair,
                params,
                timings,
                PaddingMode::Control,
                Some(block_padding),
                &frame[..end],
                &mut dst[offset..],
                rng,
                now,
            )?;
            if !layout.push(offset, length) {
                return Err(DeviceError::PacketTooLarge);
            }
            offset += length;
            peer.extension().note_fec_shard_sent();
        }
        Ok(offset)
    }

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
        self.encrypt_with_keypair_ctx(
            peer,
            keypair,
            &params,
            &timings,
            PaddingMode::Data,
            None,
            plaintext,
            dst,
            rng,
            now,
        )
    }

    /// Encrypts a control frame (ACK, CAPS or FEC shard).
    ///
    /// Control frames use a bounded `0..=15` random trailer instead of the
    /// configured `random_trailers` budget: inflating a 32-byte ACK up to the
    /// whole UDP window both wastes bandwidth and makes the frame trivially
    /// identifiable by size.
    pub fn encrypt_control_packet<R: RngCore>(
        &self,
        peer: &Peer,
        plaintext: &[u8],
        dst: &mut [u8],
        rng: &mut R,
        now: Instant,
    ) -> Result<usize> {
        self.encrypt_control_inner(peer, plaintext, dst, rng, now, None)
    }

    fn encrypt_control_inner<R: RngCore>(
        &self,
        peer: &Peer,
        plaintext: &[u8],
        dst: &mut [u8],
        rng: &mut R,
        now: Instant,
        batch_padding: Option<usize>,
    ) -> Result<usize> {
        let Some(keypair) = peer.current_keypair() else {
            return Err(DeviceError::NoKeypair);
        };
        let timings = self.timings();
        let params = self.obfuscation.load();
        self.encrypt_with_keypair_ctx(
            peer,
            &keypair,
            &params,
            &timings,
            PaddingMode::Control,
            batch_padding,
            plaintext,
            dst,
            rng,
            now,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn encrypt_with_keypair_ctx<R: RngCore>(
        &self,
        peer: &Peer,
        keypair: &Keypair,
        params: &ObfParams,
        timings: &Timings,
        mode: PaddingMode,
        batch_padding: Option<usize>,
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
        let budget = MAX_PACKET_SIZE.min(dst.len()).saturating_sub(base_len);
        let mtu = usize::from(self.mtu());
        let content_padding = match mode {
            PaddingMode::Control => batch_padding.map_or_else(
                || ObfParams::random_reserve_len(rng, budget),
                |extra| extra.min(budget),
            ),
            PaddingMode::Data => {
                if params.content_padding_addition_enabled() {
                    params
                        .content_padding_len(rng, base_len, udp_window)
                        .min(budget)
                } else if params.random_trailers {
                    // Keep a small reserve even when the observed UDP window
                    // is already exhausted, otherwise full-size packets all
                    // leave with an identical length. The reserve is bounded
                    // by 15 bytes and, once the window grows past the packet
                    // size, the regular trailer takes over, so the window
                    // cannot creep upwards without bound.
                    let trailer = params
                        .random_trailer_len(rng, base_len, udp_window)
                        .min(budget);
                    if trailer > 0 {
                        trailer
                    } else {
                        ObfParams::random_reserve_len(rng, budget.min(MESSAGE_PADDING_MULTIPLE - 1))
                    }
                } else {
                    let aligned = ObfParams::mtu_padding(plaintext.len(), mtu);
                    let room = ObfParams::mtu_padding_headroom(plaintext.len(), mtu)
                        .min(budget.saturating_sub(aligned));
                    let extra = batch_padding.map_or_else(
                        || ObfParams::random_reserve_len(rng, room),
                        |extra| extra.min(room),
                    );
                    aligned.saturating_add(extra)
                }
            }
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
        let kind = crate::ext::FrameKind::classify(plaintext);
        peer.extension().on_packet_sent(nonce, total, kind, now);
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

    pub fn flush_staged<R: RngCore, S: PacketIo>(
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
        let packets = peer.extension().fec_poll(ctx.now);
        for packet in packets {
            let Some((length, address)) = ip_packet_info(&packet) else {
                continue;
            };
            if self.allowed_ips.lookup(address) != Some(peer.id()) {
                self.incoming_drops.note_allowed_ips();
                continue;
            }
            ctx.io.deliver(peer, &packet[..length]);
        }
        // The guard must be released before sending: encrypting a shard takes
        // the same per-peer lock inside on_packet_sent.
        let due_block = peer.extension().fec_flush_due(ctx.now);
        if let Some(block) = due_block {
            let _ = self.send_fec_block_direct(peer, &block, ctx);
        }
        sent += self.flush_control(peer, ctx);
        Ok(sent)
    }

    /// Sends pending CAPS/ACK frames without touching staged data.
    pub fn flush_control<R: RngCore, S: DatagramSink>(
        &self,
        peer: &Arc<Peer>,
        ctx: &mut IoContext<'_, R, S>,
    ) -> usize {
        if peer.current_keypair().is_none() {
            return 0;
        }
        let mut sent = 0;
        let frames = peer.extension().pending_control(ctx.now);
        for frame in frames {
            let mut dst = [0u8; 1024];
            match self.encrypt_control_packet(peer, frame.bytes(), &mut dst, ctx.rng, ctx.now) {
                Ok(length) => {
                    let Some(endpoint) = peer.endpoint() else {
                        peer.extension().push_control(frame);
                        break;
                    };
                    ctx.io
                        .send_datagram(endpoint, Some(peer), &dst[..length], None);
                    peer.add_tx(length as u64);
                    peer.extension().note_frame_sent(frame.kind(), ctx.now);
                    if frame.kind() == ControlKind::FecShard {
                        peer.extension().note_fec_shard_sent();
                    }
                    sent += 1;
                }
                Err(DeviceError::NoKeypair | DeviceError::KeypairExpired) => {
                    peer.extension().push_control(frame);
                    break;
                }
                Err(_) => {}
            }
        }
        sent
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
        if plaintexts.is_empty() {
            return Ok(layout);
        }
        let timings = self.timings();
        let params = self.obfuscation.load();
        let Some(keypair) = peer
            .current_keypair()
            .filter(|keypair| !keypair.is_expired(now, timings.keychain_expire()))
        else {
            return Err(DeviceError::NoKeypair);
        };
        let mut offset = 0;
        // One random padding value per batch keeps equal-size packets at
        // equal wire lengths so that UDP GSO can still coalesce them.
        let batch_padding = ObfParams::random_reserve_len(rng, MESSAGE_PADDING_MULTIPLE - 1);
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
                PaddingMode::Data,
                Some(batch_padding),
                plaintext,
                &mut dst[offset..],
                rng,
                now,
            )?;
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
        let batch_padding = ObfParams::random_reserve_len(ctx.rng, MESSAGE_PADDING_MULTIPLE - 1);
        if peer.extension().fec_tx_active() {
            let mut offset = 0usize;
            for plaintext in plaintexts {
                // Drop the extension guard before the match body: FEC shard
                // encryption takes the same per-peer lock via on_packet_sent.
                let pushed = peer.extension().fec_push(plaintext, ctx.now);
                match pushed {
                    Ok(Some(block)) => {
                        offset = self.encode_fec_block(
                            peer,
                            &keypair,
                            &params,
                            &timings,
                            &block,
                            dst,
                            offset,
                            ctx.rng,
                            ctx.now,
                            &mut layout,
                        )?;
                    }
                    Ok(None) => {}
                    Err(_) => {
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
                            PaddingMode::Data,
                            Some(batch_padding),
                            plaintext,
                            &mut dst[offset..],
                            ctx.rng,
                            ctx.now,
                        )?;
                        if !layout.push(offset, length) {
                            return Err(DeviceError::PacketTooLarge);
                        }
                        offset += length;
                    }
                }
            }
            peer.add_tx(offset as u64);
            return Ok(SentBatch {
                layout,
                staged: 0,
                sent: plaintexts.len(),
                needs_handshake: false,
                endpoint,
            });
        }
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
                PaddingMode::Data,
                Some(batch_padding),
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

    #[must_use]
    pub fn bbr_queue_active(&self, peer: &Peer) -> bool {
        peer.extension().bbr_queue_active()
    }

    pub fn bbr_enqueue(&self, peer: &Peer, packet: &[u8]) -> bool {
        peer.extension().bbr_enqueue(packet)
    }

    #[must_use]
    pub fn bbr_drain(&self, peer: &Peer, now: Instant, max_packets: usize) -> Vec<Vec<u8>> {
        peer.extension().bbr_drain(now, max_packets)
    }

    /// Перекладывает готовые к отправке пакеты BBR-очереди в переиспользуемый батч.
    ///
    /// Возвращает число пакетов. Буфер батча переходит очереди, а очередь
    /// отдаёт ей свой: в установившемся режиме вызов не аллоцирует и не копирует
    /// байты. Батч нужно держать между вызовами, иначе буферы перестают
    /// переиспользоваться.
    pub fn bbr_drain_into(
        &self,
        peer: &Peer,
        now: Instant,
        max_packets: usize,
        batch: &mut BbrBatch,
    ) -> usize {
        peer.extension().bbr_drain_into(now, max_packets, batch)
    }

    /// Returns a BBR snapshot for the peer, or `None` when BBR is disabled.
    #[must_use]
    pub fn bbr_stats(&self, peer: &Peer) -> Option<umbrawg_cc::BbrStats> {
        peer.extension().bbr_stats()
    }

    #[must_use]
    pub fn pacing_delay(&self, peer: &Peer, bytes: usize, now: Instant) -> Duration {
        peer.extension().pacing_delay(bytes, now)
    }

    #[must_use]
    pub fn fec_packet_limit(&self, peer: &Peer) -> Option<usize> {
        peer.extension().fec_packet_limit()
    }

    /// Returns per-peer FEC accounting, or `None` when FEC is disabled.
    #[must_use]
    pub fn fec_stats(&self, peer: &Peer) -> Option<FecStats> {
        peer.extension().fec_stats()
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
        // Mirrors the kernel order in `receive.c`: accounting, keypair
        // promotion, timers and keep-key-fresh run for every authenticated
        // packet, extension frames included, before the extension dispatcher.
        // Treating a CAPS/ACK/FEC frame as ordinary traffic prevents spurious
        // rekeys and feedback resets while FEC or BBR is active.
        peer.observe_udp_window((header_end + plaintext_len) as u32);
        peer.add_rx((plaintext_len + MESSAGE_MINIMUM_LENGTH) as u64);
        if let Some(removed) = peer.promote_keypair(&keypair) {
            self.index.remove_many(&removed);
            peer.set_endpoint_from_packet(source);
            self.timers_handshake_complete(&peer);
            peer.extension().reset_feedback();
            self.flush_staged(&peer, ctx)?;
        } else {
            peer.set_endpoint_from_packet(source);
        }
        self.timers_any_authenticated_packet_traversal(&peer, ctx.rng, ctx.now);
        self.timers_any_authenticated_packet_received(&peer);
        self.keep_key_fresh_receiving(&peer, timings, ctx)?;
        if let Some(kind) = umbrawg_proto::control::extension_kind(plaintext) {
            return self.handle_extension(&peer, kind, counter, plaintext, ctx);
        }
        peer.extension().observe_received(counter, ctx.now);
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

    fn handle_extension<R: RngCore, S: PacketIo>(
        &self,
        peer: &Arc<Peer>,
        kind: ControlKind,
        counter: u64,
        plaintext: &[u8],
        ctx: &mut IoContext<'_, R, S>,
    ) -> Result<IncomingOutcome> {
        match kind {
            ControlKind::Caps => {
                peer.extension().observe_control(counter, ctx.now);
                let Ok(caps) = Caps::decode(plaintext) else {
                    return Ok(IncomingOutcome::Dropped);
                };
                peer.extension().handle_caps(caps, ctx.now);
                Ok(IncomingOutcome::Keepalive)
            }
            ControlKind::Ack => {
                peer.extension().observe_control(counter, ctx.now);
                let Ok(ack) = Ack::decode(plaintext) else {
                    return Ok(IncomingOutcome::Dropped);
                };
                peer.extension().on_ack(&ack, ctx.now);
                Ok(IncomingOutcome::Keepalive)
            }
            ControlKind::FecShard => {
                peer.extension().observe_received(counter, ctx.now);
                let Ok((header, payload)) = FecShardHeader::decode(plaintext) else {
                    peer.extension().note_fec_reject();
                    return Ok(IncomingOutcome::Dropped);
                };
                if header.validate().is_err() {
                    peer.extension().note_fec_reject();
                    return Ok(IncomingOutcome::Dropped);
                }
                let shard = FecShard {
                    block_id: header.block_id,
                    index: header.index,
                    k: header.k,
                    m: header.m,
                    shard_len: header.shard_len,
                    payload,
                };
                let packets = peer.extension().fec_decode(shard, ctx.now);
                let mut delivered = 0usize;
                for packet in packets {
                    let Some((length, address)) = ip_packet_info(&packet) else {
                        continue;
                    };
                    if self.allowed_ips.lookup(address) != Some(peer.id()) {
                        self.incoming_drops.note_allowed_ips();
                        continue;
                    }
                    ctx.io.deliver(peer, &packet[..length]);
                    delivered = delivered.saturating_add(length);
                }
                if delivered > 0 {
                    Ok(IncomingOutcome::Delivered(delivered))
                } else {
                    Ok(IncomingOutcome::Keepalive)
                }
            }
        }
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
        if self.under_load() {
            if !params.disable_cookies {
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
            }
            // Even without the cookie challenge, an initiation must stay
            // rate limited: otherwise `disable_cookies` turns the expensive
            // handshake path into a flood oracle.
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
            // BBR needs time-driven work (PROBE_BW watchdog, PROBE_RTT,
            // stale-record sweep) even when no ACK arrives.
            peer.extension().on_timer(ctx.now);
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

/// How much padding a transport packet may carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PaddingMode {
    /// Regular data packets keep the configured obfuscation padding.
    Data,
    /// ACK, CAPS and FEC shard frames use a bounded random trailer so that a
    /// 32-byte ACK is not inflated to the whole UDP window.
    Control,
}

/// Returns the transmission order of a FEC block's shards.
///
/// The order is a uniformly shuffled permutation, so the block's shards do
/// not leave the interface in the systematic `data..parity` order. The shard
/// header still carries the real index, which is what the receiver uses.
fn shard_order(count: usize, rng: &mut impl RngCore) -> Vec<usize> {
    let mut order: Vec<usize> = (0..count).collect();
    for index in (1..count).rev() {
        let upper = u32::try_from(index.saturating_add(1)).unwrap_or(u32::MAX);
        let swap = usize::try_from(random::below_with(rng, upper)).unwrap_or(0);
        order.swap(index, swap);
    }
    order
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

#[cfg(test)]
mod tests {
    use super::*;

    struct TestRng(u64);

    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            (self.next_u64() >> 32) as u32
        }

        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut value = self.0;
            value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            value ^ (value >> 31)
        }

        fn fill_bytes(&mut self, dst: &mut [u8]) {
            for chunk in dst.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                let length = chunk.len();
                chunk.copy_from_slice(&bytes[..length]);
            }
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> std::result::Result<(), rand_core::Error> {
            self.fill_bytes(dst);
            Ok(())
        }
    }

    #[test]
    fn shard_order_is_a_permutation() {
        let mut rng = TestRng(1);
        for count in 0..=16usize {
            let mut order = shard_order(count, &mut rng);
            assert_eq!(order.len(), count);
            order.sort_unstable();
            assert_eq!(order, (0..count).collect::<Vec<_>>());
        }
    }

    #[test]
    fn shard_order_is_not_fixed() {
        let mut orders = std::collections::HashSet::new();
        for seed in 0..64u64 {
            let mut rng = TestRng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
            orders.insert(shard_order(6, &mut rng));
        }
        assert!(
            orders.len() > 1,
            "shard transmission order must not be constant"
        );
        assert!(
            orders.iter().any(|order| order != &vec![0, 1, 2, 3, 4, 5]),
            "some blocks must leave systematic order"
        );
    }

    struct NullIo;

    impl DatagramSink for NullIo {
        fn send_datagram(
            &mut self,
            _endpoint: SocketAddr,
            _peer: Option<&Peer>,
            _payload: &[u8],
            _gso_size: Option<usize>,
        ) {
        }
    }

    impl PacketIo for NullIo {
        fn deliver(&mut self, _peer: &Peer, _packet: &[u8]) {}
    }

    #[test]
    fn disable_cookies_keeps_the_initiation_rate_limit() {
        use umbrawg_noise::{CookieGenerator, Handshake, StaticIdentity};

        let server_key = Key::from_bytes([0x22; 32]);
        let params = ObfParams {
            disable_cookies: true,
            ..ObfParams::default()
        };
        let device = Device::new(DeviceConfig {
            private_key: Some(server_key),
            obfuscation: params,
            ..DeviceConfig::default()
        })
        .unwrap();
        let server_public = device.public_key().expect("server key is configured");
        device.set_under_load_threshold(1);

        let mut rng = TestRng(11);
        let now = Instant::now();
        let mut io = NullIo;
        let mut scratch = [0u8; 4096];
        let mut outcomes = Vec::new();
        for index in 0..6u8 {
            let identity = StaticIdentity::from_bytes([0x40 + index; 32]);
            let mut handshake =
                Handshake::new(&identity, server_public, Key::from_bytes([0u8; 32]));
            let mut body = handshake
                .create_initiation(
                    &identity,
                    &mut rng,
                    MESSAGE_HANDSHAKE_INITIATION,
                    u32::from(index) + 1,
                    Tai64N::now(),
                )
                .unwrap();
            CookieGenerator::new(server_public)
                .add_macs(&mut body, now)
                .unwrap();
            let source: SocketAddr = format!("10.0.0.1:{}", 1000 + u16::from(index))
                .parse()
                .unwrap();
            let mut config = PeerConfig::new(identity.public_key());
            config.endpoint = Some(source);
            device.add_peer(config).unwrap();
            let mut ctx = IoContext::new(&mut rng, now, &mut scratch, &mut io);
            outcomes.push(
                device
                    .handle_initiation(&mut body, 0, source, &mut ctx)
                    .unwrap(),
            );
        }

        assert!(
            outcomes[..5]
                .iter()
                .all(|outcome| *outcome == IncomingOutcome::Handshake),
            "the first burst may pass before the bucket is drained: {outcomes:?}"
        );
        assert_eq!(
            outcomes[5],
            IncomingOutcome::Dropped,
            "without cookies the rate limiter must still reject initiations"
        );
    }

    #[test]
    fn set_ext_config_is_idempotent_for_peers() {
        use umbrawg_proto::control::{Caps, CapsFlags};

        let device = Device::new(DeviceConfig::default()).unwrap();
        let peer = device
            .add_peer(PeerConfig::new(PublicKey::from_bytes([9u8; 32])))
            .unwrap();
        let config = crate::ExtConfig {
            bbr: crate::BbrMode::Off,
            fec: crate::FecMode::Fixed { k: 2, m: 1 },
            ack_interval: 2,
            max_shard_len: 1900,
        };
        device.set_ext_config(config);
        let now = Instant::now();
        peer.extension().handle_caps(
            Caps {
                flags: CapsFlags::FEC | CapsFlags::ACK,
                ack_interval_packets: 2,
                fec_k: 2,
                fec_m: 1,
            },
            now,
        );
        assert!(peer.extension().fec_tx_active());

        device.set_ext_config(config);
        assert!(
            peer.extension().fec_tx_active(),
            "an unchanged config must not reset peer capabilities"
        );

        device.set_ext_config(crate::ExtConfig {
            fec: crate::FecMode::Fixed { k: 3, m: 1 },
            ..config
        });
        assert!(
            !peer.extension().fec_tx_active(),
            "a changed FEC profile invalidates the negotiated capabilities"
        );
    }
}
