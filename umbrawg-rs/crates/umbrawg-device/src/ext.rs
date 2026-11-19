//! Peer-level protocol extension: capabilities, ACK feedback, BBRv3 and FEC.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use umbrawg_cc::{Ack as BbrAck, Bbr, BbrConfig};
use umbrawg_fec::{FecConfig, FecDecoder, FecEncoder, FecShard};
use umbrawg_proto::control::{Ack, Caps, CapsFlags};

/// BBRv3 mode configured for the device.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BbrMode {
    /// Disabled: no CAPS, no ACKs, no BBR state.
    #[default]
    Off,
    /// Estimate BBR state from feedback but do not pace or limit sending.
    Monitor,
    /// Enable feedback and BBR pacing/limits.
    On,
}

impl BbrMode {
    /// Returns `true` for any mode that needs ACK feedback.
    #[must_use]
    pub const fn enabled(self) -> bool {
        !matches!(self, Self::Off)
    }

    /// Parses the UAPI/config spelling.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" | "0" | "false" | "no" => Some(Self::Off),
            "monitor" => Some(Self::Monitor),
            "on" | "1" | "true" | "yes" => Some(Self::On),
            _ => None,
        }
    }

    /// Returns the UAPI/config spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Monitor => "monitor",
            Self::On => "on",
        }
    }
}

/// FEC mode configured for the device.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FecMode {
    /// Disabled.
    #[default]
    Off,
    /// Adaptive mode: parity is enabled only after measured loss.
    Adaptive,
    /// Fixed `k` data and `m` parity shards.
    Fixed {
        /// Data shards per block.
        k: u8,
        /// Parity shards per block.
        m: u8,
    },
}

impl FecMode {
    /// Parses `off`, `adaptive` or `K:M`.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim().to_ascii_lowercase();
        match value.as_str() {
            "off" | "0" | "false" | "no" => Some(Self::Off),
            "adaptive" => Some(Self::Adaptive),
            other => {
                let (k, m) = other.split_once(':')?;
                Some(Self::Fixed {
                    k: k.parse().ok()?,
                    m: m.parse().ok()?,
                })
            }
        }
    }

    /// Returns the UAPI/config spelling.
    #[must_use]
    pub fn as_string(self) -> String {
        match self {
            Self::Off => "off".to_owned(),
            Self::Adaptive => "adaptive".to_owned(),
            Self::Fixed { k, m } => format!("{k}:{m}"),
        }
    }

    /// Returns the FEC block configuration, using 10+2 for adaptive mode.
    #[must_use]
    pub fn config(self) -> Option<FecConfig> {
        match self {
            Self::Off => None,
            Self::Adaptive => FecConfig::new(10, 2).ok(),
            Self::Fixed { k, m } => FecConfig::new(k, m).ok(),
        }
    }
}

/// Device-wide extension configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtConfig {
    /// BBRv3 mode.
    pub bbr: BbrMode,
    /// FEC mode.
    pub fec: FecMode,
    /// ACK interval in received datagrams.
    pub ack_interval: u16,
    /// Maximum FEC shard payload (including the two-byte length prefix).
    pub max_shard_len: u16,
}

impl Default for ExtConfig {
    fn default() -> Self {
        Self {
            bbr: BbrMode::Off,
            fec: FecMode::Off,
            ack_interval: 2,
            max_shard_len: 1900,
        }
    }
}

impl ExtConfig {
    fn local_caps(self) -> CapsFlags {
        let mut flags = CapsFlags::default();
        if self.bbr.enabled() {
            flags = flags | CapsFlags::BBR | CapsFlags::ACK;
        }
        if self.fec != FecMode::Off {
            flags = flags | CapsFlags::FEC;
            if self.fec == FecMode::Adaptive {
                flags = flags | CapsFlags::FEC_ADAPTIVE;
            }
        }
        flags
    }

    fn bbr_config(self) -> BbrConfig {
        BbrConfig {
            mss: u32::from(self.max_shard_len),
            ..BbrConfig::default()
        }
    }
}

struct AckTracker {
    largest: Option<u64>,
    bitmap: u64,
    received_since: u16,
    last_sent: Option<Instant>,
    largest_at: Instant,
    interval: u16,
    window_received: u32,
    window_highest: u64,
    window_base: u64,
    last_loss: f32,
}

impl AckTracker {
    fn new(interval: u16) -> Self {
        Self {
            largest: None,
            bitmap: 0,
            received_since: 0,
            last_sent: None,
            largest_at: Instant::now(),
            interval: interval.max(1),
            window_received: 0,
            window_highest: 0,
            window_base: 0,
            last_loss: 0.0,
        }
    }

    fn observe(&mut self, counter: u64, now: Instant, count_for_ack: bool) {
        match self.largest {
            None => {
                self.largest = Some(counter);
                self.bitmap = 1;
                self.largest_at = now;
            }
            Some(largest) if counter > largest => {
                let shift = counter - largest;
                self.bitmap = if shift >= 64 {
                    1
                } else {
                    (self.bitmap << shift) | 1
                };
                self.largest = Some(counter);
                self.largest_at = now;
            }
            Some(largest) => {
                let age = largest.saturating_sub(counter);
                if age < 64 {
                    self.bitmap |= 1 << age;
                }
            }
        }
        if count_for_ack {
            self.received_since = self.received_since.saturating_add(1);
        }
        if self.window_received == 0 {
            self.window_base = counter;
        }
        self.window_received = self.window_received.saturating_add(1);
        self.window_highest = self.window_highest.max(counter);
        if self.window_received >= 256 {
            let expected = self
                .window_highest
                .saturating_sub(self.window_base)
                .saturating_add(1);
            let lost = expected.saturating_sub(u64::from(self.window_received));
            self.last_loss = if expected == 0 {
                0.0
            } else {
                lost as f32 / expected as f32
            };
            self.window_received = 0;
            self.window_highest = counter;
            self.window_base = counter.saturating_add(1);
        }
    }

    fn last_loss(&self) -> f32 {
        self.last_loss
    }

    fn due(&self, now: Instant) -> bool {
        self.largest.is_some()
            && (self.received_since >= self.interval
                || self.last_sent.is_none_or(|sent| {
                    now.saturating_duration_since(sent) >= Duration::from_millis(1)
                }))
    }

    fn make(&mut self, now: Instant) -> Option<Ack> {
        let largest = self.largest?;
        if !self.due(now) {
            return None;
        }
        let ack = Ack {
            largest_counter: largest,
            ack_delay_us: u32::try_from(now.saturating_duration_since(self.largest_at).as_micros())
                .unwrap_or(u32::MAX),
            ecn_ce: false,
            received: self.bitmap,
        };
        self.received_since = 0;
        self.last_sent = Some(now);
        Some(ack)
    }

    fn reset(&mut self) {
        self.largest = None;
        self.bitmap = 0;
        self.received_since = 0;
        self.last_sent = None;
        self.window_received = 0;
        self.window_highest = 0;
        self.window_base = 0;
        self.last_loss = 0.0;
    }
}

pub(crate) struct PeerExtension {
    config: ExtConfig,
    local_caps: CapsFlags,
    peer_caps: CapsFlags,
    caps_attempts: u8,
    caps_next: Option<Instant>,
    ack: AckTracker,
    bbr: Option<Bbr>,
    fec_tx: Option<FecEncoder>,
    fec_rx: Option<FecDecoder>,
    fec_active: bool,
    adaptive_observed: u64,
    adaptive_clean_since: Option<Instant>,
    fec_deadline: Option<Instant>,
    pending: VecDeque<Vec<u8>>,
}

impl Default for PeerExtension {
    fn default() -> Self {
        Self::new(ExtConfig::default())
    }
}

impl PeerExtension {
    pub(crate) fn new(config: ExtConfig) -> Self {
        let mut extension = Self {
            config: ExtConfig::default(),
            local_caps: CapsFlags::default(),
            peer_caps: CapsFlags::default(),
            caps_attempts: 0,
            caps_next: None,
            ack: AckTracker::new(2),
            bbr: None,
            fec_tx: None,
            fec_rx: None,
            fec_active: false,
            adaptive_observed: 0,
            adaptive_clean_since: None,
            fec_deadline: None,
            pending: VecDeque::new(),
        };
        extension.configure(config);
        extension
    }

    pub(crate) fn configure(&mut self, config: ExtConfig) {
        self.config = config;
        self.local_caps = config.local_caps();
        let ack_interval = if config.bbr == BbrMode::Off && config.fec == FecMode::Adaptive {
            32
        } else {
            config.ack_interval
        };
        self.ack = AckTracker::new(ack_interval);
        self.bbr = config.bbr.enabled().then(|| Bbr::new(config.bbr_config()));
        self.fec_tx = config
            .fec
            .config()
            .map(|fec| FecEncoder::new(fec, usize::from(config.max_shard_len)));
        self.fec_rx = config.fec.config().map(FecDecoder::new);
        self.peer_caps = CapsFlags::default();
        self.caps_attempts = 0;
        self.caps_next = None;
        self.pending.clear();
        self.fec_deadline = None;
        self.adaptive_clean_since = None;
        self.adaptive_observed = 0;
        self.fec_active = !matches!(config.fec, FecMode::Off | FecMode::Adaptive);
    }

    pub(crate) fn fec_tx_active(&self) -> bool {
        self.fec_active
            && self.peer_caps.contains(CapsFlags::FEC)
            && self.fec_tx.is_some()
    }

    pub(crate) fn fec_active(&self) -> bool {
        self.fec_active && self.peer_caps.contains(CapsFlags::FEC)
    }

    fn update_adaptive(&mut self, now: Instant) {
        if self.config.fec != FecMode::Adaptive {
            return;
        }
        self.adaptive_observed = self.adaptive_observed.saturating_add(1);
        if self.adaptive_observed < 1024 {
            return;
        }
        let loss = self.ack.last_loss();
        if loss > 0.01 {
            self.fec_active = true;
            self.adaptive_clean_since = None;
        } else if self.fec_active {
            if loss < 0.002 {
                let since = *self.adaptive_clean_since.get_or_insert(now);
                if now.saturating_duration_since(since) >= Duration::from_secs(5) {
                    self.fec_active = false;
                    self.fec_tx = self
                        .config
                        .fec
                        .config()
                        .map(|fec| FecEncoder::new(fec, usize::from(self.config.max_shard_len)));
                }
            } else {
                self.adaptive_clean_since = None;
            }
        }
    }

    pub(crate) fn fec_push(
        &mut self,
        packet: &[u8],
        now: Instant,
    ) -> Result<Option<umbrawg_fec::EncodedBlock>, umbrawg_fec::FecError> {
        if !self.fec_tx_active() {
            return Ok(None);
        }
        let result = self
            .fec_tx
            .as_mut()
            .map_or(Ok(None), |encoder| encoder.push(packet));
        match &result {
            Ok(Some(_)) => self.fec_deadline = None,
            Ok(None) if self.fec_deadline.is_none() => {
                self.fec_deadline = Some(now + Duration::from_millis(1));
            }
            _ => {}
        }
        result
    }

    pub(crate) fn fec_flush_due(&mut self, now: Instant) -> Option<umbrawg_fec::EncodedBlock> {
        if !self.fec_tx_active() {
            return None;
        }
        if !self.fec_deadline.is_some_and(|deadline| now >= deadline) {
            return None;
        }
        self.fec_deadline = None;
        self.fec_tx.as_mut().and_then(FecEncoder::flush)
    }

    pub(crate) fn fec_packet_limit(&self) -> Option<usize> {
        if !self.fec_tx_active() {
            return None;
        }
        let config = self.config.fec.config()?;
        let total = config.k() + config.m();
        let blocks = 64usize.checked_div(total)?;
        Some((blocks * config.k()).max(1))
    }

    pub(crate) fn fec_rx(&mut self) -> Option<&mut FecDecoder> {
        if !self.peer_caps.contains(CapsFlags::FEC) {
            return None;
        }
        self.fec_rx.as_mut()
    }

    pub(crate) fn on_send(&mut self, counter: u64, len: usize, now: Instant) {
        if self.config.bbr.enabled() && self.peer_caps.contains(CapsFlags::ACK) {
            if let Some(bbr) = self.bbr.as_mut() {
                bbr.on_send(counter, len, now);
            }
        }
    }

    pub(crate) fn on_ack(&mut self, ack: &Ack, now: Instant) {
        if let Some(bbr) = self.bbr.as_mut() {
            bbr.on_ack(
                &BbrAck::new(
                    ack.largest_counter,
                    ack.received,
                    Duration::from_micros(u64::from(ack.ack_delay_us)),
                    ack.ecn_ce,
                ),
                now,
            );
        }
    }

    pub(crate) fn observe_received(&mut self, counter: u64, now: Instant) {
        self.ack.observe(counter, now, true);
        self.update_adaptive(now);
    }

    pub(crate) fn observe_control(&mut self, counter: u64, now: Instant) {
        self.ack.observe(counter, now, false);
        self.update_adaptive(now);
    }

    pub(crate) fn pacing_delay(&mut self, bytes: usize, now: Instant) -> Duration {
        if self.config.bbr != BbrMode::On || !self.peer_caps.contains(CapsFlags::ACK) {
            return Duration::ZERO;
        }
        self.bbr
            .as_ref()
            .map_or(Duration::ZERO, |bbr| bbr.next_send_delay(bytes, now))
    }

    pub(crate) fn reset_feedback(&mut self) {
        self.ack.reset();
        if self.config.bbr.enabled() {
            self.bbr = Some(Bbr::new(self.config.bbr_config()));
        }
    }

    pub(crate) fn handle_caps(&mut self, caps: Caps) {
        self.peer_caps = caps.flags;
    }

    pub(crate) fn request_caps(&mut self, now: Instant) {
        if self.local_caps.bits() == 0 || self.peer_caps.bits() != 0 || self.caps_attempts >= 3 {
            return;
        }
        if self.caps_next.is_some_and(|next| now < next) {
            return;
        }
        let caps = Caps {
            flags: self.local_caps,
            ack_interval_packets: self.config.ack_interval,
            fec_k: self
                .config
                .fec
                .config()
                .map_or(0, |fec| u8::try_from(fec.k()).unwrap_or(0)),
            fec_m: self
                .config
                .fec
                .config()
                .map_or(0, |fec| u8::try_from(fec.m()).unwrap_or(0)),
        };
        let mut frame = vec![0u8; 32];
        if let Ok(length) = caps.encode(&mut frame) {
            frame.truncate(length);
            self.pending.push_back(frame);
        }
    }

    pub(crate) fn note_caps_sent(&mut self, now: Instant) {
        self.caps_attempts = self.caps_attempts.saturating_add(1);
        self.caps_next = Some(now + Duration::from_secs(2));
    }

    pub(crate) fn pending_control(&mut self, now: Instant) -> Vec<Vec<u8>> {
        self.request_caps(now);
        if let Some(ack) = self.ack.make(now) {
            let mut frame = vec![0u8; 32];
            if let Ok(length) = ack.encode(&mut frame) {
                frame.truncate(length);
                self.pending.push_back(frame);
            }
        }
        self.pending.drain(..).collect()
    }

    pub(crate) fn push_control(&mut self, frame: Vec<u8>) {
        if self.pending.len() < 16 {
            self.pending.push_back(frame);
        }
    }

    pub(crate) fn fec_poll(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let Some(decoder) = self.fec_rx() else {
            return Vec::new();
        };
        decoder
            .poll(now)
            .into_iter()
            .flat_map(|block| block.packets)
            .collect()
    }

    pub(crate) fn fec_decode(&mut self, shard: FecShard<'_>, now: Instant) -> Vec<Vec<u8>> {
        let Some(decoder) = self.fec_rx() else {
            return Vec::new();
        };
        match decoder.push_at(shard, now) {
            Ok(blocks) => {
                let packets: Vec<Vec<u8>> =
                    blocks.into_iter().flat_map(|block| block.packets).collect();
                packets
            }
            Err(_) => Vec::new(),
        }
    }
}

impl std::fmt::Debug for PeerExtension {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PeerExtension")
            .field("bbr", &self.config.bbr)
            .field("fec", &self.config.fec)
            .field("peer_caps", &self.peer_caps.bits())
            .finish_non_exhaustive()
    }
}
