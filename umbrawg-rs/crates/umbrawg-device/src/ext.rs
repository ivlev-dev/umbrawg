//! Peer-level protocol extension: capabilities, ACK feedback, BBRv3 and FEC.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use rand_core::RngCore;
use umbrawg_cc::{Ack as BbrAck, Bbr, BbrConfig, BbrStats};
use umbrawg_fec::{EncodedBlock, FecConfig, FecDecoder, FecEncoder, FecShard};
use umbrawg_proto::control::{Ack, Caps, CapsFlags, ControlKind, FecShardHeader};

/// Maximum number of CAPS frames sent to one peer per handshake.
const CAPS_MAX_ATTEMPTS: u8 = 3;
/// Minimum spacing between two CAPS frames during the fast retry phase.
const CAPS_FAST_RETRY: Duration = Duration::from_millis(250);
/// Spacing of the last CAPS retry before the attempts are exhausted.
const CAPS_SLOW_RETRY: Duration = Duration::from_secs(2);

/// Minimum number of counters one adaptive FEC window must span.
const ADAPTIVE_WINDOW_MIN: u64 = 256;
/// A gap larger than this is treated as a counter restart, not as loss.
const ADAPTIVE_GAP_MAX: u64 = 1 << 20;
/// Total window length before the first window is judged.
const ADAPTIVE_OBSERVE_MIN: u64 = 1024;
/// Loss ratio (in 1/65536 units) that switches adaptive parity on (~1 %).
const ADAPTIVE_ON_LOSS_Q16: u32 = 655;
/// Loss ratio (in 1/65536 units) that allows adaptive parity to switch off (~0.2 %).
const ADAPTIVE_OFF_LOSS_Q16: u32 = 131;
/// How long the loss estimate must stay below [`ADAPTIVE_OFF_LOSS_Q16`].
const ADAPTIVE_CLEAN_TIME: Duration = Duration::from_secs(5);
/// Upper bound on loss reports derived from one ACK bitmap.
const MAX_BITMAP_LOSSES: usize = 32;

/// Lower bound of the randomized ACK interval, in received datagrams.
const ACK_INTERVAL_MIN: u16 = 8;
/// Upper bound of the randomized ACK interval, in received datagrams.
const ACK_INTERVAL_MAX: u16 = 16;
/// Lower bound of the randomized ACK timeout.
const ACK_TIMEOUT_MIN_US: u64 = 2_000;
/// Upper bound of the randomized ACK timeout.
const ACK_TIMEOUT_MAX_US: u64 = 5_000;
/// Lower bound of the randomized partial FEC block deadline.
const FEC_DEADLINE_MIN_US: u64 = 500;
/// Upper bound of the randomized partial FEC block deadline.
const FEC_DEADLINE_MAX_US: u64 = 2_000;

/// Small, fast, non-cryptographic PRNG used for traffic-shape jitter.
///
/// Randomness here only has to defeat simple periodicity detectors; it is not
/// a security boundary. The state is seeded from the OS CSPRNG once per
/// tracker so that two peers started with identical configuration do not
/// produce identical schedules.
struct Jitter {
    state: u64,
}

impl Jitter {
    fn seeded() -> Self {
        Self {
            state: umbrawg_crypto::random::u64() | 1,
        }
    }

    /// Returns a value in `low..=high`. `low` must not exceed `high`.
    fn range_inclusive(&mut self, low: u64, high: u64) -> u64 {
        let span = high.saturating_sub(low).saturating_add(1);
        if span <= 1 {
            return low;
        }
        let value = (u128::from(self.next_u64()) * u128::from(span)) >> 64;
        low.saturating_add(u64::try_from(value).unwrap_or(0))
    }
}

impl RngCore for Jitter {
    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.state;
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

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dst);
        Ok(())
    }
}

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
            Self::Adaptive => FecConfig::new(2, 1).ok(),
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
    /// Nominal ACK interval in received datagrams.
    ///
    /// The actual cadence is drawn from `ack_interval..=16` packets on every
    /// ACK, and the value advertised in CAPS is clamped into `8..=16`. The
    /// default of `8` yields the full `8..=16` distribution.
    pub ack_interval: u16,
    /// Maximum FEC shard payload (including the two-byte length prefix).
    pub max_shard_len: u16,
}

impl Default for ExtConfig {
    fn default() -> Self {
        Self {
            bbr: BbrMode::Off,
            fec: FecMode::Off,
            ack_interval: ACK_INTERVAL_MIN,
            max_shard_len: 1900,
        }
    }
}

impl ExtConfig {
    fn local_caps(self) -> CapsFlags {
        let mut flags = CapsFlags::default();
        if self.bbr.enabled() {
            flags = flags | CapsFlags::BBR;
        }
        if self.bbr.enabled() || self.fec != FecMode::Off {
            flags = flags | CapsFlags::ACK;
        }
        if self.fec != FecMode::Off {
            flags = flags | CapsFlags::FEC;
            if self.fec == FecMode::Adaptive {
                flags = flags | CapsFlags::FEC_ADAPTIVE;
            }
        }
        flags
    }

    fn fec_profile(self) -> Option<(u8, u8)> {
        let config = self.fec.config()?;
        Some((
            u8::try_from(config.k()).ok()?,
            u8::try_from(config.m()).ok()?,
        ))
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
    base_interval: u16,
    interval: u16,
    timeout: Duration,
    jitter: Jitter,
}

impl AckTracker {
    fn new(interval: u16) -> Self {
        let base_interval = interval.clamp(ACK_INTERVAL_MIN, ACK_INTERVAL_MAX);
        let mut jitter = Jitter::seeded();
        let interval = draw_interval(&mut jitter, base_interval);
        let timeout = draw_timeout(&mut jitter);
        Self {
            largest: None,
            bitmap: 0,
            received_since: 0,
            last_sent: None,
            largest_at: Instant::now(),
            base_interval,
            interval,
            timeout,
            jitter,
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
    }

    fn due(&self, now: Instant) -> bool {
        self.largest.is_some()
            && self.received_since > 0
            && (self.received_since >= self.interval
                || self
                    .last_sent
                    .is_none_or(|sent| now.saturating_duration_since(sent) >= self.timeout))
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
        self.interval = draw_interval(&mut self.jitter, self.base_interval);
        self.timeout = draw_timeout(&mut self.jitter);
        Some(ack)
    }

    fn reset(&mut self) {
        self.largest = None;
        self.bitmap = 0;
        self.received_since = 0;
        self.last_sent = None;
    }

    /// Returns the interval advertised in CAPS frames.
    fn advertised_interval(&self) -> u16 {
        self.base_interval
    }
}

/// Kind of payload carried by one encrypted datagram.
///
/// BBR tracks congestion-controlled bytes only: ordinary data and FEC shards
/// carry them, while CAPS/ACK frames and keepalives only consume a wire
/// counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FrameKind {
    /// An encapsulated IP packet.
    Data,
    /// A CAPS, ACK or keepalive frame.
    Control,
    /// One Reed-Solomon shard of a FEC block.
    FecShard,
}

impl FrameKind {
    /// Classifies a plaintext frame by its extension marker.
    pub(crate) fn classify(plaintext: &[u8]) -> Self {
        match umbrawg_proto::control::extension_kind(plaintext) {
            Some(ControlKind::FecShard) => Self::FecShard,
            Some(_) => Self::Control,
            None if plaintext.first().is_some_and(|byte| *byte != 0) => Self::Data,
            None => Self::Control,
        }
    }

    const fn carries_data(self) -> bool {
        matches!(self, Self::Data | Self::FecShard)
    }
}

/// Loss estimator for adaptive FEC.
///
/// Mirrors the kernel implementation: counters are grouped into windows of at
/// least [`ADAPTIVE_WINDOW_MIN`] received sequence numbers, the per-window
/// loss ratio is smoothed with an EWMA (`(old * 3 + new) / 4`) in 1/65536
/// units, and implausible gaps restart the window instead of poisoning the
/// estimate.
#[derive(Clone, Copy, Debug, Default)]
struct LossWindow {
    valid: bool,
    largest: u64,
    base: u64,
    received: u64,
    observed: u64,
    loss_q16: u32,
}

impl LossWindow {
    fn reset(&mut self, counter: u64) {
        *self = Self {
            valid: true,
            largest: counter,
            base: counter,
            received: 1,
            observed: 0,
            loss_q16: 0,
        };
    }

    /// Feeds one received counter; returns `true` when a window was closed.
    fn observe(&mut self, counter: u64) -> bool {
        if !self.valid {
            self.reset(counter);
            return false;
        }
        if counter < self.base {
            // Small backward jumps are reordering; a huge one is a new
            // counter space, for example after a peer restart.
            if self.base.saturating_sub(counter) > ADAPTIVE_GAP_MAX {
                self.reset(counter);
            }
            return false;
        }
        if counter > self.largest {
            self.largest = counter;
        }
        self.received = self.received.saturating_add(1);
        let expected = self.largest.saturating_sub(self.base).saturating_add(1);
        if expected < ADAPTIVE_WINDOW_MIN {
            return false;
        }
        if expected > ADAPTIVE_GAP_MAX {
            self.base = self.largest.saturating_add(1);
            self.received = 0;
            return false;
        }
        let lost = expected.saturating_sub(self.received);
        let sample = u32::try_from(lost.saturating_mul(65_536) / expected).unwrap_or(u32::MAX);
        self.loss_q16 = (self.loss_q16.saturating_mul(3).saturating_add(sample)) / 4;
        self.observed = self.observed.saturating_add(expected);
        self.base = self.largest.saturating_add(1);
        self.received = 0;
        true
    }
}

/// Reports bitmap holes that survived at least one ACK as losses.
///
/// A counter missing from the current bitmap but below the previous ACK's
/// largest counter was already missing one feedback frame earlier, so it is
/// no longer plausible reordering. Counters that left the 64-entry window are
/// released by [`Bbr::on_ack`] (and by the periodic sweep in
/// [`Bbr::on_timer`]) without a separate loss report: the controller cannot
/// tell a datagram lost long ago from one acknowledged long ago.
fn report_bitmap_losses(bbr: &mut Bbr, ack: &Ack, previous: u64, now: Instant) {
    let mut reported = 0usize;
    for bit in 1..64u32 {
        if ack.received & (1u64 << bit) != 0 {
            continue;
        }
        let Some(counter) = ack.largest_counter.checked_sub(u64::from(bit)) else {
            continue;
        };
        if counter >= previous {
            continue;
        }
        bbr.on_loss(counter, now);
        reported += 1;
        if reported >= MAX_BITMAP_LOSSES {
            break;
        }
    }
}

fn draw_interval(jitter: &mut Jitter, base: u16) -> u16 {
    u16::try_from(jitter.range_inclusive(u64::from(base), u64::from(ACK_INTERVAL_MAX)))
        .unwrap_or(ACK_INTERVAL_MAX)
}

fn draw_timeout(jitter: &mut Jitter) -> Duration {
    Duration::from_micros(jitter.range_inclusive(ACK_TIMEOUT_MIN_US, ACK_TIMEOUT_MAX_US))
}

/// One encoded control frame waiting for transmission.
pub(crate) struct ControlFrame {
    kind: ControlKind,
    bytes: Vec<u8>,
}

impl ControlFrame {
    const fn new(kind: ControlKind, bytes: Vec<u8>) -> Self {
        Self { kind, bytes }
    }

    pub(crate) const fn kind(&self) -> ControlKind {
        self.kind
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub(crate) struct PeerExtension {
    config: ExtConfig,
    local_caps: CapsFlags,
    peer_caps: CapsFlags,
    peer_fec_k: u8,
    peer_fec_m: u8,
    caps_attempts: u8,
    caps_next: Option<Instant>,
    caps_last_sent: Option<Instant>,
    caps_seen: Option<Caps>,
    ack: AckTracker,
    bbr: Option<Bbr>,
    fec_tx: Option<FecEncoder>,
    fec_rx: Option<FecDecoder>,
    fec_active: bool,
    loss: LossWindow,
    adaptive_clean_since: Option<Instant>,
    fec_deadline: Option<Instant>,
    jitter: Jitter,
    pending: VecDeque<ControlFrame>,
    bbr_queue: VecDeque<Vec<u8>>,
    bbr_queued_bytes: usize,
    last_ack_largest: Option<u64>,
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
            peer_fec_k: 0,
            peer_fec_m: 0,
            caps_attempts: 0,
            caps_next: None,
            caps_last_sent: None,
            caps_seen: None,
            ack: AckTracker::new(ACK_INTERVAL_MIN),
            bbr: None,
            fec_tx: None,
            fec_rx: None,
            fec_active: false,
            loss: LossWindow::default(),
            adaptive_clean_since: None,
            fec_deadline: None,
            jitter: Jitter::seeded(),
            pending: VecDeque::new(),
            bbr_queue: VecDeque::new(),
            bbr_queued_bytes: 0,
            last_ack_largest: None,
        };
        extension.apply(config);
        extension
    }

    /// Applies a device-wide configuration change.
    ///
    /// A configuration that did not change is a no-op: the peer keeps its
    /// negotiated capabilities and all live state (encoder queue, decoder,
    /// ACK and BBR trackers). A real change first flushes queued packets so
    /// nothing is lost, then replaces the affected state.
    pub(crate) fn configure(&mut self, config: ExtConfig) {
        if self.config == config {
            return;
        }
        self.apply(config);
    }

    fn apply(&mut self, config: ExtConfig) {
        let previous = self.config;
        // Preserve packets accumulated by the outgoing encoder: the partial
        // block is turned into explicit shard frames and stays queued.
        self.flush_encoder_frames();

        self.config = config;
        self.local_caps = config.local_caps();
        // ACKs are sent every 8..=16 datagrams or after a 2..=5 ms timeout,
        // whichever comes first. The cadence is re-drawn after every ACK so
        // that the feedback stream does not look like a perfect clock.
        self.ack = AckTracker::new(config.ack_interval);

        let fec_changed = config.fec != previous.fec
            || (config.fec.config().is_some() && config.max_shard_len != previous.max_shard_len);
        if fec_changed {
            let fec = config.fec.config();
            self.fec_tx = fec.map(|fec| FecEncoder::new(fec, usize::from(config.max_shard_len)));
            self.fec_rx = fec.map(FecDecoder::new);
            self.fec_active = !matches!(config.fec, FecMode::Off | FecMode::Adaptive);
            self.loss = LossWindow::default();
            self.adaptive_clean_since = None;
            self.fec_deadline = None;
        }

        let bbr_changed = config.bbr != previous.bbr
            || (config.bbr.enabled() && config.max_shard_len != previous.max_shard_len);
        if config.bbr != BbrMode::On {
            if config.bbr.enabled() {
                self.bbr = Some(Bbr::new(config.bbr_config()));
            } else {
                self.bbr = None;
            }
            // Only the `On` pacer drains the queue; anything else would strand
            // the packets there forever.
            self.bbr_queue.clear();
            self.bbr_queued_bytes = 0;
        } else if bbr_changed || self.bbr.is_none() {
            self.bbr = Some(Bbr::new(config.bbr_config()));
        }

        // Only a change in what we advertise (or in our FEC block shape)
        // invalidates what the peer told us. Anything else must keep the
        // negotiated capabilities intact.
        if self.local_caps != previous.local_caps()
            || config.fec_profile() != previous.fec_profile()
        {
            self.reset_caps();
        }
    }

    /// Emits the packets held by the outgoing encoder as queued shard frames.
    ///
    /// The frames are sent by the next control flush with the current
    /// keypair, so a reconfiguration or a keypair switch does not silently
    /// drop a partially filled block.
    fn flush_encoder_frames(&mut self) {
        let block = self
            .fec_tx
            .as_mut()
            .and_then(|encoder| encoder.flush_with_rng(&mut self.jitter));
        if let Some(block) = block {
            self.queue_fec_frames(&block);
        }
        self.fec_deadline = None;
    }

    fn queue_fec_frames(&mut self, block: &EncodedBlock) {
        for (index, shard) in block.shards.iter().enumerate() {
            let Ok(index) = u8::try_from(index) else {
                break;
            };
            let header = FecShardHeader {
                block_id: block.block_id,
                index,
                k: block.k,
                m: block.m,
                parity: index >= block.k,
                shard_len: block.shard_len,
            };
            let mut frame = vec![0u8; 32 + shard.len()];
            let Ok(header_len) = header.encode(&mut frame) else {
                break;
            };
            frame.truncate(header_len);
            frame.extend_from_slice(shard);
            self.push_control(ControlFrame::new(ControlKind::FecShard, frame));
        }
    }

    fn reset_caps(&mut self) {
        self.peer_caps = CapsFlags::default();
        self.peer_fec_k = 0;
        self.peer_fec_m = 0;
        self.caps_attempts = 0;
        self.caps_next = None;
        self.caps_last_sent = None;
        self.caps_seen = None;
    }

    /// `true` when the peer advertised exactly the FEC block shape we encode.
    fn fec_profile_matches(&self) -> bool {
        self.config
            .fec_profile()
            .is_some_and(|profile| profile == (self.peer_fec_k, self.peer_fec_m))
    }

    pub(crate) fn fec_tx_active(&self) -> bool {
        self.fec_active
            && self.fec_tx.is_some()
            && self.peer_caps.contains(CapsFlags::FEC)
            && self.fec_profile_matches()
    }

    pub(crate) fn fec_active(&self) -> bool {
        self.fec_active && self.peer_caps.contains(CapsFlags::FEC)
    }

    /// Feeds one received counter to the adaptive loss estimator.
    ///
    /// The estimator follows the kernel: a window closes after at least 256
    /// counters, the loss ratio is an EWMA, parity is switched on above 1 %
    /// once 1024 counters were observed and off below 0.2 % after five clean
    /// seconds.
    fn observe_adaptive(&mut self, counter: u64, now: Instant) {
        if self.config.fec != FecMode::Adaptive {
            return;
        }
        if !self.loss.observe(counter) {
            return;
        }
        if !self.fec_active {
            if self.loss.observed >= ADAPTIVE_OBSERVE_MIN
                && self.loss.loss_q16 > ADAPTIVE_ON_LOSS_Q16
            {
                self.fec_active = true;
                self.adaptive_clean_since = None;
            }
        } else if self.loss.loss_q16 < ADAPTIVE_OFF_LOSS_Q16 {
            let since = *self.adaptive_clean_since.get_or_insert(now);
            if now.saturating_duration_since(since) >= ADAPTIVE_CLEAN_TIME {
                self.fec_active = false;
                self.adaptive_clean_since = None;
                // Do not strand a partially filled block: emit it before
                // parity generation stops.
                self.flush_encoder_frames();
            }
        } else {
            self.adaptive_clean_since = None;
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
        let jitter = &mut self.jitter;
        let result = self
            .fec_tx
            .as_mut()
            .map_or(Ok(None), |encoder| encoder.push_with_rng(packet, jitter));
        match &result {
            Ok(Some(_)) => self.fec_deadline = None,
            Ok(None) if self.fec_deadline.is_none() => {
                let delay = self
                    .jitter
                    .range_inclusive(FEC_DEADLINE_MIN_US, FEC_DEADLINE_MAX_US);
                self.fec_deadline = Some(now + Duration::from_micros(delay));
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
        let jitter = &mut self.jitter;
        self.fec_tx
            .as_mut()
            .and_then(|encoder| encoder.flush_with_rng(jitter))
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

    /// Accounts for one encrypted datagram leaving the device.
    ///
    /// Every frame consumes a wire counter so that a valid ACK naming a
    /// control or FEC frame is not rejected as fabricated. Only frames that
    /// carry congestion-controlled bytes (data and FEC shards) enter the
    /// in-flight accounting and charge the pacer.
    pub(crate) fn on_packet_sent(
        &mut self,
        counter: u64,
        len: usize,
        kind: FrameKind,
        now: Instant,
    ) {
        if let Some(bbr) = self.bbr.as_mut() {
            bbr.note_sent_counter(counter);
        }
        if kind.carries_data() {
            self.on_send(counter, len, now);
        }
    }

    pub(crate) fn on_ack(&mut self, ack: &Ack, now: Instant) {
        let Some(bbr) = self.bbr.as_mut() else {
            return;
        };
        bbr.on_ack(
            &BbrAck::new(
                ack.largest_counter,
                ack.received,
                Duration::from_micros(u64::from(ack.ack_delay_us)),
                ack.ecn_ce,
            ),
            now,
        );
        // A hole that was already missing one ACK ago is a real loss, not
        // reordering: report it so STARTUP can exit and `inflight_hi` can be
        // cut. The very first ACK only establishes the reference point.
        let previous = self.last_ack_largest;
        self.last_ack_largest = Some(previous.map_or(ack.largest_counter, |largest| {
            largest.max(ack.largest_counter)
        }));
        if let Some(previous) = previous {
            if ack.largest_counter >= previous {
                report_bitmap_losses(bbr, ack, previous, now);
            }
        }
    }

    /// Drives the time-based parts of BBR: the `PROBE_BW` phase watchdog,
    /// `PROBE_RTT` entry/exit and the stale-record sweep. Without an ACK the
    /// controller would never leave STARTUP or refresh `RTprop`.
    pub(crate) fn on_timer(&mut self, now: Instant) {
        if self.config.bbr != BbrMode::On {
            return;
        }
        if let Some(bbr) = self.bbr.as_mut() {
            bbr.on_timer(now);
        }
    }

    pub(crate) fn bbr_stats(&self) -> Option<BbrStats> {
        self.bbr.as_ref().map(Bbr::stats)
    }

    pub(crate) fn observe_received(&mut self, counter: u64, now: Instant) {
        self.ack.observe(counter, now, true);
        self.observe_adaptive(counter, now);
    }

    pub(crate) fn observe_control(&mut self, counter: u64, now: Instant) {
        self.ack.observe(counter, now, false);
        self.observe_adaptive(counter, now);
    }

    pub(crate) fn bbr_queue_active(&self) -> bool {
        self.config.bbr == BbrMode::On && self.peer_caps.contains(CapsFlags::ACK)
    }

    pub(crate) fn bbr_enqueue(&mut self, packet: &[u8]) -> bool {
        const MAX_PACKETS: usize = 1024;
        const MAX_BYTES: usize = 4 * 1024 * 1024;
        if self.bbr_queue.len() >= MAX_PACKETS
            || self.bbr_queued_bytes.saturating_add(packet.len()) > MAX_BYTES
        {
            return false;
        }
        self.bbr_queued_bytes = self.bbr_queued_bytes.saturating_add(packet.len());
        self.bbr_queue.push_back(packet.to_vec());
        true
    }

    pub(crate) fn bbr_drain(&mut self, now: Instant, max_packets: usize) -> Vec<Vec<u8>> {
        let Some(bbr) = self.bbr.as_ref() else {
            return Vec::new();
        };
        if self.config.bbr != BbrMode::On {
            return Vec::new();
        }
        let mut output = Vec::new();
        while output.len() < max_packets {
            let Some(front) = self.bbr_queue.front() else {
                break;
            };
            if bbr.next_send_delay(front.len(), now) > Duration::from_micros(500) {
                break;
            }
            let packet = self.bbr_queue.pop_front().expect("front exists");
            self.bbr_queued_bytes = self.bbr_queued_bytes.saturating_sub(packet.len());
            output.push(packet);
        }
        output
    }

    pub(crate) fn pacing_delay(&mut self, bytes: usize, now: Instant) -> Duration {
        if self.config.bbr != BbrMode::On || !self.peer_caps.contains(CapsFlags::ACK) {
            return Duration::ZERO;
        }
        self.bbr
            .as_ref()
            .map_or(Duration::ZERO, |bbr| bbr.next_send_delay(bytes, now))
    }

    /// Resets all feedback state after the peer installed a new keypair.
    ///
    /// Besides ACK/BBR/CAPS, the FEC state is rebuilt: the decoder's block
    /// clock is discarded (a restarted peer starts again at `block_id = 0`,
    /// which the old clock would reject forever) and the encoder queue is
    /// flushed into explicit shard frames instead of being dropped.
    pub(crate) fn reset_feedback(&mut self) {
        self.flush_encoder_frames();
        self.ack.reset();
        self.last_ack_largest = None;
        if self.config.bbr.enabled() {
            self.bbr = Some(Bbr::new(self.config.bbr_config()));
        } else {
            self.bbr = None;
        }
        if let Some(fec) = self.config.fec.config() {
            self.fec_rx = Some(FecDecoder::new(fec));
        }
        self.loss = LossWindow::default();
        self.adaptive_clean_since = None;
        // A new handshake means the peer's view of our capabilities is
        // unknown again: restart the bounded CAPS exchange.
        self.reset_caps();
    }

    pub(crate) fn handle_caps(&mut self, caps: Caps, now: Instant) {
        let changed = self.caps_seen != Some(caps);
        self.caps_seen = Some(caps);
        self.peer_caps = caps.flags;
        self.peer_fec_k = caps.fec_k;
        self.peer_fec_m = caps.fec_m;
        if !changed && self.caps_attempts > 0 {
            return;
        }
        // Our CAPS may have been sent before the peer installed the new
        // keypair, or the peer changed its profile. Answer once, quickly,
        // while the attempt counter keeps the exchange bounded.
        self.schedule_caps(now);
    }

    fn schedule_caps(&mut self, now: Instant) {
        if self.local_caps.bits() == 0 {
            return;
        }
        // Hearing from the peer is a fresh stimulus: our earlier frames may
        // have been sent before it installed the keypair and were lost. Mirror
        // the kernel and hand back exactly one attempt, so a spent budget can
        // still answer a changed peer profile — but only once per stimulus.
        if self.caps_attempts >= CAPS_MAX_ATTEMPTS {
            self.caps_attempts = CAPS_MAX_ATTEMPTS - 1;
        }
        let delay = if self.caps_attempts == 0 {
            Duration::ZERO
        } else {
            CAPS_FAST_RETRY
        };
        let not_before = self
            .caps_last_sent
            .map_or(now, |sent| sent + CAPS_FAST_RETRY);
        self.caps_next = Some(not_before.max(now + delay));
    }

    pub(crate) fn request_caps(&mut self, now: Instant) {
        let (fec_k, fec_m) = self.config.fec_profile().unwrap_or((0, 0));
        if self.local_caps.bits() == 0 || self.caps_attempts >= CAPS_MAX_ATTEMPTS {
            return;
        }
        if self.caps_next.is_some_and(|next| now < next) {
            return;
        }
        if self
            .pending
            .iter()
            .any(|frame| frame.kind() == ControlKind::Caps)
        {
            return;
        }
        let caps = Caps {
            flags: self.local_caps,
            ack_interval_packets: self.ack.advertised_interval(),
            fec_k,
            fec_m,
        };
        let mut frame = vec![0u8; 32];
        if let Ok(length) = caps.encode(&mut frame) {
            frame.truncate(length);
            self.pending
                .push_back(ControlFrame::new(ControlKind::Caps, frame));
        }
    }

    /// Accounts for one transmitted control frame.
    ///
    /// Only a CAPS frame spends an attempt: ACK frames share the control
    /// path but must never exhaust the CAPS budget.
    pub(crate) fn note_frame_sent(&mut self, kind: ControlKind, now: Instant) {
        if kind != ControlKind::Caps {
            return;
        }
        self.caps_attempts = self.caps_attempts.saturating_add(1).min(CAPS_MAX_ATTEMPTS);
        self.caps_last_sent = Some(now);
        // Retry quickly while attempts remain, then leave a long gap before
        // an eventual caller-driven reconfiguration.
        let delay = if self.caps_attempts < CAPS_MAX_ATTEMPTS {
            CAPS_FAST_RETRY
        } else {
            CAPS_SLOW_RETRY
        };
        self.caps_next = Some(now + delay);
    }

    pub(crate) fn pending_control(&mut self, now: Instant) -> Vec<ControlFrame> {
        if self.local_caps.bits() == 0 {
            return Vec::new();
        }
        self.request_caps(now);
        if let Some(ack) = self.ack.make(now) {
            let mut frame = vec![0u8; 32];
            if let Ok(length) = ack.encode(&mut frame) {
                frame.truncate(length);
                self.pending
                    .push_back(ControlFrame::new(ControlKind::Ack, frame));
            }
        }
        self.pending.drain(..).collect()
    }

    pub(crate) fn push_control(&mut self, frame: ControlFrame) {
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

#[cfg(test)]
mod tests {
    use super::*;

    const BBR_CONFIG: ExtConfig = ExtConfig {
        bbr: BbrMode::On,
        fec: FecMode::Off,
        ack_interval: 2,
        max_shard_len: 1900,
    };

    fn caps(flags: CapsFlags, fec_k: u8, fec_m: u8) -> Caps {
        Caps {
            flags,
            ack_interval_packets: 2,
            fec_k,
            fec_m,
        }
    }

    fn kinds(frames: &[ControlFrame]) -> Vec<ControlKind> {
        frames.iter().map(ControlFrame::kind).collect()
    }

    #[test]
    fn ack_is_not_produced_without_new_received_data() {
        let base = Instant::now();
        let mut tracker = AckTracker::new(1);
        assert!(!tracker.due(base));
        assert!(tracker.make(base).is_none());

        tracker.observe(7, base, true);
        assert!(tracker.due(base));
        assert!(tracker.make(base).is_some());
        assert!(!tracker.due(base + Duration::from_secs(1)));
        assert!(tracker.make(base + Duration::from_secs(1)).is_none());
    }

    #[test]
    fn acks_are_neither_per_packet_nor_perfectly_paced() {
        let base = Instant::now();
        let mut tracker = AckTracker::new(2);
        let mut now = base;
        let mut intervals = Vec::new();
        let mut timeouts = Vec::new();
        let mut counter = 0u64;
        for _ in 0..512 {
            now += Duration::from_micros(250);
            counter += 1;
            tracker.observe(counter, now, true);
            if tracker.make(now).is_some() {
                intervals.push(tracker.interval);
                timeouts.push(tracker.timeout);
            }
        }
        assert!(intervals.len() > 8, "ACKs must still flow");
        for interval in &intervals {
            assert!((ACK_INTERVAL_MIN..=ACK_INTERVAL_MAX).contains(interval));
        }
        for timeout in &timeouts {
            assert!(*timeout >= Duration::from_micros(ACK_TIMEOUT_MIN_US));
            assert!(*timeout <= Duration::from_micros(ACK_TIMEOUT_MAX_US));
        }
        intervals.sort_unstable();
        intervals.dedup();
        timeouts.sort_unstable();
        timeouts.dedup();
        assert!(intervals.len() > 1, "ACK packet interval must vary");
        assert!(timeouts.len() > 1, "ACK timeout must vary");
    }

    #[test]
    fn ack_interval_is_clamped_into_the_jitter_window() {
        let small = AckTracker::new(0);
        assert_eq!(small.advertised_interval(), ACK_INTERVAL_MIN);
        let large = AckTracker::new(u16::MAX);
        assert_eq!(large.advertised_interval(), ACK_INTERVAL_MAX);
    }

    #[test]
    fn control_frames_are_typed_by_kind() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(BBR_CONFIG);
        let frames = ext.pending_control(base);
        assert_eq!(kinds(&frames), vec![ControlKind::Caps]);
        assert_eq!(
            umbrawg_proto::control::extension_kind(frames[0].bytes()),
            Some(ControlKind::Caps)
        );
    }

    #[test]
    fn acks_do_not_consume_caps_attempts() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(BBR_CONFIG);
        let frames = ext.pending_control(base);
        assert_eq!(kinds(&frames), vec![ControlKind::Caps]);
        for frame in &frames {
            ext.note_frame_sent(frame.kind(), base);
        }
        assert_eq!(ext.caps_attempts, 1);

        let mut now = base;
        for counter in 0..32u64 {
            now += Duration::from_millis(5);
            ext.observe_received(counter, now);
            let frames = ext.pending_control(now);
            assert!(
                frames.iter().all(|frame| frame.kind() != ControlKind::Caps),
                "CAPS resent before the retry interval elapsed"
            );
            for frame in &frames {
                ext.note_frame_sent(frame.kind(), now);
            }
        }
        assert_eq!(ext.caps_attempts, 1);
    }

    #[test]
    fn peer_caps_answers_once_with_a_fast_bounded_retry() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(BBR_CONFIG);
        let peer = caps(CapsFlags::BBR | CapsFlags::ACK, 0, 0);

        ext.handle_caps(peer, base);
        let frames = ext.pending_control(base);
        assert_eq!(kinds(&frames), vec![ControlKind::Caps]);
        ext.note_frame_sent(ControlKind::Caps, base);
        assert_eq!(ext.caps_attempts, 1);
        assert_eq!(ext.caps_next, Some(base + CAPS_FAST_RETRY));

        ext.handle_caps(peer, base + Duration::from_millis(10));
        assert!(ext
            .pending_control(base + Duration::from_millis(10))
            .is_empty());
        assert_eq!(ext.caps_attempts, 1);

        let changed = caps(CapsFlags::BBR | CapsFlags::ACK | CapsFlags::FEC, 2, 1);
        ext.handle_caps(changed, base + Duration::from_millis(20));
        let earliest = base + Duration::from_millis(20) + CAPS_FAST_RETRY;
        assert_eq!(ext.caps_next, Some(earliest));
        assert!(ext
            .pending_control(base + Duration::from_millis(100))
            .is_empty());

        let resent = ext.pending_control(earliest);
        assert_eq!(kinds(&resent), vec![ControlKind::Caps]);
        ext.note_frame_sent(ControlKind::Caps, earliest);
        assert_eq!(ext.caps_attempts, 2);

        let next_earliest = earliest + CAPS_FAST_RETRY;
        assert!(ext
            .pending_control(next_earliest - Duration::from_millis(1))
            .is_empty());
        let last = ext.pending_control(next_earliest);
        assert_eq!(kinds(&last), vec![ControlKind::Caps]);
        ext.note_frame_sent(ControlKind::Caps, next_earliest);
        assert_eq!(ext.caps_attempts, CAPS_MAX_ATTEMPTS);
        assert_eq!(ext.caps_next, Some(next_earliest + CAPS_SLOW_RETRY));

        ext.handle_caps(changed, next_earliest);
        assert!(ext
            .pending_control(next_earliest + CAPS_SLOW_RETRY)
            .is_empty());
        assert_eq!(ext.caps_attempts, CAPS_MAX_ATTEMPTS);
    }

    #[test]
    fn fec_tx_requires_a_matching_peer_profile() {
        let now = Instant::now();
        let mut ext = PeerExtension::new(ExtConfig {
            bbr: BbrMode::Off,
            fec: FecMode::Fixed { k: 4, m: 2 },
            ack_interval: 2,
            max_shard_len: 1900,
        });
        assert!(!ext.fec_tx_active());

        ext.handle_caps(caps(CapsFlags::FEC, 4, 1), now);
        assert!(!ext.fec_tx_active());

        ext.handle_caps(caps(CapsFlags::FEC, 4, 2), now);
        assert!(ext.fec_tx_active());

        ext.handle_caps(caps(CapsFlags::FEC, 2, 1), now);
        assert!(!ext.fec_tx_active());
    }

    #[test]
    fn fec_partial_block_deadline_is_jittered() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(ExtConfig {
            bbr: BbrMode::Off,
            fec: FecMode::Fixed { k: 2, m: 1 },
            ack_interval: 12,
            max_shard_len: 1900,
        });
        ext.handle_caps(caps(CapsFlags::FEC | CapsFlags::ACK, 2, 1), base);
        let mut delays = Vec::new();
        let mut now = base;
        for _ in 0..64 {
            assert!(ext.fec_push(&[9u8; 20], now).unwrap().is_none());
            let deadline = ext.fec_deadline.expect("deadline is armed");
            delays.push(deadline.saturating_duration_since(now));
            now += Duration::from_millis(3);
            let block = ext.fec_flush_due(now).expect("partial block is due");
            assert_eq!(block.m, 0);
            assert!(usize::from(block.shard_len) >= 22);
        }
        for delay in &delays {
            assert!(*delay >= Duration::from_micros(FEC_DEADLINE_MIN_US));
            assert!(*delay <= Duration::from_micros(FEC_DEADLINE_MAX_US));
        }
        delays.sort_unstable();
        delays.dedup();
        assert!(delays.len() > 1, "partial block deadline must vary");
    }

    #[test]
    fn adaptive_profile_is_advertised_as_two_to_one() {
        let now = Instant::now();
        let mut ext = PeerExtension::new(ExtConfig {
            bbr: BbrMode::Off,
            fec: FecMode::Adaptive,
            ack_interval: 2,
            max_shard_len: 1900,
        });
        let frames = ext.pending_control(now);
        assert_eq!(kinds(&frames), vec![ControlKind::Caps]);
        let decoded = Caps::decode(frames[0].bytes()).expect("caps frame decodes");
        assert_eq!((decoded.fec_k, decoded.fec_m), (2, 1));
        assert!((ACK_INTERVAL_MIN..=ACK_INTERVAL_MAX).contains(&ext.ack.interval));
        assert!((ACK_INTERVAL_MIN..=ACK_INTERVAL_MAX).contains(&decoded.ack_interval_packets));

        ext.handle_caps(caps(CapsFlags::FEC | CapsFlags::FEC_ADAPTIVE, 2, 1), now);
        ext.fec_active = true;
        assert!(ext.fec_tx_active());

        ext.handle_caps(caps(CapsFlags::FEC | CapsFlags::FEC_ADAPTIVE, 3, 1), now);
        assert!(!ext.fec_tx_active());
    }

    #[test]
    fn ack_flag_is_advertised_whenever_feedback_is_needed() {
        let disabled = ExtConfig::default();
        assert_eq!(disabled.local_caps().bits(), 0);

        let fec_only = ExtConfig {
            bbr: BbrMode::Off,
            fec: FecMode::Fixed { k: 2, m: 1 },
            ..ExtConfig::default()
        };
        let flags = fec_only.local_caps();
        assert!(flags.contains(CapsFlags::FEC));
        assert!(flags.contains(CapsFlags::ACK));
        assert!(!flags.contains(CapsFlags::BBR));

        let bbr_only = ExtConfig {
            bbr: BbrMode::Monitor,
            ..ExtConfig::default()
        };
        let flags = bbr_only.local_caps();
        assert!(flags.contains(CapsFlags::BBR));
        assert!(flags.contains(CapsFlags::ACK));
    }

    #[test]
    fn disabled_extension_queues_no_control_frames() {
        let base = Instant::now();
        let mut ext = PeerExtension::default();
        ext.observe_received(11, base);
        assert!(ext
            .pending_control(base + Duration::from_millis(50))
            .is_empty());
    }

    #[test]
    fn control_counters_are_reported_to_bbr() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(BBR_CONFIG);
        ext.handle_caps(caps(CapsFlags::BBR | CapsFlags::ACK, 0, 0), base);

        ext.on_packet_sent(0, 1400, FrameKind::Data, base);
        ext.on_packet_sent(7, 48, FrameKind::Control, base);
        let ack = Ack {
            largest_counter: 7,
            ack_delay_us: 0,
            ecn_ce: false,
            received: 1 << 7,
        };
        ext.on_ack(&ack, base + Duration::from_millis(10));

        let bbr = ext.bbr.as_ref().expect("bbr is enabled");
        assert_eq!(bbr.stats().delivered, 1400);
        assert_eq!(bbr.inflight(), 0);
    }

    #[test]
    fn peer_caps_grants_one_extra_send_after_budget_is_spent() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(BBR_CONFIG);
        ext.caps_attempts = CAPS_MAX_ATTEMPTS;
        ext.caps_last_sent = Some(base);
        ext.caps_next = Some(base + CAPS_SLOW_RETRY);
        ext.caps_seen = Some(caps(CapsFlags::ACK, 0, 0));

        let changed = caps(CapsFlags::ACK | CapsFlags::FEC, 2, 1);
        ext.handle_caps(changed, base + Duration::from_millis(10));
        assert_eq!(ext.caps_attempts, CAPS_MAX_ATTEMPTS - 1);
        assert!(ext
            .pending_control(base + Duration::from_millis(100))
            .is_empty());

        let earliest = base + Duration::from_millis(10) + CAPS_FAST_RETRY;
        let resent = ext.pending_control(earliest);
        assert_eq!(kinds(&resent), vec![ControlKind::Caps]);
        ext.note_frame_sent(ControlKind::Caps, earliest);
        assert_eq!(ext.caps_attempts, CAPS_MAX_ATTEMPTS);

        ext.handle_caps(changed, earliest + Duration::from_millis(1));
        assert_eq!(ext.caps_attempts, CAPS_MAX_ATTEMPTS);
        assert!(ext.pending_control(earliest + CAPS_SLOW_RETRY).is_empty());
    }

    #[test]
    fn reset_feedback_restarts_caps_exchange() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(BBR_CONFIG);
        let frames = ext.pending_control(base);
        for frame in &frames {
            ext.note_frame_sent(frame.kind(), base);
        }
        ext.handle_caps(caps(CapsFlags::ACK, 0, 0), base);
        assert_eq!(ext.caps_attempts, 1);

        ext.reset_feedback();
        assert_eq!(ext.caps_attempts, 0);
        assert!(ext.caps_seen.is_none());
        assert!(ext.caps_last_sent.is_none());
        assert!(ext.caps_next.is_none());
        assert_eq!(ext.peer_caps.bits(), 0);
    }

    fn fec_block_fixture() -> (u16, Vec<Vec<u8>>) {
        let mut encoder = FecEncoder::new(FecConfig::new(2, 1).unwrap(), 1900);
        let mut block = None;
        for index in 0..2u8 {
            block = encoder.push(&[index; 8]).unwrap().or(block);
        }
        let block = block.expect("block");
        (block.shard_len, block.shards)
    }

    fn push_block(
        ext: &mut PeerExtension,
        block_id: u32,
        shard_len: u16,
        shards: &[Vec<u8>],
        now: Instant,
    ) -> usize {
        let mut packets = 0;
        for (index, payload) in shards.iter().enumerate() {
            let index = u8::try_from(index).unwrap();
            packets += ext
                .fec_decode(
                    FecShard {
                        block_id,
                        index,
                        k: 2,
                        m: 1,
                        shard_len,
                        payload,
                    },
                    now,
                )
                .len();
        }
        packets
    }

    #[test]
    fn loss_window_uses_the_kernel_ewma() {
        let mut window = LossWindow::default();
        window.observe(0);
        for counter in 1..=255u64 {
            window.observe(counter);
        }
        assert_eq!(window.loss_q16, 0);
        assert_eq!(window.observed, 256);

        // One missing counter in the next window: 1/256 == 256 in q16 units,
        // smoothed as (old * 3 + new) / 4.
        for counter in 257..=511u64 {
            window.observe(counter);
        }
        assert_eq!(window.loss_q16, 64);
        assert_eq!(window.observed, 512);

        for counter in 513..=767u64 {
            window.observe(counter);
        }
        assert_eq!(window.loss_q16, 112);
        assert_eq!(window.observed, 768);
    }

    #[test]
    fn loss_window_restarts_on_implausible_gaps() {
        let mut window = LossWindow::default();
        window.observe(10);
        let forward = 10 + ADAPTIVE_GAP_MAX + 1;
        assert!(!window.observe(forward));
        assert_eq!(window.observed, 0);
        assert_eq!(window.base, forward + 1);

        let mut window = LossWindow::default();
        window.observe(2 * ADAPTIVE_GAP_MAX);
        window.observe(2 * ADAPTIVE_GAP_MAX);
        assert!(!window.observe(1));
        assert_eq!(window.observed, 0);
        assert!(window.valid);
        assert_eq!(window.largest, 1);
    }

    #[test]
    fn adaptive_parity_follows_loss_with_hysteresis() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(ExtConfig {
            bbr: BbrMode::Off,
            fec: FecMode::Adaptive,
            ack_interval: 2,
            max_shard_len: 1900,
        });

        let mut counter = 0u64;
        for _ in 0..4 {
            let start = counter;
            while counter < start + 256 {
                if !(10..15).contains(&(counter - start)) {
                    ext.observe_received(counter, base);
                }
                counter += 1;
            }
        }
        assert!(ext.fec_active, "1.95% loss must enable parity");

        // A couple of clean windows are not enough: the switch-off has to
        // survive five seconds below 0.2%.
        let mut now = base;
        for _ in 0..2 {
            let start = counter;
            now += Duration::from_secs(1);
            while counter < start + 256 {
                ext.observe_received(counter, now);
                counter += 1;
            }
        }
        assert!(ext.fec_active);

        for _ in 0..16 {
            let start = counter;
            now += Duration::from_secs(1);
            while counter < start + 256 {
                ext.observe_received(counter, now);
                counter += 1;
            }
        }
        assert!(!ext.fec_active, "parity must switch off after clean time");
    }

    #[test]
    fn configure_is_idempotent() {
        let base = Instant::now();
        let config = ExtConfig {
            bbr: BbrMode::Monitor,
            fec: FecMode::Fixed { k: 2, m: 1 },
            ack_interval: 2,
            max_shard_len: 1900,
        };
        let mut ext = PeerExtension::new(config);
        ext.handle_caps(caps(CapsFlags::FEC | CapsFlags::ACK, 2, 1), base);
        assert!(ext.fec_tx_active());
        assert!(ext.fec_push(&[1u8; 20], base).unwrap().is_none());
        assert_eq!(ext.fec_tx.as_ref().unwrap().pending(), 1);

        ext.configure(config);

        assert!(ext.fec_tx_active(), "unchanged config must keep peer caps");
        assert_eq!(
            ext.fec_tx.as_ref().unwrap().pending(),
            1,
            "unchanged config must not recreate the encoder"
        );
        assert!(ext.pending.is_empty());
    }

    #[test]
    fn reconfigure_flushes_the_encoder_queue() {
        let base = Instant::now();
        let config = ExtConfig {
            bbr: BbrMode::Off,
            fec: FecMode::Fixed { k: 2, m: 1 },
            ack_interval: 2,
            max_shard_len: 1900,
        };
        let mut ext = PeerExtension::new(config);
        ext.handle_caps(caps(CapsFlags::FEC | CapsFlags::ACK, 2, 1), base);
        assert!(ext.fec_push(&[7u8; 40], base).unwrap().is_none());

        ext.configure(ExtConfig {
            fec: FecMode::Fixed { k: 4, m: 1 },
            ..config
        });

        assert_eq!(ext.fec_tx.as_ref().unwrap().pending(), 0);
        let frames = ext.pending_control(base);
        let shards = frames
            .iter()
            .filter(|frame| frame.kind() == ControlKind::FecShard)
            .count();
        assert_eq!(shards, 1, "the partial block must be queued as a shard");
    }

    #[test]
    fn reset_feedback_restarts_the_fec_decoder() {
        let base = Instant::now();
        let config = ExtConfig {
            bbr: BbrMode::Off,
            fec: FecMode::Fixed { k: 2, m: 1 },
            ack_interval: 2,
            max_shard_len: 1900,
        };
        let mut ext = PeerExtension::new(config);
        ext.handle_caps(caps(CapsFlags::FEC | CapsFlags::ACK, 2, 1), base);
        let (shard_len, shards) = fec_block_fixture();
        for block_id in 0..4 {
            assert_eq!(push_block(&mut ext, block_id, shard_len, &shards, base), 2);
        }

        assert_eq!(
            push_block(&mut ext, 0, shard_len, &shards, base),
            0,
            "a restarted peer is rejected by the stale block clock"
        );

        ext.reset_feedback();
        ext.handle_caps(caps(CapsFlags::FEC | CapsFlags::ACK, 2, 1), base);

        assert_eq!(
            push_block(&mut ext, 0, shard_len, &shards, base),
            2,
            "after the reset block_id 0 must be accepted again"
        );
    }

    #[test]
    fn fec_shards_are_accounted_for_by_bbr() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(BBR_CONFIG);
        ext.handle_caps(caps(CapsFlags::BBR | CapsFlags::ACK, 0, 0), base);

        ext.on_packet_sent(0, 1200, FrameKind::FecShard, base);
        ext.on_packet_sent(1, 40, FrameKind::Control, base);
        let bbr = ext.bbr.as_ref().expect("bbr is enabled");
        assert_eq!(bbr.inflight(), 1200, "shards must enter the BBR ring");

        ext.on_ack(
            &Ack {
                largest_counter: 1,
                ack_delay_us: 0,
                ecn_ce: false,
                received: 0b11,
            },
            base + Duration::from_millis(10),
        );
        let stats = ext.bbr.as_ref().expect("bbr is enabled").stats();
        assert_eq!(stats.delivered, 1200);
        assert_eq!(
            ext.bbr.as_ref().unwrap().inflight(),
            0,
            "acknowledged shards leave the ring while control frames are ignored"
        );
    }

    #[test]
    fn ack_holes_that_survive_one_ack_are_reported_as_losses() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(BBR_CONFIG);
        ext.handle_caps(caps(CapsFlags::BBR | CapsFlags::ACK, 0, 0), base);
        for counter in 0..5u64 {
            ext.on_packet_sent(counter, 1000, FrameKind::Data, base);
        }

        // Counter 3 is missing from the bitmap, but the first ACK only
        // establishes the reference point.
        let hole = Ack {
            largest_counter: 4,
            ack_delay_us: 0,
            ecn_ce: false,
            received: 0b1_1101,
        };
        ext.on_ack(&hole, base + Duration::from_millis(5));
        assert_eq!(ext.bbr.as_ref().unwrap().stats().lost_packets, 0);

        ext.on_ack(&hole, base + Duration::from_millis(10));
        let stats = ext.bbr.as_ref().unwrap().stats();
        assert_eq!(stats.lost_packets, 1);
        assert_eq!(stats.lost_bytes, 1000);
    }

    #[test]
    fn bbr_timer_sweeps_unacknowledged_datagrams() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(BBR_CONFIG);
        ext.handle_caps(caps(CapsFlags::BBR | CapsFlags::ACK, 0, 0), base);
        ext.on_packet_sent(0, 1400, FrameKind::Data, base);
        assert_eq!(ext.bbr.as_ref().unwrap().inflight(), 1400);

        ext.on_timer(base + Duration::from_secs(3));

        let stats = ext.bbr.as_ref().unwrap().stats();
        assert_eq!(stats.inflight, 0);
        assert!(stats.orphaned_packets >= 1);
    }

    #[test]
    fn frame_kind_classifies_extension_frames() {
        assert_eq!(FrameKind::classify(&[]), FrameKind::Control);
        assert_eq!(FrameKind::classify(&[0u8; 40]), FrameKind::Control);
        assert_eq!(FrameKind::classify(&[0x45; 40]), FrameKind::Data);

        let caps = Caps {
            flags: CapsFlags::ACK,
            ack_interval_packets: 2,
            fec_k: 0,
            fec_m: 0,
        };
        let mut frame = [0u8; 32];
        let len = caps.encode(&mut frame).unwrap();
        assert_eq!(FrameKind::classify(&frame[..len]), FrameKind::Control);

        let header = FecShardHeader {
            block_id: 3,
            index: 0,
            k: 2,
            m: 1,
            parity: false,
            shard_len: 4,
        };
        let mut frame = [0u8; 64];
        let len = header.encode(&mut frame).unwrap();
        let total = len + usize::from(header.shard_len);
        assert_eq!(FrameKind::classify(&frame[..total]), FrameKind::FecShard);
    }
}
