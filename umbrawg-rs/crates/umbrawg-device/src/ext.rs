//! Peer-level protocol extension: capabilities, ACK feedback, BBRv3 and FEC.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::warn;
use rand_core::RngCore;
use umbrawg_cc::{Ack as BbrAck, Bbr, BbrConfig, BbrStats};
use umbrawg_fec::{
    DecodedBlock, EncodedBlock, FecConfig, FecDecoder, FecEncoder, FecError, FecShard,
};
use umbrawg_proto::control::{Ack, Caps, CapsFlags, ControlKind, FecShardHeader};

/// Maximum number of CAPS frames sent to one peer per handshake.
const CAPS_MAX_ATTEMPTS: u8 = 3;
/// Minimum spacing between two CAPS frames during the fast retry phase.
const CAPS_FAST_RETRY: Duration = Duration::from_millis(250);
/// Spacing of the last CAPS retry before the attempts are exhausted.
const CAPS_SLOW_RETRY: Duration = Duration::from_secs(2);
/// Minimum spacing between two zero-CAPS revocations towards one peer.
///
/// With the extension disabled locally there is nothing to advertise, but a
/// peer may still hold a stale FEC advertisement. A zero CAPS retracts it.
/// Revoking at most once per two seconds bounds the reply rate while the peer
/// keeps showing extension traffic.
const CAPS_REVOKE_INTERVAL: Duration = Duration::from_secs(2);
/// Minimum spacing between two "unsupported peer FEC profile" warnings.
const CAPS_WARN_INTERVAL: Duration = Duration::from_secs(5);

/// Largest FEC `k` the data plane implements; larger peer profiles are ignored.
const MAX_PEER_FEC_K: u8 = 8;
/// Largest FEC `m` the data plane implements; larger peer profiles are ignored.
const MAX_PEER_FEC_M: u8 = 2;

/// Minimum number of counters one adaptive FEC window must span.
const ADAPTIVE_WINDOW_MIN: u64 = 256;
/// Largest window before its counters are treated as a restart, not loss.
const ADAPTIVE_WINDOW_MAX: u64 = 1 << 24;
/// A backward jump larger than this is a counter restart, not reordering.
const ADAPTIVE_GAP_MAX: u64 = 1 << 20;
/// How long a window stays open so reordered counters can still fill it.
///
/// Mirrors `UWG_FEC_ADAPTIVE_SETTLE_JIFFIES = HZ` in `fec_data.c`: evaluating
/// on the packet count alone closed the window a few hundred microseconds
/// after a gap opened, so 25 % reordering on a fast link looked like loss.
const ADAPTIVE_SETTLE_TIME: Duration = Duration::from_secs(1);
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
/// Scratch size for one FEC shard header: 8-byte prefix plus a 12-byte body.
const FEC_SHARD_HEADER_LEN: usize = 20;

/// Maximum number of control frames kept pending for one peer.
///
/// The queue is deliberately bounded: a peer with a broken socket must not be
/// able to grow it without limit. Frames above the bound are dropped loudly
/// (log + [`FecStats::dropped_control`]) instead of disappearing silently.
const CONTROL_QUEUE_CAPACITY: usize = 16;

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

/// Per-peer FEC accounting exposed for diagnostics and future exports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FecStats {
    /// Blocks emitted by the encoder, including partial flushes.
    pub blocks_encoded: u64,
    /// Shards handed to the transport for transmission.
    pub shards_sent: u64,
    /// Blocks released by the decoder.
    pub blocks_decoded: u64,
    /// Data shards restored from parity during decoding.
    pub packets_recovered: u64,
    /// Shards rejected by the decoder or by header validation.
    pub decode_fail: u64,
    /// Shards rejected because their header or geometry was out of bounds.
    pub dropped_bounds: u64,
    /// Shards dropped because FEC was not negotiated or is disabled.
    pub dropped_disabled: u64,
    /// Control frames dropped before transmission by the peer extension
    /// (queue overflow or an encryption failure). Kept next to the FEC
    /// counters so a lost ACK/CAPS/shard never becomes a silent black hole.
    pub dropped_control: u64,
}

/// Smallest allowed FEC shard limit, including the 2-byte length prefix.
pub const MIN_MAX_SHARD_LEN: u16 = 64;

/// Default FEC shard limit, including the 2-byte length prefix.
///
/// The default is intentionally larger than an Ethernet underlay can carry so
/// that jumbo underlays keep working unchanged. The daemon narrows it from the
/// configured underlay MTU when FEC is enabled.
pub const DEFAULT_MAX_SHARD_LEN: u16 = 1900;

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
            max_shard_len: DEFAULT_MAX_SHARD_LEN,
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
/// Mirrors the kernel implementation in `fec_data.c`: counters are grouped
/// into windows of at least [`ADAPTIVE_WINDOW_MIN`] received sequence numbers,
/// a window is only judged after [`ADAPTIVE_SETTLE_TIME`] so reordered
/// counters still arrive and fill it, the per-window loss ratio is smoothed
/// with an EWMA (`(old * 3 + new) / 4`) in 1/65536 units, and implausible
/// gaps restart the window instead of poisoning the estimate.
#[derive(Clone, Copy, Debug, Default)]
struct LossWindow {
    valid: bool,
    largest: u64,
    base: u64,
    received: u64,
    observed: u64,
    loss_q16: u32,
    segment_start: Option<Instant>,
    /// Increments whenever the window is restarted, so the peer can drop a
    /// stale clean-time reference like the kernel does.
    epoch: u32,
}

impl LossWindow {
    fn reset(&mut self, counter: u64, now: Instant) {
        let epoch = self.epoch.wrapping_add(1);
        *self = Self {
            valid: true,
            largest: counter,
            base: counter,
            received: 1,
            observed: 0,
            loss_q16: 0,
            segment_start: Some(now),
            epoch,
        };
    }

    /// Feeds one received counter; returns `true` when a window was closed.
    fn observe(&mut self, counter: u64, now: Instant) -> bool {
        if !self.valid {
            self.reset(counter, now);
            return false;
        }
        if counter < self.base {
            // Small backward jumps are reordering; a huge one is a new
            // counter space, for example after a peer restart.
            if self.base.saturating_sub(counter) > ADAPTIVE_GAP_MAX {
                self.reset(counter, now);
            }
            return false;
        }
        // A late counter inside the open window is counted here: the window
        // is not closed until it had time to settle.
        if counter > self.largest {
            self.largest = counter;
        }
        self.received = self.received.saturating_add(1);
        let expected = self.largest.saturating_sub(self.base).saturating_add(1);
        if expected < ADAPTIVE_WINDOW_MIN {
            return false;
        }
        if expected > ADAPTIVE_WINDOW_MAX {
            // A counter jump this large is a restart, not loss: drop the
            // segment instead of turning it into a bogus estimate.
            self.base = self.largest.saturating_add(1);
            self.received = 0;
            self.segment_start = Some(now);
            return false;
        }
        if !self
            .segment_start
            .is_some_and(|start| now.saturating_duration_since(start) >= ADAPTIVE_SETTLE_TIME)
        {
            return false;
        }
        let lost = expected.saturating_sub(self.received);
        let sample = u32::try_from(lost.saturating_mul(65_536) / expected).unwrap_or(u32::MAX);
        // Kernel semantics: seed the estimate with the first sample, then
        // smooth it. Seeding as `(0 * 3 + sample) / 4` would hide the first
        // few windows below the switch-on threshold.
        if self.loss_q16 == 0 {
            self.loss_q16 = sample;
        } else {
            self.loss_q16 = (self.loss_q16.saturating_mul(3).saturating_add(sample)) / 4;
        }
        self.observed = self.observed.saturating_add(expected);
        self.base = self.largest.saturating_add(1);
        self.received = 0;
        self.segment_start = Some(now);
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

/// Largest ACK or CAPS frame kept inline in a [`ControlFrame`].
///
/// An ACK frame is 32 bytes and a CAPS frame is 20, so the small control
/// frames never touch the allocator on the send path.
const CONTROL_INLINE_LEN: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
enum ControlPayload {
    Inline {
        bytes: [u8; CONTROL_INLINE_LEN],
        len: u8,
    },
    Owned(Vec<u8>),
}

/// One encoded control frame waiting for transmission.
///
/// The payload sits behind an [`Arc`]: [`PeerExtension::pending_control`]
/// hands the frame to the caller without removing it from the queue, so a
/// clone must not copy a full-size FEC shard. Confirmation
/// ([`PeerExtension::note_frame_sent`]) removes the queued original.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ControlFrame {
    kind: ControlKind,
    payload: Arc<ControlPayload>,
}

impl ControlFrame {
    /// Encodes a small frame into inline storage, without allocating.
    fn inline(kind: ControlKind, encode: impl FnOnce(&mut [u8]) -> Option<usize>) -> Option<Self> {
        let mut bytes = [0u8; CONTROL_INLINE_LEN];
        let len = u8::try_from(encode(&mut bytes)?).ok()?;
        if usize::from(len) > CONTROL_INLINE_LEN {
            return None;
        }
        Some(Self {
            kind,
            payload: Arc::new(ControlPayload::Inline { bytes, len }),
        })
    }

    /// Takes ownership of an already encoded frame of arbitrary length.
    fn owned(kind: ControlKind, bytes: Vec<u8>) -> Self {
        Self {
            kind,
            payload: Arc::new(ControlPayload::Owned(bytes)),
        }
    }

    pub(crate) const fn kind(&self) -> ControlKind {
        self.kind
    }

    /// Returns `true` when both handles refer to the same queued frame.
    ///
    /// [`PeerExtension::pending_control`] hands out `Arc` clones, so a frame
    /// pushed back after an aborted flush is pointer-identical to the queued
    /// original. Value equality would mistake a new identical frame for that
    /// requeue.
    fn is_same_frame(&self, other: &Self) -> bool {
        self.kind == other.kind && Arc::ptr_eq(&self.payload, &other.payload)
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        match self.payload.as_ref() {
            ControlPayload::Inline { bytes, len } => &bytes[..usize::from(*len)],
            ControlPayload::Owned(bytes) => bytes.as_slice(),
        }
    }
}

/// Maximum number of packets held by the BBR pacing queue.
const BBR_MAX_PACKETS: usize = 1024;
/// Maximum number of plaintext bytes held by the BBR pacing queue.
const BBR_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Pacer delay below which a queued packet is released for transmission.
const BBR_RELEASE_DELAY: Duration = Duration::from_micros(500);
/// How long the congestion window may hold the queue before the pacer
/// releases packets without it.
///
/// The window is only freed by ACKs, so a run of lost ACKs would otherwise
/// pin `inflight` at the limit and stall the tunnel forever. Five milliseconds
/// is shorter than the retransmission-free tolerance of the FEC path and long
/// enough not to fight a healthy window that oscillates around the limit.
const BBR_CWND_STALL_TIMEOUT: Duration = Duration::from_millis(5);

/// One queued packet inside [`BbrQueue::bytes`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BbrSlot {
    start: u32,
    len: u32,
}

/// Packets released by one drain.
///
/// The bytes of every released packet live in one contiguous buffer, so the
/// caller encrypts them without a per-packet allocation or a second copy. A
/// worker keeps one batch across ticks: draining swaps the batch buffer with
/// the queue buffer, and the queue reuses the previous batch buffer, which
/// keeps the steady state allocation-free.
#[derive(Default)]
pub struct BbrBatch {
    bytes: Vec<u8>,
    slots: Vec<BbrSlot>,
}

impl BbrBatch {
    /// Creates an empty batch.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            slots: Vec::new(),
        }
    }

    /// Returns `true` when no packets were drained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Returns the number of drained packets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Iterates over the drained packets in the order they were queued.
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> + '_ {
        self.slots.iter().map(|slot| {
            let start = slot.start as usize;
            &self.bytes[start..start + slot.len as usize]
        })
    }

    /// Drops the drained packets while keeping the buffer capacity.
    pub fn clear(&mut self) {
        self.bytes.clear();
        self.slots.clear();
    }
}

/// FIFO of plaintext packets waiting for the BBR pacer.
///
/// Packets are appended to one contiguous byte buffer and described by
/// `(offset, len)` slots. Draining hands the buffer over instead of copying
/// packets out one by one; the dead prefix is reclaimed by compaction only
/// when the buffer has to grow.
struct BbrQueue {
    bytes: Vec<u8>,
    slots: VecDeque<BbrSlot>,
    head: usize,
    live_bytes: usize,
    /// When the congestion window first refused a packet, if it still does.
    ///
    /// `None` means the window is not the limiter (or an ACK has freed it);
    /// `Some(t)` means the queue is cwnd-blocked since `t` and the emergency
    /// release is armed.
    cwnd_blocked_since: Option<Instant>,
}

impl BbrQueue {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            slots: VecDeque::new(),
            head: 0,
            live_bytes: 0,
            cwnd_blocked_since: None,
        }
    }

    fn clear(&mut self) {
        self.slots.clear();
        if self.bytes.capacity() > 64 * 1024 {
            self.bytes = Vec::new();
        } else {
            self.bytes.clear();
        }
        self.head = 0;
        self.live_bytes = 0;
        self.cwnd_blocked_since = None;
    }

    /// Marks the congestion window as freed by feedback.
    ///
    /// An ACK moves bytes out of `inflight`, so the window has to be trusted
    /// again instead of waiting out the stall timeout.
    fn note_feedback(&mut self) {
        self.cwnd_blocked_since = None;
    }

    #[cfg(test)]
    fn live_bytes(&self) -> usize {
        self.live_bytes
    }

    fn push(&mut self, packet: &[u8]) -> bool {
        if self.slots.len() >= BBR_MAX_PACKETS
            || self.live_bytes.saturating_add(packet.len()) > BBR_MAX_BYTES
        {
            return false;
        }
        let Ok(len) = u32::try_from(packet.len()) else {
            return false;
        };
        if self.bytes.len().saturating_add(packet.len()) > self.bytes.capacity() {
            self.compact();
        }
        let Ok(start) = u32::try_from(self.bytes.len()) else {
            return false;
        };
        self.bytes.extend_from_slice(packet);
        self.slots.push_back(BbrSlot { start, len });
        self.live_bytes = self.live_bytes.saturating_add(packet.len());
        true
    }

    /// Moves the live region to the front of the buffer.
    fn compact(&mut self) {
        if self.head == 0 {
            return;
        }
        self.bytes.copy_within(self.head.., 0);
        let live = self.bytes.len() - self.head;
        self.bytes.truncate(live);
        let head = u32::try_from(self.head).unwrap_or(u32::MAX);
        for slot in &mut self.slots {
            slot.start = slot.start.saturating_sub(head);
        }
        self.head = 0;
    }

    /// Releases the packets allowed by the pacer and the congestion window.
    ///
    /// The window limits the batch to `effective_cwnd - inflight` bytes, but
    /// the head packet is always released at least once: a window that rounds
    /// down to zero (or to less than one datagram) must never strand the
    /// queue. The next releases are then held back until an ACK frees the
    /// window, and after [`BBR_CWND_STALL_TIMEOUT`] without feedback the
    /// window is ignored for one batch so missing ACKs cannot stall the
    /// tunnel.
    ///
    /// The gate uses [`Bbr::effective_cwnd`] rather than the modelled window:
    /// on a short RTT the modelled `2 * BDP` window is smaller than one
    /// ACK interval of paced bytes, and gating on it would limit throughput by
    /// the peer's ACK cadence rather than by the path.
    ///
    /// `cwnd_gate` is `false` when the peer never advertised ACK support: no
    /// in-flight accounting happens in that case, so only the pacer applies.
    /// It is also `false` on a clean path (see [`Bbr::loss_limited`]): the
    /// window is a congestion response, and before any loss cut it would only
    /// mirror — and undercut — the pacer.
    fn drain_into(
        &mut self,
        max_packets: usize,
        bbr: &Bbr,
        cwnd_gate: bool,
        now: Instant,
        batch: &mut BbrBatch,
    ) -> usize {
        let head_len = self.slots.front().map_or(0, |slot| u64::from(slot.len));
        let allowance = if cwnd_gate {
            bbr.effective_cwnd().saturating_sub(bbr.inflight())
        } else {
            u64::MAX
        };
        // The head packet does not fit the remaining window: either release
        // it once (grace) or, once the stall timeout expired, ignore the
        // window for the whole batch. Only a cwnd refusal arms the timer: a
        // pacer refusal resolves on its own and must not look like a stall.
        let paced = bbr.next_send_delay(head_len as usize, now) <= BBR_RELEASE_DELAY;
        let mut bypass = false;
        if !cwnd_gate || self.slots.is_empty() {
            self.cwnd_blocked_since = None;
        } else if paced {
            if head_len > allowance {
                match self.cwnd_blocked_since {
                    None => self.cwnd_blocked_since = Some(now),
                    Some(since) => {
                        bypass = now.saturating_duration_since(since) >= BBR_CWND_STALL_TIMEOUT;
                        if !bypass {
                            // Waiting for feedback or the timeout: hold the
                            // queue instead of releasing one packet per call,
                            // which would defeat the window entirely.
                            return 0;
                        }
                    }
                }
            } else {
                self.cwnd_blocked_since = None;
            }
        }
        let limit = if cwnd_gate && !bypass {
            Some(allowance)
        } else {
            None
        };

        let mut taken = 0usize;
        let mut end = self.head;
        let mut drained_bytes = 0u64;
        for slot in &self.slots {
            if taken >= max_packets {
                break;
            }
            if bbr.next_send_delay(slot.len as usize, now) > BBR_RELEASE_DELAY {
                break;
            }
            let len = u64::from(slot.len);
            if taken > 0 && limit.is_some_and(|limit| len > limit.saturating_sub(drained_bytes)) {
                break;
            }
            end = slot.start as usize + slot.len as usize;
            drained_bytes = drained_bytes.saturating_add(len);
            taken += 1;
        }
        if taken == 0 {
            return 0;
        }
        let Ok(head) = u32::try_from(self.head) else {
            return 0;
        };
        batch.clear();
        let whole_queue = taken == self.slots.len();
        if whole_queue {
            let mut handover = std::mem::take(&mut batch.bytes);
            std::mem::swap(&mut handover, &mut self.bytes);
            handover.truncate(end);
            batch.bytes = handover;
            batch.slots.extend(self.slots.drain(..taken));
            self.head = 0;
            self.live_bytes = 0;
        } else {
            batch.bytes.extend_from_slice(&self.bytes[self.head..end]);
            batch
                .slots
                .extend(self.slots.drain(..taken).map(|slot| BbrSlot {
                    start: slot.start.saturating_sub(head),
                    len: slot.len,
                }));
            self.head = end;
            self.live_bytes = self
                .live_bytes
                .saturating_sub(usize::try_from(drained_bytes).unwrap_or(usize::MAX));
        }
        taken
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
    /// A zero CAPS must be sent to retract a stale FEC advertisement.
    revoke_pending: bool,
    /// Last time a zero CAPS left this peer; enforces [`CAPS_REVOKE_INTERVAL`].
    revoke_last_sent: Option<Instant>,
    ack: AckTracker,
    bbr: Option<Bbr>,
    fec_tx: Option<FecEncoder>,
    /// Next `block_id` used when the encoder is recreated by a reconfiguration.
    next_block_id: u32,
    fec_rx: Option<FecDecoder>,
    fec_active: bool,
    fec_stats: FecStats,
    loss: LossWindow,
    adaptive_clean_since: Option<Instant>,
    fec_deadline: Option<Instant>,
    jitter: Jitter,
    /// Single control queue, bounded by [`CONTROL_QUEUE_CAPACITY`].
    ///
    /// Frames are removed only when [`Self::note_frame_sent`] confirms them,
    /// so an aborted flush needs no second copy and cannot double the limit.
    pending: VecDeque<ControlFrame>,
    /// Last time an unsupported peer FEC profile was logged.
    caps_warn_last: Option<Instant>,
    bbr_queue: BbrQueue,
    last_ack_largest: Option<u64>,
    /// A control flush owns the queue between `pending_control` and
    /// [`Self::finish_control_flush`].
    ///
    /// The peer extension lock is released while frames are encrypted and
    /// sent, so without this flag two workers could clone the same frames and
    /// put duplicates on the wire while the second `note_frame_sent` removed
    /// an unrelated frame.
    control_flush_active: bool,
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
            revoke_pending: false,
            revoke_last_sent: None,
            ack: AckTracker::new(ACK_INTERVAL_MIN),
            bbr: None,
            fec_tx: None,
            next_block_id: 0,
            fec_rx: None,
            fec_active: false,
            fec_stats: FecStats::default(),
            loss: LossWindow::default(),
            adaptive_clean_since: None,
            fec_deadline: None,
            jitter: Jitter::seeded(),
            pending: VecDeque::new(),
            caps_warn_last: None,
            bbr_queue: BbrQueue::new(),
            last_ack_largest: None,
            control_flush_active: false,
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
        let peer_had_fec =
            self.peer_caps.contains(CapsFlags::FEC) || self.peer_fec_k != 0 || self.peer_fec_m != 0;
        // Preserve packets accumulated by the outgoing encoder: the partial
        // block is turned into explicit shard frames and stays queued.
        self.flush_encoder_frames();
        // `block_id` is a peer-visible sequence, not encoder state: a
        // reconfiguration (for example a one-sided MTU change) must continue
        // it, otherwise the peer rejects the restarted ids as ancient.
        self.next_block_id = self
            .fec_tx
            .as_ref()
            .map_or(self.next_block_id, FecEncoder::block_id);

        self.config = config;
        self.local_caps = config.local_caps();
        // A CAPS frame already in the queue advertises the previous
        // generation. Replacing it is mandatory when the profile shrinks to
        // all-off, otherwise a stale non-zero frame could re-arm the peer's
        // FEC just before our revocation.
        let caps_changed = self.local_caps != previous.local_caps()
            || config.fec_profile() != previous.fec_profile();
        if caps_changed || self.local_caps.bits() == 0 {
            self.pending
                .retain(|frame| frame.kind() != ControlKind::Caps);
        }
        // ACKs are sent every 8..=16 datagrams or after a 2..=5 ms timeout,
        // whichever comes first. The cadence is re-drawn after every ACK so
        // that the feedback stream does not look like a perfect clock.
        self.ack = AckTracker::new(config.ack_interval);

        let fec_changed = config.fec != previous.fec
            || (config.fec.config().is_some() && config.max_shard_len != previous.max_shard_len);
        if fec_changed {
            let fec = config.fec.config();
            let block_id = self.next_block_id;
            self.fec_tx = fec.map(|fec| {
                FecEncoder::with_block_id(fec, usize::from(config.max_shard_len), block_id)
            });
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
        } else if bbr_changed || self.bbr.is_none() {
            self.bbr = Some(Bbr::new(config.bbr_config()));
        }

        // Switching every extension off while the peer still believes we run
        // FEC must retract that advertisement right away, not only after the
        // next incoming shard.
        if self.local_caps.bits() == 0 && peer_had_fec {
            self.revoke_pending = true;
        }

        // Only a change in what we advertise (or in our FEC block shape)
        // invalidates what the peer told us. Anything else must keep the
        // negotiated capabilities intact.
        if caps_changed {
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
            self.fec_stats.blocks_encoded = self.fec_stats.blocks_encoded.saturating_add(1);
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
            let mut frame = vec![0u8; FEC_SHARD_HEADER_LEN + shard.len()];
            let Ok(header_len) = header.encode(&mut frame) else {
                break;
            };
            if header_len + shard.len() != frame.len() {
                break;
            }
            frame[header_len..].copy_from_slice(shard);
            self.push_control(ControlFrame::owned(ControlKind::FecShard, frame));
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

    /// Feeds one received counter to the adaptive loss estimator.
    ///
    /// The estimator follows the kernel: a window stays open for one second
    /// after it started so reordered counters still fill it, then closes after
    /// at least 256 counters. The loss ratio is an EWMA; parity is switched on
    /// above 1 % once 1024 counters were observed and off below 0.2 % after
    /// five clean seconds.
    fn observe_adaptive(&mut self, counter: u64, now: Instant) {
        if self.config.fec != FecMode::Adaptive {
            return;
        }
        let epoch = self.loss.epoch;
        if !self.loss.observe(counter, now) {
            if self.loss.epoch != epoch {
                // The kernel clears `adaptive_clean_since` on a window reset;
                // otherwise a stale clean time could switch parity off right
                // after a peer restart.
                self.adaptive_clean_since = None;
            }
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
                // The kernel drops the stale estimate here, so switching on
                // again later needs a fresh 1024-counter observation.
                self.loss.observed = 0;
                self.loss.loss_q16 = 0;
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
            Ok(Some(_)) => {
                self.fec_deadline = None;
                self.fec_stats.blocks_encoded = self.fec_stats.blocks_encoded.saturating_add(1);
            }
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
        let block = self
            .fec_tx
            .as_mut()
            .and_then(|encoder| encoder.flush_with_rng(jitter));
        if block.is_some() {
            self.fec_stats.blocks_encoded = self.fec_stats.blocks_encoded.saturating_add(1);
        }
        block
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
        // A shard is authenticated and carries its own profile, so a shard
        // matching the local RX profile is decodable even before the peer's
        // CAPS arrive. Rejecting it here turned a lost CAPS into a permanent
        // one-way black hole after the peer was re-created. The decoder still
        // validates `k`, `m`, the index and the shard length.
        self.config.fec.config()?;
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
        // An authenticated ACK is extension traffic: if our extensions are
        // off, the peer still expects feedback and needs a zero CAPS.
        if self.local_caps.bits() == 0 {
            self.revoke_pending = true;
        }
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
        // The ACK moved bytes out of `inflight`: the queue may send again and
        // must not sit out the stall timeout.
        self.bbr_queue.note_feedback();
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

    /// Releases a locally discarded datagram from the BBR accounting.
    ///
    /// The datagram was registered with [`PeerExtension::on_send`] but the
    /// send path refused it. Its bytes leave the window without being counted
    /// as a path loss.
    pub(crate) fn on_drop_bytes(&mut self, bytes: usize) {
        if let Some(bbr) = self.bbr.as_mut() {
            bbr.on_drop_bytes(bytes);
        }
    }

    /// Earliest deadline owned by the extension: a pending ACK timeout or a
    /// partially filled FEC block that must be flushed.
    ///
    /// The daemon uses it to size its poll timeout, so feedback leaves within
    /// the 0.5..=5 ms cadence instead of a 10 ms tick.
    pub(crate) fn next_deadline(&self, now: Instant) -> Option<Instant> {
        let ack = if self.ack.received_since > 0 {
            self.ack
                .last_sent
                .map(|sent| sent + self.ack.timeout)
                .or(Some(now))
        } else {
            None
        };
        match (ack, self.fec_deadline) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
            (None, None) => None,
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
        self.bbr_queue.push(packet)
    }

    /// Releases the packets the pacer allows, copying them into per-packet
    /// buffers. Kept for callers that cannot reuse a [`BbrBatch`].
    pub(crate) fn bbr_drain(&mut self, now: Instant, max_packets: usize) -> Vec<Vec<u8>> {
        let mut batch = BbrBatch::new();
        if self.bbr_drain_into(now, max_packets, &mut batch) == 0 {
            return Vec::new();
        }
        batch.iter().map(<[u8]>::to_vec).collect()
    }

    pub(crate) fn bbr_drain_into(
        &mut self,
        now: Instant,
        max_packets: usize,
        batch: &mut BbrBatch,
    ) -> usize {
        if self.config.bbr != BbrMode::On {
            return 0;
        }
        let Some(bbr) = self.bbr.as_ref() else {
            return 0;
        };
        // The window is a reaction to congestion, not a send limit of its own.
        // On a clean path it must not replace the pacer: the ACK cadence would
        // then impose a ceiling below the path rate. Only once a loss cut has
        // bounded the pipe (`inflight_hi < cwnd`, which `PROBE_UP` can exceed)
        // does the window carry information the pacer does not already have.
        let cwnd_gate =
            self.peer_caps.contains(CapsFlags::ACK) && bbr.full_bw_reached() && bbr.loss_limited();
        self.bbr_queue
            .drain_into(max_packets, bbr, cwnd_gate, now, batch)
    }

    pub(crate) fn pacing_delay(&mut self, bytes: usize, now: Instant) -> Duration {
        if self.config.bbr != BbrMode::On || !self.peer_caps.contains(CapsFlags::ACK) {
            return Duration::ZERO;
        }
        self.bbr
            .as_ref()
            .map_or(Duration::ZERO, |bbr| bbr.next_send_delay(bytes, now))
    }

    /// Resets the per-keypair state after the peer installed a new keypair.
    ///
    /// Wire counters and FEC `block_id`s live inside one keypair, so the ACK
    /// tracker, the BBR ring and the FEC decoder's block clock are discarded.
    /// Capabilities are a *device* property, not a keypair one: the kernel
    /// never drops `peer->caps` on a rekey and neither do we. Keeping
    /// `peer_caps` (and the negotiated FEC profile) is what prevents the
    /// silent one-way FEC black hole after a rekey, where incoming shards
    /// would otherwise be counted as `dropped_disabled` until a fresh CAPS
    /// arrives. Only the bounded exchange bookkeeping is re-armed so our own
    /// CAPS can be re-sent once in case it raced the keypair installation on
    /// the peer.
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
        self.caps_attempts = 0;
        self.caps_next = None;
        self.caps_last_sent = None;
        self.caps_seen = None;
    }

    /// Rejects a peer FEC profile the data plane cannot decode.
    ///
    /// Mirrors the kernel: a `k` or `m` beyond the implemented maximum is not
    /// an error, the peer simply must never be matched. Dropping the FEC flags
    /// keeps both sides from negotiating a profile one of them would discard.
    /// The complaint is rate-limited like `net_dbg_ratelimited`, because a
    /// peer repeating an unsupported CAPS would otherwise flood the log.
    fn sanitize_peer_caps(&mut self, caps: &mut Caps, now: Instant) {
        if !caps.flags.contains(CapsFlags::FEC) {
            return;
        }
        if caps.fec_k >= 1
            && caps.fec_k <= MAX_PEER_FEC_K
            && caps.fec_m >= 1
            && caps.fec_m <= MAX_PEER_FEC_M
        {
            return;
        }
        if self
            .caps_warn_last
            .is_none_or(|last| now.saturating_duration_since(last) >= CAPS_WARN_INTERVAL)
        {
            warn!(
                "peer advertised unsupported FEC {}:{}; ignoring FEC",
                caps.fec_k, caps.fec_m
            );
            self.caps_warn_last = Some(now);
        }
        caps.flags = CapsFlags::from_bits(
            caps.flags.bits() & !(CapsFlags::FEC.bits() | CapsFlags::FEC_ADAPTIVE.bits()),
        );
        caps.fec_k = 0;
        caps.fec_m = 0;
    }

    pub(crate) fn handle_caps(&mut self, mut caps: Caps, now: Instant) {
        // Evidence is what the peer actually advertised, before our profile
        // sanitization: even an unsupported FEC shape still shows a stale
        // advertisement that a zero CAPS must retract.
        let peer_has_extensions = caps.flags.bits() != 0 || caps.fec_k != 0 || caps.fec_m != 0;
        self.sanitize_peer_caps(&mut caps, now);
        let changed = self.caps_seen != Some(caps);
        self.caps_seen = Some(caps);
        self.peer_caps = caps.flags;
        self.peer_fec_k = caps.fec_k;
        self.peer_fec_m = caps.fec_m;
        if self.local_caps.bits() == 0 {
            // Nothing to advertise, but an extension frame from the peer is
            // evidence that it still holds a stale advertisement and needs a
            // zero CAPS. An all-off CAPS is not evidence: treating it as such
            // would let two all-off peers answer each other forever.
            if peer_has_extensions {
                self.revoke_pending = true;
            }
            return;
        }
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
        if let Some(frame) =
            ControlFrame::inline(ControlKind::Caps, |output| caps.encode(output).ok())
        {
            self.enqueue_control_back(frame);
        }
    }

    /// Builds the zero CAPS frame that retracts a stale FEC advertisement.
    ///
    /// The frame is only produced while [`Self::revoke_pending`] is set and at
    /// most once per [`CAPS_REVOKE_INTERVAL`], so a peer that keeps sending
    /// extension traffic cannot turn the retraction into a packet storm.
    fn request_revocation(&mut self, now: Instant) {
        if !self.revoke_pending {
            return;
        }
        if self
            .revoke_last_sent
            .is_some_and(|sent| now < sent + CAPS_REVOKE_INTERVAL)
        {
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
            flags: CapsFlags::default(),
            ack_interval_packets: self.ack.advertised_interval(),
            fec_k: 0,
            fec_m: 0,
        };
        if let Some(frame) =
            ControlFrame::inline(ControlKind::Caps, |output| caps.encode(output).ok())
        {
            // The retraction must leave before any stale shard or CAPS still
            // queued from the previous profile.
            self.enqueue_control_front(frame);
        }
    }

    /// Accounts for one transmitted control frame.
    ///
    /// The frame is removed from the queue only here. If the flush aborted
    /// before sending it, [`Self::push_control`] finds it still at the front
    /// and leaves it queued for the next flush.
    ///
    /// Only a CAPS frame spends an attempt: ACK frames share the control
    /// path but must never exhaust the CAPS budget. A zero CAPS is a
    /// revocation rather than a negotiation attempt, so it only advances the
    /// revocation rate limiter.
    pub(crate) fn note_frame_sent(&mut self, kind: ControlKind, now: Instant) {
        if let Some(frame) = self.pending.pop_front() {
            debug_assert_eq!(frame.kind(), kind);
        }
        if kind != ControlKind::Caps {
            return;
        }
        if self.local_caps.bits() == 0 {
            self.revoke_last_sent = Some(now);
            self.revoke_pending = false;
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
        // Producing new CAPS/ACK frames needs our advertised capabilities.
        // Frames that already sit in the queue, however, must always leave:
        // an encoder flushed right before FEC was turned off would otherwise
        // stay pending forever (and its block would never reach the peer).
        if self.local_caps.bits() != 0 {
            self.request_caps(now);
            if let Some(ack) = self.ack.make(now) {
                if let Some(frame) =
                    ControlFrame::inline(ControlKind::Ack, |output| ack.encode(output).ok())
                {
                    self.enqueue_control_back(frame);
                }
            }
        } else {
            self.request_revocation(now);
        }
        // The queue keeps ownership until `note_frame_sent` confirms a send.
        // Cloning a frame only bumps an `Arc`; the bound stays
        // `CONTROL_QUEUE_CAPACITY` instead of doubling with a lease copy.
        self.pending.iter().cloned().collect()
    }

    /// Starts a serialized control flush and returns the frames to send.
    ///
    /// The extension lock is released while the caller encrypts and sends, so
    /// a concurrent worker must see an empty batch instead of cloning the
    /// same frames again. The owner must call [`Self::finish_control_flush`]
    /// after every frame was confirmed or requeued.
    pub(crate) fn begin_control_flush(&mut self, now: Instant) -> Vec<ControlFrame> {
        if self.control_flush_active {
            return Vec::new();
        }
        let frames = self.pending_control(now);
        if !frames.is_empty() {
            self.control_flush_active = true;
        }
        frames
    }

    /// Releases the control queue after [`Self::begin_control_flush`].
    pub(crate) fn finish_control_flush(&mut self) {
        self.control_flush_active = false;
    }

    /// Appends a newly generated frame, enforcing the single explicit limit.
    fn enqueue_control_back(&mut self, frame: ControlFrame) {
        if self.pending.len() < CONTROL_QUEUE_CAPACITY {
            self.pending.push_back(frame);
            return;
        }
        self.count_control_drop();
        warn!(
            "dropping {:?} control frame: the per-peer queue is full",
            frame.kind()
        );
    }

    /// Puts a revocation at the front, evicting the newest tail frame if full.
    fn enqueue_control_front(&mut self, frame: ControlFrame) {
        if self.pending.len() >= CONTROL_QUEUE_CAPACITY {
            if let Some(dropped) = self.pending.pop_back() {
                self.count_control_drop();
                warn!(
                    "dropping {:?} control frame: the revocation needs the queue",
                    dropped.kind()
                );
            }
        }
        self.pending.push_front(frame);
    }

    pub(crate) fn push_control(&mut self, frame: ControlFrame) {
        if self
            .pending
            .front()
            .is_some_and(|front| front.is_same_frame(&frame))
        {
            // The flush failed on this frame and stopped. Nothing was removed
            // when it was handed out, so the frame and the whole tail stay
            // queued in order for the next flush.
            return;
        }
        self.enqueue_control_back(frame);
    }

    /// Accounts for one control frame dropped before it reached the transport.
    ///
    /// Called on an encryption failure that is not recoverable (bad buffer
    /// shape, MTU mismatch, ...). The frame was handed out by
    /// [`Self::pending_control`] and is removed from the queue here.
    pub(crate) fn note_control_drop(&mut self) {
        self.pending.pop_front();
        self.count_control_drop();
    }

    fn count_control_drop(&mut self) {
        self.fec_stats.dropped_control = self.fec_stats.dropped_control.saturating_add(1);
    }

    /// Returns FEC accounting for this peer.
    ///
    /// The counters are reported while FEC is enabled and also while it is off
    /// as soon as anything was recorded (a control frame dropped by the peer
    /// extension or a shard rejected as disabled). This keeps
    /// [`FecStats::dropped_control`] observable without changing the
    /// `None`-while-clean contract for peers that never used the extension.
    pub(crate) fn fec_stats(&self) -> Option<FecStats> {
        (self.config.fec != FecMode::Off || self.fec_stats != FecStats::default())
            .then_some(self.fec_stats)
    }

    /// Accounts for one shard handed to the transport.
    pub(crate) fn note_fec_shard_sent(&mut self) {
        self.fec_stats.shards_sent = self.fec_stats.shards_sent.saturating_add(1);
    }

    /// Accounts for a shard rejected before decoding (bad or out-of-bounds header).
    pub(crate) fn note_fec_reject(&mut self) {
        // Even a malformed shard proves the peer still sends extension
        // traffic; while we are all-off it needs the zero-CAPS retraction.
        if self.local_caps.bits() == 0 {
            self.revoke_pending = true;
        }
        self.fec_stats.decode_fail = self.fec_stats.decode_fail.saturating_add(1);
        self.fec_stats.dropped_bounds = self.fec_stats.dropped_bounds.saturating_add(1);
    }

    fn account_decoded(&mut self, blocks: &[DecodedBlock]) {
        for block in blocks {
            self.fec_stats.blocks_decoded = self.fec_stats.blocks_decoded.saturating_add(1);
            let recovered = u64::try_from(block.recovered).unwrap_or(u64::MAX);
            self.fec_stats.packets_recovered =
                self.fec_stats.packets_recovered.saturating_add(recovered);
        }
    }

    pub(crate) fn fec_poll(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let blocks = {
            let Some(decoder) = self.fec_rx() else {
                return Vec::new();
            };
            decoder.poll(now)
        };
        self.account_decoded(&blocks);
        blocks.into_iter().flat_map(|block| block.packets).collect()
    }

    pub(crate) fn fec_decode(&mut self, shard: FecShard<'_>, now: Instant) -> Vec<Vec<u8>> {
        // The shard reached us authenticated and with a valid header, so it is
        // extension traffic even when the local decoder is off. Note it before
        // the disabled check so a stale FEC peer learns about the revocation.
        if self.local_caps.bits() == 0 {
            self.revoke_pending = true;
        }
        let result = {
            let Some(decoder) = self.fec_rx() else {
                self.fec_stats.dropped_disabled = self.fec_stats.dropped_disabled.saturating_add(1);
                return Vec::new();
            };
            decoder.push_at(shard, now)
        };
        match result {
            Ok(blocks) => {
                self.account_decoded(&blocks);
                blocks.into_iter().flat_map(|block| block.packets).collect()
            }
            Err(error) => {
                self.fec_stats.decode_fail = self.fec_stats.decode_fail.saturating_add(1);
                if is_bounds_error(error) {
                    self.fec_stats.dropped_bounds = self.fec_stats.dropped_bounds.saturating_add(1);
                }
                Vec::new()
            }
        }
    }
}

fn is_bounds_error(error: FecError) -> bool {
    matches!(
        error,
        FecError::TooManyShards { .. }
            | FecError::InvalidIndex { .. }
            | FecError::InvalidShardLen { .. }
            | FecError::ShardLenTooLarge { .. }
            | FecError::PayloadLenMismatch { .. }
            | FecError::InvalidPacketLen { .. }
            | FecError::ConfigMismatch { .. }
            | FecError::ShardLenMismatch { .. }
            | FecError::ZeroDataShards
            | FecError::ZeroParityShards
            | FecError::PacketTooLarge { .. }
    )
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
        assert!(matches!(
            frames[0].payload.as_ref(),
            ControlPayload::Inline { .. }
        ));
    }

    #[test]
    fn ack_frames_are_inline_and_decode() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(BBR_CONFIG);
        assert!(!ext.pending_control(base).is_empty());

        let now = base + Duration::from_millis(5);
        for counter in 0..4u64 {
            ext.observe_received(counter, now);
        }
        let frames = ext.pending_control(now);
        let frame = frames
            .iter()
            .find(|frame| frame.kind() == ControlKind::Ack)
            .expect("ACK is due after the first observation");
        assert!(matches!(
            frame.payload.as_ref(),
            ControlPayload::Inline { .. }
        ));
        assert_eq!(frame.bytes().len(), 32);

        let ack = Ack::decode(frame.bytes()).expect("ACK decodes");
        assert_eq!(ack.largest_counter, 3);
        assert_eq!(ack.received & 0b1111, 0b1111);
        assert!(!ack.ecn_ce);
    }

    #[test]
    fn control_backlog_is_bounded_and_keeps_kind() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(BBR_CONFIG);
        let initial = ext.pending_control(base);
        assert!(!initial.is_empty());
        for frame in &initial {
            ext.note_frame_sent(frame.kind(), base);
        }
        for index in 0..32u8 {
            ext.push_control(ControlFrame::owned(ControlKind::FecShard, vec![index; 8]));
        }
        assert_eq!(ext.pending.len(), 16);
        assert!(ext
            .pending
            .iter()
            .all(|frame| frame.kind() == ControlKind::FecShard));
        let frames = ext.pending_control(base);
        assert_eq!(
            frames
                .iter()
                .filter(|frame| frame.kind() == ControlKind::FecShard)
                .count(),
            16
        );
        assert!(matches!(
            frames[0].payload.as_ref(),
            ControlPayload::Owned(bytes) if bytes == &[0u8; 8]
        ));
    }

    fn bbr_packets(count: usize) -> Vec<Vec<u8>> {
        (0..count)
            .map(|index| vec![u8::try_from(index % 251).unwrap(); 40 + index % 13])
            .collect()
    }

    #[test]
    fn bbr_queue_drains_packets_in_order() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(BBR_CONFIG);
        let mut batch = BbrBatch::new();
        let packets = bbr_packets(64);
        for packet in &packets {
            assert!(ext.bbr_enqueue(packet));
        }
        assert_eq!(
            ext.bbr_queue.live_bytes(),
            packets.iter().map(Vec::len).sum::<usize>()
        );

        let mut drained = Vec::new();
        loop {
            let count = ext.bbr_drain_into(base, 7, &mut batch);
            if count == 0 {
                break;
            }
            assert!(count <= 7);
            drained.extend(batch.iter().map(<[u8]>::to_vec));
        }
        assert_eq!(drained, packets);
        assert!(ext.bbr_queue.slots.is_empty());
        assert_eq!(ext.bbr_queue.live_bytes(), 0);
    }

    #[test]
    fn bbr_queue_keeps_order_across_compaction() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(BBR_CONFIG);
        let mut batch = BbrBatch::new();
        let mut expected: Vec<Vec<u8>> = Vec::new();
        let mut drained = 0usize;

        for round in 0..8u8 {
            for index in 0..16u8 {
                let value = round * 16 + index;
                let packet = vec![value; 64 + usize::from(value % 17)];
                assert!(ext.bbr_enqueue(&packet));
                expected.push(packet);
            }
            assert_eq!(ext.bbr_drain_into(base, 5, &mut batch), 5);
            for (offset, packet) in batch.iter().enumerate() {
                assert_eq!(packet, expected[drained + offset].as_slice());
            }
            drained += batch.len();
        }
        loop {
            let count = ext.bbr_drain_into(base, 64, &mut batch);
            if count == 0 {
                break;
            }
            for (offset, packet) in batch.iter().enumerate() {
                assert_eq!(packet, expected[drained + offset].as_slice());
            }
            drained += count;
        }
        assert_eq!(drained, expected.len());
    }

    #[test]
    fn bbr_queue_enforces_its_limits() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(BBR_CONFIG);
        for index in 0..BBR_MAX_PACKETS {
            assert!(ext.bbr_enqueue(&[u8::try_from(index % 251).unwrap(); 8]));
        }
        assert!(!ext.bbr_enqueue(&[0u8; 8]));
        assert_eq!(ext.bbr_queue.slots.len(), BBR_MAX_PACKETS);
        assert_eq!(ext.bbr_queue.live_bytes(), BBR_MAX_PACKETS * 8);
        ext.bbr_queue.clear();
        assert_eq!(ext.bbr_queue.live_bytes(), 0);

        let packet = vec![1u8; BBR_MAX_BYTES / 3];
        assert!(ext.bbr_enqueue(&packet));
        assert!(ext.bbr_enqueue(&packet));
        assert!(ext.bbr_enqueue(&packet));
        assert!(!ext.bbr_enqueue(&packet));

        let mut batch = BbrBatch::new();
        assert_eq!(ext.bbr_drain_into(base, BBR_MAX_PACKETS, &mut batch), 3);
        assert!(ext.bbr_queue.slots.is_empty());
        assert!(batch.bytes.capacity() >= packet.len());
    }

    #[test]
    fn bbr_batch_recycles_the_queue_buffer() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(BBR_CONFIG);
        let mut batch = BbrBatch::new();

        assert!(ext.bbr_enqueue(&[1u8; 100]));
        assert_eq!(ext.bbr_drain_into(base, 8, &mut batch), 1);
        assert_eq!(batch.iter().next().map(<[u8]>::len), Some(100));

        assert!(ext.bbr_enqueue(&[2u8; 100]));
        assert_eq!(ext.bbr_drain_into(base, 8, &mut batch), 1);
        assert_eq!(
            batch.iter().next().map(<[u8]>::to_vec),
            Some(vec![2u8; 100])
        );
        assert!(
            ext.bbr_queue.bytes.capacity() >= 100,
            "the queue must take the previous batch buffer"
        );
    }

    #[test]
    fn bbr_drain_obeys_the_pacer() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(BBR_CONFIG);
        let mut batch = BbrBatch::new();
        ext.handle_caps(caps(CapsFlags::BBR | CapsFlags::ACK, 0, 0), base);
        for counter in 0..4u64 {
            ext.on_packet_sent(counter, 1400, FrameKind::Data, base);
        }
        assert!(ext.bbr_enqueue(&[5u8; 1400]));
        assert_eq!(ext.bbr_drain_into(base, 8, &mut batch), 0);
        assert_eq!(
            ext.bbr_drain_into(base + Duration::from_secs(1), 8, &mut batch),
            1
        );
        assert_eq!(batch.iter().next().map(<[u8]>::len), Some(1400));
    }

    /// Payload used by the BBR tests: the MSS of [`BBR_CONFIG`], so
    /// `min_cwnd = 4 * MSS` and every window figure is a whole packet count.
    const DATA_LEN: usize = 1900;

    fn bbr_acked_ext(base: Instant) -> PeerExtension {
        let mut ext = PeerExtension::new(BBR_CONFIG);
        ext.handle_caps(caps(CapsFlags::BBR | CapsFlags::ACK, 0, 0), base);
        ext
    }

    fn data_packets(count: usize) -> Vec<Vec<u8>> {
        (0..count)
            .map(|index| vec![u8::try_from(index).unwrap(); DATA_LEN])
            .collect()
    }

    fn charge_inflight(ext: &mut PeerExtension, packets: usize, now: Instant) -> u64 {
        charge_inflight_from(ext, 0, packets, now)
    }

    fn charge_inflight_from(
        ext: &mut PeerExtension,
        first_counter: u64,
        packets: usize,
        now: Instant,
    ) -> u64 {
        for counter in first_counter..first_counter + packets as u64 {
            ext.on_packet_sent(counter, DATA_LEN, FrameKind::Data, now);
        }
        ext.bbr_stats().expect("bbr is enabled").inflight
    }

    /// Effective window used by the gate, mirrored from
    /// `Bbr::effective_cwnd`: the modelled window or one 5 ms ACK interval of
    /// paced bytes, capped at 4 MiB.
    fn effective_cwnd(ext: &PeerExtension) -> u64 {
        let stats = ext.bbr_stats().expect("bbr is enabled");
        let floor = (stats.pacing_rate * 5 / 1000).min(4 * 1024 * 1024);
        stats.cwnd.max(floor)
    }

    /// Charges more datagrams than the effective window holds.
    fn fill_window(ext: &mut PeerExtension, first_counter: u64, now: Instant) {
        let fill = usize::try_from(effective_cwnd(ext) / DATA_LEN as u64).unwrap() + 1;
        charge_inflight_from(ext, first_counter, fill, now);
    }

    /// Drives the controller until `STARTUP` declares the path full.
    ///
    /// A quick exchange first primes a 500 µs `min_rtt`, so the modelled window
    /// stays at or below twice the bytes the pacer emits per round and the
    /// controller never considers itself application limited. Every round then
    /// sends sixteen datagrams and acknowledges exactly those one millisecond
    /// later, which measures the same delivered rate round after round: no
    /// bandwidth growth, so the controller leaves `STARTUP`.
    fn reach_full_bw(ext: &mut PeerExtension, base: Instant) -> Instant {
        ext.on_packet_sent(0, DATA_LEN, FrameKind::Data, base);
        ext.on_ack(
            &Ack {
                largest_counter: 0,
                ack_delay_us: 0,
                ecn_ce: false,
                received: 1,
            },
            base + Duration::from_micros(500),
        );

        let mut counter = 1u64;
        let mut now = base;
        for round in 1..=5u64 {
            now = base + Duration::from_millis(2 * round);
            for _ in 0..16 {
                ext.on_packet_sent(counter, DATA_LEN, FrameKind::Data, now);
                counter += 1;
            }
            ext.on_ack(
                &Ack {
                    largest_counter: counter - 1,
                    ack_delay_us: 0,
                    ecn_ce: false,
                    received: u64::MAX,
                },
                now + Duration::from_millis(1),
            );
        }
        assert!(
            ext.bbr.as_ref().expect("bbr is enabled").full_bw_reached(),
            "STARTUP must declare the path full"
        );
        assert_eq!(ext.bbr_stats().expect("bbr is enabled").inflight, 0);
        now + Duration::from_millis(1)
    }

    fn loss_limited(ext: &PeerExtension) -> bool {
        ext.bbr.as_ref().expect("bbr is enabled").loss_limited()
    }

    /// Drives the controller into a loss-limited window.
    ///
    /// The clean plateau is followed by a faster exchange (so `2 * BDP` lifts
    /// above the bound), then by a lost burst that cuts `inflight_hi`. The cut
    /// clamps `cwnd` to the new bound, so the gain cycle is walked with the
    /// watchdog until `PROBE_UP` may exceed it again — the only state in which
    /// the window holds a loss-derived limit.
    fn reach_loss_limited(ext: &mut PeerExtension, base: Instant) -> Instant {
        let mut now = reach_full_bw(ext, base);
        assert!(!loss_limited(ext), "a clean plateau is not loss limited");

        let mut counter = 400u64;
        now += Duration::from_millis(1);
        for _ in 0..16 {
            ext.on_packet_sent(counter, DATA_LEN, FrameKind::Data, now);
            counter += 1;
        }
        ext.on_ack(
            &Ack {
                largest_counter: counter - 1,
                ack_delay_us: 0,
                ecn_ce: false,
                received: u64::MAX,
            },
            now + Duration::from_micros(500),
        );

        now += Duration::from_millis(1);
        for _ in 0..32 {
            ext.on_packet_sent(counter, DATA_LEN, FrameKind::Data, now);
            counter += 1;
        }
        for lost in counter - 32..counter {
            ext.bbr
                .as_mut()
                .expect("bbr is enabled")
                .on_loss(lost, now + Duration::from_micros(100));
        }
        assert!(
            ext.bbr_stats().expect("bbr is enabled").inflight_hi < u64::MAX,
            "the burst must cut the loss bound"
        );

        let mut steps = 0;
        while !loss_limited(ext) {
            assert!(
                steps < 8,
                "PROBE_UP must let the window exceed the loss bound"
            );
            now += Duration::from_millis(1);
            ext.on_timer(now);
            steps += 1;
        }
        now
    }

    #[test]
    fn bbr_gate_ignores_a_startup_window() {
        let base = Instant::now();
        let mut ext = bbr_acked_ext(base);
        assert!(!ext.bbr.as_ref().expect("bbr is enabled").full_bw_reached());

        let packets = data_packets(8);
        let inflight = charge_inflight(&mut ext, 8, base);
        let window = ext.bbr_stats().expect("bbr is enabled").cwnd;
        assert!(
            inflight >= window,
            "in-flight {inflight} must already exceed the window {window}"
        );
        for packet in &packets {
            assert!(ext.bbr_enqueue(packet));
        }

        // `STARTUP` is still probing the path: only the pacer applies.
        let mut batch = BbrBatch::new();
        assert_eq!(
            ext.bbr_drain_into(base + Duration::from_secs(1), 16, &mut batch),
            packets.len()
        );
        assert_eq!(
            batch.iter().map(<[u8]>::to_vec).collect::<Vec<_>>(),
            packets
        );
        assert!(ext.bbr_queue.slots.is_empty());
    }

    #[test]
    fn bbr_gate_ignores_a_clean_plateau() {
        let base = Instant::now();
        let mut ext = bbr_acked_ext(base);
        let now = reach_full_bw(&mut ext, base);
        assert!(!loss_limited(&ext), "no loss cut reached the controller");

        let packets = data_packets(6);
        for packet in &packets {
            assert!(ext.bbr_enqueue(packet));
        }
        fill_window(&mut ext, 1000, now);
        assert!(
            ext.bbr_stats().expect("bbr is enabled").inflight > effective_cwnd(&ext),
            "the window is exhausted"
        );

        // The window is not a loss response here, so it must not hold the
        // queue back: the pacer has already limited the rate.
        let mut batch = BbrBatch::new();
        assert_eq!(
            ext.bbr_drain_into(now + Duration::from_secs(1), 16, &mut batch),
            packets.len()
        );
        assert_eq!(
            batch.iter().map(<[u8]>::to_vec).collect::<Vec<_>>(),
            packets
        );
        assert!(ext.bbr_queue.slots.is_empty());
    }

    #[test]
    fn bbr_gate_applies_after_a_loss_cut() {
        let base = Instant::now();
        let mut ext = bbr_acked_ext(base);
        let now = reach_loss_limited(&mut ext, base);

        let packets = data_packets(4);
        for packet in &packets {
            assert!(ext.bbr_enqueue(packet));
        }
        fill_window(&mut ext, 1000, now);
        assert!(
            ext.bbr_stats().expect("bbr is enabled").inflight > effective_cwnd(&ext),
            "the window is exhausted"
        );

        let later = now + Duration::from_secs(1);
        let mut batch = BbrBatch::new();
        assert_eq!(ext.bbr_drain_into(later, 8, &mut batch), 1);
        assert_eq!(batch.iter().next(), Some(packets[0].as_slice()));
        // The grace packet is not repeated: without feedback the window holds.
        assert_eq!(
            ext.bbr_drain_into(later + Duration::from_millis(1), 8, &mut batch),
            0
        );
        assert_eq!(ext.bbr_queue.slots.len(), 3);
    }

    #[test]
    fn bbr_cwnd_limits_the_drained_batch() {
        let base = Instant::now();
        let mut ext = bbr_acked_ext(base);
        let now = reach_loss_limited(&mut ext, base);
        let packets = data_packets(6);
        // Two datagrams of allowance, plus less than one datagram of slack.
        let fill = usize::try_from(effective_cwnd(&ext) / DATA_LEN as u64).unwrap() - 2;
        charge_inflight_from(&mut ext, 1000, fill, now);
        for packet in &packets {
            assert!(ext.bbr_enqueue(packet));
        }

        let mut batch = BbrBatch::new();
        assert_eq!(
            ext.bbr_drain_into(now + Duration::from_secs(1), 8, &mut batch),
            2
        );
        assert_eq!(batch.len(), 2);
        assert_eq!(batch.iter().next(), Some(packets[0].as_slice()));
        assert_eq!(
            batch.iter().map(<[u8]>::to_vec).collect::<Vec<_>>(),
            packets[..2]
        );
        assert_eq!(ext.bbr_queue.slots.len(), 4);
        assert_eq!(ext.bbr_queue.live_bytes(), 4 * DATA_LEN);
    }

    #[test]
    fn bbr_cwnd_releases_at_least_one_packet_when_full() {
        let base = Instant::now();
        let mut ext = bbr_acked_ext(base);
        let now = reach_loss_limited(&mut ext, base);
        let packets = data_packets(4);
        for packet in &packets {
            assert!(ext.bbr_enqueue(packet));
        }
        fill_window(&mut ext, 1000, now);

        let later = now + Duration::from_secs(1);
        let mut batch = BbrBatch::new();
        assert_eq!(ext.bbr_drain_into(later, 8, &mut batch), 1);
        assert_eq!(batch.iter().next(), Some(packets[0].as_slice()));
        assert_eq!(
            ext.bbr_drain_into(later + Duration::from_millis(1), 8, &mut batch),
            0
        );
        assert_eq!(ext.bbr_queue.slots.len(), 3);
    }

    #[test]
    fn bbr_ack_reenables_the_cwnd_blocked_queue() {
        let base = Instant::now();
        let mut ext = bbr_acked_ext(base);
        let now = reach_loss_limited(&mut ext, base);
        let packets = data_packets(4);
        for packet in &packets {
            assert!(ext.bbr_enqueue(packet));
        }

        let fill = usize::try_from(effective_cwnd(&ext) / DATA_LEN as u64).unwrap() + 1;
        charge_inflight_from(&mut ext, 1000, fill, now);
        let largest = 1000 + fill as u64 - 1;

        let later = now + Duration::from_secs(1);
        let mut batch = BbrBatch::new();
        assert_eq!(ext.bbr_drain_into(later, 8, &mut batch), 1);
        assert_eq!(
            ext.bbr_drain_into(later + Duration::from_millis(1), 8, &mut batch),
            0
        );

        // An ACK drains the whole window, so the rest leaves in queue order
        // without waiting for the stall timeout.
        ext.on_ack(
            &Ack {
                largest_counter: largest,
                ack_delay_us: 0,
                ecn_ce: false,
                received: u64::MAX,
            },
            later + Duration::from_millis(2),
        );
        assert_eq!(
            ext.bbr_drain_into(later + Duration::from_millis(2), 8, &mut batch),
            3
        );
        assert_eq!(
            batch.iter().map(<[u8]>::to_vec).collect::<Vec<_>>(),
            packets[1..]
        );
        assert!(ext.bbr_queue.slots.is_empty());
        assert_eq!(ext.bbr_queue.live_bytes(), 0);
    }

    #[test]
    fn bbr_cwnd_stall_timeout_bypasses_the_window() {
        let base = Instant::now();
        let mut ext = bbr_acked_ext(base);
        let now = reach_loss_limited(&mut ext, base);
        let packets = data_packets(4);
        for packet in &packets {
            assert!(ext.bbr_enqueue(packet));
        }
        fill_window(&mut ext, 1000, now);

        let blocked = now + Duration::from_secs(1);
        let mut batch = BbrBatch::new();
        assert_eq!(ext.bbr_drain_into(blocked, 8, &mut batch), 1);
        assert_eq!(
            ext.bbr_drain_into(blocked + Duration::from_millis(4), 8, &mut batch),
            0
        );
        // No ACK arrived: after the timeout the window stops holding the queue.
        assert_eq!(
            ext.bbr_drain_into(blocked + BBR_CWND_STALL_TIMEOUT, 8, &mut batch),
            3
        );
        assert_eq!(
            batch.iter().map(<[u8]>::to_vec).collect::<Vec<_>>(),
            packets[1..]
        );
        assert!(ext.bbr_queue.slots.is_empty());
    }

    #[test]
    fn bbr_cwnd_stall_ignores_a_pacer_hold() {
        let base = Instant::now();
        let mut ext = bbr_acked_ext(base);
        let now = reach_loss_limited(&mut ext, base);
        let packets = data_packets(4);
        for packet in &packets {
            assert!(ext.bbr_enqueue(packet));
        }
        // Charging the whole window at `now` also overspends the pacer.
        fill_window(&mut ext, 1000, now);

        // At `now` the pacer, not the window, is the limiter: no packet leaves
        // and the stall timer must stay disarmed.
        let mut batch = BbrBatch::new();
        assert_eq!(ext.bbr_drain_into(now, 8, &mut batch), 0);
        assert_eq!(ext.bbr_queue.cwnd_blocked_since, None);

        // Once pacing allows, the window is seen as the limiter and the grace
        // packet goes out.
        let later = now + Duration::from_secs(1);
        assert_eq!(ext.bbr_drain_into(later, 8, &mut batch), 1);
        assert_eq!(ext.bbr_queue.cwnd_blocked_since, Some(later));
    }

    #[test]
    fn bbr_cwnd_gate_uses_the_ack_interval_floor() {
        let base = Instant::now();
        let mut ext = bbr_acked_ext(base);
        let now = reach_loss_limited(&mut ext, base);

        let stats = ext.bbr_stats().expect("bbr is enabled");
        let floor = (stats.pacing_rate * 5 / 1000).min(4 * 1024 * 1024);
        assert!(
            floor > stats.cwnd,
            "the floor must dominate: cwnd {} floor {floor}",
            stats.cwnd
        );

        // Fill the modelled window: a raw-cwnd gate would hold the queue now.
        let fill = usize::try_from(stats.cwnd / DATA_LEN as u64).unwrap() + 1;
        charge_inflight_from(&mut ext, 1000, fill, now);
        let inflight = ext.bbr_stats().expect("bbr is enabled").inflight;
        assert!(inflight >= stats.cwnd, "the raw window is full");

        let room = effective_cwnd(&ext).saturating_sub(inflight);
        let count = usize::try_from(room / DATA_LEN as u64).unwrap().min(20);
        assert!(count > 0, "the floor must leave room for the batch");
        let packets = data_packets(count);
        for packet in &packets {
            assert!(ext.bbr_enqueue(packet));
        }

        // `effective_cwnd - inflight` is the floor minus the window, which
        // fits the whole batch: the ACK cadence does not throttle the queue.
        let mut batch = BbrBatch::new();
        assert_eq!(
            ext.bbr_drain_into(now + Duration::from_secs(1), 32, &mut batch),
            count
        );
        assert!(ext.bbr_queue.slots.is_empty());
        assert_eq!(
            batch.iter().map(<[u8]>::to_vec).collect::<Vec<_>>(),
            packets
        );
    }

    #[test]
    fn bbr_without_ack_caps_paces_without_a_window() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(BBR_CONFIG);
        let later = base + Duration::from_secs(1);
        let packets = data_packets(8);
        for packet in &packets {
            assert!(ext.bbr_enqueue(packet));
        }

        let mut batch = BbrBatch::new();
        assert_eq!(ext.bbr_drain_into(later, 8, &mut batch), 8);
        assert!(ext.bbr_queue.slots.is_empty());
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
    fn zero_caps_retracts_a_stale_fec_advertisement() {
        let base = Instant::now();
        let mut ext = PeerExtension::default();
        assert_eq!(ext.local_caps.bits(), 0);

        // A long-lived peer still advertises FEC while everything is off
        // locally: the next control flush must retract our capabilities.
        ext.handle_caps(caps(CapsFlags::ACK | CapsFlags::FEC, 2, 1), base);
        let frames = ext.pending_control(base);
        assert_eq!(kinds(&frames), vec![ControlKind::Caps]);
        let decoded = Caps::decode(frames[0].bytes()).expect("caps frame decodes");
        assert_eq!(decoded.flags.bits(), 0);
        assert_eq!((decoded.fec_k, decoded.fec_m), (0, 0));
        ext.note_frame_sent(ControlKind::Caps, base);

        // A silent peer must not keep the retraction alive.
        assert!(ext
            .pending_control(base + Duration::from_secs(30))
            .is_empty());

        // Repeated evidence is answered at most once per interval.
        ext.handle_caps(
            caps(CapsFlags::ACK | CapsFlags::FEC, 2, 1),
            base + Duration::from_secs(1),
        );
        assert!(ext
            .pending_control(base + Duration::from_secs(1))
            .is_empty());
        let frames = ext.pending_control(base + CAPS_REVOKE_INTERVAL);
        assert_eq!(kinds(&frames), vec![ControlKind::Caps]);
        assert_eq!(ext.fec_stats.dropped_control, 0);
    }

    #[test]
    fn incoming_extension_traffic_revokes_while_off() {
        let base = Instant::now();
        let mut ext = PeerExtension::default();
        let (shard_len, shards) = fec_block_fixture();
        assert!(ext
            .fec_decode(
                FecShard {
                    block_id: 0,
                    index: 0,
                    k: 2,
                    m: 1,
                    shard_len,
                    payload: &shards[0],
                },
                base,
            )
            .is_empty());
        assert_eq!(ext.fec_stats.dropped_disabled, 1);
        let frames = ext.pending_control(base);
        assert_eq!(kinds(&frames), vec![ControlKind::Caps]);
        let decoded = Caps::decode(frames[0].bytes()).expect("caps frame decodes");
        assert_eq!(decoded.flags.bits(), 0);
    }

    #[test]
    fn queued_caps_is_replaced_when_the_profile_turns_off() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(ExtConfig {
            bbr: BbrMode::Off,
            fec: FecMode::Fixed { k: 2, m: 1 },
            ack_interval: 2,
            max_shard_len: 1900,
        });
        ext.handle_caps(caps(CapsFlags::ACK | CapsFlags::FEC, 2, 1), base);
        let stale = Caps {
            flags: CapsFlags::ACK | CapsFlags::FEC,
            ack_interval_packets: 2,
            fec_k: 2,
            fec_m: 1,
        };
        ext.push_control(
            ControlFrame::inline(ControlKind::Caps, |output| stale.encode(output).ok())
                .expect("caps frame fits"),
        );

        // A flush can hand the frame to the transport caller and race a
        // reconfiguration; the queue must still replace it before the next
        // attempt. The old lease copy was restored first and won this race.
        let handed = ext.pending_control(base);
        assert_eq!(kinds(&handed), vec![ControlKind::Caps]);

        ext.configure(ExtConfig::default());
        let frames = ext.pending_control(base + Duration::from_millis(1));
        assert_eq!(kinds(&frames), vec![ControlKind::Caps]);
        let decoded = Caps::decode(frames[0].bytes()).expect("caps frame decodes");
        assert_eq!(
            decoded.flags.bits(),
            0,
            "a stale non-zero CAPS must not survive the switch to all-off"
        );
    }

    #[test]
    fn all_off_caps_is_not_extension_traffic() {
        let base = Instant::now();
        let mut ext = PeerExtension::default();
        ext.handle_caps(caps(CapsFlags::default(), 0, 0), base);
        assert!(
            ext.pending_control(base + Duration::from_secs(1))
                .is_empty(),
            "two all-off peers must fall silent instead of answering each other"
        );
        assert!(!ext.revoke_pending);
    }

    #[test]
    fn fec_shard_of_the_local_profile_is_decoded_before_caps() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(ExtConfig {
            bbr: BbrMode::Off,
            fec: FecMode::Fixed { k: 2, m: 1 },
            ack_interval: 2,
            max_shard_len: 1900,
        });
        let (shard_len, shards) = fec_block_fixture();

        // No `handle_caps`: the shard itself carries and authenticates the
        // profile, so it must still decode.
        assert_eq!(push_block(&mut ext, 0, shard_len, &shards, base), 2);
        let stats = ext.fec_stats().expect("counters are always observable");
        assert_eq!(stats.blocks_decoded, 1);
        assert_eq!(stats.dropped_disabled, 0);

        // A profile the local decoder was not built for is still rejected.
        assert!(ext
            .fec_decode(
                FecShard {
                    block_id: 1,
                    index: 0,
                    k: 3,
                    m: 1,
                    shard_len,
                    payload: &shards[0],
                },
                base,
            )
            .is_empty());
        assert_eq!(ext.fec_stats().unwrap().decode_fail, 1);
    }

    #[test]
    fn unsupported_peer_fec_profile_is_ignored() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(ExtConfig {
            bbr: BbrMode::Off,
            fec: FecMode::Fixed { k: 2, m: 1 },
            ack_interval: 2,
            max_shard_len: 1900,
        });

        ext.handle_caps(caps(CapsFlags::FEC | CapsFlags::ACK, 9, 1), base);
        assert!(!ext.peer_caps.contains(CapsFlags::FEC));
        assert_eq!((ext.peer_fec_k, ext.peer_fec_m), (0, 0));
        assert!(!ext.fec_tx_active());

        ext.handle_caps(caps(CapsFlags::FEC | CapsFlags::ACK, 2, 3), base);
        assert!(!ext.peer_caps.contains(CapsFlags::FEC));
        assert_eq!((ext.peer_fec_k, ext.peer_fec_m), (0, 0));

        ext.handle_caps(caps(CapsFlags::FEC | CapsFlags::ACK, 2, 1), base);
        assert!(ext.peer_caps.contains(CapsFlags::FEC));
        assert!(ext.fec_tx_active());
    }

    #[test]
    fn unsupported_fec_warning_is_rate_limited() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(ExtConfig {
            bbr: BbrMode::Off,
            fec: FecMode::Fixed { k: 2, m: 1 },
            ack_interval: 2,
            max_shard_len: 1900,
        });

        ext.handle_caps(caps(CapsFlags::FEC | CapsFlags::ACK, 9, 1), base);
        assert_eq!(ext.caps_warn_last, Some(base));

        ext.handle_caps(
            caps(CapsFlags::FEC | CapsFlags::ACK, 9, 1),
            base + Duration::from_secs(1),
        );
        assert_eq!(
            ext.caps_warn_last,
            Some(base),
            "a repeated profile must not log again inside the interval"
        );

        ext.handle_caps(
            caps(CapsFlags::FEC | CapsFlags::ACK, 9, 1),
            base + CAPS_WARN_INTERVAL,
        );
        assert_eq!(
            ext.caps_warn_last,
            Some(base + CAPS_WARN_INTERVAL),
            "the limiter must allow a fresh warning after the interval"
        );
    }

    #[test]
    fn configure_preserves_the_fec_block_id() {
        let base = Instant::now();
        let config = ExtConfig {
            bbr: BbrMode::Off,
            fec: FecMode::Fixed { k: 2, m: 1 },
            ack_interval: 2,
            max_shard_len: 1900,
        };
        let mut ext = PeerExtension::new(config);
        ext.handle_caps(caps(CapsFlags::FEC | CapsFlags::ACK, 2, 1), base);

        assert!(ext.fec_push(&[1u8; 40], base).unwrap().is_none());
        let first = ext.fec_push(&[2u8; 40], base).unwrap().expect("block");
        assert_eq!(first.block_id, 0);
        assert!(ext.fec_push(&[3u8; 40], base).unwrap().is_none());
        let second = ext.fec_push(&[4u8; 40], base).unwrap().expect("block");
        assert_eq!(second.block_id, 1);

        // Only the MTU changes: `k`/`m` stay the same, so TX stays active.
        ext.configure(ExtConfig {
            max_shard_len: 1200,
            ..config
        });
        assert!(ext.fec_tx_active());
        assert_eq!(ext.fec_tx.as_ref().unwrap().block_id(), 2);

        assert!(ext.fec_push(&[5u8; 40], base).unwrap().is_none());
        let third = ext.fec_push(&[6u8; 40], base).unwrap().expect("block");
        assert_eq!(
            third.block_id, 2,
            "a recreated encoder must not restart the peer-visible sequence"
        );
    }

    #[test]
    fn aborted_control_flush_keeps_every_frame() {
        let base = Instant::now();
        let mut ext = PeerExtension::default();
        let first = ControlFrame::owned(ControlKind::FecShard, vec![1u8; 8]);
        let second = ControlFrame::owned(ControlKind::FecShard, vec![2u8; 8]);
        let third = ControlFrame::owned(ControlKind::FecShard, vec![3u8; 8]);
        ext.push_control(first.clone());
        ext.push_control(second.clone());
        ext.push_control(third.clone());

        let frames = ext.pending_control(base);
        assert_eq!(frames, vec![first, second.clone(), third.clone()]);
        // The first frame was sent; the flush then hit `NoEndpoint`/`NoKeypair`
        // on the second one and the caller pushed it back.
        ext.note_frame_sent(frames[0].kind(), base);
        ext.push_control(frames[1].clone());

        let remaining = ext.pending_control(base);
        assert_eq!(
            remaining,
            vec![second, third],
            "the aborted tail must be resent"
        );
        assert_eq!(ext.fec_stats.dropped_control, 0);
    }

    #[test]
    fn dropped_control_is_counted_and_not_resent() {
        let base = Instant::now();
        let mut ext = PeerExtension::default();
        let frame = ControlFrame::owned(ControlKind::FecShard, vec![7u8; 8]);
        ext.push_control(frame);
        let frames = ext.pending_control(base);
        assert_eq!(frames.len(), 1);
        // An encryption failure that is not recoverable drops this frame.
        ext.note_control_drop();
        assert_eq!(ext.fec_stats().unwrap().dropped_control, 1);
        assert!(ext.pending_control(base).is_empty());
    }

    #[test]
    fn reset_feedback_keeps_negotiated_caps_and_rearms_the_exchange() {
        let base = Instant::now();
        let config = ExtConfig {
            bbr: BbrMode::On,
            fec: FecMode::Fixed { k: 2, m: 1 },
            ack_interval: 2,
            max_shard_len: 1900,
        };
        let mut ext = PeerExtension::new(config);
        let frames = ext.pending_control(base);
        for frame in &frames {
            ext.note_frame_sent(frame.kind(), base);
        }
        let peer = caps(CapsFlags::ACK | CapsFlags::FEC, 2, 1);
        ext.handle_caps(peer, base);
        assert!(ext.caps_attempts >= 1);
        assert!(ext.fec_tx_active());

        ext.reset_feedback();
        assert_eq!(ext.caps_attempts, 0);
        assert!(ext.caps_seen.is_none());
        assert!(ext.caps_last_sent.is_none());
        assert!(ext.caps_next.is_none());
        assert_eq!(
            ext.peer_caps,
            CapsFlags::ACK | CapsFlags::FEC,
            "capabilities are a device property and must survive a rekey"
        );
        assert_eq!((ext.peer_fec_k, ext.peer_fec_m), (2, 1));
        assert!(
            ext.fec_tx_active(),
            "FEC TX must stay negotiated across the keypair switch"
        );
        assert!(ext.bbr.is_some(), "BBR restarts with an empty ring");
    }

    #[test]
    fn caps_changes_after_a_keypair_reset_are_still_applied() {
        let base = Instant::now();
        let config = ExtConfig {
            bbr: BbrMode::Off,
            fec: FecMode::Fixed { k: 2, m: 1 },
            ack_interval: 2,
            max_shard_len: 1900,
        };
        let mut ext = PeerExtension::new(config);
        ext.handle_caps(caps(CapsFlags::ACK | CapsFlags::FEC, 2, 1), base);

        ext.reset_feedback();
        assert!(ext.fec_tx_active(), "the old profile is still valid");

        ext.handle_caps(
            caps(CapsFlags::ACK | CapsFlags::FEC, 3, 1),
            base + Duration::from_millis(1),
        );
        assert_eq!(
            (ext.peer_fec_k, ext.peer_fec_m),
            (3, 1),
            "a changed peer profile must be applied after a rekey"
        );
        assert!(
            !ext.fec_tx_active(),
            "a mismatched profile must disable FEC TX until the peer changes back"
        );

        ext.handle_caps(
            caps(CapsFlags::ACK | CapsFlags::FEC, 2, 1),
            base + Duration::from_millis(2),
        );
        assert!(ext.fec_tx_active());
    }

    #[test]
    fn full_size_shards_survive_a_profile_change() {
        let base = Instant::now();
        let config = ExtConfig {
            bbr: BbrMode::Off,
            fec: FecMode::Fixed { k: 2, m: 1 },
            ack_interval: 2,
            max_shard_len: 1385,
        };
        let mut ext = PeerExtension::new(config);
        ext.handle_caps(caps(CapsFlags::ACK | CapsFlags::FEC, 2, 1), base);
        assert!(ext.fec_push(&[0x5a; 1352], base).unwrap().is_none());

        // Turning FEC off must still release the block that was flushed from
        // the encoder; a stranded shard used to stay pending forever because
        // `pending_control` short-circuited on `local_caps == 0`.
        ext.configure(ExtConfig {
            fec: FecMode::Off,
            ..config
        });

        let frames = ext.pending_control(base);
        let shards: Vec<&ControlFrame> = frames
            .iter()
            .filter(|frame| frame.kind() == ControlKind::FecShard)
            .collect();
        assert_eq!(shards.len(), 1, "the flushed block must leave the queue");
        assert!(
            shards[0].bytes().len() > 1024,
            "the frame is a full-size FEC shard, not a tiny ACK"
        );
        assert_eq!(ext.fec_stats.dropped_control, 0);
        for frame in &frames {
            ext.note_frame_sent(frame.kind(), base);
        }
        assert!(
            ext.pending_control(base).is_empty(),
            "nothing may stay pending after the flush"
        );
    }

    #[test]
    fn full_size_shards_survive_a_keypair_reset() {
        let base = Instant::now();
        let config = ExtConfig {
            bbr: BbrMode::On,
            fec: FecMode::Fixed { k: 2, m: 1 },
            ack_interval: 2,
            max_shard_len: 1385,
        };
        let mut ext = PeerExtension::new(config);
        ext.handle_caps(caps(CapsFlags::ACK | CapsFlags::FEC, 2, 1), base);
        assert!(ext.fec_push(&[0x5a; 1352], base).unwrap().is_none());

        ext.reset_feedback();

        let frames = ext.pending_control(base);
        let shards: Vec<&ControlFrame> = frames
            .iter()
            .filter(|frame| frame.kind() == ControlKind::FecShard)
            .collect();
        assert_eq!(shards.len(), 1);
        assert!(shards[0].bytes().len() > 1024);
        assert_eq!(ext.fec_stats.dropped_control, 0);
        for frame in &frames {
            ext.note_frame_sent(frame.kind(), base);
        }
        assert!(ext.pending_control(base).is_empty());
    }

    #[test]
    fn control_queue_overflow_is_counted_not_silent() {
        let mut ext = PeerExtension::default();
        for _ in 0..(CONTROL_QUEUE_CAPACITY + 2) {
            ext.push_control(ControlFrame::owned(ControlKind::FecShard, vec![0u8; 8]));
        }
        assert_eq!(ext.pending.len(), CONTROL_QUEUE_CAPACITY);
        assert_eq!(ext.fec_stats.dropped_control, 2);
    }

    #[test]
    fn control_queue_stays_bounded_across_flushes() {
        let base = Instant::now();
        let mut ext = PeerExtension::default();
        for index in 0..CONTROL_QUEUE_CAPACITY {
            ext.push_control(ControlFrame::owned(
                ControlKind::FecShard,
                vec![u8::try_from(index).unwrap(); 8],
            ));
        }

        let handed = ext.pending_control(base);
        assert_eq!(handed.len(), CONTROL_QUEUE_CAPACITY);
        assert_eq!(
            ext.pending.len(),
            CONTROL_QUEUE_CAPACITY,
            "handing frames out must not duplicate or extend the queue"
        );

        ext.push_control(ControlFrame::owned(ControlKind::FecShard, vec![0xff; 8]));
        assert_eq!(ext.pending.len(), CONTROL_QUEUE_CAPACITY);
        assert_eq!(ext.fec_stats.dropped_control, 1);

        for frame in &handed {
            ext.note_frame_sent(frame.kind(), base);
        }
        assert!(ext.pending.is_empty());
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
    fn fec_encode_counters_track_full_and_partial_blocks() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(ExtConfig {
            bbr: BbrMode::Off,
            fec: FecMode::Fixed { k: 2, m: 1 },
            ack_interval: 2,
            max_shard_len: 1900,
        });
        ext.handle_caps(caps(CapsFlags::FEC | CapsFlags::ACK, 2, 1), base);

        assert!(ext.fec_push(&[1u8; 20], base).unwrap().is_none());
        assert_eq!(ext.fec_stats().unwrap().blocks_encoded, 0);
        let block = ext.fec_push(&[2u8; 20], base).unwrap().expect("full block");
        assert_eq!(block.shards.len(), 3);
        assert_eq!(ext.fec_stats().unwrap().blocks_encoded, 1);

        assert!(ext.fec_push(&[3u8; 20], base).unwrap().is_none());
        let partial = ext
            .fec_flush_due(base + Duration::from_millis(5))
            .expect("partial block is due");
        assert_eq!(partial.m, 0);
        assert_eq!(ext.fec_stats().unwrap().blocks_encoded, 2);
    }

    #[test]
    fn fec_decode_counters_track_recovery_and_failures() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(ExtConfig {
            bbr: BbrMode::Off,
            fec: FecMode::Fixed { k: 2, m: 1 },
            ack_interval: 2,
            max_shard_len: 1900,
        });
        ext.handle_caps(caps(CapsFlags::FEC | CapsFlags::ACK, 2, 1), base);
        let (shard_len, shards) = fec_block_fixture();

        let packets = ext.fec_decode(
            FecShard {
                block_id: 4,
                index: 0,
                k: 2,
                m: 1,
                shard_len,
                payload: &shards[0],
            },
            base,
        );
        assert!(packets.is_empty());
        let packets = ext.fec_decode(
            FecShard {
                block_id: 4,
                index: 2,
                k: 2,
                m: 1,
                shard_len,
                payload: &shards[2],
            },
            base,
        );
        assert_eq!(packets.len(), 2);

        let stats = ext.fec_stats().expect("fec is configured");
        assert_eq!(stats.blocks_decoded, 1);
        assert_eq!(stats.packets_recovered, 1);
        assert_eq!(stats.decode_fail, 0);

        let oversized = vec![0u8; usize::from(umbrawg_fec::MAX_SHARD_LEN) + 1];
        assert!(ext
            .fec_decode(
                FecShard {
                    block_id: 5,
                    index: 0,
                    k: 2,
                    m: 1,
                    shard_len: umbrawg_fec::MAX_SHARD_LEN + 1,
                    payload: &oversized,
                },
                base,
            )
            .is_empty());
        let stats = ext.fec_stats().expect("fec is configured");
        assert_eq!(stats.decode_fail, 1);
        assert_eq!(stats.dropped_bounds, 1);
        assert_eq!(stats.blocks_decoded, 1);
    }

    #[test]
    fn fec_shards_are_dropped_when_fec_is_disabled() {
        let base = Instant::now();
        let mut ext = PeerExtension::default();
        let (shard_len, shards) = fec_block_fixture();
        assert!(ext
            .fec_decode(
                FecShard {
                    block_id: 0,
                    index: 0,
                    k: 2,
                    m: 1,
                    shard_len,
                    payload: &shards[0],
                },
                base,
            )
            .is_empty());
        assert_eq!(ext.fec_stats.dropped_disabled, 1);
        let stats = ext
            .fec_stats()
            .expect("counters stay observable with FEC off");
        assert_eq!(stats.dropped_disabled, 1);
        assert_eq!(stats.dropped_control, 0);
    }

    #[test]
    fn loss_window_uses_the_kernel_ewma() {
        let mut window = LossWindow::default();
        let base = Instant::now();

        // First window: 0..=255, then counter 256 one second later closes it.
        for counter in 0..=255u64 {
            window.observe(counter, base);
        }
        assert_eq!(window.loss_q16, 0);
        assert!(window.observe(256, base + ADAPTIVE_SETTLE_TIME));
        assert_eq!(window.loss_q16, 0);
        assert_eq!(window.observed, 257);

        // One missing counter: 1/256 == 256 in q16 units. The kernel seeds
        // the estimate with the first non-zero sample.
        let now = base + Duration::from_secs(2);
        for counter in 258..=511u64 {
            window.observe(counter, now);
        }
        assert!(window.observe(512, now + ADAPTIVE_SETTLE_TIME));
        assert_eq!(window.loss_q16, 256);
        assert_eq!(window.observed, 513);

        // Two missing counters: sample 512, smoothed as (256 * 3 + 512) / 4.
        let now = now + Duration::from_secs(2);
        for counter in 515..=767u64 {
            window.observe(counter, now);
        }
        assert!(window.observe(768, now + ADAPTIVE_SETTLE_TIME));
        assert_eq!(window.loss_q16, 320);
        assert_eq!(window.observed, 769);
    }

    #[test]
    fn loss_window_restarts_on_implausible_gaps() {
        let base = Instant::now();
        let mut window = LossWindow::default();
        window.observe(10, base);
        let forward = 10 + ADAPTIVE_WINDOW_MAX + 1;
        assert!(!window.observe(forward, base + ADAPTIVE_SETTLE_TIME));
        assert_eq!(window.observed, 0);
        assert_eq!(window.base, forward + 1);

        let mut window = LossWindow::default();
        window.observe(2 * ADAPTIVE_GAP_MAX, base);
        window.observe(2 * ADAPTIVE_GAP_MAX, base);
        assert!(!window.observe(1, base + ADAPTIVE_SETTLE_TIME));
        assert_eq!(window.observed, 0);
        assert!(window.valid);
        assert_eq!(window.largest, 1);
    }

    #[test]
    fn loss_window_waits_for_the_settle_interval() {
        let mut window = LossWindow::default();
        let base = Instant::now();
        // 192 counters plus the window maximum: the old fixed-count observer
        // closed here and counted the 63 late counters as loss.
        for counter in 0..=191u64 {
            window.observe(counter, base);
        }
        assert!(!window.observe(255, base));
        assert_eq!(window.observed, 0, "the window must stay open");

        // The reordered tail arrives 200 ms later, still inside the settle
        // interval, and fills the window.
        for counter in 192..=254u64 {
            window.observe(counter, base + Duration::from_millis(200));
        }
        assert!(window.observe(256, base + ADAPTIVE_SETTLE_TIME));
        assert_eq!(window.loss_q16, 0, "reordering is not loss");
    }

    fn adaptive_ext() -> PeerExtension {
        PeerExtension::new(ExtConfig {
            bbr: BbrMode::Off,
            fec: FecMode::Adaptive,
            ack_interval: 2,
            max_shard_len: 1900,
        })
    }

    /// Feeds `windows` segments of 256 counters, closing each segment with
    /// the first counter of the next one after `step` (longer than the settle
    /// interval). `missing` counters never arrive.
    fn feed_adaptive_windows(
        ext: &mut PeerExtension,
        first: u64,
        windows: u64,
        start: Instant,
        step: Duration,
        missing: impl Fn(u64) -> bool,
    ) -> u64 {
        let mut counter = first;
        let mut now = start;
        for _ in 0..windows {
            for value in counter..counter + 256 {
                if !missing(value) {
                    ext.observe_received(value, now);
                }
            }
            counter += 256;
            now += step;
            ext.observe_received(counter, now);
            counter += 1;
        }
        counter
    }

    #[test]
    fn adaptive_ignores_reordering_on_a_fast_link() {
        let base = Instant::now();
        let mut ext = adaptive_ext();
        let mut counter = 0u64;

        // 25 % of every window arrives late, but well inside the one-second
        // settle interval. The old fixed-count observer closed the window at
        // the largest counter and counted all of them as loss.
        for block in 0..6u64 {
            let at = base + Duration::from_millis(1500 * block);
            let end = (block + 1) * 256;
            let mut delayed = Vec::new();
            for value in counter..end {
                if value + 1 != end && value % 4 == 3 {
                    delayed.push(value);
                } else {
                    ext.observe_received(value, at);
                }
            }
            for value in delayed {
                ext.observe_received(value, at + Duration::from_millis(200));
            }
            counter = end;
        }
        ext.observe_received(counter, base + Duration::from_millis(1500 * 6));

        assert!(ext.loss.observed >= ADAPTIVE_OBSERVE_MIN);
        assert_eq!(ext.loss.loss_q16, 0, "reordering must not look like loss");
        assert!(
            !ext.fec_active,
            "25 % reordering must not enable adaptive parity"
        );
    }

    #[test]
    fn adaptive_enables_on_real_loss_and_switches_off_after_hysteresis() {
        let base = Instant::now();
        let mut ext = adaptive_ext();
        let step = Duration::from_millis(1500);

        // ~2 % of every window is genuinely lost.
        let next = feed_adaptive_windows(&mut ext, 0, 6, base, step, |counter| counter % 52 == 0);
        assert!(
            ext.fec_active,
            "1.9 % real loss must enable adaptive parity"
        );

        // A couple of clean windows are not enough to switch off.
        let clean_at = base + Duration::from_millis(1500 * 6);
        let next = feed_adaptive_windows(&mut ext, next, 2, clean_at, step, |_| false);
        assert!(ext.fec_active);

        let clean_at = clean_at + Duration::from_millis(1500 * 2);
        feed_adaptive_windows(&mut ext, next, 16, clean_at, step, |_| false);
        assert!(
            !ext.fec_active,
            "parity must switch off after the five-second clean window"
        );
        assert_eq!(ext.loss.loss_q16, 0);
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
        assert!(stats.lost_packets >= 1);
        assert_eq!(stats.orphaned_packets, 0);
    }

    #[test]
    fn control_flush_is_serialized_between_workers() {
        let base = Instant::now();
        let mut ext = PeerExtension::default();
        for value in [1u8, 2] {
            let frame = ControlFrame::inline(ControlKind::Ack, |output| {
                output[0] = value;
                Some(1)
            })
            .expect("frame fits");
            ext.push_control(frame);
        }

        let first = ext.begin_control_flush(base);
        assert_eq!(first.len(), 2);
        assert!(
            ext.begin_control_flush(base).is_empty(),
            "a concurrent flush must not clone the frames already being sent"
        );

        // Abort after the first frame: the second stays queued exactly once.
        ext.note_frame_sent(first[0].kind(), base);
        let second = first[1].clone();
        ext.push_control(second);
        ext.finish_control_flush();

        let resent = ext.begin_control_flush(base);
        assert_eq!(resent.len(), 1, "the aborted frame must not be lost");
        ext.note_frame_sent(resent[0].kind(), base);
        ext.finish_control_flush();
        assert!(ext.begin_control_flush(base).is_empty());
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
