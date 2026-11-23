//! Peer-level protocol extension: capabilities and FEC.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::warn;
use rand_core::RngCore;
use umbrawg_fec::{
    DecodedBlock, EncodedBlock, FecConfig, FecDecoder, FecEncoder, FecError, FecShard,
};
use umbrawg_proto::control::{Caps, CapsFlags, ControlKind, FecShardHeader};

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
/// Lower bound of the randomized partial FEC block deadline.
///
/// This is only the batching window for packets of one burst, not a latency
/// target: the daemon's poll timeout is rounded up to whole milliseconds
/// (`poll_timeout_ms`), so a block that stops filling is actually sent on the
/// next 1 ms wake-up. Sparse packets do not go through this timer at all —
/// see [`FEC_SOLO_GAP`] — so the deadline can stay short without trading away
/// the RTT of an idle flow.
const FEC_DEADLINE_MIN_US: u64 = 100;
/// Upper bound of the randomized partial FEC block deadline.
const FEC_DEADLINE_MAX_US: u64 = 300;
/// Idle gap after which the next packet opens a block and is flushed at once.
///
/// A sparse flow (ping, a keepalive, one TCP segment per RTT) otherwise waits
/// for [`FEC_DEADLINE_MIN_US`..`FEC_DEADLINE_MAX_US`] plus the poll timeout,
/// which is what turned a 0.3 ms RTT into 3.7–4.3 ms with FEC 2:1. Packets
/// that arrive closer together than this still share one block, so bulk
/// traffic keeps the full `k`-packet batching and its parity efficiency: a
/// saturated flow is read from the TUN in batches, and the few hundred
/// microseconds between two batches must not turn into a one-packet block.
const FEC_SOLO_GAP: Duration = Duration::from_millis(2);
/// Longest gap between two shards of one RX block before it is released.
///
/// The decoder deadline slides with every accepted shard (`umbrawg-fec`), so
/// this bounds the *stall* of one block, not its total duration: an `8:2`
/// block on a 10 Mbit/s link is spread over ~11 ms, but consecutive shards
/// are only a serialization time (~1.1 ms) plus queuing apart. Keeping the
/// stall short bounds the head-of-line wait after a lost block;
/// `MAX_BLOCK_HOLD` in `umbrawg-fec` bounds the whole block.
const FEC_RX_BLOCK_TIMEOUT: Duration = Duration::from_millis(2);
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

/// FEC mode configured for the device.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FecMode {
    /// Disabled.
    Off,
    /// Adaptive mode: parity is enabled only after measured loss.
    #[default]
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
    /// counters so a lost CAPS frame or shard never becomes a silent black hole.
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
    /// FEC mode.
    pub fec: FecMode,
    /// Maximum FEC shard payload (including the two-byte length prefix).
    pub max_shard_len: u16,
}

impl Default for ExtConfig {
    fn default() -> Self {
        Self {
            fec: FecMode::Adaptive,
            max_shard_len: DEFAULT_MAX_SHARD_LEN,
        }
    }
}

impl ExtConfig {
    fn local_caps(self) -> CapsFlags {
        if self.fec == FecMode::Off {
            return CapsFlags::default();
        }
        let mut flags = CapsFlags::FEC | CapsFlags::FEC_PARTIAL;
        if self.fec == FecMode::Adaptive {
            flags = flags | CapsFlags::FEC_ADAPTIVE;
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

/// Largest CAPS frame kept inline in a [`ControlFrame`].
///
/// A CAPS frame is 20 bytes, so it never touches the allocator on the send
/// path.
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
    fec_tx: Option<FecEncoder>,
    /// Next `block_id` used when the encoder is recreated by a reconfiguration.
    next_block_id: u32,
    fec_rx: Option<FecDecoder>,
    fec_active: bool,
    fec_stats: FecStats,
    loss: LossWindow,
    adaptive_clean_since: Option<Instant>,
    fec_deadline: Option<Instant>,
    /// Arrival time of the last packet handed to the FEC encoder.
    ///
    /// Used to tell a lone packet after an idle gap (flushed at once) from a
    /// packet inside a burst (batched into a full block).
    last_fec_push: Option<Instant>,
    jitter: Jitter,
    /// Single control queue, bounded by [`CONTROL_QUEUE_CAPACITY`].
    ///
    /// Frames are removed only when [`Self::note_frame_sent`] confirms them,
    /// so an aborted flush needs no second copy and cannot double the limit.
    pending: VecDeque<ControlFrame>,
    /// Last time an unsupported peer FEC profile was logged.
    caps_warn_last: Option<Instant>,
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
            // A sentinel that always differs from `config`, so `apply` builds
            // the initial FEC state even when `config` equals the defaults.
            config: ExtConfig {
                fec: FecMode::Off,
                max_shard_len: 0,
            },
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
            fec_tx: None,
            next_block_id: 0,
            fec_rx: None,
            fec_active: false,
            fec_stats: FecStats::default(),
            loss: LossWindow::default(),
            adaptive_clean_since: None,
            fec_deadline: None,
            last_fec_push: None,
            jitter: Jitter::seeded(),
            pending: VecDeque::new(),
            caps_warn_last: None,
            control_flush_active: false,
        };
        extension.apply(config);
        extension
    }

    /// Applies a device-wide configuration change.
    ///
    /// A configuration that did not change is a no-op: the peer keeps its
    /// negotiated capabilities and all live state (encoder queue, decoder,
    /// adaptive loss estimate). A real change first flushes queued packets so
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
        let fec_changed = config.fec != previous.fec
            || (config.fec.config().is_some() && config.max_shard_len != previous.max_shard_len);
        if fec_changed {
            let fec = config.fec.config();
            let block_id = self.next_block_id;
            self.fec_tx = fec.map(|fec| {
                FecEncoder::with_block_id(fec, usize::from(config.max_shard_len), block_id)
            });
            self.fec_rx = fec.map(fec_decoder);
            self.fec_active = !matches!(config.fec, FecMode::Off | FecMode::Adaptive);
            self.loss = LossWindow::default();
            self.adaptive_clean_since = None;
            self.fec_deadline = None;
            self.last_fec_push = None;
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
        let parity = self.partial_parity();
        let block = self
            .fec_tx
            .as_mut()
            .and_then(|encoder| encoder.flush_with_parity_rng(parity, &mut self.jitter));
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

    /// `true` while adaptive FEC has switched parity on for this peer.
    ///
    /// The daemon uses it to keep the TUN MTU at its base value until
    /// adaptive FEC actually starts protecting traffic.
    pub(crate) fn fec_adaptive_active(&self) -> bool {
        self.config.fec == FecMode::Adaptive && self.fec_active
    }

    pub(crate) fn fec_tx_active(&self) -> bool {
        self.fec_active
            && self.fec_tx.is_some()
            && self.peer_caps.contains(CapsFlags::FEC)
            && self.fec_profile_matches()
    }

    /// Parity shards to attach to a partial block sent to this peer.
    ///
    /// Partial parity is only emitted when the peer advertised both
    /// [`CapsFlags::FEC`] and [`CapsFlags::FEC_PARTIAL`]; otherwise the legacy
    /// `m = 0` form keeps the wire compatible. The local `m` is returned as-is
    /// and clamped by the encoder, so a mismatch cannot exceed the negotiated
    /// profile.
    fn partial_parity(&self) -> u8 {
        if !self
            .peer_caps
            .contains(CapsFlags::FEC | CapsFlags::FEC_PARTIAL)
        {
            return 0;
        }
        self.config.fec_profile().map_or(0, |(_, m)| m)
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
        // A packet that opens a block after an idle gap is not worth batching:
        // sending it now (with partial parity) removes the deadline from the
        // RTT of a sparse flow, while a burst still fills a whole block.
        let solo = self
            .last_fec_push
            .is_some_and(|last| now.saturating_duration_since(last) >= FEC_SOLO_GAP)
            && self
                .fec_tx
                .as_ref()
                .is_some_and(|encoder| encoder.pending() == 0);
        let jitter = &mut self.jitter;
        let result = self
            .fec_tx
            .as_mut()
            .map_or(Ok(None), |encoder| encoder.push_with_rng(packet, jitter));
        match result {
            Ok(Some(_)) => {
                self.last_fec_push = Some(now);
                self.fec_deadline = None;
                self.fec_stats.blocks_encoded = self.fec_stats.blocks_encoded.saturating_add(1);
                result
            }
            Ok(None) => {
                self.last_fec_push = Some(now);
                if solo {
                    return Ok(self.flush_partial_block());
                }
                if self.fec_deadline.is_none() {
                    let delay = self
                        .jitter
                        .range_inclusive(FEC_DEADLINE_MIN_US, FEC_DEADLINE_MAX_US);
                    self.fec_deadline = Some(now + Duration::from_micros(delay));
                }
                result
            }
            Err(_) => result,
        }
    }

    pub(crate) fn fec_flush_due(&mut self, now: Instant) -> Option<umbrawg_fec::EncodedBlock> {
        if !self.fec_tx_active() {
            return None;
        }
        if !self.fec_deadline.is_some_and(|deadline| now >= deadline) {
            return None;
        }
        self.flush_partial_block()
    }

    /// Emits the packets held by the encoder as a partial block with parity.
    ///
    /// Both the solo flush of an idle flow and the deadline flush go through
    /// here, so the wire form (including the negotiated partial parity) is
    /// identical and neither path can drop a queued packet.
    fn flush_partial_block(&mut self) -> Option<umbrawg_fec::EncodedBlock> {
        self.fec_deadline = None;
        let parity = self.partial_parity();
        let jitter = &mut self.jitter;
        let block = self
            .fec_tx
            .as_mut()
            .and_then(|encoder| encoder.flush_with_parity_rng(parity, jitter));
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

    /// Earliest deadline owned by the extension: a partially filled FEC block
    /// that must be flushed.
    ///
    /// The daemon uses it to size its poll timeout instead of waiting for the
    /// next data packet or the idle tick.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.fec_deadline
    }

    pub(crate) fn observe_received(&mut self, counter: u64, now: Instant) {
        self.observe_adaptive(counter, now);
    }

    /// Resets the per-keypair state after the peer installed a new keypair.
    ///
    /// Wire counters and FEC `block_id`s live inside one keypair, so the
    /// adaptive loss estimate and the FEC decoder's block clock are discarded.
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
        if let Some(fec) = self.config.fec.config() {
            self.fec_rx = Some(fec_decoder(fec));
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
            caps.flags.bits()
                & !(CapsFlags::FEC.bits()
                    | CapsFlags::FEC_ADAPTIVE.bits()
                    | CapsFlags::FEC_PARTIAL.bits()),
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
    /// Only a CAPS frame spends an attempt; a zero CAPS is a revocation
    /// rather than a negotiation attempt, so it only advances the revocation
    /// rate limiter.
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
        // Producing new CAPS frames needs our advertised capabilities.
        // Frames that already sit in the queue, however, must always leave:
        // an encoder flushed right before FEC was turned off would otherwise
        // stay pending forever (and its block would never reach the peer).
        if self.local_caps.bits() != 0 {
            self.request_caps(now);
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

/// Builds the RX decoder with the daemon's short stall timeout.
///
/// The library default is generous so that a block on a slow link is not cut
/// off; the daemon instead relies on the sliding deadline (which follows a
/// slow but steady stream of shards) and wants the in-order release to move
/// on quickly after a lost block, hence [`FEC_RX_BLOCK_TIMEOUT`].
fn fec_decoder(config: FecConfig) -> FecDecoder {
    FecDecoder::with_timeout(config, FEC_RX_BLOCK_TIMEOUT)
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
            .field("fec", &self.config.fec)
            .field("peer_caps", &self.peer_caps.bits())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FEC_CONFIG: ExtConfig = ExtConfig {
        fec: FecMode::Fixed { k: 2, m: 1 },
        max_shard_len: 1900,
    };

    fn caps(flags: CapsFlags, fec_k: u8, fec_m: u8) -> Caps {
        Caps {
            flags,
            fec_k,
            fec_m,
        }
    }

    fn kinds(frames: &[ControlFrame]) -> Vec<ControlKind> {
        frames.iter().map(ControlFrame::kind).collect()
    }

    const fn off_config() -> ExtConfig {
        ExtConfig {
            fec: FecMode::Off,
            max_shard_len: DEFAULT_MAX_SHARD_LEN,
        }
    }

    fn off_ext() -> PeerExtension {
        PeerExtension::new(off_config())
    }

    #[test]
    fn control_frames_are_typed_by_kind() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(FEC_CONFIG);
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
    fn control_backlog_is_bounded_and_keeps_kind() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(FEC_CONFIG);
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

    #[test]
    fn peer_caps_answers_once_with_a_fast_bounded_retry() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(FEC_CONFIG);
        let peer = caps(CapsFlags::FEC, 2, 1);

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

        let changed = caps(CapsFlags::FEC | CapsFlags::FEC_ADAPTIVE, 2, 1);
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
            fec: FecMode::Fixed { k: 4, m: 2 },
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
            fec: FecMode::Fixed { k: 4, m: 2 },
            max_shard_len: 1900,
        });
        ext.handle_caps(caps(CapsFlags::FEC | CapsFlags::FEC_PARTIAL, 4, 2), base);
        let mut delays = Vec::new();
        // Two packets inside one burst: the first one arms the deadline, the
        // second one is still batched because the gap stays below the solo
        // threshold, so neither is flushed early.
        let mut now = base;
        for _ in 0..64 {
            assert!(ext.fec_push(&[9u8; 20], now).unwrap().is_none());
            let deadline = ext.fec_deadline.expect("deadline is armed");
            delays.push(deadline.saturating_duration_since(now));
            let second = now + FEC_SOLO_GAP / 100;
            assert!(ext.fec_push(&[8u8; 20], second).unwrap().is_none());
            assert_eq!(ext.fec_tx.as_ref().unwrap().pending(), 2);
            assert!(ext.fec_flush_due(second).is_none(), "not due yet");
            let block = ext
                .fec_flush_due(deadline + Duration::from_micros(1))
                .expect("partial block is due");
            assert_eq!(block.m, 2, "partial parity is preserved");
            assert_eq!(block.k, 2);
            assert!(usize::from(block.shard_len) >= 22);
            assert!(ext.fec_deadline.is_none());
            now = deadline + FEC_SOLO_GAP / 100;
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
    fn fec_deadline_budget_stays_sub_millisecond() {
        // The partial deadline is the extra RTT of a batched flow, so it must
        // stay well below one poll timeout (which rounds up to a whole ms).
        assert!(Duration::from_micros(FEC_DEADLINE_MAX_US) < Duration::from_millis(1));
        assert!(
            Duration::from_micros(FEC_DEADLINE_MIN_US) < Duration::from_micros(FEC_DEADLINE_MAX_US)
        );
        assert!(FEC_SOLO_GAP <= Duration::from_millis(2));
    }

    fn fixed_two_to_one(caps_flags: CapsFlags) -> PeerExtension {
        let now = Instant::now();
        let mut ext = PeerExtension::new(ExtConfig {
            fec: FecMode::Fixed { k: 2, m: 1 },
            max_shard_len: 1900,
        });
        ext.handle_caps(caps(caps_flags, 2, 1), now);
        assert!(ext.fec_tx_active());
        ext
    }

    #[test]
    fn fec_lone_packet_after_an_idle_gap_is_flushed_immediately() {
        let base = Instant::now();
        let mut ext = fixed_two_to_one(CapsFlags::FEC | CapsFlags::FEC_PARTIAL);
        // First packet ever: there is no spacing history yet, so it is batched
        // and the deadline is armed instead of being sent half-empty.
        assert!(ext.fec_push(&[1u8; 20], base).unwrap().is_none());
        assert!(ext.fec_deadline.is_some());
        let flushed = ext
            .fec_flush_due(base + Duration::from_micros(FEC_DEADLINE_MAX_US))
            .expect("deadline flush");
        assert_eq!((flushed.k, flushed.m), (1, 1));

        // Traffic stops for longer than the solo gap: the next packet must not
        // wait for any timer, and it keeps its partial parity.
        let idle = base + FEC_SOLO_GAP + Duration::from_millis(5);
        let block = ext
            .fec_push(&[2u8; 30], idle)
            .unwrap()
            .expect("a lone packet is sent at once");
        assert_eq!((block.k, block.m), (1, 1));
        assert_eq!(block.shards.len(), 2);
        assert!(ext.fec_deadline.is_none(), "no timer may stay armed");
        assert_eq!(ext.fec_tx.as_ref().unwrap().pending(), 0);
    }

    #[test]
    fn fec_burst_still_batches_packets_into_a_full_block() {
        let base = Instant::now();
        let mut ext = fixed_two_to_one(CapsFlags::FEC | CapsFlags::FEC_PARTIAL);
        // The first packet of a burst is batched (its deadline is armed) ...
        assert!(ext.fec_push(&[1u8; 20], base).unwrap().is_none());
        assert!(ext.fec_deadline.is_some(), "the deadline is armed");
        // ... and a packet arriving well inside the solo gap completes the
        // block, which is sent at once without any timer.
        let block = ext
            .fec_push(&[2u8; 20], base + FEC_SOLO_GAP / 2)
            .unwrap()
            .expect("full block");
        assert_eq!((block.k, block.m), (2, 1));
        assert_eq!(block.shards.len(), 3);
        assert!(ext.fec_deadline.is_none(), "a full block needs no timer");
    }

    #[test]
    fn fec_solo_flush_keeps_the_legacy_shape_without_partial_parity() {
        let base = Instant::now();
        let mut ext = fixed_two_to_one(CapsFlags::FEC);
        assert!(ext.fec_push(&[1u8; 20], base).unwrap().is_none());
        let _ = ext
            .fec_flush_due(base + Duration::from_micros(FEC_DEADLINE_MAX_US))
            .expect("deadline flush");
        let block = ext
            .fec_push(&[2u8; 20], base + FEC_SOLO_GAP + Duration::from_millis(1))
            .unwrap()
            .expect("solo block");
        assert_eq!((block.k, block.m), (1, 0));
        assert_eq!(block.shards.len(), 1, "legacy peers get no parity");
    }

    #[test]
    fn fec_lone_packet_is_delivered_without_waiting_for_the_rx_timeout() {
        let base = Instant::now();
        let mut ext = fixed_two_to_one(CapsFlags::FEC | CapsFlags::FEC_PARTIAL);
        assert!(ext.fec_push(&[1u8; 20], base).unwrap().is_none());
        let _ = ext
            .fec_flush_due(base + Duration::from_micros(FEC_DEADLINE_MAX_US))
            .expect("deadline flush");
        let block = ext
            .fec_push(
                &[0x11u8; 24],
                base + FEC_SOLO_GAP + Duration::from_millis(1),
            )
            .unwrap()
            .expect("solo block");

        let mut rx = PeerExtension::new(ExtConfig {
            fec: FecMode::Fixed { k: 2, m: 1 },
            max_shard_len: 1900,
        });
        rx.fec_active = true;
        let mut delivered = Vec::new();
        // Lose the data shard: the parity shard alone must restore it at once,
        // long before the block timeout would release anything.
        for index in 1..block.shards.len() {
            delivered.extend(rx.fec_decode(
                FecShard {
                    block_id: block.block_id,
                    index: u8::try_from(index).unwrap(),
                    k: block.k,
                    m: block.m,
                    shard_len: block.shard_len,
                    payload: &block.shards[index],
                },
                base,
            ));
        }
        assert_eq!(delivered, vec![vec![0x11u8; 24]]);
        assert_eq!(rx.fec_stats().unwrap().packets_recovered, 1);
    }

    #[test]
    fn fec_rx_uses_the_short_daemon_stall_timeout() {
        let mut ext = PeerExtension::new(ExtConfig {
            fec: FecMode::Fixed { k: 2, m: 1 },
            max_shard_len: 1900,
        });
        let decoder = ext.fec_rx().expect("fec is configured");
        assert_eq!(decoder.timeout(), FEC_RX_BLOCK_TIMEOUT);
        assert_eq!(FEC_RX_BLOCK_TIMEOUT, Duration::from_millis(2));
    }

    #[test]
    fn fec_decode_follows_a_slow_block_instead_of_dropping_it() {
        // A 4:2 block whose shards arrive 1 ms apart spans 5 ms, well past the
        // 2 ms stall timeout. The decoder deadline slides with every shard, so
        // the daemon must deliver all four packets instead of finalizing the
        // block after its first two shards.
        let fec = FecConfig::new(4, 2).unwrap();
        let mut encoder = FecEncoder::new(fec, 1900);
        let packets: Vec<Vec<u8>> = (0..4u8).map(|index| vec![index; 40]).collect();
        let mut block = None;
        for packet in &packets {
            block = encoder.push(packet).unwrap().or(block);
        }
        let block = block.expect("full block");

        let mut ext = PeerExtension::new(ExtConfig {
            fec: FecMode::Fixed { k: 4, m: 2 },
            max_shard_len: 1900,
        });
        let base = Instant::now();
        let mut delivered = Vec::new();
        for index in 0..block.shards.len() {
            delivered.extend(ext.fec_decode(
                FecShard {
                    block_id: block.block_id,
                    index: u8::try_from(index).unwrap(),
                    k: block.k,
                    m: block.m,
                    shard_len: block.shard_len,
                    payload: &block.shards[index],
                },
                base + Duration::from_millis(u64::try_from(index).unwrap()),
            ));
        }
        assert_eq!(delivered, packets);
        let stats = ext.fec_stats().expect("fec is configured");
        assert_eq!(stats.blocks_decoded, 1);
        assert_eq!(stats.decode_fail, 0);
    }

    #[test]
    fn adaptive_profile_is_advertised_as_two_to_one() {
        let now = Instant::now();
        let mut ext = PeerExtension::new(ExtConfig {
            fec: FecMode::Adaptive,
            max_shard_len: 1900,
        });
        let frames = ext.pending_control(now);
        assert_eq!(kinds(&frames), vec![ControlKind::Caps]);
        let decoded = Caps::decode(frames[0].bytes()).expect("caps frame decodes");
        assert_eq!((decoded.fec_k, decoded.fec_m), (2, 1));

        ext.handle_caps(caps(CapsFlags::FEC | CapsFlags::FEC_ADAPTIVE, 2, 1), now);
        ext.fec_active = true;
        assert!(ext.fec_tx_active());

        ext.handle_caps(caps(CapsFlags::FEC | CapsFlags::FEC_ADAPTIVE, 3, 1), now);
        assert!(!ext.fec_tx_active());
    }

    #[test]
    fn partial_block_carries_parity_when_the_peer_supports_it() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(ExtConfig {
            fec: FecMode::Fixed { k: 2, m: 1 },
            max_shard_len: 1900,
        });
        ext.handle_caps(caps(CapsFlags::FEC | CapsFlags::FEC_PARTIAL, 2, 1), base);
        assert!(ext.fec_tx_active());

        assert!(ext.fec_push(&[9u8; 20], base).unwrap().is_none());
        let block = ext
            .fec_flush_due(base + Duration::from_millis(5))
            .expect("partial block is due");
        assert_eq!((block.k, block.m), (1, 1));
        assert_eq!(block.shards.len(), 2);
        assert!(usize::from(block.shard_len) >= 22);

        // The parity shard alone restores the packet: the decoder accepts the
        // partial `(1, 1)` shape although the local profile is `2:1`.
        let block_id = block.block_id;
        let shard_len = block.shard_len;
        let packets = ext.fec_decode(
            FecShard {
                block_id,
                index: 1,
                k: block.k,
                m: block.m,
                shard_len,
                payload: &block.shards[1],
            },
            base,
        );
        assert_eq!(packets, vec![vec![9u8; 20]]);
        assert_eq!(ext.fec_stats().unwrap().packets_recovered, 1);

        // A `k' = 2` partial block is still narrower than the local `4:2`
        // profile and must be decoded with its own shape.
        let mut wide = PeerExtension::new(ExtConfig {
            fec: FecMode::Fixed { k: 4, m: 2 },
            max_shard_len: 1900,
        });
        wide.handle_caps(caps(CapsFlags::FEC | CapsFlags::FEC_PARTIAL, 4, 2), base);
        assert!(wide.fec_push(&[1u8; 20], base).unwrap().is_none());
        assert!(wide.fec_push(&[2u8; 20], base).unwrap().is_none());
        let block = wide
            .fec_flush_due(base + Duration::from_millis(5))
            .expect("partial block is due");
        assert_eq!((block.k, block.m), (2, 2));
        assert_eq!(block.shards.len(), 4);
        let packets = wide.fec_decode(
            FecShard {
                block_id: block.block_id,
                index: 0,
                k: block.k,
                m: block.m,
                shard_len: block.shard_len,
                payload: &block.shards[0],
            },
            base,
        );
        assert!(packets.is_empty());
        let packets = wide.fec_decode(
            FecShard {
                block_id: block.block_id,
                index: 2,
                k: block.k,
                m: block.m,
                shard_len: block.shard_len,
                payload: &block.shards[2],
            },
            base,
        );
        assert_eq!(packets, vec![vec![1u8; 20], vec![2u8; 20]]);
    }

    #[test]
    fn partial_parity_requires_the_peer_flag() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(ExtConfig {
            fec: FecMode::Fixed { k: 2, m: 1 },
            max_shard_len: 1900,
        });
        ext.handle_caps(caps(CapsFlags::FEC, 2, 1), base);
        assert_eq!(ext.partial_parity(), 0);
        assert!(ext.fec_push(&[9u8; 20], base).unwrap().is_none());
        let block = ext
            .fec_flush_due(base + Duration::from_millis(5))
            .expect("partial block is due");
        assert_eq!((block.k, block.m), (1, 0), "no flag keeps the legacy m=0");

        ext.handle_caps(caps(CapsFlags::FEC | CapsFlags::FEC_PARTIAL, 2, 1), base);
        assert_eq!(ext.partial_parity(), 1);

        // The bit is only meaningful together with FEC, like the kernel.
        ext.handle_caps(caps(CapsFlags::FEC_PARTIAL, 2, 1), base);
        assert_eq!(ext.partial_parity(), 0);
    }

    #[test]
    fn fec_flags_are_advertised_only_when_fec_is_on() {
        let disabled = off_config();
        assert_eq!(disabled.local_caps().bits(), 0);

        let fixed = ExtConfig {
            fec: FecMode::Fixed { k: 2, m: 1 },
            ..ExtConfig::default()
        };
        let flags = fixed.local_caps();
        assert!(flags.contains(CapsFlags::FEC));
        assert!(flags.contains(CapsFlags::FEC_PARTIAL));
        assert!(!flags.contains(CapsFlags::FEC_ADAPTIVE));

        let adaptive = ExtConfig::default();
        assert_eq!(adaptive.fec, FecMode::Adaptive);
        let flags = adaptive.local_caps();
        assert!(flags.contains(CapsFlags::FEC));
        assert!(flags.contains(CapsFlags::FEC_PARTIAL));
        assert!(flags.contains(CapsFlags::FEC_ADAPTIVE));
    }

    #[test]
    fn disabled_extension_queues_no_control_frames() {
        let base = Instant::now();
        let mut ext = off_ext();
        ext.observe_received(11, base);
        assert!(ext
            .pending_control(base + Duration::from_millis(50))
            .is_empty());
    }

    #[test]
    fn peer_caps_grants_one_extra_send_after_budget_is_spent() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(FEC_CONFIG);
        ext.caps_attempts = CAPS_MAX_ATTEMPTS;
        ext.caps_last_sent = Some(base);
        ext.caps_next = Some(base + CAPS_SLOW_RETRY);
        ext.caps_seen = Some(caps(CapsFlags::FEC, 2, 1));

        let changed = caps(CapsFlags::FEC | CapsFlags::FEC_ADAPTIVE, 2, 1);
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
        let mut ext = off_ext();
        assert_eq!(ext.local_caps.bits(), 0);

        // A long-lived peer still advertises FEC while everything is off
        // locally: the next control flush must retract our capabilities.
        ext.handle_caps(caps(CapsFlags::FEC, 2, 1), base);
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
        ext.handle_caps(caps(CapsFlags::FEC, 2, 1), base + Duration::from_secs(1));
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
        let mut ext = off_ext();
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
            fec: FecMode::Fixed { k: 2, m: 1 },
            max_shard_len: 1900,
        });
        ext.handle_caps(caps(CapsFlags::FEC, 2, 1), base);
        let stale = Caps {
            flags: CapsFlags::FEC,
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

        ext.configure(off_config());
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
        let mut ext = off_ext();
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
            fec: FecMode::Fixed { k: 2, m: 1 },
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
            fec: FecMode::Fixed { k: 2, m: 1 },
            max_shard_len: 1900,
        });

        ext.handle_caps(caps(CapsFlags::FEC, 9, 1), base);
        assert!(!ext.peer_caps.contains(CapsFlags::FEC));
        assert_eq!((ext.peer_fec_k, ext.peer_fec_m), (0, 0));
        assert!(!ext.fec_tx_active());

        ext.handle_caps(caps(CapsFlags::FEC | CapsFlags::FEC_PARTIAL, 2, 3), base);
        assert!(!ext.peer_caps.contains(CapsFlags::FEC));
        assert!(
            !ext.peer_caps.contains(CapsFlags::FEC_PARTIAL),
            "an invalid profile must drop every FEC capability"
        );
        assert_eq!((ext.peer_fec_k, ext.peer_fec_m), (0, 0));

        ext.handle_caps(caps(CapsFlags::FEC, 2, 1), base);
        assert!(ext.peer_caps.contains(CapsFlags::FEC));
        assert!(ext.fec_tx_active());
    }

    #[test]
    fn unsupported_fec_warning_is_rate_limited() {
        let base = Instant::now();
        let mut ext = PeerExtension::new(ExtConfig {
            fec: FecMode::Fixed { k: 2, m: 1 },
            max_shard_len: 1900,
        });

        ext.handle_caps(caps(CapsFlags::FEC, 9, 1), base);
        assert_eq!(ext.caps_warn_last, Some(base));

        ext.handle_caps(caps(CapsFlags::FEC, 9, 1), base + Duration::from_secs(1));
        assert_eq!(
            ext.caps_warn_last,
            Some(base),
            "a repeated profile must not log again inside the interval"
        );

        ext.handle_caps(caps(CapsFlags::FEC, 9, 1), base + CAPS_WARN_INTERVAL);
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
            fec: FecMode::Fixed { k: 2, m: 1 },
            max_shard_len: 1900,
        };
        let mut ext = PeerExtension::new(config);
        ext.handle_caps(caps(CapsFlags::FEC, 2, 1), base);

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
        let mut ext = off_ext();
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
        let mut ext = off_ext();
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
            fec: FecMode::Fixed { k: 2, m: 1 },
            max_shard_len: 1900,
        };
        let mut ext = PeerExtension::new(config);
        let frames = ext.pending_control(base);
        for frame in &frames {
            ext.note_frame_sent(frame.kind(), base);
        }
        let peer = caps(CapsFlags::FEC, 2, 1);
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
            CapsFlags::FEC,
            "capabilities are a device property and must survive a rekey"
        );
        assert_eq!((ext.peer_fec_k, ext.peer_fec_m), (2, 1));
        assert!(
            ext.fec_tx_active(),
            "FEC TX must stay negotiated across the keypair switch"
        );
    }

    #[test]
    fn caps_changes_after_a_keypair_reset_are_still_applied() {
        let base = Instant::now();
        let config = ExtConfig {
            fec: FecMode::Fixed { k: 2, m: 1 },
            max_shard_len: 1900,
        };
        let mut ext = PeerExtension::new(config);
        ext.handle_caps(caps(CapsFlags::FEC, 2, 1), base);

        ext.reset_feedback();
        assert!(ext.fec_tx_active(), "the old profile is still valid");

        ext.handle_caps(caps(CapsFlags::FEC, 3, 1), base + Duration::from_millis(1));
        assert_eq!(
            (ext.peer_fec_k, ext.peer_fec_m),
            (3, 1),
            "a changed peer profile must be applied after a rekey"
        );
        assert!(
            !ext.fec_tx_active(),
            "a mismatched profile must disable FEC TX until the peer changes back"
        );

        ext.handle_caps(caps(CapsFlags::FEC, 2, 1), base + Duration::from_millis(2));
        assert!(ext.fec_tx_active());
    }

    #[test]
    fn full_size_shards_survive_a_profile_change() {
        let base = Instant::now();
        let config = ExtConfig {
            fec: FecMode::Fixed { k: 2, m: 1 },
            max_shard_len: 1385,
        };
        let mut ext = PeerExtension::new(config);
        ext.handle_caps(caps(CapsFlags::FEC, 2, 1), base);
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
            "the frame is a full-size FEC shard, not a tiny control frame"
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
            fec: FecMode::Fixed { k: 2, m: 1 },
            max_shard_len: 1385,
        };
        let mut ext = PeerExtension::new(config);
        ext.handle_caps(caps(CapsFlags::FEC, 2, 1), base);
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
        let mut ext = off_ext();
        for _ in 0..(CONTROL_QUEUE_CAPACITY + 2) {
            ext.push_control(ControlFrame::owned(ControlKind::FecShard, vec![0u8; 8]));
        }
        assert_eq!(ext.pending.len(), CONTROL_QUEUE_CAPACITY);
        assert_eq!(ext.fec_stats.dropped_control, 2);
    }

    #[test]
    fn control_queue_stays_bounded_across_flushes() {
        let base = Instant::now();
        let mut ext = off_ext();
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
            fec: FecMode::Fixed { k: 2, m: 1 },
            max_shard_len: 1900,
        });
        ext.handle_caps(caps(CapsFlags::FEC, 2, 1), base);

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
            fec: FecMode::Fixed { k: 2, m: 1 },
            max_shard_len: 1900,
        });
        ext.handle_caps(caps(CapsFlags::FEC, 2, 1), base);
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
        let mut ext = off_ext();
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
            fec: FecMode::Adaptive,
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
    fn default_config_is_adaptive_and_stays_quiet_when_clean() {
        let now = Instant::now();
        let mut ext = PeerExtension::default();
        assert_eq!(ext.config.fec, FecMode::Adaptive);
        assert!(ext
            .local_caps
            .contains(CapsFlags::FEC | CapsFlags::FEC_ADAPTIVE));

        ext.handle_caps(caps(CapsFlags::FEC | CapsFlags::FEC_ADAPTIVE, 2, 1), now);
        assert!(
            !ext.fec_tx_active(),
            "adaptive parity starts disabled until loss is measured"
        );
        assert!(!ext.fec_adaptive_active());
        assert!(ext.fec_push(&[0x45; 40], now).unwrap().is_none());
        assert!(ext
            .pending_control(now)
            .iter()
            .all(|frame| frame.kind() == ControlKind::Caps));
        let stats = ext.fec_stats().expect("adaptive FEC is configured");
        assert_eq!(stats.blocks_encoded, 0);
        assert_eq!(stats.shards_sent, 0);
    }

    #[test]
    fn adaptive_enables_two_to_one_on_two_percent_loss() {
        let base = Instant::now();
        let mut ext = adaptive_ext();
        let step = Duration::from_millis(1500);

        // Exactly 2 % of every window is lost.
        let next = feed_adaptive_windows(&mut ext, 0, 6, base, step, |counter| counter % 50 == 0);
        assert!(ext.fec_active, "2 % real loss must enable adaptive parity");
        assert!(ext.fec_adaptive_active());
        let profile = ext.config.fec.config().expect("adaptive profile");
        assert_eq!((profile.k(), profile.m()), (2, 1));

        // The same estimate switches back off after five clean seconds.
        let clean_at = base + step * 6;
        feed_adaptive_windows(&mut ext, next, 16, clean_at, step, |_| false);
        assert!(!ext.fec_active);
        assert!(!ext.fec_adaptive_active());
    }

    #[test]
    fn configure_is_idempotent() {
        let base = Instant::now();
        let config = ExtConfig {
            fec: FecMode::Fixed { k: 2, m: 1 },
            max_shard_len: 1900,
        };
        let mut ext = PeerExtension::new(config);
        ext.handle_caps(caps(CapsFlags::FEC, 2, 1), base);
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
            fec: FecMode::Fixed { k: 2, m: 1 },
            max_shard_len: 1900,
        };
        let mut ext = PeerExtension::new(config);
        ext.handle_caps(caps(CapsFlags::FEC, 2, 1), base);
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
            fec: FecMode::Fixed { k: 2, m: 1 },
            max_shard_len: 1900,
        };
        let mut ext = PeerExtension::new(config);
        ext.handle_caps(caps(CapsFlags::FEC, 2, 1), base);
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
        ext.handle_caps(caps(CapsFlags::FEC, 2, 1), base);

        assert_eq!(
            push_block(&mut ext, 0, shard_len, &shards, base),
            2,
            "after the reset block_id 0 must be accepted again"
        );
    }

    #[test]
    fn control_flush_is_serialized_between_workers() {
        let base = Instant::now();
        let mut ext = off_ext();
        for value in [1u8, 2] {
            let frame = ControlFrame::inline(ControlKind::FecShard, |output| {
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
}
