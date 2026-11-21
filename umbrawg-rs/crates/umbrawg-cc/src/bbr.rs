//! The BBRv3-style controller itself.

use core::time::Duration;
use std::time::Instant;

use crate::config::BbrConfig;
use crate::filters::{BwWindow, MinRtt};
use crate::pacing::{Pacer, MAX_RATE, NS_PER_SEC};
use crate::ring::{LossOutcome, SentPacket, SentRing, SlotState, RING_CAPACITY};
use crate::types::{Ack, BbrStats, Mode};

/// Denominator for fixed-point gains (`1.0 == 1000`).
const GAIN_UNIT: u64 = 1000;
/// Startup pacing gain, `2/ln(2)` rounded down.
const STARTUP_GAIN: u64 = 2770;
/// Drain pacing gain, the inverse of the startup gain.
const DRAIN_GAIN: u64 = GAIN_UNIT * GAIN_UNIT / STARTUP_GAIN;
/// Steady-state congestion-window gain.
const CWND_GAIN: u64 = 2000;
/// `PROBE_BW` pacing gain cycle.
const CYCLE_GAINS: [u64; 8] = [1250, 750, 1000, 1000, 1000, 1000, 1000, 1000];
/// Bandwidth growth that counts as "more capacity is available".
const FULL_BW_THRESHOLD: u64 = 1250;
/// Rounds without such growth before the pipe is declared full.
const FULL_BW_ROUNDS: u32 = 3;
/// Per-round loss ratio (percent) that triggers the loss response.
// Random loss must not shrink the window; match the kernel controller.
const LOSS_THRESHOLD_PCT: u64 = 20;
/// Upper bound for the loss compensation of rate samples (percent).
const LOSS_COMPENSATION_MAX_PCT: u64 = 25;
/// RTT window length.
const MIN_RTT_WINDOW_NS: u64 = 10 * NS_PER_SEC;
/// Time spent in `PROBE_RTT`.
const PROBE_RTT_DURATION_NS: u64 = 200_000_000;
/// Frequency of the stale-record sweep.
const SWEEP_INTERVAL_NS: u64 = 500_000_000;
/// Minimum age of a record before it can be swept.
const MAX_SWEEP_AGE_NS: u64 = 2 * NS_PER_SEC;
/// Floor for every reported delay.
const MAX_DELAY_NS: u64 = NS_PER_SEC;
/// Minimum accepted RTT sample.
const MIN_RTT_SAMPLE_NS: u64 = 1_000;
/// Bounded time in DRAIN for a tunnel whose application queue never empties.
const DRAIN_MAX_NS: u64 = 100_000_000;
/// Divisor of the `inflight_hi` additive growth step.
const HI_GROWTH_DIVISOR: u64 = 64;
/// Bound on rate samples relative to `cwnd / min_rtt`.
const RATE_SANITY_FACTOR: u64 = 4;
/// Largest peer-reported ACK delay accepted from the wire.
const MAX_ACK_DELAY_NS: u64 = NS_PER_SEC;
/// Time span of paced bytes the congestion window must always cover.
///
/// The peer acknowledges every 8..=16 datagrams or after 2..=5 ms, so on a
/// short RTT the modelled window (`2 * BDP`) can hold less than one ACK
/// interval of paced traffic. A sender restricted to that window goes idle
/// between ACKs, and its rate becomes a function of the peer's ACK timer plus
/// our own ACK wake-up latency (the idle poll ceiling) instead of the path.
/// The floor keeps one worst-case ACK interval in flight and removes that
/// dependency.
const CWND_FLOOR_NS: u64 = 5_000_000;
/// Upper bound for the floor, so a bogus pacing rate cannot lift it without
/// limit.
const CWND_FLOOR_MAX: u64 = 4 * 1024 * 1024;

fn dur_ns(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

/// Clamps a peer-reported ACK delay to a plausible value.
fn ack_delay_ns(duration: Duration) -> u64 {
    dur_ns(duration).min(MAX_ACK_DELAY_NS)
}

/// Subtracts a peer-reported ACK delay from an interval.
fn subtract_delay(interval_ns: u64, delay_ns: u64) -> u64 {
    if interval_ns == 0 {
        return 1;
    }
    let delay = delay_ns.min(interval_ns.saturating_sub(1));
    interval_ns - delay
}

/// RTT sample with the ACK delay removed.
///
/// The delay is capped at half of the raw sample: a peer that reports a delay
/// larger than the measured RTT must not be able to drive the RTT floor to
/// zero. The result is always at least one microsecond.
fn rtt_sample(raw_ns: u64, ack_delay_ns: u64) -> u64 {
    if raw_ns == 0 {
        return MIN_RTT_SAMPLE_NS;
    }
    let delay = ack_delay_ns.min(raw_ns / 2);
    raw_ns.saturating_sub(delay).max(MIN_RTT_SAMPLE_NS)
}

/// Scales a delivered-rate sample up by the long-term loss ratio.
///
/// A tunnel ACK stream only counts delivered bytes, so on a path that loses
/// a stable fraction of datagrams the raw delivery rate is low by exactly
/// that fraction. Dividing by `1 - loss_ratio` recovers the rate at which
/// the sender was actually able to transmit, which is what `BtlBw` models.
/// The correction is capped at 25 % of loss and disabled for anything above
/// it (such a path is better described by its delivered rate).
fn compensate_loss(rate: u64, delivered: u64, lost: u64) -> u64 {
    let total = delivered.saturating_add(lost);
    if total == 0 || lost == 0 {
        return rate;
    }
    let pct = lost.saturating_mul(100) / total;
    if pct == 0 || pct > LOSS_COMPENSATION_MAX_PCT {
        return rate;
    }
    let scaled = u128::from(rate) * 100 / u128::from(100 - pct);
    u64::try_from(scaled).unwrap_or(u64::MAX)
}

/// ACK-based BBRv3-style congestion controller.
///
/// All methods are non-blocking and free of panics: time arithmetic saturates,
/// capacities are bounded and every external value is validated. See the
/// crate documentation for the model and the deviations from Linux BBRv3.
#[derive(Debug, Clone)]
pub struct Bbr {
    config: BbrConfig,
    mss: u64,
    min_cwnd: u64,
    initial_rtt_ns: u64,
    initial_rate: u64,
    origin: Option<Instant>,

    mode: Mode,
    cwnd: u64,
    pacing_rate: u64,
    inflight: u64,
    delivered: u64,
    largest_acked: u64,
    max_sent: Option<u64>,

    pacer: Pacer,
    ring: SentRing,
    bw: BwWindow,
    btl_bw: u64,
    min_rtt: MinRtt,

    full_bw: u64,
    full_bw_cnt: u32,
    full_bw_reached: bool,

    round_count: u64,
    next_round_delivered: u64,
    round_delivered: u64,
    round_lost: u64,
    round_max_inflight: u64,
    round_congestion: bool,
    last_cut_round: u64,

    app_limited: bool,

    inflight_hi: u64,
    inflight_lo: u64,
    bw_hi: u64,

    cycle_idx: usize,
    cycle_start_ns: u64,
    drain_start_ns: u64,

    probe_rtt_start_ns: u64,
    probe_rtt_done_ns: u64,
    probe_rtt_round: u64,

    lost_bytes: u64,
    lost_packets: u64,
    spurious_losses: u64,
    orphaned_packets: u64,
    dropped_packets: u64,
    ecn_ce: u64,
    last_sweep_ns: u64,
}

impl Bbr {
    /// Creates a controller in `STARTUP` mode.
    pub fn new(config: BbrConfig) -> Self {
        let config = config.sanitized();
        let mss = u64::from(config.mss);
        let min_cwnd = mss.saturating_mul(u64::from(config.min_cwnd_packets));
        let initial_rtt_ns = dur_ns(config.initial_rtt).max(MIN_RTT_SAMPLE_NS);
        let initial_rate = (min_cwnd.saturating_mul(NS_PER_SEC) / initial_rtt_ns).max(1);
        Self {
            config,
            mss,
            min_cwnd,
            initial_rtt_ns,
            initial_rate,
            origin: None,
            mode: Mode::Startup,
            cwnd: min_cwnd,
            pacing_rate: initial_rate,
            inflight: 0,
            delivered: 0,
            largest_acked: 0,
            max_sent: None,
            pacer: Pacer::new(mss, initial_rate),
            ring: SentRing::new(),
            bw: BwWindow::new(),
            btl_bw: 0,
            min_rtt: MinRtt::new(),
            full_bw: 0,
            full_bw_cnt: 0,
            full_bw_reached: false,
            round_count: 0,
            next_round_delivered: 0,
            round_delivered: 0,
            round_lost: 0,
            round_max_inflight: 0,
            round_congestion: false,
            last_cut_round: u64::MAX,
            app_limited: false,
            inflight_hi: u64::MAX,
            inflight_lo: 0,
            bw_hi: 0,
            cycle_idx: 0,
            cycle_start_ns: 0,
            drain_start_ns: 0,
            probe_rtt_start_ns: 0,
            probe_rtt_done_ns: 0,
            probe_rtt_round: 0,
            lost_bytes: 0,
            lost_packets: 0,
            spurious_losses: 0,
            orphaned_packets: 0,
            dropped_packets: 0,
            ecn_ce: 0,
            last_sweep_ns: 0,
        }
    }

    /// Current pacing rate in bytes per second.
    pub fn pacing_rate(&self) -> u64 {
        self.pacing_rate
    }

    /// Current congestion window in bytes.
    pub fn cwnd(&self) -> u64 {
        self.cwnd
    }

    /// Bytes currently considered in flight.
    pub fn inflight(&self) -> u64 {
        self.inflight
    }

    /// Congestion window used to gate transmission.
    ///
    /// Returns [`Bbr::cwnd`] or the bytes paced in one worst-case ACK
    /// interval ([`CWND_FLOOR_NS`]), whichever is larger:
    ///
    /// ```text
    /// effective = max(cwnd, min(pacing_rate * 5 ms, 4 MiB))
    /// ```
    ///
    /// The modelled window is `2 * BDP`, which on a small RTT is smaller than
    /// the amount the pacer can emit between two ACKs. Gating on it directly
    /// would leave the sender idle for the rest of every ACK interval and tie
    /// throughput to the peer's ACK cadence. The floor is capped at 4 MiB so
    /// that a bogus rate sample cannot open the window without bound.
    ///
    /// [`Bbr::cwnd`] and [`BbrStats::cwnd`] keep reporting the modelled
    /// window, so statistics still describe the controller itself.
    pub fn effective_cwnd(&self) -> u64 {
        let floor =
            u128::from(self.pacing_rate) * u128::from(CWND_FLOOR_NS) / u128::from(NS_PER_SEC);
        let floor = u64::try_from(floor).unwrap_or(u64::MAX).min(CWND_FLOOR_MAX);
        self.cwnd.max(floor)
    }

    /// Current mode of the state machine.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Whether `STARTUP` already declared the path full.
    ///
    /// Until then the window is a growth artefact rather than a measurement of
    /// the path: it is derived from an estimate that is still doubling every
    /// round, and gating transmission on it throttles the very ACK stream that
    /// feeds the estimate. Callers that use the window as a send limit (rather
    /// than as a statistic) must wait for this flag.
    pub fn full_bw_reached(&self) -> bool {
        self.full_bw_reached
    }

    /// Whether the path has already signalled congestion.
    ///
    /// `inflight_hi` starts unbounded ([`u64::MAX`]) and is only lowered by a
    /// loss or ECN response, so `inflight_hi < cwnd` means the bound is
    /// measured and the window is currently probing above it. On a clean path
    /// the flag stays `false` and the window carries no information the pacer
    /// does not already have.
    pub fn loss_limited(&self) -> bool {
        self.inflight_hi < self.cwnd
    }

    /// Whether one more datagram of `len` bytes may be sent right now.
    ///
    /// Combines the congestion-window limit with the pacer allowance. The
    /// pacer allowance is refreshed by [`Bbr::on_send`], [`Bbr::on_ack`],
    /// [`Bbr::on_loss`] and [`Bbr::on_timer`].
    pub fn can_send(&self, len: usize) -> bool {
        let len = u64::try_from(len).unwrap_or(u64::MAX);
        let limit = self.cwnd.max(self.min_cwnd).max(self.mss);
        if self.inflight.saturating_add(len) > limit {
            return false;
        }
        if self.inflight == 0 {
            return true;
        }
        self.pacer.can_send(len)
    }

    /// Delay until `len` bytes fit into the pacing budget at the current
    /// rate. Returns [`Duration::ZERO`] when the datagram may be sent now.
    ///
    /// The pacer does not wake the caller: when the congestion window is the
    /// limiting factor the caller has to wait for an ACK.
    pub fn next_send_delay(&self, len: usize, now: Instant) -> Duration {
        let Some(now_ns) = self.stamp_at(now) else {
            return Duration::ZERO;
        };
        let len = u64::try_from(len).unwrap_or(u64::MAX);
        Duration::from_nanos(self.pacer.delay_ns(len, now_ns).min(MAX_DELAY_NS))
    }

    /// Snapshot of the controller state.
    pub fn stats(&self) -> BbrStats {
        BbrStats {
            mode: self.mode,
            pacing_rate: self.pacing_rate,
            cwnd: self.cwnd,
            inflight: self.inflight,
            btl_bw: self.btl_bw,
            min_rtt: Duration::from_nanos(self.min_rtt.min().unwrap_or(self.initial_rtt_ns)),
            latest_rtt: Duration::from_nanos(self.min_rtt.latest().unwrap_or(self.initial_rtt_ns)),
            delivered: self.delivered,
            lost_bytes: self.lost_bytes,
            lost_packets: self.lost_packets,
            spurious_losses: self.spurious_losses,
            orphaned_packets: self.orphaned_packets,
            dropped_packets: self.dropped_packets,
            rounds: self.round_count,
            app_limited: self.app_limited,
            inflight_hi: self.inflight_hi,
            inflight_lo: self.inflight_lo,
            pacing_gain: u32::try_from(self.pacing_gain()).unwrap_or(u32::MAX),
            cwnd_gain: u32::try_from(CWND_GAIN).unwrap_or(u32::MAX),
            full_bw_reached: self.full_bw_reached,
            probe_bw_phase: u8::try_from(self.cycle_idx).unwrap_or(u8::MAX),
            ecn_ce: self.ecn_ce,
        }
    }

    /// Registers a transmitted wire counter without in-flight accounting.
    ///
    /// Control and FEC frames also consume counters, and the peer reports
    /// them in `largest_counter`. Tracking them keeps a valid ACK from being
    /// rejected as referring to an unsent datagram.
    pub fn note_sent_counter(&mut self, counter: u64) {
        self.max_sent = Some(self.max_sent.map_or(counter, |max| max.max(counter)));
    }

    /// Registers a datagram that has just been transmitted.
    ///
    /// `counter` is the wire counter of the datagram, `len` its payload size
    /// in bytes. The tracking ring keeps the last 8192 datagrams; older
    /// records are released from the in-flight accounting.
    pub fn on_send(&mut self, counter: u64, len: usize, now: Instant) {
        let now_ns = self.stamp(now);
        self.pacer.refill(now_ns);

        self.note_sent_counter(counter);

        let len = u64::try_from(len).unwrap_or(u64::MAX);
        let record_len = u32::try_from(len).unwrap_or(u32::MAX);
        let packet = SentPacket {
            counter,
            len: record_len,
            sent_at_ns: now_ns,
            delivered_at_send: self.delivered,
            state: SlotState::InFlight,
        };

        if let Some(evicted) = self.ring.insert(packet) {
            self.inflight = self.inflight.saturating_sub(u64::from(evicted.len));
            self.orphaned_packets = self.orphaned_packets.saturating_add(1);
        }
        self.inflight = self.inflight.saturating_add(len);
        self.round_max_inflight = self.round_max_inflight.max(self.inflight);
        self.pacer.consume(len);
    }

    /// Processes a cumulative acknowledgement.
    ///
    /// An ACK that names a counter we never sent cannot describe our stream:
    /// it is dropped before it can touch the in-flight accounting or the
    /// bounds. The reported ACK delay is clamped to one second.
    pub fn on_ack(&mut self, ack: &Ack, now: Instant) {
        let Some(max_sent) = self.max_sent else {
            return;
        };
        if ack.largest_counter > max_sent {
            return;
        }
        let now_ns = self.stamp(now);
        self.pacer.refill(now_ns);

        self.largest_acked = self.largest_acked.max(ack.largest_counter);
        let prior_delivered = self.delivered;
        let newest = self.acknowledge(ack);
        let newly_acked = self.delivered.saturating_sub(prior_delivered);

        let (unreachable_bytes, unreachable_packets) =
            self.ring.release_unreachable(ack.largest_counter, 63);
        if unreachable_packets > 0 {
            self.inflight = self.inflight.saturating_sub(unreachable_bytes);
            // The records left the ACK window unacknowledged: that is the
            // watermark loss signal. They are counted as losses, not as
            // orphans, so one datagram never appears in both counters.
            self.note_loss_batch(unreachable_bytes, unreachable_packets, now_ns);
        }

        let ack_delay_ns = ack_delay_ns(ack.ack_delay);

        if let Some(packet) = newest {
            let rtt = rtt_sample(now_ns.saturating_sub(packet.sent_at_ns), ack_delay_ns);
            self.min_rtt.sample(rtt, now_ns);
        }

        if ack.ecn_ce && self.config.enable_ecn && newly_acked > 0 {
            self.ecn_ce = self.ecn_ce.saturating_add(1);
            self.round_congestion = true;
            self.handle_ecn_cut(now_ns);
        }

        let rate_sample = newest.and_then(|packet| {
            if newly_acked == 0 {
                return None;
            }
            self.rate_sample(&packet, now_ns, ack_delay_ns)
        });

        let starts_round = newly_acked > 0
            && newest.is_some_and(|packet| packet.delivered_at_send >= self.next_round_delivered);
        if starts_round {
            self.start_round(now_ns);
            self.next_round_delivered = self.delivered;
        }

        if let Some(rate) = rate_sample {
            self.bw.add(rate);
            self.btl_bw = self.bw.max().min(MAX_RATE);
        }

        self.update_mode(now_ns);
        self.maybe_enter_probe_rtt(now_ns);
        self.probe_rtt_step(now_ns);
        self.update_cwnd(newly_acked);
        self.update_pacing(now_ns);
    }

    /// Reports a datagram that was really lost (not recovered by FEC).
    ///
    /// Reports for counters that were already acknowledged or already
    /// declared lost are counted as spurious and ignored.
    pub fn on_loss(&mut self, counter: u64, now: Instant) {
        let now_ns = self.stamp(now);
        self.pacer.refill(now_ns);

        match self.ring.mark_lost(counter) {
            LossOutcome::InFlight(packet) => {
                let len = u64::from(packet.len);
                self.inflight = self.inflight.saturating_sub(len);
                self.note_loss(len, now_ns);
            }
            // The watermark or a previous bitmap already counted this loss.
            LossOutcome::AlreadyCounted | LossOutcome::Dropped => {}
            LossOutcome::Unknown => {
                let unreachable =
                    counter < self.largest_acked && self.largest_acked.saturating_sub(counter) > 63;
                if unreachable {
                    let len = self.mss;
                    self.note_loss(len, now_ns);
                } else {
                    self.spurious_losses = self.spurious_losses.saturating_add(1);
                }
            }
        }

        self.update_cwnd(0);
        self.update_pacing(now_ns);
    }

    /// Returns a locally dropped datagram to the congestion window.
    ///
    /// The datagram was registered with [`Bbr::on_send`] but never reached the
    /// wire (for example the underlay refused it). Its bytes leave the
    /// in-flight accounting, but the drop is not treated as delivery and not
    /// treated as a congestion signal: a local error says nothing about the
    /// path. Reports for counters that are unknown, acknowledged, lost or
    /// already dropped are ignored.
    pub fn on_drop(&mut self, counter: u64, now: Instant) {
        if self.max_sent.is_none_or(|max| counter > max) {
            return;
        }
        let now_ns = self.stamp(now);
        self.pacer.refill(now_ns);
        if let Some(packet) = self.ring.mark_dropped(counter) {
            self.inflight = self.inflight.saturating_sub(u64::from(packet.len));
            self.dropped_packets = self.dropped_packets.saturating_add(1);
        }
    }

    /// Releases the newest in-flight datagrams covering `bytes`.
    ///
    /// Used on a batch send error, where the wire counter of every failed
    /// datagram is not available at the drop site but the datagrams were the
    /// ones encrypted last. The walk starts at [`SentRing`] capacity and stops
    /// once the byte budget is covered, so the cost is bounded. The drops are
    /// not counted as path losses.
    pub fn on_drop_bytes(&mut self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let Some(max_sent) = self.max_sent else {
            return;
        };
        let mut budget = u64::try_from(bytes).unwrap_or(u64::MAX);
        let mut counter = max_sent;
        let mut released = 0u64;
        for _ in 0..RING_CAPACITY {
            if budget == 0 {
                break;
            }
            if let Some(packet) = self.ring.mark_dropped(counter) {
                let len = u64::from(packet.len);
                self.inflight = self.inflight.saturating_sub(len);
                budget = budget.saturating_sub(len);
                released = released.saturating_add(1);
            }
            let Some(previous) = counter.checked_sub(1) else {
                break;
            };
            counter = previous;
        }
        self.dropped_packets = self.dropped_packets.saturating_add(released);
    }

    /// Drives time-based work: pacing refill, `PROBE_BW` phase watchdog,
    /// `PROBE_RTT` entry and exit, and the stale-record sweep.
    pub fn on_timer(&mut self, now: Instant) {
        let now_ns = self.stamp(now);
        self.pacer.refill(now_ns);

        if self.mode == Mode::ProbeBw {
            let phase = self.phase_duration_ns();
            if now_ns.saturating_sub(self.cycle_start_ns) >= phase.saturating_mul(2) {
                self.cycle_idx = (self.cycle_idx + 1) % CYCLE_GAINS.len();
                self.cycle_start_ns = now_ns;
                self.update_pacing(now_ns);
            }
        }

        self.probe_rtt_step(now_ns);
        self.maybe_enter_probe_rtt(now_ns);
        self.update_mode(now_ns);

        if now_ns.saturating_sub(self.last_sweep_ns) >= SWEEP_INTERVAL_NS {
            self.last_sweep_ns = now_ns;
            let age = MAX_SWEEP_AGE_NS.max(self.phase_duration_ns().saturating_mul(20));
            let (bytes, packets) = self.ring.sweep(now_ns, age);
            if packets > 0 {
                self.inflight = self.inflight.saturating_sub(bytes);
                // A record that outlived the sweep age was never acknowledged:
                // it is a loss, not an orphan. Keeping the two counters
                // disjoint makes the statistics summable.
                self.note_loss_batch(bytes, packets, now_ns);
            }
        }

        self.update_cwnd(0);
        self.update_pacing(now_ns);
    }

    fn note_loss(&mut self, len: u64, now_ns: u64) {
        self.note_loss_batch(len, 1, now_ns);
    }

    /// Accounts a batch of losses and applies the per-round cut once.
    fn note_loss_batch(&mut self, bytes: u64, packets: u64, now_ns: u64) {
        if packets == 0 {
            return;
        }
        self.lost_bytes = self.lost_bytes.saturating_add(bytes);
        self.lost_packets = self.lost_packets.saturating_add(packets);
        self.round_lost = self.round_lost.saturating_add(bytes);
        self.round_congestion = true;

        let total = self.round_delivered.saturating_add(self.round_lost);
        if total > 0
            && self.round_lost.saturating_mul(100) >= total.saturating_mul(LOSS_THRESHOLD_PCT)
            && self.last_cut_round != self.round_count
        {
            self.apply_loss_cut(now_ns);
        }
    }

    fn acknowledge(&mut self, ack: &Ack) -> Option<SentPacket> {
        let mut bytes = 0u64;
        let mut newest: Option<SentPacket> = None;
        let mut bits = ack.bitmap;
        while bits != 0 {
            let bit = bits.trailing_zeros();
            bits &= bits - 1;
            let Some(counter) = ack.largest_counter.checked_sub(u64::from(bit)) else {
                continue;
            };
            let Some(packet) = self.ring.mark_acked(counter) else {
                continue;
            };
            bytes = bytes.saturating_add(u64::from(packet.len));
            newest = Some(newest.map_or(packet, |best: SentPacket| {
                if packet.sent_at_ns >= best.sent_at_ns {
                    packet
                } else {
                    best
                }
            }));
        }
        if bytes > 0 {
            self.delivered = self.delivered.saturating_add(bytes);
            self.inflight = self.inflight.saturating_sub(bytes);
            self.round_delivered = self.round_delivered.saturating_add(bytes);
        }
        newest
    }

    fn rate_sample(&self, packet: &SentPacket, now_ns: u64, delay_ns: u64) -> Option<u64> {
        let delivered = self.delivered.saturating_sub(packet.delivered_at_send);
        if delivered == 0 {
            return None;
        }
        let interval = subtract_delay(now_ns.saturating_sub(packet.sent_at_ns), delay_ns);
        let numerator = u128::from(delivered) * u128::from(NS_PER_SEC);
        let raw = numerator / u128::from(interval.max(1));
        let raw = u64::try_from(raw).unwrap_or(u64::MAX);
        let compensated = compensate_loss(raw, self.delivered, self.lost_bytes);
        Some(self.sanity_rate(compensated))
    }

    /// Caps a rate sample at a few times `cwnd / min_rtt` so that a single
    /// bogus ACK cannot poison the bandwidth estimate.
    fn sanity_rate(&self, rate: u64) -> u64 {
        let rtt = self
            .min_rtt
            .min()
            .unwrap_or(self.initial_rtt_ns)
            .max(MIN_RTT_SAMPLE_NS);
        let cwnd = self.cwnd.max(self.min_cwnd);
        let bound = u128::from(cwnd) * u128::from(RATE_SANITY_FACTOR) * u128::from(NS_PER_SEC)
            / u128::from(rtt);
        let bound = u64::try_from(bound).unwrap_or(u64::MAX);
        rate.min(bound.max(1)).min(MAX_RATE)
    }

    fn start_round(&mut self, now_ns: u64) {
        let app_limited = self.round_max_inflight.saturating_mul(2) < self.cwnd;

        self.adapt_bounds();
        if self.mode == Mode::Startup && self.btl_bw > 0 && !app_limited {
            self.check_full_bw();
        }
        if self.mode == Mode::ProbeBw {
            self.advance_cycle(now_ns);
        }

        self.round_count = self.round_count.saturating_add(1);
        self.round_delivered = 0;
        self.round_lost = 0;
        self.round_max_inflight = self.inflight;
        self.round_congestion = false;
        self.app_limited = app_limited;
        let rotate = !app_limited || self.round_count <= 1;
        self.bw.on_round_start(rotate);
    }

    fn check_full_bw(&mut self) {
        let bw = self.btl_bw;
        if bw.saturating_mul(GAIN_UNIT) >= self.full_bw.saturating_mul(FULL_BW_THRESHOLD) {
            self.full_bw = bw;
            self.full_bw_cnt = 0;
        } else {
            self.full_bw_cnt = self.full_bw_cnt.saturating_add(1);
            if self.full_bw_cnt >= FULL_BW_ROUNDS {
                self.full_bw_reached = true;
                self.enter_drain();
            }
        }
    }

    fn enter_drain(&mut self) {
        if self.mode == Mode::Drain {
            return;
        }
        let floor = self.bdp().max(self.min_cwnd);
        self.inflight_hi = self.inflight.max(self.cwnd).max(floor);
        self.inflight_lo = self.inflight_lo.min(self.inflight_hi);
        self.bw_hi = self.btl_bw;
        self.mode = Mode::Drain;
        self.drain_start_ns = 0;
    }

    fn update_mode(&mut self, now_ns: u64) {
        match self.mode {
            Mode::Startup => {
                if self.full_bw_reached {
                    // A tunnel carries an external application queue; draining it
                    // inside the controller leaves the sender stuck. Move to the
                    // steady-state gain cycle at 1.0 instead.
                    self.mode = Mode::ProbeBw;
                    self.cycle_idx = 2;
                    self.cycle_start_ns = now_ns;
                }
            }
            Mode::Drain => {
                if self.drain_start_ns == 0 {
                    self.drain_start_ns = now_ns;
                }
                let target = self.bdp().max(self.min_cwnd);
                let drained = self.inflight <= target
                    || now_ns.saturating_sub(self.drain_start_ns) >= DRAIN_MAX_NS;
                if drained {
                    self.drain_start_ns = 0;
                    self.mode = Mode::ProbeBw;
                    self.cycle_idx = 0;
                    self.cycle_start_ns = now_ns;
                }
            }
            Mode::ProbeBw | Mode::ProbeRtt => {}
        }
    }

    fn advance_cycle(&mut self, now_ns: u64) {
        if now_ns.saturating_sub(self.cycle_start_ns) < self.phase_duration_ns() {
            return;
        }
        let was_probe_up = self.cycle_idx == 0;
        let ended_round_clean = !self.round_congestion && self.last_cut_round != self.round_count;
        self.cycle_idx = (self.cycle_idx + 1) % CYCLE_GAINS.len();
        self.cycle_start_ns = now_ns;

        if was_probe_up && ended_round_clean {
            let observed = self.round_max_inflight.max(self.cwnd);
            self.inflight_hi = self.inflight_hi.max(observed).max(self.min_cwnd);
            self.bw_hi = self.btl_bw;
        }
    }

    fn adapt_bounds(&mut self) {
        if self.mode == Mode::ProbeRtt {
            return;
        }
        let bdp = self.bdp();
        let floor = bdp.max(self.min_cwnd);
        let total = self.round_delivered.saturating_add(self.round_lost);
        let lossy = total > 0
            && self.round_lost.saturating_mul(100) >= total.saturating_mul(LOSS_THRESHOLD_PCT);
        let congestion = lossy || self.round_congestion;

        if congestion {
            if self.round_max_inflight > 0 && self.last_cut_round != self.round_count {
                self.cut_upper_bounds();
            }
        } else {
            if self.btl_bw.saturating_mul(100) > self.bw_hi.saturating_mul(105).max(1) {
                self.inflight_hi = self
                    .inflight_hi
                    .max(bdp.saturating_mul(2).max(self.min_cwnd));
                self.bw_hi = self.btl_bw;
            }
            if self.round_max_inflight.saturating_mul(100) >= self.inflight_hi.saturating_mul(95) {
                let step = (self.inflight_hi / HI_GROWTH_DIVISOR).max(self.mss);
                self.inflight_hi = self.inflight_hi.saturating_add(step);
            }
            self.inflight_hi = self.inflight_hi.max(floor);
            let lo_target = bdp.saturating_mul(3) / 4;
            self.inflight_lo = self
                .inflight_lo
                .max(lo_target)
                .min(self.inflight_hi)
                .max(self.min_cwnd);
        }

        self.inflight_hi = self.inflight_hi.max(self.min_cwnd);
        self.inflight_lo = self
            .inflight_lo
            .min(self.inflight_hi)
            .max(self.min_cwnd.min(self.inflight_hi));
    }

    fn cut_upper_bounds(&mut self) {
        let total = self.round_delivered.saturating_add(self.round_lost).max(1);
        let pct = (self.round_lost.saturating_mul(100) / total).clamp(LOSS_THRESHOLD_PCT, 50);
        let beta = 1000u64.saturating_sub(pct.saturating_mul(10));
        let floor = self.bdp().max(self.min_cwnd);
        let base = self.round_max_inflight.max(self.inflight);
        let cut = base.saturating_mul(beta) / 1000;
        self.inflight_hi = self.inflight_hi.min(cut.max(floor)).max(self.min_cwnd);
        self.inflight_lo = self
            .inflight_lo
            .min(self.inflight_hi)
            .min(cut)
            .max(self.min_cwnd);
        self.last_cut_round = self.round_count;
    }

    fn apply_loss_cut(&mut self, now_ns: u64) {
        self.cut_upper_bounds();
        if self.mode == Mode::Startup && self.btl_bw > 0 {
            self.full_bw_reached = true;
            self.enter_drain();
            self.bw_hi = self.btl_bw;
        }
        if self.mode == Mode::ProbeBw && CYCLE_GAINS[self.cycle_idx] > GAIN_UNIT {
            self.cycle_idx = 1;
            self.cycle_start_ns = now_ns;
        }
    }

    fn handle_ecn_cut(&mut self, now_ns: u64) {
        if !self.config.enable_ecn
            || self.mode == Mode::ProbeRtt
            || self.last_cut_round == self.round_count
        {
            return;
        }
        let floor = self.bdp().max(self.min_cwnd);
        let base = self.round_max_inflight.max(self.inflight);
        let cut = base.saturating_mul(980) / 1000;
        self.inflight_hi = self.inflight_hi.min(cut.max(floor)).max(self.min_cwnd);
        self.inflight_lo = self.inflight_lo.min(self.inflight_hi).max(self.min_cwnd);
        self.last_cut_round = self.round_count;
        if self.mode == Mode::ProbeBw && CYCLE_GAINS[self.cycle_idx] > GAIN_UNIT {
            self.cycle_idx = 1;
            self.cycle_start_ns = now_ns;
        }
    }

    fn maybe_enter_probe_rtt(&mut self, now_ns: u64) {
        if self.mode == Mode::ProbeRtt || self.min_rtt.min().is_none() {
            return;
        }
        if self.min_rtt.age(now_ns) < MIN_RTT_WINDOW_NS {
            return;
        }
        self.mode = Mode::ProbeRtt;
        self.probe_rtt_start_ns = now_ns;
        self.probe_rtt_done_ns = now_ns.saturating_add(PROBE_RTT_DURATION_NS);
        self.probe_rtt_round = self.round_count;
    }

    fn probe_rtt_step(&mut self, now_ns: u64) {
        if self.mode != Mode::ProbeRtt {
            return;
        }
        let elapsed = now_ns.saturating_sub(self.probe_rtt_start_ns);
        let min_rtt = self.min_rtt.min().unwrap_or(self.initial_rtt_ns);
        let drained = self.inflight <= self.min_cwnd
            || elapsed
                >= PROBE_RTT_DURATION_NS
                    .saturating_add(min_rtt)
                    .saturating_add(self.phase_duration_ns());
        if elapsed < PROBE_RTT_DURATION_NS
            || now_ns < self.probe_rtt_done_ns
            || !drained
            || self.round_count <= self.probe_rtt_round
        {
            return;
        }
        self.min_rtt.refresh(now_ns);
        self.mode = if self.full_bw_reached {
            Mode::ProbeBw
        } else {
            Mode::Startup
        };
        self.cycle_idx = 1;
        self.cycle_start_ns = now_ns;
        self.bw_hi = self.btl_bw;
        self.update_cwnd(0);
        self.update_pacing(now_ns);
    }

    fn update_cwnd(&mut self, acked_bytes: u64) {
        let bdp = self.bdp();
        let target = bdp.saturating_mul(CWND_GAIN) / GAIN_UNIT;
        let hi = self.inflight_hi.max(self.min_cwnd);
        let lo = self.inflight_lo.min(hi).max(self.min_cwnd);
        let cwnd = match self.mode {
            Mode::ProbeRtt => self.min_cwnd,
            Mode::Startup => {
                let grown = self.cwnd.saturating_add(acked_bytes);
                let cap = bdp.saturating_mul(4).max(self.min_cwnd);
                grown.max(target).min(cap).min(hi)
            }
            Mode::Drain => target.max(lo).min(hi),
            Mode::ProbeBw => {
                let cap = if CYCLE_GAINS[self.cycle_idx] > GAIN_UNIT {
                    hi.saturating_add(hi / 4)
                } else {
                    hi
                };
                target.max(lo).min(cap)
            }
        };
        self.cwnd = cwnd.max(self.min_cwnd);
    }

    fn update_pacing(&mut self, now_ns: u64) {
        let gain = self.pacing_gain();
        let rate = if self.btl_bw == 0 {
            self.initial_rate
        } else {
            self.btl_bw.saturating_mul(gain) / GAIN_UNIT
        }
        .max(1);
        self.pacing_rate = rate;
        self.pacer.set_rate(rate);
        self.pacer.refill(now_ns);
    }

    fn pacing_gain(&self) -> u64 {
        match self.mode {
            Mode::Startup => STARTUP_GAIN,
            Mode::Drain => DRAIN_GAIN,
            Mode::ProbeBw => CYCLE_GAINS[self.cycle_idx % CYCLE_GAINS.len()],
            Mode::ProbeRtt => GAIN_UNIT,
        }
    }

    fn bdp(&self) -> u64 {
        let rtt = self.min_rtt.min().unwrap_or(self.initial_rtt_ns);
        let bytes = u128::from(self.btl_bw) * u128::from(rtt) / u128::from(NS_PER_SEC);
        u64::try_from(bytes).unwrap_or(u64::MAX)
    }

    fn phase_duration_ns(&self) -> u64 {
        self.min_rtt.min().unwrap_or(self.initial_rtt_ns)
    }

    fn stamp(&mut self, now: Instant) -> u64 {
        let origin = *self.origin.get_or_insert(now);
        now.saturating_duration_since(origin)
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64
    }

    fn stamp_at(&self, now: Instant) -> Option<u64> {
        self.origin.map(|origin| {
            now.saturating_duration_since(origin)
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtt_sample_subtracts_delay_with_floor() {
        assert_eq!(rtt_sample(20_000_000, 0), 20_000_000);
        assert_eq!(rtt_sample(20_000_000, 5_000_000), 15_000_000);
        assert_eq!(rtt_sample(20_000_000, 40_000_000), 10_000_000);
        assert_eq!(rtt_sample(10, 10), MIN_RTT_SAMPLE_NS);
        assert_eq!(rtt_sample(0, 0), MIN_RTT_SAMPLE_NS);
    }

    #[test]
    fn interval_delay_subtraction_is_bounded() {
        assert_eq!(subtract_delay(1000, 0), 1000);
        assert_eq!(subtract_delay(1000, 400), 600);
        assert_eq!(subtract_delay(1000, 5000), 1);
        assert_eq!(subtract_delay(0, 5000), 1);
    }

    #[test]
    fn loss_compensation_is_bounded() {
        assert_eq!(compensate_loss(1000, 1000, 0), 1000);
        assert_eq!(compensate_loss(1000, 980, 20), 1020);
        assert_eq!(compensate_loss(1000, 100, 100), 1000);
        assert_eq!(compensate_loss(1000, 0, 100), 1000);
    }

    #[test]
    fn ack_delay_is_clamped_to_one_second() {
        assert_eq!(ack_delay_ns(Duration::ZERO), 0);
        assert_eq!(ack_delay_ns(Duration::from_millis(5)), 5_000_000);
        assert_eq!(ack_delay_ns(Duration::from_secs(1)), MAX_ACK_DELAY_NS);
        assert_eq!(ack_delay_ns(Duration::from_secs(60)), MAX_ACK_DELAY_NS);
        assert_eq!(
            ack_delay_ns(Duration::from_secs(u64::MAX)),
            MAX_ACK_DELAY_NS
        );
    }

    #[test]
    fn ack_beyond_largest_sent_counter_keeps_inflight() {
        let base = Instant::now();
        let mut bbr = Bbr::new(BbrConfig::default());
        for counter in 0..4u64 {
            bbr.on_send(counter, 1400, base);
        }
        assert_eq!(bbr.inflight(), 4 * 1400);

        let min_rtt_before = bbr.stats().min_rtt;
        let bogus = Ack::new(u64::MAX, u64::MAX, Duration::from_secs(60), true);
        bbr.on_ack(&bogus, base + Duration::from_millis(10));

        let stats = bbr.stats();
        assert_eq!(bbr.inflight(), 4 * 1400);
        assert_eq!(stats.delivered, 0);
        assert_eq!(stats.lost_packets, 0);
        assert_eq!(stats.rounds, 0);
        assert_eq!(stats.ecn_ce, 0);
        assert_eq!(stats.min_rtt, min_rtt_before);

        bbr.on_ack(
            &Ack::new(3, u64::MAX, Duration::ZERO, false),
            base + Duration::from_millis(20),
        );
        assert_eq!(bbr.inflight(), 0);
        assert_eq!(bbr.stats().delivered, 4 * 1400);
    }

    #[test]
    fn ack_naming_a_control_counter_is_accepted() {
        let base = Instant::now();
        let mut bbr = Bbr::new(BbrConfig::default());
        bbr.on_send(0, 1400, base);
        bbr.note_sent_counter(5);

        bbr.on_ack(
            &Ack::new(5, 1 << 5, Duration::ZERO, false),
            base + Duration::from_millis(20),
        );

        assert_eq!(bbr.inflight(), 0);
        assert_eq!(bbr.stats().delivered, 1400);
    }

    #[test]
    fn loss_limited_is_false_until_the_path_signals_congestion() {
        let base = Instant::now();
        let mut bbr = Bbr::new(BbrConfig::default());
        assert!(!bbr.loss_limited(), "inflight_hi starts unbounded");

        // A clean, acknowledged round sets a bandwidth estimate and a window
        // but never touches the loss bound.
        for counter in 0..8u64 {
            bbr.on_send(counter, 1400, base);
        }
        bbr.on_ack(
            &Ack::new(7, u64::MAX, Duration::ZERO, false),
            base + Duration::from_millis(1),
        );
        assert_eq!(bbr.inflight_hi, u64::MAX);
        assert!(!bbr.loss_limited());
    }

    #[test]
    fn loss_limited_follows_the_cut_upper_bound() {
        let mut bbr = Bbr::new(BbrConfig::default());
        let cwnd = bbr.cwnd();

        bbr.inflight_hi = cwnd - 1;
        assert!(bbr.loss_limited(), "a bound below the window limits it");
        bbr.inflight_hi = cwnd;
        assert!(!bbr.loss_limited());
        bbr.inflight_hi = cwnd + 1;
        assert!(!bbr.loss_limited());
        bbr.inflight_hi = u64::MAX;
        assert!(!bbr.loss_limited());
    }

    #[test]
    fn loss_cut_lowers_the_bound_and_keeps_the_window_clamped() {
        let base = Instant::now();
        let mut bbr = Bbr::new(BbrConfig::default());
        for counter in 0..8u64 {
            bbr.on_send(counter, 1400, base);
        }
        bbr.on_ack(
            &Ack::new(7, u64::MAX, Duration::ZERO, false),
            base + Duration::from_millis(1),
        );
        assert_eq!(bbr.inflight_hi, u64::MAX);

        // A whole round lost in STARTUP is a congestion signal.
        for counter in 8..16u64 {
            bbr.on_send(counter, 1400, base + Duration::from_millis(2));
        }
        for counter in 8..16u64 {
            bbr.on_loss(counter, base + Duration::from_millis(3));
        }

        assert!(bbr.inflight_hi < u64::MAX, "the cut must bound the pipe");
        assert!(bbr.full_bw_reached(), "loss ends STARTUP");
        // Every window update clamps `cwnd` to the bound, so the flag only
        // becomes true again once PROBE_UP is allowed to exceed it.
        assert_eq!(bbr.loss_limited(), bbr.inflight_hi < bbr.cwnd);
        assert!(!bbr.loss_limited());
    }

    #[test]
    fn full_bw_reached_exposes_the_startup_exit() {
        let base = Instant::now();
        let mut bbr = Bbr::new(BbrConfig::default());
        assert!(!bbr.full_bw_reached());
        assert!(!bbr.stats().full_bw_reached);

        // One acknowledged round provides a bandwidth estimate.
        for counter in 0..8u64 {
            bbr.on_send(counter, 1400, base);
        }
        bbr.on_ack(
            &Ack::new(7, u64::MAX, Duration::ZERO, false),
            base + Duration::from_millis(1),
        );
        assert!(!bbr.full_bw_reached(), "STARTUP is still probing");

        // A burst of losses in STARTUP ends the probing phase.
        for counter in 8..16u64 {
            bbr.on_send(counter, 1400, base + Duration::from_millis(2));
        }
        for counter in 8..16u64 {
            bbr.on_loss(counter, base + Duration::from_millis(3));
        }
        assert!(bbr.full_bw_reached());
        assert!(bbr.stats().full_bw_reached);
    }

    #[test]
    fn effective_cwnd_keeps_a_window_above_the_floor() {
        let bbr = Bbr::new(BbrConfig::default());
        // 4 * 1400 bytes over a 50 ms initial RTT: the floor is 560 bytes,
        // far below the modelled window.
        assert_eq!(bbr.pacing_rate(), 112_000);
        assert!(bbr.cwnd() > bbr.pacing_rate() * CWND_FLOOR_NS / NS_PER_SEC);
        assert_eq!(bbr.effective_cwnd(), bbr.cwnd());
    }

    #[test]
    fn effective_cwnd_covers_one_ack_interval_on_a_short_rtt() {
        let bbr = Bbr::new(BbrConfig {
            initial_rtt: Duration::from_millis(1),
            ..BbrConfig::default()
        });
        // 5600 bytes per millisecond: one 5 ms ACK interval is 28 000 bytes.
        assert_eq!(bbr.cwnd(), 5600);
        assert_eq!(bbr.pacing_rate(), 5_600_000);
        assert_eq!(bbr.effective_cwnd(), 28_000);
        assert!(bbr.effective_cwnd() > bbr.cwnd());
    }

    #[test]
    fn effective_cwnd_floor_is_capped() {
        let bbr = Bbr::new(BbrConfig {
            initial_rtt: Duration::from_micros(1),
            ..BbrConfig::default()
        });
        assert!(bbr.pacing_rate() * CWND_FLOOR_NS / NS_PER_SEC > CWND_FLOOR_MAX);
        assert_eq!(bbr.effective_cwnd(), CWND_FLOOR_MAX);
    }

    #[test]
    fn effective_cwnd_follows_the_pacing_rate_after_an_ack() {
        let base = Instant::now();
        let mut bbr = Bbr::new(BbrConfig {
            initial_rtt: Duration::from_millis(1),
            ..BbrConfig::default()
        });
        for counter in 0..8u64 {
            bbr.on_send(counter, 1400, base);
        }
        bbr.on_ack(
            &Ack::new(7, u64::MAX, Duration::ZERO, false),
            base + Duration::from_millis(1),
        );
        let stats = bbr.stats();
        let floor = stats.pacing_rate * CWND_FLOOR_NS / NS_PER_SEC;
        assert!(floor > stats.cwnd);
        assert_eq!(bbr.effective_cwnd(), floor);
        assert_eq!(stats.cwnd, bbr.cwnd());
    }

    #[test]
    fn watermark_release_counts_losses_beyond_the_ack_window() {
        let base = Instant::now();
        let mut bbr = Bbr::new(BbrConfig::default());
        for counter in 0..80u64 {
            bbr.on_send(counter, 1400, base);
        }
        // Only the newest counter is acknowledged: counters 0..=15 left the
        // 64-bit bitmap window unacknowledged and are the watermark loss.
        bbr.on_ack(
            &Ack::new(79, 1, Duration::ZERO, false),
            base + Duration::from_millis(5),
        );
        let stats = bbr.stats();
        assert_eq!(stats.lost_packets, 16, "{stats:?}");
        assert_eq!(stats.lost_bytes, 16 * 1400, "{stats:?}");
        assert_eq!(bbr.inflight(), 63 * 1400);
        assert_eq!(
            stats.orphaned_packets, 0,
            "watermark losses must not also count as orphans"
        );
    }

    #[test]
    fn stale_sweep_counts_losses() {
        let base = Instant::now();
        let mut bbr = Bbr::new(BbrConfig::default());
        for counter in 0..4u64 {
            bbr.on_send(counter, 1400, base);
        }
        bbr.on_timer(base + Duration::from_secs(3));
        let stats = bbr.stats();
        assert_eq!(bbr.inflight(), 0);
        assert_eq!(stats.lost_packets, 4, "{stats:?}");
        assert_eq!(stats.lost_bytes, 4 * 1400, "{stats:?}");
        assert_eq!(stats.dropped_packets, 0);
    }

    #[test]
    fn ring_eviction_is_orphaned_but_not_lost() {
        let base = Instant::now();
        let mut bbr = Bbr::new(BbrConfig::default());
        // One counter past the ring capacity displaces the oldest in-flight
        // record. That is an orphan: no feedback ever named it, and it must
        // not be counted as a loss.
        for counter in 0..=(RING_CAPACITY as u64) {
            bbr.on_send(counter, 1400, base);
        }
        let stats = bbr.stats();
        assert_eq!(stats.orphaned_packets, 1, "{stats:?}");
        assert_eq!(stats.lost_packets, 0, "{stats:?}");
        assert_eq!(stats.lost_bytes, 0, "{stats:?}");
    }

    #[test]
    fn on_drop_releases_inflight_without_a_loss() {
        let base = Instant::now();
        let mut bbr = Bbr::new(BbrConfig::default());
        for counter in 0..4u64 {
            bbr.on_send(counter, 1400, base);
        }
        bbr.on_drop(1, base + Duration::from_millis(1));
        assert_eq!(bbr.inflight(), 3 * 1400);
        let stats = bbr.stats();
        assert_eq!(stats.dropped_packets, 1, "{stats:?}");
        assert_eq!(stats.lost_packets, 0, "{stats:?}");
        // A later loss report for the same counter must not count again.
        bbr.on_loss(1, base + Duration::from_millis(2));
        let stats = bbr.stats();
        assert_eq!(stats.lost_packets, 0, "{stats:?}");
        assert_eq!(stats.spurious_losses, 0, "{stats:?}");
    }

    #[test]
    fn on_drop_bytes_releases_the_newest_datagrams() {
        let base = Instant::now();
        let mut bbr = Bbr::new(BbrConfig::default());
        for counter in 0..4u64 {
            bbr.on_send(counter, 1400, base);
        }
        bbr.on_drop_bytes(2 * 1400);
        let stats = bbr.stats();
        assert_eq!(bbr.inflight(), 2 * 1400);
        assert_eq!(stats.dropped_packets, 2, "{stats:?}");
        assert_eq!(stats.lost_packets, 0, "{stats:?}");
        // The newest counters were released; the older two are still tracked.
        bbr.on_drop(2, base + Duration::from_millis(1));
        assert_eq!(bbr.stats().dropped_packets, 2);
        bbr.on_drop(1, base + Duration::from_millis(2));
        assert_eq!(bbr.stats().dropped_packets, 3);
        assert_eq!(bbr.inflight(), 1400);
    }

    #[test]
    fn on_drop_ignores_unknown_and_acked_counters() {
        let base = Instant::now();
        let mut bbr = Bbr::new(BbrConfig::default());
        bbr.on_send(0, 1400, base);
        bbr.on_drop(7, base + Duration::from_millis(1));
        assert_eq!(bbr.inflight(), 1400);
        assert_eq!(bbr.stats().dropped_packets, 0);
        bbr.on_ack(
            &Ack::new(0, 1, Duration::ZERO, false),
            base + Duration::from_millis(2),
        );
        bbr.on_drop(0, base + Duration::from_millis(3));
        assert_eq!(bbr.stats().dropped_packets, 0);
        assert_eq!(bbr.inflight(), 0);
    }
}
