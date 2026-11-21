//! Public value types: feedback, controller mode and statistics.

use core::time::Duration;

/// Sender state machine of the controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    /// Ramping the pacing rate up at `2.77 * BtlBw` until the pipe is full.
    Startup,
    /// Draining the queue built during [`Mode::Startup`].
    Drain,
    /// Steady state: the pacing gain cycles around `BtlBw`.
    ProbeBw,
    /// Periodic queue drain that refreshes the RTT floor.
    ProbeRtt,
}

/// Cumulative acknowledgement for the outer UDP flow.
///
/// The bitmap follows the wire format of the UmbraWG extension: bit `i` is
/// set when the datagram with counter `largest_counter - i` was received.
/// Datagrams recovered by FEC are marked as received as well.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ack {
    /// Highest counter known to be received.
    pub largest_counter: u64,
    /// Received bitmap, bit `i` covers `largest_counter - i`.
    pub bitmap: u64,
    /// Delay between receiving `largest_counter` and emitting this ACK.
    pub ack_delay: Duration,
    /// Whether an ECN-CE mark was observed.
    pub ecn_ce: bool,
}

impl Ack {
    /// Builds an acknowledgement frame.
    pub const fn new(largest_counter: u64, bitmap: u64, ack_delay: Duration, ecn_ce: bool) -> Self {
        Self {
            largest_counter,
            bitmap,
            ack_delay,
            ecn_ce,
        }
    }
}

/// Snapshot of the controller state, useful for monitoring and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BbrStats {
    /// Current mode of the state machine.
    pub mode: Mode,
    /// Current pacing rate in bytes per second.
    pub pacing_rate: u64,
    /// Current congestion window in bytes.
    pub cwnd: u64,
    /// Bytes currently considered in flight.
    pub inflight: u64,
    /// Windowed maximum delivery rate in bytes per second.
    pub btl_bw: u64,
    /// Windowed minimum RTT (the initial RTT until the first sample).
    pub min_rtt: Duration,
    /// Most recent RTT sample (the initial RTT until the first sample).
    pub latest_rtt: Duration,
    /// Total bytes acknowledged (including FEC-recovered datagrams).
    pub delivered: u64,
    /// Total bytes reported lost through [`crate::Bbr::on_loss`].
    pub lost_bytes: u64,
    /// Total datagrams reported lost through [`crate::Bbr::on_loss`].
    pub lost_packets: u64,
    /// Loss reports ignored because the datagram was already resolved.
    pub spurious_losses: u64,
    /// Unacknowledged datagrams dropped from the tracking ring.
    pub orphaned_packets: u64,
    /// Datagrams dropped locally by the send path and released from the
    /// in-flight accounting without being treated as path loss.
    pub dropped_packets: u64,
    /// Completed packet-timed rounds.
    pub rounds: u64,
    /// Whether the last round was application-limited.
    pub app_limited: bool,
    /// Current upper in-flight bound in bytes.
    pub inflight_hi: u64,
    /// Current lower in-flight bound in bytes.
    pub inflight_lo: u64,
    /// Current pacing gain in per-mille (`1000` means 1.0).
    pub pacing_gain: u32,
    /// Current cwnd gain in per-mille.
    pub cwnd_gain: u32,
    /// Whether the pipe was declared full during `STARTUP`.
    pub full_bw_reached: bool,
    /// Phase index of the `PROBE_BW` pacing cycle (0..=7).
    pub probe_bw_phase: u8,
    /// Number of ECN-CE marks observed.
    pub ecn_ce: u64,
}
