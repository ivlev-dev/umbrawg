//! BBRv3-style congestion control for the UmbraWG outer UDP flow.
//!
//! The controller is sender-side and ACK-clocked: it consumes cumulative ACK
//! frames ([`Ack`]), the lengths of transmitted datagrams and the time of
//! transmission, and produces a pacing rate, a congestion window and an
//! in-flight limit. It never inspects the encapsulated IP protocol, so it
//! works the same for TCP, UDP or ICMP payloads.
//!
//! # Model
//!
//! * `BtlBw` — windowed maximum of the delivery-rate samples over 10
//!   round trips. Round boundaries are detected with the `delivered` byte
//!   counter, exactly like the Linux implementation.
//! * `RTprop` — windowed minimum RTT over 10 seconds. A separate 10 second
//!   watchdog triggers `PROBE_RTT` when the minimum has not been refreshed.
//! * Modes — `STARTUP` (pacing gain 2.77), `DRAIN` (gain 1/2.77),
//!   `PROBE_BW` (gain cycle `[1.25, 0.75, 1, 1, 1, 1, 1, 1]`, one phase per
//!   `RTprop`) and `PROBE_RTT` (cwnd of 4 packets for 200 ms).
//! * `cwnd = max(cwnd_gain * BtlBw * RTprop, min_cwnd_packets * mss)`,
//!   clamped by the `inflight_hi`/`inflight_lo` bounds.
//! * Loss at or above 2 % per round lowers `inflight_hi`; a growing `BtlBw`
//!   (more than 5 %) raises it again. `inflight_lo` is a recovery floor that
//!   keeps the window from collapsing after a loss burst.
//! * Pacing is a token bucket. [`Bbr::next_send_delay`] only reports the
//!   delay needed by the bucket; it never sleeps.
//!
//! # FEC and loss
//!
//! Packets recovered by the FEC layer are reported as received in the ACK
//! bitmap, so they never produce a gap. [`Bbr::on_loss`] is the explicit
//! congestion signal; the ACK watermark and the stale-record sweep also
//! report a datagram that left the tracked window unacknowledged as a loss.
//! Calling [`Bbr::on_loss`] for a counter that was already acknowledged (or
//! already declared lost) is treated as spurious and ignored.
//! [`Bbr::on_drop`] releases a datagram that failed locally without treating
//! the local error as a path loss.
//!
//! # Deviations from Linux BBRv3
//!
//! * Delivery-rate samples are loss-compensated by the round loss ratio
//!   (bounded by 25 %), because a tunnel ACK stream reports only delivered
//!   bytes and random loss must not shrink `BtlBw` multiplicatively.
//! * `inflight_hi` is floored at one BDP, `inflight_lo` at the minimum
//!   window; `inflight_hi` is never driven below one BDP of the current
//!   `BtlBw` estimate.
//! * No ECN-driven `bw_lo`, no long-term policer detector, no ACK
//!   aggregation (`extra_acked`) accounting.
//! * The ACK delay of the peer is subtracted from rate intervals (bounded by
//!   the interval itself) and from RTT samples (bounded by half the sample,
//!   with a 1 µs floor).
//!
//! # Example
//!
//! ```
//! use std::time::{Duration, Instant};
//! use umbrawg_cc::{Ack, Bbr, BbrConfig};
//!
//! let mut bbr = Bbr::new(BbrConfig::default());
//! let now = Instant::now();
//! bbr.on_send(0, 1400, now);
//! bbr.on_ack(&Ack::new(0, 1, Duration::ZERO, false), now + Duration::from_millis(20));
//! assert!(bbr.pacing_rate() > 0);
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod bbr;
mod config;
mod filters;
mod pacing;
mod ring;
mod types;

pub use bbr::Bbr;
pub use config::BbrConfig;
pub use types::{Ack, BbrStats, Mode};
