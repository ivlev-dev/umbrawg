#![allow(dead_code)]

//! Deterministic path simulator used by the integration tests.
//!
//! The link is a single FIFO queue with a fixed service rate, a propagation
//! delay, an optional drop-tail buffer, optional random loss and an optional
//! ECN threshold. ACKs are generated per delivered datagram and carry the
//! 64-bit bitmap of the extension protocol.

use std::cmp::Reverse;
use std::collections::{BTreeSet, BinaryHeap};
use std::time::{Duration, Instant};

use umbrawg_cc::{Ack, Bbr, BbrConfig, BbrStats, Mode};

pub const MSS: usize = 1400;
const NS: u64 = 1_000_000_000;
const KIND_DELIVER: u8 = 0;
const KIND_RECOVER: u8 = 1;
const KIND_LOSS: u8 = 2;

pub fn dur_ns(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

pub fn ms(value: u64) -> Duration {
    Duration::from_millis(value)
}

pub fn secs(value: u64) -> Duration {
    Duration::from_secs(value)
}

/// Deterministic xorshift64* PRNG (no dependencies).
#[derive(Debug, Clone)]
pub struct Lcg(u64);

impl Lcg {
    pub fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub fn percent(&mut self, pct: u32) -> bool {
        if pct == 0 {
            return false;
        }
        self.next_u64() % 100 < u64::from(pct)
    }

    pub fn range(&mut self, low: u64, high: u64) -> u64 {
        if high <= low {
            return low;
        }
        low + self.next_u64() % (high - low + 1)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SimConfig {
    /// Bottleneck rate in bytes per second.
    pub bw: u64,
    /// Propagation RTT with an empty queue.
    pub rtt: Duration,
    /// Drop-tail buffer size in bytes.
    pub buffer: u64,
    /// Independent random loss in percent.
    pub loss_pct: u32,
    /// When true, "lost" datagrams are recovered by FEC instead of being
    /// reported through `on_loss`.
    pub fec_recover: bool,
    /// ACK delay carried by every ACK.
    pub ack_delay: Duration,
    /// Simulated duration.
    pub duration: Duration,
    /// Queue depth above which ECN-CE is signalled.
    pub ecn_threshold: Option<u64>,
    /// Window during which the application offers only one datagram per
    /// 100 ms (an application-limited phase).
    pub stall: Option<(Duration, Duration)>,
}

impl SimConfig {
    pub fn new(bw: u64, rtt: Duration) -> Self {
        Self {
            bw,
            rtt,
            buffer: 4 * 1024 * 1024,
            loss_pct: 0,
            fec_recover: false,
            ack_delay: Duration::ZERO,
            duration: secs(8),
            ecn_threshold: None,
            stall: None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Delivery {
    len: u64,
    lost: bool,
    ecn: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct Sample {
    pub at_ns: u64,
    pub rx_bytes: u64,
    pub pacing_rate: u64,
    pub cwnd: u64,
    pub inflight: u64,
    pub inflight_hi: u64,
    pub inflight_lo: u64,
    pub btl_bw: u64,
    pub mode: Mode,
    pub queue: u64,
}

pub struct SimResult {
    pub samples: Vec<Sample>,
    pub max_queue: u64,
    pub rx_bytes: u64,
    pub sent: u64,
    pub stats: BbrStats,
}

impl SimResult {
    fn sample_at(&self, at_ns: u64) -> Sample {
        self.samples
            .iter()
            .find(|sample| sample.at_ns >= at_ns)
            .copied()
            .unwrap_or(*self.samples.last().expect("samples are never empty"))
    }

    fn window(&self, from: Duration, to: Duration) -> &[Sample] {
        let from = dur_ns(from);
        let to = dur_ns(to);
        let start = self
            .samples
            .iter()
            .position(|sample| sample.at_ns >= from)
            .unwrap_or(self.samples.len());
        let end = self
            .samples
            .iter()
            .position(|sample| sample.at_ns >= to)
            .unwrap_or(self.samples.len());
        &self.samples[start..end.max(start)]
    }

    /// Average pacing rate over a time window, bytes per second.
    pub fn avg_pacing(&self, from: Duration, to: Duration) -> u64 {
        let window = self.window(from, to);
        if window.is_empty() {
            return 0;
        }
        let sum: u128 = window
            .iter()
            .map(|sample| u128::from(sample.pacing_rate))
            .sum();
        u64::try_from(sum / window.len() as u128).unwrap_or(u64::MAX)
    }

    /// Delivered throughput over a time window, bytes per second.
    pub fn rx_rate(&self, from: Duration, to: Duration) -> u64 {
        let a = self.sample_at(dur_ns(from));
        let b = self.sample_at(dur_ns(to));
        if b.at_ns <= a.at_ns {
            return 0;
        }
        let bytes = b.rx_bytes.saturating_sub(a.rx_bytes) as u128;
        let ns = b.at_ns - a.at_ns;
        u64::try_from(bytes * u128::from(NS) / u128::from(ns)).unwrap_or(u64::MAX)
    }

    pub fn max_queue_between(&self, from: Duration, to: Duration) -> u64 {
        self.window(from, to)
            .iter()
            .map(|sample| sample.queue)
            .max()
            .unwrap_or(0)
    }

    pub fn max_inflight_hi(&self) -> u64 {
        self.samples
            .iter()
            .map(|sample| sample.inflight_hi)
            .max()
            .unwrap_or(0)
    }

    pub fn min_cwnd_between(&self, from: Duration, to: Duration) -> u64 {
        self.window(from, to)
            .iter()
            .map(|sample| sample.cwnd)
            .min()
            .unwrap_or(0)
    }

    pub fn max_cwnd_between(&self, from: Duration, to: Duration) -> u64 {
        self.window(from, to)
            .iter()
            .map(|sample| sample.cwnd)
            .max()
            .unwrap_or(0)
    }

    pub fn cwnd_at(&self, at: Duration) -> u64 {
        self.sample_at(dur_ns(at)).cwnd
    }

    pub fn mode_present(&self, from: Duration, to: Duration, mode: Mode) -> bool {
        self.window(from, to)
            .iter()
            .any(|sample| sample.mode == mode)
    }
}

pub struct Sim {
    cfg: SimConfig,
    bbr: Bbr,
    start: Instant,
    now_ns: u64,
    counter: u64,
    link_free_ns: u64,
    events: BinaryHeap<Reverse<(u64, u8, u64)>>,
    deliveries: Vec<Delivery>,
    received: BTreeSet<u64>,
    largest_received: u64,
    ecn_pending: bool,
    rng: Lcg,
    queue_bytes: u64,
    max_queue: u64,
    rx_bytes: u64,
    last_send_ns: u64,
    samples: Vec<Sample>,
}

impl Sim {
    pub fn run(cfg: SimConfig) -> SimResult {
        let mut sim = Self {
            cfg,
            bbr: Bbr::new(BbrConfig::default()),
            start: Instant::now(),
            now_ns: 0,
            counter: 0,
            link_free_ns: 0,
            events: BinaryHeap::new(),
            deliveries: Vec::new(),
            received: BTreeSet::new(),
            largest_received: 0,
            ecn_pending: false,
            rng: Lcg::new(0x5eed_1234_abcd_9876),
            queue_bytes: 0,
            max_queue: 0,
            rx_bytes: 0,
            last_send_ns: 0,
            samples: Vec::new(),
        };
        sim.drive();
        SimResult {
            samples: sim.samples,
            max_queue: sim.max_queue,
            rx_bytes: sim.rx_bytes,
            sent: sim.counter,
            stats: sim.bbr.stats(),
        }
    }

    fn inst(&self, at_ns: u64) -> Instant {
        self.start + Duration::from_nanos(at_ns)
    }

    fn drive(&mut self) {
        let end = dur_ns(self.cfg.duration);
        let mut next_sample = 0u64;
        while self.now_ns < end {
            self.bbr.on_timer(self.inst(self.now_ns));

            while let Some(&Reverse((at, kind, counter))) = self.events.peek() {
                if at > self.now_ns {
                    break;
                }
                self.events.pop();
                self.handle_event(kind, counter, at);
            }

            if self.now_ns >= next_sample {
                self.capture();
                next_sample = self.now_ns.saturating_add(10_000_000);
            }

            let mut sends = 0u32;
            while self.try_send() {
                sends += 1;
                if sends > 65_536 {
                    break;
                }
            }

            let next_event = self
                .events
                .peek()
                .map(|Reverse((at, _, _))| *at)
                .unwrap_or(end);
            let mut next = next_event.min(end);
            if self.events.is_empty() {
                next = next.min(self.now_ns.saturating_add(1_000_000));
            }
            let delay = dur_ns(self.bbr.next_send_delay(MSS, self.inst(self.now_ns)));
            if delay > 0 {
                next = next.min(self.now_ns.saturating_add(delay));
            }
            if next <= self.now_ns {
                next = self.now_ns.saturating_add(1);
            }
            self.now_ns = next.min(end);
        }
    }

    fn try_send(&mut self) -> bool {
        if !self.bbr.can_send(MSS) {
            return false;
        }
        if let Some((from, to)) = self.cfg.stall {
            let now = self.now_ns;
            if now >= dur_ns(from)
                && now < dur_ns(to)
                && now.saturating_sub(self.last_send_ns) < 100_000_000
            {
                return false;
            }
        }
        if !self
            .bbr
            .next_send_delay(MSS, self.inst(self.now_ns))
            .is_zero()
        {
            return false;
        }

        let counter = self.counter;
        self.counter = self.counter.saturating_add(1);
        let now = self.now_ns;
        self.last_send_ns = now;
        self.bbr.on_send(counter, MSS, self.inst(now));

        let service = self.link_free_ns.max(now);
        let tx_ns =
            u64::try_from(u128::from(MSS as u64) * u128::from(NS) / u128::from(self.cfg.bw.max(1)))
                .unwrap_or(u64::MAX);
        let finish = service.saturating_add(tx_ns);
        self.link_free_ns = finish;

        let queued = if service > now {
            u64::try_from(u128::from(service - now) * u128::from(self.cfg.bw) / u128::from(NS))
                .unwrap_or(u64::MAX)
        } else {
            0
        };
        self.queue_bytes = queued;
        self.max_queue = self.max_queue.max(queued);

        let ecn = self
            .cfg
            .ecn_threshold
            .is_some_and(|threshold| queued > threshold);
        let overflow = queued.saturating_add(MSS as u64) > self.cfg.buffer;
        let lost = overflow || self.rng.percent(self.cfg.loss_pct);
        let at = finish.saturating_add(dur_ns(self.cfg.rtt));
        self.deliveries.push(Delivery {
            len: MSS as u64,
            lost,
            ecn,
        });
        self.events.push(Reverse((at, KIND_DELIVER, counter)));
        true
    }

    fn handle_event(&mut self, kind: u8, counter: u64, at: u64) {
        let Some(delivery) = self.deliveries.get(counter as usize).copied() else {
            return;
        };
        match kind {
            KIND_DELIVER => {
                if delivery.lost {
                    if self.cfg.fec_recover {
                        let recover_at = at.saturating_add(dur_ns(self.cfg.rtt));
                        self.events
                            .push(Reverse((recover_at, KIND_RECOVER, counter)));
                    } else {
                        let report_at = at.saturating_add(dur_ns(self.cfg.rtt).saturating_mul(2));
                        self.events.push(Reverse((report_at, KIND_LOSS, counter)));
                    }
                } else {
                    self.receive(counter, delivery, at);
                }
            }
            KIND_RECOVER => self.receive(counter, delivery, at),
            KIND_LOSS => self.bbr.on_loss(counter, self.inst(at)),
            _ => {}
        }
    }

    fn receive(&mut self, counter: u64, delivery: Delivery, at: u64) {
        self.received.insert(counter);
        self.largest_received = self.largest_received.max(counter);
        self.rx_bytes = self.rx_bytes.saturating_add(delivery.len);
        if delivery.ecn {
            self.ecn_pending = true;
        }
        self.send_ack(at);
    }

    fn send_ack(&mut self, at: u64) {
        let largest = self.largest_received;
        let mut bitmap = 0u64;
        let lowest = largest.saturating_sub(63);
        for &counter in self.received.range(lowest..=largest) {
            bitmap |= 1u64 << (largest - counter);
        }
        let ecn = self.ecn_pending;
        self.ecn_pending = false;
        if self.received.len() > 512 {
            let cutoff = largest.saturating_sub(256);
            self.received = self.received.split_off(&cutoff);
        }
        let ack = Ack::new(largest, bitmap, self.cfg.ack_delay, ecn);
        self.bbr.on_ack(&ack, self.inst(at));
    }

    fn capture(&mut self) {
        let queue = if self.link_free_ns > self.now_ns {
            u64::try_from(
                u128::from(self.link_free_ns - self.now_ns) * u128::from(self.cfg.bw)
                    / u128::from(NS),
            )
            .unwrap_or(u64::MAX)
        } else {
            0
        };
        let stats = self.bbr.stats();
        self.samples.push(Sample {
            at_ns: self.now_ns,
            rx_bytes: self.rx_bytes,
            pacing_rate: self.bbr.pacing_rate(),
            cwnd: self.bbr.cwnd(),
            inflight: self.bbr.inflight(),
            inflight_hi: stats.inflight_hi,
            inflight_lo: stats.inflight_lo,
            btl_bw: stats.btl_bw,
            mode: self.bbr.mode(),
            queue,
        });
    }
}
