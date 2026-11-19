mod support;

use std::time::{Duration, Instant};

use support::Lcg;
use umbrawg_cc::{Ack, Bbr, BbrConfig, Mode};

const MSS: usize = 1400;
const MIN_CWND: u64 = 4 * MSS as u64;

fn base_time() -> Instant {
    Instant::now()
}

fn after(base: Instant, duration: Duration) -> Instant {
    base + duration
}

#[test]
fn initial_state_is_minimum_window() {
    let bbr = Bbr::new(BbrConfig::default());
    assert_eq!(bbr.cwnd(), MIN_CWND);
    assert_eq!(bbr.inflight(), 0);
    assert_eq!(bbr.mode(), Mode::Startup);
    assert!(bbr.pacing_rate() > 0);
    assert!(bbr.can_send(MSS));
    assert_eq!(bbr.stats().cwnd_gain, 2000);
    assert_eq!(bbr.stats().pacing_gain, 2770);
}

#[test]
fn single_packet_round_trip() {
    let base = base_time();
    let mut bbr = Bbr::new(BbrConfig::default());
    bbr.on_send(0, MSS, base);
    assert_eq!(bbr.inflight(), MSS as u64);

    bbr.on_ack(
        &Ack::new(0, 1, Duration::ZERO, false),
        after(base, Duration::from_millis(20)),
    );

    assert_eq!(bbr.inflight(), 0);
    let stats = bbr.stats();
    assert_eq!(stats.delivered, MSS as u64);
    assert_eq!(stats.lost_packets, 0);
    assert_eq!(stats.min_rtt, Duration::from_millis(20));
    assert!(bbr.pacing_rate() > 0);
}

#[test]
fn zero_rtt_ack_is_safe() {
    let base = base_time();
    let mut bbr = Bbr::new(BbrConfig::default());
    bbr.on_send(0, MSS, base);
    bbr.on_ack(&Ack::new(0, 1, Duration::ZERO, false), base);

    let stats = bbr.stats();
    assert_eq!(stats.min_rtt, Duration::from_micros(1));
    assert!(bbr.pacing_rate() >= 1);
    assert!(bbr.cwnd() >= MIN_CWND);
}

#[test]
fn huge_rtt_sample_is_safe() {
    let base = base_time();
    let mut bbr = Bbr::new(BbrConfig::default());
    bbr.on_send(0, MSS, base);
    bbr.on_ack(
        &Ack::new(0, 1, Duration::ZERO, false),
        after(base, Duration::from_secs(3600)),
    );

    let stats = bbr.stats();
    assert_eq!(stats.min_rtt, Duration::from_secs(3600));
    assert_eq!(stats.delivered, MSS as u64);
    assert!(bbr.pacing_rate() >= 1);
    assert!(bbr.cwnd() >= MIN_CWND);
}

#[test]
fn ack_delay_larger_than_rtt_is_clamped() {
    let base = base_time();
    let mut bbr = Bbr::new(BbrConfig::default());
    bbr.on_send(0, MSS, base);
    bbr.on_ack(
        &Ack::new(0, 1, Duration::from_secs(5), false),
        after(base, Duration::from_millis(20)),
    );

    let stats = bbr.stats();
    assert_eq!(stats.min_rtt, Duration::from_millis(10));
    assert!(stats.min_rtt >= Duration::from_micros(1));
}

#[test]
fn counter_overflow_is_handled() {
    let base = base_time();
    let mut bbr = Bbr::new(BbrConfig::default());
    bbr.on_send(u64::MAX, MSS, base);
    bbr.on_send(0, MSS, base);
    bbr.on_ack(
        &Ack::new(u64::MAX, u64::MAX, Duration::ZERO, false),
        after(base, Duration::from_millis(20)),
    );
    assert_eq!(bbr.stats().delivered, MSS as u64);
    // Counter zero is outside the 64-bit bitmap window of `u64::MAX`, so it
    // is released from the in-flight accounting as unreachable.
    assert_eq!(bbr.inflight(), 0);
    assert_eq!(bbr.stats().orphaned_packets, 1);

    bbr.on_loss(u64::MAX - 1, after(base, Duration::from_millis(30)));
    bbr.on_loss(u64::MAX, after(base, Duration::from_millis(31)));
    bbr.on_timer(after(base, Duration::from_millis(32)));
    assert!(bbr.pacing_rate() >= 1);
}

#[test]
fn bitmap_holes_are_not_losses_and_can_be_recovered() {
    let base = base_time();
    let mut bbr = Bbr::new(BbrConfig::default());
    for counter in 0..10u64 {
        bbr.on_send(counter, MSS, base);
    }
    let with_holes = !(1 << 6) & !(1 << 3);
    bbr.on_ack(
        &Ack::new(9, with_holes, Duration::ZERO, false),
        after(base, Duration::from_millis(20)),
    );

    let stats = bbr.stats();
    assert_eq!(stats.delivered, 8 * MSS as u64);
    assert_eq!(bbr.inflight(), 2 * MSS as u64);
    assert_eq!(stats.lost_bytes, 0);
    assert_eq!(stats.lost_packets, 0);

    bbr.on_ack(
        &Ack::new(9, u64::MAX, Duration::ZERO, false),
        after(base, Duration::from_millis(25)),
    );
    let stats = bbr.stats();
    assert_eq!(stats.delivered, 10 * MSS as u64);
    assert_eq!(bbr.inflight(), 0);
    assert_eq!(stats.lost_packets, 0);
}

#[test]
fn loss_for_acked_packet_is_spurious() {
    let base = base_time();
    let mut bbr = Bbr::new(BbrConfig::default());
    bbr.on_send(0, MSS, base);
    bbr.on_ack(
        &Ack::new(0, 1, Duration::ZERO, false),
        after(base, Duration::from_millis(20)),
    );
    let pacing_before = bbr.pacing_rate();
    let delivered_before = bbr.stats().delivered;

    bbr.on_loss(0, after(base, Duration::from_millis(21)));

    let stats = bbr.stats();
    assert_eq!(stats.spurious_losses, 1);
    assert_eq!(stats.lost_packets, 0);
    assert_eq!(stats.delivered, delivered_before);
    assert_eq!(bbr.pacing_rate(), pacing_before);
}

#[test]
fn duplicate_ack_does_not_advance_rounds() {
    let base = base_time();
    let mut bbr = Bbr::new(BbrConfig::default());
    for counter in 0..4u64 {
        bbr.on_send(counter, MSS, base);
    }
    let ack = Ack::new(3, u64::MAX, Duration::ZERO, false);
    bbr.on_ack(&ack, after(base, Duration::from_millis(20)));
    let rounds = bbr.stats().rounds;
    let delivered = bbr.stats().delivered;

    bbr.on_ack(&ack, after(base, Duration::from_millis(21)));
    bbr.on_ack(&ack, after(base, Duration::from_millis(22)));

    assert_eq!(bbr.stats().rounds, rounds);
    assert_eq!(bbr.stats().delivered, delivered);
}

#[test]
fn timer_releases_orphaned_packets() {
    let base = base_time();
    let mut bbr = Bbr::new(BbrConfig::default());
    for counter in 0..5u64 {
        bbr.on_send(counter, MSS, base);
    }
    bbr.on_timer(after(base, Duration::from_secs(5)));

    let stats = bbr.stats();
    assert_eq!(bbr.inflight(), 0);
    assert_eq!(stats.orphaned_packets, 5);
    assert!(bbr.cwnd() >= MIN_CWND);
}

#[test]
fn send_window_is_enforced() {
    let base = base_time();
    let mut bbr = Bbr::new(BbrConfig::default());
    let mut now = base;
    for counter in 0..4u64 {
        now += Duration::from_millis(30);
        bbr.on_timer(now);
        assert!(bbr.can_send(MSS), "packet {counter} should fit");
        bbr.on_send(counter, MSS, now);
    }
    assert!(!bbr.can_send(MSS));
    assert_eq!(bbr.inflight(), MIN_CWND);
}

#[test]
fn zero_length_datagram_is_safe() {
    let base = base_time();
    let mut bbr = Bbr::new(BbrConfig::default());
    bbr.on_send(0, 0, base);
    bbr.on_ack(
        &Ack::new(0, 1, Duration::ZERO, false),
        after(base, Duration::from_millis(20)),
    );
    bbr.on_loss(0, after(base, Duration::from_millis(21)));
    bbr.on_timer(after(base, Duration::from_millis(22)));
    assert_eq!(bbr.stats().delivered, 0);
    assert!(bbr.pacing_rate() >= 1);
}

#[test]
fn ack_without_send_is_ignored() {
    let base = base_time();
    let mut bbr = Bbr::new(BbrConfig::default());
    bbr.on_ack(
        &Ack::new(1000, u64::MAX, Duration::ZERO, true),
        after(base, Duration::from_millis(20)),
    );
    let stats = bbr.stats();
    assert_eq!(stats.delivered, 0);
    assert_eq!(bbr.inflight(), 0);
    assert_eq!(stats.rounds, 0);
}

#[test]
fn ten_thousand_random_events_do_not_panic() {
    let mut rng = Lcg::new(0xDEAD_BEEF_1234_5678);
    let mut bbr = Bbr::new(BbrConfig::default());
    let mut now = base_time();
    let mut counter = 0u64;

    for step in 0..10_000u64 {
        now += Duration::from_micros(rng.range(0, 5_000));
        match rng.range(0, 3) {
            0 => {
                let len = rng.range(0, 3_000) as usize;
                bbr.on_send(counter, len, now);
                counter = counter.saturating_add(1);
            }
            1 => {
                let largest = counter.saturating_sub(rng.range(0, 100));
                let shift = rng.range(0, 63) as u32;
                let bitmap = rng.next_u64() >> shift;
                let delay = Duration::from_micros(rng.range(0, 2_000_000));
                let ecn = rng.percent(5);
                bbr.on_ack(&Ack::new(largest, bitmap, delay, ecn), now);
            }
            2 => {
                let lost = counter.saturating_sub(rng.range(0, 200));
                bbr.on_loss(lost, now);
            }
            _ => bbr.on_timer(now),
        }

        let stats = bbr.stats();
        assert!(bbr.cwnd() >= MIN_CWND, "step {step}");
        assert!(bbr.pacing_rate() >= 1, "step {step}");
        assert!(
            stats.inflight_lo <= stats.inflight_hi,
            "step {step}: {:?}",
            stats
        );
        assert!(bbr.mode() != Mode::ProbeRtt || bbr.cwnd() == MIN_CWND);
    }
}
