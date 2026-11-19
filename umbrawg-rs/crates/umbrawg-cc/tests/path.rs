mod support;

use std::time::Duration;

use support::{ms, secs, Sim, SimConfig};
use umbrawg_cc::Mode;

const BW: u64 = 12_500_000;
const RTT: Duration = Duration::from_millis(20);
const MSS: u64 = 1400;
const BDP: u64 = 250_000;

fn path() -> SimConfig {
    SimConfig::new(BW, RTT)
}

#[test]
fn steady_state_reaches_link_bandwidth() {
    let cfg = SimConfig {
        duration: secs(8),
        ..path()
    };
    let result = Sim::run(cfg);

    assert!(result.stats.full_bw_reached, "{:?}", result.stats);
    assert!(result.stats.btl_bw * 100 >= BW * 90, "{:?}", result.stats);

    let pacing = result.avg_pacing(ms(5000), ms(8000));
    assert!(
        pacing * 100 >= BW * 90 && pacing * 100 <= BW * 110,
        "average pacing {pacing} outside 90..110% of {BW}: {:?}",
        result.stats
    );

    let rx = result.rx_rate(ms(5000), ms(8000));
    assert!(
        rx * 100 >= BW * 95,
        "delivered rate {rx}: {:?}",
        result.stats
    );

    let header = result.max_queue_between(ms(6000), ms(8000));
    assert!(
        header < 400_000,
        "queue keeps growing: {header} bytes buffered"
    );

    let max_cwnd = result.max_cwnd_between(ms(6000), ms(8000));
    assert!(
        max_cwnd <= 2 * BDP + 4 * MSS,
        "cwnd {max_cwnd} exceeds two BDPs"
    );

    assert!(
        result.stats.mode == Mode::ProbeBw,
        "steady state should be PROBE_BW: {:?}",
        result.stats
    );
}

#[test]
fn two_percent_loss_lowers_inflight_hi_without_collapsing_rate() {
    let baseline = Sim::run(SimConfig {
        duration: secs(10),
        ..path()
    });
    let lossy = Sim::run(SimConfig {
        duration: secs(10),
        loss_pct: 2,
        ..path()
    });

    assert!(
        lossy.stats.lost_packets > 0,
        "the lossy run must report losses: {:?}",
        lossy.stats
    );

    let rx = lossy.rx_rate(ms(7000), ms(9000));
    assert!(
        rx * 100 >= BW * 85,
        "throughput collapsed to {rx}: {:?}",
        lossy.stats
    );

    let pacing = lossy.avg_pacing(ms(7000), ms(9000));
    assert!(
        pacing * 100 >= BW * 80 && pacing * 100 <= BW * 125,
        "pacing {pacing} left the sane band: {:?}",
        lossy.stats
    );

    assert!(
        lossy.stats.inflight_lo <= lossy.stats.inflight_hi,
        "bounds inverted: {:?}",
        lossy.stats
    );
    let one_bdp = lossy.stats.btl_bw * lossy.stats.min_rtt.as_nanos() as u64 / 1_000_000_000;
    assert!(
        lossy.stats.inflight_hi >= one_bdp * 9 / 10,
        "inflight_hi fell below one BDP: {:?}",
        lossy.stats
    );
    assert!(
        lossy.stats.inflight_hi * 2 < baseline.stats.inflight_hi,
        "loss did not reduce inflight_hi: lossy={} baseline={}",
        lossy.stats.inflight_hi,
        baseline.stats.inflight_hi
    );
    assert!(
        lossy.stats.inflight_hi <= BDP * 3 / 2,
        "inflight_hi did not converge towards the BDP floor: lossy={} baseline={}",
        lossy.stats.inflight_hi,
        baseline.stats.inflight_hi
    );
    assert!(
        lossy.stats.mode != Mode::Startup,
        "startup did not terminate: {:?}",
        lossy.stats
    );
}

#[test]
fn fec_recovered_losses_do_not_slow_the_flow() {
    let result = Sim::run(SimConfig {
        duration: secs(8),
        loss_pct: 2,
        fec_recover: true,
        ..path()
    });

    assert_eq!(result.stats.lost_packets, 0, "{:?}", result.stats);
    assert_eq!(result.stats.spurious_losses, 0, "{:?}", result.stats);

    let rx = result.rx_rate(ms(5000), ms(8000));
    assert!(
        rx * 100 >= BW * 95,
        "FEC-recovered path lost throughput: {rx}: {:?}",
        result.stats
    );

    let pacing = result.avg_pacing(ms(5000), ms(8000));
    assert!(
        pacing * 100 >= BW * 90 && pacing * 100 <= BW * 110,
        "average pacing {pacing} outside 90..110% of {BW}: {:?}",
        result.stats
    );
}

#[test]
fn probe_rtt_cuts_cwnd_to_four_packets_and_recovers() {
    let result = Sim::run(SimConfig {
        duration: secs(12),
        ..path()
    });

    assert!(
        result.mode_present(ms(10_000), ms(11_000), Mode::ProbeRtt),
        "PROBE_RTT did not trigger after ten seconds: {:?}",
        result.stats
    );

    let min_cwnd = result.min_cwnd_between(ms(10_000), ms(11_000));
    assert_eq!(min_cwnd, 4 * MSS, "cwnd was not cut to four packets");

    let recovered = result.cwnd_at(ms(11_500));
    assert!(
        recovered > 4 * MSS * 4,
        "cwnd did not recover after PROBE_RTT: {recovered}"
    );
}

#[test]
fn ecn_marks_lower_inflight_hi_without_collapsing_rate() {
    let baseline = Sim::run(SimConfig {
        duration: secs(8),
        ..path()
    });
    let ecn = Sim::run(SimConfig {
        duration: secs(8),
        ecn_threshold: Some(20_000),
        ..path()
    });

    assert!(ecn.stats.ecn_ce > 0, "no ECN-CE marks were observed");
    assert!(
        ecn.stats.inflight_hi <= baseline.stats.inflight_hi,
        "ECN raised inflight_hi: ecn={} baseline={}",
        ecn.stats.inflight_hi,
        baseline.stats.inflight_hi
    );

    let rx = ecn.rx_rate(ms(5000), ms(8000));
    assert!(
        rx * 100 >= BW * 85,
        "ECN run collapsed to {rx}: {:?}",
        ecn.stats
    );
}

#[test]
fn application_limited_period_preserves_the_bandwidth_estimate() {
    let result = Sim::run(SimConfig {
        duration: secs(10),
        stall: Some((secs(3), secs(6))),
        ..path()
    });

    let before = result
        .samples
        .iter()
        .find(|sample| sample.at_ns >= 2_900_000_000)
        .map(|sample| sample.btl_bw)
        .expect("samples exist");
    let during = result
        .samples
        .iter()
        .find(|sample| sample.at_ns >= 5_900_000_000)
        .map(|sample| sample.btl_bw)
        .expect("samples exist");
    assert!(
        during * 100 >= BW * 90,
        "BtlBw collapsed during an application-limited phase: {during}"
    );
    assert!(
        during * 100 >= before * 90,
        "BtlBw changed from {before} to {during} while idle"
    );

    let rx = result.rx_rate(ms(7000), ms(9000));
    assert!(
        rx * 100 >= BW * 90,
        "the flow did not resume after the application-limited phase: {rx}"
    );
}

#[test]
fn bounds_and_window_stay_sane() {
    let result = Sim::run(SimConfig {
        duration: secs(6),
        ..path()
    });
    for sample in &result.samples {
        assert!(
            sample.inflight_lo <= sample.inflight_hi,
            "bounds inverted at {} ns",
            sample.at_ns
        );
        assert!(
            sample.cwnd >= 4 * MSS,
            "cwnd below the minimum at {} ns",
            sample.at_ns
        );
        // STARTUP deliberately overshoots and DRAIN removes the queue, so a
        // temporary inflight above cwnd is expected; it must stay bounded.
        assert!(
            sample.inflight <= sample.cwnd.saturating_mul(4),
            "inflight {} far above cwnd {} at {} ns",
            sample.inflight,
            sample.cwnd,
            sample.at_ns
        );
    }
    assert!(!result.samples.is_empty());
}
