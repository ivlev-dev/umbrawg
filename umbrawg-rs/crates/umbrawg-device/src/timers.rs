use std::time::{Duration, Instant};

use rand_core::RngCore;

use umbrawg_proto::messages::limits::{
    KEEPALIVE_TIMEOUT, MAX_TIMER_HANDSHAKES, REJECT_AFTER_TIME, REKEY_AFTER_TIME, REKEY_TIMEOUT,
    REKEY_TIMEOUT_JITTER_MAX_MILLIS,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Range16 {
    lo: u16,
    hi: u16,
}

impl Range16 {
    #[must_use]
    pub const fn new(lo: u16, hi: u16) -> Self {
        Self { lo, hi }
    }

    #[must_use]
    pub const fn single(value: u16) -> Self {
        Self {
            lo: value,
            hi: value,
        }
    }

    #[must_use]
    pub fn from_lo_hi(lo: u16, hi: u16) -> Option<Self> {
        if lo > hi {
            None
        } else {
            Some(Self { lo, hi })
        }
    }

    #[must_use]
    pub const fn lo(self) -> u16 {
        self.lo
    }

    #[must_use]
    pub const fn hi(self) -> u16 {
        self.hi
    }

    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.lo == 0 && self.hi == 0
    }

    #[must_use]
    pub fn pick(self, rng: &mut impl RngCore) -> u16 {
        if self.hi <= self.lo {
            return self.lo;
        }
        let span = u32::from(self.hi) - u32::from(self.lo) + 1;
        self.lo + (rng.next_u32() % span) as u16
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timings {
    pub rekey_after_time: Range16,
    pub rekey_timeout: Range16,
    pub reject_after_time: Range16,
    pub keepalive_timeout: Range16,
    pub max_handshake_attempts: Range16,
}

impl Timings {
    #[must_use]
    pub fn new() -> Self {
        Self {
            rekey_after_time: Range16::single(REKEY_AFTER_TIME as u16),
            rekey_timeout: Range16::single(REKEY_TIMEOUT as u16),
            reject_after_time: Range16::single(REJECT_AFTER_TIME as u16),
            keepalive_timeout: Range16::single(KEEPALIVE_TIMEOUT as u16),
            max_handshake_attempts: Range16::single(MAX_TIMER_HANDSHAKES as u16),
        }
    }

    #[must_use]
    pub fn validate(&self) -> bool {
        [
            self.rekey_after_time,
            self.rekey_timeout,
            self.reject_after_time,
            self.keepalive_timeout,
            self.max_handshake_attempts,
        ]
        .into_iter()
        .all(|range| range.lo() <= range.hi())
    }

    fn seconds(range: Range16, default: u16, rng: &mut impl RngCore) -> u64 {
        u64::from(if range.is_zero() {
            default
        } else {
            range.pick(rng)
        })
    }

    fn seconds_hi(range: Range16, default: u16) -> u64 {
        u64::from(if range.is_zero() {
            default
        } else {
            range.hi()
        })
    }

    fn seconds_lo(range: Range16, default: u16) -> u64 {
        u64::from(if range.is_zero() {
            default
        } else {
            range.lo()
        })
    }

    #[must_use]
    pub fn retransmit_handshake(&self, rng: &mut impl RngCore) -> Duration {
        Duration::from_secs(Self::seconds(self.rekey_timeout, REKEY_TIMEOUT as u16, rng))
            + jitter(rng)
    }

    #[must_use]
    pub fn rekey_min_timeout(&self) -> Duration {
        Duration::from_secs(Self::seconds_lo(self.rekey_timeout, REKEY_TIMEOUT as u16))
    }

    #[must_use]
    pub fn send_keepalive(&self, rng: &mut impl RngCore) -> Duration {
        Duration::from_secs(Self::seconds(
            self.keepalive_timeout,
            KEEPALIVE_TIMEOUT as u16,
            rng,
        ))
    }

    #[must_use]
    pub fn new_handshake(&self, rng: &mut impl RngCore) -> Duration {
        let keepalive = Self::seconds_hi(self.keepalive_timeout, KEEPALIVE_TIMEOUT as u16);
        let rekey = Self::seconds(self.rekey_timeout, REKEY_TIMEOUT as u16, rng);
        Duration::from_secs(keepalive + rekey) + jitter(rng)
    }

    #[must_use]
    pub fn key_refresh_sending(&self, rng: &mut impl RngCore) -> Duration {
        Duration::from_secs(Self::seconds(
            self.rekey_after_time,
            REKEY_AFTER_TIME as u16,
            rng,
        ))
    }

    #[must_use]
    pub fn key_refresh_receiving(&self) -> Duration {
        let reject = Self::seconds_hi(self.reject_after_time, REJECT_AFTER_TIME as u16);
        let keepalive = Self::seconds_lo(self.keepalive_timeout, KEEPALIVE_TIMEOUT as u16);
        let rekey = Self::seconds_lo(self.rekey_timeout, REKEY_TIMEOUT as u16);
        Duration::from_secs(reject.saturating_sub(keepalive).saturating_sub(rekey))
    }

    #[must_use]
    pub fn keychain_expire(&self) -> Duration {
        Duration::from_secs(Self::seconds_hi(
            self.reject_after_time,
            REJECT_AFTER_TIME as u16,
        ))
    }

    #[must_use]
    pub fn max_handshake_attempts(&self, rng: &mut impl RngCore) -> u32 {
        Self::seconds(
            self.max_handshake_attempts,
            MAX_TIMER_HANDSHAKES as u16,
            rng,
        )
        .min(u64::from(u32::MAX)) as u32
    }
}

impl Default for Timings {
    fn default() -> Self {
        Self::new()
    }
}

fn jitter(rng: &mut impl RngCore) -> Duration {
    Duration::from_millis(u64::from(
        rng.next_u32() % REKEY_TIMEOUT_JITTER_MAX_MILLIS as u32,
    ))
}

pub const TIMER_COUNT: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum TimerKind {
    RetransmitHandshake = 0,
    SendKeepalive = 1,
    NewHandshake = 2,
    ZeroKeyMaterial = 3,
    PersistentKeepalive = 4,
}

impl TimerKind {
    pub const ALL: [Self; 5] = [
        Self::RetransmitHandshake,
        Self::SendKeepalive,
        Self::NewHandshake,
        Self::ZeroKeyMaterial,
        Self::PersistentKeepalive,
    ];

    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Timers {
    deadlines: [Option<Instant>; 5],
    pub handshake_attempts: u32,
    pub max_handshake_attempts: u32,
    pub need_another_keepalive: bool,
    pub sent_last_minute_handshake: bool,
}

impl Timers {
    #[must_use]
    pub fn new() -> Self {
        Self {
            deadlines: [None; 5],
            handshake_attempts: 0,
            max_handshake_attempts: MAX_TIMER_HANDSHAKES as u32,
            need_another_keepalive: false,
            sent_last_minute_handshake: false,
        }
    }

    pub fn arm(&mut self, kind: TimerKind, deadline: Instant) {
        self.deadlines[kind.index()] = Some(deadline);
    }

    pub fn disarm(&mut self, kind: TimerKind) {
        self.deadlines[kind.index()] = None;
    }

    #[must_use]
    pub fn deadline(&self, kind: TimerKind) -> Option<Instant> {
        self.deadlines[kind.index()]
    }

    #[must_use]
    pub fn is_pending(&self, kind: TimerKind) -> bool {
        self.deadlines[kind.index()].is_some()
    }

    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        self.deadlines.iter().flatten().copied().min()
    }

    pub fn expire(&mut self, now: Instant, out: &mut [TimerKind; 5]) -> usize {
        let mut count = 0;
        for (index, kind) in TimerKind::ALL.into_iter().enumerate() {
            if self.deadlines[index].is_some_and(|deadline| now >= deadline) {
                self.deadlines[index] = None;
                out[count] = kind;
                count += 1;
            }
        }
        count
    }

    pub fn reset(&mut self) {
        self.deadlines = [None; 5];
        self.handshake_attempts = 0;
        self.need_another_keepalive = false;
        self.sent_last_minute_handshake = false;
    }
}

impl Default for Timers {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StepRng(u32);

    impl RngCore for StepRng {
        fn next_u32(&mut self) -> u32 {
            self.0 = self.0.wrapping_add(1);
            self.0
        }

        fn next_u64(&mut self) -> u64 {
            u64::from(self.next_u32()) << 32 | u64::from(self.next_u32())
        }

        fn fill_bytes(&mut self, dst: &mut [u8]) {
            for chunk in dst.chunks_mut(4) {
                let bytes = self.next_u32().to_le_bytes();
                let length = chunk.len();
                chunk.copy_from_slice(&bytes[..length]);
            }
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dst);
            Ok(())
        }
    }

    #[test]
    fn ranges_pick_inside_bounds() {
        let mut rng = StepRng(0);
        let range = Range16::new(5, 9);
        for _ in 0..16 {
            let value = range.pick(&mut rng);
            assert!((5..=9).contains(&value));
        }
        assert_eq!(Range16::single(7).pick(&mut rng), 7);
        assert!(Range16::from_lo_hi(9, 5).is_none());
    }

    #[test]
    fn defaults_match_wireguard() {
        let timings = Timings::new();
        assert!(timings.validate());
        assert_eq!(timings.rekey_after_time.lo(), 120);
        assert_eq!(timings.rekey_timeout.lo(), 5);
        assert_eq!(timings.reject_after_time.lo(), 180);
        assert_eq!(timings.keepalive_timeout.lo(), 10);
        assert_eq!(timings.max_handshake_attempts.lo(), 18);
    }

    #[test]
    fn zero_ranges_fall_back_to_defaults() {
        let timings = Timings {
            rekey_after_time: Range16::default(),
            rekey_timeout: Range16::default(),
            reject_after_time: Range16::default(),
            keepalive_timeout: Range16::default(),
            max_handshake_attempts: Range16::default(),
        };
        let mut rng = StepRng(1);
        assert_eq!(timings.rekey_min_timeout(), Duration::from_secs(5));
        assert_eq!(
            timings.key_refresh_sending(&mut rng),
            Duration::from_secs(120)
        );
        assert_eq!(timings.keychain_expire(), Duration::from_secs(180));
        assert_eq!(timings.max_handshake_attempts(&mut rng), 18);
        assert_eq!(timings.key_refresh_receiving(), Duration::from_secs(165));
    }

    #[test]
    fn timers_are_ordered_and_expire_once() {
        let now = Instant::now();
        let mut timers = Timers::new();
        timers.arm(TimerKind::SendKeepalive, now + Duration::from_secs(1));
        timers.arm(TimerKind::RetransmitHandshake, now);
        timers.arm(TimerKind::ZeroKeyMaterial, now + Duration::from_secs(10));
        assert_eq!(
            timers.next_deadline(),
            Some(now)
        );
        let mut expired = [TimerKind::SendKeepalive; 5];
        let count = timers.expire(now + Duration::from_secs(2), &mut expired);
        assert_eq!(&expired[..count], &[TimerKind::RetransmitHandshake, TimerKind::SendKeepalive]);
        assert_eq!(timers.deadline(TimerKind::RetransmitHandshake), None);
        let count = timers.expire(now + Duration::from_secs(2), &mut expired);
        assert_eq!(count, 0);
        assert_eq!(timers.next_deadline(), Some(now + Duration::from_secs(10)));
        timers.disarm(TimerKind::ZeroKeyMaterial);
        assert!(timers.next_deadline().is_none());
    }

    #[test]
    fn reset_clears_attempts() {
        let mut timers = Timers::new();
        timers.handshake_attempts = 3;
        timers.need_another_keepalive = true;
        timers.sent_last_minute_handshake = true;
        timers.arm(TimerKind::NewHandshake, Instant::now());
        timers.reset();
        assert_eq!(timers.handshake_attempts, 0);
        assert!(!timers.need_another_keepalive);
        assert!(!timers.sent_last_minute_handshake);
        assert!(timers.next_deadline().is_none());
    }
}
