//! Ограничения исходящих датаграмм по MTU подложки (underlay).
//!
//! GSO-сегмент становится отдельным IP-пакетом, поэтому его размер не должен
//! превышать `underlay_mtu - 28`: иначе ядро не сегментирует супер-датаграмму,
//! а отправит кадр крупнее MTU, который выбросит первый же коммутатор.

use core::fmt;
use std::sync::Mutex;

use umbrawg_transport::{AddressFamily, GsoLimits, MAX_SEGMENTS};

/// MTU подложки по умолчанию: безопасен для обычного Ethernet.
pub const DEFAULT_UNDERLAY_MTU: u32 = 1500;

/// Минимальный допустимый MTU подложки (минимальный IPv4 reassembly buffer).
pub const MIN_UNDERLAY_MTU: u32 = 576;

/// Максимальный допустимый MTU подложки.
pub const MAX_UNDERLAY_MTU: u32 = 65_535;

/// Ограничение числа сегментов в одной GSO-датаграмме по умолчанию.
pub const DEFAULT_GSO_SEGMENTS: usize = 64;

/// Накладные расходы WireGuard/UmbraWG на пакет данных без `S4`.
pub const WIRE_OVERHEAD: usize = 32;

/// Разобранные ограничения подложки.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Underlay {
    mtu: u32,
    segments: usize,
}

impl Underlay {
    /// Собирает ограничения из `UMBRAWG_UNDERLAY_MTU` и `UMBRAWG_GSO_SEGMENTS`.
    pub fn from_env() -> Result<Self, String> {
        let mtu = underlay_mtu(std::env::var("UMBRAWG_UNDERLAY_MTU").ok().as_deref())?;
        let segments = gso_segments(std::env::var("UMBRAWG_GSO_SEGMENTS").ok().as_deref())?;
        Self::new(mtu, segments)
    }

    /// Проверяет и создаёт ограничения из готовых значений.
    pub fn new(mtu: u32, segments: usize) -> Result<Self, String> {
        Ok(Self {
            mtu: validate_underlay_mtu(mtu)?,
            segments: validate_gso_segments(segments)?,
        })
    }

    /// MTU подложки в байтах.
    pub fn mtu(self) -> u32 {
        self.mtu
    }

    /// Ограничения GSO для IPv4: размер сегмента из MTU подложки, потолок
    /// сегментов — из конфигурации.
    pub fn gso_limits(self) -> GsoLimits {
        let derived = GsoLimits::from_mtu(self.mtu, AddressFamily::Ipv4);
        GsoLimits::new(derived.max_gso_size(), self.segments)
            .expect("underlay limits are validated on construction")
    }

    /// Максимальный размер GSO-сегмента (UDP payload) в байтах.
    pub fn max_segment(self) -> usize {
        self.gso_limits().max_gso_size()
    }
}

impl fmt::Display for Underlay {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "underlay mtu {} bytes, gso segment size <= {} bytes, gso segments <= {}",
            self.mtu,
            self.max_segment(),
            self.segments
        )
    }
}

/// Разбирает MTU подложки с диапазоном `576..=65535`.
pub fn underlay_mtu(value: Option<&str>) -> Result<u32, String> {
    let Some(raw) = value else {
        return Ok(DEFAULT_UNDERLAY_MTU);
    };
    let text = raw.trim();
    let mtu = text
        .parse::<u32>()
        .map_err(|_| format!("UMBRAWG_UNDERLAY_MTU: ожидается MTU в байтах, получено {text:?}"))?;
    validate_underlay_mtu(mtu)
}

fn validate_underlay_mtu(mtu: u32) -> Result<u32, String> {
    if !(MIN_UNDERLAY_MTU..=MAX_UNDERLAY_MTU).contains(&mtu) {
        return Err(format!(
            "UMBRAWG_UNDERLAY_MTU: MTU {mtu} вне диапазона \
             {MIN_UNDERLAY_MTU}..={MAX_UNDERLAY_MTU} байт"
        ));
    }
    Ok(mtu)
}

/// Разбирает потолок сегментов GSO с диапазоном `1..=64`.
pub fn gso_segments(value: Option<&str>) -> Result<usize, String> {
    let Some(raw) = value else {
        return Ok(DEFAULT_GSO_SEGMENTS);
    };
    let text = raw.trim();
    let segments = text.parse::<usize>().map_err(|_| {
        format!("UMBRAWG_GSO_SEGMENTS: ожидается число сегментов, получено {text:?}")
    })?;
    validate_gso_segments(segments)
}

fn validate_gso_segments(segments: usize) -> Result<usize, String> {
    if !(1..=MAX_SEGMENTS).contains(&segments) {
        return Err(format!(
            "UMBRAWG_GSO_SEGMENTS: {segments} вне диапазона 1..={MAX_SEGMENTS}"
        ));
    }
    Ok(segments)
}

/// Проверка соответствия TUN MTU и MTU подложки.
///
/// `S4` — максимальный префикс данных в профиле обфускации, поэтому кадр
/// данных занимает `tun_mtu + WIRE_OVERHEAD + S4` байт.
#[derive(Debug)]
pub struct MtuGuard {
    underlay: Underlay,
    last: Mutex<Option<(u16, u16)>>,
}

impl MtuGuard {
    /// Создаёт проверку для ограничений `underlay`.
    pub fn new(underlay: Underlay) -> Self {
        Self {
            underlay,
            last: Mutex::new(None),
        }
    }

    /// Проверяет TUN MTU и `S4`, логируя вердикт только при изменении входа.
    pub fn check(&self, tun_mtu: u16, s4: u16) {
        let Some((fits, message)) = self.record(tun_mtu, s4) else {
            return;
        };
        if fits {
            log::info!("{message}");
        } else {
            log::warn!("{message}");
        }
    }

    fn record(&self, tun_mtu: u16, s4: u16) -> Option<(bool, String)> {
        let mut last = match self.last.lock() {
            Ok(last) => last,
            Err(poisoned) => poisoned.into_inner(),
        };
        if *last == Some((tun_mtu, s4)) {
            return None;
        }
        *last = Some((tun_mtu, s4));
        Some(mtu_report(self.underlay, tun_mtu, s4))
    }
}

/// Возвращает вердикт (`true` — кадр помещается) и текст для лога.
pub fn mtu_report(underlay: Underlay, tun_mtu: u16, s4: u16) -> (bool, String) {
    let overhead = WIRE_OVERHEAD + usize::from(s4);
    let frame = usize::from(tun_mtu) + overhead;
    let limit = underlay.max_segment();
    if frame <= limit {
        return (
            true,
            format!(
                "TUN MTU {tun_mtu} + {overhead} bytes of overhead = {frame} bytes fits the \
                 {limit}-byte IPv4 payload budget of the {}-byte underlay MTU",
                underlay.mtu()
            ),
        );
    }
    let safe_mtu = limit.saturating_sub(overhead);
    (
        false,
        format!(
            "TUN MTU {tun_mtu} + {overhead} bytes of WireGuard/obfuscation overhead = {frame} \
             bytes exceeds the {limit}-byte IPv4 payload budget of the {}-byte underlay MTU: \
             such datagrams are sent without GSO and rely on IP fragmentation. Lower the TUN MTU \
             to {safe_mtu} or raise the underlay MTU (UMBRAWG_UNDERLAY_MTU)",
            underlay.mtu()
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn underlay_mtu_defaults_to_ethernet() {
        assert_eq!(underlay_mtu(None), Ok(DEFAULT_UNDERLAY_MTU));
        assert_eq!(underlay_mtu(Some(" 9000 ")), Ok(9000));
        assert_eq!(underlay_mtu(Some("576")), Ok(MIN_UNDERLAY_MTU));
        assert_eq!(underlay_mtu(Some("65535")), Ok(MAX_UNDERLAY_MTU));
    }

    #[test]
    fn underlay_mtu_rejects_out_of_range() {
        for value in ["", " ", "0", "575", "65536", "jumbo", "-1", "9k"] {
            let error = underlay_mtu(Some(value)).expect_err(value);
            assert!(error.contains("UMBRAWG_UNDERLAY_MTU"), "{value}: {error}");
        }
    }

    #[test]
    fn gso_segments_defaults_and_bounds() {
        assert_eq!(gso_segments(None), Ok(DEFAULT_GSO_SEGMENTS));
        assert_eq!(gso_segments(Some("1")), Ok(1));
        assert_eq!(gso_segments(Some("64")), Ok(MAX_SEGMENTS));
        assert_eq!(gso_segments(Some(" 32 ")), Ok(32));
        for value in ["", "0", "65", "many", "-1"] {
            let error = gso_segments(Some(value)).expect_err(value);
            assert!(error.contains("UMBRAWG_GSO_SEGMENTS"), "{value}: {error}");
        }
    }

    #[test]
    fn underlay_1500_keeps_obfuscated_segments_plain() {
        let rules = Underlay::new(1500, DEFAULT_GSO_SEGMENTS).unwrap();
        assert_eq!(rules.max_segment(), 1472);
        assert!(rules.max_segment() < 1420 + 32 + 60);
        assert_eq!(rules.gso_limits().max_segments(), DEFAULT_GSO_SEGMENTS);
    }

    #[test]
    fn underlay_9000_allows_obfuscated_segments() {
        let rules = Underlay::new(9000, DEFAULT_GSO_SEGMENTS).unwrap();
        assert_eq!(rules.max_segment(), 8972);
        assert!(rules.max_segment() >= 1420 + 32 + 60);
        let limits = rules.gso_limits();
        assert_eq!(limits.max_segments(), DEFAULT_GSO_SEGMENTS);
        assert_eq!(limits.max_gso_size(), 8972);
    }

    #[test]
    fn gso_segment_cap_survives_tiny_underlay() {
        let rules = Underlay::new(MIN_UNDERLAY_MTU, MAX_SEGMENTS).unwrap();
        assert_eq!(rules.max_segment(), 548);
        assert_eq!(rules.gso_limits().max_segments(), MAX_SEGMENTS);
    }

    #[test]
    fn report_accepts_fitting_frame() {
        let rules = Underlay::new(1500, DEFAULT_GSO_SEGMENTS).unwrap();
        let (fits, message) = mtu_report(rules, 1380, 60);
        assert!(fits);
        assert!(message.contains("fits"));
    }

    #[test]
    fn report_warns_and_recommends_smaller_tun_mtu() {
        let rules = Underlay::new(1500, DEFAULT_GSO_SEGMENTS).unwrap();
        let (fits, message) = mtu_report(rules, 1420, 60);
        assert!(!fits);
        assert!(message.contains("1512"), "{message}");
        assert!(message.contains("1472"), "{message}");
        assert!(message.contains("1380"), "{message}");
        assert!(message.contains("UMBRAWG_UNDERLAY_MTU"), "{message}");
    }

    #[test]
    fn report_uses_ipv4_payload_budget() {
        let rules = Underlay::new(1500, DEFAULT_GSO_SEGMENTS).unwrap();
        let (fits, message) = mtu_report(rules, 1400, 60);
        assert!(!fits, "{message}");
        assert!(message.contains("1492"), "{message}");
        assert!(message.contains("1380"), "{message}");
    }

    #[test]
    fn report_accounts_for_jumbo_underlay() {
        let rules = Underlay::new(9000, DEFAULT_GSO_SEGMENTS).unwrap();
        let (fits, _) = mtu_report(rules, 8800, 60);
        assert!(fits);
    }

    #[test]
    fn guard_reports_only_on_change() {
        let guard = MtuGuard::new(Underlay::new(1500, DEFAULT_GSO_SEGMENTS).unwrap());
        assert!(guard.record(1420, 60).is_some());
        assert!(guard.record(1420, 60).is_none());
        assert!(guard.record(1420, 28).is_some());
        assert!(guard.record(1420, 60).is_some());
        assert!(guard.record(1400, 60).is_some());
    }
}
