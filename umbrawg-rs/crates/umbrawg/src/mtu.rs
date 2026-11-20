//! Ограничения исходящих датаграмм по MTU подложки (underlay).
//!
//! GSO-сегмент становится отдельным IP-пакетом, поэтому его размер не должен
//! превышать `underlay_mtu - 28`: иначе ядро не сегментирует супер-датаграмму,
//! а отправит кадр крупнее MTU, который выбросит первый же коммутатор.

use core::fmt;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Mutex;

use umbrawg_device::{DEFAULT_MAX_SHARD_LEN, MIN_MAX_SHARD_LEN};
use umbrawg_fec::MAX_SHARD_PADDING;
use umbrawg_proto::control::{EXTENSION_HEADER_LEN, FEC_HEADER_LEN};
use umbrawg_proto::messages::MESSAGE_PADDING_MULTIPLE;
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

/// Минимальный TUN MTU, который имеет смысл выставлять (минимум IPv4).
pub const MIN_TUN_MTU: u16 = 576;

/// Худший случай накладных расходов IP+UDP в подложке: IPv6 (40) + UDP (8).
pub const UNDERLAY_IP_UDP_OVERHEAD: usize = 48;

/// Двухбайтовый little-endian префикс длины пакета внутри FEC-шарда.
///
/// Вставляется `umbrawg_fec::FecEncoder` и входит в `shard_len`.
pub const FEC_LENGTH_PREFIX_LEN: usize = 2;

/// Накладные расходы одного FEC-шарда сверх TUN-пакета, `WIRE_OVERHEAD` и `S4`.
///
/// Складывается из:
/// * [`FEC_LENGTH_PREFIX_LEN`] — префикс длины пакета внутри шарда;
/// * [`EXTENSION_HEADER_LEN`] — префикс extension-кадра;
/// * [`FEC_HEADER_LEN`] — заголовок FEC-шарда;
/// * [`MAX_SHARD_PADDING`] — максимальный случайный паддинг шарда;
/// * `MESSAGE_PADDING_MULTIPLE - 1` — максимальный случайный паддинг
///   control-сообщения (`PaddingMode::Control`).
///
/// `WIRE_OVERHEAD` (заголовок transport-сообщения и AEAD-тег) учитывается
/// отдельно. Настройки `random_trailers` и `content_padding_addition` к
/// control-кадрам не применяются: их паддинг всегда ограничен 15 байтами.
pub const FEC_WIRE_OVERHEAD: usize = FEC_LENGTH_PREFIX_LEN
    + EXTENSION_HEADER_LEN
    + FEC_HEADER_LEN
    + MAX_SHARD_PADDING
    + (MESSAGE_PADDING_MULTIPLE - 1);

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

/// MTU TUN-интерфейса при включённом FEC.
///
/// Полный бюджет underlay-датаграммы: `mtu - 48` (IPv6+UDP). Из него вычитаются
/// заголовок transport-сообщения с AEAD-тегом ([`WIRE_OVERHEAD`]), префикс
/// обфускации `S4` и накладные FEC-шарда ([`FEC_WIRE_OVERHEAD`]). Результат
/// ограничен снизу [`MIN_TUN_MTU`] и сверху `base_mtu` — MTU устройства без FEC.
///
/// При выключенном FEC возвращается `base_mtu`, поэтому поведение демона не
/// меняется.
pub fn fec_tun_mtu(underlay: Underlay, base_mtu: u16, s4: u16, fec: bool) -> u16 {
    if !fec {
        return base_mtu;
    }
    let overhead = UNDERLAY_IP_UDP_OVERHEAD + WIRE_OVERHEAD + usize::from(s4) + FEC_WIRE_OVERHEAD;
    let budget = (underlay.mtu() as usize).saturating_sub(overhead);
    let floor = usize::from(MIN_TUN_MTU.min(base_mtu));
    let value = budget.clamp(floor, usize::from(base_mtu));
    u16::try_from(value).unwrap_or(base_mtu)
}

/// Максимальный `ExtConfig::max_shard_len` для датаграмм, влезающих в underlay.
///
/// `max_shard_len` включает двухбайтовый префикс длины, поэтому полезный
/// размер пакета в шарде на два байта меньше. Бюджет:
/// `mtu - 48 (IPv6+UDP) - WIRE_OVERHEAD - 20 (extension + FEC) - 15 (padding)`,
/// ограниченный `64..=1900`. Случайный паддинг шарда уже входит в предел через
/// сам `max_shard_len`, отдельно его вычитать не нужно.
pub fn fec_max_shard_len(underlay: Underlay) -> usize {
    let budget = (underlay.mtu() as usize)
        .saturating_sub(UNDERLAY_IP_UDP_OVERHEAD + WIRE_OVERHEAD)
        .saturating_sub(EXTENSION_HEADER_LEN + FEC_HEADER_LEN + (MESSAGE_PADDING_MULTIPLE - 1));
    budget.clamp(
        usize::from(MIN_MAX_SHARD_LEN),
        usize::from(DEFAULT_MAX_SHARD_LEN),
    )
}

const IFREQ_DATA_LEN: usize = if cfg!(target_pointer_width = "64") {
    24
} else {
    16
};

const SIOCGIFMTU: libc::Ioctl = 0x8921;
const SIOCSIFMTU: libc::Ioctl = 0x8922;

#[repr(C, align(8))]
struct IfReq {
    name: [libc::c_char; libc::IFNAMSIZ],
    data: [u8; IFREQ_DATA_LEN],
}

impl IfReq {
    fn new(name: &str) -> io::Result<Self> {
        if name.len() >= libc::IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface name is longer than 15 bytes",
            ));
        }
        if name.as_bytes().contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface name contains a NUL byte",
            ));
        }
        let mut ifreq = Self {
            name: [0; libc::IFNAMSIZ],
            data: [0; IFREQ_DATA_LEN],
        };
        for (dst, src) in ifreq.name.iter_mut().zip(name.bytes()) {
            *dst = src as libc::c_char;
        }
        Ok(ifreq)
    }

    fn mtu(&self) -> u32 {
        u32::from_ne_bytes([self.data[0], self.data[1], self.data[2], self.data[3]])
    }

    fn set_mtu(&mut self, mtu: u16) {
        self.data[..4].copy_from_slice(&u32::from(mtu).to_ne_bytes());
    }
}

fn control_socket() -> io::Result<OwnedFd> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Читает MTU интерфейса через `SIOCGIFMTU`.
pub fn interface_mtu(name: &str) -> io::Result<u32> {
    let mut ifreq = IfReq::new(name)?;
    let socket = control_socket()?;
    let result = unsafe { libc::ioctl(socket.as_raw_fd(), SIOCGIFMTU, &mut ifreq) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ifreq.mtu())
}

/// Выставляет MTU интерфейса через `SIOCSIFMTU` и возвращает фактическое значение.
pub fn set_interface_mtu(name: &str, mtu: u16) -> io::Result<u32> {
    let mut ifreq = IfReq::new(name)?;
    ifreq.set_mtu(mtu);
    let socket = control_socket()?;
    let result = unsafe { libc::ioctl(socket.as_raw_fd(), SIOCSIFMTU, &ifreq) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    interface_mtu(name)
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

    /// Ограничения подложки, по которым считается TUN MTU.
    pub fn underlay(&self) -> Underlay {
        self.underlay
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

    use rand_core::RngCore;
    use umbrawg_fec::{FecConfig, FecEncoder, FecError};

    fn underlay(mtu: u32) -> Underlay {
        Underlay::new(mtu, DEFAULT_GSO_SEGMENTS).expect("underlay")
    }

    struct MaxRng;

    impl RngCore for MaxRng {
        fn next_u32(&mut self) -> u32 {
            u32::MAX
        }

        fn next_u64(&mut self) -> u64 {
            u64::MAX
        }

        fn fill_bytes(&mut self, dst: &mut [u8]) {
            dst.fill(0xff);
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dst);
            Ok(())
        }
    }

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

    #[test]
    fn fec_overhead_matches_wire_layout() {
        assert_eq!(WIRE_OVERHEAD, 32);
        assert_eq!(EXTENSION_HEADER_LEN, 8);
        assert_eq!(FEC_HEADER_LEN, 12);
        assert_eq!(MESSAGE_PADDING_MULTIPLE, 16);
        assert_eq!(MAX_SHARD_PADDING, 31);
        assert_eq!(FEC_LENGTH_PREFIX_LEN, 2);
        assert_eq!(FEC_WIRE_OVERHEAD, 2 + 8 + 12 + 31 + 15);
        assert_eq!(FEC_WIRE_OVERHEAD, 68);
    }

    #[test]
    fn ethernet_fec_budget_covers_the_derived_tun_mtu() {
        let rules = underlay(1500);
        let shard = fec_max_shard_len(rules);
        let tun = fec_tun_mtu(rules, 1420, 0, true);
        assert_eq!(shard, 1385);
        assert_eq!(tun, 1352);
        assert!(shard >= usize::from(tun) + FEC_LENGTH_PREFIX_LEN);
        let datagram = WIRE_OVERHEAD
            + EXTENSION_HEADER_LEN
            + FEC_HEADER_LEN
            + shard
            + (MESSAGE_PADDING_MULTIPLE - 1);
        assert_eq!(datagram, 1500 - UNDERLAY_IP_UDP_OVERHEAD);
    }

    #[test]
    fn ethernet_fec_budget_cannot_cover_a_full_1420_packet() {
        let rules = underlay(1500);
        let shard = fec_max_shard_len(rules);
        assert!(shard < 1420 + FEC_LENGTH_PREFIX_LEN);
        let mut encoder = FecEncoder::new(FecConfig::new(2, 1).unwrap(), shard);
        assert!(matches!(
            encoder.push(&[0u8; 1420]),
            Err(FecError::PacketTooLarge { .. })
        ));
    }

    #[test]
    fn fec_tun_mtu_accounts_for_s4() {
        let rules = underlay(1500);
        assert_eq!(fec_tun_mtu(rules, 1420, 60, true), 1292);
        let shard = fec_max_shard_len(rules);
        let tun = fec_tun_mtu(rules, 1420, 60, true);
        let worst_shard = (usize::from(tun) + FEC_LENGTH_PREFIX_LEN + MAX_SHARD_PADDING).min(shard);
        let datagram =
            WIRE_OVERHEAD + 60 + EXTENSION_HEADER_LEN + FEC_HEADER_LEN + worst_shard + 15;
        assert!(datagram <= 1500 - UNDERLAY_IP_UDP_OVERHEAD, "{datagram}");
    }

    #[test]
    fn jumbo_underlay_caps_the_shard_limit() {
        let rules = underlay(9000);
        assert_eq!(fec_max_shard_len(rules), usize::from(DEFAULT_MAX_SHARD_LEN));
        assert_eq!(fec_tun_mtu(rules, 1420, 0, true), 1420);
        assert!(fec_max_shard_len(rules) >= 1420 + FEC_LENGTH_PREFIX_LEN);
    }

    #[test]
    fn small_underlay_respects_the_tun_floor() {
        let rules = underlay(1280);
        let tun = fec_tun_mtu(rules, 1420, 0, true);
        let shard = fec_max_shard_len(rules);
        assert_eq!(tun, 1132);
        assert_eq!(shard, 1165);
        assert!(tun >= MIN_TUN_MTU);
        assert!(shard >= usize::from(tun) + FEC_LENGTH_PREFIX_LEN);
        assert!(usize::from(tun) <= 1280 - UNDERLAY_IP_UDP_OVERHEAD - WIRE_OVERHEAD);
    }

    #[test]
    fn fec_off_keeps_the_base_mtu() {
        let rules = underlay(1500);
        assert_eq!(fec_tun_mtu(rules, 1420, 0, false), 1420);
        assert_eq!(fec_tun_mtu(rules, 1420, 60, false), 1420);
        assert_eq!(fec_tun_mtu(underlay(9000), 1420, 0, false), 1420);
    }

    #[test]
    fn tiny_underlay_falls_back_to_the_tun_floor() {
        let rules = underlay(MIN_UNDERLAY_MTU);
        assert_eq!(fec_tun_mtu(rules, 1420, 0, true), MIN_TUN_MTU);
        assert_eq!(fec_max_shard_len(rules), 461);
    }

    #[test]
    fn encoder_packet_at_the_derived_mtu_fits_the_underlay() {
        let rules = underlay(1500);
        let shard = fec_max_shard_len(rules);
        let tun = usize::from(fec_tun_mtu(rules, 1420, 0, true));
        let mut encoder = FecEncoder::new(FecConfig::new(2, 1).unwrap(), shard);
        let packet = vec![0u8; tun];
        assert_eq!(encoder.push_with_rng(&packet, &mut MaxRng).unwrap(), None);
        let block = encoder
            .push_with_rng(&packet, &mut MaxRng)
            .unwrap()
            .expect("block");
        let shard_len = usize::from(block.shard_len);
        assert!(shard_len <= shard);
        assert_eq!(shard_len, tun + FEC_LENGTH_PREFIX_LEN + MAX_SHARD_PADDING);
        let datagram = WIRE_OVERHEAD
            + EXTENSION_HEADER_LEN
            + FEC_HEADER_LEN
            + shard_len
            + (MESSAGE_PADDING_MULTIPLE - 1);
        assert!(
            datagram <= 1500 - UNDERLAY_IP_UDP_OVERHEAD,
            "datagram {datagram} exceeds the underlay budget"
        );
    }

    #[test]
    fn interface_mtu_ioctl_reports_missing_interfaces() {
        let error = interface_mtu("uwg-missing0").expect_err("interface must not exist");
        assert_eq!(error.raw_os_error(), Some(libc::ENODEV));
        assert!(set_interface_mtu("uwg-missing0", 1420).is_err());
    }
}
