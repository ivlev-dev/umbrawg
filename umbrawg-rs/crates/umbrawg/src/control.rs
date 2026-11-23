//! UAPI-обёртка, проверяющая MTU после применения конфигурации.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use umbrawg_device::{Device, FecMode};
use umbrawg_uapi::{DeviceControl, DeviceSnapshot, SetRequest, UapiError};

use crate::mtu::{
    fec_max_shard_len, fec_mtu_required, fec_tun_mtu, interface_mtu, set_interface_mtu, MtuGuard,
    Underlay, MIN_TUN_MTU,
};

/// Делегирует управление устройством и перепроверяет MTU после `set=1`.
///
/// При включённом FEC обёртка выводит `ExtConfig::max_shard_len` и MTU
/// TUN-интерфейса из MTU подложки, при выключенном — возвращает значения,
/// заданные конфигурацией.
pub struct ConfigControl {
    device: Arc<Device>,
    guard: Arc<MtuGuard>,
    ifname: String,
    shard_cap: u16,
    /// Last observed adaptive-activity state, so the event loop only touches
    /// the interface MTU when the policy actually flips.
    last_mtu_active: AtomicBool,
}

impl ConfigControl {
    /// Создаёт обёртку над `device` с проверкой `guard`.
    ///
    /// `shard_cap` — настроенный пользователем предел `max_shard_len`; от него
    /// считается значение при включённом FEC.
    pub fn new(
        device: Arc<Device>,
        guard: Arc<MtuGuard>,
        ifname: impl Into<String>,
        shard_cap: u16,
    ) -> Self {
        let last_mtu_active =
            fec_mtu_required(device.ext_config().fec, device.fec_adaptive_active());
        Self {
            device,
            guard,
            ifname: ifname.into(),
            shard_cap,
            last_mtu_active: AtomicBool::new(last_mtu_active),
        }
    }

    /// `true` when the FEC profile currently reserves TUN MTU for shards.
    ///
    /// A fixed profile reserves it immediately; adaptive only while parity is
    /// active on at least one running peer.
    fn fec_mtu_active(&self) -> bool {
        fec_mtu_required(
            self.device.ext_config().fec,
            self.device.fec_adaptive_active(),
        )
    }

    fn fec_enabled(&self) -> bool {
        self.device.ext_config().fec != FecMode::Off
    }

    /// Актуальные ограничения подложки: стартовые из env, но с MTU,
    /// изменённым через UAPI.
    fn underlay(&self) -> Underlay {
        let base = self.guard.underlay();
        base.with_mtu(u32::from(self.device.underlay_mtu()))
            .unwrap_or(base)
    }

    /// Пересчитывает `max_shard_len`: при FEC — не больше бюджета подложки,
    /// при выключенном FEC — настроенный предел.
    fn sync_shard_limit(&self) {
        let mut ext = self.device.ext_config();
        let derived = fec_max_shard_len(self.underlay());
        let derived = u16::try_from(derived).unwrap_or(u16::MAX);
        let want = if self.fec_enabled() {
            self.shard_cap.min(derived)
        } else {
            self.shard_cap
        };
        if ext.max_shard_len == want {
            return;
        }
        let previous = ext.max_shard_len;
        ext.max_shard_len = want;
        self.device.set_ext_config(ext);
        if want < previous {
            log::info!(
                "FEC shard limit lowered from {previous} to {want} bytes to fit the {}-byte \
                 underlay MTU (packets stay protected up to {} bytes)",
                self.underlay().mtu(),
                want.saturating_sub(2)
            );
        } else {
            log::info!(
                "FEC shard limit restored from {previous} to {want} bytes (FEC is off or the \
                 underlay allows larger shards)"
            );
        }
    }

    fn desired_tun_mtu(&self) -> u16 {
        fec_tun_mtu(
            self.underlay(),
            self.device.mtu(),
            self.device.obfuscation().s4,
            self.fec_mtu_active(),
        )
    }

    /// Принимает MTU, выставленный вручную (`ip link set mtu`), как новую базу.
    ///
    /// Если фактический MTU отличается от последнего выведенного значения,
    /// значит его изменили в обход демона. База устройства обновляется до
    /// применения запроса, поэтому `SET_DEVICE` учитывает её при следующем
    /// расчёте FEC-MTU. Значения ниже [`MIN_TUN_MTU`] игнорируются: политика
    /// FEC не должна опускать туннель ниже минимального IPv4.
    fn adopt_manual_mtu(&self) {
        let Ok(actual) = interface_mtu(&self.ifname) else {
            return;
        };
        let previous = self.desired_tun_mtu();
        let Some(base) = accepted_base(Some(actual), previous) else {
            return;
        };
        self.device.set_mtu(base);
        log::info!(
            "TUN MTU of {} was changed outside the daemon to {} bytes (expected {}); using it as \
             the base MTU",
            self.ifname,
            base,
            previous
        );
    }

    /// Приводит MTU TUN-интерфейса к значению, выведенному из underlay и FEC.
    fn sync_tun_mtu(&self) -> u16 {
        let want = self.desired_tun_mtu();
        let current = match interface_mtu(&self.ifname) {
            Ok(mtu) => u16::try_from(mtu).ok(),
            Err(error) => {
                log::warn!("cannot read MTU of {}: {error}", self.ifname);
                None
            }
        };
        if current == Some(want) {
            return want;
        }
        match set_interface_mtu(&self.ifname, want) {
            Ok(actual) => {
                let actual = u16::try_from(actual).unwrap_or(want);
                log::info!(
                    "TUN MTU of {} changed from {} to {actual} bytes (underlay MTU {}, FEC {}, \
                     S4 {})",
                    self.ifname,
                    current.map_or_else(|| "?".to_owned(), |mtu| mtu.to_string()),
                    self.guard.underlay().mtu(),
                    if self.fec_mtu_active() { "on" } else { "off" },
                    self.device.obfuscation().s4
                );
                actual
            }
            Err(error) => {
                log::warn!(
                    "cannot set MTU {want} on {}: {error}; the interface keeps {} bytes",
                    self.ifname,
                    current.map_or_else(|| "its current".to_owned(), |mtu| mtu.to_string())
                );
                current.unwrap_or(want)
            }
        }
    }

    /// Applies an adaptive on/off transition to the TUN MTU.
    ///
    /// Called from the RX/worker housekeeping, never from the TX hot path. It
    /// performs no syscall unless [`Device::fec_adaptive_active`] flipped since
    /// the previous call.
    pub(crate) fn sync_adaptive_mtu(&self) -> bool {
        let active = self.fec_mtu_active();
        if self.last_mtu_active.swap(active, Ordering::Relaxed) == active {
            return false;
        }
        let tun_mtu = self.sync_tun_mtu();
        self.check(tun_mtu);
        log::info!(
            "adaptive FEC {}: TUN MTU of {} is {tun_mtu} bytes",
            if active { "enabled" } else { "disabled" },
            self.ifname
        );
        true
    }

    fn check(&self, tun_mtu: u16) {
        let s4 = self.device.obfuscation().s4;
        self.guard.check_with(self.underlay(), tun_mtu, s4);
    }
}

/// Возвращает ручной MTU, если он отличается от последнего выведенного.
///
/// `actual` — фактический MTU интерфейса, `previous_desired` — значение,
/// которое демон хотел видеть при прошлой синхронизации. Равенство означает,
/// что MTU не трогали, и базой остаётся сохранённое значение.
fn accepted_base(actual: Option<u32>, previous_desired: u16) -> Option<u16> {
    let actual = u16::try_from(actual?).ok()?;
    if actual == previous_desired || actual < MIN_TUN_MTU {
        return None;
    }
    Some(actual)
}

impl DeviceControl for ConfigControl {
    fn snapshot(&self) -> DeviceSnapshot {
        self.device.snapshot()
    }

    fn apply(&self, request: SetRequest) -> Result<(), UapiError> {
        self.adopt_manual_mtu();
        self.device.apply(request)?;
        self.sync_shard_limit();
        let tun_mtu = self.sync_tun_mtu();
        self.check(tun_mtu);
        self.last_mtu_active
            .store(self.fec_mtu_active(), Ordering::Relaxed);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use umbrawg_device::{DeviceConfig, ExtConfig, DEFAULT_MAX_SHARD_LEN};

    use crate::mtu::Underlay;

    use super::*;

    fn fec_control(device_underlay: u16, guard_underlay: u32) -> (Arc<Device>, ConfigControl) {
        let ext = ExtConfig {
            fec: FecMode::Fixed { k: 2, m: 1 },
            ..ExtConfig::default()
        };
        let device = Arc::new(
            Device::new(DeviceConfig {
                underlay_mtu: device_underlay,
                ext,
                ..DeviceConfig::default()
            })
            .expect("device"),
        );
        let guard = Arc::new(MtuGuard::new(
            Underlay::new(guard_underlay, 64).expect("underlay"),
        ));
        let control = ConfigControl::new(
            Arc::clone(&device),
            guard,
            "uwg-test0",
            DEFAULT_MAX_SHARD_LEN,
        );
        (device, control)
    }

    #[test]
    fn guard_exposes_the_underlay() {
        let guard = MtuGuard::new(Underlay::new(1500, 64).unwrap());
        assert_eq!(guard.underlay().mtu(), 1500);
    }

    #[test]
    fn tun_mtu_follows_the_device_underlay() {
        let (device, control) = fec_control(1500, 1500);
        assert_eq!(control.desired_tun_mtu(), 1352);

        // A UAPI `underlay-mtu` change must move the derived TUN MTU even
        // though the daemon started with a 1500-byte underlay.
        device.set_underlay_mtu(9000).expect("underlay");
        assert_eq!(control.desired_tun_mtu(), 1420);
        control.sync_shard_limit();
        assert_eq!(device.ext_config().max_shard_len, DEFAULT_MAX_SHARD_LEN);

        device.set_underlay_mtu(1280).expect("underlay");
        assert_eq!(control.desired_tun_mtu(), 1132);
        control.sync_shard_limit();
        assert_eq!(device.ext_config().max_shard_len, 1165);
    }

    #[test]
    fn adaptive_keeps_the_base_mtu_until_parity_is_active() {
        let device = Arc::new(
            Device::new(DeviceConfig {
                underlay_mtu: 1500,
                ext: ExtConfig {
                    fec: FecMode::Adaptive,
                    ..ExtConfig::default()
                },
                ..DeviceConfig::default()
            })
            .expect("device"),
        );
        let guard = Arc::new(MtuGuard::new(Underlay::new(1500, 64).expect("underlay")));
        let control = ConfigControl::new(
            Arc::clone(&device),
            guard,
            "uwg-test0",
            DEFAULT_MAX_SHARD_LEN,
        );
        assert!(
            !device.fec_adaptive_active(),
            "a fresh adaptive device has no measured loss"
        );
        assert_eq!(
            control.desired_tun_mtu(),
            device.mtu(),
            "adaptive must not lower the TUN MTU on a clean channel"
        );
        assert!(!control.sync_adaptive_mtu(), "no transition means no ioctl");

        let fixed = ExtConfig {
            fec: FecMode::Fixed { k: 2, m: 1 },
            ..ExtConfig::default()
        };
        device.set_ext_config(fixed);
        assert_eq!(
            control.desired_tun_mtu(),
            1352,
            "a fixed profile reserves the shard budget immediately"
        );
    }

    #[test]
    fn manual_mtu_becomes_the_base_without_rolling_fec_back() {
        assert_eq!(accepted_base(Some(1300), 1420), Some(1300));
        assert_eq!(accepted_base(Some(1420), 1420), None);
        assert_eq!(accepted_base(None, 1420), None);
        assert_eq!(accepted_base(Some(0), 1420), None);
        assert_eq!(accepted_base(Some(u32::from(MIN_TUN_MTU - 1)), 1420), None);

        // A manual 1400 on a 1500-byte underlay is remembered as the base,
        // while the FEC policy still programs 1352. Turning FEC off restores
        // the manual value instead of the previous 1420.
        let rules = Underlay::new(1500, 64).expect("underlay");
        assert_eq!(accepted_base(Some(1400), 1352), Some(1400));
        assert_eq!(fec_tun_mtu(rules, 1400, 0, true), 1352);
        assert_eq!(fec_tun_mtu(rules, 1400, 0, false), 1400);
    }
}
