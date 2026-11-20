//! UAPI-обёртка, проверяющая MTU после применения конфигурации.

use std::sync::Arc;

use umbrawg_device::{Device, FecMode};
use umbrawg_uapi::{DeviceControl, DeviceSnapshot, SetRequest, UapiError};

use crate::mtu::{fec_max_shard_len, fec_tun_mtu, interface_mtu, set_interface_mtu, MtuGuard};

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
        Self {
            device,
            guard,
            ifname: ifname.into(),
            shard_cap,
        }
    }

    fn fec_enabled(&self) -> bool {
        self.device.ext_config().fec != FecMode::Off
    }

    /// Пересчитывает `max_shard_len`: при FEC — не больше бюджета подложки,
    /// при выключенном FEC — настроенный предел.
    fn sync_shard_limit(&self) {
        let mut ext = self.device.ext_config();
        let derived = fec_max_shard_len(self.guard.underlay());
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
                self.guard.underlay().mtu(),
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
            self.guard.underlay(),
            self.device.mtu(),
            self.device.obfuscation().s4,
            self.fec_enabled(),
        )
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
                    if self.fec_enabled() { "on" } else { "off" },
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

    fn check(&self, tun_mtu: u16) {
        let s4 = self.device.obfuscation().s4;
        self.guard.check(tun_mtu, s4);
    }
}

impl DeviceControl for ConfigControl {
    fn snapshot(&self) -> DeviceSnapshot {
        self.device.snapshot()
    }

    fn apply(&self, request: SetRequest) -> Result<(), UapiError> {
        self.device.apply(request)?;
        self.sync_shard_limit();
        let tun_mtu = self.sync_tun_mtu();
        self.check(tun_mtu);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::mtu::Underlay;

    use super::*;

    #[test]
    fn guard_exposes_the_underlay() {
        let guard = MtuGuard::new(Underlay::new(1500, 64).unwrap());
        assert_eq!(guard.underlay().mtu(), 1500);
    }
}
