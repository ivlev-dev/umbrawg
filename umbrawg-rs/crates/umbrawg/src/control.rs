//! UAPI-обёртка, проверяющая MTU после применения конфигурации.

use std::sync::Arc;

use umbrawg_device::Device;
use umbrawg_uapi::{DeviceControl, DeviceSnapshot, SetRequest, UapiError};

use crate::mtu::MtuGuard;

/// Делегирует управление устройству и перепроверяет MTU после `set=1`.
pub struct ConfigControl {
    device: Arc<Device>,
    guard: Arc<MtuGuard>,
}

impl ConfigControl {
    /// Создаёт обёртку над `device` с проверкой `guard`.
    pub fn new(device: Arc<Device>, guard: Arc<MtuGuard>) -> Self {
        Self { device, guard }
    }

    fn check(&self) {
        let mtu = self.device.mtu();
        let s4 = self.device.obfuscation().s4;
        self.guard.check(mtu, s4);
    }
}

impl DeviceControl for ConfigControl {
    fn snapshot(&self) -> DeviceSnapshot {
        self.device.snapshot()
    }

    fn apply(&self, request: SetRequest) -> Result<(), UapiError> {
        self.device.apply(request)?;
        self.check();
        Ok(())
    }
}
