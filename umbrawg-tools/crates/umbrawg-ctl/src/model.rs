use std::net::SocketAddr;

use umbrawg_config::{
    AllowedIp, Config, DeviceConfig, Key, ObfuscationConfig, PeerConfig, U16Range,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TimeSpec {
    pub seconds: i64,
    pub nanoseconds: i64,
}

impl TimeSpec {
    pub const fn new(seconds: i64, nanoseconds: i64) -> Self {
        Self {
            seconds,
            nanoseconds,
        }
    }

    pub const fn is_zero(self) -> bool {
        self.seconds == 0 && self.nanoseconds == 0
    }

    pub fn as_seconds(self) -> f64 {
        self.seconds as f64 + self.nanoseconds as f64 / 1_000_000_000.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub public_key: Key,
    pub preshared_key: Option<Key>,
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive: U16Range,
    pub last_handshake_time: TimeSpec,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub allowed_ips: Vec<AllowedIp>,
}

impl Default for Peer {
    fn default() -> Self {
        Self {
            public_key: Key::zero(),
            preshared_key: None,
            endpoint: None,
            persistent_keepalive: U16Range::default(),
            last_handshake_time: TimeSpec::default(),
            rx_bytes: 0,
            tx_bytes: 0,
            allowed_ips: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    pub name: String,
    pub ifindex: Option<u32>,
    pub private_key: Option<Key>,
    pub public_key: Option<Key>,
    pub listen_port: u16,
    pub fwmark: u32,
    pub obfuscation: ObfuscationConfig,
    pub peers: Vec<Peer>,
}

impl Device {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ifindex: None,
            private_key: None,
            public_key: None,
            listen_port: 0,
            fwmark: 0,
            obfuscation: ObfuscationConfig::default(),
            peers: Vec::new(),
        }
    }

    pub fn to_config(&self) -> Config {
        let peers = self
            .peers
            .iter()
            .map(|peer| PeerConfig {
                public_key: peer.public_key.clone(),
                preshared_key: peer.preshared_key.clone().filter(|key| !key.is_zero()),
                allowed_ips: if peer.allowed_ips.is_empty() {
                    None
                } else {
                    Some(peer.allowed_ips.clone())
                },
                endpoint: peer.endpoint,
                persistent_keepalive: (!peer.persistent_keepalive.is_zero())
                    .then_some(peer.persistent_keepalive),
                remove: false,
            })
            .collect();
        Config {
            device: DeviceConfig {
                private_key: self.private_key.clone().filter(|key| !key.is_zero()),
                listen_port: (self.listen_port != 0).then_some(self.listen_port),
                fwmark: (self.fwmark != 0).then_some(self.fwmark),
                obfuscation: self.obfuscation.clone(),
                quick: Default::default(),
            },
            peers,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetDevice {
    pub name: String,
    pub replace_peers: bool,
    pub device: DeviceConfig,
    pub peers: Vec<PeerConfig>,
}

impl SetDevice {
    pub fn from_config(name: impl Into<String>, config: &Config) -> Self {
        let mut device = config.device.clone();
        device.private_key = Some(device.private_key.take().unwrap_or_else(Key::zero));
        device.fwmark = Some(device.fwmark.unwrap_or(0));
        Self {
            name: name.into(),
            replace_peers: true,
            device,
            peers: config.peers.clone(),
        }
    }

    pub fn for_interface(name: impl Into<String>, device: DeviceConfig) -> Self {
        Self {
            name: name.into(),
            replace_peers: false,
            device,
            peers: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> Peer {
        Peer {
            public_key: Key::from_bytes([1u8; 32]),
            preshared_key: Some(Key::from_bytes([2u8; 32])),
            endpoint: Some("192.0.2.1:51820".parse().expect("valid")),
            persistent_keepalive: U16Range::single(25),
            last_handshake_time: TimeSpec::new(100, 5),
            rx_bytes: 10,
            tx_bytes: 20,
            allowed_ips: vec!["10.0.0.0/8".parse().expect("valid")],
        }
    }

    #[test]
    fn setconf_resets_private_key_and_fwmark() {
        let set = SetDevice::from_config("uwg0", &Config::default());
        assert!(set.replace_peers);
        assert_eq!(set.device.private_key.as_ref(), Some(&Key::zero()));
        assert_eq!(set.device.fwmark, Some(0));
        assert!(set.peers.is_empty());
    }

    #[test]
    fn setconf_keeps_explicit_values() {
        let mut config = Config::default();
        config.device.private_key = Some(Key::from_bytes([3u8; 32]));
        config.device.fwmark = Some(0x42);
        let set = SetDevice::from_config("uwg0", &config);
        assert_eq!(set.device.private_key, Some(Key::from_bytes([3u8; 32])));
        assert_eq!(set.device.fwmark, Some(0x42));
    }

    #[test]
    fn converts_runtime_device_to_config() {
        let mut device = Device::new("uwg0");
        device.listen_port = 51820;
        device.fwmark = 0x42;
        device.private_key = Some(Key::from_bytes([4u8; 32]));
        device.peers.push(peer());
        let config = device.to_config();
        assert_eq!(config.device.listen_port, Some(51820));
        assert_eq!(config.device.fwmark, Some(0x42));
        assert_eq!(config.device.private_key, Some(Key::from_bytes([4u8; 32])));
        assert_eq!(config.peers.len(), 1);
        assert_eq!(config.peers[0].allowed_ips.as_ref().map(Vec::len), Some(1));
        assert_eq!(
            config.peers[0].persistent_keepalive,
            Some(U16Range::single(25))
        );
    }

    #[test]
    fn drops_unset_runtime_fields() {
        let device = Device::new("uwg0");
        let config = device.to_config();
        assert!(config.device.private_key.is_none());
        assert!(config.device.listen_port.is_none());
        assert!(config.device.fwmark.is_none());
    }

    #[test]
    fn omits_empty_allowed_ips() {
        let mut device = Device::new("uwg0");
        device.peers.push(Peer {
            allowed_ips: Vec::new(),
            persistent_keepalive: U16Range::default(),
            ..peer()
        });
        let config = device.to_config();
        assert!(config.peers[0].allowed_ips.is_none());
        assert!(config.peers[0].persistent_keepalive.is_none());
    }
}
