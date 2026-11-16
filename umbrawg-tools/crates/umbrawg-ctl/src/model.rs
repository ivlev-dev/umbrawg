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
    pub advanced_security: Option<bool>,
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
            advanced_security: None,
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

/// How a configuration file is applied to an interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigApplication {
    /// `uwg setconf`: the file replaces the whole peer list.
    Replace,
    /// `uwg addconf`: the file appends peers to the running configuration.
    Append,
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

    /// Applies a configuration file the way `uwg setconf`/`uwg addconf` do.
    ///
    /// Both commands replace the allowed IP list of every peer they mention,
    /// even when the `[Peer]` section has no `AllowedIPs` key, which mirrors
    /// the legacy `awg` parser. `setconf` additionally resets the private key
    /// and the fwmark when the file does not set them; `addconf` leaves the
    /// running values alone.
    pub fn from_config_file(
        name: impl Into<String>,
        config: &Config,
        application: ConfigApplication,
    ) -> Self {
        let mut set = Self::from_config(name, config);
        set.replace_peers = application == ConfigApplication::Replace;
        if application == ConfigApplication::Append {
            set.device.private_key = config.device.private_key.clone();
            set.device.fwmark = config.device.fwmark;
        }
        for peer in &mut set.peers {
            if peer.remove {
                continue;
            }
            peer.allowed_ips = Some(peer.allowed_ips.clone().unwrap_or_default());
        }
        set
    }

    /// Plans `uwg syncconf`: peers missing from the file are removed, peers
    /// shared with the running configuration stay connected.
    ///
    /// This follows the legacy `awg syncconf`, which turns off
    /// `UWGDEVICE_F_REPLACE_PEERS` and sends explicit peer removals instead.
    pub fn synced_from(name: impl Into<String>, config: &Config, runtime: &Device) -> Self {
        let mut set = Self::from_config_file(name, config, ConfigApplication::Replace);
        if config.peers.is_empty() || runtime.peers.is_empty() {
            return set;
        }
        set.replace_peers = false;
        let configured: Vec<&Key> = config.peers.iter().map(|peer| &peer.public_key).collect();
        for peer in &runtime.peers {
            if configured.contains(&&peer.public_key) {
                continue;
            }
            set.peers.push(PeerConfig {
                public_key: peer.public_key.clone(),
                preshared_key: None,
                allowed_ips: None,
                endpoint: None,
                persistent_keepalive: None,
                remove: true,
            });
        }
        set
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
            advanced_security: Some(true),
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

    fn config_with_peers(keys: &[[u8; 32]]) -> Config {
        let mut config = Config::default();
        for key in keys {
            config.peers.push(PeerConfig {
                public_key: Key::from_bytes(*key),
                preshared_key: None,
                allowed_ips: None,
                endpoint: None,
                persistent_keepalive: None,
                remove: false,
            });
        }
        config
    }

    #[test]
    fn addconf_appends_and_replaces_allowed_ips() {
        let config = config_with_peers(&[[1u8; 32]]);
        let set = SetDevice::from_config_file("uwg0", &config, ConfigApplication::Append);
        assert!(!set.replace_peers);
        assert_eq!(set.peers.len(), 1);
        assert_eq!(set.peers[0].allowed_ips, Some(Vec::new()));
        assert!(!set.peers[0].remove);
    }

    #[test]
    fn setconf_file_replaces_peers_and_allowed_ips() {
        let mut config = config_with_peers(&[[1u8; 32]]);
        config.peers[0].allowed_ips = Some(vec!["10.0.0.0/8".parse().expect("valid")]);
        let set = SetDevice::from_config_file("uwg0", &config, ConfigApplication::Replace);
        assert!(set.replace_peers);
        assert_eq!(
            set.peers[0].allowed_ips,
            Some(vec!["10.0.0.0/8".parse().expect("valid")])
        );
    }

    #[test]
    fn addconf_keeps_removed_peers_untouched() {
        let mut config = config_with_peers(&[[1u8; 32]]);
        config.peers[0].remove = true;
        let set = SetDevice::from_config_file("uwg0", &config, ConfigApplication::Append);
        assert!(set.peers[0].allowed_ips.is_none());
        assert!(set.peers[0].remove);
    }

    #[test]
    fn addconf_does_not_reset_unset_device_keys() {
        let config = config_with_peers(&[[1u8; 32]]);
        let set = SetDevice::from_config_file("uwg0", &config, ConfigApplication::Append);
        assert!(set.device.private_key.is_none());
        assert!(set.device.fwmark.is_none());
        assert!(set.device.listen_port.is_none());
        let set = SetDevice::from_config_file("uwg0", &config, ConfigApplication::Replace);
        assert_eq!(set.device.private_key.as_ref(), Some(&Key::zero()));
        assert_eq!(set.device.fwmark, Some(0));
    }

    #[test]
    fn addconf_keeps_device_keys_from_the_file() {
        let mut config = config_with_peers(&[[1u8; 32]]);
        config.device.private_key = Some(Key::from_bytes([3u8; 32]));
        config.device.fwmark = Some(0x42);
        config.device.listen_port = Some(51820);
        let set = SetDevice::from_config_file("uwg0", &config, ConfigApplication::Append);
        assert_eq!(set.device.private_key, Some(Key::from_bytes([3u8; 32])));
        assert_eq!(set.device.fwmark, Some(0x42));
        assert_eq!(set.device.listen_port, Some(51820));
    }

    #[test]
    fn syncconf_without_runtime_peers_replaces_all() {
        let config = config_with_peers(&[[1u8; 32]]);
        let runtime = Device::new("uwg0");
        let set = SetDevice::synced_from("uwg0", &config, &runtime);
        assert!(set.replace_peers);
        assert_eq!(set.peers.len(), 1);
    }

    #[test]
    fn syncconf_removes_peers_missing_from_the_file() {
        let config = config_with_peers(&[[1u8; 32]]);
        let mut runtime = Device::new("uwg0");
        runtime.peers.push(Peer {
            public_key: Key::from_bytes([1u8; 32]),
            ..Peer::default()
        });
        runtime.peers.push(Peer {
            public_key: Key::from_bytes([9u8; 32]),
            ..Peer::default()
        });
        let set = SetDevice::synced_from("uwg0", &config, &runtime);
        assert!(!set.replace_peers);
        assert_eq!(set.peers.len(), 2);
        assert!(!set.peers[0].remove);
        assert_eq!(set.peers[0].allowed_ips, Some(Vec::new()));
        assert_eq!(set.peers[1].public_key, Key::from_bytes([9u8; 32]));
        assert!(set.peers[1].remove);
    }

    #[test]
    fn syncconf_with_empty_file_removes_every_peer() {
        let config = Config::default();
        let mut runtime = Device::new("uwg0");
        runtime.peers.push(Peer {
            public_key: Key::from_bytes([9u8; 32]),
            ..Peer::default()
        });
        let set = SetDevice::synced_from("uwg0", &config, &runtime);
        assert!(set.replace_peers);
        assert!(set.peers.is_empty());
    }
}
