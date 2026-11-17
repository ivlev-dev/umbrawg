// SPDX-License-Identifier: MIT

//! Builder for the peer entries of `UWGDEVICE_A_PEERS`.

use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6,
};

use crate::{
    allowedip::UmbrawgAllowedIp,
    constants::{
        UWGPEER_F_HAS_ADVANCED_SECURITY, UWGPEER_F_REMOVE_ME,
        UWGPEER_F_REPLACE_ALLOWEDIPS, UWGPEER_F_UPDATE_ONLY, UWG_KEY_LEN,
    },
    error::UmbrawgConfigError,
    peer::{UmbrawgPeer, UmbrawgPeerAttribute},
    range::u16_range_pack,
};

/// Flags a caller may set through [`UmbrawgPeerConfig`].
///
/// [`UWGPEER_F_HAS_ADVANCED_SECURITY`] is read-only: the kernel reports it
/// and the builder expresses the same setting through the
/// [`UmbrawgPeerAttribute::AdvancedSecurity`] presence flag.
const PEER_FLAGS_ALLOWED: u32 =
    UWGPEER_F_REMOVE_ME | UWGPEER_F_REPLACE_ALLOWEDIPS | UWGPEER_F_UPDATE_ONLY;

/// Persistent keepalive wire format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Keepalive {
    /// `u16` interval, the format of kernel modules up to genl version 2.
    Legacy(u16),
    /// `u32` packing a `u16` range (`lo | hi << 16`), the format of the
    /// UmbraWG 3.x kernel module.
    Range(u32),
}

/// Builder for one peer of the `UWGDEVICE_A_PEERS` list.
///
/// The public key is mandatory and is therefore a constructor argument.
/// Everything else is optional and only emitted when configured. The
/// resulting [`UmbrawgPeer`] never contains the
/// [`UmbrawgPeerAttribute::AdvancedSecurity`] attribute with a `false`
/// payload: an absent flag means `false` on the wire.
///
/// # Example
///
/// ```
/// use std::net::Ipv6Addr;
///
/// use netlink_packet_umbrawg::UmbrawgPeerConfig;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let peer = UmbrawgPeerConfig::try_new(&[9u8; 32])?
///     .preshared_key([3u8; 32])
///     .endpoint_v6(Ipv6Addr::LOCALHOST, 51820)
///     .persistent_keepalive(25)
///     .allowed_ip("0.0.0.0".parse()?, 0)?
///     .allowed_ip("::".parse()?, 0)?
///     .advanced_security(true)
///     .build()?;
///
/// assert!(!peer.0.is_empty());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UmbrawgPeerConfig {
    public_key: [u8; UWG_KEY_LEN],
    preshared_key: Option<[u8; UWG_KEY_LEN]>,
    endpoint: Option<SocketAddr>,
    keepalive: Option<Keepalive>,
    allowed_ips: Vec<UmbrawgAllowedIp>,
    advanced_security: bool,
    flags: u32,
    protocol_version: Option<u32>,
}

impl UmbrawgPeerConfig {
    /// Creates a peer configuration with the given public key.
    pub fn new(public_key: [u8; UWG_KEY_LEN]) -> Self {
        Self {
            public_key,
            preshared_key: None,
            endpoint: None,
            keepalive: None,
            allowed_ips: Vec::new(),
            advanced_security: false,
            flags: 0,
            protocol_version: None,
        }
    }

    /// Creates a peer configuration from a public key slice.
    ///
    /// # Errors
    ///
    /// Returns [`UmbrawgConfigError::InvalidKeyLength`] unless the slice is
    /// exactly 32 bytes long.
    pub fn try_new(public_key: &[u8]) -> Result<Self, UmbrawgConfigError> {
        Ok(Self::new(key(public_key, "peer public key")?))
    }

    /// Returns the configured public key.
    pub fn public_key(&self) -> &[u8; UWG_KEY_LEN] {
        &self.public_key
    }

    /// Sets the preshared key.
    pub fn preshared_key(mut self, key: [u8; UWG_KEY_LEN]) -> Self {
        self.preshared_key = Some(key);
        self
    }

    /// Sets the preshared key from a slice.
    ///
    /// # Errors
    ///
    /// Returns [`UmbrawgConfigError::InvalidKeyLength`] unless the slice is
    /// exactly 32 bytes long.
    pub fn try_preshared_key(
        mut self,
        value: &[u8],
    ) -> Result<Self, UmbrawgConfigError> {
        self.preshared_key = Some(key(value, "preshared key")?);
        Ok(self)
    }

    /// Removes the preshared key by sending an all-zero key.
    pub fn clear_preshared_key(mut self) -> Self {
        self.preshared_key = Some([0u8; UWG_KEY_LEN]);
        self
    }

    /// Sets the endpoint address.
    ///
    /// Both IPv4 and IPv6 socket addresses are accepted; the family is
    /// encoded in the wire format.
    pub fn endpoint(mut self, endpoint: SocketAddr) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    /// Sets an IPv4 endpoint.
    pub fn endpoint_v4(mut self, addr: Ipv4Addr, port: u16) -> Self {
        self.endpoint = Some(SocketAddr::V4(SocketAddrV4::new(addr, port)));
        self
    }

    /// Sets an IPv6 endpoint with an unspecified traffic class and scope.
    ///
    /// Use [`endpoint_v6_scoped`](Self::endpoint_v6_scoped) for link-local
    /// addresses that need a scope id.
    pub fn endpoint_v6(mut self, addr: Ipv6Addr, port: u16) -> Self {
        self.endpoint =
            Some(SocketAddr::V6(SocketAddrV6::new(addr, port, 0, 0)));
        self
    }

    /// Sets an IPv6 endpoint with an explicit scope id, as required for
    /// link-local addresses.
    pub fn endpoint_v6_scoped(
        mut self,
        addr: Ipv6Addr,
        port: u16,
        scope_id: u32,
    ) -> Self {
        self.endpoint =
            Some(SocketAddr::V6(SocketAddrV6::new(addr, port, 0, scope_id)));
        self
    }

    /// Sets a persistent keepalive interval in seconds; `0` disables it.
    ///
    /// The interval is emitted as the `u32` packed range of the UmbraWG 3.x
    /// kernel module. Use
    /// [`persistent_keepalive_legacy`](Self::persistent_keepalive_legacy)
    /// for genl family version 2 modules.
    pub fn persistent_keepalive(mut self, seconds: u16) -> Self {
        self.keepalive =
            Some(Keepalive::Range(u16_range_pack(seconds, seconds)));
        self
    }

    /// Sets a persistent keepalive interval range in seconds.
    ///
    /// # Errors
    ///
    /// [`build`](Self::build) returns [`UmbrawgConfigError::InvalidRange`]
    /// when `lo > hi`.
    pub fn persistent_keepalive_range(mut self, lo: u16, hi: u16) -> Self {
        self.keepalive = Some(Keepalive::Range(u16_range_pack(lo, hi)));
        self
    }

    /// Sets a persistent keepalive interval in the legacy `u16` format.
    pub fn persistent_keepalive_legacy(mut self, seconds: u16) -> Self {
        self.keepalive = Some(Keepalive::Legacy(seconds));
        self
    }

    /// Adds an allowed IP.
    ///
    /// # Errors
    ///
    /// Returns [`UmbrawgConfigError::InvalidCidr`] when the prefix length
    /// exceeds 32 for IPv4 or 128 for IPv6.
    pub fn allowed_ip(
        mut self,
        addr: IpAddr,
        cidr: u8,
    ) -> Result<Self, UmbrawgConfigError> {
        self.allowed_ips.push(UmbrawgAllowedIp::new(addr, cidr)?);
        Ok(self)
    }

    /// Adds an allowed IP from an `"addr"` or `"addr/prefix"` spec.
    ///
    /// # Errors
    ///
    /// Returns [`UmbrawgConfigError::InvalidAllowedIpSpec`] for malformed
    /// input and [`UmbrawgConfigError::InvalidCidr`] for an out-of-range
    /// prefix length.
    pub fn allowed_ip_spec(
        mut self,
        spec: &str,
    ) -> Result<Self, UmbrawgConfigError> {
        self.allowed_ips.push(UmbrawgAllowedIp::from_spec(spec)?);
        Ok(self)
    }

    /// Adds an allowed IP that removes the route instead of adding it.
    ///
    /// # Errors
    ///
    /// Returns [`UmbrawgConfigError::InvalidCidr`] when the prefix length
    /// exceeds 32 for IPv4 or 128 for IPv6.
    pub fn remove_allowed_ip(
        mut self,
        addr: IpAddr,
        cidr: u8,
    ) -> Result<Self, UmbrawgConfigError> {
        self.allowed_ips.push(UmbrawgAllowedIp::remove(addr, cidr)?);
        Ok(self)
    }

    /// Appends already built allowed IP entries.
    pub fn allowed_ips(
        mut self,
        allowed_ips: impl IntoIterator<Item = UmbrawgAllowedIp>,
    ) -> Self {
        self.allowed_ips.extend(allowed_ips);
        self
    }

    /// Requests removal of all current allowed IPs of the peer before the
    /// configured ones are added.
    pub fn replace_allowed_ips(mut self) -> Self {
        self.flags |= UWGPEER_F_REPLACE_ALLOWEDIPS;
        self
    }

    /// Enables or disables UmbraWG advanced security for the peer.
    pub fn advanced_security(mut self, enabled: bool) -> Self {
        self.advanced_security = enabled;
        self
    }

    /// Removes the peer instead of adding or updating it.
    pub fn remove(mut self) -> Self {
        self.flags |= UWGPEER_F_REMOVE_ME;
        self
    }

    /// Only updates the peer when it already exists.
    pub fn update_only(mut self) -> Self {
        self.flags |= UWGPEER_F_UPDATE_ONLY;
        self
    }

    /// Replaces the peer flags.
    ///
    /// Only [`UWGPEER_F_REMOVE_ME`], [`UWGPEER_F_REPLACE_ALLOWEDIPS`] and
    /// [`UWGPEER_F_UPDATE_ONLY`] may be set;
    /// [`UWGPEER_F_HAS_ADVANCED_SECURITY`] is read-only and is represented by
    /// [`advanced_security`](Self::advanced_security) instead.
    pub fn flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Sets `UWGPEER_A_PROTOCOL_VERSION`.
    ///
    /// The kernel documents `1` as the only accepted value; it is normally
    /// left unset so that the current protocol is used.
    pub fn protocol_version(mut self, version: u32) -> Self {
        self.protocol_version = Some(version);
        self
    }

    /// Builds the peer attribute list.
    ///
    /// # Errors
    ///
    /// Returns [`UmbrawgConfigError`] when a keepalive range is inverted, a
    /// flag or the protocol version is unsupported.
    pub fn build(self) -> Result<UmbrawgPeer, UmbrawgConfigError> {
        self.validate()?;

        let mut attributes =
            vec![UmbrawgPeerAttribute::PublicKey(self.public_key)];
        if let Some(key) = self.preshared_key {
            attributes.push(UmbrawgPeerAttribute::PresharedKey(key));
        }
        if self.flags != 0 {
            attributes.push(UmbrawgPeerAttribute::Flags(self.flags));
        }
        if let Some(endpoint) = self.endpoint {
            attributes.push(UmbrawgPeerAttribute::Endpoint(endpoint));
        }
        match self.keepalive {
            Some(Keepalive::Legacy(seconds)) => attributes
                .push(UmbrawgPeerAttribute::PersistentKeepalive(seconds)),
            Some(Keepalive::Range(range)) => attributes
                .push(UmbrawgPeerAttribute::PersistentKeepaliveRange(range)),
            None => {}
        }
        if let Some(version) = self.protocol_version {
            attributes.push(UmbrawgPeerAttribute::ProtocolVersion(version));
        }
        if self.advanced_security {
            attributes.push(UmbrawgPeerAttribute::AdvancedSecurity(true));
        }
        if !self.allowed_ips.is_empty()
            || self.flags & UWGPEER_F_REPLACE_ALLOWEDIPS != 0
        {
            attributes.push(UmbrawgPeerAttribute::AllowedIps(self.allowed_ips));
        }

        Ok(UmbrawgPeer(attributes))
    }

    /// Parses an existing peer back into a configuration.
    ///
    /// Read-only attributes (`LastHandshake`, `RxBytes`, `TxBytes`) and
    /// unknown attributes are dropped. The read-only
    /// [`UWGPEER_F_HAS_ADVANCED_SECURITY`] flag is translated into
    /// [`advanced_security`](Self::advanced_security).
    ///
    /// # Errors
    ///
    /// Returns [`UmbrawgConfigError::MissingPublicKey`] when the peer has no
    /// public key.
    pub fn from_peer(peer: &UmbrawgPeer) -> Result<Self, UmbrawgConfigError> {
        let public_key = peer
            .0
            .iter()
            .find_map(|attribute| match attribute {
                UmbrawgPeerAttribute::PublicKey(key) => Some(*key),
                _ => None,
            })
            .ok_or(UmbrawgConfigError::MissingPublicKey)?;

        let mut config = Self::new(public_key);
        for attribute in &peer.0 {
            match attribute {
                UmbrawgPeerAttribute::PublicKey(_) => {}
                UmbrawgPeerAttribute::PresharedKey(key) => {
                    config.preshared_key = Some(*key);
                }
                UmbrawgPeerAttribute::Endpoint(endpoint) => {
                    config.endpoint = Some(*endpoint);
                }
                UmbrawgPeerAttribute::PersistentKeepalive(seconds) => {
                    config.keepalive = Some(Keepalive::Legacy(*seconds));
                }
                UmbrawgPeerAttribute::PersistentKeepaliveRange(range) => {
                    config.keepalive = Some(Keepalive::Range(*range));
                }
                UmbrawgPeerAttribute::AllowedIps(allowed_ips) => {
                    config.allowed_ips = allowed_ips.clone();
                }
                UmbrawgPeerAttribute::ProtocolVersion(version) => {
                    config.protocol_version = Some(*version);
                }
                UmbrawgPeerAttribute::Flags(flags) => {
                    config.flags = flags & PEER_FLAGS_ALLOWED;
                    if flags & UWGPEER_F_HAS_ADVANCED_SECURITY != 0 {
                        config.advanced_security = true;
                    }
                }
                UmbrawgPeerAttribute::AdvancedSecurity(enabled) => {
                    config.advanced_security |= *enabled;
                }
                UmbrawgPeerAttribute::LastHandshake(_)
                | UmbrawgPeerAttribute::RxBytes(_)
                | UmbrawgPeerAttribute::TxBytes(_)
                | UmbrawgPeerAttribute::Other(_) => {}
            }
        }

        Ok(config)
    }

    pub(crate) fn validate(&self) -> Result<(), UmbrawgConfigError> {
        if let Some(Keepalive::Range(range)) = self.keepalive {
            let (lo, hi) = crate::range::u16_range_unpack(range);
            if lo > hi {
                return Err(UmbrawgConfigError::InvalidRange {
                    field: "persistent keepalive",
                    lo: u32::from(lo),
                    hi: u32::from(hi),
                });
            }
        }

        if self.flags & !PEER_FLAGS_ALLOWED != 0 {
            return Err(UmbrawgConfigError::UnsupportedFlags {
                field: "UWGPEER_A_FLAGS",
                flags: self.flags,
            });
        }

        if let Some(version) = self.protocol_version {
            if version != 1 {
                return Err(UmbrawgConfigError::UnsupportedProtocolVersion {
                    version,
                });
            }
        }

        Ok(())
    }
}

impl TryFrom<&UmbrawgPeer> for UmbrawgPeerConfig {
    type Error = UmbrawgConfigError;

    fn try_from(peer: &UmbrawgPeer) -> Result<Self, Self::Error> {
        Self::from_peer(peer)
    }
}

impl TryFrom<UmbrawgPeer> for UmbrawgPeerConfig {
    type Error = UmbrawgConfigError;

    fn try_from(peer: UmbrawgPeer) -> Result<Self, Self::Error> {
        Self::from_peer(&peer)
    }
}

fn key(
    value: &[u8],
    field: &'static str,
) -> Result<[u8; UWG_KEY_LEN], UmbrawgConfigError> {
    value
        .try_into()
        .map_err(|_| UmbrawgConfigError::InvalidKeyLength {
            field,
            expected: UWG_KEY_LEN,
            actual: value.len(),
        })
}
