// SPDX-License-Identifier: MIT

//! Builder for `UWG_CMD_SET_DEVICE` messages.

use crate::{
    attribute::{fec_pack, UmbrawgAttribute},
    bbr::BbrMode,
    constants::{UWGDEVICE_F_REPLACE_PEERS, UWG_KEY_LEN},
    error::UmbrawgConfigError,
    fec::FecMode,
    message::{UmbrawgCmd, UmbrawgMessage},
    peer_config::UmbrawgPeerConfig,
    range::u32_range_unpack,
};

/// Length of a Curve25519 key in bytes, for brevity in this module.
const KEY_LEN: usize = UWG_KEY_LEN;

/// Length of the header protection key in bytes.
const HEADER_PROTECTION_KEY_LEN: usize = 32;

/// Minimal `S1`..`S4` padding when a header protection key is configured.
///
/// Mirrors `HEADER_PROTECTION_NONCE_SIZE` of the kernel module, which is the
/// ChaCha20-Poly1305 nonce length.
pub const HEADER_PROTECTION_NONCE_LEN: u16 = 12;

/// Maximal interface name length the kernel accepts (`IFNAMSIZ - 1`).
const IFNAME_MAX_LEN: usize = 15;
/// Largest accepted number of additional external UDP ports.
pub const EXTRA_PORTS_MAX: u8 = 8;

/// One of the four magic header ranges (`UWGDEVICE_A_H1`..`UWGDEVICE_A_H4`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum UmbrawgMagicHeader {
    /// `UWGDEVICE_A_H1`: magic header of handshake initiation messages.
    H1,
    /// `UWGDEVICE_A_H2`: magic header of handshake response messages.
    H2,
    /// `UWGDEVICE_A_H3`: magic header of cookie reply messages.
    H3,
    /// `UWGDEVICE_A_H4`: magic header of transport data messages.
    H4,
}

impl UmbrawgMagicHeader {
    /// Returns the header name as used by the kernel API, e.g. `"H1"`.
    pub fn name(self) -> &'static str {
        match self {
            Self::H1 => "H1",
            Self::H2 => "H2",
            Self::H3 => "H3",
            Self::H4 => "H4",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::H1 => 0,
            Self::H2 => 1,
            Self::H3 => 2,
            Self::H4 => 3,
        }
    }

    fn all() -> [Self; 4] {
        [Self::H1, Self::H2, Self::H3, Self::H4]
    }
}

/// Maximal length of an `I1`..`I5` descriptor in bytes.
///
/// The value must fit into a NUL-terminated netlink string attribute, whose
/// total length (including the four-byte header and the trailing NUL) is
/// limited by the `u16` attribute length.
pub const INTERMEDIATE_SPEC_MAX_LEN: usize = u16::MAX as usize - 5;

/// Builder for a `UWG_CMD_SET_DEVICE` message.
///
/// The builder accepts the raw values of the UmbraWG UAPI and validates them
/// against the constraints of the kernel module. For the packed wire formats
/// (`H1`..`H4` as `u32` ranges, the `u16` tuning ranges) it takes the
/// unpacked bounds and performs the packing itself.
///
/// Keys are accepted either as fixed-size arrays, which are valid by
/// construction, or as slices through the `try_*` methods, which reject
/// values of the wrong length with
/// [`UmbrawgConfigError::InvalidKeyLength`].
///
/// BBR and FEC are configured with [`bbr`](Self::bbr) and [`fec`](Self::fec)
/// using the typed [`BbrMode`] and [`FecMode`] enums; both are restored by
/// [`from_message`](Self::from_message), so a `UWG_CMD_GET_DEVICE` reply
/// survives a configuration round trip.
///
/// # Example
///
/// ```
/// use netlink_packet_umbrawg::{UmbrawgDeviceConfig, UmbrawgPeerConfig};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let peer = UmbrawgPeerConfig::new([7u8; 32])
///     .endpoint_v4("10.0.0.1".parse()?, 51820)
///     .allowed_ip("0.0.0.0".parse()?, 0)?;
///
/// let msg = UmbrawgDeviceConfig::by_name("uwg0")
///     .private_key([1u8; 32])
///     .listen_port(51820)
///     .fwmark(0)
///     .junk(4, 40, 70)
///     .padding(0, 0, 0, 0)
///     .h1(61220074, 118999195)
///     .content_padding_addition(51, 197)
///     .peer(peer)
///     .build()?;
///
/// assert_eq!(msg.cmd, netlink_packet_umbrawg::UmbrawgCmd::SetDevice);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UmbrawgDeviceConfig {
    if_index: Option<u32>,
    if_name: Option<String>,
    private_key: Option<[u8; KEY_LEN]>,
    listen_port: Option<u16>,
    extra_ports: Option<u8>,
    fwmark: Option<u32>,
    flags: Option<u32>,
    junk_count: Option<u16>,
    junk_min_size: Option<u16>,
    junk_max_size: Option<u16>,
    s: [Option<u16>; 4],
    magic_headers: [Option<(u32, u32)>; 4],
    intermediates: [Option<String>; 5],
    header_protection_key: Option<[u8; HEADER_PROTECTION_KEY_LEN]>,
    content_padding_addition: Option<u32>,
    rekey_after_time: Option<u32>,
    rekey_timeout: Option<u32>,
    reject_after_time: Option<u32>,
    keepalive_timeout: Option<u32>,
    max_handshake_attempts: Option<u32>,
    random_trailers: Option<bool>,
    disable_cookies: Option<bool>,
    bbr: Option<BbrMode>,
    fec: Option<FecMode>,
    peers: Vec<UmbrawgPeerConfig>,
}

impl Default for UmbrawgDeviceConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl UmbrawgDeviceConfig {
    /// Creates an empty configuration.
    ///
    /// An interface must be selected with [`by_name`](Self::by_name),
    /// [`if_name`](Self::if_name), [`by_index`](Self::by_index) or
    /// [`if_index`](Self::if_index) before
    /// [`build`](Self::build) succeeds.
    pub fn new() -> Self {
        Self {
            if_index: None,
            if_name: None,
            private_key: None,
            listen_port: None,
            extra_ports: None,
            fwmark: None,
            flags: None,
            junk_count: None,
            junk_min_size: None,
            junk_max_size: None,
            s: [None; 4],
            magic_headers: [None; 4],
            intermediates: [None, None, None, None, None],
            header_protection_key: None,
            content_padding_addition: None,
            rekey_after_time: None,
            rekey_timeout: None,
            reject_after_time: None,
            keepalive_timeout: None,
            max_handshake_attempts: None,
            random_trailers: None,
            disable_cookies: None,
            bbr: None,
            fec: None,
            peers: Vec::new(),
        }
    }

    /// Creates a configuration for the interface with the given name.
    pub fn by_name(name: impl Into<String>) -> Self {
        Self::new().if_name(name)
    }

    /// Creates a configuration for the interface with the given index.
    pub fn by_index(index: u32) -> Self {
        Self::new().if_index(index)
    }

    /// Selects the interface by name.
    ///
    /// The name must not be longer than 15 bytes and must not contain NUL
    /// bytes; otherwise [`build`](Self::build) fails.
    pub fn if_name(mut self, name: impl Into<String>) -> Self {
        self.if_name = Some(name.into());
        self
    }

    /// Selects the interface by index.
    ///
    /// An interface index and an interface name are mutually exclusive.
    pub fn if_index(mut self, index: u32) -> Self {
        self.if_index = Some(index);
        self
    }

    /// Sets the static private key.
    ///
    /// An all-zero key removes the key, the way `uwg`(8) does. The key is
    /// length-checked by its type; use
    /// [`try_private_key`](Self::try_private_key) for untrusted bytes.
    pub fn private_key(mut self, key: [u8; KEY_LEN]) -> Self {
        self.private_key = Some(key);
        self
    }

    /// Sets the static private key from a slice.
    ///
    /// # Errors
    ///
    /// Returns [`UmbrawgConfigError::InvalidKeyLength`] unless the slice is
    /// exactly 32 bytes long.
    pub fn try_private_key(
        mut self,
        key: &[u8],
    ) -> Result<Self, UmbrawgConfigError> {
        self.private_key = Some(checked_key(key, "private key")?);
        Ok(self)
    }

    /// Sets the UDP listen port; `0` makes the kernel choose one randomly.
    pub fn listen_port(mut self, port: u16) -> Self {
        self.listen_port = Some(port);
        self
    }

    /// Sets the number of additional external UDP ports (`0..=8`).
    pub fn extra_ports(mut self, ports: u8) -> Self {
        self.extra_ports = Some(ports);
        self
    }

    /// Sets the firewall mark; `0` disables it.
    pub fn fwmark(mut self, mark: u32) -> Self {
        self.fwmark = Some(mark);
        self
    }

    /// Sets the device flags, replacing any previously configured value.
    ///
    /// Only [`UWGDEVICE_F_REPLACE_PEERS`] is accepted by the kernel.
    pub fn flags(mut self, flags: u32) -> Self {
        self.flags = Some(flags);
        self
    }

    /// Removes all existing peers before applying the configured ones.
    pub fn replace_peers(mut self) -> Self {
        self.flags = Some(self.flags.unwrap_or(0) | UWGDEVICE_F_REPLACE_PEERS);
        self
    }

    /// Sets the number of junk packets (`Jc`).
    pub fn junk_count(mut self, count: u16) -> Self {
        self.junk_count = Some(count);
        self
    }

    /// Sets the minimal junk packet size (`Jmin`).
    pub fn junk_min_size(mut self, size: u16) -> Self {
        self.junk_min_size = Some(size);
        self
    }

    /// Sets the maximal junk packet size (`Jmax`).
    pub fn junk_max_size(mut self, size: u16) -> Self {
        self.junk_max_size = Some(size);
        self
    }

    /// Sets `Jc`, `Jmin` and `Jmax` at once.
    ///
    /// The kernel requires `Jmin <= Jmax`, which is checked by
    /// [`build`](Self::build).
    pub fn junk(mut self, count: u16, min_size: u16, max_size: u16) -> Self {
        self.junk_count = Some(count);
        self.junk_min_size = Some(min_size);
        self.junk_max_size = Some(max_size);
        self
    }

    /// Sets the `S1` padding of handshake initiation messages.
    pub fn s1(mut self, value: u16) -> Self {
        self.s[0] = Some(value);
        self
    }

    /// Sets the `S2` padding of handshake response messages.
    pub fn s2(mut self, value: u16) -> Self {
        self.s[1] = Some(value);
        self
    }

    /// Sets the `S3` padding of cookie reply messages.
    pub fn s3(mut self, value: u16) -> Self {
        self.s[2] = Some(value);
        self
    }

    /// Sets the `S4` padding of transport data messages.
    pub fn s4(mut self, value: u16) -> Self {
        self.s[3] = Some(value);
        self
    }

    /// Sets `S1`..`S4` at once.
    ///
    /// With a header protection key configured, every value must be at least
    /// [`HEADER_PROTECTION_NONCE_LEN`]; [`build`](Self::build) checks it.
    pub fn padding(mut self, s1: u16, s2: u16, s3: u16, s4: u16) -> Self {
        self.s = [Some(s1), Some(s2), Some(s3), Some(s4)];
        self
    }

    /// Sets one magic header range from its inclusive bounds.
    ///
    /// The bounds are packed into the `u64` wire format used by the UmbraWG
    /// 3.x kernel module. [`build`](Self::build) rejects `lo > hi` and
    /// overlapping headers.
    pub fn magic_header(
        mut self,
        header: UmbrawgMagicHeader,
        lo: u32,
        hi: u32,
    ) -> Self {
        self.magic_headers[header.index()] = Some((lo, hi));
        self
    }

    /// Sets one magic header from a spec string, e.g. `"61220074"` or
    /// `"61220074-118999195"`.
    ///
    /// # Errors
    ///
    /// Returns [`UmbrawgConfigError::InvalidMagicHeaderSpec`] when the spec
    /// is not a decimal value or a valid `"<lo>-<hi>"` range.
    pub fn magic_header_spec(
        mut self,
        header: UmbrawgMagicHeader,
        spec: &str,
    ) -> Result<Self, UmbrawgConfigError> {
        let packed =
            crate::range::u32_range_from_string(spec).ok_or_else(|| {
                UmbrawgConfigError::InvalidMagicHeaderSpec {
                    header,
                    spec: spec.to_string(),
                }
            })?;
        self.magic_headers[header.index()] = Some(u32_range_unpack(packed));
        Ok(self)
    }

    /// Sets the `H1` magic header range.
    pub fn h1(self, lo: u32, hi: u32) -> Self {
        self.magic_header(UmbrawgMagicHeader::H1, lo, hi)
    }

    /// Sets the `H2` magic header range.
    pub fn h2(self, lo: u32, hi: u32) -> Self {
        self.magic_header(UmbrawgMagicHeader::H2, lo, hi)
    }

    /// Sets the `H3` magic header range.
    pub fn h3(self, lo: u32, hi: u32) -> Self {
        self.magic_header(UmbrawgMagicHeader::H3, lo, hi)
    }

    /// Sets the `H4` magic header range.
    pub fn h4(self, lo: u32, hi: u32) -> Self {
        self.magic_header(UmbrawgMagicHeader::H4, lo, hi)
    }

    /// Sets the `I1` intermediate header descriptor.
    pub fn i1(mut self, spec: impl Into<String>) -> Self {
        self.intermediates[0] = Some(spec.into());
        self
    }

    /// Sets the `I2` intermediate header descriptor.
    pub fn i2(mut self, spec: impl Into<String>) -> Self {
        self.intermediates[1] = Some(spec.into());
        self
    }

    /// Sets the `I3` intermediate header descriptor.
    pub fn i3(mut self, spec: impl Into<String>) -> Self {
        self.intermediates[2] = Some(spec.into());
        self
    }

    /// Sets the `I4` intermediate header descriptor.
    pub fn i4(mut self, spec: impl Into<String>) -> Self {
        self.intermediates[3] = Some(spec.into());
        self
    }

    /// Sets the `I5` intermediate header descriptor.
    pub fn i5(mut self, spec: impl Into<String>) -> Self {
        self.intermediates[4] = Some(spec.into());
        self
    }

    /// Sets the header protection key.
    ///
    /// The key is length-checked by its type; use
    /// [`try_header_protection_key`](Self::try_header_protection_key) for
    /// untrusted bytes. When a key is configured, `S1`..`S4` must not be
    /// smaller than [`HEADER_PROTECTION_NONCE_LEN`].
    pub fn header_protection_key(
        mut self,
        key: [u8; HEADER_PROTECTION_KEY_LEN],
    ) -> Self {
        self.header_protection_key = Some(key);
        self
    }

    /// Sets the header protection key from a slice.
    ///
    /// # Errors
    ///
    /// Returns [`UmbrawgConfigError::InvalidKeyLength`] unless the slice is
    /// exactly 32 bytes long.
    pub fn try_header_protection_key(
        mut self,
        key: &[u8],
    ) -> Result<Self, UmbrawgConfigError> {
        self.header_protection_key =
            Some(checked_key(key, "header protection key")?);
        Ok(self)
    }

    /// Sets the content padding addition range.
    pub fn content_padding_addition(mut self, lo: u16, hi: u16) -> Self {
        self.content_padding_addition = Some(pack_range(lo, hi));
        self
    }

    /// Sets the rekey-after-time range in seconds.
    pub fn rekey_after_time(mut self, lo: u16, hi: u16) -> Self {
        self.rekey_after_time = Some(pack_range(lo, hi));
        self
    }

    /// Sets the rekey timeout range in seconds.
    pub fn rekey_timeout(mut self, lo: u16, hi: u16) -> Self {
        self.rekey_timeout = Some(pack_range(lo, hi));
        self
    }

    /// Sets the reject-after-time range in seconds.
    pub fn reject_after_time(mut self, lo: u16, hi: u16) -> Self {
        self.reject_after_time = Some(pack_range(lo, hi));
        self
    }

    /// Sets the keepalive timeout range in seconds.
    pub fn keepalive_timeout(mut self, lo: u16, hi: u16) -> Self {
        self.keepalive_timeout = Some(pack_range(lo, hi));
        self
    }

    /// Sets the maximal handshake attempts range.
    pub fn max_handshake_attempts(mut self, lo: u16, hi: u16) -> Self {
        self.max_handshake_attempts = Some(pack_range(lo, hi));
        self
    }

    /// Enables or disables random trailers (UmbraWG 3.1).
    pub fn random_trailers(mut self, enabled: bool) -> Self {
        self.random_trailers = Some(enabled);
        self
    }

    /// Enables or disables cookie replies (UmbraWG 3.1).
    pub fn disable_cookies(mut self, disabled: bool) -> Self {
        self.disable_cookies = Some(disabled);
        self
    }

    /// Sets the BBR congestion control mode (`UWGDEVICE_A_BBR`).
    ///
    /// The mode is emitted as a `u8`: `0` off, `1` monitor, `2` on.
    pub fn bbr(mut self, mode: BbrMode) -> Self {
        self.bbr = Some(mode);
        self
    }

    /// Sets the forward error correction mode (`UWGDEVICE_A_FEC`).
    ///
    /// The mode is emitted as a `u32`: `0` off, `1` adaptive, otherwise
    /// `(K << 8) | M`. [`build`](Self::build) rejects
    /// [`FecMode::Fixed`] shard counts that the kernel does not accept.
    pub fn fec(mut self, mode: FecMode) -> Self {
        self.fec = Some(mode);
        self
    }

    /// Adds a peer to the message.
    pub fn peer(mut self, peer: UmbrawgPeerConfig) -> Self {
        self.peers.push(peer);
        self
    }

    /// Adds several peers to the message.
    pub fn peers(
        mut self,
        peers: impl IntoIterator<Item = UmbrawgPeerConfig>,
    ) -> Self {
        self.peers.extend(peers);
        self
    }

    /// Builds the `UWG_CMD_SET_DEVICE` message.
    ///
    /// # Errors
    ///
    /// Returns [`UmbrawgConfigError`] when the configuration violates a
    /// kernel constraint, for example when no interface is selected or when
    /// `Jmin > Jmax`.
    pub fn build(self) -> Result<UmbrawgMessage, UmbrawgConfigError> {
        Ok(UmbrawgMessage {
            cmd: UmbrawgCmd::SetDevice,
            attributes: self.into_attributes()?,
        })
    }

    /// Validates the configuration and returns the attribute list of a
    /// `UWG_CMD_SET_DEVICE` message.
    ///
    /// # Errors
    ///
    /// Returns [`UmbrawgConfigError`] for the same reasons as
    /// [`build`](Self::build).
    pub fn into_attributes(
        self,
    ) -> Result<Vec<UmbrawgAttribute>, UmbrawgConfigError> {
        self.validate()?;

        let mut attributes = Vec::new();

        if let Some(index) = self.if_index {
            attributes.push(UmbrawgAttribute::IfIndex(index));
        }
        if let Some(name) = &self.if_name {
            attributes.push(UmbrawgAttribute::IfName(name.clone()));
        }
        if let Some(key) = self.private_key {
            attributes.push(UmbrawgAttribute::PrivateKey(key));
        }
        if let Some(port) = self.listen_port {
            attributes.push(UmbrawgAttribute::ListenPort(port));
        }
        if let Some(extra_ports) = self.extra_ports {
            attributes.push(UmbrawgAttribute::ExtraPorts(extra_ports));
        }
        if let Some(mark) = self.fwmark {
            attributes.push(UmbrawgAttribute::Fwmark(mark));
        }
        if let Some(flags) = self.flags {
            attributes.push(UmbrawgAttribute::Flags(flags));
        }
        for header in UmbrawgMagicHeader::all() {
            if let Some((lo, hi)) = self.magic_headers[header.index()] {
                attributes.push(match header {
                    UmbrawgMagicHeader::H1 => {
                        UmbrawgAttribute::H1Range(pack_u32_range(lo, hi))
                    }
                    UmbrawgMagicHeader::H2 => {
                        UmbrawgAttribute::H2Range(pack_u32_range(lo, hi))
                    }
                    UmbrawgMagicHeader::H3 => {
                        UmbrawgAttribute::H3Range(pack_u32_range(lo, hi))
                    }
                    UmbrawgMagicHeader::H4 => {
                        UmbrawgAttribute::H4Range(pack_u32_range(lo, hi))
                    }
                });
            }
        }
        if let Some(count) = self.junk_count {
            attributes.push(UmbrawgAttribute::JC(count));
        }
        if let Some(min) = self.junk_min_size {
            attributes.push(UmbrawgAttribute::Jmin(min));
        }
        if let Some(max) = self.junk_max_size {
            attributes.push(UmbrawgAttribute::Jmax(max));
        }
        let padding = [
            UmbrawgAttribute::S1,
            UmbrawgAttribute::S2,
            UmbrawgAttribute::S3,
            UmbrawgAttribute::S4,
        ];
        for (value, constructor) in self.s.iter().zip(padding) {
            if let Some(value) = value {
                attributes.push(constructor(*value));
            }
        }
        let intermediates = [
            UmbrawgAttribute::I1,
            UmbrawgAttribute::I2,
            UmbrawgAttribute::I3,
            UmbrawgAttribute::I4,
            UmbrawgAttribute::I5,
        ];
        for (value, constructor) in self.intermediates.iter().zip(intermediates)
        {
            if let Some(value) = value {
                attributes.push(constructor(value.clone()));
            }
        }
        if let Some(key) = self.header_protection_key {
            attributes.push(UmbrawgAttribute::HeaderProtectionKey(key));
        }
        for (value, constructor) in [
            (
                self.content_padding_addition,
                UmbrawgAttribute::ContentPaddingAddition
                    as fn(u32) -> UmbrawgAttribute,
            ),
            (self.rekey_after_time, UmbrawgAttribute::RekeyAfterTime),
            (self.rekey_timeout, UmbrawgAttribute::RekeyTimeout),
            (self.reject_after_time, UmbrawgAttribute::RejectAfterTime),
            (self.keepalive_timeout, UmbrawgAttribute::KeepaliveTimeout),
            (
                self.max_handshake_attempts,
                UmbrawgAttribute::MaxHandshakeAttempts,
            ),
        ] {
            if let Some(value) = value {
                attributes.push(constructor(value));
            }
        }
        if let Some(enabled) = self.random_trailers {
            attributes.push(UmbrawgAttribute::RandomTrailers(enabled));
        }
        if let Some(disabled) = self.disable_cookies {
            attributes.push(UmbrawgAttribute::DisableCookies(disabled));
        }
        if let Some(mode) = self.bbr {
            attributes.push(UmbrawgAttribute::Bbr(mode.as_u8()));
        }
        if let Some(mode) = self.fec {
            let value = match mode {
                FecMode::Off => crate::attribute::FEC_OFF,
                FecMode::Adaptive => crate::attribute::FEC_ADAPTIVE,
                FecMode::Fixed { k, m } => fec_pack(k, m)
                    .ok_or(UmbrawgConfigError::InvalidFecShards { k, m })?,
            };
            attributes.push(UmbrawgAttribute::Fec(value));
        }
        if !self.peers.is_empty() {
            let peers = self
                .peers
                .into_iter()
                .map(UmbrawgPeerConfig::build)
                .collect::<Result<Vec<_>, _>>()?;
            attributes.push(UmbrawgAttribute::Peers(peers));
        }

        Ok(attributes)
    }

    /// Parses an existing message back into a configuration.
    ///
    /// Read-only attributes of `UWG_CMD_GET_DEVICE` replies are ignored:
    /// public keys, byte counters, handshake timestamps and unknown
    /// attributes are dropped. The BBR and FEC modes are restored from
    /// `UWGDEVICE_A_BBR` and `UWGDEVICE_A_FEC`. When a reply carries both an
    /// interface name and an interface index, the index is dropped because
    /// `UWG_CMD_SET_DEVICE` accepts exactly one of them.
    ///
    /// # Errors
    ///
    /// Returns [`UmbrawgConfigError`] when the message carries a command
    /// other than [`UmbrawgCmd::GetDevice`] or [`UmbrawgCmd::SetDevice`],
    /// when a BBR or FEC payload is invalid, or when an attribute cannot be
    /// represented by the builder, such as a malformed magic header spec.
    pub fn from_message(
        msg: &UmbrawgMessage,
    ) -> Result<Self, UmbrawgConfigError> {
        if !matches!(msg.cmd, UmbrawgCmd::GetDevice | UmbrawgCmd::SetDevice) {
            return Err(UmbrawgConfigError::UnsupportedCommand {
                command: msg.cmd.into(),
            });
        }

        let mut config = Self::new();
        let mut peers = Vec::new();

        for attribute in &msg.attributes {
            match attribute {
                UmbrawgAttribute::IfIndex(index) => {
                    config.if_index = Some(*index);
                }
                UmbrawgAttribute::IfName(name) => {
                    config.if_name = Some(name.clone());
                }
                UmbrawgAttribute::PrivateKey(key) => {
                    config.private_key = Some(*key);
                }
                UmbrawgAttribute::ListenPort(port) => {
                    config.listen_port = Some(*port);
                }
                UmbrawgAttribute::ExtraPorts(ports) => {
                    config.extra_ports = Some(*ports);
                }
                UmbrawgAttribute::Fwmark(mark) => {
                    config.fwmark = Some(*mark);
                }
                UmbrawgAttribute::Flags(flags) => {
                    config.flags = Some(*flags);
                }
                UmbrawgAttribute::Peers(list) => {
                    for peer in list {
                        peers.push(UmbrawgPeerConfig::from_peer(peer)?);
                    }
                }
                UmbrawgAttribute::JC(count) => {
                    config.junk_count = Some(*count);
                }
                UmbrawgAttribute::Jmin(size) => {
                    config.junk_min_size = Some(*size);
                }
                UmbrawgAttribute::Jmax(size) => {
                    config.junk_max_size = Some(*size);
                }
                UmbrawgAttribute::S1(value) => config.s[0] = Some(*value),
                UmbrawgAttribute::S2(value) => config.s[1] = Some(*value),
                UmbrawgAttribute::S3(value) => config.s[2] = Some(*value),
                UmbrawgAttribute::S4(value) => config.s[3] = Some(*value),
                UmbrawgAttribute::H1(spec) => {
                    config.set_header_from_spec(UmbrawgMagicHeader::H1, spec)?
                }
                UmbrawgAttribute::H2(spec) => {
                    config.set_header_from_spec(UmbrawgMagicHeader::H2, spec)?
                }
                UmbrawgAttribute::H3(spec) => {
                    config.set_header_from_spec(UmbrawgMagicHeader::H3, spec)?
                }
                UmbrawgAttribute::H4(spec) => {
                    config.set_header_from_spec(UmbrawgMagicHeader::H4, spec)?
                }
                UmbrawgAttribute::H1Range(range) => {
                    config.magic_headers[0] = Some(u32_range_unpack(*range))
                }
                UmbrawgAttribute::H2Range(range) => {
                    config.magic_headers[1] = Some(u32_range_unpack(*range))
                }
                UmbrawgAttribute::H3Range(range) => {
                    config.magic_headers[2] = Some(u32_range_unpack(*range))
                }
                UmbrawgAttribute::H4Range(range) => {
                    config.magic_headers[3] = Some(u32_range_unpack(*range))
                }
                UmbrawgAttribute::H1Legacy(value) => {
                    config.magic_headers[0] = Some((*value, *value))
                }
                UmbrawgAttribute::H2Legacy(value) => {
                    config.magic_headers[1] = Some((*value, *value))
                }
                UmbrawgAttribute::H3Legacy(value) => {
                    config.magic_headers[2] = Some((*value, *value))
                }
                UmbrawgAttribute::H4Legacy(value) => {
                    config.magic_headers[3] = Some((*value, *value))
                }
                UmbrawgAttribute::I1(spec) => {
                    config.intermediates[0] = Some(spec.clone())
                }
                UmbrawgAttribute::I2(spec) => {
                    config.intermediates[1] = Some(spec.clone())
                }
                UmbrawgAttribute::I3(spec) => {
                    config.intermediates[2] = Some(spec.clone())
                }
                UmbrawgAttribute::I4(spec) => {
                    config.intermediates[3] = Some(spec.clone())
                }
                UmbrawgAttribute::I5(spec) => {
                    config.intermediates[4] = Some(spec.clone())
                }
                UmbrawgAttribute::HeaderProtectionKey(key) => {
                    config.header_protection_key = Some(*key);
                }
                UmbrawgAttribute::ContentPaddingAddition(value) => {
                    config.content_padding_addition = Some(*value);
                }
                UmbrawgAttribute::RekeyAfterTime(value) => {
                    config.rekey_after_time = Some(*value);
                }
                UmbrawgAttribute::RekeyTimeout(value) => {
                    config.rekey_timeout = Some(*value);
                }
                UmbrawgAttribute::RejectAfterTime(value) => {
                    config.reject_after_time = Some(*value);
                }
                UmbrawgAttribute::KeepaliveTimeout(value) => {
                    config.keepalive_timeout = Some(*value);
                }
                UmbrawgAttribute::MaxHandshakeAttempts(value) => {
                    config.max_handshake_attempts = Some(*value);
                }
                UmbrawgAttribute::RandomTrailers(enabled) => {
                    config.random_trailers = Some(*enabled);
                }
                UmbrawgAttribute::DisableCookies(disabled) => {
                    config.disable_cookies = Some(*disabled);
                }
                UmbrawgAttribute::Bbr(value) => {
                    config.bbr = Some(BbrMode::from_u8(*value).ok_or(
                        UmbrawgConfigError::InvalidBbrMode { value: *value },
                    )?);
                }
                UmbrawgAttribute::Fec(value) => {
                    config.fec = Some(FecMode::from_u32(*value).ok_or(
                        UmbrawgConfigError::InvalidFecValue { value: *value },
                    )?);
                }
                UmbrawgAttribute::PublicKey(_)
                | UmbrawgAttribute::Peer(_)
                | UmbrawgAttribute::Other(_) => {}
            }
        }

        config.peers = peers;
        if config.if_name.is_some() {
            config.if_index = None;
        }
        Ok(config)
    }

    fn set_header_from_spec(
        &mut self,
        header: UmbrawgMagicHeader,
        spec: &str,
    ) -> Result<(), UmbrawgConfigError> {
        let packed =
            crate::range::u32_range_from_string(spec).ok_or_else(|| {
                UmbrawgConfigError::InvalidMagicHeaderSpec {
                    header,
                    spec: spec.to_string(),
                }
            })?;
        self.magic_headers[header.index()] = Some(u32_range_unpack(packed));
        Ok(())
    }

    fn validate(&self) -> Result<(), UmbrawgConfigError> {
        match (&self.if_name, self.if_index) {
            (None, None) => return Err(UmbrawgConfigError::MissingInterface),
            (Some(_), Some(_)) => {
                return Err(UmbrawgConfigError::ConflictingInterface)
            }
            _ => {}
        }

        if let Some(name) = &self.if_name {
            if name.is_empty()
                || name.len() > IFNAME_MAX_LEN
                || name.as_bytes().contains(&0)
            {
                return Err(UmbrawgConfigError::InvalidInterfaceName {
                    name: name.clone(),
                });
            }
        }

        if let Some(flags) = self.flags {
            if flags & !UWGDEVICE_F_REPLACE_PEERS != 0 {
                return Err(UmbrawgConfigError::UnsupportedFlags {
                    field: "UWGDEVICE_A_FLAGS",
                    flags,
                });
            }
        }

        if let Some(extra_ports) = self.extra_ports {
            if extra_ports > EXTRA_PORTS_MAX {
                return Err(UmbrawgConfigError::InvalidRange {
                    field: "UWGDEVICE_A_EXTRA_PORTS",
                    lo: 0,
                    hi: u32::from(EXTRA_PORTS_MAX),
                });
            }
        }

        if let (Some(min), Some(max)) = (self.junk_min_size, self.junk_max_size)
        {
            if min > max {
                return Err(UmbrawgConfigError::InvalidRange {
                    field: "Jmin/Jmax",
                    lo: u32::from(min),
                    hi: u32::from(max),
                });
            }
        }

        for header in UmbrawgMagicHeader::all() {
            if let Some((lo, hi)) = self.magic_headers[header.index()] {
                if lo > hi {
                    return Err(UmbrawgConfigError::InvalidMagicHeaderRange {
                        header,
                        lo,
                        hi,
                    });
                }
            }
        }
        for (index, first) in UmbrawgMagicHeader::all().into_iter().enumerate()
        {
            let Some((first_lo, first_hi)) = self.magic_headers[index] else {
                continue;
            };
            let all = UmbrawgMagicHeader::all();
            for second in &all[index + 1..] {
                let Some((second_lo, second_hi)) =
                    self.magic_headers[second.index()]
                else {
                    continue;
                };
                if first_lo <= second_hi && second_lo <= first_hi {
                    return Err(UmbrawgConfigError::OverlappingMagicHeaders {
                        first,
                        second: *second,
                    });
                }
            }
        }

        if self.header_protection_key.is_some() {
            let names = ["S1", "S2", "S3", "S4"];
            for (index, value) in self.s.iter().enumerate() {
                if let Some(value) = value {
                    if *value < HEADER_PROTECTION_NONCE_LEN {
                        return Err(
                            UmbrawgConfigError::PaddingBelowHeaderProtectionNonce {
                                field: names[index],
                                value: *value,
                                min: HEADER_PROTECTION_NONCE_LEN,
                            },
                        );
                    }
                }
            }
        }

        let names = ["I1", "I2", "I3", "I4", "I5"];
        for (index, spec) in self.intermediates.iter().enumerate() {
            if let Some(spec) = spec {
                if spec.as_bytes().contains(&0) {
                    return Err(
                        UmbrawgConfigError::IntermediateSpecContainsNul {
                            field: names[index],
                        },
                    );
                }
                if spec.len() > INTERMEDIATE_SPEC_MAX_LEN {
                    return Err(UmbrawgConfigError::IntermediateSpecTooLong {
                        field: names[index],
                        len: spec.len(),
                        max: INTERMEDIATE_SPEC_MAX_LEN,
                    });
                }
            }
        }

        for (field, value) in [
            ("ContentPaddingAddition", self.content_padding_addition),
            ("RekeyAfterTime", self.rekey_after_time),
            ("RekeyTimeout", self.rekey_timeout),
            ("RejectAfterTime", self.reject_after_time),
            ("KeepaliveTimeout", self.keepalive_timeout),
            ("MaxHandshakeAttempts", self.max_handshake_attempts),
        ] {
            if let Some(value) = value {
                let (lo, hi) = crate::range::u16_range_unpack(value);
                if lo > hi {
                    return Err(UmbrawgConfigError::InvalidRange {
                        field,
                        lo: u32::from(lo),
                        hi: u32::from(hi),
                    });
                }
            }
        }

        for peer in &self.peers {
            peer.validate()?;
        }

        Ok(())
    }
}

impl TryFrom<&UmbrawgMessage> for UmbrawgDeviceConfig {
    type Error = UmbrawgConfigError;

    fn try_from(msg: &UmbrawgMessage) -> Result<Self, Self::Error> {
        Self::from_message(msg)
    }
}

impl TryFrom<UmbrawgMessage> for UmbrawgDeviceConfig {
    type Error = UmbrawgConfigError;

    fn try_from(msg: UmbrawgMessage) -> Result<Self, Self::Error> {
        Self::from_message(&msg)
    }
}

fn checked_key(
    key: &[u8],
    field: &'static str,
) -> Result<[u8; KEY_LEN], UmbrawgConfigError> {
    key.try_into()
        .map_err(|_| UmbrawgConfigError::InvalidKeyLength {
            field,
            expected: KEY_LEN,
            actual: key.len(),
        })
}

fn pack_range(lo: u16, hi: u16) -> u32 {
    crate::range::u16_range_pack(lo, hi)
}

fn pack_u32_range(lo: u32, hi: u32) -> u64 {
    crate::range::u32_range_pack(lo, hi)
}
