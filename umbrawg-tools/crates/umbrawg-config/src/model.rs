use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;

use crate::allowed_ip::AllowedIp;
use crate::cipher::Cipher;
use crate::endpoint::{format_endpoint, parse_endpoint};
use crate::error::Error;
use crate::ini::{Document, Entry, Section, SectionKind};
use crate::key::Key;
use crate::range::{U16Range, U32Range};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseOptions {
    pub allow_quick_keys: bool,
    pub resolve_endpoints: bool,
}

impl ParseOptions {
    pub const KERNEL: Self = Self {
        allow_quick_keys: false,
        resolve_endpoints: true,
    };

    pub const QUICK: Self = Self {
        allow_quick_keys: true,
        resolve_endpoints: true,
    };

    pub const fn without_dns() -> Self {
        Self {
            allow_quick_keys: false,
            resolve_endpoints: false,
        }
    }
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self::KERNEL
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObfuscationConfig {
    pub jc: Option<u16>,
    pub jmin: Option<u16>,
    pub jmax: Option<u16>,
    pub s1: Option<u16>,
    pub s2: Option<u16>,
    pub s3: Option<u16>,
    pub s4: Option<u16>,
    pub h1: Option<U32Range>,
    pub h2: Option<U32Range>,
    pub h3: Option<U32Range>,
    pub h4: Option<U32Range>,
    pub i1: Option<String>,
    pub i2: Option<String>,
    pub i3: Option<String>,
    pub i4: Option<String>,
    pub i5: Option<String>,
    pub header_protection_key: Option<Key>,
    pub content_padding_addition: Option<U16Range>,
    pub rekey_after_time: Option<U16Range>,
    pub rekey_timeout: Option<U16Range>,
    pub reject_after_time: Option<U16Range>,
    pub keepalive_timeout: Option<U16Range>,
    pub max_handshake_attempts: Option<U16Range>,
    pub random_trailers: Option<bool>,
    pub disable_cookies: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoutingTable {
    Off,
    Id(u32),
    Name(String),
}

impl RoutingTable {
    pub fn parse(value: &str) -> Result<Self, Error> {
        if value.eq_ignore_ascii_case("off") {
            return Ok(Self::Off);
        }
        if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
            let id = value.parse::<u32>().map_err(|_| Error::InvalidValue {
                line: 0,
                key: "Table".to_owned(),
                value: value.to_owned(),
            })?;
            return Ok(Self::Id(id));
        }
        if value.is_empty() {
            return Err(Error::InvalidValue {
                line: 0,
                key: "Table".to_owned(),
                value: value.to_owned(),
            });
        }
        Ok(Self::Name(value.to_owned()))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QuickConfig {
    pub address: Vec<String>,
    pub dns: Vec<String>,
    pub mtu: Option<u32>,
    pub table: Option<RoutingTable>,
    pub pre_up: Option<String>,
    pub post_up: Option<String>,
    pub pre_down: Option<String>,
    pub post_down: Option<String>,
    pub save_config: Option<bool>,
}

/// Keys of the `[Interface]` section that only `uwg-quick` understands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuickKey {
    Address,
    Dns,
    Mtu,
    Table,
    PreUp,
    PostUp,
    PreDown,
    PostDown,
    SaveConfig,
}

impl QuickKey {
    /// Classifies a configuration key (case-insensitively).
    pub fn parse(key: &str) -> Option<Self> {
        if key.eq_ignore_ascii_case("Address") {
            Some(Self::Address)
        } else if key.eq_ignore_ascii_case("DNS") {
            Some(Self::Dns)
        } else if key.eq_ignore_ascii_case("MTU") {
            Some(Self::Mtu)
        } else if key.eq_ignore_ascii_case("Table") {
            Some(Self::Table)
        } else if key.eq_ignore_ascii_case("PreUp") {
            Some(Self::PreUp)
        } else if key.eq_ignore_ascii_case("PostUp") {
            Some(Self::PostUp)
        } else if key.eq_ignore_ascii_case("PreDown") {
            Some(Self::PreDown)
        } else if key.eq_ignore_ascii_case("PostDown") {
            Some(Self::PostDown)
        } else if key.eq_ignore_ascii_case("SaveConfig") {
            Some(Self::SaveConfig)
        } else {
            None
        }
    }

    /// Every quick key, in the order `uwg-quick save` writes them.
    pub const ALL: [Self; 9] = [
        Self::Address,
        Self::Dns,
        Self::Mtu,
        Self::Table,
        Self::SaveConfig,
        Self::PreUp,
        Self::PostUp,
        Self::PreDown,
        Self::PostDown,
    ];
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceConfig {
    pub private_key: Option<Key>,
    pub listen_port: Option<u16>,
    pub fwmark: Option<u32>,
    pub obfuscation: ObfuscationConfig,
    pub quick: QuickConfig,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerConfig {
    pub public_key: Key,
    pub preshared_key: Option<Key>,
    /// `Cipher` of the peer: the transport data cipher.
    ///
    /// Missing means [`Cipher::ChaCha20Poly1305`], the historical default.
    pub cipher: Option<Cipher>,
    /// `AdvancedSecurity` of the peer.
    ///
    /// The kernel module owns this setting: `uwg` only reports it through
    /// `UWGPEER_A_ADVANCED_SECURITY` and never sends it to the userspace
    /// UAPI daemon, which has no such key.
    pub advanced_security: Option<bool>,
    pub allowed_ips: Option<Vec<AllowedIp>>,
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive: Option<U16Range>,
    pub remove: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub device: DeviceConfig,
    pub peers: Vec<PeerConfig>,
}

impl Config {
    pub fn parse(input: &str) -> Result<Self, Error> {
        Self::parse_with(input, ParseOptions::default())
    }

    pub fn parse_with(input: &str, options: ParseOptions) -> Result<Self, Error> {
        let document = Document::parse(input)?;
        Self::from_document(&document, options)
    }

    pub fn from_document(document: &Document, options: ParseOptions) -> Result<Self, Error> {
        let mut config = Self::default();
        for section in &document.sections {
            match section.kind {
                SectionKind::Interface => {
                    for entry in &section.entries {
                        config.device.apply_entry(entry, options)?;
                    }
                }
                SectionKind::Peer => {
                    let mut builder = PeerBuilder::default();
                    for entry in &section.entries {
                        builder.apply_entry(entry, options)?;
                    }
                    config.peers.push(builder.finish()?);
                }
                SectionKind::Other => {
                    return Err(Error::UnrecognizedLine {
                        line: section.line,
                        text: format!("[{}]", section.name),
                    });
                }
            }
        }
        Ok(config)
    }

    pub fn from_args<I, S>(args: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let args: Vec<String> = args
            .into_iter()
            .map(|value| value.as_ref().to_owned())
            .collect();
        let mut config = Self::default();
        let mut peer: Option<PeerBuilder> = None;
        let mut index = 0;
        while index < args.len() {
            let key = args[index].as_str();
            if key == "peer" {
                if let Some(builder) = peer.take() {
                    config.peers.push(builder.finish()?);
                }
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| Error::InvalidArgument(key.to_owned()))?;
                peer = Some(PeerBuilder {
                    public_key: Some(Key::from_base64(value)?),
                    ..PeerBuilder::default()
                });
                index += 2;
                continue;
            }
            if key == "remove" {
                let builder = peer
                    .as_mut()
                    .ok_or_else(|| Error::InvalidArgument(key.to_owned()))?;
                builder.remove = true;
                index += 1;
                continue;
            }
            if let Some(builder) = peer.as_mut() {
                if let Some(consumed) = builder.apply_arg(key, &args[index + 1..])? {
                    index += consumed;
                } else {
                    return Err(Error::InvalidArgument(key.to_owned()));
                }
            } else {
                if let Some(consumed) = config.apply_device_arg(key, &args[index + 1..])? {
                    index += consumed;
                } else {
                    return Err(Error::InvalidArgument(key.to_owned()));
                }
            }
        }
        if let Some(builder) = peer.take() {
            config.peers.push(builder.finish()?);
        }
        Ok(config)
    }

    fn apply_device_arg(&mut self, key: &str, rest: &[String]) -> Result<Option<usize>, Error> {
        let Some(value) = rest.first() else {
            return Err(Error::InvalidArgument(key.to_owned()));
        };
        let consumed = match key {
            "listen-port" => {
                self.device.listen_port = Some(parse_u16("listen-port", value)?);
                2
            }
            "fwmark" => {
                self.device.fwmark = Some(parse_fwmark(value)?);
                2
            }
            "private-key" => {
                self.device.private_key = Some(Key::from_file(std::path::Path::new(value))?);
                2
            }
            "jc" => {
                self.device.obfuscation.jc = Some(parse_u16(key, value)?);
                2
            }
            "jmin" => {
                self.device.obfuscation.jmin = Some(parse_u16(key, value)?);
                2
            }
            "jmax" => {
                self.device.obfuscation.jmax = Some(parse_u16(key, value)?);
                2
            }
            "s1" => {
                self.device.obfuscation.s1 = Some(parse_u16(key, value)?);
                2
            }
            "s2" => {
                self.device.obfuscation.s2 = Some(parse_u16(key, value)?);
                2
            }
            "s3" => {
                self.device.obfuscation.s3 = Some(parse_u16(key, value)?);
                2
            }
            "s4" => {
                self.device.obfuscation.s4 = Some(parse_u16(key, value)?);
                2
            }
            "h1" => {
                self.device.obfuscation.h1 = Some(U32Range::parse(value)?);
                2
            }
            "h2" => {
                self.device.obfuscation.h2 = Some(U32Range::parse(value)?);
                2
            }
            "h3" => {
                self.device.obfuscation.h3 = Some(U32Range::parse(value)?);
                2
            }
            "h4" => {
                self.device.obfuscation.h4 = Some(U32Range::parse(value)?);
                2
            }
            "i1" => {
                self.device.obfuscation.i1 = Some(value.clone());
                2
            }
            "i2" => {
                self.device.obfuscation.i2 = Some(value.clone());
                2
            }
            "i3" => {
                self.device.obfuscation.i3 = Some(value.clone());
                2
            }
            "i4" => {
                self.device.obfuscation.i4 = Some(value.clone());
                2
            }
            "i5" => {
                self.device.obfuscation.i5 = Some(value.clone());
                2
            }
            "header-protection-key" => {
                self.device.obfuscation.header_protection_key =
                    Some(Key::from_file(std::path::Path::new(value))?);
                2
            }
            "content-padding-addition" => {
                self.device.obfuscation.content_padding_addition = Some(U16Range::parse(value)?);
                2
            }
            "rekey-after-time" => {
                self.device.obfuscation.rekey_after_time = Some(U16Range::parse(value)?);
                2
            }
            "rekey-timeout" => {
                self.device.obfuscation.rekey_timeout = Some(U16Range::parse(value)?);
                2
            }
            "reject-after-time" => {
                self.device.obfuscation.reject_after_time = Some(U16Range::parse(value)?);
                2
            }
            "keepalive-timeout" => {
                self.device.obfuscation.keepalive_timeout = Some(U16Range::parse(value)?);
                2
            }
            "max-handshake-attempts" => {
                self.device.obfuscation.max_handshake_attempts = Some(U16Range::parse(value)?);
                2
            }
            "random-trailers" => {
                self.device.obfuscation.random_trailers =
                    Some(parse_bool("random-trailers", value)?);
                2
            }
            "disable-cookies" => {
                self.device.obfuscation.disable_cookies =
                    Some(parse_bool("disable-cookies", value)?);
                2
            }
            _ => return Ok(None),
        };
        Ok(Some(consumed))
    }

    pub fn to_document(&self, include_quick: bool) -> Document {
        let mut interface = Section {
            name: "Interface".to_owned(),
            kind: SectionKind::Interface,
            line: 0,
            entries: Vec::new(),
        };
        if let Some(port) = self.device.listen_port {
            push_entry(&mut interface, "ListenPort", port.to_string());
        }
        if let Some(fwmark) = self.device.fwmark {
            push_entry(&mut interface, "FwMark", format!("0x{fwmark:x}"));
        }
        if let Some(key) = &self.device.private_key {
            push_entry(&mut interface, "PrivateKey", key.to_base64());
        }
        let obfuscation = &self.device.obfuscation;
        if let Some(value) = obfuscation.jc {
            push_entry(&mut interface, "Jc", value.to_string());
        }
        if let Some(value) = obfuscation.jmin {
            push_entry(&mut interface, "Jmin", value.to_string());
        }
        if let Some(value) = obfuscation.jmax {
            push_entry(&mut interface, "Jmax", value.to_string());
        }
        if let Some(value) = obfuscation.s1 {
            push_entry(&mut interface, "S1", value.to_string());
        }
        if let Some(value) = obfuscation.s2 {
            push_entry(&mut interface, "S2", value.to_string());
        }
        if let Some(value) = obfuscation.s3 {
            push_entry(&mut interface, "S3", value.to_string());
        }
        if let Some(value) = obfuscation.s4 {
            push_entry(&mut interface, "S4", value.to_string());
        }
        for (index, value) in [
            obfuscation.h1,
            obfuscation.h2,
            obfuscation.h3,
            obfuscation.h4,
        ]
        .into_iter()
        .enumerate()
        {
            if let Some(value) = value {
                if value != U32Range::single(index as u32 + 1) {
                    push_entry(
                        &mut interface,
                        &format!("H{}", index + 1),
                        value.to_string(),
                    );
                }
            }
        }
        for (index, value) in [
            &obfuscation.i1,
            &obfuscation.i2,
            &obfuscation.i3,
            &obfuscation.i4,
            &obfuscation.i5,
        ]
        .into_iter()
        .enumerate()
        {
            if let Some(value) = value {
                push_entry(&mut interface, &format!("I{}", index + 1), value.clone());
            }
        }
        if let Some(key) = &obfuscation.header_protection_key {
            push_entry(&mut interface, "HeaderProtectionKey", key.to_base64());
        }
        for (name, value) in [
            (
                "ContentPaddingAddition",
                obfuscation.content_padding_addition,
            ),
            ("RekeyAfterTime", obfuscation.rekey_after_time),
            ("RekeyTimeout", obfuscation.rekey_timeout),
            ("RejectAfterTime", obfuscation.reject_after_time),
            ("KeepaliveTimeout", obfuscation.keepalive_timeout),
            ("MaxHandshakeAttempts", obfuscation.max_handshake_attempts),
        ] {
            if let Some(value) = value {
                push_entry(&mut interface, name, value.to_string());
            }
        }
        if let Some(value) = obfuscation.random_trailers {
            push_entry(&mut interface, "RandomTrailers", bool_text(value));
        }
        if let Some(value) = obfuscation.disable_cookies {
            push_entry(&mut interface, "DisableCookies", bool_text(value));
        }
        if include_quick {
            let quick = &self.device.quick;
            if !quick.address.is_empty() {
                push_entry(&mut interface, "Address", quick.address.join(", "));
            }
            if !quick.dns.is_empty() {
                push_entry(&mut interface, "DNS", quick.dns.join(", "));
            }
            if let Some(value) = quick.mtu {
                push_entry(&mut interface, "MTU", value.to_string());
            }
            if let Some(value) = &quick.table {
                push_entry(&mut interface, "Table", table_text(value));
            }
            for (name, value) in [
                ("PreUp", &quick.pre_up),
                ("PostUp", &quick.post_up),
                ("PreDown", &quick.pre_down),
                ("PostDown", &quick.post_down),
            ] {
                if let Some(value) = value {
                    push_entry(&mut interface, name, value.clone());
                }
            }
            if let Some(value) = quick.save_config {
                push_entry(&mut interface, "SaveConfig", bool_text(value));
            }
        }

        let mut sections = vec![interface];
        for peer in &self.peers {
            let mut section = Section {
                name: "Peer".to_owned(),
                kind: SectionKind::Peer,
                line: 0,
                entries: Vec::new(),
            };
            push_entry(&mut section, "PublicKey", peer.public_key.to_base64());
            if let Some(key) = &peer.preshared_key {
                push_entry(&mut section, "PresharedKey", key.to_base64());
            }
            if let Some(cipher) = peer.cipher {
                push_entry(&mut section, "Cipher", cipher.to_string());
            }
            if let Some(value) = peer.advanced_security {
                push_entry(&mut section, "AdvancedSecurity", bool_text(value));
            }
            if let Some(allowed_ips) = &peer.allowed_ips {
                if !allowed_ips.is_empty() {
                    let value = allowed_ips
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ");
                    push_entry(&mut section, "AllowedIPs", value);
                }
            }
            if let Some(endpoint) = &peer.endpoint {
                push_entry(&mut section, "Endpoint", format_endpoint(endpoint));
            }
            if let Some(value) = peer.persistent_keepalive {
                if !value.is_zero() {
                    push_entry(&mut section, "PersistentKeepalive", value.to_string());
                }
            }
            sections.push(section);
        }

        Document { sections }
    }

    pub fn to_ini(&self, include_quick: bool) -> String {
        self.to_document(include_quick).to_string()
    }

    /// Allowed IPs whose host bits are not zero.
    ///
    /// The kernel masks them silently, so `uwg` only warns about them.
    pub fn allowed_ips_with_host_bits(&self) -> Vec<AllowedIp> {
        self.peers
            .iter()
            .filter_map(|peer| peer.allowed_ips.as_ref())
            .flatten()
            .filter(|allowed_ip| allowed_ip.has_host_bits())
            .copied()
            .collect()
    }
}

impl DeviceConfig {
    fn apply_entry(&mut self, entry: &Entry, options: ParseOptions) -> Result<(), Error> {
        let key = entry.key.to_ascii_lowercase();
        match key.as_str() {
            "listenport" => {
                self.listen_port = Some(parse_u16_at(entry, "ListenPort", &entry.value)?)
            }
            "fwmark" => self.fwmark = Some(parse_fwmark_at(entry, &entry.value)?),
            "privatekey" => self.private_key = Some(Key::from_base64(&entry.value)?),
            "jc" => self.obfuscation.jc = Some(parse_u16_at(entry, "Jc", &entry.value)?),
            "jmin" => self.obfuscation.jmin = Some(parse_u16_at(entry, "Jmin", &entry.value)?),
            "jmax" => self.obfuscation.jmax = Some(parse_u16_at(entry, "Jmax", &entry.value)?),
            "s1" => self.obfuscation.s1 = Some(parse_u16_at(entry, "S1", &entry.value)?),
            "s2" => self.obfuscation.s2 = Some(parse_u16_at(entry, "S2", &entry.value)?),
            "s3" => self.obfuscation.s3 = Some(parse_u16_at(entry, "S3", &entry.value)?),
            "s4" => self.obfuscation.s4 = Some(parse_u16_at(entry, "S4", &entry.value)?),
            "h1" => self.obfuscation.h1 = Some(parse_range_at(entry, "H1", &entry.value)?),
            "h2" => self.obfuscation.h2 = Some(parse_range_at(entry, "H2", &entry.value)?),
            "h3" => self.obfuscation.h3 = Some(parse_range_at(entry, "H3", &entry.value)?),
            "h4" => self.obfuscation.h4 = Some(parse_range_at(entry, "H4", &entry.value)?),
            "i1" => self.obfuscation.i1 = Some(entry.value.clone()),
            "i2" => self.obfuscation.i2 = Some(entry.value.clone()),
            "i3" => self.obfuscation.i3 = Some(entry.value.clone()),
            "i4" => self.obfuscation.i4 = Some(entry.value.clone()),
            "i5" => self.obfuscation.i5 = Some(entry.value.clone()),
            "headerprotectionkey" => {
                self.obfuscation.header_protection_key = Some(Key::from_base64(&entry.value)?);
            }
            "contentpaddingaddition" => {
                self.obfuscation.content_padding_addition = Some(parse_u16_range_at(
                    entry,
                    "ContentPaddingAddition",
                    &entry.value,
                )?);
            }
            "rekeyaftertime" => {
                self.obfuscation.rekey_after_time =
                    Some(parse_u16_range_at(entry, "RekeyAfterTime", &entry.value)?);
            }
            "rekeytimeout" => {
                self.obfuscation.rekey_timeout =
                    Some(parse_u16_range_at(entry, "RekeyTimeout", &entry.value)?);
            }
            "rejectaftertime" => {
                self.obfuscation.reject_after_time =
                    Some(parse_u16_range_at(entry, "RejectAfterTime", &entry.value)?);
            }
            "keepalivetimeout" => {
                self.obfuscation.keepalive_timeout =
                    Some(parse_u16_range_at(entry, "KeepaliveTimeout", &entry.value)?);
            }
            "maxhandshakeattempts" => {
                self.obfuscation.max_handshake_attempts = Some(parse_u16_range_at(
                    entry,
                    "MaxHandshakeAttempts",
                    &entry.value,
                )?);
            }
            "randomtrailers" => {
                self.obfuscation.random_trailers =
                    Some(parse_bool_at(entry, "RandomTrailers", &entry.value)?);
            }
            "disablecookies" => {
                self.obfuscation.disable_cookies =
                    Some(parse_bool_at(entry, "DisableCookies", &entry.value)?);
            }
            _ => match QuickKey::parse(&entry.key) {
                Some(quick) if options.allow_quick_keys => {
                    self.apply_quick_entry(quick, entry)?;
                }
                _ => {
                    return Err(Error::UnrecognizedKey {
                        line: entry.line,
                        key: entry.key.clone(),
                    });
                }
            },
        }
        Ok(())
    }

    fn apply_quick_entry(&mut self, key: QuickKey, entry: &Entry) -> Result<(), Error> {
        match key {
            QuickKey::Address => self.quick.address.extend(split_list(&entry.value)),
            QuickKey::Dns => self.quick.dns.extend(split_list(&entry.value)),
            QuickKey::Mtu => self.quick.mtu = Some(parse_u32_at(entry, "MTU", &entry.value)?),
            QuickKey::Table => self.quick.table = Some(RoutingTable::parse(&entry.value)?),
            QuickKey::PreUp => self.quick.pre_up = Some(entry.value.clone()),
            QuickKey::PostUp => self.quick.post_up = Some(entry.value.clone()),
            QuickKey::PreDown => self.quick.pre_down = Some(entry.value.clone()),
            QuickKey::PostDown => self.quick.post_down = Some(entry.value.clone()),
            QuickKey::SaveConfig => {
                self.quick.save_config = Some(parse_bool_at(entry, "SaveConfig", &entry.value)?);
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct PeerBuilder {
    public_key: Option<Key>,
    preshared_key: Option<Key>,
    cipher: Option<Cipher>,
    advanced_security: Option<bool>,
    allowed_ips: Option<Vec<AllowedIp>>,
    endpoint: Option<SocketAddr>,
    persistent_keepalive: Option<U16Range>,
    remove: bool,
}

impl PeerBuilder {
    fn apply_entry(&mut self, entry: &Entry, options: ParseOptions) -> Result<(), Error> {
        let key = entry.key.to_ascii_lowercase();
        match key.as_str() {
            "publickey" => self.public_key = Some(Key::from_base64(&entry.value)?),
            "presharedkey" => self.preshared_key = Some(Key::from_base64(&entry.value)?),
            "cipher" => {
                self.cipher = Some(parse_cipher_at(entry, "Cipher", &entry.value)?);
            }
            "advancedsecurity" => {
                self.advanced_security =
                    Some(parse_bool_at(entry, "AdvancedSecurity", &entry.value)?);
            }
            "allowedips" => {
                let parsed = parse_allowed_ips(&entry.value, entry.line, "AllowedIPs")?;
                match &mut self.allowed_ips {
                    Some(list) => list.extend(parsed),
                    None => self.allowed_ips = Some(parsed),
                }
            }
            "endpoint" => {
                self.endpoint = Some(parse_endpoint(&entry.value, options.resolve_endpoints)?);
            }
            "persistentkeepalive" => {
                self.persistent_keepalive = Some(parse_u16_range_at(
                    entry,
                    "PersistentKeepalive",
                    &entry.value,
                )?);
            }
            _ => {
                return Err(Error::UnrecognizedKey {
                    line: entry.line,
                    key: entry.key.clone(),
                });
            }
        }
        Ok(())
    }

    fn apply_arg(&mut self, key: &str, rest: &[String]) -> Result<Option<usize>, Error> {
        let Some(value) = rest.first() else {
            return Err(Error::InvalidArgument(key.to_owned()));
        };
        let consumed = match key {
            "preshared-key" => {
                self.preshared_key = Some(Key::from_file(std::path::Path::new(value))?);
                2
            }
            "endpoint" => {
                self.endpoint = Some(parse_endpoint(value, true)?);
                2
            }
            "cipher" => {
                self.cipher = Some(Cipher::parse(value)?);
                2
            }
            "advanced-security" => {
                self.advanced_security = Some(parse_bool("AdvancedSecurity", value)?);
                2
            }
            "persistent-keepalive" => {
                self.persistent_keepalive = Some(U16Range::parse(value)?);
                2
            }
            "allowed-ips" => {
                let cleaned: String = value
                    .chars()
                    .filter(|value| !value.is_whitespace())
                    .collect();
                self.allowed_ips = Some(parse_allowed_ips(&cleaned, 0, "allowed-ips")?);
                2
            }
            _ => return Ok(None),
        };
        Ok(Some(consumed))
    }

    fn finish(self) -> Result<PeerConfig, Error> {
        Ok(PeerConfig {
            public_key: self.public_key.ok_or(Error::MissingPeerPublicKey)?,
            preshared_key: self.preshared_key,
            cipher: self.cipher,
            advanced_security: self.advanced_security,
            allowed_ips: self.allowed_ips,
            endpoint: self.endpoint,
            persistent_keepalive: self.persistent_keepalive,
            remove: self.remove,
        })
    }
}

fn parse_allowed_ips(value: &str, line: usize, key: &str) -> Result<Vec<AllowedIp>, Error> {
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    value
        .split(',')
        .map(|entry| {
            entry.parse::<AllowedIp>().map_err(|_| Error::InvalidValue {
                line,
                key: key.to_owned(),
                value: entry.to_owned(),
            })
        })
        .collect()
}

fn parse_u16_at(entry: &Entry, key: &str, value: &str) -> Result<u16, Error> {
    parse_u16(key, value).map_err(|_| Error::InvalidValue {
        line: entry.line,
        key: key.to_owned(),
        value: value.to_owned(),
    })
}

fn parse_u32_at(entry: &Entry, key: &str, value: &str) -> Result<u32, Error> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::InvalidValue {
            line: entry.line,
            key: key.to_owned(),
            value: value.to_owned(),
        });
    }
    value.parse::<u32>().map_err(|_| Error::InvalidValue {
        line: entry.line,
        key: key.to_owned(),
        value: value.to_owned(),
    })
}

fn parse_range_at(entry: &Entry, key: &str, value: &str) -> Result<U32Range, Error> {
    U32Range::parse(value).map_err(|_| Error::InvalidValue {
        line: entry.line,
        key: key.to_owned(),
        value: value.to_owned(),
    })
}

fn parse_u16_range_at(entry: &Entry, key: &str, value: &str) -> Result<U16Range, Error> {
    U16Range::parse(value).map_err(|_| Error::InvalidValue {
        line: entry.line,
        key: key.to_owned(),
        value: value.to_owned(),
    })
}

fn parse_bool_at(entry: &Entry, key: &str, value: &str) -> Result<bool, Error> {
    parse_bool(key, value).map_err(|_| Error::InvalidValue {
        line: entry.line,
        key: key.to_owned(),
        value: value.to_owned(),
    })
}

fn parse_cipher_at(entry: &Entry, key: &str, value: &str) -> Result<Cipher, Error> {
    Cipher::parse(value).map_err(|_| Error::InvalidValue {
        line: entry.line,
        key: key.to_owned(),
        value: value.to_owned(),
    })
}

fn parse_u16(key: &str, value: &str) -> Result<u16, Error> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::InvalidValue {
            line: 0,
            key: key.to_owned(),
            value: value.to_owned(),
        });
    }
    value.parse::<u16>().map_err(|_| Error::InvalidValue {
        line: 0,
        key: key.to_owned(),
        value: value.to_owned(),
    })
}

fn parse_bool(key: &str, value: &str) -> Result<bool, Error> {
    if value.eq_ignore_ascii_case("on") || value.eq_ignore_ascii_case("true") {
        return Ok(true);
    }
    if value.eq_ignore_ascii_case("off") || value.eq_ignore_ascii_case("false") {
        return Ok(false);
    }
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::InvalidValue {
            line: 0,
            key: key.to_owned(),
            value: value.to_owned(),
        });
    }
    let number = value.parse::<u32>().map_err(|_| Error::InvalidValue {
        line: 0,
        key: key.to_owned(),
        value: value.to_owned(),
    })?;
    Ok(number != 0)
}

fn parse_fwmark_at(entry: &Entry, value: &str) -> Result<u32, Error> {
    parse_fwmark(value).map_err(|_| Error::InvalidValue {
        line: entry.line,
        key: "FwMark".to_owned(),
        value: value.to_owned(),
    })
}

fn parse_fwmark(value: &str) -> Result<u32, Error> {
    if value.eq_ignore_ascii_case("off") {
        return Ok(0);
    }
    let error = || Error::InvalidValue {
        line: 0,
        key: "FwMark".to_owned(),
        value: value.to_owned(),
    };
    if value.starts_with("0x") && value.len() > 2 {
        u32::from_str_radix(&value[2..], 16).map_err(|_| error())
    } else if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        value.parse::<u32>().map_err(|_| error())
    } else {
        Err(error())
    }
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(|value: char| value == ',' || value.is_whitespace())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// Splits a comma- or whitespace-separated list value (`Address`, `DNS`).
pub fn split_list_value(value: &str) -> Vec<String> {
    split_list(value)
}

/// Classifies a `DNS` entry as a nameserver instead of a search domain.
pub fn is_dns_address(token: &str) -> bool {
    (!token.is_empty()
        && token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.'))
        || token.contains(':')
}

/// Parses a boolean configuration value (`on`/`off`, `true`/`false`, `0`/`1`).
pub fn parse_bool_value(value: &str) -> Result<bool, Error> {
    parse_bool("value", value)
}

fn table_text(value: &RoutingTable) -> String {
    match value {
        RoutingTable::Off => "off".to_owned(),
        RoutingTable::Id(id) => id.to_string(),
        RoutingTable::Name(name) => name.clone(),
    }
}

fn bool_text(value: bool) -> &'static str {
    if value {
        "on"
    } else {
        "off"
    }
}

fn push_entry(section: &mut Section, key: &str, value: impl Into<String>) {
    section.entries.push(Entry {
        key: key.to_owned(),
        value: value.into(),
        line: 0,
    });
}

impl fmt::Display for RoutingTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Off => f.write_str("off"),
            Self::Id(id) => write!(f, "{id}"),
            Self::Name(name) => f.write_str(name),
        }
    }
}

impl FromStr for RoutingTable {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIVATE: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const PUBLIC: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

    const SAMPLE: &str = "\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = 51820
FwMark = 0x1234
Jc = 4
Jmin = 40
Jmax = 70
S1 = 92
S2 = 115
S3 = 44
S4 = 9
H1 = 61220074-118999195
H2 = 605047389-945520346
H3 = 1477291385-1814368140
H4 = 1951993942-1997499713
I1 = <b 0x160d2f><c>
I2 = <r 10>
HeaderProtectionKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
ContentPaddingAddition = 0-100
RekeyAfterTime = 120
RekeyTimeout = 5
RejectAfterTime = 180
KeepaliveTimeout = 10
MaxHandshakeAttempts = 7
RandomTrailers = on
DisableCookies = off

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
PresharedKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Cipher = aes-256-gcm
AdvancedSecurity = on
AllowedIPs = 10.0.0.0/8, fd00::/64
Endpoint = 192.0.2.1:51820
PersistentKeepalive = 25
";

    #[test]
    fn parses_obfuscated_config() {
        let config = Config::parse(SAMPLE).expect("valid config");
        let device = &config.device;
        assert_eq!(device.listen_port, Some(51820));
        assert_eq!(device.fwmark, Some(0x1234));
        assert_eq!(
            device.private_key.as_ref().map(Key::to_base64),
            Some(PRIVATE.to_owned())
        );
        assert_eq!(device.obfuscation.jc, Some(4));
        assert_eq!(device.obfuscation.s4, Some(9));
        assert_eq!(
            device.obfuscation.h1,
            Some(U32Range::new(61_220_074, 118_999_195))
        );
        assert_eq!(device.obfuscation.i1.as_deref(), Some("<b 0x160d2f><c>"));
        assert_eq!(
            device.obfuscation.content_padding_addition,
            Some(U16Range::new(0, 100))
        );
        assert_eq!(device.obfuscation.random_trailers, Some(true));
        assert_eq!(device.obfuscation.disable_cookies, Some(false));
        assert_eq!(config.peers.len(), 1);
        let peer = &config.peers[0];
        assert_eq!(peer.public_key.to_base64(), PUBLIC);
        assert_eq!(peer.allowed_ips.as_ref().map(Vec::len), Some(2));
        assert_eq!(
            peer.endpoint,
            Some("192.0.2.1:51820".parse().expect("valid"))
        );
        assert_eq!(peer.persistent_keepalive, Some(U16Range::single(25)));
        assert_eq!(peer.advanced_security, Some(true));
        assert_eq!(peer.cipher, Some(Cipher::Aes256Gcm));
    }

    #[test]
    fn round_trips_obfuscated_config() {
        let config = Config::parse(SAMPLE).expect("valid config");
        let emitted = config.to_ini(false);
        let reparsed = Config::parse(&emitted).expect("emitted config parses");
        assert_eq!(config, reparsed);
        assert!(emitted.contains("H1 = 61220074-118999195"));
        assert!(emitted.contains("I1 = <b 0x160d2f><c>"));
        assert!(emitted.contains("AllowedIPs = 10.0.0.0/8, fd00::/64"));
        assert!(emitted.contains("AdvancedSecurity = on"));
        assert!(emitted.contains("Cipher = aes-256-gcm"));
    }

    #[test]
    fn parses_peer_cipher() {
        let config = Config::parse(
            "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nCIPHER = AES-256-GCM\n",
        )
        .expect("valid config");
        assert_eq!(config.peers[0].cipher, Some(Cipher::Aes256Gcm));
        assert!(config.to_ini(false).contains("Cipher = aes-256-gcm\n"));

        let config = Config::parse(
            "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nCipher = chacha20-poly1305\n",
        )
        .expect("valid config");
        assert_eq!(config.peers[0].cipher, Some(Cipher::ChaCha20Poly1305));
    }

    #[test]
    fn rejects_bad_peer_cipher() {
        assert!(Config::parse(
            "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nCipher = aes\n"
        )
        .is_err());
        assert!(Config::from_args(["peer", PUBLIC, "cipher", "aes"]).is_err());
    }

    #[test]
    fn omits_cipher_when_unset() {
        let config =
            Config::parse("[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\n")
                .expect("valid config");
        assert_eq!(config.peers[0].cipher, None);
        assert!(!config.to_ini(false).contains("Cipher"));
    }

    #[test]
    fn parses_peer_advanced_security() {
        let config = Config::parse(
            "[Peer]\npublickey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nADVANCEDSECURITY = on\n",
        )
        .expect("valid config");
        assert_eq!(config.peers[0].advanced_security, Some(true));
        let emitted = config.to_ini(false);
        assert!(emitted.contains("AdvancedSecurity = on\n"));

        for value in ["on", "ON", "true", "TRUE", "1"] {
            let input = format!(
                "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAdvancedSecurity = {value}\n"
            );
            let config = Config::parse(&input).expect("valid config");
            assert_eq!(config.peers[0].advanced_security, Some(true), "{value}");
        }
        for value in ["off", "OFF", "false", "False", "0"] {
            let input = format!(
                "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAdvancedSecurity = {value}\n"
            );
            let config = Config::parse(&input).expect("valid config");
            assert_eq!(config.peers[0].advanced_security, Some(false), "{value}");
            assert!(config.to_ini(false).contains("AdvancedSecurity = off\n"));
        }
    }

    #[test]
    fn rejects_bad_peer_advanced_security() {
        assert!(Config::parse(
            "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAdvancedSecurity = maybe\n"
        )
        .is_err());
    }

    #[test]
    fn omits_advanced_security_when_unset() {
        let config =
            Config::parse("[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\n")
                .expect("valid config");
        assert_eq!(config.peers[0].advanced_security, None);
        assert!(!config.to_ini(false).contains("AdvancedSecurity"));
    }

    #[test]
    fn rejects_unknown_keys_and_sections() {
        assert!(Config::parse("[Interface]\nUnknown = 1\n").is_err());
        assert!(Config::parse("[Other]\n").is_err());
        assert!(Config::parse("[Peer]\nPublicKey = x\n").is_err());
        assert!(Config::parse("[Peer]\nAllowedIPs = 10.0.0.0/8\n").is_err());
    }

    #[test]
    fn rejects_bad_values() {
        assert!(Config::parse("[Interface]\nListenPort = 70000\n").is_err());
        assert!(Config::parse("[Interface]\nJc = abc\n").is_err());
        assert!(Config::parse("[Interface]\nH1 = 10-5\n").is_err());
        assert!(Config::parse("[Interface]\nRandomTrailers = maybe\n").is_err());
        assert!(Config::parse("[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 10.0.0.0/33\n").is_err());
        assert!(Config::parse("[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nEndpoint = 10.0.0.1\n").is_err());
    }

    #[test]
    fn quick_keys_require_quick_mode() {
        let input = "[Interface]\nAddress = 10.0.0.2/24, fd00::2/64\nDNS = 1.1.1.1\nMTU = 1420\nTable = off\nPreUp = echo hi\nSaveConfig = true\n";
        assert!(Config::parse(input).is_err());
        let config = Config::parse_with(input, ParseOptions::QUICK).expect("valid");
        assert_eq!(config.device.quick.address.len(), 2);
        assert_eq!(config.device.quick.dns, vec!["1.1.1.1"]);
        assert_eq!(config.device.quick.mtu, Some(1420));
        assert_eq!(config.device.quick.table, Some(RoutingTable::Off));
        assert_eq!(config.device.quick.pre_up.as_deref(), Some("echo hi"));
        assert_eq!(config.device.quick.save_config, Some(true));
        let emitted = config.to_ini(true);
        assert!(emitted.contains("Address = 10.0.0.2/24, fd00::2/64"));
        assert!(emitted.contains("Table = off"));
    }

    #[test]
    fn parses_set_arguments() {
        let args = [
            "listen-port",
            "51820",
            "fwmark",
            "off",
            "jc",
            "4",
            "h1",
            "10-20",
            "random-trailers",
            "on",
            "peer",
            PUBLIC,
            "allowed-ips",
            "10.0.0.0/8,fd00::/64",
            "persistent-keepalive",
            "25",
            "cipher",
            "aes-256-gcm",
            "advanced-security",
            "on",
        ];
        let config = Config::from_args(args).expect("valid arguments");
        assert_eq!(config.device.listen_port, Some(51820));
        assert_eq!(config.device.fwmark, Some(0));
        assert_eq!(config.device.obfuscation.jc, Some(4));
        assert_eq!(config.device.obfuscation.h1, Some(U32Range::new(10, 20)));
        assert_eq!(config.device.obfuscation.random_trailers, Some(true));
        assert_eq!(config.peers.len(), 1);
        assert_eq!(config.peers[0].allowed_ips.as_ref().map(Vec::len), Some(2));
        assert_eq!(config.peers[0].advanced_security, Some(true));
        assert_eq!(config.peers[0].cipher, Some(Cipher::Aes256Gcm));
    }

    #[test]
    fn rejects_bad_set_arguments() {
        assert!(Config::from_args(["unknown"]).is_err());
        assert!(Config::from_args(["listen-port"]).is_err());
        assert!(Config::from_args(["peer", "not-a-key"]).is_err());
        assert!(Config::from_args(["remove"]).is_err());
        assert!(Config::from_args(["peer", PUBLIC, "listen-port", "1"]).is_err());
        assert!(Config::from_args(["fwmark", "0xzz"]).is_err());
    }

    #[test]
    fn empty_allowed_ips_clears_list() {
        let config =
            Config::from_args(["peer", PUBLIC, "allowed-ips", ""]).expect("valid arguments");
        assert_eq!(config.peers[0].allowed_ips, Some(Vec::new()));
    }

    #[test]
    fn routing_table_parsing() {
        assert_eq!(
            RoutingTable::parse("off").expect("valid"),
            RoutingTable::Off
        );
        assert_eq!(
            RoutingTable::parse("100").expect("valid"),
            RoutingTable::Id(100)
        );
        assert_eq!(
            RoutingTable::parse("custom").expect("valid"),
            RoutingTable::Name("custom".to_owned())
        );
        assert_eq!(RoutingTable::Off.to_string(), "off");
        assert_eq!(RoutingTable::Id(7).to_string(), "7");
        assert_eq!(RoutingTable::Name("main".to_owned()).to_string(), "main");
        assert!(RoutingTable::parse("").is_err());
    }

    #[test]
    fn classifies_quick_keys() {
        assert_eq!(QuickKey::parse("Address"), Some(QuickKey::Address));
        assert_eq!(QuickKey::parse("dns"), Some(QuickKey::Dns));
        assert_eq!(QuickKey::parse("MTU"), Some(QuickKey::Mtu));
        assert_eq!(QuickKey::parse("table"), Some(QuickKey::Table));
        assert_eq!(QuickKey::parse("PreUp"), Some(QuickKey::PreUp));
        assert_eq!(QuickKey::parse("postup"), Some(QuickKey::PostUp));
        assert_eq!(QuickKey::parse("PreDown"), Some(QuickKey::PreDown));
        assert_eq!(QuickKey::parse("postdown"), Some(QuickKey::PostDown));
        assert_eq!(QuickKey::parse("SaveConfig"), Some(QuickKey::SaveConfig));
        assert_eq!(QuickKey::parse("PrivateKey"), None);
        assert_eq!(QuickKey::parse("AllowedIPs"), None);
        assert_eq!(QuickKey::ALL.len(), 9);
    }

    #[test]
    fn splits_quick_list_values() {
        assert_eq!(
            split_list_value("10.0.0.2/24, fd00::2/64  ,10.0.0.3/32"),
            ["10.0.0.2/24", "fd00::2/64", "10.0.0.3/32"]
        );
        assert!(split_list_value("  ").is_empty());
    }

    #[test]
    fn classifies_dns_entries() {
        assert!(is_dns_address("1.1.1.1"));
        assert!(is_dns_address("fd00::1"));
        assert!(!is_dns_address("example.com"));
        assert!(!is_dns_address("10.0.0.0/8"));
        assert!(!is_dns_address(""));
    }

    #[test]
    fn parses_boolean_values() {
        assert!(parse_bool_value("on").expect("valid"));
        assert!(parse_bool_value("TRUE").expect("valid"));
        assert!(!parse_bool_value("off").expect("valid"));
        assert!(!parse_bool_value("0").expect("valid"));
        assert!(parse_bool_value("2").expect("valid"));
        assert!(parse_bool_value("yes").is_err());
    }

    #[test]
    fn finds_allowed_ips_with_host_bits() {
        let mut config = Config::default();
        config.peers.push(PeerConfig {
            public_key: Key::from_base64(PUBLIC).expect("valid"),
            preshared_key: None,
            cipher: None,
            advanced_security: None,
            allowed_ips: Some(vec![
                "10.0.0.0/8".parse().expect("valid"),
                "10.1.2.3/8".parse().expect("valid"),
            ]),
            endpoint: None,
            persistent_keepalive: None,
            remove: false,
        });
        let dirty = config.allowed_ips_with_host_bits();
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty[0].to_string(), "10.1.2.3/8");
        assert!(Config::default().allowed_ips_with_host_bits().is_empty());
    }
}
