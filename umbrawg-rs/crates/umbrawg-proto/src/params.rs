//! UmbraWG 3.1 obfuscation parameters and their textual representation.

use core::ops::RangeInclusive;
use core::str::FromStr;

use rand_core::RngCore;
use umbrawg_crypto::{random, Key};

use crate::header_protection::NONCE_LEN;
use crate::messages::{
    limits::DEFAULT_UDP_WINDOW, MESSAGE_DATA, MESSAGE_HANDSHAKE_COOKIE,
    MESSAGE_HANDSHAKE_INITIATION, MESSAGE_HANDSHAKE_RESPONSE, MESSAGE_PADDING_MULTIPLE,
};
use crate::obf::MessageKind;
use crate::special::SpecialPacket;
use crate::{ProtoError, Result};

const HEADER_PROTECTION_MIN_PADDING: u16 = NONCE_LEN as u16;

/// Parsed obfuscation parameters shared by the userspace device and the kernel
/// module configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObfParams {
    /// Magic header range for handshake initiation messages (`H1`).
    pub h1: RangeInclusive<u32>,
    /// Magic header range for handshake response messages (`H2`).
    pub h2: RangeInclusive<u32>,
    /// Magic header range for cookie reply messages (`H3`).
    pub h3: RangeInclusive<u32>,
    /// Magic header range for transport messages (`H4`).
    pub h4: RangeInclusive<u32>,
    /// Junk prefix length for handshake initiation messages (`S1`).
    pub s1: u16,
    /// Junk prefix length for handshake response messages (`S2`).
    pub s2: u16,
    /// Junk prefix length for cookie reply messages (`S3`).
    pub s3: u16,
    /// Junk prefix length for transport messages (`S4`).
    pub s4: u16,
    /// Number of junk packets sent before a handshake (`Jc`).
    pub jc: u16,
    /// Minimum junk packet size (`Jmin`).
    pub jmin: u16,
    /// Maximum junk packet size (`Jmax`).
    pub jmax: u16,
    /// Special packet template `I1`.
    pub i1: Option<SpecialPacket>,
    /// Special packet template `I2`.
    pub i2: Option<SpecialPacket>,
    /// Special packet template `I3`.
    pub i3: Option<SpecialPacket>,
    /// Special packet template `I4`.
    pub i4: Option<SpecialPacket>,
    /// Special packet template `I5`.
    pub i5: Option<SpecialPacket>,
    /// Key used for header protection; a zero key disables protection.
    pub header_protection_key: Option<Key>,
    /// Extra random content padding range (`ContentPaddingAddition`).
    pub content_padding_addition: RangeInclusive<u16>,
    /// Whether random trailers are appended to messages.
    pub random_trailers: bool,
    /// Whether cookie replies are disabled.
    pub disable_cookies: bool,
}

impl Default for ObfParams {
    fn default() -> Self {
        Self {
            h1: MESSAGE_HANDSHAKE_INITIATION..=MESSAGE_HANDSHAKE_INITIATION,
            h2: MESSAGE_HANDSHAKE_RESPONSE..=MESSAGE_HANDSHAKE_RESPONSE,
            h3: MESSAGE_HANDSHAKE_COOKIE..=MESSAGE_HANDSHAKE_COOKIE,
            h4: MESSAGE_DATA..=MESSAGE_DATA,
            s1: 0,
            s2: 0,
            s3: 0,
            s4: 0,
            jc: 0,
            jmin: 0,
            jmax: 0,
            i1: None,
            i2: None,
            i3: None,
            i4: None,
            i5: None,
            header_protection_key: None,
            content_padding_addition: 0..=0,
            random_trailers: false,
            disable_cookies: false,
        }
    }
}

impl ObfParams {
    /// Creates parameters with wire-compatible defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Applies one textual configuration value.
    ///
    /// Only syntax is checked here; cross-field constraints are enforced by
    /// [`Self::validate`] so that partial configurations can be built
    /// incrementally.
    pub fn set_param(&mut self, name: &str, value: &str) -> Result<()> {
        match name {
            "h1" => self.h1 = parse_u32_range_named(name, value)?,
            "h2" => self.h2 = parse_u32_range_named(name, value)?,
            "h3" => self.h3 = parse_u32_range_named(name, value)?,
            "h4" => self.h4 = parse_u32_range_named(name, value)?,
            "s1" => self.s1 = parse_u16_named(name, value)?,
            "s2" => self.s2 = parse_u16_named(name, value)?,
            "s3" => self.s3 = parse_u16_named(name, value)?,
            "s4" => self.s4 = parse_u16_named(name, value)?,
            "jc" => self.jc = parse_u16_named(name, value)?,
            "jmin" => self.jmin = parse_u16_named(name, value)?,
            "jmax" => self.jmax = parse_u16_named(name, value)?,
            "i1" => self.i1 = parse_special_packet(value)?,
            "i2" => self.i2 = parse_special_packet(value)?,
            "i3" => self.i3 = parse_special_packet(value)?,
            "i4" => self.i4 = parse_special_packet(value)?,
            "i5" => self.i5 = parse_special_packet(value)?,
            "header_protection_key" => {
                self.header_protection_key = Some(Key::from_hex(value.trim())?);
            }
            "content_padding_addition" => {
                self.content_padding_addition = parse_u16_range_named(name, value)?;
            }
            "random_trailers" => self.random_trailers = parse_bool(value)?,
            "disable_cookies" => self.disable_cookies = parse_bool(value)?,
            _ => return Err(ProtoError::UnknownParameter(name.to_string())),
        }
        Ok(())
    }

    /// Returns `true` when a non-zero header protection key is configured.
    #[must_use]
    pub fn has_header_protection(&self) -> bool {
        self.header_protection_key
            .as_ref()
            .is_some_and(|key| !key.is_zero())
    }

    /// Returns `true` when content padding addition is enabled.
    #[must_use]
    pub fn content_padding_addition_enabled(&self) -> bool {
        !(self.content_padding_addition.start() == &0 && self.content_padding_addition.end() == &0)
    }

    /// Returns `true` when junk packets are configured.
    #[must_use]
    pub fn junk_enabled(&self) -> bool {
        self.jc > 0 && self.jmax > 0
    }

    /// Returns the number of junk packets to send, or zero when disabled.
    #[must_use]
    pub fn junk_count(&self) -> u16 {
        if self.junk_enabled() {
            self.jc
        } else {
            0
        }
    }

    /// Returns the header range for `kind`.
    #[must_use]
    pub fn header_range(&self, kind: MessageKind) -> &RangeInclusive<u32> {
        match kind {
            MessageKind::Initiation => &self.h1,
            MessageKind::Response => &self.h2,
            MessageKind::Cookie => &self.h3,
            MessageKind::Transport => &self.h4,
        }
    }

    /// Returns the junk prefix length for `kind`.
    #[must_use]
    pub fn padding(&self, kind: MessageKind) -> u16 {
        match kind {
            MessageKind::Initiation => self.s1,
            MessageKind::Response => self.s2,
            MessageKind::Cookie => self.s3,
            MessageKind::Transport => self.s4,
        }
    }

    /// Returns the configured special packets in `I1..I5` order.
    pub fn special_packets(&self) -> impl Iterator<Item = &SpecialPacket> {
        [&self.i1, &self.i2, &self.i3, &self.i4, &self.i5]
            .into_iter()
            .flatten()
            .filter(|packet| !packet.is_empty())
    }

    /// Validates cross-field constraints.
    pub fn validate(&self) -> Result<()> {
        let headers = [
            ("H1", &self.h1),
            ("H2", &self.h2),
            ("H3", &self.h3),
            ("H4", &self.h4),
        ];
        for (name, range) in headers {
            if range.start() > range.end() {
                return Err(ProtoError::InvalidRange(format!(
                    "{name}={}-{}",
                    range.start(),
                    range.end()
                )));
            }
        }
        for (first_index, (_, first)) in headers.iter().enumerate() {
            for (second_index, (_, second)) in headers.iter().enumerate().skip(first_index + 1) {
                if first.start() <= second.end() && second.start() <= first.end() {
                    return Err(ProtoError::OverlappingHeaders {
                        first: first_index as u8 + 1,
                        second: second_index as u8 + 1,
                    });
                }
            }
        }
        if self.jmin > self.jmax {
            return Err(ProtoError::InvalidJunkRange {
                min: self.jmin,
                max: self.jmax,
            });
        }
        if self.has_header_protection() {
            let paddings = [self.s1, self.s2, self.s3, self.s4];
            for (index, value) in paddings.into_iter().enumerate() {
                if value < HEADER_PROTECTION_MIN_PADDING {
                    return Err(ProtoError::HeaderProtectionPadding {
                        index: index as u8 + 1,
                        value,
                        minimum: HEADER_PROTECTION_MIN_PADDING,
                    });
                }
            }
        }
        Ok(())
    }

    /// Validates the parameters and rejects tags unsupported by the kernel.
    pub fn validate_for_kernel(&self) -> Result<()> {
        self.validate()?;
        for packet in [&self.i1, &self.i2, &self.i3, &self.i4, &self.i5]
            .into_iter()
            .flatten()
        {
            packet.validate_for_kernel()?;
        }
        Ok(())
    }

    /// Returns content padding bytes for a transport packet.
    ///
    /// `packet_len` is the packet length including junk prefix, header and
    /// authentication tag. Mirrors `uwg_peer_skb_randomize_padding_addition`.
    pub fn content_padding_len(
        &self,
        rng: &mut impl RngCore,
        packet_len: usize,
        udp_window: usize,
    ) -> usize {
        if !self.content_padding_addition_enabled() || udp_window < packet_len {
            return 0;
        }
        let addition = usize::from(random::u16_inclusive_with(
            rng,
            &self.content_padding_addition,
        ));
        addition.min(udp_window - packet_len)
    }

    /// Returns random trailer bytes for a packet.
    ///
    /// Mirrors `uwg_peer_skb_random_trailer`.
    pub fn random_trailer_len(
        &self,
        rng: &mut impl RngCore,
        packet_len: usize,
        udp_window: usize,
    ) -> usize {
        if !self.random_trailers || udp_window <= packet_len {
            return 0;
        }
        let space = (udp_window - packet_len).min(u32::MAX as usize) as u32;
        random::below_with(rng, space) as usize
    }

    /// Returns random trailer bytes using the default UDP window.
    pub fn default_random_trailer_len(&self, rng: &mut impl RngCore, packet_len: usize) -> usize {
        self.random_trailer_len(rng, packet_len, DEFAULT_UDP_WINDOW as usize)
    }

    /// Returns the padding required to align a payload to 16 bytes within the
    /// MTU. Mirrors `calculate_skb_padding`.
    #[must_use]
    pub fn mtu_padding(payload_len: usize, mtu: usize) -> usize {
        let align = |value: usize| {
            value.saturating_add(MESSAGE_PADDING_MULTIPLE - 1) & !(MESSAGE_PADDING_MULTIPLE - 1)
        };
        if mtu == 0 {
            return align(payload_len) - payload_len;
        }
        let mut last_unit = payload_len;
        if last_unit > mtu {
            last_unit %= mtu;
        }
        align(last_unit).min(mtu) - last_unit
    }
}

fn parse_special_packet(value: &str) -> Result<Option<SpecialPacket>> {
    let packet = SpecialPacket::parse(value)?;
    if packet.tags().is_empty() {
        Ok(None)
    } else {
        Ok(Some(packet))
    }
}

fn parse_u32_range_named(name: &str, value: &str) -> Result<RangeInclusive<u32>> {
    parse_range(name, value, |raw| parse_number(name, raw))
}

fn parse_u16_range_named(name: &str, value: &str) -> Result<RangeInclusive<u16>> {
    parse_range(name, value, |raw| parse_number(name, raw))
}

fn parse_range<T: FromStr + Ord + Copy>(
    name: &str,
    value: &str,
    parse: impl Fn(&str) -> Result<T>,
) -> Result<RangeInclusive<T>> {
    let value = value.trim();
    let (low, high) = match value.split_once('-') {
        Some((low, high)) => (parse(low)?, parse(high)?),
        None => {
            let single = parse(value)?;
            (single, single)
        }
    };
    if low > high {
        return Err(ProtoError::InvalidRange(format!("{name}={value}")));
    }
    Ok(low..=high)
}

fn parse_number<T: FromStr>(name: &str, value: &str) -> Result<T> {
    let value = value.trim();
    if value.is_empty() {
        return Err(ProtoError::InvalidValue {
            name: name.to_string(),
            value: value.to_string(),
        });
    }
    value.parse().map_err(|_| ProtoError::InvalidValue {
        name: name.to_string(),
        value: value.to_string(),
    })
}

fn parse_u16_named(name: &str, value: &str) -> Result<u16> {
    parse_number(name, value)
}

/// Parses a `u32` range in `"lo-hi"` or `"value"` form.
pub fn parse_u32_range(value: &str) -> Result<RangeInclusive<u32>> {
    parse_u32_range_named("range", value)
}

/// Parses a `u16` range in `"lo-hi"` or `"value"` form.
pub fn parse_u16_range(value: &str) -> Result<RangeInclusive<u16>> {
    parse_u16_range_named("range", value)
}

/// Parses an unsigned 16-bit decimal size.
pub fn parse_u16_size(value: &str) -> Result<u16> {
    parse_u16_named("size", value)
}

/// Parses a Go-compatible boolean value.
///
/// Accepts `1`/`0`, the `strconv.ParseBool` spellings of `true`/`false`, and
/// the `on`/`off` spellings used by `uwg` for `AdvancedSecurity`.
pub fn parse_bool(value: &str) -> Result<bool> {
    match value.trim() {
        "1" | "t" | "T" | "TRUE" | "true" | "True" | "on" | "ON" | "On" => Ok(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" | "off" | "OFF" | "Off" => Ok(false),
        other => Err(ProtoError::InvalidValue {
            name: "bool".to_string(),
            value: other.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedRng(u32);

    impl RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            let value = self.0;
            self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            value
        }

        fn next_u64(&mut self) -> u64 {
            u64::from(self.next_u32()) << 32 | u64::from(self.next_u32())
        }

        fn fill_bytes(&mut self, dst: &mut [u8]) {
            for chunk in dst.chunks_mut(4) {
                let value = self.next_u32().to_le_bytes();
                let length = chunk.len();
                chunk.copy_from_slice(&value[..length]);
            }
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> std::result::Result<(), rand_core::Error> {
            self.fill_bytes(dst);
            Ok(())
        }
    }

    #[test]
    fn defaults_match_wireguard_types() {
        let params = ObfParams::default();
        assert_eq!(params.h1, 1..=1);
        assert_eq!(params.h2, 2..=2);
        assert_eq!(params.h3, 3..=3);
        assert_eq!(params.h4, 4..=4);
        assert!(!params.has_header_protection());
        assert!(!params.junk_enabled());
        assert!(params.validate().is_ok());
    }

    #[test]
    fn parses_ranges() {
        assert_eq!(
            parse_u32_range("712026294-712074283").unwrap(),
            712026294..=712074283
        );
        assert_eq!(parse_u32_range("42").unwrap(), 42..=42);
        assert_eq!(parse_u32_range(" 1 - 2 ").unwrap(), 1..=2);
        assert!(parse_u32_range("10-5").is_err());
        assert!(parse_u32_range("").is_err());
        assert!(parse_u32_range("1-2-3").is_err());
        assert!(parse_u32_range("-1").is_err());
        assert!(parse_u32_range("4294967296").is_err());
        assert_eq!(parse_u16_range("0-100").unwrap(), 0..=100);
        assert!(parse_u16_range("70000").is_err());
        assert_eq!(parse_u16_size("12").unwrap(), 12);
        assert!(parse_u16_size("65536").is_err());
    }

    #[test]
    fn parses_go_booleans() {
        for value in ["1", "t", "T", "TRUE", "true", "True", "on", "ON"] {
            assert!(parse_bool(value).unwrap());
        }
        for value in ["0", "f", "F", "FALSE", "false", "False", "off", "OFF"] {
            assert!(!parse_bool(value).unwrap());
        }
        assert!(parse_bool("yes").is_err());
    }

    #[test]
    fn set_param_handles_every_field() {
        let mut params = ObfParams::default();
        let values = [
            ("h1", "100-200"),
            ("h2", "201"),
            ("h3", "300-400"),
            ("h4", "500-600"),
            ("s1", "12"),
            ("s2", "13"),
            ("s3", "14"),
            ("s4", "15"),
            ("jc", "3"),
            ("jmin", "10"),
            ("jmax", "20"),
            ("i1", "<b 0x01><r 2>"),
            ("i2", "<rc 3>"),
            ("i3", "<rd 4>"),
            ("i4", "<t>"),
            ("i5", "<c>"),
            ("content_padding_addition", "0-64"),
            ("random_trailers", "true"),
            ("disable_cookies", "1"),
        ];
        for (name, value) in values {
            params.set_param(name, value).unwrap();
        }
        params
            .set_param("header_protection_key", &"11".repeat(32))
            .unwrap();
        assert_eq!(params.h1, 100..=200);
        assert_eq!(params.s4, 15);
        assert_eq!(params.jc, 3);
        assert_eq!(params.i1.as_ref().unwrap().len(), 3);
        assert!(params.has_header_protection());
        assert!(params.content_padding_addition_enabled());
        assert!(params.random_trailers);
        assert!(params.disable_cookies);
        assert!(params.validate().is_ok());
    }

    #[test]
    fn set_param_rejects_invalid_input() {
        let mut params = ObfParams::default();
        assert!(matches!(
            params.set_param("unknown", "1"),
            Err(ProtoError::UnknownParameter(_))
        ));
        assert!(params.set_param("h1", "bad").is_err());
        assert!(params.set_param("s1", "70000").is_err());
        assert!(params.set_param("i1", "<b 0xzz>").is_err());
        assert!(params.set_param("header_protection_key", "00").is_err());
        assert!(params.set_param("random_trailers", "maybe").is_err());
    }

    #[test]
    fn empty_special_packet_disables_slot() {
        let mut params = ObfParams::default();
        params.set_param("i1", "").unwrap();
        assert!(params.i1.is_none());
        params.set_param("i2", "<d>").unwrap();
        assert!(params.i2.as_ref().unwrap().is_empty());
        assert_eq!(params.special_packets().count(), 0);
    }

    #[test]
    fn validate_detects_header_overlap() {
        let mut params = ObfParams::default();
        params.set_param("h1", "1-10").unwrap();
        params.set_param("h2", "10-20").unwrap();
        assert_eq!(
            params.validate(),
            Err(ProtoError::OverlappingHeaders {
                first: 1,
                second: 2
            })
        );
    }

    #[test]
    fn validate_accepts_adjacent_headers() {
        let mut params = ObfParams::default();
        params.set_param("h1", "1-5").unwrap();
        params.set_param("h2", "6-10").unwrap();
        params.set_param("h3", "11-20").unwrap();
        params.set_param("h4", "21-30").unwrap();
        assert!(params.validate().is_ok());
    }

    #[test]
    fn validate_requires_long_prefixes_for_header_protection() {
        let mut params = ObfParams::default();
        params
            .set_param("header_protection_key", &"22".repeat(32))
            .unwrap();
        params.set_param("s1", "11").unwrap();
        assert_eq!(
            params.validate(),
            Err(ProtoError::HeaderProtectionPadding {
                index: 1,
                value: 11,
                minimum: 12
            })
        );
        params.set_param("s1", "12").unwrap();
        params.set_param("s2", "12").unwrap();
        params.set_param("s3", "12").unwrap();
        params.set_param("s4", "12").unwrap();
        assert!(params.validate().is_ok());
    }

    #[test]
    fn zero_key_disables_header_protection() {
        let mut params = ObfParams::default();
        params
            .set_param("header_protection_key", &"00".repeat(32))
            .unwrap();
        assert!(!params.has_header_protection());
        assert!(params.validate().is_ok());
    }

    #[test]
    fn validate_rejects_bad_junk_range() {
        let mut params = ObfParams::default();
        params.set_param("jmin", "20").unwrap();
        params.set_param("jmax", "10").unwrap();
        assert_eq!(
            params.validate(),
            Err(ProtoError::InvalidJunkRange { min: 20, max: 10 })
        );
    }

    #[test]
    fn kernel_validation_rejects_extended_tags() {
        let mut params = ObfParams::default();
        params.set_param("i1", "<r 1>").unwrap();
        assert!(params.validate_for_kernel().is_ok());
        params.set_param("i2", "<ds>").unwrap();
        assert!(matches!(
            params.validate_for_kernel(),
            Err(ProtoError::TagNotSupportedByKernel { .. })
        ));
    }

    #[test]
    fn special_packets_iterates_non_empty_slots() {
        let mut params = ObfParams::default();
        params.set_param("i2", "<r 1>").unwrap();
        params.set_param("i5", "<t>").unwrap();
        assert_eq!(params.special_packets().count(), 2);
    }

    #[test]
    fn content_padding_respects_window() {
        let mut params = ObfParams::default();
        params
            .set_param("content_padding_addition", "0-100")
            .unwrap();
        let mut rng = FixedRng(0);
        assert_eq!(params.content_padding_len(&mut rng, 500, 500), 0);
        let value = params.content_padding_len(&mut rng, 400, 500);
        assert!(value <= 100);
        let disabled = ObfParams::default();
        assert_eq!(disabled.content_padding_len(&mut rng, 10, 500), 0);
    }

    #[test]
    fn random_trailer_respects_window() {
        let mut params = ObfParams::default();
        params.set_param("random_trailers", "true").unwrap();
        let mut rng = FixedRng(7);
        assert_eq!(params.random_trailer_len(&mut rng, 500, 500), 0);
        assert_eq!(params.random_trailer_len(&mut rng, 600, 500), 0);
        let value = params.random_trailer_len(&mut rng, 400, 500);
        assert!(value < 100);
        let disabled = ObfParams::default();
        assert_eq!(disabled.random_trailer_len(&mut rng, 10, 500), 0);
    }

    #[test]
    fn mtu_padding_matches_kernel() {
        assert_eq!(ObfParams::mtu_padding(0, 0), 0);
        assert_eq!(ObfParams::mtu_padding(1, 0), 15);
        assert_eq!(ObfParams::mtu_padding(16, 0), 0);
        assert_eq!(ObfParams::mtu_padding(17, 0), 15);
        assert_eq!(ObfParams::mtu_padding(100, 1500), 12);
        assert_eq!(ObfParams::mtu_padding(1500, 1500), 0);
        assert_eq!(ObfParams::mtu_padding(10, 8), 6);
    }
}
