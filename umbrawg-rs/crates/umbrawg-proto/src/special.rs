//! Special packet templates used by `I1..I5`.
//!
//! A template is a sequence of tags copied from the textual configuration
//! format. The kernel module supports `<b>`, `<c>`, `<t>`, `<r>`, `<rc>` and
//! `<rd>`; the userspace implementation additionally understands the Go-only
//! `<d>`, `<ds>` and `<dz>` tags. Use [`SpecialPacket::parse_strict`] or
//! [`SpecialPacket::validate_for_kernel`] when a configuration must be
//! accepted by the kernel module.

use rand_core::RngCore;

use crate::{hex, ProtoError, Result};

/// Maximum size of a special packet, matching `JP_MAX_PACKET_SIZE`.
pub const MAX_SPECIAL_PACKET_SIZE: usize = 65_535;

const ALNUM: &[u8; 52] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Values substituted into a special packet at send time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SpecialPacketContext {
    /// Current Unix time in seconds for the `<t>` tag.
    pub unix_time: u32,
    /// Per-peer packet counter for the `<c>` tag.
    pub counter: u32,
}

/// One component of a special packet template.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tag {
    /// `<b 0x...>`: a fixed byte sequence.
    Bytes(Vec<u8>),
    /// `<r N>`: `N` random bytes.
    Random(usize),
    /// `<rc N>`: `N` random ASCII letters.
    RandomChars(usize),
    /// `<rd N>`: `N` random decimal digits.
    RandomDigits(usize),
    /// `<t>`: the current Unix time as a big-endian `u32`.
    Timestamp,
    /// `<c>`: the per-peer packet counter as a big-endian `u32`.
    Counter,
    /// `<d>`: dynamic payload placeholder.
    Data,
    /// `<ds>`: base64 dynamic payload placeholder.
    DataString,
    /// `<dz N>`: dynamic payload length encoded in `N` big-endian bytes.
    DataSize(usize),
}

impl Tag {
    /// Returns the textual tag name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Bytes(_) => "b",
            Self::Random(_) => "r",
            Self::RandomChars(_) => "rc",
            Self::RandomDigits(_) => "rd",
            Self::Timestamp => "t",
            Self::Counter => "c",
            Self::Data => "d",
            Self::DataString => "ds",
            Self::DataSize(_) => "dz",
        }
    }

    /// Returns the number of bytes this tag contributes.
    #[must_use]
    pub const fn len(&self) -> usize {
        match self {
            Self::Bytes(bytes) => bytes.len(),
            Self::Random(len) | Self::RandomChars(len) | Self::RandomDigits(len) => *len,
            Self::Timestamp | Self::Counter => 4,
            Self::Data | Self::DataString => 0,
            Self::DataSize(len) => *len,
        }
    }

    /// Returns `true` if the tag contributes no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns `true` if the kernel module supports the tag.
    #[must_use]
    pub const fn is_kernel_compatible(&self) -> bool {
        !matches!(self, Self::Data | Self::DataString | Self::DataSize(_))
    }
}

/// A parsed special packet template.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpecialPacket {
    parts: Vec<Tag>,
    size: usize,
}

impl SpecialPacket {
    /// Parses a template, accepting the userspace tag union.
    pub fn parse(spec: &str) -> Result<Self> {
        Self::build(spec, false)
    }

    /// Parses a template and rejects tags unsupported by the kernel module.
    pub fn parse_strict(spec: &str) -> Result<Self> {
        Self::build(spec, true)
    }

    fn build(spec: &str, strict: bool) -> Result<Self> {
        let parts = parse_tags(spec, strict)?;
        let mut size = 0usize;
        for part in &parts {
            size = size
                .checked_add(part.len())
                .ok_or(ProtoError::SpecialPacketTooLarge(usize::MAX))?;
            if size > MAX_SPECIAL_PACKET_SIZE {
                return Err(ProtoError::SpecialPacketTooLarge(size));
            }
        }
        Ok(Self { parts, size })
    }

    /// Returns the encoded size in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.size
    }

    /// Returns `true` if the template encodes no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Returns the parsed tags.
    #[must_use]
    pub fn tags(&self) -> &[Tag] {
        &self.parts
    }

    /// Returns `true` if the template contains the `<c>` counter tag.
    #[must_use]
    pub fn uses_counter(&self) -> bool {
        self.parts.iter().any(|tag| matches!(tag, Tag::Counter))
    }

    /// Returns an error if the template uses tags unsupported by the kernel.
    pub fn validate_for_kernel(&self) -> Result<()> {
        if let Some(tag) = self.parts.iter().find(|tag| !tag.is_kernel_compatible()) {
            return Err(ProtoError::TagNotSupportedByKernel {
                tag: tag.name().to_string(),
            });
        }
        Ok(())
    }

    /// Encodes the template into `dst`, returning the number of bytes written.
    ///
    /// Dynamic payload tags decode as an empty payload: `<d>` and `<ds>`
    /// contribute nothing, while `<dz N>` writes `N` zero bytes representing
    /// the zero-length payload.
    pub fn encode(
        &self,
        rng: &mut impl RngCore,
        context: &SpecialPacketContext,
        dst: &mut [u8],
    ) -> Result<usize> {
        if dst.len() < self.size {
            return Err(ProtoError::BufferTooSmall {
                required: self.size,
                available: dst.len(),
            });
        }
        let mut written = 0usize;
        for part in &self.parts {
            let start = written;
            let end = start + part.len();
            match part {
                Tag::Bytes(bytes) => dst[start..end].copy_from_slice(bytes),
                Tag::Random(len) => {
                    let _ = len;
                    rng.fill_bytes(&mut dst[start..end]);
                }
                Tag::RandomChars(len) => {
                    let _ = len;
                    rng.fill_bytes(&mut dst[start..end]);
                    for byte in &mut dst[start..end] {
                        *byte = ALNUM[usize::from(*byte) % ALNUM.len()];
                    }
                }
                Tag::RandomDigits(len) => {
                    let _ = len;
                    rng.fill_bytes(&mut dst[start..end]);
                    for byte in &mut dst[start..end] {
                        *byte = b'0' + (*byte % 10);
                    }
                }
                Tag::Timestamp => {
                    dst[start..end].copy_from_slice(&context.unix_time.to_be_bytes());
                }
                Tag::Counter => {
                    dst[start..end].copy_from_slice(&context.counter.to_be_bytes());
                }
                Tag::Data | Tag::DataString => {}
                Tag::DataSize(len) => {
                    let _ = len;
                    dst[start..end].fill(0);
                }
            }
            written = end;
        }
        Ok(written)
    }
}

fn parse_tags(spec: &str, strict: bool) -> Result<Vec<Tag>> {
    let mut parts = Vec::new();
    let mut rest = spec;
    while let Some(start) = rest.find('<') {
        let after_open = &rest[start + 1..];
        let Some(end) = after_open.find('>') else {
            return Err(ProtoError::InvalidTag {
                tag: after_open.to_string(),
                reason: "missing closing '>'".to_string(),
            });
        };
        let inner = &after_open[..end];
        parts.push(parse_tag(inner, strict)?);
        rest = &after_open[end + 1..];
    }
    Ok(parts)
}

fn parse_tag(inner: &str, strict: bool) -> Result<Tag> {
    let mut fields = inner.split_whitespace();
    let key = fields.next().ok_or_else(|| ProtoError::InvalidTag {
        tag: inner.to_string(),
        reason: "empty tag".to_string(),
    })?;
    let value = fields.next();
    if fields.next().is_some() {
        return Err(ProtoError::InvalidTag {
            tag: inner.to_string(),
            reason: "too many arguments".to_string(),
        });
    }
    match key {
        "b" => {
            let raw = value.ok_or_else(|| invalid_tag(inner, "missing hexadecimal value"))?;
            let stripped = raw
                .strip_prefix("0x")
                .or_else(|| raw.strip_prefix("0X"))
                .unwrap_or(raw);
            if stripped.is_empty() {
                return Err(invalid_tag(inner, "empty hexadecimal value"));
            }
            let bytes = hex::decode_hex(stripped)
                .ok_or_else(|| invalid_tag(inner, "invalid hexadecimal value"))?;
            Ok(Tag::Bytes(bytes))
        }
        "r" => Ok(Tag::Random(parse_size(inner, value)?)),
        "rc" => Ok(Tag::RandomChars(parse_size(inner, value)?)),
        "rd" => Ok(Tag::RandomDigits(parse_size(inner, value)?)),
        "t" => {
            require_no_value(inner, value)?;
            Ok(Tag::Timestamp)
        }
        "c" => {
            require_no_value(inner, value)?;
            Ok(Tag::Counter)
        }
        "d" => {
            require_no_value(inner, value)?;
            reject_extended(strict, "d")?;
            Ok(Tag::Data)
        }
        "ds" => {
            require_no_value(inner, value)?;
            reject_extended(strict, "ds")?;
            Ok(Tag::DataString)
        }
        "dz" => {
            let size = parse_size(inner, value)?;
            reject_extended(strict, "dz")?;
            Ok(Tag::DataSize(size))
        }
        _ => Err(invalid_tag(inner, &format!("unknown tag name '{key}'"))),
    }
}

fn invalid_tag(tag: &str, reason: &str) -> ProtoError {
    ProtoError::InvalidTag {
        tag: tag.to_string(),
        reason: reason.to_string(),
    }
}

fn require_no_value(inner: &str, value: Option<&str>) -> Result<()> {
    if value.is_some() {
        return Err(invalid_tag(inner, "unexpected argument"));
    }
    Ok(())
}

fn reject_extended(strict: bool, tag: &str) -> Result<()> {
    if strict {
        return Err(ProtoError::TagNotSupportedByKernel {
            tag: tag.to_string(),
        });
    }
    Ok(())
}

fn parse_size(inner: &str, value: Option<&str>) -> Result<usize> {
    let raw = value.ok_or_else(|| invalid_tag(inner, "missing size"))?;
    if !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_tag(
            inner,
            "size must be a non-negative decimal integer",
        ));
    }
    let size: usize = raw
        .parse()
        .map_err(|_| invalid_tag(inner, "size is out of range"))?;
    if size > MAX_SPECIAL_PACKET_SIZE {
        return Err(ProtoError::SpecialPacketTooLarge(size));
    }
    Ok(size)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedRng(u8);

    impl RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0u8; 4];
            self.fill_bytes(&mut bytes);
            u32::from_le_bytes(bytes)
        }

        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0u8; 8];
            self.fill_bytes(&mut bytes);
            u64::from_le_bytes(bytes)
        }

        fn fill_bytes(&mut self, dst: &mut [u8]) {
            for byte in dst {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> std::result::Result<(), rand_core::Error> {
            self.fill_bytes(dst);
            Ok(())
        }
    }

    fn context() -> SpecialPacketContext {
        SpecialPacketContext {
            unix_time: 0x0102_0304,
            counter: 0x0506_0708,
        }
    }

    #[test]
    fn parses_all_kernel_tags_in_order() {
        let packet = SpecialPacket::parse("<b 0xdeadbeef><r 3><rc 4><rd 2><t><c>").unwrap();
        assert_eq!(packet.len(), 4 + 3 + 4 + 2 + 4 + 4);
        assert_eq!(
            packet.tags().iter().map(Tag::name).collect::<Vec<_>>(),
            ["b", "r", "rc", "rd", "t", "c"]
        );
        assert!(packet.validate_for_kernel().is_ok());
        assert!(packet.uses_counter());
    }

    #[test]
    fn accepts_hex_without_prefix() {
        assert_eq!(
            SpecialPacket::parse("<b deadBEEF>").unwrap().tags(),
            &[Tag::Bytes(vec![0xde, 0xad, 0xbe, 0xef])]
        );
    }

    #[test]
    fn encodes_static_timestamp_and_counter() {
        let packet = SpecialPacket::parse("<b 0x0a0b><t><c>").unwrap();
        let mut buffer = [0u8; 10];
        let written = packet
            .encode(&mut FixedRng(0), &context(), &mut buffer)
            .unwrap();
        assert_eq!(written, 10);
        assert_eq!(
            buffer,
            [0x0a, 0x0b, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
    }

    #[test]
    fn encodes_random_alphabets() {
        let packet = SpecialPacket::parse("<rc 64><rd 64>").unwrap();
        let mut buffer = [0u8; 128];
        packet
            .encode(&mut FixedRng(0), &context(), &mut buffer)
            .unwrap();
        assert!(buffer[..64].iter().all(u8::is_ascii_alphabetic));
        assert!(buffer[64..].iter().all(u8::is_ascii_digit));
    }

    #[test]
    fn rejects_empty_and_malformed_tags() {
        assert!(SpecialPacket::parse("<b 0x>").is_err());
        assert!(SpecialPacket::parse("<b>").is_err());
        assert!(SpecialPacket::parse("<r>").is_err());
        assert!(SpecialPacket::parse("<r -1>").is_err());
        assert!(SpecialPacket::parse("<r 1 2>").is_err());
        assert!(SpecialPacket::parse("<x 1>").is_err());
        assert!(SpecialPacket::parse("<t 1>").is_err());
        assert!(SpecialPacket::parse("<b 0x0>").is_err());
        assert!(SpecialPacket::parse("<unknown>").is_err());
        assert!(SpecialPacket::parse("<r 70000>").is_err());
        assert!(SpecialPacket::parse("<b 0x00><r 65535>").is_err());
    }

    #[test]
    fn missing_angle_bracket_is_an_error() {
        assert!(matches!(
            SpecialPacket::parse("<r 3"),
            Err(ProtoError::InvalidTag { .. })
        ));
    }

    #[test]
    fn empty_spec_is_empty_packet() {
        let packet = SpecialPacket::parse("").unwrap();
        assert!(packet.is_empty());
        let mut buffer = [0u8; 1];
        assert_eq!(
            packet
                .encode(&mut FixedRng(0), &context(), &mut buffer)
                .unwrap(),
            0
        );
        assert!(SpecialPacket::parse("plain text without tags")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn strict_parser_rejects_extended_tags() {
        assert!(SpecialPacket::parse("<d><ds><dz 4>").is_ok());
        for spec in ["<d>", "<ds>", "<dz 4>"] {
            assert!(matches!(
                SpecialPacket::parse_strict(spec),
                Err(ProtoError::TagNotSupportedByKernel { .. })
            ));
        }
        assert!(SpecialPacket::parse_strict("<b 0x00><r 1>").is_ok());
    }

    #[test]
    fn extended_tags_follow_go_semantics() {
        let packet = SpecialPacket::parse("<d><ds><dz 3>").unwrap();
        assert_eq!(packet.len(), 3);
        assert!(packet.validate_for_kernel().is_err());
        let mut buffer = [0xffu8; 3];
        packet
            .encode(&mut FixedRng(0), &context(), &mut buffer)
            .unwrap();
        assert_eq!(buffer, [0, 0, 0]);
    }

    #[test]
    fn encode_checks_buffer_size() {
        let packet = SpecialPacket::parse("<r 8>").unwrap();
        let mut buffer = [0u8; 7];
        assert!(matches!(
            packet.encode(&mut FixedRng(0), &context(), &mut buffer),
            Err(ProtoError::BufferTooSmall { .. })
        ));
    }
}
