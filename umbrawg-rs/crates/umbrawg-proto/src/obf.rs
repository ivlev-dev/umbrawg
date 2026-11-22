//! Outgoing and incoming obfuscation for all four message types.

use core::ops::Range;

use rand_core::RngCore;
use umbrawg_crypto::{random, Key};

use crate::header_protection::{self, NONCE_LEN};
use crate::messages::{
    MESSAGE_DATA, MESSAGE_HANDSHAKE_COOKIE, MESSAGE_HANDSHAKE_INITIATION,
    MESSAGE_HANDSHAKE_RESPONSE, TRANSPORT_HEADER_SIZE,
};
use crate::params::ObfParams;
use crate::special::SpecialPacket;
use crate::{ProtoError, Result};

/// The four obfuscated message kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MessageKind {
    /// Handshake initiation.
    Initiation,
    /// Handshake response.
    Response,
    /// Cookie reply.
    Cookie,
    /// Transport data.
    Transport,
}

impl MessageKind {
    /// All message kinds in numeric order.
    pub const ALL: [Self; 4] = [
        Self::Initiation,
        Self::Response,
        Self::Cookie,
        Self::Transport,
    ];

    /// Detection order: transport first.
    ///
    /// With `random_trailers` every kind's length gate is relaxed to `>=`, so
    /// each packet is also compared against the magic ranges of the three
    /// control kinds. Their ranges are only a few thousand values wide, but a
    /// transport packet is decoded at the wrong offset for those checks and
    /// therefore hits a control range completely at random: with the reference
    /// profile (`H1..H3` ~69k of 2^32) that silently dropped ~4 packets per
    /// second under full load, and each drop collapsed the TCP congestion
    /// window. A genuine transport packet always decodes into `H4` at its own
    /// offset, so checking it first removes the false positives from the hot
    /// path; only handshakes keep a ~4e-6 chance of matching `H4` by accident,
    /// which the handshake retry covers.
    const DETECTION_ORDER: [Self; 4] = [
        Self::Transport,
        Self::Initiation,
        Self::Response,
        Self::Cookie,
    ];

    /// Returns the numeric message type.
    #[must_use]
    pub const fn message_type(self) -> u32 {
        match self {
            Self::Initiation => MESSAGE_HANDSHAKE_INITIATION,
            Self::Response => MESSAGE_HANDSHAKE_RESPONSE,
            Self::Cookie => MESSAGE_HANDSHAKE_COOKIE,
            Self::Transport => MESSAGE_DATA,
        }
    }

    /// Returns the fixed protected body size.
    #[must_use]
    pub const fn body_len(self) -> usize {
        match self {
            Self::Initiation => crate::messages::INITIATION_SIZE,
            Self::Response => crate::messages::RESPONSE_SIZE,
            Self::Cookie => crate::messages::COOKIE_REPLY_SIZE,
            Self::Transport => TRANSPORT_HEADER_SIZE,
        }
    }
}

/// Layout of an outgoing fixed-size message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedLayout {
    /// Length of the random junk prefix.
    pub padding: usize,
    /// Range of the protected message body within the packet.
    pub body: Range<usize>,
    /// Total packet length including the random trailer.
    pub total: usize,
}

/// Layout of an outgoing transport header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportLayout {
    /// Length of the random junk prefix.
    pub padding: usize,
    /// Range of the protected transport header within the packet.
    pub header: Range<usize>,
}

/// Result of classifying an incoming packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DetectedPacket {
    /// Detected message kind.
    pub kind: MessageKind,
    /// Length of the junk prefix.
    pub padding: usize,
    /// Length of the protected body.
    pub body_len: usize,
}

impl DetectedPacket {
    /// Returns the protected body slice.
    #[must_use]
    pub fn body<'a>(&self, packet: &'a [u8]) -> Option<&'a [u8]> {
        packet.get(self.padding..self.padding.checked_add(self.body_len)?)
    }

    /// Returns the mutable protected body slice.
    pub fn body_mut<'a>(&self, packet: &'a mut [u8]) -> Option<&'a mut [u8]> {
        let end = self.padding.checked_add(self.body_len)?;
        packet.get_mut(self.padding..end)
    }
}

/// Applies and removes UmbraWG 3.1 obfuscation.
#[derive(Clone, Copy, Debug)]
pub struct Obfuscator<'a> {
    params: &'a ObfParams,
}

impl<'a> Obfuscator<'a> {
    /// Creates an obfuscator over `params`.
    #[must_use]
    pub const fn new(params: &'a ObfParams) -> Self {
        Self { params }
    }

    /// Returns the underlying parameters.
    #[must_use]
    pub const fn params(&self) -> &'a ObfParams {
        self.params
    }

    /// Returns the active header protection key, if any.
    #[must_use]
    pub fn header_key(&self) -> Option<&'a Key> {
        self.params
            .header_protection_key
            .as_ref()
            .filter(|key| !key.is_zero())
    }

    /// Returns `true` when header protection is enabled.
    #[must_use]
    pub fn has_header_protection(&self) -> bool {
        self.header_key().is_some()
    }

    /// Returns `true` when any obfuscation feature differs from the plain
    /// WireGuard defaults.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        let params = self.params;
        params.s1 != 0
            || params.s2 != 0
            || params.s3 != 0
            || params.s4 != 0
            || params.junk_enabled()
            || params.has_header_protection()
            || params.random_trailers
            || params.content_padding_addition_enabled()
            || params.i1.is_some()
            || params.i2.is_some()
            || params.i3.is_some()
            || params.i4.is_some()
            || params.i5.is_some()
            || params.h1 != (MESSAGE_HANDSHAKE_INITIATION..=MESSAGE_HANDSHAKE_INITIATION)
            || params.h2 != (MESSAGE_HANDSHAKE_RESPONSE..=MESSAGE_HANDSHAKE_RESPONSE)
            || params.h3 != (MESSAGE_HANDSHAKE_COOKIE..=MESSAGE_HANDSHAKE_COOKIE)
            || params.h4 != (MESSAGE_DATA..=MESSAGE_DATA)
    }

    /// Picks a magic header value for `kind`.
    #[must_use]
    pub fn pick_header(&self, kind: MessageKind, rng: &mut impl RngCore) -> u32 {
        random::u32_inclusive_with(rng, self.params.header_range(kind))
    }

    /// Returns the number of junk packets to send before a handshake.
    #[must_use]
    pub fn junk_count(&self) -> u16 {
        self.params.junk_count()
    }

    /// Returns a random junk packet length.
    #[must_use]
    pub fn junk_packet_len(&self, rng: &mut impl RngCore) -> usize {
        if !self.params.junk_enabled() {
            return 0;
        }
        usize::from(random::u16_inclusive_with(
            rng,
            &(self.params.jmin..=self.params.jmax),
        ))
    }

    /// Fills `dst` with one junk packet and returns its length.
    pub fn write_junk(&self, rng: &mut impl RngCore, dst: &mut [u8]) -> Result<usize> {
        let len = self.junk_packet_len(rng);
        if dst.len() < len {
            return Err(ProtoError::BufferTooSmall {
                required: len,
                available: dst.len(),
            });
        }
        rng.fill_bytes(&mut dst[..len]);
        Ok(len)
    }

    /// Returns the special packet templates in `I1..I5` order.
    pub fn special_packets(&self) -> impl Iterator<Item = &'a SpecialPacket> {
        self.params.special_packets()
    }

    /// Prepares an outgoing fixed-size message.
    ///
    /// Writes the random junk prefix, selects the magic header and writes it at
    /// the start of the body, and fills the random trailer. Returns the selected
    /// header value and the resulting layout.
    ///
    /// The caller must fill `dst[layout.body]` and compute the message MACs
    /// afterwards, then call [`Self::finish_fixed`] to apply header protection.
    pub fn begin_fixed(
        &self,
        kind: MessageKind,
        rng: &mut impl RngCore,
        udp_window: usize,
        dst: &mut [u8],
    ) -> Result<(u32, FixedLayout)> {
        let body_len = kind.body_len();
        let padding = usize::from(self.params.padding(kind));
        let trailer = self
            .params
            .random_trailer_len(rng, padding + body_len, udp_window);
        let total = padding + body_len + trailer;
        if dst.len() < total {
            return Err(ProtoError::BufferTooSmall {
                required: total,
                available: dst.len(),
            });
        }
        if self.has_header_protection() && padding < NONCE_LEN {
            return Err(ProtoError::HeaderProtectionPrefixTooShort {
                padding,
                minimum: NONCE_LEN,
            });
        }
        rng.fill_bytes(&mut dst[..padding]);
        let header = self.pick_header(kind, rng);
        dst[padding..padding + 4].copy_from_slice(&header.to_le_bytes());
        rng.fill_bytes(&mut dst[padding + body_len..total]);
        Ok((
            header,
            FixedLayout {
                padding,
                body: padding..padding + body_len,
                total,
            },
        ))
    }

    /// Applies header protection to a message prepared by [`Self::begin_fixed`].
    pub fn finish_fixed(
        &self,
        kind: MessageKind,
        dst: &mut [u8],
        layout: &FixedLayout,
    ) -> Result<()> {
        let body_len = kind.body_len();
        if layout.body.start != layout.padding || layout.body.len() != body_len {
            return Err(ProtoError::InvalidLength {
                expected: body_len,
                actual: layout.body.len(),
            });
        }
        if layout.total < layout.body.end {
            return Err(ProtoError::InvalidLength {
                expected: layout.body.end,
                actual: layout.total,
            });
        }
        if dst.len() < layout.total {
            return Err(ProtoError::BufferTooSmall {
                required: layout.total,
                available: dst.len(),
            });
        }
        if let Some(key) = self.header_key() {
            let nonce = header_protection::nonce_from_packet(dst).ok_or(
                ProtoError::HeaderProtectionPrefixTooShort {
                    padding: layout.padding,
                    minimum: NONCE_LEN,
                },
            )?;
            header_protection::xor(key, &nonce, &mut dst[layout.body.clone()]);
        }
        Ok(())
    }

    /// Prepares an outgoing transport header.
    ///
    /// Writes the `S4` junk prefix, the magic type, receiver index and counter,
    /// and applies header protection to the 16-byte transport header. The
    /// caller encrypts the content that follows `layout.header.end` in place.
    pub fn begin_transport(
        &self,
        rng: &mut impl RngCore,
        dst: &mut [u8],
        receiver_index: u32,
        counter: u64,
    ) -> Result<TransportLayout> {
        let padding = usize::from(self.params.s4);
        let end = padding + TRANSPORT_HEADER_SIZE;
        if dst.len() < end {
            return Err(ProtoError::BufferTooSmall {
                required: end,
                available: dst.len(),
            });
        }
        if self.has_header_protection() && padding < NONCE_LEN {
            return Err(ProtoError::HeaderProtectionPrefixTooShort {
                padding,
                minimum: NONCE_LEN,
            });
        }
        rng.fill_bytes(&mut dst[..padding]);
        let header = self.pick_header(MessageKind::Transport, rng);
        dst[padding..padding + 4].copy_from_slice(&header.to_le_bytes());
        dst[padding + 4..padding + 8].copy_from_slice(&receiver_index.to_le_bytes());
        dst[padding + 8..end].copy_from_slice(&counter.to_le_bytes());
        if let Some(key) = self.header_key() {
            let nonce = header_protection::nonce_from_packet(dst).ok_or(
                ProtoError::HeaderProtectionPrefixTooShort {
                    padding,
                    minimum: NONCE_LEN,
                },
            )?;
            header_protection::xor(key, &nonce, &mut dst[padding..end]);
        }
        Ok(TransportLayout {
            padding,
            header: padding..end,
        })
    }

    /// Applies or removes header protection on an arbitrary header slice.
    pub fn protect(&self, nonce: &[u8; NONCE_LEN], data: &mut [u8]) -> Result<()> {
        if let Some(key) = self.header_key() {
            header_protection::xor(key, nonce, data);
        }
        Ok(())
    }

    /// Decodes the obfuscated message type at `offset` in `packet`.
    #[must_use]
    pub fn decode_type(&self, packet: &[u8], offset: usize) -> Option<u32> {
        let mask = self.type_mask(packet);
        self.decode_masked_type(packet, offset, mask.as_ref())
    }

    fn type_mask(&self, packet: &[u8]) -> Option<[u8; 4]> {
        let key = self.header_key()?;
        let nonce = header_protection::nonce_from_packet(packet)?;
        Some(header_protection::mask4(key, &nonce))
    }

    fn decode_masked_type(
        &self,
        packet: &[u8],
        offset: usize,
        mask: Option<&[u8; 4]>,
    ) -> Option<u32> {
        let field: [u8; 4] = packet
            .get(offset..offset.checked_add(4)?)?
            .try_into()
            .ok()?;
        let raw = u32::from_le_bytes(field);
        match self.header_key() {
            Some(_) => {
                let mask = mask?;
                Some(raw ^ u32::from_le_bytes(*mask))
            }
            None => Some(raw),
        }
    }

    /// Classifies an incoming packet and returns its layout.
    #[must_use]
    pub fn detect(&self, packet: &[u8]) -> Option<DetectedPacket> {
        let mask = self.type_mask(packet);
        for kind in MessageKind::DETECTION_ORDER {
            if let Some(detected) = self.match_kind(packet, kind, mask.as_ref()) {
                return Some(detected);
            }
        }
        None
    }

    fn match_kind(
        &self,
        packet: &[u8],
        kind: MessageKind,
        mask: Option<&[u8; 4]>,
    ) -> Option<DetectedPacket> {
        let padding = usize::from(self.params.padding(kind));
        let expected = if kind == MessageKind::Transport {
            padding.checked_add(crate::messages::TRANSPORT_MIN_SIZE)?
        } else {
            padding.checked_add(kind.body_len())?
        };
        let length_ok = if kind == MessageKind::Transport || self.params.random_trailers {
            packet.len() >= expected
        } else {
            packet.len() == expected
        };
        if !length_ok {
            return None;
        }
        let header = self.decode_masked_type(packet, padding, mask)?;
        if !self.params.header_range(kind).contains(&header) {
            return None;
        }
        Some(DetectedPacket {
            kind,
            padding,
            body_len: kind.body_len(),
        })
    }

    /// Classifies an incoming packet and removes header protection in place.
    ///
    /// The ChaCha20 block that masks the message type is reused for the first
    /// [`header_protection::BLOCK_LEN`] bytes of the header, so a transport
    /// packet needs a single keystream block instead of two.
    pub fn open_incoming(&self, packet: &mut [u8]) -> Option<DetectedPacket> {
        let Some(key) = self.header_key() else {
            return self.detect(packet);
        };
        let nonce = header_protection::nonce_from_packet(packet)?;
        let mut stream = header_protection::HeaderStream::new(key, &nonce);
        let mask = stream.mask4();
        let detected = MessageKind::DETECTION_ORDER
            .into_iter()
            .find_map(|kind| self.match_kind(packet, kind, Some(&mask)))?;
        let end = detected.padding + detected.body_len;
        stream.apply(packet.get_mut(detected.padding..end)?);
        Some(detected)
    }

    /// Removes header protection from a detected packet body.
    pub fn unprotect(&self, kind: MessageKind, packet: &mut [u8], padding: usize) -> Result<()> {
        let body_len = kind.body_len();
        let end = padding + body_len;
        if packet.len() < end {
            return Err(ProtoError::BufferTooSmall {
                required: end,
                available: packet.len(),
            });
        }
        if let Some(key) = self.header_key() {
            let nonce = header_protection::nonce_from_packet(packet).ok_or(
                ProtoError::HeaderProtectionPrefixTooShort {
                    padding,
                    minimum: NONCE_LEN,
                },
            )?;
            header_protection::xor(key, &nonce, &mut packet[padding..end]);
        }
        Ok(())
    }

    /// Removes header protection using a detected layout.
    pub fn unprotect_detected(&self, packet: &mut [u8], detected: DetectedPacket) -> Result<()> {
        self.unprotect(detected.kind, packet, detected.padding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_kinds_have_expected_sizes() {
        assert_eq!(MessageKind::Initiation.body_len(), 148);
        assert_eq!(MessageKind::Response.body_len(), 92);
        assert_eq!(MessageKind::Cookie.body_len(), 64);
        assert_eq!(MessageKind::Transport.body_len(), 16);
        for (index, kind) in MessageKind::ALL.into_iter().enumerate() {
            assert_eq!(kind.message_type(), index as u32 + 1);
        }
    }

    struct FixedRng(u64);

    impl RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (self.0 >> 32) as u32
        }

        fn next_u64(&mut self) -> u64 {
            (u64::from(self.next_u32()) << 32) | u64::from(self.next_u32())
        }

        fn fill_bytes(&mut self, dst: &mut [u8]) {
            for chunk in dst.chunks_mut(4) {
                let bytes = self.next_u32().to_le_bytes();
                let length = chunk.len();
                chunk.copy_from_slice(&bytes[..length]);
            }
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> std::result::Result<(), rand_core::Error> {
            self.fill_bytes(dst);
            Ok(())
        }
    }

    fn protected_params() -> ObfParams {
        let mut params = ObfParams::default();
        params.set_param("s1", "16").unwrap();
        params.set_param("s2", "16").unwrap();
        params.set_param("s3", "16").unwrap();
        params.set_param("s4", "16").unwrap();
        params.set_param("h1", "1000-2000").unwrap();
        params.set_param("h2", "3000-4000").unwrap();
        params.set_param("h3", "5000-6000").unwrap();
        params.set_param("h4", "7000-8000").unwrap();
        params
            .set_param("header_protection_key", &"5a".repeat(32))
            .unwrap();
        params.validate().unwrap();
        params
    }

    #[test]
    fn open_incoming_matches_detect_and_unprotect() {
        let params = protected_params();
        let obfuscator = Obfuscator::new(&params);
        for kind in MessageKind::ALL {
            let mut rng = FixedRng(u64::from(kind.message_type()));
            let trailer = if kind == MessageKind::Transport {
                48
            } else {
                0
            };
            let mut packet = vec![0u8; 16 + kind.body_len() + trailer];
            match kind {
                MessageKind::Transport => {
                    obfuscator
                        .begin_transport(&mut rng, &mut packet, 0x1122_3344, 7)
                        .unwrap();
                }
                _ => {
                    let (_, layout) = obfuscator
                        .begin_fixed(kind, &mut rng, 500, &mut packet)
                        .unwrap();
                    obfuscator.finish_fixed(kind, &mut packet, &layout).unwrap();
                }
            }
            let detected = obfuscator.detect(&packet).unwrap();
            assert_eq!(detected.kind, kind);
            let mut expected = packet.clone();
            obfuscator
                .unprotect_detected(&mut expected, detected)
                .unwrap();
            let mut actual = packet.clone();
            let detected = obfuscator.open_incoming(&mut actual).unwrap();
            assert_eq!(detected.kind, kind);
            assert_eq!(detected.padding, 16);
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn open_incoming_without_header_protection_keeps_bytes() {
        let mut params = ObfParams::default();
        params.set_param("s4", "12").unwrap();
        let obfuscator = Obfuscator::new(&params);
        let mut rng = FixedRng(3);
        let mut packet = vec![0u8; 12 + MessageKind::Transport.body_len() + 16];
        obfuscator
            .begin_transport(&mut rng, &mut packet, 1, 2)
            .unwrap();
        let original = packet.clone();
        let detected = obfuscator.open_incoming(&mut packet).unwrap();
        assert_eq!(detected.kind, MessageKind::Transport);
        assert_eq!(packet, original);
    }

    #[test]
    fn open_incoming_rejects_short_packets() {
        let params = protected_params();
        let obfuscator = Obfuscator::new(&params);
        assert!(obfuscator.open_incoming(&mut [0u8; 8]).is_none());
        assert!(obfuscator.open_incoming(&mut [0u8; 40]).is_none());
    }

    #[test]
    fn open_incoming_reuses_one_block_for_control_messages() {
        let params = protected_params();
        let obfuscator = Obfuscator::new(&params);
        let mut rng = FixedRng(11);
        let kind = MessageKind::Initiation;
        let mut packet = vec![0u8; 16 + kind.body_len()];
        let (_, layout) = obfuscator
            .begin_fixed(kind, &mut rng, 500, &mut packet)
            .unwrap();
        obfuscator.finish_fixed(kind, &mut packet, &layout).unwrap();
        let mut expected = packet.clone();
        let detected = obfuscator.detect(&packet).unwrap();
        obfuscator
            .unprotect_detected(&mut expected, detected)
            .unwrap();
        let detected = obfuscator.open_incoming(&mut packet).unwrap();
        assert_eq!(detected.body_len, kind.body_len());
        assert_eq!(packet, expected);
    }
}
