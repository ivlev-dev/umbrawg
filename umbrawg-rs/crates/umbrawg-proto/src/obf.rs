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
    /// All message kinds in detection order.
    pub const ALL: [Self; 4] = [
        Self::Initiation,
        Self::Response,
        Self::Cookie,
        Self::Transport,
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
        for kind in MessageKind::ALL {
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
                continue;
            }
            let Some(header) = self.decode_masked_type(packet, padding, mask.as_ref()) else {
                continue;
            };
            if self.params.header_range(kind).contains(&header) {
                return Some(DetectedPacket {
                    kind,
                    padding,
                    body_len: kind.body_len(),
                });
            }
        }
        None
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
}
