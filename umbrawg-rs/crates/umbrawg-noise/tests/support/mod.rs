#![allow(dead_code)]

use rand_core::{Error as RngError, RngCore};
use umbrawg_crypto::tai64n::Tai64N;
use umbrawg_crypto::{Key, PublicKey};
use umbrawg_noise::{Handshake, Result, StaticIdentity};
use umbrawg_proto::messages::{INITIATION_SIZE, RESPONSE_SIZE};
use umbrawg_proto::{HandshakeInitiation, HandshakeResponse};

pub struct SequenceRng {
    next: u8,
}

impl SequenceRng {
    pub const fn new(start: u8) -> Self {
        Self { next: start }
    }
}

impl RngCore for SequenceRng {
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
            *byte = self.next;
            self.next = self.next.wrapping_add(1);
        }
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), RngError> {
        self.fill_bytes(dst);
        Ok(())
    }
}

pub fn pattern(start: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = start.wrapping_add(index as u8);
    }
    bytes
}

pub fn clamped(mut bytes: [u8; 32]) -> [u8; 32] {
    bytes[0] &= 248;
    bytes[31] = (bytes[31] & 127) | 64;
    bytes
}

pub fn psk() -> Key {
    Key::from_bytes(clamped(pattern(0x81)))
}

pub fn timestamp(unix_seconds: u64, nanos: u32) -> Tai64N {
    Tai64N::from_parts(unix_seconds, nanos)
}

pub fn consume_initiation(
    identity: &StaticIdentity,
    handshake: &mut Handshake,
    raw: &mut [u8; INITIATION_SIZE],
) -> Result<()> {
    let message = HandshakeInitiation::parse(raw)?;
    let initiation = identity.decrypt_initiation(&message)?;
    handshake.consume_initiation(initiation, &message)
}

pub fn consume_response(
    identity: &StaticIdentity,
    handshake: &mut Handshake,
    raw: &mut [u8; RESPONSE_SIZE],
) -> Result<()> {
    let message = HandshakeResponse::parse(raw)?;
    handshake.consume_response(identity, &message)
}

pub fn decode_hex(input: &str) -> Vec<u8> {
    assert_eq!(input.len() % 2, 0);
    let bytes = input.as_bytes();
    (0..bytes.len() / 2)
        .map(|index| (nibble(bytes[index * 2]) << 4) | nibble(bytes[index * 2 + 1]))
        .collect()
}

pub fn hex_to_array<const N: usize>(input: &str) -> [u8; N] {
    let decoded = decode_hex(input);
    assert_eq!(decoded.len(), N);
    let mut out = [0u8; N];
    out.copy_from_slice(&decoded);
    out
}

pub fn public_key(hex: &str) -> PublicKey {
    PublicKey::from_bytes(hex_to_array::<32>(hex))
}

fn nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hexadecimal character"),
    }
}
