mod support;

use rand_core::RngCore;
use support::{hex, TestRng};
use umbrawg_proto::{
    CookieReply, HandshakeInitiation, HandshakeResponse, MessageType, ProtoError, TransportPacket,
};

const GO_INITIATION: &str = "4433221188776655202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f808182838485868788898a8b8c8d8e8f909192939495969798999a9ba0a1a2a3a4a5a6a7a8a9aaabacadaeafc0c1c2c3c4c5c6c7c8c9cacbcccdcecf";
const GO_RESPONSE: &str = "04030201080706050c0b0a09202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f606162636465666768696a6b6c6d6e6f808182838485868788898a8b8c8d8e8f";
const GO_COOKIE: &str = "0d0c0b0a11100f0e303132333435363738393a3b3c3d3e3f4041424344454647505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f";

fn pattern(start: u8, length: usize) -> Vec<u8> {
    (0..length).map(|index| start + index as u8).collect()
}

#[test]
fn initiation_layout_matches_go() {
    let mut buffer = [0u8; HandshakeInitiation::SIZE];
    {
        let mut message = HandshakeInitiation::from_array(&mut buffer);
        message.set_message_type(0x1122_3344);
        message.set_sender_index(0x5566_7788);
        message.ephemeral_mut().copy_from_slice(&pattern(0x20, 32));
        message
            .encrypted_static_mut()
            .copy_from_slice(&pattern(0x40, 48));
        message
            .encrypted_timestamp_mut()
            .copy_from_slice(&pattern(0x80, 28));
        message.mac1_mut().copy_from_slice(&pattern(0xa0, 16));
        message.mac2_mut().copy_from_slice(&pattern(0xc0, 16));
        assert_eq!(message.message_type(), 0x1122_3344);
        assert_eq!(message.sender_index(), 0x5566_7788);
    }
    assert_eq!(buffer.to_vec(), hex(GO_INITIATION));
}

#[test]
fn initiation_parses_go_vector() {
    let mut bytes = hex(GO_INITIATION);
    let message = HandshakeInitiation::parse(&mut bytes).unwrap();
    assert_eq!(message.message_type(), 0x1122_3344);
    assert_eq!(message.sender_index(), 0x5566_7788);
    assert_eq!(message.ephemeral().as_slice(), pattern(0x20, 32).as_slice());
    assert_eq!(
        message.encrypted_static().as_slice(),
        pattern(0x40, 48).as_slice()
    );
    assert_eq!(
        message.encrypted_timestamp().as_slice(),
        pattern(0x80, 28).as_slice()
    );
    assert_eq!(message.mac1().as_slice(), pattern(0xa0, 16).as_slice());
    assert_eq!(message.mac2().as_slice(), pattern(0xc0, 16).as_slice());
}

#[test]
fn response_layout_matches_go() {
    let mut buffer = [0u8; HandshakeResponse::SIZE];
    {
        let mut message = HandshakeResponse::from_array(&mut buffer);
        message.set_message_type(0x0102_0304);
        message.set_sender_index(0x0506_0708);
        message.set_receiver_index(0x090a_0b0c);
        message.ephemeral_mut().copy_from_slice(&pattern(0x20, 32));
        message
            .encrypted_nothing_mut()
            .copy_from_slice(&pattern(0x40, 16));
        message.mac1_mut().copy_from_slice(&pattern(0x60, 16));
        message.mac2_mut().copy_from_slice(&pattern(0x80, 16));
    }
    assert_eq!(buffer.to_vec(), hex(GO_RESPONSE));
    let mut bytes = buffer;
    let message = HandshakeResponse::parse(&mut bytes).unwrap();
    assert_eq!(message.receiver_index(), 0x090a_0b0c);
    assert_eq!(message.sender_index(), 0x0506_0708);
}

#[test]
fn cookie_layout_matches_go() {
    let mut buffer = [0u8; CookieReply::SIZE];
    {
        let mut message = CookieReply::from_array(&mut buffer);
        message.set_message_type(0x0a0b_0c0d);
        message.set_receiver_index(0x0e0f_1011);
        message.nonce_mut().copy_from_slice(&pattern(0x30, 24));
        message
            .encrypted_cookie_mut()
            .copy_from_slice(&pattern(0x50, 32));
    }
    assert_eq!(buffer.to_vec(), hex(GO_COOKIE));
    let mut bytes = buffer;
    let message = CookieReply::parse(&mut bytes).unwrap();
    assert_eq!(message.receiver_index(), 0x0e0f_1011);
    assert_eq!(message.nonce().as_slice(), pattern(0x30, 24).as_slice());
}

#[test]
fn macs_are_mutable_together() {
    let mut buffer = [0u8; HandshakeInitiation::SIZE];
    let mut message = HandshakeInitiation::from_array(&mut buffer);
    {
        let (mac1, mac2) = message.macs_mut();
        mac1.fill(0xaa);
        mac2.fill(0xbb);
    }
    assert_eq!(message.mac1(), &[0xaa; 16]);
    assert_eq!(message.mac2(), &[0xbb; 16]);
}

#[test]
fn transport_header_fields_are_little_endian() {
    let mut buffer = vec![0u8; 32];
    let mut packet = TransportPacket::parse(&mut buffer).unwrap();
    packet.set_message_type(4);
    packet.set_receiver_index(0x0a0b_0c0d);
    packet.set_counter(0x0102_0304_0506_0708);
    assert_eq!(packet.header()[..4], [4, 0, 0, 0]);
    assert_eq!(packet.header()[4..8], [0x0d, 0x0c, 0x0b, 0x0a]);
    assert_eq!(packet.header()[8..16], [8, 7, 6, 5, 4, 3, 2, 1]);
    assert_eq!(packet.receiver_index(), 0x0a0b_0c0d);
    assert_eq!(packet.counter(), 0x0102_0304_0506_0708);
    assert_eq!(packet.encrypted_content().len(), 16);
    assert_eq!(packet.plaintext_len(), 0);
}

#[test]
fn wrong_lengths_are_rejected() {
    let mut short = vec![0u8; 10];
    assert!(matches!(
        HandshakeInitiation::parse(&mut short),
        Err(ProtoError::InvalidLength { .. })
    ));
    assert!(matches!(
        HandshakeResponse::parse(&mut short),
        Err(ProtoError::InvalidLength { .. })
    ));
    assert!(matches!(
        CookieReply::parse(&mut short),
        Err(ProtoError::InvalidLength { .. })
    ));
    assert!(matches!(
        TransportPacket::parse(&mut short),
        Err(ProtoError::BufferTooSmall { .. })
    ));
}

#[test]
fn message_type_mapping() {
    assert_eq!(
        MessageType::try_from(1).unwrap(),
        MessageType::HandshakeInitiation
    );
    assert_eq!(MessageType::try_from(4).unwrap(), MessageType::Transport);
    assert_eq!(MessageType::from_u32(77), MessageType::Invalid);
    assert_eq!(MessageType::HandshakeInitiation.fixed_size(), Some(148));
    assert_eq!(MessageType::Transport.fixed_size(), Some(16));
    assert_eq!(MessageType::Invalid.fixed_size(), None);
}

#[test]
fn rng_is_deterministic() {
    let mut first = TestRng::new(7);
    let mut second = TestRng::new(7);
    let mut left = [0u8; 40];
    let mut right = [0u8; 40];
    first.fill_bytes(&mut left);
    second.fill_bytes(&mut right);
    assert_eq!(left, right);
}
