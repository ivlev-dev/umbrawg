mod support;

use support::{hex, TestRng};
use umbrawg_crypto::{aead, Key};
use umbrawg_proto::header_protection;
use umbrawg_proto::messages::{limits::DEFAULT_UDP_WINDOW, INITIATION_SIZE};
use umbrawg_proto::{
    DetectedPacket, FixedLayout, HandshakeInitiation, MessageKind, ObfParams, Obfuscator,
    ProtoError, SpecialPacketContext, TransportPacket,
};

const HP_KEY: &str = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";

fn no_obfuscation() -> ObfParams {
    ObfParams::default()
}

#[test]
fn plain_defaults_roundtrip() {
    let params = no_obfuscation();
    let obfuscator = Obfuscator::new(&params);
    assert!(!obfuscator.is_enabled());

    let mut packet = [0u8; INITIATION_SIZE];
    let mut rng = TestRng::new(1);
    let (header, layout) = obfuscator
        .begin_fixed(
            MessageKind::Initiation,
            &mut rng,
            DEFAULT_UDP_WINDOW as usize,
            &mut packet,
        )
        .unwrap();
    assert_eq!(header, 1);
    assert_eq!(layout.padding, 0);
    assert_eq!(layout.body, 0..INITIATION_SIZE);
    assert_eq!(layout.total, INITIATION_SIZE);
    {
        let mut message = HandshakeInitiation::parse(&mut packet).unwrap();
        assert_eq!(message.message_type(), 1);
        message.set_sender_index(42);
    }
    obfuscator
        .finish_fixed(MessageKind::Initiation, &mut packet, &layout)
        .unwrap();

    let detected = obfuscator.detect(&packet).unwrap();
    assert_eq!(
        detected,
        DetectedPacket {
            kind: MessageKind::Initiation,
            padding: 0,
            body_len: INITIATION_SIZE
        }
    );
    obfuscator
        .unprotect_detected(&mut packet, detected)
        .unwrap();
    let message = HandshakeInitiation::parse(&mut packet).unwrap();
    assert_eq!(message.sender_index(), 42);
}

#[test]
fn header_range_and_prefix_roundtrip() {
    let mut params = no_obfuscation();
    params.set_param("h1", "1000-2000").unwrap();
    params.set_param("s1", "24").unwrap();
    let obfuscator = Obfuscator::new(&params);
    let mut rng = TestRng::new(2);
    let mut packet = [0u8; 24 + INITIATION_SIZE];

    let (header, layout) = obfuscator
        .begin_fixed(MessageKind::Initiation, &mut rng, 500, &mut packet)
        .unwrap();
    assert!((1000..=2000).contains(&header));
    assert_eq!(layout.padding, 24);
    assert_eq!(layout.body, 24..24 + INITIATION_SIZE);
    assert_ne!(&packet[..24], &[0u8; 24]);

    let detected = obfuscator.detect(&packet).unwrap();
    assert_eq!(detected.kind, MessageKind::Initiation);
    assert_eq!(detected.padding, 24);
    assert_eq!(obfuscator.decode_type(&packet, 24), Some(header));
    assert_eq!(
        u32::from_le_bytes(packet[24..28].try_into().unwrap()),
        header
    );
}

#[test]
fn header_protection_matches_go_vector() {
    let mut params = no_obfuscation();
    params.set_param("header_protection_key", HP_KEY).unwrap();
    let obfuscator = Obfuscator::new(&params);
    let nonce = *b"UmbraWGS1234";
    let mut data = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f90919293");
    obfuscator.protect(&nonce, &mut data).unwrap();
    assert_eq!(data, hex("55385888977c1fd5c623e75ce6123e1b82179e2a9fdc4e0ca708c6c7fa02948191dfdaf48528dc824af9c3c46caa3d63e39659d7378e5e46f6cfeac37742a9d89abedf10f2a0e3fa9b4317821dad78e2fcb7719f0999f06a2149a82172cc5e574d1015cadf5a91d80a7e3ce732fbd8f2c6982cca97ebe0d0a406de1590b7722b414d1796a40c8ccdf7ab6488d87df6afae3e5bf8"));
    obfuscator.protect(&nonce, &mut data).unwrap();
    assert_eq!(data, hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f90919293"));
    assert_eq!(
        header_protection::mask4(&Key::from_hex(HP_KEY).unwrap(), b"UmbraWGS1234"),
        [0x55, 0x39, 0x5a, 0x8b]
    );
}

#[test]
fn header_protection_roundtrip_and_detection() {
    let mut params = no_obfuscation();
    params.set_param("header_protection_key", HP_KEY).unwrap();
    params.set_param("h1", "7000-7100").unwrap();
    params.set_param("s1", "12").unwrap();
    let obfuscator = Obfuscator::new(&params);
    assert!(obfuscator.has_header_protection());
    let mut rng = TestRng::new(3);
    let mut packet = [0u8; 12 + INITIATION_SIZE];

    let (header, layout) = obfuscator
        .begin_fixed(MessageKind::Initiation, &mut rng, 500, &mut packet)
        .unwrap();
    assert_eq!(layout.padding, 12);
    assert_eq!(
        u32::from_le_bytes(packet[12..16].try_into().unwrap()),
        header
    );
    obfuscator
        .finish_fixed(MessageKind::Initiation, &mut packet, &layout)
        .unwrap();
    assert_ne!(
        u32::from_le_bytes(packet[12..16].try_into().unwrap()),
        header
    );
    assert_eq!(obfuscator.decode_type(&packet, 12), Some(header));
    let detected = obfuscator.detect(&packet).unwrap();
    assert_eq!(detected.kind, MessageKind::Initiation);
    obfuscator
        .unprotect_detected(&mut packet, detected)
        .unwrap();
    assert_eq!(
        u32::from_le_bytes(packet[12..16].try_into().unwrap()),
        header
    );
}

#[test]
fn header_protection_requires_long_prefix() {
    let mut params = no_obfuscation();
    params.set_param("header_protection_key", HP_KEY).unwrap();
    params.set_param("s1", "11").unwrap();
    assert!(matches!(
        params.validate(),
        Err(ProtoError::HeaderProtectionPadding { index: 1, .. })
    ));
    let obfuscator = Obfuscator::new(&params);
    let mut rng = TestRng::new(4);
    let mut packet = [0u8; 11 + INITIATION_SIZE];
    assert!(matches!(
        obfuscator.begin_fixed(MessageKind::Initiation, &mut rng, 500, &mut packet),
        Err(ProtoError::HeaderProtectionPrefixTooShort { .. })
    ));
}

#[test]
fn every_fixed_kind_roundtrips() {
    let mut params = no_obfuscation();
    params.set_param("h1", "100").unwrap();
    params.set_param("h2", "200").unwrap();
    params.set_param("h3", "300").unwrap();
    params.set_param("s1", "12").unwrap();
    params.set_param("s2", "13").unwrap();
    params.set_param("s3", "14").unwrap();
    params.set_param("s4", "12").unwrap();
    params.set_param("header_protection_key", HP_KEY).unwrap();
    assert!(params.validate().is_ok());
    let obfuscator = Obfuscator::new(&params);
    let mut rng = TestRng::new(11);

    for kind in [
        MessageKind::Initiation,
        MessageKind::Response,
        MessageKind::Cookie,
    ] {
        let padding = usize::from(params.padding(kind));
        let body_len = kind.body_len();
        let mut packet = vec![0u8; padding + body_len];
        let (header, layout) = obfuscator
            .begin_fixed(kind, &mut rng, 500, &mut packet)
            .unwrap();
        assert_eq!(layout.padding, padding);
        assert_eq!(layout.body, padding..padding + body_len);
        packet[padding + 4..padding + body_len].fill(0x5a);
        obfuscator.finish_fixed(kind, &mut packet, &layout).unwrap();

        let detected = obfuscator.detect(&packet).unwrap();
        assert_eq!(detected.kind, kind);
        assert_eq!(detected.padding, padding);
        assert_eq!(detected.body_len, body_len);
        obfuscator
            .unprotect_detected(&mut packet, detected)
            .unwrap();
        assert_eq!(
            u32::from_le_bytes(packet[padding..padding + 4].try_into().unwrap()),
            header
        );
        assert!(packet[padding + 4..padding + body_len]
            .iter()
            .all(|byte| *byte == 0x5a));
    }
}

#[test]
fn transport_header_roundtrip() {
    let mut params = no_obfuscation();
    params.set_param("h4", "4000-4100").unwrap();
    params.set_param("s4", "16").unwrap();
    params.set_param("header_protection_key", HP_KEY).unwrap();
    let obfuscator = Obfuscator::new(&params);
    let mut rng = TestRng::new(5);
    let content = b"0123456789";
    let mut packet = vec![0u8; 16 + 16 + content.len() + aead::TAG_LEN];

    let layout = obfuscator
        .begin_transport(&mut rng, &mut packet, 0x1122_3344, 7)
        .unwrap();
    assert_eq!(layout.padding, 16);
    assert_eq!(layout.header, 16..32);
    packet[32..32 + content.len()].copy_from_slice(content);
    let key = Key::from_bytes([9u8; 32]);
    aead::seal_in_place(
        &key,
        7,
        &[],
        &mut packet[32..32 + content.len() + aead::TAG_LEN],
    )
    .unwrap();

    let total = 32 + content.len() + aead::TAG_LEN;
    let detected = obfuscator.detect(&packet[..total]).unwrap();
    assert_eq!(
        detected,
        DetectedPacket {
            kind: MessageKind::Transport,
            padding: 16,
            body_len: 16
        }
    );
    obfuscator
        .unprotect_detected(&mut packet[..total], detected)
        .unwrap();
    let mut transport = TransportPacket::parse(&mut packet[16..total]).unwrap();
    assert_eq!(transport.receiver_index(), 0x1122_3344);
    assert_eq!(transport.counter(), 7);
    assert_eq!(
        transport.encrypted_content().len(),
        content.len() + aead::TAG_LEN
    );
    assert_eq!(transport.plaintext_len(), content.len());
    let opened = aead::open_in_place(&key, 7, &[], transport.encrypted_content_mut()).unwrap();
    assert_eq!(opened, content);
}

#[test]
fn random_trailers_change_length_rules() {
    let mut params = no_obfuscation();
    params.set_param("random_trailers", "true").unwrap();
    params.set_param("h1", "100-200").unwrap();
    let obfuscator = Obfuscator::new(&params);
    let mut rng = TestRng::new(6);
    let mut packet = [0u8; 600];
    let (_, layout) = obfuscator
        .begin_fixed(MessageKind::Initiation, &mut rng, 500, &mut packet)
        .unwrap();
    assert!(layout.total >= INITIATION_SIZE);
    assert!(layout.total < 500);
    assert!(obfuscator.detect(&packet[..layout.total]).is_some());

    let mut strict = no_obfuscation();
    strict.set_param("h1", "300-400").unwrap();
    let strict = Obfuscator::new(&strict);
    assert!(strict.detect(&packet[..layout.total]).is_none());
}

#[test]
fn detect_boundaries() {
    let params = no_obfuscation();
    let obfuscator = Obfuscator::new(&params);
    assert!(obfuscator.detect(&[]).is_none());
    assert!(obfuscator.detect(&[1, 0, 0]).is_none());

    let mut initiation = vec![0u8; INITIATION_SIZE];
    initiation[..4].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(
        obfuscator.detect(&initiation).unwrap().kind,
        MessageKind::Initiation
    );
    assert!(obfuscator
        .detect(&initiation[..INITIATION_SIZE - 1])
        .is_none());

    let mut transport = vec![0u8; 32];
    transport[..4].copy_from_slice(&4u32.to_le_bytes());
    assert_eq!(
        obfuscator.detect(&transport).unwrap().kind,
        MessageKind::Transport
    );
    assert!(obfuscator.detect(&transport[..31]).is_none());
}

#[test]
fn zero_header_range_is_supported() {
    let mut params = no_obfuscation();
    params.set_param("h1", "0").unwrap();
    let obfuscator = Obfuscator::new(&params);
    let mut packet = vec![0u8; INITIATION_SIZE];
    let mut rng = TestRng::new(7);
    let (header, _) = obfuscator
        .begin_fixed(MessageKind::Initiation, &mut rng, 500, &mut packet)
        .unwrap();
    assert_eq!(header, 0);
    assert_eq!(
        obfuscator.detect(&packet).unwrap().kind,
        MessageKind::Initiation
    );
}

#[test]
fn begin_checks_destination_size() {
    let params = no_obfuscation();
    let obfuscator = Obfuscator::new(&params);
    let mut rng = TestRng::new(8);
    let mut packet = [0u8; 10];
    assert!(matches!(
        obfuscator.begin_fixed(MessageKind::Initiation, &mut rng, 500, &mut packet),
        Err(ProtoError::BufferTooSmall { .. })
    ));
    assert!(matches!(
        obfuscator.begin_transport(&mut rng, &mut packet, 1, 1),
        Err(ProtoError::BufferTooSmall { .. })
    ));
}

#[test]
fn finish_rejects_inconsistent_layout() {
    let params = no_obfuscation();
    let obfuscator = Obfuscator::new(&params);
    let mut packet = [0u8; INITIATION_SIZE];
    let layout = FixedLayout {
        padding: 0,
        body: 0..10,
        total: INITIATION_SIZE,
    };
    assert!(matches!(
        obfuscator.finish_fixed(MessageKind::Initiation, &mut packet, &layout),
        Err(ProtoError::InvalidLength { .. })
    ));
}

#[test]
fn junk_packets_are_bounded() {
    let mut params = no_obfuscation();
    params.set_param("jc", "5").unwrap();
    params.set_param("jmin", "10").unwrap();
    params.set_param("jmax", "20").unwrap();
    let obfuscator = Obfuscator::new(&params);
    assert_eq!(obfuscator.junk_count(), 5);
    let mut rng = TestRng::new(9);
    let mut buffer = [0u8; 32];
    for _ in 0..16 {
        let len = obfuscator.write_junk(&mut rng, &mut buffer).unwrap();
        assert!((10..=20).contains(&len));
    }
    assert!(matches!(
        obfuscator.write_junk(&mut rng, &mut buffer[..5]),
        Err(ProtoError::BufferTooSmall { .. })
    ));

    let mut disabled = no_obfuscation();
    disabled.set_param("jc", "5").unwrap();
    disabled.set_param("jmax", "0").unwrap();
    let obfuscator = Obfuscator::new(&disabled);
    assert_eq!(obfuscator.junk_count(), 0);
    assert_eq!(obfuscator.junk_packet_len(&mut rng), 0);
}

#[test]
fn special_packets_are_encoded_in_order() {
    let mut params = no_obfuscation();
    params.set_param("i1", "<b 0xdead><r 4>").unwrap();
    params.set_param("i3", "<t>").unwrap();
    let obfuscator = Obfuscator::new(&params);
    let packets: Vec<_> = obfuscator.special_packets().collect();
    assert_eq!(packets.len(), 2);
    let context = SpecialPacketContext {
        unix_time: 0x0102_0304,
        counter: 0,
    };
    let mut rng = TestRng::new(10);
    let mut buffer = [0u8; 8];
    assert_eq!(packets[0].len(), 6);
    assert_eq!(
        packets[0].encode(&mut rng, &context, &mut buffer).unwrap(),
        6
    );
    assert_eq!(&buffer[..2], &[0xde, 0xad]);
    assert_eq!(packets[1].len(), 4);
    assert_eq!(
        packets[1].encode(&mut rng, &context, &mut buffer).unwrap(),
        4
    );
    assert_eq!(buffer[..4], [0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn enabled_flag_tracks_configuration() {
    let mut params = no_obfuscation();
    assert!(!Obfuscator::new(&params).is_enabled());
    params.set_param("s4", "12").unwrap();
    assert!(Obfuscator::new(&params).is_enabled());
    let mut params = no_obfuscation();
    params.set_param("h4", "4-10").unwrap();
    assert!(Obfuscator::new(&params).is_enabled());
    let mut params = no_obfuscation();
    params.set_param("jc", "1").unwrap();
    params.set_param("jmax", "10").unwrap();
    assert!(Obfuscator::new(&params).is_enabled());
}

#[test]
fn plain_header_protection_is_noop() {
    let params = no_obfuscation();
    let obfuscator = Obfuscator::new(&params);
    let mut data = [1u8, 2, 3, 4];
    obfuscator.protect(b"UmbraWGS1234", &mut data).unwrap();
    assert_eq!(data, [1, 2, 3, 4]);
    assert!(obfuscator.header_key().is_none());
}

#[test]
fn zero_key_disables_protection() {
    let mut params = no_obfuscation();
    params
        .set_param("header_protection_key", &"00".repeat(32))
        .unwrap();
    let obfuscator = Obfuscator::new(&params);
    assert!(!obfuscator.has_header_protection());
    let mut data = [1u8, 2, 3, 4];
    obfuscator.protect(b"UmbraWGS1234", &mut data).unwrap();
    assert_eq!(data, [1, 2, 3, 4]);
}
