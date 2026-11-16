mod support;

use std::time::{Duration, Instant};

use umbrawg_crypto::aead;
use umbrawg_crypto::PublicKey;
use umbrawg_noise::{
    CookieChecker, CookieGenerator, Handshake, HandshakeState, NoiseError, StaticIdentity,
};
use umbrawg_proto::messages::{
    INITIATION_SIZE, MESSAGE_HANDSHAKE_INITIATION, MESSAGE_HANDSHAKE_RESPONSE, RESPONSE_SIZE,
};
use umbrawg_proto::{HandshakeInitiation, HandshakeResponse, ProtoError};

use support::{consume_initiation, consume_response, pattern, psk, timestamp, SequenceRng};

fn pair() -> (StaticIdentity, StaticIdentity, Handshake, Handshake) {
    let initiator = StaticIdentity::from_bytes(pattern(0x01));
    let responder = StaticIdentity::from_bytes(pattern(0x21));
    let initiator_handshake = Handshake::new(&initiator, responder.public_key(), psk());
    let responder_handshake = Handshake::new(&responder, initiator.public_key(), psk());
    (
        initiator,
        responder,
        initiator_handshake,
        responder_handshake,
    )
}

#[test]
fn full_handshake_derives_matching_transport_keys() {
    let (initiator, responder, mut initiator_handshake, mut responder_handshake) = pair();
    let mut initiator_rng = SequenceRng::new(0x41);
    let mut responder_rng = SequenceRng::new(0x61);

    let mut initiation = initiator_handshake
        .create_initiation(
            &initiator,
            &mut initiator_rng,
            MESSAGE_HANDSHAKE_INITIATION,
            0x1111_1111,
            timestamp(1_700_000_000, 123_456_789),
        )
        .unwrap();
    consume_initiation(&responder, &mut responder_handshake, &mut initiation).unwrap();

    assert_eq!(
        initiator_handshake.state(),
        HandshakeState::InitiationCreated
    );
    assert_eq!(
        responder_handshake.state(),
        HandshakeState::InitiationConsumed
    );
    assert_eq!(responder_handshake.remote_index(), 0x1111_1111);
    assert_eq!(
        responder_handshake.latest_timestamp(),
        timestamp(1_700_000_000, 123_456_789)
    );

    let mut response = responder_handshake
        .create_response(&mut responder_rng, MESSAGE_HANDSHAKE_RESPONSE, 0x2222_2222)
        .unwrap();
    consume_response(&initiator, &mut initiator_handshake, &mut response).unwrap();

    assert_eq!(
        initiator_handshake.state(),
        HandshakeState::ResponseConsumed
    );
    assert_eq!(initiator_handshake.remote_index(), 0x2222_2222);

    let initiator_keys = initiator_handshake.begin_session().unwrap();
    let responder_keys = responder_handshake.begin_session().unwrap();

    assert!(initiator_keys.is_initiator());
    assert!(!responder_keys.is_initiator());
    assert_eq!(initiator_keys.send_key(), responder_keys.receive_key());
    assert_eq!(initiator_keys.receive_key(), responder_keys.send_key());
    assert_eq!(initiator_keys.local_index(), 0x1111_1111);
    assert_eq!(initiator_keys.remote_index(), 0x2222_2222);
    assert_eq!(responder_keys.local_index(), 0x2222_2222);
    assert_eq!(responder_keys.remote_index(), 0x1111_1111);
    assert_eq!(initiator_handshake.state(), HandshakeState::Zeroed);

    let plaintext = b"umbrawg noise transport payload";
    let mut sealed = [0u8; 32 + aead::TAG_LEN];
    let sealed_len =
        aead::seal_into(initiator_keys.send_key(), 0, b"", plaintext, &mut sealed).unwrap();
    let mut opened = [0u8; 32];
    let opened_len = aead::open_into(
        responder_keys.receive_key(),
        0,
        b"",
        &sealed[..sealed_len],
        &mut opened,
    )
    .unwrap();
    assert_eq!(&opened[..opened_len], plaintext);
}

#[test]
fn replay_and_stale_timestamps_are_rejected() {
    let (initiator, responder, mut initiator_handshake, mut responder_handshake) = pair();
    let mut initiator_rng = SequenceRng::new(0x41);

    let mut initiation = initiator_handshake
        .create_initiation(
            &initiator,
            &mut initiator_rng,
            MESSAGE_HANDSHAKE_INITIATION,
            1,
            timestamp(1_700_000_000, 0),
        )
        .unwrap();
    consume_initiation(&responder, &mut responder_handshake, &mut initiation).unwrap();

    let mut repeated = initiation;
    assert!(matches!(
        consume_initiation(&responder, &mut responder_handshake, &mut repeated),
        Err(NoiseError::Replay)
    ));

    let mut stale = initiator_handshake
        .create_initiation(
            &initiator,
            &mut initiator_rng,
            MESSAGE_HANDSHAKE_INITIATION,
            2,
            timestamp(1_699_999_999, 0),
        )
        .unwrap();
    assert!(matches!(
        consume_initiation(&responder, &mut responder_handshake, &mut stale),
        Err(NoiseError::Replay)
    ));

    let mut fresh = initiator_handshake
        .create_initiation(
            &initiator,
            &mut initiator_rng,
            MESSAGE_HANDSHAKE_INITIATION,
            3,
            timestamp(1_700_000_001, 0),
        )
        .unwrap();
    consume_initiation(&responder, &mut responder_handshake, &mut fresh).unwrap();
}

#[test]
fn rejects_wrong_message_type_and_length() {
    let (initiator, responder, mut initiator_handshake, mut responder_handshake) = pair();
    let mut rng = SequenceRng::new(0x41);

    let mut initiation = initiator_handshake
        .create_initiation(&initiator, &mut rng, 2, 1, timestamp(1_700_000_000, 0))
        .unwrap();
    {
        let message = HandshakeInitiation::parse(&mut initiation).unwrap();
        let decrypted = responder.decrypt_initiation(&message).unwrap();
        assert!(matches!(
            responder_handshake.consume_initiation(decrypted, &message),
            Err(NoiseError::UnexpectedMessageType { .. })
        ));
    }

    let mut short = [0u8; INITIATION_SIZE - 1];
    assert!(matches!(
        HandshakeInitiation::parse(&mut short),
        Err(ProtoError::InvalidLength { .. })
    ));

    let mut response = [0u8; RESPONSE_SIZE];
    assert!(matches!(
        HandshakeResponse::parse(&mut response[..RESPONSE_SIZE - 1]),
        Err(ProtoError::InvalidLength { .. })
    ));
}

#[test]
fn rejects_wrong_receiver_index() {
    let (initiator, responder, mut initiator_handshake, mut responder_handshake) = pair();
    let mut initiation = initiator_handshake
        .create_initiation(
            &initiator,
            &mut SequenceRng::new(0x41),
            MESSAGE_HANDSHAKE_INITIATION,
            0x0a0b_0c0d,
            timestamp(1_700_000_000, 0),
        )
        .unwrap();
    consume_initiation(&responder, &mut responder_handshake, &mut initiation).unwrap();

    let mut response = responder_handshake
        .create_response(
            &mut SequenceRng::new(0x61),
            MESSAGE_HANDSHAKE_RESPONSE,
            0x1a1b_1c1d,
        )
        .unwrap();
    let mut message = HandshakeResponse::parse(&mut response).unwrap();
    let actual = message.receiver_index().wrapping_add(1);
    message.set_receiver_index(actual);
    assert!(matches!(
        initiator_handshake.consume_response(&initiator, &message),
        Err(NoiseError::InvalidReceiverIndex { expected: 0x0a0b_0c0d, actual: got }) if got == actual
    ));
}

#[test]
fn rejects_unknown_peer_and_corrupted_payloads() {
    let initiator = StaticIdentity::from_bytes(pattern(0x01));
    let responder = StaticIdentity::from_bytes(pattern(0x21));
    let other = StaticIdentity::from_bytes(pattern(0x41));
    let mut initiator_handshake = Handshake::new(&initiator, responder.public_key(), psk());

    let mut initiation = initiator_handshake
        .create_initiation(
            &initiator,
            &mut SequenceRng::new(0x41),
            MESSAGE_HANDSHAKE_INITIATION,
            1,
            timestamp(1_700_000_000, 0),
        )
        .unwrap();

    {
        let message = HandshakeInitiation::parse(&mut initiation).unwrap();
        let mut wrong_peer_handshake = Handshake::new(&responder, other.public_key(), psk());
        let decrypted = responder.decrypt_initiation(&message).unwrap();
        assert!(matches!(
            wrong_peer_handshake.consume_initiation(decrypted, &message),
            Err(NoiseError::PeerMismatch)
        ));
    }

    let mut corrupted_static = initiation;
    corrupted_static[40] ^= 1;
    {
        let message = HandshakeInitiation::parse(&mut corrupted_static).unwrap();
        assert!(matches!(
            responder.decrypt_initiation(&message),
            Err(NoiseError::Authentication)
        ));
    }

    let mut corrupted_timestamp = initiation;
    corrupted_timestamp[88] ^= 1;
    {
        let message = HandshakeInitiation::parse(&mut corrupted_timestamp).unwrap();
        let decrypted = responder.decrypt_initiation(&message).unwrap();
        let mut responder_handshake = Handshake::new(&responder, initiator.public_key(), psk());
        assert!(matches!(
            responder_handshake.consume_initiation(decrypted, &message),
            Err(NoiseError::Authentication)
        ));
    }
}

#[test]
fn rejects_corrupted_response() {
    let (initiator, responder, mut initiator_handshake, mut responder_handshake) = pair();
    let mut initiation = initiator_handshake
        .create_initiation(
            &initiator,
            &mut SequenceRng::new(0x41),
            MESSAGE_HANDSHAKE_INITIATION,
            1,
            timestamp(1_700_000_000, 0),
        )
        .unwrap();
    consume_initiation(&responder, &mut responder_handshake, &mut initiation).unwrap();

    let mut response = responder_handshake
        .create_response(&mut SequenceRng::new(0x61), MESSAGE_HANDSHAKE_RESPONSE, 2)
        .unwrap();
    response[44] ^= 1;
    assert!(matches!(
        consume_response(&initiator, &mut initiator_handshake, &mut response),
        Err(NoiseError::Authentication)
    ));
}

#[test]
fn static_static_precomputation_is_required() {
    let identity = StaticIdentity::from_bytes(pattern(0x01));
    let invalid_remote = PublicKey::from_bytes([0u8; 32]);
    let mut handshake = Handshake::new(&identity, invalid_remote, psk());

    assert!(!handshake.has_precomputed_static_static());
    assert!(matches!(
        handshake.create_initiation(
            &identity,
            &mut SequenceRng::new(0x41),
            MESSAGE_HANDSHAKE_INITIATION,
            1,
            timestamp(1_700_000_000, 0),
        ),
        Err(NoiseError::MissingStaticStatic)
    ));
}

#[test]
fn rejects_invalid_state_transitions() {
    let (initiator, responder, mut initiator_handshake, mut responder_handshake) = pair();

    assert!(matches!(
        initiator_handshake.begin_session(),
        Err(NoiseError::InvalidState { .. })
    ));
    assert!(matches!(
        responder_handshake.create_response(
            &mut SequenceRng::new(0x61),
            MESSAGE_HANDSHAKE_RESPONSE,
            1
        ),
        Err(NoiseError::InvalidState { .. })
    ));

    let mut initiation = initiator_handshake
        .create_initiation(
            &initiator,
            &mut SequenceRng::new(0x41),
            MESSAGE_HANDSHAKE_INITIATION,
            1,
            timestamp(1_700_000_000, 0),
        )
        .unwrap();
    consume_initiation(&responder, &mut responder_handshake, &mut initiation).unwrap();

    let mut response = responder_handshake
        .create_response(&mut SequenceRng::new(0x61), MESSAGE_HANDSHAKE_RESPONSE, 2)
        .unwrap();
    consume_response(&initiator, &mut initiator_handshake, &mut response).unwrap();

    assert!(responder_handshake.begin_session().is_ok());
    assert!(matches!(
        responder_handshake.begin_session(),
        Err(NoiseError::InvalidState { .. })
    ));
}

#[test]
fn mac_fields_are_validated_and_cookie_replies_restore_mac2() {
    let (initiator, responder, mut initiator_handshake, _) = pair();
    let now = Instant::now();
    let source = [0xc0, 0x00, 0x02, 0x01, 0x30, 0x39];

    let mut initiation = initiator_handshake
        .create_initiation(
            &initiator,
            &mut SequenceRng::new(0x41),
            MESSAGE_HANDSHAKE_INITIATION,
            0x0a0b_0c0d,
            timestamp(1_700_000_000, 0),
        )
        .unwrap();
    let mut generator = CookieGenerator::new(responder.public_key());
    let mut checker = CookieChecker::new(&responder, &mut SequenceRng::new(0xc1), now);
    assert!(checker.secret_is_fresh(now + Duration::from_secs(120)));
    assert!(!checker.secret_is_fresh(now + Duration::from_secs(121)));

    generator.add_macs(&mut initiation, now).unwrap();
    assert!(checker.check_mac1(&initiation));
    assert!(!checker.check_mac2(&initiation, &source, now));

    let mut corrupted = initiation;
    corrupted[41] ^= 1;
    assert!(!checker.check_mac1(&corrupted));
    corrupted = initiation;
    corrupted[120] ^= 1;
    assert!(!checker.check_mac1(&corrupted));
    assert!(!checker.check_mac1(&[0u8; 31]));

    let mut reply = checker
        .create_reply(
            &initiation,
            0x0a0b_0c0d,
            &source,
            3,
            &mut SequenceRng::new(0xa1),
            now,
        )
        .unwrap();
    {
        let message = umbrawg_proto::CookieReply::parse(&mut reply).unwrap();
        generator.consume_reply(&message, now).unwrap();
    }
    assert!(generator.has_cookie(now));
    assert!(generator.has_cookie(now + Duration::from_secs(115)));
    assert!(!generator.has_cookie(now + Duration::from_secs(116)));

    generator.add_macs(&mut initiation, now).unwrap();
    assert!(checker.check_mac2(&initiation, &source, now));
    assert!(!checker.check_mac2(&initiation, &[1, 2, 3, 4, 5, 6], now));

    let mut corrupted_mac2 = initiation;
    corrupted_mac2[140] ^= 1;
    assert!(!checker.check_mac2(&corrupted_mac2, &source, now));

    let mut corrupted_body = initiation;
    corrupted_body[50] ^= 1;
    assert!(!checker.check_mac2(&corrupted_body, &source, now));
}

#[test]
fn rejects_invalid_cookie_replies() {
    let (initiator, responder, mut handshake, _) = pair();
    let now = Instant::now();
    let source = [1u8, 2, 3, 4, 5, 6];
    let mut checker = CookieChecker::new(&responder, &mut SequenceRng::new(0xc1), now);
    let mut generator = CookieGenerator::new(responder.public_key());

    let mut initiation = handshake
        .create_initiation(
            &initiator,
            &mut SequenceRng::new(0x41),
            MESSAGE_HANDSHAKE_INITIATION,
            7,
            timestamp(1_700_000_000, 0),
        )
        .unwrap();
    generator.add_macs(&mut initiation, now).unwrap();
    let reply = checker
        .create_reply(&initiation, 7, &source, 3, &mut SequenceRng::new(0xa1), now)
        .unwrap();

    let mut reply_buffer = reply;
    {
        let message = umbrawg_proto::CookieReply::parse(&mut reply_buffer).unwrap();
        let mut fresh = CookieGenerator::new(responder.public_key());
        assert!(matches!(
            fresh.consume_reply(&message, now),
            Err(NoiseError::MissingMac1)
        ));
    }

    let mut corrupted = reply;
    corrupted[40] ^= 1;
    {
        let message = umbrawg_proto::CookieReply::parse(&mut corrupted).unwrap();
        assert!(matches!(
            generator.consume_reply(&message, now),
            Err(NoiseError::CookieAuthentication)
        ));
    }

    let mut wrong_type = reply;
    {
        let mut message = umbrawg_proto::CookieReply::parse(&mut wrong_type).unwrap();
        message.set_message_type(4);
        assert!(matches!(
            generator.consume_reply(&message, now),
            Err(NoiseError::UnexpectedMessageType { .. })
        ));
    }
}
