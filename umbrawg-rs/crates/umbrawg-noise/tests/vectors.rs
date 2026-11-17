mod support;

use std::time::Instant;

use umbrawg_crypto::Key;
use umbrawg_noise::{
    initial_chain_key, initial_hash, kdf1, kdf2, kdf3, CookieChecker, CookieGenerator, Handshake,
    StaticIdentity,
};
use umbrawg_proto::messages::{
    INITIATION_SIZE, MESSAGE_HANDSHAKE_INITIATION, MESSAGE_HANDSHAKE_RESPONSE, RESPONSE_SIZE,
};
use umbrawg_proto::{CookieReply, HandshakeInitiation, HandshakeResponse};

use support::{clamped, hex_to_array, pattern, psk, timestamp, SequenceRng};

const INITIAL_CHAIN_KEY: &str = "60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36";
const INITIAL_HASH: &str = "2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3";
const KDF1: &str = "a44d033c3ade03a84f191399742f1ea1b9f50eeb91697a729130624c97034e44";
const KDF2_0: &str = "a44d033c3ade03a84f191399742f1ea1b9f50eeb91697a729130624c97034e44";
const KDF2_1: &str = "e510cc8ce4977d86f67584b53187bf61749bab2d84f8c286a3cfb20a4a7dc4b4";
const KDF3_0: &str = "a44d033c3ade03a84f191399742f1ea1b9f50eeb91697a729130624c97034e44";
const KDF3_1: &str = "e510cc8ce4977d86f67584b53187bf61749bab2d84f8c286a3cfb20a4a7dc4b4";
const KDF3_2: &str = "d721fb090d31dc5b2ae0f696c96e3436738ca8238e129298e22d9b316f1eb67e";
const INIT_PUBLIC: &str = "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c";
const RESP_PUBLIC: &str = "5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b";
const INITIATION: &str = "443322110d0c0b0a64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d48466158a0e4ca242d151ca97ab90159a98b67e616625e68b4065d357376b6598e644ad7d678c0295d22de4cb43d5135581ed36346bfa7cf42a122639f89315e67f2b43de40f99f8e6be9135e1632baa63f80c4434874974e42c96f23e94200000000000000000000000000000000";
const RESPONSE: &str = "887766551d1c1b1a0d0c0b0a244fe3b963e899dd295baffce248d3530f3a9a7479ba063002680ebfe7adad49fbab2f1562120398989fbccdd90250145c24831f9ce11b8d4432c4b1e659468900000000000000000000000000000000";
const INITIATOR_SEND: &str = "d526ecde46bb2b51ed4b5b019ca94aa8909c9a3796f41a99ce4e7ecfd295e309";
const INITIATOR_RECV: &str = "7da1778e5d0b33aa1c905b6a7736f6e1b8b97f3bf09b0887495064f94b0f35e0";
const RESPONDER_SEND: &str = "7da1778e5d0b33aa1c905b6a7736f6e1b8b97f3bf09b0887495064f94b0f35e0";
const RESPONDER_RECV: &str = "d526ecde46bb2b51ed4b5b019ca94aa8909c9a3796f41a99ce4e7ecfd295e309";
const COOKIE_REPLY: &str = "ccbbaa990d0c0b0aa1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b89d3259b13aae0edf27a8a9eb735a073800919a88a5932eb4796632d53d97679e";
const INITIATION_WITH_MAC2: &str = "443322110d0c0b0a64b101b1d0be5a8704bd078f9895001fc03e8e9f9522f188dd128d9846d48466158a0e4ca242d151ca97ab90159a98b67e616625e68b4065d357376b6598e644ad7d678c0295d22de4cb43d5135581ed36346bfa7cf42a122639f89315e67f2b43de40f99f8e6be9135e1632baa63f80c4434874974e42c96f23e94288cd7265dd35c273a0ed62308559de4c";
const INITIATION_MAC2: &str = "88cd7265dd35c273a0ed62308559de4c";
const SOURCE: [u8; 6] = [0xc0, 0x00, 0x02, 0x01, 0x30, 0x39];

#[test]
fn kdf_vectors_match_go() {
    assert_eq!(initial_chain_key(), hex_to_array::<32>(INITIAL_CHAIN_KEY));
    assert_eq!(initial_hash(), hex_to_array::<32>(INITIAL_HASH));

    let chaining_key = initial_chain_key();
    let psk = clamped(pattern(0x81));

    assert_eq!(kdf1(&chaining_key, &psk), hex_to_array::<32>(KDF1));
    let (first, second) = kdf2(&chaining_key, &psk);
    assert_eq!(first, hex_to_array::<32>(KDF2_0));
    assert_eq!(second, hex_to_array::<32>(KDF2_1));
    let (first, second, third) = kdf3(&chaining_key, &psk);
    assert_eq!(first, hex_to_array::<32>(KDF3_0));
    assert_eq!(second, hex_to_array::<32>(KDF3_1));
    assert_eq!(third, hex_to_array::<32>(KDF3_2));
}

#[test]
fn initiation_and_response_match_go() {
    let initiator = StaticIdentity::from_bytes(pattern(0x01));
    let responder = StaticIdentity::from_bytes(pattern(0x21));
    assert_eq!(
        initiator.public_key().to_bytes(),
        hex_to_array::<32>(INIT_PUBLIC)
    );
    assert_eq!(
        responder.public_key().to_bytes(),
        hex_to_array::<32>(RESP_PUBLIC)
    );

    let now = Instant::now();
    let mut initiator_handshake = Handshake::new(&initiator, responder.public_key(), psk());
    let mut responder_handshake = Handshake::new(&responder, initiator.public_key(), psk());

    let mut initiation = initiator_handshake
        .create_initiation(
            &initiator,
            &mut SequenceRng::new(0x41),
            0x1122_3344,
            0x0a0b_0c0d,
            timestamp(1_700_000_000, 123_456_789),
        )
        .unwrap();
    let mut initiator_generator = CookieGenerator::new(responder.public_key());
    initiator_generator.add_macs(&mut initiation, now).unwrap();
    let expected_initiation = hex_to_array::<INITIATION_SIZE>(INITIATION);
    assert_eq!(initiation, expected_initiation);

    let mut consume_initiation = initiation;
    {
        let mut message = HandshakeInitiation::parse(&mut consume_initiation).unwrap();
        message.set_message_type(MESSAGE_HANDSHAKE_INITIATION);
        let decrypted = responder.decrypt_initiation(&message).unwrap();
        assert_eq!(decrypted.peer_static(), initiator.public_key());
        responder_handshake
            .consume_initiation(decrypted, &message)
            .unwrap();
    }

    let mut response = responder_handshake
        .create_response(&mut SequenceRng::new(0x61), 0x5566_7788, 0x1a1b_1c1d)
        .unwrap();
    let mut responder_generator = CookieGenerator::new(initiator.public_key());
    responder_generator.add_macs(&mut response, now).unwrap();
    let expected_response = hex_to_array::<RESPONSE_SIZE>(RESPONSE);
    assert_eq!(response, expected_response);

    let mut consume_response = response;
    {
        let mut message = HandshakeResponse::parse(&mut consume_response).unwrap();
        message.set_message_type(MESSAGE_HANDSHAKE_RESPONSE);
        initiator_handshake
            .consume_response(&initiator, &message)
            .unwrap();
    }

    let initiator_keys = initiator_handshake.begin_session().unwrap();
    let responder_keys = responder_handshake.begin_session().unwrap();
    assert_eq!(
        initiator_keys.send_key().to_bytes(),
        hex_to_array::<32>(INITIATOR_SEND)
    );
    assert_eq!(
        initiator_keys.receive_key().to_bytes(),
        hex_to_array::<32>(INITIATOR_RECV)
    );
    assert_eq!(
        responder_keys.send_key().to_bytes(),
        hex_to_array::<32>(RESPONDER_SEND)
    );
    assert_eq!(
        responder_keys.receive_key().to_bytes(),
        hex_to_array::<32>(RESPONDER_RECV)
    );
}

#[test]
fn cookie_reply_matches_go() {
    let responder = StaticIdentity::from_bytes(pattern(0x21));
    let now = Instant::now();
    let mut checker = CookieChecker::from_secret(&responder, Key::from_bytes(pattern(0xc1)), now);
    let mut generator = CookieGenerator::new(responder.public_key());

    let mut initiation = hex_to_array::<INITIATION_SIZE>(INITIATION);
    generator.add_macs(&mut initiation, now).unwrap();

    let reply = checker
        .create_reply(
            &initiation,
            0x0a0b_0c0d,
            &SOURCE,
            0x99aa_bbcc,
            &mut SequenceRng::new(0xa1),
            now,
        )
        .unwrap();
    assert_eq!(reply, hex_to_array::<64>(COOKIE_REPLY));

    let mut reply_buffer = reply;
    {
        let mut message = CookieReply::parse(&mut reply_buffer).unwrap();
        message.set_message_type(3);
        generator.consume_reply(&message, now).unwrap();
    }

    generator.add_macs(&mut initiation, now).unwrap();
    assert_eq!(
        initiation,
        hex_to_array::<INITIATION_SIZE>(INITIATION_WITH_MAC2)
    );
    assert_eq!(
        &initiation[INITIATION_SIZE - 16..],
        &hex_to_array::<16>(INITIATION_MAC2)[..]
    );
    assert!(checker.check_mac2(&initiation, &SOURCE, now));
}
