use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand_core::RngCore;

use umbrawg_crypto::{Key, PrivateKey, PublicKey};
use umbrawg_device::{
    AllowedIp, DatagramSink, Device, DeviceConfig, DeviceControl, DeviceError, IncomingMeta,
    IncomingOutcome, IoContext, PacketIo, Peer, PeerConfig, PeerState, PreparedIncoming,
    SendOutcome, Timings, DEFAULT_EXTRA_PORTS,
};
use umbrawg_proto::special::SpecialPacket;
use umbrawg_proto::ObfParams;
use umbrawg_uapi::{
    AllowedIp as UapiAllowedIp, AllowedIpChange, Cipher, PeerRequest, SetRequest,
    SpecialPacketUpdate, U16Range,
};

struct TestRng(u64);

impl TestRng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }
}

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        self.next() as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.next()
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        for chunk in dst.chunks_mut(8) {
            let bytes = self.next().to_le_bytes();
            let length = chunk.len();
            chunk.copy_from_slice(&bytes[..length]);
        }
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dst);
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct Sent {
    payload: Vec<u8>,
    gso_size: Option<usize>,
}

struct MemoryIo {
    sent: Vec<Sent>,
    delivered: Vec<(PublicKey, Vec<u8>)>,
}

impl MemoryIo {
    fn new() -> Self {
        Self {
            sent: Vec::new(),
            delivered: Vec::new(),
        }
    }

    fn take_sent(&mut self) -> Vec<Sent> {
        std::mem::take(&mut self.sent)
    }
}

impl DatagramSink for MemoryIo {
    fn send_datagram(
        &mut self,
        _endpoint: SocketAddr,
        _peer: Option<&Peer>,
        payload: &[u8],
        gso_size: Option<usize>,
    ) {
        self.sent.push(Sent {
            payload: payload.to_vec(),
            gso_size,
        });
    }
}

impl PacketIo for MemoryIo {
    fn deliver(&mut self, peer: &Peer, packet: &[u8]) {
        self.delivered.push((peer.public_key(), packet.to_vec()));
    }
}

fn key(byte: u8) -> Key {
    Key::from_bytes([byte; 32])
}

fn device(byte: u8, obfuscation: ObfParams) -> Arc<Device> {
    Arc::new(
        Device::new(DeviceConfig {
            private_key: Some(key(byte)),
            obfuscation,
            timings: Timings::new(),
            ..DeviceConfig::default()
        })
        .unwrap(),
    )
}

fn prefix(address: &str, cidr: u8) -> AllowedIp {
    AllowedIp::new(address.parse().unwrap(), cidr).unwrap()
}

struct Pair {
    a: Arc<Device>,
    b: Arc<Device>,
    peer_a: Arc<Peer>,
    peer_b: Arc<Peer>,
    addr_a: SocketAddr,
    addr_b: SocketAddr,
    rng: TestRng,
    scratch: Vec<u8>,
    io_a: MemoryIo,
    io_b: MemoryIo,
}

fn pair(obfuscation: ObfParams) -> Pair {
    let a = device(0x11, obfuscation.clone());
    let b = device(0x22, obfuscation);
    let addr_a: SocketAddr = "10.0.0.1:1111".parse().unwrap();
    let addr_b: SocketAddr = "10.0.0.2:2222".parse().unwrap();
    let mut config_b = PeerConfig::new(b.public_key().unwrap());
    config_b.endpoint = Some(addr_b);
    config_b.allowed_ips = vec![prefix("10.0.0.2", 32)];
    let peer_b = a.add_peer(config_b).unwrap();
    let mut config_a = PeerConfig::new(a.public_key().unwrap());
    config_a.endpoint = Some(addr_a);
    config_a.allowed_ips = vec![prefix("10.0.0.1", 32)];
    let peer_a = b.add_peer(config_a).unwrap();
    Pair {
        a,
        b,
        peer_a,
        peer_b,
        addr_a,
        addr_b,
        rng: TestRng::new(0x1234_5678),
        scratch: vec![0u8; 65_535],
        io_a: MemoryIo::new(),
        io_b: MemoryIo::new(),
    }
}

fn deliver_one(
    packet: Sent,
    source: SocketAddr,
    dst: &Arc<Device>,
    dst_io: &mut MemoryIo,
    rng: &mut TestRng,
    now: Instant,
    scratch: &mut [u8],
) -> IncomingOutcome {
    let mut payload = packet.payload;
    let meta = IncomingMeta::new(source, packet.gso_size);
    let mut ctx = IoContext::new(rng, now, scratch, dst_io);
    dst.handle_incoming(&mut payload, meta, &mut ctx)
        .expect("incoming packet")
}

fn flush(
    source: SocketAddr,
    dst: &Arc<Device>,
    src_io: &mut MemoryIo,
    dst_io: &mut MemoryIo,
    rng: &mut TestRng,
    now: Instant,
    scratch: &mut [u8],
) -> Vec<IncomingOutcome> {
    let sent = src_io.take_sent();
    sent.into_iter()
        .map(|packet| deliver_one(packet, source, dst, dst_io, rng, now, scratch))
        .collect()
}

fn complete_handshake(pair: &mut Pair, now: Instant) {
    {
        let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_a);
        pair.a.initiate_handshake(&pair.peer_b, &mut ctx).unwrap();
    }
    flush(
        pair.addr_a,
        &pair.b,
        &mut pair.io_a,
        &mut pair.io_b,
        &mut pair.rng,
        now,
        &mut pair.scratch,
    );
    flush(
        pair.addr_b,
        &pair.a,
        &mut pair.io_b,
        &mut pair.io_a,
        &mut pair.rng,
        now,
        &mut pair.scratch,
    );
    flush(
        pair.addr_a,
        &pair.b,
        &mut pair.io_a,
        &mut pair.io_b,
        &mut pair.rng,
        now,
        &mut pair.scratch,
    );
}

fn ipv4_packet(source: [u8; 4], destination: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut packet = vec![0u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet[20..].copy_from_slice(payload);
    packet
}

fn ipv6_packet(source: [u8; 16], destination: [u8; 16], payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0u8; 40 + payload.len()];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    packet[6] = 17;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source);
    packet[24..40].copy_from_slice(&destination);
    packet[40..].copy_from_slice(payload);
    packet
}

#[test]
fn handshake_establishes_sessions_on_both_devices() {
    let mut pair = pair(ObfParams::default());
    let now = Instant::now();
    complete_handshake(&mut pair, now);
    assert_eq!(pair.a.peer_state(&pair.peer_b, now), PeerState::Established);
    assert_eq!(pair.b.peer_state(&pair.peer_a, now), PeerState::Established);
    assert!(pair.peer_a.current_keypair().is_some());
    assert!(pair.peer_b.current_keypair().is_some());
    assert_eq!(pair.a.peer_count(), 1);
    assert_eq!(pair.b.peer_count(), 1);
    assert_eq!(
        pair.a
            .route("10.0.0.2".parse().unwrap())
            .unwrap()
            .public_key(),
        pair.b.public_key().unwrap()
    );
}

#[test]
fn initiation_flood_enables_under_load_and_cookie_reply() {
    let mut pair = pair(ObfParams::default());
    let now = Instant::now();
    pair.b.set_under_load_threshold(4);
    {
        let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_a);
        pair.a.initiate_handshake(&pair.peer_b, &mut ctx).unwrap();
    }
    let initiation = pair.io_a.take_sent().pop().expect("handshake initiation");
    assert!(!pair.b.under_load());

    for _ in 0..3 {
        let outcome = deliver_one(
            initiation.clone(),
            pair.addr_a,
            &pair.b,
            &mut pair.io_b,
            &mut pair.rng,
            now,
            &mut pair.scratch,
        );
        assert_ne!(outcome, IncomingOutcome::Cookie);
        assert!(!pair.b.under_load());
    }
    pair.io_b.take_sent();

    let outcome = deliver_one(
        initiation.clone(),
        pair.addr_a,
        &pair.b,
        &mut pair.io_b,
        &mut pair.rng,
        now,
        &mut pair.scratch,
    );
    assert_eq!(outcome, IncomingOutcome::Cookie);
    assert!(pair.b.under_load());
    let replies = pair.io_b.take_sent();
    assert_eq!(replies.len(), 1);
    let outcome = deliver_one(
        replies.into_iter().next().unwrap(),
        pair.addr_b,
        &pair.a,
        &mut pair.io_a,
        &mut pair.rng,
        now,
        &mut pair.scratch,
    );
    assert_eq!(outcome, IncomingOutcome::Cookie);

    pair.b.refresh_under_load(now + Duration::from_secs(2));
    assert!(!pair.b.under_load());
    let outcome = deliver_one(
        initiation,
        pair.addr_a,
        &pair.b,
        &mut pair.io_b,
        &mut pair.rng,
        now + Duration::from_secs(2),
        &mut pair.scratch,
    );
    assert_ne!(outcome, IncomingOutcome::Cookie);
}

#[test]
fn disabled_under_load_detector_keeps_cookies_off() {
    let mut pair = pair(ObfParams::default());
    let now = Instant::now();
    pair.b.set_under_load_threshold(1);
    pair.b.set_under_load_detection(false);
    {
        let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_a);
        pair.a.initiate_handshake(&pair.peer_b, &mut ctx).unwrap();
    }
    let initiation = pair.io_a.take_sent().pop().expect("handshake initiation");
    let outcome = deliver_one(
        initiation.clone(),
        pair.addr_a,
        &pair.b,
        &mut pair.io_b,
        &mut pair.rng,
        now,
        &mut pair.scratch,
    );
    assert_ne!(outcome, IncomingOutcome::Cookie);
    assert!(!pair.b.under_load());

    pair.b.set_under_load_detection(true);
    pair.io_b.take_sent();
    let outcome = deliver_one(
        initiation,
        pair.addr_a,
        &pair.b,
        &mut pair.io_b,
        &mut pair.rng,
        now,
        &mut pair.scratch,
    );
    assert_eq!(outcome, IncomingOutcome::Cookie);
    assert!(pair.b.under_load());
    assert_eq!(pair.b.under_load_threshold(), 1);
}

#[test]
fn transport_round_trip_respects_allowed_ips() {
    let mut pair = pair(ObfParams::default());
    let now = Instant::now();
    complete_handshake(&mut pair, now);

    let packet = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], b"hello umbrawg");
    let mut output = vec![0u8; 65_535];
    {
        let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_a);
        pair.a
            .send_data(&pair.peer_b, &packet, &mut output, &mut ctx)
            .unwrap();
    }
    flush(
        pair.addr_a,
        &pair.b,
        &mut pair.io_a,
        &mut pair.io_b,
        &mut pair.rng,
        now,
        &mut pair.scratch,
    );
    assert_eq!(pair.io_b.delivered.len(), 1);
    assert_eq!(pair.io_b.delivered[0].0, pair.a.public_key().unwrap());
    assert_eq!(pair.io_b.delivered[0].1, packet);

    let disallowed = ipv4_packet([10, 9, 9, 9], [10, 0, 0, 2], b"spoof");
    {
        let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_a);
        pair.a
            .send_data(&pair.peer_b, &disallowed, &mut output, &mut ctx)
            .unwrap();
    }
    flush(
        pair.addr_a,
        &pair.b,
        &mut pair.io_a,
        &mut pair.io_b,
        &mut pair.rng,
        now,
        &mut pair.scratch,
    );
    assert_eq!(pair.io_b.delivered.len(), 1);

    let source = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let destination = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let packet6 = ipv6_packet(source, destination, b"v6");
    pair.b
        .allowed_ips()
        .insert(prefix("2001:db8::1", 128), pair.peer_a.id());
    {
        let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_a);
        pair.a
            .send_data(&pair.peer_b, &packet6, &mut output, &mut ctx)
            .unwrap();
    }
    flush(
        pair.addr_a,
        &pair.b,
        &mut pair.io_a,
        &mut pair.io_b,
        &mut pair.rng,
        now,
        &mut pair.scratch,
    );
    assert_eq!(pair.io_b.delivered.len(), 2);
    assert_eq!(pair.io_b.delivered[1].1, packet6);
}

#[test]
fn aes256gcm_transport_round_trip() {
    let mut pair = pair(ObfParams::default());
    pair.peer_a.set_cipher(Cipher::Aes256Gcm);
    pair.peer_b.set_cipher(Cipher::Aes256Gcm);
    let now = Instant::now();
    complete_handshake(&mut pair, now);

    let packet = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], b"aes payload");
    let mut output = vec![0u8; 65_535];
    {
        let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_a);
        pair.a
            .send_data(&pair.peer_b, &packet, &mut output, &mut ctx)
            .unwrap();
    }
    flush(
        pair.addr_a,
        &pair.b,
        &mut pair.io_a,
        &mut pair.io_b,
        &mut pair.rng,
        now,
        &mut pair.scratch,
    );
    assert_eq!(pair.io_b.delivered.len(), 1);
    assert_eq!(pair.io_b.delivered[0].1, packet);
}

#[test]
fn cipher_mismatch_drops_transport_packets() {
    let mut pair = pair(ObfParams::default());
    pair.peer_a.set_cipher(Cipher::Aes256Gcm);
    let now = Instant::now();
    complete_handshake(&mut pair, now);

    let packet = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], b"wrong cipher");
    let mut output = vec![0u8; 65_535];
    {
        let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_a);
        pair.a
            .send_data(&pair.peer_b, &packet, &mut output, &mut ctx)
            .unwrap();
    }
    flush(
        pair.addr_a,
        &pair.b,
        &mut pair.io_a,
        &mut pair.io_b,
        &mut pair.rng,
        now,
        &mut pair.scratch,
    );
    assert!(pair.io_b.delivered.is_empty());
}

#[test]
fn replayed_transport_packet_is_dropped() {
    let mut pair = pair(ObfParams::default());
    let now = Instant::now();
    complete_handshake(&mut pair, now);

    let packet = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], b"replay me");
    let mut output = vec![0u8; 65_535];
    {
        let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_a);
        pair.a
            .send_data(&pair.peer_b, &packet, &mut output, &mut ctx)
            .unwrap();
    }
    let sent = pair.io_a.take_sent();
    for datagram in sent.clone() {
        let outcome = deliver_one(
            datagram,
            pair.addr_a,
            &pair.b,
            &mut pair.io_b,
            &mut pair.rng,
            now,
            &mut pair.scratch,
        );
        assert_eq!(outcome, IncomingOutcome::Delivered(packet.len()));
    }
    assert_eq!(pair.io_b.delivered.len(), 1);
    for datagram in sent {
        let outcome = deliver_one(
            datagram,
            pair.addr_a,
            &pair.b,
            &mut pair.io_b,
            &mut pair.rng,
            now,
            &mut pair.scratch,
        );
        assert_eq!(outcome, IncomingOutcome::Dropped);
    }
    assert_eq!(pair.io_b.delivered.len(), 1);
}

#[test]
fn obfuscation_headers_junk_and_trailers_are_applied() {
    let params = ObfParams {
        s1: 12,
        s2: 12,
        s3: 12,
        s4: 12,
        h1: 1000..=2000,
        h2: 3000..=4000,
        h3: 5000..=6000,
        h4: 7000..=8000,
        jc: 3,
        jmin: 10,
        jmax: 20,
        i1: Some(SpecialPacket::parse("<b 0xdeadbeef><r 8>").unwrap()),
        i2: Some(SpecialPacket::parse("<rc 6><rd 4>").unwrap()),
        header_protection_key: Some(key(0x5a)),
        random_trailers: true,
        content_padding_addition: 1..=32,
        ..ObfParams::default()
    };
    params.validate().unwrap();

    let mut pair = pair(params.clone());
    let now = Instant::now();
    {
        let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_a);
        pair.a.initiate_handshake(&pair.peer_b, &mut ctx).unwrap();
    }
    let sent = pair.io_a.take_sent();
    assert_eq!(sent.len(), 2 + 3 + 1);
    let initiation = sent.last().unwrap();
    assert!(initiation.payload.len() >= 12 + 148);
    let wire_type = u32::from_le_bytes(initiation.payload[12..16].try_into().unwrap());
    assert_ne!(wire_type, 1);
    for datagram in sent {
        deliver_one(
            datagram,
            pair.addr_a,
            &pair.b,
            &mut pair.io_b,
            &mut pair.rng,
            now,
            &mut pair.scratch,
        );
    }
    flush(
        pair.addr_b,
        &pair.a,
        &mut pair.io_b,
        &mut pair.io_a,
        &mut pair.rng,
        now,
        &mut pair.scratch,
    );
    flush(
        pair.addr_a,
        &pair.b,
        &mut pair.io_a,
        &mut pair.io_b,
        &mut pair.rng,
        now,
        &mut pair.scratch,
    );
    assert_eq!(pair.a.peer_state(&pair.peer_b, now), PeerState::Established);

    let packet = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], b"obfuscated payload");
    let mut output = vec![0u8; 65_535];
    {
        let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_a);
        pair.a
            .send_data(&pair.peer_b, &packet, &mut output, &mut ctx)
            .unwrap();
    }
    let sent = pair.io_a.take_sent();
    assert_eq!(sent.len(), 1);
    assert!(sent[0].payload.len() > 12 + 16 + packet.len() + 16);
    let wire_type = u32::from_le_bytes(sent[0].payload[12..16].try_into().unwrap());
    assert_ne!(wire_type, 4);
    for datagram in sent {
        deliver_one(
            datagram,
            pair.addr_a,
            &pair.b,
            &mut pair.io_b,
            &mut pair.rng,
            now,
            &mut pair.scratch,
        );
    }
    assert_eq!(pair.io_b.delivered.len(), 1);
    assert_eq!(pair.io_b.delivered[0].1, packet);
}

#[test]
fn staging_flushes_after_handshake() {
    let mut pair = pair(ObfParams::default());
    let now = Instant::now();
    let packet = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], b"staged");
    let mut output = vec![0u8; 65_535];
    {
        let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_a);
        let outcome = pair
            .a
            .send_packet(&pair.peer_b, &packet, &mut output, &mut ctx)
            .unwrap();
        assert_eq!(outcome, SendOutcome::Staged);
    }
    assert_eq!(pair.peer_b.staged_len(), 1);
    flush(
        pair.addr_a,
        &pair.b,
        &mut pair.io_a,
        &mut pair.io_b,
        &mut pair.rng,
        now,
        &mut pair.scratch,
    );
    flush(
        pair.addr_b,
        &pair.a,
        &mut pair.io_b,
        &mut pair.io_a,
        &mut pair.rng,
        now,
        &mut pair.scratch,
    );
    flush(
        pair.addr_a,
        &pair.b,
        &mut pair.io_a,
        &mut pair.io_b,
        &mut pair.rng,
        now,
        &mut pair.scratch,
    );
    assert_eq!(pair.peer_b.staged_len(), 0);
    assert_eq!(pair.io_b.delivered.len(), 1);
    assert_eq!(pair.io_b.delivered[0].1, packet);
}

#[test]
fn gso_batch_is_coalesced_and_reassembled() {
    let mut pair = pair(ObfParams::default());
    let now = Instant::now();
    complete_handshake(&mut pair, now);

    let first = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], &[1u8; 100]);
    let second = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], &[2u8; 100]);
    let mut output = vec![0u8; 65_535];
    let layout = {
        let mut rng = TestRng::new(9);
        pair.a
            .encrypt_batch(
                &pair.peer_b,
                &[first.as_slice(), second.as_slice()],
                &mut output,
                &mut rng,
                now,
            )
            .unwrap()
    };
    assert_eq!(layout.len(), 1);
    let group = layout.groups()[0];
    assert_eq!(group.segments, 2);
    assert_eq!(group.segment_len, group.len() / 2);
    let datagram = Sent {
        payload: output[..layout.total_len()].to_vec(),
        gso_size: Some(group.segment_len),
    };
    deliver_one(
        datagram,
        pair.addr_a,
        &pair.b,
        &mut pair.io_b,
        &mut pair.rng,
        now,
        &mut pair.scratch,
    );
    assert_eq!(pair.io_b.delivered.len(), 2);
    assert_eq!(pair.io_b.delivered[0].1, first);
    assert_eq!(pair.io_b.delivered[1].1, second);
}

#[test]
fn timers_retransmit_keepalive_rekey_and_reject() {
    let now = Instant::now();

    let mut retransmit = pair(ObfParams::default());
    {
        let mut ctx = IoContext::new(
            &mut retransmit.rng,
            now,
            &mut retransmit.scratch,
            &mut retransmit.io_a,
        );
        retransmit
            .a
            .initiate_handshake(&retransmit.peer_b, &mut ctx)
            .unwrap();
    }
    retransmit.io_a.sent.clear();
    {
        let later = now + Duration::from_secs(7);
        let mut ctx = IoContext::new(
            &mut retransmit.rng,
            later,
            &mut retransmit.scratch,
            &mut retransmit.io_a,
        );
        assert!(retransmit.a.tick(&mut ctx).unwrap() >= 1);
    }
    assert!(!retransmit.io_a.sent.is_empty());
    assert!(retransmit.a.next_deadline().is_some());

    let mut keepalive = pair(ObfParams::default());
    complete_handshake(&mut keepalive, now);
    let packet = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], b"timer");
    let mut output = vec![0u8; 65_535];
    {
        let mut ctx = IoContext::new(
            &mut keepalive.rng,
            now,
            &mut keepalive.scratch,
            &mut keepalive.io_a,
        );
        keepalive
            .a
            .send_data(&keepalive.peer_b, &packet, &mut output, &mut ctx)
            .unwrap();
    }
    flush(
        keepalive.addr_a,
        &keepalive.b,
        &mut keepalive.io_a,
        &mut keepalive.io_b,
        &mut keepalive.rng,
        now,
        &mut keepalive.scratch,
    );
    keepalive.io_b.sent.clear();
    {
        let later = now + Duration::from_secs(11);
        let mut ctx = IoContext::new(
            &mut keepalive.rng,
            later,
            &mut keepalive.scratch,
            &mut keepalive.io_b,
        );
        assert!(keepalive.b.tick(&mut ctx).unwrap() >= 1);
    }
    assert!(!keepalive.io_b.sent.is_empty());
    flush(
        keepalive.addr_b,
        &keepalive.a,
        &mut keepalive.io_b,
        &mut keepalive.io_a,
        &mut keepalive.rng,
        now + Duration::from_secs(11),
        &mut keepalive.scratch,
    );
    assert!(keepalive.io_a.delivered.is_empty());

    let mut rekey = pair(ObfParams::default());
    complete_handshake(&mut rekey, now);
    rekey.io_a.sent.clear();
    {
        let later = now + Duration::from_secs(121);
        let mut ctx = IoContext::new(&mut rekey.rng, later, &mut rekey.scratch, &mut rekey.io_a);
        rekey
            .a
            .send_data(&rekey.peer_b, &packet, &mut output, &mut ctx)
            .unwrap();
    }
    assert_eq!(rekey.io_a.sent.len(), 2);

    let mut reject = pair(ObfParams::default());
    complete_handshake(&mut reject, now);
    let late = now + Duration::from_secs(181);
    let error = reject
        .a
        .encrypt_packet(&reject.peer_b, &packet, &mut output, &mut reject.rng, late)
        .unwrap_err();
    assert_eq!(error, DeviceError::KeypairExpired);

    let mut zero = pair(ObfParams::default());
    complete_handshake(&mut zero, now);
    {
        let later = now + Duration::from_secs(541);
        let mut ctx = IoContext::new(&mut zero.rng, later, &mut zero.scratch, &mut zero.io_b);
        zero.b.tick(&mut ctx).unwrap();
    }
    assert!(zero.peer_a.current_keypair().is_none());
    assert_eq!(
        zero.b
            .peer_state(&zero.peer_a, now + Duration::from_secs(541)),
        PeerState::Down
    );
}

#[test]
fn uapi_snapshot_and_apply_patch_the_device() {
    let mut pair = pair(ObfParams::default());
    let now = Instant::now();
    complete_handshake(&mut pair, now);

    let snapshot = pair.a.snapshot();
    assert_eq!(
        snapshot.private_key.as_ref().unwrap().to_bytes(),
        PrivateKey::from_bytes(key(0x11).to_bytes()).to_bytes()
    );
    assert_eq!(snapshot.peers.len(), 1);
    assert_eq!(snapshot.peers[0].public_key, pair.b.public_key().unwrap());
    assert_eq!(snapshot.peers[0].allowed_ips.len(), 1);
    assert_eq!(
        snapshot.peers[0].allowed_ips[0].address(),
        "10.0.0.2".parse::<IpAddr>().unwrap()
    );
    assert!(snapshot.peers[0].last_handshake_time_sec > 0);
    assert_eq!(snapshot.peers[0].advanced_security, None);
    assert_eq!(snapshot.extra_ports, DEFAULT_EXTRA_PORTS);

    let mut advanced = PeerRequest::new(pair.b.public_key().unwrap());
    advanced.advanced_security = Some(true);
    let mut request = SetRequest::default();
    request.peers.push(advanced);
    pair.a.apply(request).unwrap();
    assert_eq!(pair.a.snapshot().peers[0].advanced_security, Some(true));

    let mut advanced = PeerRequest::new(pair.b.public_key().unwrap());
    advanced.advanced_security = Some(false);
    let mut request = SetRequest::default();
    request.peers.push(advanced);
    pair.a.apply(request).unwrap();
    assert_eq!(pair.a.snapshot().peers[0].advanced_security, Some(false));

    let new_prefix = UapiAllowedIp::new("192.168.0.0".parse().unwrap(), 16).unwrap();
    let mut peer_request = PeerRequest::new(pair.b.public_key().unwrap());
    peer_request.replace_allowed_ips = true;
    peer_request
        .allowed_ips
        .push(AllowedIpChange::Add(new_prefix));
    let mut request = SetRequest::default();
    request.peers.push(peer_request);
    pair.a.apply(request).unwrap();

    let snapshot = pair.a.snapshot();
    assert_eq!(snapshot.peers[0].allowed_ips.len(), 1);
    assert_eq!(
        snapshot.peers[0].allowed_ips[0].address(),
        "192.168.0.0".parse::<IpAddr>().unwrap()
    );
    assert_eq!(
        pair.a
            .route("192.168.0.1".parse().unwrap())
            .unwrap()
            .public_key(),
        pair.b.public_key().unwrap()
    );
    assert!(pair.a.route("10.0.0.2".parse().unwrap()).is_none());

    let mut request = SetRequest::default();
    request.obfuscation.i1 = SpecialPacketUpdate::Set("<b 0x01><r 4>".to_owned());
    request.obfuscation.random_trailers = Some(true);
    request.timings.keepalive_timeout = Some(U16Range::new(4, 6));
    pair.a.apply(request).unwrap();

    let snapshot = pair.a.snapshot();
    assert_eq!(snapshot.obfuscation.i1.as_deref(), Some("<b 0x01><r 4>"));
    assert!(snapshot.obfuscation.random_trailers);
    assert_eq!(snapshot.timings.keepalive_timeout.lo(), 4);
    assert_eq!(snapshot.timings.keepalive_timeout.hi(), 6);

    let request = SetRequest {
        extra_ports: Some(2),
        ..SetRequest::default()
    };
    pair.a.apply(request).unwrap();
    assert_eq!(pair.a.extra_ports(), 2);
    assert_eq!(pair.a.snapshot().extra_ports, 2);

    let request = SetRequest {
        extra_ports: Some(9),
        ..SetRequest::default()
    };
    pair.a.apply(request).unwrap();
    assert_eq!(pair.a.extra_ports(), 8);
    assert_eq!(pair.a.snapshot().extra_ports, 8);
}

#[test]
fn invalid_update_does_not_apply_destructive_changes() {
    let pair = pair(ObfParams::default());
    let key_before = pair.a.private_key();
    let peers_before = pair.a.snapshot().peers.len();
    assert_eq!(peers_before, 1);

    let mut request = SetRequest {
        private_key: Some(Key::from_bytes([0x77; 32])),
        replace_peers: true,
        ..SetRequest::default()
    };
    request.obfuscation.jmin = Some(100);
    request.obfuscation.jmax = Some(10);

    assert!(pair.a.apply(request).is_err());
    assert_eq!(pair.a.private_key(), key_before);
    assert_eq!(pair.a.snapshot().peers.len(), peers_before);
    assert_eq!(pair.a.obfuscation().jmin, 0);
}

#[test]
fn send_batch_coalesces_equal_lengths_and_keeps_order() {
    let mut pair = pair(ObfParams::default());
    let now = Instant::now();
    complete_handshake(&mut pair, now);

    let first = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], &[1u8; 100]);
    let second = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], &[2u8; 100]);
    let third = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], &[3u8; 40]);
    let mut output = vec![0u8; 65_535];
    let sent = {
        let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_a);
        pair.a
            .send_batch(
                &pair.peer_b,
                &[first.as_slice(), second.as_slice(), third.as_slice()],
                &mut output,
                &mut ctx,
            )
            .unwrap()
    };
    assert_eq!(sent.sent, 3);
    assert_eq!(sent.staged, 0);
    assert!(!sent.needs_handshake);
    assert_eq!(sent.endpoint, Some(pair.addr_b));
    assert_eq!(sent.layout.len(), 2);

    let groups = sent.layout.groups();
    assert_eq!(groups[0].segments, 2);
    assert_eq!(groups[0].len(), groups[0].segment_len * 2);
    assert_eq!(groups[1].segments, 1);
    assert_eq!(groups[1].segment_len, groups[1].len());

    for group in groups {
        let datagram = Sent {
            payload: output[group.start..group.end()].to_vec(),
            gso_size: (group.segments > 1).then_some(group.segment_len),
        };
        deliver_one(
            datagram,
            pair.addr_a,
            &pair.b,
            &mut pair.io_b,
            &mut pair.rng,
            now,
            &mut pair.scratch,
        );
    }
    assert_eq!(pair.io_b.delivered.len(), 3);
    assert_eq!(pair.io_b.delivered[0].1, first);
    assert_eq!(pair.io_b.delivered[1].1, second);
    assert_eq!(pair.io_b.delivered[2].1, third);
}

#[test]
fn send_batch_stages_without_keypair_and_flushes_in_order() {
    let mut pair = pair(ObfParams::default());
    let now = Instant::now();
    let first = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], b"first");
    let second = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], b"second");
    let third = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], b"third");
    let mut output = vec![0u8; 65_535];
    {
        let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_a);
        let sent = pair
            .a
            .send_batch(
                &pair.peer_b,
                &[first.as_slice(), second.as_slice(), third.as_slice()],
                &mut output,
                &mut ctx,
            )
            .unwrap();
        assert_eq!(sent.sent, 0);
        assert_eq!(sent.staged, 3);
        assert!(sent.needs_handshake);
        assert!(sent.layout.is_empty());
    }
    assert_eq!(pair.peer_b.staged_len(), 3);

    complete_handshake(&mut pair, now);
    assert_eq!(pair.peer_b.staged_len(), 0);
    let delivered: Vec<Vec<u8>> = pair
        .io_b
        .delivered
        .iter()
        .map(|(_, packet)| packet.clone())
        .collect();
    assert_eq!(delivered, vec![first, second, third]);
}

#[test]
fn send_batch_reports_missing_endpoint() {
    let sender = device(0x33, ObfParams::default());
    let receiver = device(0x44, ObfParams::default());
    let peer = sender
        .add_peer(PeerConfig::new(receiver.public_key().unwrap()))
        .unwrap();
    let packet = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], b"data");
    let mut output = vec![0u8; 65_535];
    let mut rng = TestRng::new(7);
    let mut scratch = vec![0u8; 65_535];
    let mut io = MemoryIo::new();
    let mut ctx = IoContext::new(&mut rng, Instant::now(), &mut scratch, &mut io);
    assert!(matches!(
        sender.send_batch(&peer, &[packet.as_slice()], &mut output, &mut ctx),
        Err(DeviceError::NoEndpoint)
    ));
    assert!(matches!(sender.after_batch_sent(&peer, &mut ctx), Ok(())));
}

#[test]
fn send_batch_without_data_is_a_noop() {
    let mut pair = pair(ObfParams::default());
    let now = Instant::now();
    complete_handshake(&mut pair, now);
    let mut output = vec![0u8; 64];
    let sent = {
        let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_a);
        pair.a
            .send_batch(&pair.peer_b, &[], &mut output, &mut ctx)
            .unwrap()
    };
    assert_eq!(sent.sent, 0);
    assert_eq!(sent.staged, 0);
    assert!(sent.layout.is_empty());
    assert!(pair.io_a.take_sent().is_empty());
}

#[test]
fn for_each_peer_visits_every_peer() {
    let a = device(1, ObfParams::default());
    let mut expected: Vec<PublicKey> = Vec::new();
    for byte in 1..4u8 {
        let config = PeerConfig::new(PublicKey::from_bytes([byte; 32]));
        expected.push(a.add_peer(config).unwrap().public_key());
    }
    expected.sort_by_key(PublicKey::to_bytes);

    let mut visited = Vec::new();
    a.for_each_peer(|peer| visited.push(peer.public_key()));
    visited.sort_by_key(PublicKey::to_bytes);
    assert_eq!(visited, expected);

    let peers: Vec<PublicKey> = a.peers().iter().map(|peer| peer.public_key()).collect();
    assert_eq!(peers, expected);
}

#[test]
fn incoming_snapshot_matches_handle_incoming() {
    let a = device(1, ObfParams::default());
    let snapshot = a.incoming_snapshot();
    let source: SocketAddr = "127.0.0.1:1000".parse().unwrap();
    let packets = [
        ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], b"snapshot"),
        vec![0u8; 32],
        vec![0xff; 148],
    ];
    for packet in packets {
        let mut io = MemoryIo::new();
        let mut rng = TestRng::new(3);
        let mut scratch = vec![0u8; 65_535];
        let mut ctx = IoContext::new(&mut rng, Instant::now(), &mut scratch, &mut io);
        let mut with_snapshot = packet.clone();
        let from_snapshot = a
            .handle_incoming_with(
                &mut with_snapshot,
                IncomingMeta::new(source, None),
                &snapshot,
                &mut ctx,
            )
            .unwrap();
        let mut plain = packet.clone();
        let outcome = a
            .handle_incoming(&mut plain, IncomingMeta::new(source, None), &mut ctx)
            .unwrap();
        assert_eq!(from_snapshot, outcome);
        assert_eq!(from_snapshot, IncomingOutcome::Dropped);
    }
}

fn encrypted_data(pair: &mut Pair, now: Instant, payload: &[u8]) -> Sent {
    let packet = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], payload);
    let mut output = vec![0u8; 65_535];
    {
        let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_a);
        pair.a
            .send_data(&pair.peer_b, &packet, &mut output, &mut ctx)
            .unwrap();
    }
    let mut sent = pair.io_a.take_sent();
    assert_eq!(sent.len(), 1);
    sent.remove(0)
}

#[test]
fn prepared_transport_is_delivered_like_the_direct_path() {
    let mut pair = pair(ObfParams::default());
    let now = Instant::now();
    complete_handshake(&mut pair, now);
    let packet = encrypted_data(&mut pair, now, b"direct path");

    let direct = deliver_one(
        packet.clone(),
        pair.addr_a,
        &pair.b,
        &mut pair.io_b,
        &mut pair.rng,
        now,
        &mut pair.scratch,
    );
    assert!(matches!(direct, IncomingOutcome::Delivered(_)));

    assert_eq!(pair.io_b.delivered.len(), 1);
    let second = encrypted_data(&mut pair, now, b"direct path");
    let mut payload = second.payload;
    let snapshot = pair.b.incoming_snapshot();
    let prepared = pair.b.prepare_incoming(&mut payload, &snapshot, now);
    assert!(matches!(prepared, PreparedIncoming::Transport(_)));
    let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_b);
    let outcome = pair
        .b
        .handle_prepared(&mut payload, prepared, pair.addr_a, &snapshot, &mut ctx)
        .unwrap();
    assert!(matches!(outcome, IncomingOutcome::Delivered(_)));
    assert_eq!(pair.io_b.delivered.len(), 2);
    assert_eq!(pair.io_b.delivered[0].0, pair.io_b.delivered[1].0);
    assert_eq!(pair.io_b.delivered[0].1, pair.io_b.delivered[1].1);
}

#[test]
fn prepared_transport_rejects_a_replay() {
    let mut pair = pair(ObfParams::default());
    let now = Instant::now();
    complete_handshake(&mut pair, now);
    let packet = encrypted_data(&mut pair, now, b"replay path");

    let mut payload = packet.payload.clone();
    let snapshot = pair.b.incoming_snapshot();
    let prepared = pair.b.prepare_incoming(&mut payload, &snapshot, now);
    assert!(matches!(prepared, PreparedIncoming::Transport(_)));
    let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_b);
    assert!(matches!(
        pair.b
            .handle_prepared(&mut payload, prepared, pair.addr_a, &snapshot, &mut ctx)
            .unwrap(),
        IncomingOutcome::Delivered(_)
    ));

    let mut duplicate = packet.payload;
    let prepared = pair.b.prepare_incoming(&mut duplicate, &snapshot, now);
    assert!(matches!(prepared, PreparedIncoming::Transport(_)));
    let outcome = pair
        .b
        .handle_prepared(&mut duplicate, prepared, pair.addr_a, &snapshot, &mut ctx)
        .unwrap();
    assert_eq!(outcome, IncomingOutcome::Dropped);
    assert_eq!(pair.io_b.delivered.len(), 1);
}

#[test]
fn prepared_control_packet_completes_the_handshake() {
    let mut pair = pair(ObfParams::default());
    let now = Instant::now();
    {
        let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_a);
        pair.a.initiate_handshake(&pair.peer_b, &mut ctx).unwrap();
    }
    let mut sent = pair.io_a.take_sent();
    assert_eq!(sent.len(), 1);
    let mut payload = sent.remove(0).payload;
    let snapshot = pair.b.incoming_snapshot();
    let prepared = pair.b.prepare_incoming(&mut payload, &snapshot, now);
    assert!(matches!(prepared, PreparedIncoming::Control(_)));
    let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_b);
    let outcome = pair
        .b
        .handle_prepared(&mut payload, prepared, pair.addr_a, &snapshot, &mut ctx)
        .unwrap();
    assert_eq!(outcome, IncomingOutcome::Handshake);
    assert!(!pair.io_b.take_sent().is_empty());
}

#[test]
fn prepared_unknown_session_is_dropped() {
    let mut pair = pair(ObfParams::default());
    let now = Instant::now();
    complete_handshake(&mut pair, now);
    let packet = encrypted_data(&mut pair, now, b"unknown path");
    let mut payload = packet.payload;
    payload[4..8].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    let snapshot = pair.b.incoming_snapshot();
    let prepared = pair.b.prepare_incoming(&mut payload, &snapshot, now);
    assert!(matches!(prepared, PreparedIncoming::Dropped));
}

#[test]
fn prepared_gro_segments_are_delivered_independently() {
    let mut pair = pair(ObfParams::default());
    let now = Instant::now();
    complete_handshake(&mut pair, now);

    let mut payloads = Vec::new();
    for index in 0..3u8 {
        let packet = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], &[b'A' + index; 100]);
        let mut output = vec![0u8; 65_535];
        {
            let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_a);
            pair.a
                .send_data(&pair.peer_b, &packet, &mut output, &mut ctx)
                .unwrap();
        }
        payloads.push(pair.io_a.take_sent().remove(0).payload);
    }
    let gro_size = payloads[0].len();
    assert!(payloads.iter().all(|payload| payload.len() == gro_size));
    let mut datagram: Vec<u8> = payloads.concat();
    let snapshot = pair.b.incoming_snapshot();

    for offset in (0..datagram.len()).step_by(gro_size) {
        let segment = &mut datagram[offset..offset + gro_size];
        let prepared = pair.b.prepare_incoming(segment, &snapshot, now);
        assert!(matches!(prepared, PreparedIncoming::Transport(_)));
        let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_b);
        let outcome = pair
            .b
            .handle_prepared(segment, prepared, pair.addr_a, &snapshot, &mut ctx)
            .unwrap();
        assert!(matches!(outcome, IncomingOutcome::Delivered(_)));
    }
    assert_eq!(pair.io_b.delivered.len(), 3);
}
