use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand_core::RngCore;

use umbrawg_crypto::{Key, PrivateKey, PublicKey};
use umbrawg_device::{
    AllowedIp, BbrMode, DatagramSink, Device, DeviceConfig, DeviceControl, DeviceError, ExtConfig,
    FecMode, IncomingMeta, IncomingOutcome, IoContext, PacketIo, Peer, PeerConfig, PeerState,
    PreparedIncoming, SendOutcome, TimerEvent, TimerKind, Timings, DEFAULT_EXTRA_PORTS,
};
use umbrawg_proto::control::{Caps, CapsFlags};
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

fn send_data(pair: &mut Pair, from_a: bool, payload: &[u8], now: Instant) {
    let mut output = vec![0u8; 65_535];
    if from_a {
        let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_a);
        pair.a
            .send_data(&pair.peer_b, payload, &mut output, &mut ctx)
            .unwrap();
    } else {
        let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_b);
        pair.b
            .send_data(&pair.peer_a, payload, &mut output, &mut ctx)
            .unwrap();
    }
}

fn deliver_all(pair: &mut Pair, from_a: bool, now: Instant) {
    if from_a {
        flush(
            pair.addr_a,
            &pair.b,
            &mut pair.io_a,
            &mut pair.io_b,
            &mut pair.rng,
            now,
            &mut pair.scratch,
        );
    } else {
        flush(
            pair.addr_b,
            &pair.a,
            &mut pair.io_b,
            &mut pair.io_a,
            &mut pair.rng,
            now,
            &mut pair.scratch,
        );
    }
}

fn send_caps_frame(
    pair: &mut Pair,
    from_a: bool,
    flags: CapsFlags,
    fec_k: u8,
    fec_m: u8,
    now: Instant,
) {
    let caps = Caps {
        flags,
        ack_interval_packets: 2,
        fec_k,
        fec_m,
    };
    let mut frame = [0u8; 32];
    let length = caps.encode(&mut frame).unwrap();
    let mut dst = [0u8; 1024];
    if from_a {
        let length = pair
            .a
            .encrypt_control_packet(&pair.peer_b, &frame[..length], &mut dst, &mut pair.rng, now)
            .unwrap();
        pair.io_a
            .send_datagram(pair.addr_a, Some(&pair.peer_b), &dst[..length], None);
    } else {
        let length = pair
            .b
            .encrypt_control_packet(&pair.peer_a, &frame[..length], &mut dst, &mut pair.rng, now)
            .unwrap();
        pair.io_b
            .send_datagram(pair.addr_b, Some(&pair.peer_a), &dst[..length], None);
    }
}

fn has_new_handshake(device: &Device, peer: &Peer, at: Instant) -> bool {
    let mut events = [TimerEvent {
        peer: peer.id(),
        kind: TimerKind::NewHandshake,
    }; 8];
    let count = device.poll_timers(at, &mut events);
    events[..count]
        .iter()
        .any(|event| event.peer == peer.id() && event.kind == TimerKind::NewHandshake)
}

/// Waits for a fresh real-time TAI64N timestamp bucket.
///
/// WireGuard rejects an initiation whose timestamp is not strictly greater
/// than the last consumed one, and [`umbrawg_crypto::tai64n::Tai64N::now`]
/// quantizes nanoseconds to ~16.7 ms. Tests drive the device with simulated
/// `Instant`s, so a second handshake in the same run still has to wait for the
/// wall clock to leave the previous bucket.
fn wait_for_fresh_timestamp() {
    std::thread::sleep(Duration::from_millis(25));
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
fn zero_header_protection_key_is_plain_on_the_wire() {
    let params = ObfParams {
        header_protection_key: Some(key(0)),
        ..ObfParams::default()
    };
    let mut pair = pair(params);
    let now = Instant::now();
    complete_handshake(&mut pair, now);

    let packet = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], b"zero key");
    send_data(&mut pair, true, &packet, now);
    deliver_all(&mut pair, true, now);
    assert_eq!(pair.io_b.delivered.len(), 1);
    assert_eq!(pair.io_b.delivered[0].1, packet);
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

    let packets: Vec<Vec<u8>> = (0..3u8)
        .map(|index| ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], &[b'A' + index; 100]))
        .collect();
    let plaintexts: Vec<&[u8]> = packets.iter().map(Vec::as_slice).collect();
    let mut output = vec![0u8; 65_535];
    let layout = {
        let mut rng = TestRng::new(19);
        pair.a
            .encrypt_batch(&pair.peer_b, &plaintexts, &mut output, &mut rng, now)
            .unwrap()
    };
    assert_eq!(layout.len(), 1);
    let group = layout.groups()[0];
    assert_eq!(group.segments, 3);
    let gro_size = group.segment_len;
    let mut datagram = output[..layout.total_len()].to_vec();
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

#[test]
fn control_frames_get_bounded_padding() {
    let params = ObfParams {
        random_trailers: true,
        ..ObfParams::default()
    };
    let mut pair = pair(params);
    let now = Instant::now();
    complete_handshake(&mut pair, now);

    let big = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], &[7u8; 1200]);
    let mut output = vec![0u8; 65_535];
    {
        let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_a);
        pair.a
            .send_data(&pair.peer_b, &big, &mut output, &mut ctx)
            .unwrap();
    }
    pair.io_a.take_sent();

    let frame = [0u8; 32];
    let base = 16 + frame.len() + 16;
    let mut lengths = std::collections::HashSet::new();
    for _ in 0..96 {
        let mut dst = vec![0u8; 1024];
        let length = pair
            .a
            .encrypt_control_packet(&pair.peer_b, &frame, &mut dst, &mut pair.rng, now)
            .unwrap();
        assert!(length >= base);
        assert!(length <= base + 15, "control frame grew to {length} bytes");
        lengths.insert(length);
    }
    assert!(lengths.len() > 1, "control padding must vary");
}

#[test]
fn full_mtu_random_trailers_keep_a_small_reserve() {
    let params = ObfParams {
        random_trailers: true,
        ..ObfParams::default()
    };
    let mut pair = pair(params);
    let now = Instant::now();
    complete_handshake(&mut pair, now);

    let packet = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], &[3u8; 1400]);
    let base = 16 + packet.len() + 16;
    let mut lengths = std::collections::HashSet::new();
    for _ in 0..96 {
        let mut output = vec![0u8; 65_535];
        {
            let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_a);
            pair.a
                .send_data(&pair.peer_b, &packet, &mut output, &mut ctx)
                .unwrap();
        }
        let sent = pair.io_a.take_sent();
        assert_eq!(sent.len(), 1);
        let length = sent[0].payload.len();
        assert!(length >= base);
        assert!(
            length <= base + 15,
            "full-MTU trailer grew to {length} bytes"
        );
        lengths.insert(length);
    }
    assert!(
        lengths.len() > 1,
        "full-MTU packets must not share one length"
    );
}

#[test]
fn mixed_batches_pad_small_packets_without_splitting_them() {
    // A TUN batch can mix a full-MTU packet with small inner ACKs. The full
    // packet has no room inside the UDP window, but the ACKs do: they must
    // still receive the batch's random addition and stay equal to each other.
    let mut pair = pair(ObfParams {
        content_padding_addition: 51..=197,
        ..ObfParams::default()
    });
    let now = Instant::now();
    complete_handshake(&mut pair, now);

    let big = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], &[1u8; 1400]);
    let small = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], &[2u8; 52]);
    let plaintexts: [&[u8]; 4] = [&big, &small, &small, &small];
    let small_base = 16 + small.len() + 16;
    let mut output = vec![0u8; 65_535];
    let layout = {
        let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_a);
        pair.a
            .send_batch(&pair.peer_b, &plaintexts, &mut output, &mut ctx)
            .unwrap()
            .layout
    };
    assert_eq!(
        layout.len(),
        2,
        "big and small packets are separate GSO groups"
    );
    assert_eq!(layout.groups()[0].segments, 1);
    assert_eq!(layout.groups()[1].segments, 3);
    assert!(
        layout.groups()[1].segment_len >= small_base + 51,
        "small packets keep the content padding addition"
    );
}

#[test]
fn batch_padding_keeps_equal_packets_gso_compatible() {
    // Both padding policies must draw once per batch: equal plaintexts have to
    // keep equal wire lengths or UDP GSO degenerates into one datagram per
    // packet. Small inner packets (TCP ACKs) are where the addition actually
    // applies, because a full-MTU packet has no room inside the UDP window.
    for params in [
        ObfParams {
            random_trailers: true,
            ..ObfParams::default()
        },
        ObfParams {
            content_padding_addition: 51..=197,
            ..ObfParams::default()
        },
        ObfParams {
            random_trailers: true,
            content_padding_addition: 51..=197,
            ..ObfParams::default()
        },
    ] {
        let padding_enabled = params.content_padding_addition_enabled() || params.random_trailers;
        let content_padding_enabled = params.content_padding_addition_enabled();
        let mut pair = pair(params);
        let now = Instant::now();
        complete_handshake(&mut pair, now);

        let packets: Vec<Vec<u8>> = (0..4u8)
            .map(|index| ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], &[b'a' + index; 52]))
            .collect();
        let plaintexts: Vec<&[u8]> = packets.iter().map(Vec::as_slice).collect();
        let base = 16 + packets[0].len() + 16;
        let mut output = vec![0u8; 65_535];
        let mut seen = std::collections::HashSet::new();
        for _ in 0..32 {
            let layout = {
                let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_a);
                let sent = pair
                    .a
                    .send_batch(&pair.peer_b, &plaintexts, &mut output, &mut ctx)
                    .unwrap();
                sent.layout
            };
            assert_eq!(
                layout.len(),
                1,
                "equal plaintexts must coalesce into one GSO group"
            );
            assert_eq!(layout.groups()[0].segments, plaintexts.len());
            if padding_enabled {
                assert!(layout.groups()[0].segment_len >= base);
                seen.insert(layout.groups()[0].segment_len);
            }
        }
        if content_padding_enabled {
            assert!(
                seen.iter().all(|length| *length >= base + 51),
                "content padding addition must stay in range: {seen:?}"
            );
        }
        if padding_enabled {
            assert!(seen.len() > 1, "batch padding must vary between batches");
        }
    }
}

#[test]
fn fec_shards_fit_an_ethernet_underlay() {
    // 1500-byte underlay with IPv6+UDP headers leaves a 1452-byte datagram
    // budget. A one-shard frame adds 2 (length) + 20 (extension+FEC headers)
    // + up to 31 (shard padding) + 15 (control padding) + 32 (transport
    // header and AEAD tag), so the derived shard limit is 1385 and the TUN MTU
    // is 1352. See `umbrawg::mtu` for the production formulas.
    const UNDERLAY_BUDGET: usize = 1500 - 48;
    const MAX_SHARD_LEN: u16 = 1385;
    const TUN_MTU: usize = 1352;

    let mut pair = pair(ObfParams::default());
    let ext = ExtConfig {
        fec: FecMode::Fixed { k: 2, m: 1 },
        ack_interval: 2,
        max_shard_len: MAX_SHARD_LEN,
        ..ExtConfig::default()
    };
    pair.a.set_ext_config(ext);
    pair.b.set_ext_config(ext);
    let now = Instant::now();
    complete_handshake(&mut pair, now);
    let flags = CapsFlags::ACK | CapsFlags::FEC;
    send_caps_frame(&mut pair, true, flags, 2, 1, now);
    deliver_all(&mut pair, true, now);
    send_caps_frame(&mut pair, false, flags, 2, 1, now);
    deliver_all(&mut pair, false, now);

    let payload = vec![0x5a; TUN_MTU - 20];
    let first = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], &payload);
    let second = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], &payload);
    assert_eq!(first.len(), TUN_MTU);

    let mut output = vec![0u8; 65_535];
    let layout = {
        let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_a);
        let sent = pair
            .a
            .send_batch(&pair.peer_b, &[&first, &second], &mut output, &mut ctx)
            .unwrap();
        assert_eq!(sent.sent, 2);
        sent.layout
    };
    let ranges: Vec<std::ops::Range<usize>> = layout
        .groups()
        .iter()
        .flat_map(|group| group.ranges())
        .collect();
    assert_eq!(ranges.len(), 3, "k=2, m=1 must produce three shards");
    for range in &ranges {
        assert!(
            range.len() <= UNDERLAY_BUDGET,
            "FEC shard datagram {} exceeds the {UNDERLAY_BUDGET}-byte budget",
            range.len()
        );
        pair.io_a.send_datagram(
            pair.addr_a,
            Some(&pair.peer_b),
            &output[range.clone()],
            None,
        );
    }

    deliver_all(&mut pair, true, now);
    assert_eq!(pair.io_b.delivered.len(), 2);
}

#[test]
fn extension_frames_disarm_the_new_handshake_timer() {
    let mut pair = pair(ObfParams::default());
    let ext = ExtConfig {
        bbr: BbrMode::Monitor,
        ..ExtConfig::default()
    };
    pair.a.set_ext_config(ext);
    pair.b.set_ext_config(ext);
    let now = Instant::now();
    complete_handshake(&mut pair, now);
    let at = now + Duration::from_secs(30);
    let data = ipv4_packet([10, 0, 0, 2], [10, 0, 0, 1], b"ping");

    send_data(&mut pair, false, &data, now);
    deliver_all(&mut pair, false, now);
    assert!(
        has_new_handshake(&pair.b, &pair.peer_a, at),
        "sending data must arm NewHandshake"
    );

    send_data(&mut pair, false, &data, now);
    deliver_all(&mut pair, false, now);
    assert!(
        has_new_handshake(&pair.b, &pair.peer_a, at),
        "sending data must re-arm NewHandshake after a tick"
    );

    send_data(&mut pair, false, &data, now);
    deliver_all(&mut pair, false, now);
    send_caps_frame(&mut pair, true, CapsFlags::BBR | CapsFlags::ACK, 0, 0, now);
    deliver_all(&mut pair, true, now);
    assert!(
        !has_new_handshake(&pair.b, &pair.peer_a, at),
        "an authenticated extension frame must disarm NewHandshake"
    );
}

#[test]
fn fec_shards_are_visible_to_bbr() {
    let mut pair = pair(ObfParams::default());
    let ext = ExtConfig {
        bbr: BbrMode::On,
        fec: FecMode::Fixed { k: 2, m: 1 },
        ack_interval: 2,
        max_shard_len: 1900,
    };
    pair.a.set_ext_config(ext);
    pair.b.set_ext_config(ext);
    let now = Instant::now();
    complete_handshake(&mut pair, now);

    let flags = CapsFlags::BBR | CapsFlags::ACK | CapsFlags::FEC;
    send_caps_frame(&mut pair, true, flags, 2, 1, now);
    deliver_all(&mut pair, true, now);
    send_caps_frame(&mut pair, false, flags, 2, 1, now);
    deliver_all(&mut pair, false, now);
    pair.io_a.take_sent();
    pair.io_b.take_sent();

    let first = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], b"first");
    let second = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], b"second");
    let mut output = vec![0u8; 65_535];
    let layout = {
        let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_a);
        let sent = pair
            .a
            .send_batch(&pair.peer_b, &[&first, &second], &mut output, &mut ctx)
            .unwrap();
        assert_eq!(sent.sent, 2);
        sent.layout
    };
    let ranges: Vec<std::ops::Range<usize>> = layout
        .groups()
        .iter()
        .flat_map(|group| group.ranges())
        .collect();
    assert_eq!(ranges.len(), 3, "k=2, m=1 must produce three shards");
    for range in ranges {
        pair.io_a
            .send_datagram(pair.addr_a, Some(&pair.peer_b), &output[range], None);
    }

    let stats = pair.a.bbr_stats(&pair.peer_b).expect("bbr is enabled");
    assert!(stats.inflight > 0, "FEC shards must enter the BBR ring");
    assert_eq!(stats.delivered, 0);

    let tx = pair.a.fec_stats(&pair.peer_b).expect("FEC is configured");
    assert_eq!(tx.blocks_encoded, 1);
    assert_eq!(tx.shards_sent, 3);

    deliver_all(&mut pair, true, now);
    assert_eq!(pair.io_b.delivered.len(), 2);
    let rx = pair.b.fec_stats(&pair.peer_a).expect("FEC is configured");
    assert_eq!(rx.blocks_decoded, 1);
    assert!(rx.packets_recovered <= 1);
    assert_eq!(rx.decode_fail, 0);

    {
        let later = now + Duration::from_millis(5);
        let mut ctx = IoContext::new(&mut pair.rng, later, &mut pair.scratch, &mut pair.io_b);
        pair.b.flush_staged(&pair.peer_a, &mut ctx).unwrap();
    }
    assert!(!pair.io_b.sent.is_empty(), "the receiver must ACK shards");
    let later = now + Duration::from_millis(5);
    deliver_all(&mut pair, false, later);

    let stats = pair.a.bbr_stats(&pair.peer_b).expect("bbr is enabled");
    assert!(stats.delivered > 0, "ACKed shards must count as delivered");
    assert_eq!(stats.inflight, 0);
}

const FEC_UNDERLAY_SHARD_LEN: u16 = 1385;
const FEC_TUN_MTU: usize = 1352;

fn fec_ext_config() -> ExtConfig {
    ExtConfig {
        bbr: BbrMode::On,
        fec: FecMode::Fixed { k: 2, m: 1 },
        ack_interval: 2,
        max_shard_len: FEC_UNDERLAY_SHARD_LEN,
    }
}

fn exchange_caps(pair: &mut Pair, now: Instant) {
    let flags = CapsFlags::BBR | CapsFlags::ACK | CapsFlags::FEC;
    send_caps_frame(pair, true, flags, 2, 1, now);
    deliver_all(pair, true, now);
    send_caps_frame(pair, false, flags, 2, 1, now);
    deliver_all(pair, false, now);
}

/// Sends a batch through FEC and forwards the produced datagrams to the other
/// side. Returns the number of datagrams the FEC encoder laid out.
fn send_fec_batch(pair: &mut Pair, from_a: bool, packets: &[&[u8]], now: Instant) -> usize {
    let mut output = vec![0u8; 65_535];
    let layout = if from_a {
        let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_a);
        pair.a
            .send_batch(&pair.peer_b, packets, &mut output, &mut ctx)
            .unwrap()
            .layout
    } else {
        let mut ctx = IoContext::new(&mut pair.rng, now, &mut pair.scratch, &mut pair.io_b);
        pair.b
            .send_batch(&pair.peer_a, packets, &mut output, &mut ctx)
            .unwrap()
            .layout
    };
    let ranges: Vec<std::ops::Range<usize>> = layout
        .groups()
        .iter()
        .flat_map(|group| group.ranges())
        .collect();
    for range in &ranges {
        if from_a {
            pair.io_a.send_datagram(
                pair.addr_a,
                Some(&pair.peer_b),
                &output[range.clone()],
                None,
            );
        } else {
            pair.io_b.send_datagram(
                pair.addr_b,
                Some(&pair.peer_a),
                &output[range.clone()],
                None,
            );
        }
    }
    ranges.len()
}

fn full_size_packet(marker: u8) -> Vec<u8> {
    ipv4_packet(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        &vec![marker; FEC_TUN_MTU - 20],
    )
}

fn full_size_packet_back(marker: u8) -> Vec<u8> {
    ipv4_packet(
        [10, 0, 0, 2],
        [10, 0, 0, 1],
        &vec![marker; FEC_TUN_MTU - 20],
    )
}

#[test]
fn rekey_keeps_fec_caps_and_flushes_full_size_shards() {
    let mut pair = pair(ObfParams::default());
    let ext = fec_ext_config();
    pair.a.set_ext_config(ext);
    pair.b.set_ext_config(ext);
    let now = Instant::now();
    complete_handshake(&mut pair, now);
    exchange_caps(&mut pair, now);

    // A complete block before the rekey, so the initiator has non-zero BBR
    // state that must be discarded by the keypair switch.
    let first = full_size_packet(0x11);
    let second = full_size_packet(0x22);
    assert_eq!(
        send_fec_batch(&mut pair, true, &[&first, &second], now),
        3,
        "k=2, m=1 must produce three full-size shards"
    );
    deliver_all(&mut pair, true, now);
    assert_eq!(pair.io_b.delivered.len(), 2);

    {
        let later = now + Duration::from_millis(5);
        let mut ctx = IoContext::new(&mut pair.rng, later, &mut pair.scratch, &mut pair.io_b);
        pair.b.flush_staged(&pair.peer_a, &mut ctx).unwrap();
    }
    deliver_all(&mut pair, false, now + Duration::from_millis(5));
    assert!(
        pair.a
            .bbr_stats(&pair.peer_b)
            .expect("bbr is enabled")
            .delivered
            > 0,
        "the ACK round must move the initiator BBR state"
    );

    // A partial block in the encoder at the moment of the rekey. Its shard is
    // bigger than the old 1 KiB control buffer. A lone packet starts a block
    // and is flushed at once, so the block is opened by a pair of packets
    // inside the batching window: the second one stays queued.
    let third = full_size_packet(0x33);
    let queued = full_size_packet(0x34);
    let burst = now + Duration::from_millis(6);
    assert_eq!(
        send_fec_batch(&mut pair, true, &[&third], burst),
        1,
        "a lone packet is flushed at once without waiting for the deadline"
    );
    assert_eq!(
        send_fec_batch(
            &mut pair,
            true,
            &[&queued],
            burst + Duration::from_micros(100)
        ),
        0,
        "a packet inside the batching window stays queued"
    );
    let encoded_before = pair
        .a
        .fec_stats(&pair.peer_b)
        .expect("FEC is configured")
        .blocks_encoded;
    let decoded_before = pair
        .b
        .fec_stats(&pair.peer_a)
        .expect("FEC is configured")
        .blocks_decoded;

    pair.io_a.sent.clear();
    pair.io_b.sent.clear();
    pair.io_b.delivered.clear();

    let rekey_at = now + Duration::from_secs(6);
    let before = pair.peer_b.current_keypair().expect("keypair");
    wait_for_fresh_timestamp();
    complete_handshake(&mut pair, rekey_at);
    assert!(
        !Arc::ptr_eq(&before, &pair.peer_b.current_keypair().expect("keypair")),
        "the test must install a new keypair"
    );

    let initiator = pair.a.bbr_stats(&pair.peer_b).expect("bbr is enabled");
    assert_eq!(
        initiator.delivered, 0,
        "the initiator must start a fresh BBR epoch after a rekey"
    );
    assert!(
        initiator.inflight > 0,
        "the shard flushed at the rekey must enter the new BBR ring"
    );
    let encoded = pair
        .a
        .fec_stats(&pair.peer_b)
        .expect("FEC is configured")
        .blocks_encoded;
    assert!(
        encoded > encoded_before,
        "the partial block must be flushed into shard frames at the rekey"
    );
    assert_eq!(
        pair.io_b.delivered.len(),
        1,
        "the full-size shard flushed at the rekey must be decoded, not dropped"
    );
    assert_eq!(pair.io_b.delivered[0].1.len(), FEC_TUN_MTU);
    let rx = pair.b.fec_stats(&pair.peer_a).expect("FEC is configured");
    assert_eq!(
        rx.blocks_decoded,
        decoded_before + 1,
        "the flushed full-size shard must be decoded"
    );
    assert_eq!(
        rx.dropped_disabled, 0,
        "the responder must keep the initiator CAPS across the rekey"
    );

    // The responder keeps the initiator CAPS too: it must still emit FEC
    // shards after promoting the new keypair.
    let fourth = full_size_packet_back(0x44);
    let fifth = full_size_packet_back(0x55);
    pair.io_a.delivered.clear();
    assert_eq!(
        send_fec_batch(&mut pair, false, &[&fourth, &fifth], rekey_at),
        3,
        "the responder must keep FEC TX enabled across the rekey"
    );
    deliver_all(&mut pair, false, rekey_at);
    assert_eq!(pair.io_a.delivered.len(), 2);
}

#[test]
fn config_change_flushes_full_size_shards_instead_of_stranding_them() {
    let mut pair = pair(ObfParams::default());
    let ext = fec_ext_config();
    pair.a.set_ext_config(ext);
    pair.b.set_ext_config(ext);
    let now = Instant::now();
    complete_handshake(&mut pair, now);
    exchange_caps(&mut pair, now);

    let packet = full_size_packet(0x66);
    assert_eq!(
        send_fec_batch(&mut pair, true, &[&packet], now),
        0,
        "one packet of a k=2 block produces no datagram yet"
    );
    pair.io_a.sent.clear();
    pair.io_b.delivered.clear();

    // Disabling FEC on the sender must release the block it just flushed.
    pair.a.set_ext_config(ExtConfig {
        fec: FecMode::Off,
        ..ext
    });
    {
        let later = now + Duration::from_millis(1);
        let mut ctx = IoContext::new(&mut pair.rng, later, &mut pair.scratch, &mut pair.io_a);
        pair.a.flush_staged(&pair.peer_b, &mut ctx).unwrap();
    }
    assert!(
        pair.io_a.sent.iter().any(|sent| sent.payload.len() > 1024),
        "the full-size shard must leave the device, not be dropped by a 1 KiB buffer"
    );

    deliver_all(&mut pair, true, now + Duration::from_millis(1));
    assert_eq!(pair.io_b.delivered.len(), 1);
    assert_eq!(pair.io_b.delivered[0].1.len(), FEC_TUN_MTU);
    assert_eq!(
        pair.b
            .fec_stats(&pair.peer_a)
            .expect("FEC is configured")
            .blocks_decoded,
        1
    );
}

#[test]
fn turning_fec_off_revokes_the_stale_advertisement_with_zero_caps() {
    let mut pair = pair(ObfParams::default());
    let ext = fec_ext_config();
    pair.a.set_ext_config(ext);
    pair.b.set_ext_config(ext);
    let now = Instant::now();
    complete_handshake(&mut pair, now);
    exchange_caps(&mut pair, now);
    pair.io_a.take_sent();
    pair.io_b.take_sent();

    // B switches every extension off while A still believes B runs FEC.
    pair.b.set_ext_config(ExtConfig::default());
    let revocation_at = now + Duration::from_millis(1);
    {
        let mut ctx = IoContext::new(
            &mut pair.rng,
            revocation_at,
            &mut pair.scratch,
            &mut pair.io_b,
        );
        pair.b.flush_control(&pair.peer_a, &mut ctx);
    }
    assert!(
        !pair.io_b.sent.is_empty(),
        "the all-off side must retract its old CAPS instead of staying silent"
    );
    deliver_all(&mut pair, false, revocation_at);

    // A must have dropped the stale peer FEC capability: a batch now goes out
    // as plain packets instead of FEC shards.
    let first = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], b"first");
    let second = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], b"second");
    let mut output = vec![0u8; 65_535];
    let layout = {
        let mut ctx = IoContext::new(
            &mut pair.rng,
            revocation_at + Duration::from_millis(1),
            &mut pair.scratch,
            &mut pair.io_a,
        );
        pair.a
            .send_batch(&pair.peer_b, &[&first, &second], &mut output, &mut ctx)
            .unwrap()
            .layout
    };
    let groups = layout
        .groups()
        .iter()
        .flat_map(|group| group.ranges())
        .count();
    assert_eq!(
        groups, 2,
        "after the zero CAPS the sender must stop FEC encoding"
    );
}

#[test]
fn fec_block_ids_survive_a_one_sided_mtu_change() {
    let mut pair = pair(ObfParams::default());
    let ext = fec_ext_config();
    pair.a.set_ext_config(ext);
    pair.b.set_ext_config(ext);
    let now = Instant::now();
    complete_handshake(&mut pair, now);
    exchange_caps(&mut pair, now);

    let first = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], &vec![0x11; 900]);
    let second = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], &vec![0x22; 900]);
    assert_eq!(send_fec_batch(&mut pair, true, &[&first, &second], now), 3);
    deliver_all(&mut pair, true, now);
    assert_eq!(pair.io_b.delivered.len(), 2);
    pair.io_b.delivered.clear();

    // One-sided MTU change: `k`/`m` stay the same, so TX remains enabled, but
    // the encoder is recreated. Its block sequence must continue.
    pair.a.set_ext_config(ExtConfig {
        max_shard_len: 1200,
        ..ext
    });
    let third = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], &vec![0x33; 900]);
    let fourth = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], &vec![0x44; 900]);
    let later = now + Duration::from_millis(1);
    assert_eq!(
        send_fec_batch(&mut pair, true, &[&third, &fourth], later),
        3
    );
    deliver_all(&mut pair, true, later);
    assert_eq!(
        pair.io_b.delivered.len(),
        2,
        "block ids restarted at 0 would be rejected by the peer as ancient"
    );
}

#[test]
fn stale_ack_from_the_previous_keypair_is_ignored() {
    let mut pair = pair(ObfParams::default());
    let ext = ExtConfig {
        bbr: BbrMode::On,
        ..ExtConfig::default()
    };
    pair.a.set_ext_config(ext);
    pair.b.set_ext_config(ext);
    let now = Instant::now();
    complete_handshake(&mut pair, now);
    let flags = CapsFlags::BBR | CapsFlags::ACK;
    // Only the responder advertises: A receives ACK feedback and can track
    // inflight, while its own first data packet still uses counter 0. That is
    // what makes the stale ACK below name a counter of the new epoch too.
    send_caps_frame(&mut pair, false, flags, 0, 0, now);
    deliver_all(&mut pair, false, now);

    let one = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], b"one");
    send_data(&mut pair, true, &one, now);
    deliver_all(&mut pair, true, now);
    {
        let later = now + Duration::from_millis(5);
        let mut ctx = IoContext::new(&mut pair.rng, later, &mut pair.scratch, &mut pair.io_b);
        pair.b.flush_staged(&pair.peer_a, &mut ctx).unwrap();
    }
    let stale_ack = pair.io_b.take_sent();
    assert!(
        !stale_ack.is_empty(),
        "the receiver must ACK the first keypair"
    );

    let rekey_at = now + Duration::from_secs(6);
    let before = pair.peer_b.current_keypair().expect("keypair");
    wait_for_fresh_timestamp();
    complete_handshake(&mut pair, rekey_at);
    assert!(
        !Arc::ptr_eq(&before, &pair.peer_b.current_keypair().expect("keypair")),
        "the test must install a new keypair"
    );
    assert_eq!(
        pair.a
            .bbr_stats(&pair.peer_b)
            .expect("bbr is enabled")
            .delivered,
        0
    );

    // The first data packet of the new epoch reuses counter 0, exactly the
    // `largest_counter` of the ACK captured above.
    let three = ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], b"three");
    send_data(&mut pair, true, &three, rekey_at + Duration::from_millis(1));
    {
        let stats = pair.a.bbr_stats(&pair.peer_b).expect("bbr is enabled");
        assert!(
            stats.inflight > 0,
            "the new epoch must carry data for a stale ACK to bite"
        );
        assert_eq!(stats.delivered, 0);
    }

    let deliver_at = rekey_at + Duration::from_millis(2);
    for packet in stale_ack {
        deliver_one(
            packet,
            pair.addr_b,
            &pair.a,
            &mut pair.io_a,
            &mut pair.rng,
            deliver_at,
            &mut pair.scratch,
        );
    }

    let stats = pair.a.bbr_stats(&pair.peer_b).expect("bbr is enabled");
    assert_eq!(
        stats.delivered, 0,
        "an ACK decrypted with the previous keypair must not acknowledge the new epoch"
    );
    assert!(
        stats.inflight > 0,
        "the stale ACK must not release the new epoch's in-flight data"
    );
}
