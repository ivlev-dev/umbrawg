use std::env;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use rand_core::OsRng;

use umbrawg_crypto::tai64n::Tai64N;
use umbrawg_crypto::{Key, PublicKey};
use umbrawg_noise::{CookieGenerator, Handshake, StaticIdentity};
use umbrawg_proto::obf::{MessageKind, Obfuscator};
use umbrawg_proto::ObfParams;

const MAX_FLOOD_PACKET: usize = 2048;

struct Options {
    target: SocketAddr,
    public_key: PublicKey,
    pps: u64,
    seconds: u64,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("flood: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let options = parse_args(env::args().skip(1))?;
    let identity = StaticIdentity::generate(&mut OsRng);
    let remote = options.public_key;
    let params = ObfParams::default();
    let obfuscator = Obfuscator::new(&params);
    let mut handshake = Handshake::new(&identity, remote, Key::from_bytes([0u8; 32]));
    let mut cookies = CookieGenerator::new(remote);
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(options.target)?;
    let mut rng = OsRng;
    let mut packet = vec![0u8; MAX_FLOOD_PACKET];
    let deadline = Instant::now() + Duration::from_secs(options.seconds);
    let interval = Duration::from_nanos(1_000_000_000 / options.pps.max(1));
    let mut next = Instant::now();
    let mut sent = 0u64;
    let mut index = 1u32;

    while Instant::now() < deadline {
        let header = obfuscator.pick_header(MessageKind::Initiation, &mut rng);
        let raw = handshake.create_initiation(&identity, &mut rng, header, index, Tai64N::now())?;
        let (_, layout) =
            obfuscator.begin_fixed(MessageKind::Initiation, &mut rng, 0, &mut packet)?;
        packet[layout.body.clone()].copy_from_slice(&raw);
        cookies.add_macs(&mut packet[layout.body.clone()], Instant::now())?;
        obfuscator.finish_fixed(MessageKind::Initiation, &mut packet, &layout)?;
        socket.send(&packet[..layout.total])?;
        sent += 1;
        index = index.wrapping_add(1).max(1);

        next += interval;
        let now = Instant::now();
        if next > now {
            std::thread::sleep(next - now);
        } else if now.saturating_duration_since(next) > Duration::from_millis(50) {
            next = now;
        }
    }

    println!("flood: sent {sent} initiations to {}", options.target);
    Ok(())
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut target = None;
    let mut public_key = None;
    let mut pps = 5000u64;
    let mut seconds = 10u64;
    let mut args = args;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--target" => target = Some(args.next().ok_or("--target needs a value")?),
            "--public-key" => public_key = Some(args.next().ok_or("--public-key needs a value")?),
            "--pps" => {
                pps = args
                    .next()
                    .ok_or("--pps needs a value")?
                    .parse()
                    .map_err(|_| "--pps must be a positive integer".to_owned())?;
            }
            "--seconds" => {
                seconds = args
                    .next()
                    .ok_or("--seconds needs a value")?
                    .parse()
                    .map_err(|_| "--seconds must be a positive integer".to_owned())?;
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if pps == 0 || seconds == 0 {
        return Err("--pps and --seconds must be positive".to_owned());
    }
    let target = target
        .ok_or("--target is required")?
        .parse()
        .map_err(|_| "--target must be an ip:port".to_owned())?;
    let public_key = parse_public_key(&public_key.ok_or("--public-key is required")?)?;
    Ok(Options {
        target,
        public_key,
        pps,
        seconds,
    })
}

fn parse_public_key(value: &str) -> Result<PublicKey, String> {
    let value = value.trim();
    if value.len() == 64 {
        return PublicKey::from_hex(value).map_err(|_| "invalid hex public key".to_owned());
    }
    let bytes = decode_base64(value)?;
    Ok(PublicKey::from_bytes(bytes))
}

fn decode_base64(value: &str) -> Result<[u8; 32], String> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let value = value.trim();
    if value.len() != 44 || !value.ends_with('=') {
        return Err("public key must be 44 base64 characters".to_owned());
    }
    let mut output = [0u8; 32];
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    let mut written = 0usize;
    for character in value.bytes().take(43) {
        let digit = ALPHABET
            .iter()
            .position(|candidate| *candidate == character)
            .ok_or("public key is not valid base64")? as u32;
        accumulator = (accumulator << 6) | digit;
        bits += 6;
        while bits >= 8 {
            bits -= 8;
            if written == output.len() {
                return Err("public key is too long".to_owned());
            }
            output[written] = (accumulator >> bits) as u8;
            written += 1;
            accumulator &= (1 << bits) - 1;
        }
    }
    if written != output.len() {
        return Err("public key has the wrong length".to_owned());
    }
    Ok(output)
}
