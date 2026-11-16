use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand_core::{impls::fill_bytes_via_next, Error as RandError, RngCore};

use umbrawg_crypto::{aead, blake2s, Key, PrivateKey, KEY_LEN};
use umbrawg_proto::{obf::MessageKind, ObfParams, Obfuscator};
use umbrawg_transport::{GsoLayout, GsoSize, coalesce_into, split_into_segments};
use umbrawg_tun::VirtioNetHdr;

const SIZES: [usize; 5] = [64, 256, 1420, 8192, 65535];
const TAG_LEN: usize = aead::TAG_LEN;

struct FixedRng(u64);

impl RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111B9);
        z ^ (z >> 31)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        fill_bytes_via_next(self, dst);
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(dst);
        Ok(())
    }
}

fn fixed_key() -> Key {
    Key::from_bytes([0x42; KEY_LEN])
}

fn make_obf_params(enabled: bool) -> ObfParams {
    let mut params = ObfParams::default();
    if enabled {
        params.s1 = 16;
        params.s4 = 16;
        params.random_trailers = true;
        params.header_protection_key = Some(Key::from_bytes([0x22; KEY_LEN]));
    }
    params
}

fn bench_aead(c: &mut Criterion) {
    let key = fixed_key();
    let aad = b"aad";

    let mut group = c.benchmark_group("aead_seal_in_place");
    for &size in &SIZES {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let mut buf = vec![0u8; size + TAG_LEN];
            buf[..size].fill(0x5a);
            b.iter(|| {
                buf[..size].fill(0x5a);
                aead::seal_in_place(&key, 1, aad, &mut buf).unwrap();
                black_box(&buf);
            });
        });
    }
    group.finish();

    let mut group = c.benchmark_group("aead_open_in_place");
    for &size in &SIZES {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let mut sealed = vec![0u8; size + TAG_LEN];
            sealed[..size].fill(0x5a);
            aead::seal_in_place(&key, 1, aad, &mut sealed).unwrap();
            b.iter_with_setup(
                || {
                    
                    sealed.clone()
                },
                |mut buf| {
                    let out = aead::open_in_place(&key, 1, aad, &mut buf).unwrap();
                    black_box(out);
                },
            );
        });
    }
    group.finish();

    let mut group = c.benchmark_group("aead_seal_into");
    for &size in &SIZES {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let plaintext = vec![0x5a; size];
            let mut dst = vec![0u8; size + TAG_LEN];
            b.iter(|| {
                aead::seal_into(&key, 1, aad, &plaintext, &mut dst).unwrap();
                black_box(&dst);
            });
        });
    }
    group.finish();

    let mut group = c.benchmark_group("aead_open_into");
    for &size in &SIZES {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let mut sealed = vec![0u8; size + TAG_LEN];
            sealed[..size].fill(0x5a);
            aead::seal_in_place(&key, 1, aad, &mut sealed).unwrap();
            let mut dst = vec![0u8; size];
            b.iter(|| {
                aead::open_into(&key, 1, aad, &sealed, &mut dst).unwrap();
                black_box(&dst);
            });
        });
    }
    group.finish();
}

fn bench_blake2s(c: &mut Criterion) {
    let key = core::array::from_fn::<u8, 32, _>(|i| i as u8);
    for &size in &[64usize, 1420usize, 65535usize] {
        let data = vec![0x5a; size];

        let mut group = c.benchmark_group("blake2s_hash");
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let digest = blake2s::hash(data);
                black_box(digest);
            });
        });
        group.finish();

        let mut group = c.benchmark_group("blake2s_hash_into");
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            let mut out = [0u8; blake2s::HASH_LEN];
            b.iter(|| {
                blake2s::hash_into(data, &mut out);
                black_box(out);
            });
        });
        group.finish();
    }

    let data = vec![0x5a; 1420];
    {
        let mut group = c.benchmark_group("blake2s_keyed");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("keyed_16", |b| {
        b.iter(|| {
            let out = blake2s::keyed_16(&key, &data);
            black_box(out);
        });
    });
    group.bench_function("keyed_32", |b| {
        b.iter(|| {
            let out = blake2s::keyed_32(&key, &data);
            black_box(out);
        });
    });
    group.finish();
    }

    {
        let mut group = c.benchmark_group("blake2s_incremental");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("incremental", |b| {
        b.iter(|| {
            let mut hasher = blake2s::Blake2s::new();
            hasher.update(&data);
            let digest = hasher.finalize();
            black_box(digest);
        });
    });
    group.finish();
}
}

fn bench_x25519(c: &mut Criterion) {
    let alice = PrivateKey::from_bytes([7; KEY_LEN]);
    let bob = PrivateKey::from_bytes([9; KEY_LEN]);
    let bob_public = bob.public_key();

    let mut group = c.benchmark_group("x25519");
    group.bench_function("public_key", |b| {
        b.iter(|| {
            let public = alice.public_key();
            black_box(public);
        });
    });
    group.bench_function("diffie_hellman", |b| {
        b.iter(|| {
            let shared = alice.diffie_hellman(&bob_public);
            black_box(shared);
        });
    });
    let mut private_bytes = [0x11; KEY_LEN];
    private_bytes[0] &= 248;
    private_bytes[KEY_LEN - 1] = (private_bytes[KEY_LEN - 1] & 127) | 64;
    group.bench_function("from_bytes_clamped", |b| {
        b.iter(|| {
            let private = PrivateKey::from_bytes(private_bytes);
            black_box(private);
        });
    });
    group.finish();
}

fn bench_obf(c: &mut Criterion) {
    let kinds = [MessageKind::Initiation, MessageKind::Transport];
    for &enabled in &[false, true] {
        let params = make_obf_params(enabled);
        let obf = Obfuscator::new(&params);
        let label = if enabled { "obf" } else { "plain" };

        for &kind in &kinds {
            let mut group = c.benchmark_group(format!("obf_begin_fixed_{}", label));
            group.bench_function(format!("{:?}", kind), |b| {
                b.iter_with_setup(
                    || (vec![0u8; 512], FixedRng(1)),
                    |(mut dst, mut rng)| {
                        let result = obf.begin_fixed(kind, &mut rng, 500, &mut dst);
                        let _ = black_box(result);
                        black_box(dst);
                    },
                );
            });
            group.finish();
        }

        let mut group = c.benchmark_group(format!("obf_finish_fixed_{}", label));
        for &kind in &kinds {
            group.bench_function(format!("{:?}", kind), |b| {
                b.iter_with_setup(
                    || {
                        let mut dst = vec![0u8; 512];
                        let mut rng = FixedRng(1);
                        let (header, layout) = obf.begin_fixed(kind, &mut rng, 500, &mut dst).unwrap();
                        black_box(header);
                        (dst, layout)
                    },
                    |(mut dst, layout)| {
                        obf.finish_fixed(kind, &mut dst, &layout).unwrap();
                        black_box(dst);
                    },
                );
            });
        }
        group.finish();

        let mut group = c.benchmark_group(format!("obf_begin_transport_{}", label));
        group.bench_function("transport", |b| {
            b.iter_with_setup(
                || (vec![0u8; 128], FixedRng(2)),
                |(mut dst, mut rng)| {
                    let result = obf.begin_transport(&mut rng, &mut dst, 0x1122_3344, 7);
                    let _ = black_box(result);
                    black_box(dst);
                },
            );
        });
        group.finish();

        let mut group = c.benchmark_group(format!("obf_detect_{}", label));
        for &kind in &kinds {
            group.bench_function(format!("{:?}", kind), |b| {
                b.iter_with_setup(
                    || {
                        let mut dst = vec![0u8; 512];
                        let mut rng = FixedRng(3);
                        let (_header, layout) = obf.begin_fixed(kind, &mut rng, 500, &mut dst).unwrap();
                        obf.finish_fixed(kind, &mut dst, &layout).unwrap();
                        let mut packet = dst[..layout.total].to_vec();
                        if packet.len() < 32 {
                            packet.resize(32, 0);
                        }
                        packet
                    },
                    |dst| {
                        let detected = obf.detect(&dst);
                        black_box(detected);
                    },
                );
            });
        }
        group.finish();

        let mut group = c.benchmark_group(format!("obf_unprotect_{}", label));
        for &kind in &kinds {
            group.bench_function(format!("{:?}", kind), |b| {
                b.iter_with_setup(
                    || {
                        let mut dst = vec![0u8; 512];
                        let mut rng = FixedRng(4);
                        let (_header, layout) = obf.begin_fixed(kind, &mut rng, 500, &mut dst).unwrap();
                        obf.finish_fixed(kind, &mut dst, &layout).unwrap();
                        let mut packet = dst[..layout.total].to_vec();
                        if packet.len() < 32 {
                            packet.resize(32, 0);
                        }
                        packet
                    },
                    |mut dst| {
                        let detected = obf.detect(&dst).unwrap();
                        obf.unprotect_detected(&mut dst, detected).unwrap();
                        black_box(dst);
                    },
                );
            });
        }
        group.finish();
    }
}

fn bench_gso(c: &mut Criterion) {
    let gso_size = GsoSize::from_usize(1420).unwrap();
    let total = 1420 * 64;

    let mut group = c.benchmark_group("gso_layout");
    group.bench_function("for_payload", |b| {
        b.iter(|| {
            let layout = GsoLayout::for_payload(total, gso_size).unwrap();
            black_box(layout);
        });
    });
    group.finish();

    let payload = vec![0x5a; total];
    let parts: Vec<Vec<u8>> = (0..64).map(|_| vec![0x5a; 1420]).collect();
    let part_refs: Vec<&[u8]> = parts.iter().map(|p| &p[..]).collect();

    let mut group = c.benchmark_group("gso_split");
    group.throughput(Throughput::Bytes(total as u64));
    group.bench_function("split_into_segments", |b| {
        b.iter_with_setup(
            || {
                let out = vec![vec![0u8; 1420]; 64];
                (payload.clone(), out)
            },
            |(payload, mut out)| {
                let mut refs: Vec<&mut [u8]> = out.iter_mut().map(|b| &mut b[..]).collect();
                let n = split_into_segments(&payload, gso_size, &mut refs).unwrap();
                black_box(n);
            },
        );
    });
    group.finish();

    let mut out = vec![0u8; total];
    let mut group = c.benchmark_group("gso_coalesce");
    group.throughput(Throughput::Bytes(total as u64));
    group.bench_function("coalesce_into", |b| {
        b.iter(|| {
            let layout = coalesce_into(&part_refs, &mut out).unwrap();
            black_box(layout);
        });
    });
    group.finish();

    let mut group = c.benchmark_group("virtio_header");
    let header = VirtioNetHdr {
        flags: 0x01,
        gso_type: 0x05,
        hdr_len: 54,
        gso_size: 1420,
        csum_start: 34,
        csum_offset: 6,
        num_buffers: 0,
    };
    let mut bytes = [0u8; VirtioNetHdr::LEN];
    group.bench_function("encode", |b| {
        b.iter(|| {
            header.encode(&mut bytes).unwrap();
            black_box(bytes);
        });
    });
    group.bench_function("decode", |b| {
        b.iter(|| {
            let decoded = VirtioNetHdr::decode(&bytes).unwrap();
            black_box(decoded);
        });
    });
    group.finish();
}

fn bench_batch(c: &mut Criterion) {
    let key = fixed_key();
    let aad = b"aad";
    let packet_size = 1420usize;
    let packet_count = 64usize;
    let total = packet_size * packet_count;

    let mut group = c.benchmark_group("batch_64x1420");
    group.throughput(Throughput::Bytes(total as u64));
    group.bench_function("seal_packets", |b| {
        b.iter(|| {
            let mut packets = vec![vec![0x5a; packet_size + TAG_LEN]; packet_count];
            for (i, packet) in packets.iter_mut().enumerate() {
                aead::seal_in_place(&key, i as u64, aad, packet).unwrap();
            }
            black_box(&packets);
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_aead,
    bench_blake2s,
    bench_x25519,
    bench_obf,
    bench_gso,
    bench_batch
);
criterion_main!(benches);
