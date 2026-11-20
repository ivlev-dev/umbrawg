use std::time::Instant;

use umbrawg_crypto::aead::{Aead, Algorithm, TAG_LEN};
use umbrawg_crypto::Key;

const SIZES: [usize; 6] = [64, 256, 1024, 1420, 4096, 16384];

fn iterations(size: usize) -> u64 {
    match size {
        0..=256 => 2_000_000,
        257..=4096 => 300_000,
        _ => 60_000,
    }
}

fn bench(algorithm: Algorithm, size: usize) -> f64 {
    let key = Key::from_bytes([0x42; 32]);
    let aead = Aead::new_with(algorithm, &key);
    let mut buffer = vec![0u8; size + TAG_LEN];
    let iterations = iterations(size);
    for counter in 0..1000 {
        aead.seal_in_place(counter, &[], &mut buffer).unwrap();
        buffer[0] ^= 1;
    }
    let start = Instant::now();
    for counter in 0..iterations {
        aead.seal_in_place(counter, &[], &mut buffer).unwrap();
        buffer[0] ^= 1;
    }
    let elapsed = start.elapsed().as_secs_f64();
    (size as f64 * iterations as f64) / elapsed / 1_000_000.0
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn cpu_features() -> (bool, bool, bool, bool) {
    (
        std::is_x86_feature_detected!("aes"),
        std::is_x86_feature_detected!("pclmulqdq"),
        std::is_x86_feature_detected!("avx2"),
        std::is_x86_feature_detected!("vaes"),
    )
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn cpu_features() -> (bool, bool, bool, bool) {
    (false, false, false, false)
}

fn main() {
    let (aesni, pclmul, avx2, vaes) = cpu_features();
    println!("cpu: aes={aesni} pclmulqdq={pclmul} avx2={avx2} vaes={vaes}");
    println!(
        "{:<22} {:>7} {:>12} {:>12}",
        "algorithm", "bytes", "Mbit/s", "GByte/s"
    );
    for algorithm in [Algorithm::ChaCha20Poly1305, Algorithm::Aes256Gcm] {
        for size in SIZES {
            let mbps = bench(algorithm, size);
            println!(
                "{:<22} {:>7} {:>12.1} {:>12.3}",
                algorithm.as_str(),
                size,
                mbps,
                mbps / 8.0 / 1000.0
            );
        }
    }
}
