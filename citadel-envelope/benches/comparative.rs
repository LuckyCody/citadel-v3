// SPDX-License-Identifier: AGPL-3.0-or-later
//! Comparative benchmarks: Citadel Hybrid vs pure AES-256-GCM.
//!
//! Run with: `cargo bench --bench comparative --features bench`
//!
//! These benchmarks compare wall-clock performance across multiple payload
//! sizes. The goal is to show where Citadel's hybrid post-quantum overhead
//! lands relative to the symmetric encryption floor.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use citadel_envelope::{Aad, Citadel, Context, HybridX25519MlKem768Provider, KemProvider};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::rngs::OsRng;

/// Payload sizes to benchmark.
const PAYLOAD_SIZES: &[usize] = &[64, 1024, 65_536, 1_048_576];

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("keygen");

    group.bench_function("citadel_hybrid", |b| {
        b.iter(HybridX25519MlKem768Provider::keygen);
    });

    group.bench_function("aes_256_gcm_key", |b| {
        b.iter(|| Aes256Gcm::generate_key(OsRng));
    });

    group.finish();
}

fn bench_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt");

    let citadel = Citadel::new();
    let (citadel_pk, _citadel_sk) = citadel.generate_keypair();

    let aes_key = Aes256Gcm::generate_key(OsRng);
    let aes_cipher = Aes256Gcm::new(&aes_key);

    let aad = Aad::raw(b"bench-aad");
    let ctx = Context::raw(b"bench-ctx");
    let nonce = Nonce::from([0u8; 12]);

    for &size in PAYLOAD_SIZES {
        let plaintext = vec![0x42u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("citadel_hybrid", size),
            &plaintext,
            |b, pt| {
                b.iter(|| {
                    citadel.seal(&citadel_pk, pt, &aad, &ctx).unwrap();
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("aes256gcm_only", size),
            &plaintext,
            |b, pt| {
                b.iter(|| {
                    let _ct = aes_cipher.encrypt(&nonce, pt.as_slice()).unwrap();
                });
            },
        );
    }

    group.finish();
}

fn bench_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("decrypt");

    let citadel = Citadel::new();
    let (citadel_pk, citadel_sk) = citadel.generate_keypair();

    let aes_key = Aes256Gcm::generate_key(OsRng);
    let aes_cipher = Aes256Gcm::new(&aes_key);

    let aad = Aad::raw(b"bench-aad");
    let ctx = Context::raw(b"bench-ctx");
    let nonce = Nonce::from([0u8; 12]);

    for &size in PAYLOAD_SIZES {
        let plaintext = vec![0x42u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        let citadel_ct = citadel.seal(&citadel_pk, &plaintext, &aad, &ctx).unwrap();
        group.bench_with_input(
            BenchmarkId::new("citadel_hybrid", size),
            &citadel_ct,
            |b, ct| {
                b.iter(|| {
                    citadel.open(&citadel_sk, ct, &aad, &ctx).unwrap();
                });
            },
        );

        let aes_ct = aes_cipher.encrypt(&nonce, plaintext.as_slice()).unwrap();
        group.bench_with_input(
            BenchmarkId::new("aes256gcm_only", size),
            &aes_ct,
            |b, ct| {
                b.iter(|| {
                    let _pt = aes_cipher.decrypt(&nonce, ct.as_slice()).unwrap();
                });
            },
        );
    }

    group.finish();
}

fn bench_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("overhead_bytes");

    let citadel = Citadel::new();
    let (citadel_pk, _) = citadel.generate_keypair();
    let plaintext = vec![0u8; 64];
    let aad = Aad::raw(b"bench-aad");
    let ctx = Context::raw(b"bench-ctx");

    let citadel_ct = citadel.seal(&citadel_pk, &plaintext, &aad, &ctx).unwrap();
    let citadel_overhead = citadel_ct.len() - plaintext.len();

    let nonce = Nonce::from([0u8; 12]);
    let aes_key = Aes256Gcm::generate_key(OsRng);
    let aes_cipher = Aes256Gcm::new(&aes_key);
    let aes_ct = aes_cipher.encrypt(&nonce, plaintext.as_slice()).unwrap();
    let aes_overhead = 12 + aes_ct.len() - plaintext.len();

    println!("\n=== Ciphertext Overhead (bytes added to 64B plaintext) ===");
    println!(
        "  Citadel Hybrid:    {} bytes  (ct total: {})",
        citadel_overhead,
        citadel_ct.len()
    );
    println!(
        "  Pure AES-256-GCM:  {} bytes  (nonce: 12 + ct: {})",
        aes_overhead,
        aes_ct.len()
    );
    println!();

    group.bench_function("report_printed", |b| b.iter(|| {}));
    group.finish();
}

criterion_group!(
    benches,
    bench_keygen,
    bench_encrypt,
    bench_decrypt,
    bench_overhead
);
criterion_main!(benches);
