// SPDX-License-Identifier: AGPL-3.0-or-later
// Additional permission: an OpenSSL/AWS-LC linking exception under AGPLv3 section 7 applies to this file; see LICENSE-EXCEPTION.
//
// Standalone ML-KEM-768 timing repro — no Citadel envelope, no AEAD, no KDF.
//
// Purpose: isolate whether key-A-vs-key-B timing signal is provider, codegen,
// platform, or microarchitectural. Strips all Citadel wrapping so the timed
// closure is ONLY the ML-KEM decapsulate call through shared preallocated
// buffers.
//
// Bench targets (3 providers × 3 variants = 9 benches):
//   libcrux_same_key_control           — libcrux: same key, random class
//   libcrux_same_key_two_pool_control  — libcrux: same key, two ct pools
//   libcrux_key_a_vs_key_b             — libcrux: two keys, class = which key
//   rustcrypto_same_key_control           — release provider: same key, random class
//   rustcrypto_same_key_two_pool_control  — release provider: same key, two ct pools
//   rustcrypto_key_a_vs_key_b             — release provider: two keys, class = which key
//   awslc_same_key_control             — AWS-LC: same key, random class
//   awslc_same_key_two_pool_control    — AWS-LC: same key, two ct pools
//   awslc_key_a_vs_key_b               — AWS-LC: two keys, class = which key
//
// Run all:
//   cargo bench --bench mlkem_standalone -p citadel-envelope
//
// Run individual:
//   cargo bench --bench mlkem_standalone -p citadel-envelope -- --filter libcrux_key_a_vs_key_b
//
// Run with specific seed (3 independent seeds to confirm):
//   cargo bench --bench mlkem_standalone -p citadel-envelope -- --filter libcrux_key_a_vs_key_b

use dudect_bencher::{
    ctbench::{run_benches_console, BenchMetadata, BenchName, BenchOpts},
    BenchRng, Class, CtRunner,
};
use rand::Rng;
use std::hint::black_box;
use std::path::PathBuf;

use libcrux_ml_kem::mlkem768;

use ml_kem::{
    kem::{Decapsulate, Encapsulate, Kem, KeyExport},
    ml_kem_768::{
        Ciphertext as RustCryptoCiphertext, DecapsulationKey as RustCryptoDecapsulationKey,
        EncapsulationKey as RustCryptoEncapsulationKey,
    },
    MlKem768,
};
#[allow(deprecated)]
use ml_kem::{ml_kem_768::ExpandedDecapsulationKey, ExpandedKeyEncoding};

use aws_lc_rs::kem::{Ciphertext as AwsCiphertext, DecapsulationKey, ML_KEM_768};
use fips203::{
    ml_kem_768,
    traits::{Decaps as FipsDecaps, Encaps as FipsEncaps, KeyGen as FipsKeyGen},
};

const MLKEM_SK_BYTES: usize = 2400;
const MLKEM_CT_BYTES: usize = 1088;

// ---------------------------------------------------------------------------
// libcrux helpers — raw ML-KEM-768, no Citadel wrapping
// ---------------------------------------------------------------------------

fn libcrux_keygen() -> (mlkem768::MlKem768PublicKey, [u8; MLKEM_SK_BYTES]) {
    let mut seed = [0u8; 64];
    getrandom::getrandom(&mut seed).unwrap();
    let kp = mlkem768::generate_key_pair(seed);
    let (dk, ek) = kp.into_parts();
    let sk_bytes: [u8; MLKEM_SK_BYTES] = *dk.as_slice();
    (ek, sk_bytes)
}

fn libcrux_encapsulate(pk: &mlkem768::MlKem768PublicKey) -> ([u8; MLKEM_CT_BYTES], [u8; 32]) {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).unwrap();
    let (ct, ss) = mlkem768::encapsulate(pk, seed);
    let ct_bytes: [u8; MLKEM_CT_BYTES] = ct.as_ref().try_into().unwrap();
    let ss_bytes: [u8; 32] = ss.as_ref().try_into().unwrap();
    (ct_bytes, ss_bytes)
}

fn libcrux_decapsulate_from_buffers(
    sk_buf: &[u8; MLKEM_SK_BYTES],
    ct_buf: &[u8; MLKEM_CT_BYTES],
) -> [u8; 32] {
    let sk = mlkem768::MlKem768PrivateKey::from(*sk_buf);
    let ct = mlkem768::MlKem768Ciphertext::from(*ct_buf);
    let ss = mlkem768::decapsulate(&sk, &ct);
    let mut out = [0u8; 32];
    out.copy_from_slice(ss.as_ref());
    out
}

// ---------------------------------------------------------------------------
// RustCrypto release-provider helpers — raw ML-KEM-768, no Citadel wrapping
// ---------------------------------------------------------------------------

#[allow(deprecated)]
fn rustcrypto_keygen() -> ([u8; MLKEM_SK_BYTES], Vec<u8>) {
    let (sk, pk) = MlKem768::generate_keypair();
    let sk_bytes: [u8; MLKEM_SK_BYTES] = sk.to_expanded_bytes().into();
    (sk_bytes, pk.to_bytes().as_slice().to_vec())
}

fn rustcrypto_encapsulate(pk_bytes: &[u8]) -> ([u8; MLKEM_CT_BYTES], [u8; 32]) {
    let pk_array: [u8; 1184] = pk_bytes.try_into().unwrap();
    let pk = RustCryptoEncapsulationKey::new(&pk_array.into()).unwrap();
    let (ct, ss) = pk.encapsulate();
    let ct_bytes: [u8; MLKEM_CT_BYTES] = ct.into();
    let mut ss_bytes = [0u8; 32];
    ss_bytes.copy_from_slice(ss.as_ref());
    (ct_bytes, ss_bytes)
}

#[allow(deprecated)]
fn rustcrypto_decapsulate_from_buffers(
    sk_buf: &[u8; MLKEM_SK_BYTES],
    ct_buf: &[u8; MLKEM_CT_BYTES],
) -> [u8; 32] {
    let encoded: ExpandedDecapsulationKey = (*sk_buf).into();
    let sk = RustCryptoDecapsulationKey::from_expanded_bytes(&encoded).unwrap();
    let ct: RustCryptoCiphertext = (*ct_buf).into();
    let ss = sk.decapsulate(&ct);
    let mut out = [0u8; 32];
    out.copy_from_slice(ss.as_ref());
    out
}

// ---------------------------------------------------------------------------
// libcrux benches
// ---------------------------------------------------------------------------

fn libcrux_same_key_control(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (pk, sk_bytes) = libcrux_keygen();

    let mut samples = Vec::new();
    for _ in 0..8192 {
        let (ct_bytes, _) = libcrux_encapsulate(&pk);
        samples.push((sk_bytes, ct_bytes));
    }

    let mut shared_sk = [0u8; MLKEM_SK_BYTES];
    let mut shared_ct = [0u8; MLKEM_CT_BYTES];

    for _ in 0..100_000 {
        let sample = &samples[rng.gen_range(0..samples.len())];
        let class = if rng.gen::<bool>() {
            Class::Left
        } else {
            Class::Right
        };

        shared_sk.copy_from_slice(&sample.0);
        shared_ct.copy_from_slice(&sample.1);

        runner.run_one(class, || {
            let _ = black_box(libcrux_decapsulate_from_buffers(
                black_box(&shared_sk),
                black_box(&shared_ct),
            ));
        });
    }
}

fn libcrux_same_key_two_pool_control(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (pk, sk_bytes) = libcrux_keygen();

    let mut samples = Vec::new();
    for _ in 0..4096 {
        let (ct_a, _) = libcrux_encapsulate(&pk);
        samples.push((Class::Left, sk_bytes, ct_a));

        let (ct_b, _) = libcrux_encapsulate(&pk);
        samples.push((Class::Right, sk_bytes, ct_b));
    }

    let mut shared_sk = [0u8; MLKEM_SK_BYTES];
    let mut shared_ct = [0u8; MLKEM_CT_BYTES];

    for _ in 0..100_000 {
        let sample = &samples[rng.gen_range(0..samples.len())];

        shared_sk.copy_from_slice(&sample.1);
        shared_ct.copy_from_slice(&sample.2);

        runner.run_one(sample.0, || {
            let _ = black_box(libcrux_decapsulate_from_buffers(
                black_box(&shared_sk),
                black_box(&shared_ct),
            ));
        });
    }
}

fn libcrux_key_a_vs_key_b(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (pk_a, sk_a_bytes) = libcrux_keygen();
    let (pk_b, sk_b_bytes) = libcrux_keygen();

    let mut samples = Vec::new();
    for _ in 0..4096 {
        let (ct_a, _) = libcrux_encapsulate(&pk_a);
        samples.push((Class::Left, sk_a_bytes, ct_a));

        let (ct_b, _) = libcrux_encapsulate(&pk_b);
        samples.push((Class::Right, sk_b_bytes, ct_b));
    }

    let mut shared_sk = [0u8; MLKEM_SK_BYTES];
    let mut shared_ct = [0u8; MLKEM_CT_BYTES];

    for _ in 0..100_000 {
        let sample = &samples[rng.gen_range(0..samples.len())];

        shared_sk.copy_from_slice(&sample.1);
        shared_ct.copy_from_slice(&sample.2);

        runner.run_one(sample.0, || {
            let _ = black_box(libcrux_decapsulate_from_buffers(
                black_box(&shared_sk),
                black_box(&shared_ct),
            ));
        });
    }
}

// ---------------------------------------------------------------------------
// RustCrypto release-provider benches
// ---------------------------------------------------------------------------

fn rustcrypto_same_key_control(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (sk_bytes, pk_bytes) = rustcrypto_keygen();

    let mut samples = Vec::new();
    for _ in 0..8192 {
        let (ct_bytes, _) = rustcrypto_encapsulate(&pk_bytes);
        samples.push((sk_bytes, ct_bytes));
    }

    let mut shared_sk = [0u8; MLKEM_SK_BYTES];
    let mut shared_ct = [0u8; MLKEM_CT_BYTES];

    for _ in 0..100_000 {
        let sample = &samples[rng.gen_range(0..samples.len())];
        let class = if rng.gen::<bool>() {
            Class::Left
        } else {
            Class::Right
        };

        shared_sk.copy_from_slice(&sample.0);
        shared_ct.copy_from_slice(&sample.1);

        runner.run_one(class, || {
            let _ = black_box(rustcrypto_decapsulate_from_buffers(
                black_box(&shared_sk),
                black_box(&shared_ct),
            ));
        });
    }
}

fn rustcrypto_same_key_two_pool_control(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (sk_bytes, pk_bytes) = rustcrypto_keygen();

    let mut samples = Vec::new();
    for _ in 0..4096 {
        let (ct_a, _) = rustcrypto_encapsulate(&pk_bytes);
        samples.push((Class::Left, sk_bytes, ct_a));

        let (ct_b, _) = rustcrypto_encapsulate(&pk_bytes);
        samples.push((Class::Right, sk_bytes, ct_b));
    }

    let mut shared_sk = [0u8; MLKEM_SK_BYTES];
    let mut shared_ct = [0u8; MLKEM_CT_BYTES];

    for _ in 0..100_000 {
        let sample = &samples[rng.gen_range(0..samples.len())];

        shared_sk.copy_from_slice(&sample.1);
        shared_ct.copy_from_slice(&sample.2);

        runner.run_one(sample.0, || {
            let _ = black_box(rustcrypto_decapsulate_from_buffers(
                black_box(&shared_sk),
                black_box(&shared_ct),
            ));
        });
    }
}

fn rustcrypto_key_a_vs_key_b(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (sk_a_bytes, pk_a_bytes) = rustcrypto_keygen();
    let (sk_b_bytes, pk_b_bytes) = rustcrypto_keygen();

    let mut samples = Vec::new();
    for _ in 0..4096 {
        let (ct_a, _) = rustcrypto_encapsulate(&pk_a_bytes);
        samples.push((Class::Left, sk_a_bytes, ct_a));

        let (ct_b, _) = rustcrypto_encapsulate(&pk_b_bytes);
        samples.push((Class::Right, sk_b_bytes, ct_b));
    }

    let mut shared_sk = [0u8; MLKEM_SK_BYTES];
    let mut shared_ct = [0u8; MLKEM_CT_BYTES];

    for _ in 0..100_000 {
        let sample = &samples[rng.gen_range(0..samples.len())];

        shared_sk.copy_from_slice(&sample.1);
        shared_ct.copy_from_slice(&sample.2);

        runner.run_one(sample.0, || {
            let _ = black_box(rustcrypto_decapsulate_from_buffers(
                black_box(&shared_sk),
                black_box(&shared_ct),
            ));
        });
    }
}

// ---------------------------------------------------------------------------
// aws-lc-rs helpers — BoringSSL/AWS-LC backed ML-KEM-768
// ---------------------------------------------------------------------------

fn awslc_keygen() -> ([u8; MLKEM_SK_BYTES], Vec<u8>) {
    let dk = DecapsulationKey::generate(&ML_KEM_768).unwrap();
    let sk_bytes_owned = dk.key_bytes().unwrap();
    let sk_bytes: [u8; MLKEM_SK_BYTES] = sk_bytes_owned.as_ref().try_into().unwrap();
    let ek = dk.encapsulation_key().unwrap();
    let ek_bytes = ek.key_bytes().unwrap();
    (sk_bytes, ek_bytes.as_ref().to_vec())
}

fn awslc_encapsulate(ek_bytes: &[u8]) -> ([u8; MLKEM_CT_BYTES], [u8; 32]) {
    let ek = aws_lc_rs::kem::EncapsulationKey::new(&ML_KEM_768, ek_bytes).unwrap();
    let (ct, ss) = ek.encapsulate().unwrap();
    let ct_bytes: [u8; MLKEM_CT_BYTES] = ct.as_ref().try_into().unwrap();
    let mut ss_bytes = [0u8; 32];
    ss_bytes.copy_from_slice(ss.as_ref());
    (ct_bytes, ss_bytes)
}

fn awslc_decapsulate_from_buffers(
    sk_buf: &[u8; MLKEM_SK_BYTES],
    ct_buf: &[u8; MLKEM_CT_BYTES],
) -> [u8; 32] {
    let dk = DecapsulationKey::new(&ML_KEM_768, sk_buf).unwrap();
    let ct = AwsCiphertext::from(ct_buf.as_ref());
    let ss = dk.decapsulate(ct).unwrap();
    let mut out = [0u8; 32];
    out.copy_from_slice(ss.as_ref());
    out
}

// ---------------------------------------------------------------------------
// aws-lc-rs benches
// ---------------------------------------------------------------------------

fn awslc_same_key_control(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (sk_bytes, ek_bytes) = awslc_keygen();

    let mut samples = Vec::new();
    for _ in 0..8192 {
        let (ct_bytes, _) = awslc_encapsulate(&ek_bytes);
        samples.push((sk_bytes, ct_bytes));
    }

    let mut shared_sk = [0u8; MLKEM_SK_BYTES];
    let mut shared_ct = [0u8; MLKEM_CT_BYTES];

    for _ in 0..100_000 {
        let sample = &samples[rng.gen_range(0..samples.len())];
        let class = if rng.gen::<bool>() {
            Class::Left
        } else {
            Class::Right
        };

        shared_sk.copy_from_slice(&sample.0);
        shared_ct.copy_from_slice(&sample.1);

        runner.run_one(class, || {
            let _ = black_box(awslc_decapsulate_from_buffers(
                black_box(&shared_sk),
                black_box(&shared_ct),
            ));
        });
    }
}

fn awslc_same_key_two_pool_control(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (sk_bytes, ek_bytes) = awslc_keygen();

    let mut samples = Vec::new();
    for _ in 0..4096 {
        let (ct_a, _) = awslc_encapsulate(&ek_bytes);
        samples.push((Class::Left, sk_bytes, ct_a));

        let (ct_b, _) = awslc_encapsulate(&ek_bytes);
        samples.push((Class::Right, sk_bytes, ct_b));
    }

    let mut shared_sk = [0u8; MLKEM_SK_BYTES];
    let mut shared_ct = [0u8; MLKEM_CT_BYTES];

    for _ in 0..100_000 {
        let sample = &samples[rng.gen_range(0..samples.len())];

        shared_sk.copy_from_slice(&sample.1);
        shared_ct.copy_from_slice(&sample.2);

        runner.run_one(sample.0, || {
            let _ = black_box(awslc_decapsulate_from_buffers(
                black_box(&shared_sk),
                black_box(&shared_ct),
            ));
        });
    }
}

fn awslc_key_a_vs_key_b(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (sk_a_bytes, ek_a_bytes) = awslc_keygen();
    let (sk_b_bytes, ek_b_bytes) = awslc_keygen();

    let mut samples = Vec::new();
    for _ in 0..4096 {
        let (ct_a, _) = awslc_encapsulate(&ek_a_bytes);
        samples.push((Class::Left, sk_a_bytes, ct_a));

        let (ct_b, _) = awslc_encapsulate(&ek_b_bytes);
        samples.push((Class::Right, sk_b_bytes, ct_b));
    }

    let mut shared_sk = [0u8; MLKEM_SK_BYTES];
    let mut shared_ct = [0u8; MLKEM_CT_BYTES];

    for _ in 0..100_000 {
        let sample = &samples[rng.gen_range(0..samples.len())];

        shared_sk.copy_from_slice(&sample.1);
        shared_ct.copy_from_slice(&sample.2);

        runner.run_one(sample.0, || {
            let _ = black_box(awslc_decapsulate_from_buffers(
                black_box(&shared_sk),
                black_box(&shared_ct),
            ));
        });
    }
}

// ---------------------------------------------------------------------------
// fips203 screening benches — parsed keys, matching Citadel's actual key stage
// ---------------------------------------------------------------------------

fn fips203_same_key_control(runner: &mut CtRunner, rng: &mut BenchRng) {
    let mut key_rng = rand::thread_rng();
    let (pk, sk) = ml_kem_768::KG::try_keygen_with_rng(&mut key_rng).unwrap();
    let mut ciphertexts = Vec::with_capacity(8192);
    for _ in 0..8192 {
        let (_, ct) = pk.try_encaps_with_rng(&mut key_rng).unwrap();
        ciphertexts.push(ct);
    }

    for _ in 0..100_000 {
        let ct = &ciphertexts[rng.gen_range(0..ciphertexts.len())];
        let class = if rng.gen::<bool>() {
            Class::Left
        } else {
            Class::Right
        };
        runner.run_one(class, || {
            let _ = black_box(sk.try_decaps(black_box(ct)).unwrap());
        });
    }
}

fn fips203_key_a_vs_key_b(runner: &mut CtRunner, rng: &mut BenchRng) {
    let mut key_rng = rand::thread_rng();
    let (pk_a, sk_a) = ml_kem_768::KG::try_keygen_with_rng(&mut key_rng).unwrap();
    let (pk_b, sk_b) = ml_kem_768::KG::try_keygen_with_rng(&mut key_rng).unwrap();
    let mut samples = Vec::with_capacity(8192);
    for _ in 0..4096 {
        let (_, ct_a) = pk_a.try_encaps_with_rng(&mut key_rng).unwrap();
        samples.push((Class::Left, false, ct_a));
        let (_, ct_b) = pk_b.try_encaps_with_rng(&mut key_rng).unwrap();
        samples.push((Class::Right, true, ct_b));
    }

    for _ in 0..100_000 {
        let (class, use_b, ct) = &samples[rng.gen_range(0..samples.len())];
        let sk = if *use_b { &sk_b } else { &sk_a };
        runner.run_one(*class, || {
            let _ = black_box(sk.try_decaps(black_box(ct)).unwrap());
        });
    }
}

// ---------------------------------------------------------------------------
// main — custom CLI matching timing_sidechannel.rs
// ---------------------------------------------------------------------------

fn main() {
    let mut opts = BenchOpts::default();
    let mut args = std::env::args().skip(1).peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bench" => {}
            "--filter" => {
                opts.filter = args.next();
            }
            "--continuous" => {
                opts.continuous = true;
                opts.filter = args.next();
            }
            "--out" => {
                opts.file_out = args.next().map(PathBuf::from);
            }
            "-h" | "--help" => {
                println!(
                    "Usage: mlkem_standalone [--filter BENCH] [--continuous BENCH] [--out FILE]"
                );
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }

    let benches = vec![
        BenchMetadata {
            name: BenchName("libcrux_same_key_control"),
            seed: None,
            benchfn: libcrux_same_key_control,
        },
        BenchMetadata {
            name: BenchName("libcrux_same_key_two_pool_control"),
            seed: None,
            benchfn: libcrux_same_key_two_pool_control,
        },
        BenchMetadata {
            name: BenchName("libcrux_key_a_vs_key_b"),
            seed: None,
            benchfn: libcrux_key_a_vs_key_b,
        },
        BenchMetadata {
            name: BenchName("rustcrypto_same_key_control"),
            seed: None,
            benchfn: rustcrypto_same_key_control,
        },
        BenchMetadata {
            name: BenchName("rustcrypto_same_key_two_pool_control"),
            seed: None,
            benchfn: rustcrypto_same_key_two_pool_control,
        },
        BenchMetadata {
            name: BenchName("rustcrypto_key_a_vs_key_b"),
            seed: None,
            benchfn: rustcrypto_key_a_vs_key_b,
        },
        BenchMetadata {
            name: BenchName("awslc_same_key_control"),
            seed: None,
            benchfn: awslc_same_key_control,
        },
        BenchMetadata {
            name: BenchName("awslc_same_key_two_pool_control"),
            seed: None,
            benchfn: awslc_same_key_two_pool_control,
        },
        BenchMetadata {
            name: BenchName("awslc_key_a_vs_key_b"),
            seed: None,
            benchfn: awslc_key_a_vs_key_b,
        },
        BenchMetadata {
            name: BenchName("fips203_same_key_control"),
            seed: None,
            benchfn: fips203_same_key_control,
        },
        BenchMetadata {
            name: BenchName("fips203_key_a_vs_key_b"),
            seed: None,
            benchfn: fips203_key_a_vs_key_b,
        },
    ];

    run_benches_console(opts, benches).expect("standalone ML-KEM timing benchmark failed");
}
