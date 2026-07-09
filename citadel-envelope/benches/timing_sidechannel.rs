// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Statistical timing side-channel analysis using dudect-bencher.
//
// Tests that Citadel's KEM-decapsulate + AEAD-open path does not branch on
// secrets. Gating benches compare inputs in the same public equivalence class:
// same length, same parse outcome, and same observable success/failure result.
//
// Public-format timing differences (for example valid ciphertext vs a
// truncated envelope) are documented as informational only; they do not leak a
// secret because the attacker already knows the public format class and the API
// explicitly returns the failure bit.
//
// Run:  cargo bench --bench timing_sidechannel -p citadel-envelope
//
// The bench runs until it can either confirm constant-time behavior or detect
// a timing leak. It prints the t-statistic periodically; |t| < 4.5 after 100K
// samples means no detectable leak.

use dudect_bencher::{
    ctbench::{run_benches_console, BenchMetadata, BenchName, BenchOpts},
    BenchRng, Class, CtRunner,
};
use rand::Rng;
use std::hint::black_box;
use std::path::PathBuf;

use citadel_envelope::{timing_diagnostics, wire, Aad, Citadel, Context, SecretKey};
use pqcrypto_traits::kem::{
    Ciphertext as PqCiphertext, SecretKey as PqSecretKey, SharedSecret as PqSharedSecret,
};

fn dummy_touch(key_bytes: &[u8], ciphertext: &[u8]) -> u64 {
    let mut acc = 0u64;
    for b in key_bytes {
        acc = acc.rotate_left(5) ^ (*b as u64);
    }
    for b in ciphertext {
        acc = acc.rotate_left(7).wrapping_add(*b as u64);
    }
    black_box(acc)
}

fn bench_tag_first_byte_vs_last_byte_failure(runner: &mut CtRunner, rng: &mut BenchRng) {
    let cit = Citadel::new();
    let (pk, sk) = cit.generate_keypair();
    let aad = Aad::raw(b"dudect-aad");
    let ctx = Context::raw(b"dudect-ctx");

    let plaintext = vec![0x42u8; 256];
    let ct = cit.seal(&pk, &plaintext, &aad, &ctx).unwrap();

    let mut tag_first = ct.clone();
    let mut tag_last = ct.clone();
    let len = ct.len();
    // AES-GCM tag is the final 16 bytes. Both classes are same-length,
    // parse-valid ciphertexts that fail authentication.
    tag_first[len - 16] ^= 0x01;
    tag_last[len - 1] ^= 0x01;

    let mut inputs = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..100_000 {
        if rng.gen::<bool>() {
            inputs.push(tag_first.clone());
            classes.push(Class::Left);
        } else {
            inputs.push(tag_last.clone());
            classes.push(Class::Right);
        }
    }

    for (class, input) in classes.into_iter().zip(inputs) {
        runner.run_one(class, || {
            let _ = black_box(cit.open(&sk, black_box(&input), &aad, &ctx));
        });
    }
}

fn bench_wrong_aad_vs_wrong_tag_failure(runner: &mut CtRunner, rng: &mut BenchRng) {
    let cit = Citadel::new();
    let (pk, sk) = cit.generate_keypair();
    let aad_good = Aad::raw(b"dudect-aad-good");
    let aad_bad = Aad::raw(b"dudect-aad-BAD!");
    let ctx = Context::raw(b"dudect-ctx");

    let plaintext = vec![0x42u8; 256];
    let ct = cit.seal(&pk, &plaintext, &aad_good, &ctx).unwrap();
    let mut ct_bad_tag = ct.clone();
    let last = ct_bad_tag.len() - 1;
    ct_bad_tag[last] ^= 0x01;

    let mut classes = Vec::new();
    let mut use_wrong_aad = Vec::new();

    for _ in 0..100_000 {
        if rng.gen::<bool>() {
            use_wrong_aad.push(true);
            classes.push(Class::Left);
        } else {
            use_wrong_aad.push(false);
            classes.push(Class::Right);
        }
    }

    for (class, wrong_aad) in classes.into_iter().zip(use_wrong_aad) {
        let (input, aad) = if wrong_aad {
            (&ct, &aad_bad)
        } else {
            (&ct_bad_tag, &aad_good)
        };
        runner.run_one(class, || {
            let _ = black_box(cit.open(&sk, black_box(input), aad, &ctx));
        });
    }
}

fn bench_kem_corruption_a_vs_b_failure(runner: &mut CtRunner, rng: &mut BenchRng) {
    let cit = Citadel::new();
    let (pk, sk) = cit.generate_keypair();
    let aad = Aad::raw(b"dudect-aad");
    let ctx = Context::raw(b"dudect-ctx");

    let plaintext = vec![0x42u8; 256];
    let ct = cit.seal(&pk, &plaintext, &aad, &ctx).unwrap();
    let mut kem_a = ct.clone();
    let mut kem_b = ct.clone();
    // Header is 6 bytes; the KEM ciphertext follows. Both classes preserve the
    // public wire shape and should proceed through the same implicit-rejection
    // KEM/KDF/AEAD failure pipeline.
    kem_a[6] ^= 0x01;
    kem_b[7] ^= 0x01;

    let mut inputs = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..100_000 {
        if rng.gen::<bool>() {
            inputs.push(kem_a.clone());
            classes.push(Class::Left);
        } else {
            inputs.push(kem_b.clone());
            classes.push(Class::Right);
        }
    }

    for (class, input) in classes.into_iter().zip(inputs) {
        runner.run_one(class, || {
            let _ = black_box(cit.open(&sk, black_box(&input), &aad, &ctx));
        });
    }
}

fn bench_key_material_fixed_vs_random_success(runner: &mut CtRunner, rng: &mut BenchRng) {
    let cit = Citadel::new();
    let (pk_fixed, sk_fixed) = cit.generate_keypair();
    let aad = Aad::raw(b"dudect-aad");
    let ctx = Context::raw(b"dudect-ctx");

    let plaintext = vec![0x42u8; 256];
    let fixed_sk_bytes = sk_fixed.to_bytes();

    let mut fixed_pairs = Vec::new();
    let mut random_pairs = Vec::new();
    for _ in 0..4096 {
        let fixed_sk = SecretKey::from_bytes(&fixed_sk_bytes).unwrap();
        let fixed_ct = cit.seal(&pk_fixed, &plaintext, &aad, &ctx).unwrap();
        fixed_pairs.push((fixed_sk, fixed_ct));

        let (pk, sk) = cit.generate_keypair();
        let ct = cit.seal(&pk, &plaintext, &aad, &ctx).unwrap();
        random_pairs.push((sk, ct));
    }

    let mut classes = Vec::new();
    let mut use_fixed = Vec::new();

    for _ in 0..100_000 {
        if rng.gen::<bool>() {
            use_fixed.push(true);
            classes.push(Class::Left);
        } else {
            use_fixed.push(false);
            classes.push(Class::Right);
        }
    }

    let mut fixed_idx = 0usize;
    let mut random_idx = 0usize;
    for (class, fixed) in classes.into_iter().zip(use_fixed) {
        if fixed {
            let pair = &fixed_pairs[fixed_idx % fixed_pairs.len()];
            fixed_idx += 1;
            runner.run_one(class, || {
                let _ = black_box(cit.open(&pair.0, black_box(&pair.1), &aad, &ctx));
            });
        } else {
            let pair = &random_pairs[random_idx % random_pairs.len()];
            random_idx += 1;
            runner.run_one(class, || {
                let _ = black_box(cit.open(&pair.0, black_box(&pair.1), &aad, &ctx));
            });
        }
    }
}

fn bench_null_fixed_vs_random_harness_control(runner: &mut CtRunner, rng: &mut BenchRng) {
    let cit = Citadel::new();
    let (pk_fixed, sk_fixed) = cit.generate_keypair();
    let aad = Aad::raw(b"dudect-aad");
    let ctx = Context::raw(b"dudect-ctx");

    let plaintext = vec![0x42u8; 256];
    let fixed_sk_bytes = sk_fixed.to_bytes().to_vec();

    let mut fixed_pairs = Vec::new();
    let mut random_pairs = Vec::new();
    for _ in 0..4096 {
        let fixed_ct = cit.seal(&pk_fixed, &plaintext, &aad, &ctx).unwrap();
        fixed_pairs.push((fixed_sk_bytes.clone(), fixed_ct));

        let (pk, sk) = cit.generate_keypair();
        let ct = cit.seal(&pk, &plaintext, &aad, &ctx).unwrap();
        random_pairs.push((sk.to_bytes().to_vec(), ct));
    }

    let mut classes = Vec::new();
    let mut use_fixed = Vec::new();

    for _ in 0..100_000 {
        if rng.gen::<bool>() {
            use_fixed.push(true);
            classes.push(Class::Left);
        } else {
            use_fixed.push(false);
            classes.push(Class::Right);
        }
    }

    let mut fixed_idx = 0usize;
    let mut random_idx = 0usize;
    for (class, fixed) in classes.into_iter().zip(use_fixed) {
        if fixed {
            let pair = &fixed_pairs[fixed_idx % fixed_pairs.len()];
            fixed_idx += 1;
            runner.run_one(class, || {
                let _ = dummy_touch(black_box(&pair.0), black_box(&pair.1));
            });
        } else {
            let pair = &random_pairs[random_idx % random_pairs.len()];
            random_idx += 1;
            runner.run_one(class, || {
                let _ = dummy_touch(black_box(&pair.0), black_box(&pair.1));
            });
        }
    }
}

#[allow(clippy::type_complexity)]
fn build_stage_pairs(
    count: usize,
    plaintext: &[u8],
    aad: &Aad,
    ctx: &Context,
) -> (
    Vec<(SecretKey, Vec<u8>)>,
    Vec<(SecretKey, Vec<u8>)>,
    Vec<(Vec<u8>, [u8; 32], Vec<u8>)>,
    Vec<(Vec<u8>, [u8; 32], Vec<u8>)>,
    Vec<([u8; 32], [u8; 12], Vec<u8>)>,
    Vec<([u8; 32], [u8; 12], Vec<u8>)>,
) {
    let cit = Citadel::new();
    let (pk_fixed, sk_fixed) = cit.generate_keypair();
    let fixed_sk_bytes = sk_fixed.to_bytes();

    let mut fixed_kem_pairs = Vec::new();
    let mut random_kem_pairs = Vec::new();
    let mut fixed_kdf_pairs = Vec::new();
    let mut random_kdf_pairs = Vec::new();
    let mut fixed_aead_pairs = Vec::new();
    let mut random_aead_pairs = Vec::new();

    for i in 0..count {
        let fixed_sk = SecretKey::from_bytes(&fixed_sk_bytes).unwrap();
        let fixed_ct = cit.seal(&pk_fixed, plaintext, aad, ctx).unwrap();
        let fixed_parts = wire::decode_wire(&fixed_ct).unwrap();
        let fixed_kem_ct = fixed_parts.kem_ciphertext.to_vec();
        let fixed_ss = timing_diagnostics::hybrid_decapsulate(&fixed_sk, &fixed_kem_ct).unwrap();
        let fixed_hash = timing_diagnostics::ct_hash(&fixed_kem_ct);
        let fixed_aes_key =
            timing_diagnostics::derive_key(&fixed_ss, &fixed_hash, ctx.as_bytes()).unwrap();
        fixed_kem_pairs.push((fixed_sk, fixed_kem_ct));
        fixed_kdf_pairs.push((fixed_ss.to_vec(), fixed_hash, ctx.as_bytes().to_vec()));

        let fixed_nonce = [i as u8; 12];
        let fixed_aead_ct =
            timing_diagnostics::aead_seal(&fixed_aes_key, &fixed_nonce, plaintext, aad.as_bytes())
                .unwrap();
        fixed_aead_pairs.push((fixed_aes_key, fixed_nonce, fixed_aead_ct));

        let (pk, sk) = cit.generate_keypair();
        let random_ct = cit.seal(&pk, plaintext, aad, ctx).unwrap();
        let random_parts = wire::decode_wire(&random_ct).unwrap();
        let random_kem_ct = random_parts.kem_ciphertext.to_vec();
        let random_ss = timing_diagnostics::hybrid_decapsulate(&sk, &random_kem_ct).unwrap();
        let random_hash = timing_diagnostics::ct_hash(&random_kem_ct);
        let random_aes_key =
            timing_diagnostics::derive_key(&random_ss, &random_hash, ctx.as_bytes()).unwrap();
        random_kem_pairs.push((sk, random_kem_ct));
        random_kdf_pairs.push((random_ss.to_vec(), random_hash, ctx.as_bytes().to_vec()));

        let random_nonce = [i.wrapping_add(17) as u8; 12];
        let random_aead_ct = timing_diagnostics::aead_seal(
            &random_aes_key,
            &random_nonce,
            plaintext,
            aad.as_bytes(),
        )
        .unwrap();
        random_aead_pairs.push((random_aes_key, random_nonce, random_aead_ct));
    }

    (
        fixed_kem_pairs,
        random_kem_pairs,
        fixed_kdf_pairs,
        random_kdf_pairs,
        fixed_aead_pairs,
        random_aead_pairs,
    )
}

fn bench_stage_hybrid_kem_fixed_vs_random_success(runner: &mut CtRunner, rng: &mut BenchRng) {
    let aad = Aad::raw(b"dudect-aad");
    let ctx = Context::raw(b"dudect-ctx");
    let plaintext = vec![0x42u8; 256];
    let (fixed_pairs, random_pairs, _, _, _, _) = build_stage_pairs(2048, &plaintext, &aad, &ctx);

    let mut fixed_idx = 0usize;
    let mut random_idx = 0usize;
    for _ in 0..100_000 {
        if rng.gen::<bool>() {
            let pair = &fixed_pairs[fixed_idx % fixed_pairs.len()];
            fixed_idx += 1;
            runner.run_one(Class::Left, || {
                let _ = black_box(timing_diagnostics::hybrid_decapsulate(
                    &pair.0,
                    black_box(&pair.1),
                ));
            });
        } else {
            let pair = &random_pairs[random_idx % random_pairs.len()];
            random_idx += 1;
            runner.run_one(Class::Right, || {
                let _ = black_box(timing_diagnostics::hybrid_decapsulate(
                    &pair.0,
                    black_box(&pair.1),
                ));
            });
        }
    }
}

fn bench_stage_x25519_fixed_vs_random_success(runner: &mut CtRunner, rng: &mut BenchRng) {
    let aad = Aad::raw(b"dudect-aad");
    let ctx = Context::raw(b"dudect-ctx");
    let plaintext = vec![0x42u8; 256];
    let (fixed_pairs, random_pairs, _, _, _, _) = build_stage_pairs(2048, &plaintext, &aad, &ctx);

    let mut fixed_idx = 0usize;
    let mut random_idx = 0usize;
    for _ in 0..100_000 {
        if rng.gen::<bool>() {
            let pair = &fixed_pairs[fixed_idx % fixed_pairs.len()];
            fixed_idx += 1;
            runner.run_one(Class::Left, || {
                let _ = black_box(timing_diagnostics::x25519_decapsulate_only(
                    &pair.0,
                    black_box(&pair.1),
                ));
            });
        } else {
            let pair = &random_pairs[random_idx % random_pairs.len()];
            random_idx += 1;
            runner.run_one(Class::Right, || {
                let _ = black_box(timing_diagnostics::x25519_decapsulate_only(
                    &pair.0,
                    black_box(&pair.1),
                ));
            });
        }
    }
}

fn bench_stage_mlkem_fixed_vs_random_success(runner: &mut CtRunner, rng: &mut BenchRng) {
    let aad = Aad::raw(b"dudect-aad");
    let ctx = Context::raw(b"dudect-ctx");
    let plaintext = vec![0x42u8; 256];
    let (fixed_pairs, random_pairs, _, _, _, _) = build_stage_pairs(2048, &plaintext, &aad, &ctx);

    let mut fixed_idx = 0usize;
    let mut random_idx = 0usize;
    for _ in 0..100_000 {
        if rng.gen::<bool>() {
            let pair = &fixed_pairs[fixed_idx % fixed_pairs.len()];
            fixed_idx += 1;
            runner.run_one(Class::Left, || {
                let _ = black_box(timing_diagnostics::mlkem_decapsulate_only(
                    &pair.0,
                    black_box(&pair.1),
                ));
            });
        } else {
            let pair = &random_pairs[random_idx % random_pairs.len()];
            random_idx += 1;
            runner.run_one(Class::Right, || {
                let _ = black_box(timing_diagnostics::mlkem_decapsulate_only(
                    &pair.0,
                    black_box(&pair.1),
                ));
            });
        }
    }
}

fn bench_stage_mlkem_key_a_vs_key_b_success(runner: &mut CtRunner, rng: &mut BenchRng) {
    let cit = Citadel::new();
    let (pk_a, sk_a) = cit.generate_keypair();
    let (pk_b, sk_b) = cit.generate_keypair();
    let sk_a_bytes = sk_a.to_bytes();
    let sk_b_bytes = sk_b.to_bytes();
    let aad = Aad::raw(b"dudect-aad");
    let ctx = Context::raw(b"dudect-ctx");
    let plaintext = vec![0x42u8; 256];

    let mut samples = Vec::new();
    for _ in 0..4096 {
        let sk = SecretKey::from_bytes(&sk_a_bytes).unwrap();
        let ct = cit.seal(&pk_a, &plaintext, &aad, &ctx).unwrap();
        let parts = wire::decode_wire(&ct).unwrap();
        samples.push((Class::Left, sk, parts.kem_ciphertext.to_vec()));

        let sk = SecretKey::from_bytes(&sk_b_bytes).unwrap();
        let ct = cit.seal(&pk_b, &plaintext, &aad, &ctx).unwrap();
        let parts = wire::decode_wire(&ct).unwrap();
        samples.push((Class::Right, sk, parts.kem_ciphertext.to_vec()));
    }

    for _ in 0..100_000 {
        let sample = &samples[rng.gen_range(0..samples.len())];
        runner.run_one(sample.0, || {
            let _ = black_box(timing_diagnostics::mlkem_decapsulate_only(
                &sample.1,
                black_box(&sample.2),
            ));
        });
    }
}

fn bench_stage_mlkem_same_key_pool_a_vs_pool_b_success(runner: &mut CtRunner, rng: &mut BenchRng) {
    let cit = Citadel::new();
    let (pk, sk_original) = cit.generate_keypair();
    let sk_bytes = sk_original.to_bytes();
    let aad = Aad::raw(b"dudect-aad");
    let ctx = Context::raw(b"dudect-ctx");
    let plaintext = vec![0x42u8; 256];

    let mut samples = Vec::new();
    for _ in 0..4096 {
        let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
        let ct = cit.seal(&pk, &plaintext, &aad, &ctx).unwrap();
        let parts = wire::decode_wire(&ct).unwrap();
        samples.push((sk, parts.kem_ciphertext.to_vec()));

        let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
        let ct = cit.seal(&pk, &plaintext, &aad, &ctx).unwrap();
        let parts = wire::decode_wire(&ct).unwrap();
        samples.push((sk, parts.kem_ciphertext.to_vec()));
    }

    for _ in 0..100_000 {
        let sample = &samples[rng.gen_range(0..samples.len())];
        let class = if rng.gen::<bool>() {
            Class::Left
        } else {
            Class::Right
        };
        runner.run_one(class, || {
            let _ = black_box(timing_diagnostics::mlkem_decapsulate_only(
                &sample.0,
                black_box(&sample.1),
            ));
        });
    }
}

fn bench_stage_mlkem_same_key_shared_buffer_control(runner: &mut CtRunner, rng: &mut BenchRng) {
    let cit = Citadel::new();
    let (pk, sk_original) = cit.generate_keypair();
    let sk_bytes = sk_original.to_bytes();
    let aad = Aad::raw(b"dudect-aad");
    let ctx = Context::raw(b"dudect-ctx");
    let plaintext = vec![0x42u8; 256];

    let mut samples = Vec::new();
    for _ in 0..8192 {
        let ct = cit.seal(&pk, &plaintext, &aad, &ctx).unwrap();
        let parts = wire::decode_wire(&ct).unwrap();
        samples.push((sk_bytes, *parts.kem_ciphertext));
    }

    let mut shared_key = [0u8; wire::KEM_SECRET_KEY_BYTES];
    let mut shared_ct = [0u8; wire::KEM_CIPHERTEXT_BYTES];

    for _ in 0..100_000 {
        let sample = &samples[rng.gen_range(0..samples.len())];
        let class = if rng.gen::<bool>() {
            Class::Left
        } else {
            Class::Right
        };

        shared_key.copy_from_slice(&sample.0);
        shared_ct.copy_from_slice(&sample.1);

        runner.run_one(class, || {
            let _ = black_box(timing_diagnostics::mlkem_decapsulate_from_key_bytes(
                black_box(&shared_key),
                black_box(&shared_ct),
            ));
        });
    }
}

fn bench_stage_mlkem_same_key_pool_a_vs_pool_b_shared_buffer_success(
    runner: &mut CtRunner,
    rng: &mut BenchRng,
) {
    let cit = Citadel::new();
    let (pk, sk_original) = cit.generate_keypair();
    let sk_bytes = sk_original.to_bytes();
    let aad = Aad::raw(b"dudect-aad");
    let ctx = Context::raw(b"dudect-ctx");
    let plaintext = vec![0x42u8; 256];

    let mut samples = Vec::new();
    for _ in 0..4096 {
        let ct = cit.seal(&pk, &plaintext, &aad, &ctx).unwrap();
        let parts = wire::decode_wire(&ct).unwrap();
        samples.push((Class::Left, sk_bytes, *parts.kem_ciphertext));

        let ct = cit.seal(&pk, &plaintext, &aad, &ctx).unwrap();
        let parts = wire::decode_wire(&ct).unwrap();
        samples.push((Class::Right, sk_bytes, *parts.kem_ciphertext));
    }

    let mut shared_key = [0u8; wire::KEM_SECRET_KEY_BYTES];
    let mut shared_ct = [0u8; wire::KEM_CIPHERTEXT_BYTES];

    for _ in 0..100_000 {
        let sample = &samples[rng.gen_range(0..samples.len())];

        shared_key.copy_from_slice(&sample.1);
        shared_ct.copy_from_slice(&sample.2);

        runner.run_one(sample.0, || {
            let _ = black_box(timing_diagnostics::mlkem_decapsulate_from_key_bytes(
                black_box(&shared_key),
                black_box(&shared_ct),
            ));
        });
    }
}

fn bench_stage_mlkem_key_a_vs_key_b_shared_buffer_success(
    runner: &mut CtRunner,
    rng: &mut BenchRng,
) {
    let cit = Citadel::new();
    let (pk_a, sk_a) = cit.generate_keypair();
    let (pk_b, sk_b) = cit.generate_keypair();
    let sk_a_bytes = sk_a.to_bytes();
    let sk_b_bytes = sk_b.to_bytes();
    let aad = Aad::raw(b"dudect-aad");
    let ctx = Context::raw(b"dudect-ctx");
    let plaintext = vec![0x42u8; 256];

    let mut samples = Vec::new();
    for _ in 0..4096 {
        let ct = cit.seal(&pk_a, &plaintext, &aad, &ctx).unwrap();
        let parts = wire::decode_wire(&ct).unwrap();
        samples.push((Class::Left, sk_a_bytes, *parts.kem_ciphertext));

        let ct = cit.seal(&pk_b, &plaintext, &aad, &ctx).unwrap();
        let parts = wire::decode_wire(&ct).unwrap();
        samples.push((Class::Right, sk_b_bytes, *parts.kem_ciphertext));
    }

    let mut shared_key = [0u8; wire::KEM_SECRET_KEY_BYTES];
    let mut shared_ct = [0u8; wire::KEM_CIPHERTEXT_BYTES];

    for _ in 0..100_000 {
        let sample = &samples[rng.gen_range(0..samples.len())];

        shared_key.copy_from_slice(&sample.1);
        shared_ct.copy_from_slice(&sample.2);

        runner.run_one(sample.0, || {
            let _ = black_box(timing_diagnostics::mlkem_decapsulate_from_key_bytes(
                black_box(&shared_key),
                black_box(&shared_ct),
            ));
        });
    }
}

fn pqclean_mlkem768_decapsulate_from_buffers(
    sk_bytes: &[u8; wire::MLKEM_SECRET_KEY_BYTES],
    ct_bytes: &[u8; wire::MLKEM_CIPHERTEXT_BYTES],
) -> [u8; 32] {
    let sk = pqcrypto_mlkem::mlkem768::SecretKey::from_bytes(sk_bytes).unwrap();
    let ct = pqcrypto_mlkem::mlkem768::Ciphertext::from_bytes(ct_bytes).unwrap();
    let ss = pqcrypto_mlkem::mlkem768::decapsulate(&ct, &sk);
    let mut out = [0u8; 32];
    out.copy_from_slice(ss.as_bytes());
    out
}

fn bench_pqclean_mlkem_same_key_shared_buffer_control(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (pk, sk) = pqcrypto_mlkem::mlkem768::keypair();
    let sk_bytes: [u8; wire::MLKEM_SECRET_KEY_BYTES] = sk.as_bytes().try_into().unwrap();

    let mut samples = Vec::new();
    for _ in 0..8192 {
        let (_, ct) = pqcrypto_mlkem::mlkem768::encapsulate(&pk);
        let ct_bytes: [u8; wire::MLKEM_CIPHERTEXT_BYTES] = ct.as_bytes().try_into().unwrap();
        samples.push((sk_bytes, ct_bytes));
    }

    let mut shared_key = [0u8; wire::MLKEM_SECRET_KEY_BYTES];
    let mut shared_ct = [0u8; wire::MLKEM_CIPHERTEXT_BYTES];

    for _ in 0..100_000 {
        let sample = &samples[rng.gen_range(0..samples.len())];
        let class = if rng.gen::<bool>() {
            Class::Left
        } else {
            Class::Right
        };

        shared_key.copy_from_slice(&sample.0);
        shared_ct.copy_from_slice(&sample.1);

        runner.run_one(class, || {
            let _ = black_box(pqclean_mlkem768_decapsulate_from_buffers(
                black_box(&shared_key),
                black_box(&shared_ct),
            ));
        });
    }
}

fn bench_pqclean_mlkem_same_key_pool_a_vs_pool_b_shared_buffer_success(
    runner: &mut CtRunner,
    rng: &mut BenchRng,
) {
    let (pk, sk) = pqcrypto_mlkem::mlkem768::keypair();
    let sk_bytes: [u8; wire::MLKEM_SECRET_KEY_BYTES] = sk.as_bytes().try_into().unwrap();

    let mut samples = Vec::new();
    for _ in 0..4096 {
        let (_, ct_a) = pqcrypto_mlkem::mlkem768::encapsulate(&pk);
        let ct_a_bytes: [u8; wire::MLKEM_CIPHERTEXT_BYTES] = ct_a.as_bytes().try_into().unwrap();
        samples.push((Class::Left, sk_bytes, ct_a_bytes));

        let (_, ct_b) = pqcrypto_mlkem::mlkem768::encapsulate(&pk);
        let ct_b_bytes: [u8; wire::MLKEM_CIPHERTEXT_BYTES] = ct_b.as_bytes().try_into().unwrap();
        samples.push((Class::Right, sk_bytes, ct_b_bytes));
    }

    let mut shared_key = [0u8; wire::MLKEM_SECRET_KEY_BYTES];
    let mut shared_ct = [0u8; wire::MLKEM_CIPHERTEXT_BYTES];

    for _ in 0..100_000 {
        let sample = &samples[rng.gen_range(0..samples.len())];

        shared_key.copy_from_slice(&sample.1);
        shared_ct.copy_from_slice(&sample.2);

        runner.run_one(sample.0, || {
            let _ = black_box(pqclean_mlkem768_decapsulate_from_buffers(
                black_box(&shared_key),
                black_box(&shared_ct),
            ));
        });
    }
}

fn bench_pqclean_mlkem_key_a_vs_key_b_shared_buffer_success(
    runner: &mut CtRunner,
    rng: &mut BenchRng,
) {
    let (pk_a, sk_a) = pqcrypto_mlkem::mlkem768::keypair();
    let (pk_b, sk_b) = pqcrypto_mlkem::mlkem768::keypair();
    let sk_a_bytes: [u8; wire::MLKEM_SECRET_KEY_BYTES] = sk_a.as_bytes().try_into().unwrap();
    let sk_b_bytes: [u8; wire::MLKEM_SECRET_KEY_BYTES] = sk_b.as_bytes().try_into().unwrap();

    let mut samples = Vec::new();
    for _ in 0..4096 {
        let (_, ct_a) = pqcrypto_mlkem::mlkem768::encapsulate(&pk_a);
        let ct_a_bytes: [u8; wire::MLKEM_CIPHERTEXT_BYTES] = ct_a.as_bytes().try_into().unwrap();
        samples.push((Class::Left, sk_a_bytes, ct_a_bytes));

        let (_, ct_b) = pqcrypto_mlkem::mlkem768::encapsulate(&pk_b);
        let ct_b_bytes: [u8; wire::MLKEM_CIPHERTEXT_BYTES] = ct_b.as_bytes().try_into().unwrap();
        samples.push((Class::Right, sk_b_bytes, ct_b_bytes));
    }

    let mut shared_key = [0u8; wire::MLKEM_SECRET_KEY_BYTES];
    let mut shared_ct = [0u8; wire::MLKEM_CIPHERTEXT_BYTES];

    for _ in 0..100_000 {
        let sample = &samples[rng.gen_range(0..samples.len())];

        shared_key.copy_from_slice(&sample.1);
        shared_ct.copy_from_slice(&sample.2);

        runner.run_one(sample.0, || {
            let _ = black_box(pqclean_mlkem768_decapsulate_from_buffers(
                black_box(&shared_key),
                black_box(&shared_ct),
            ));
        });
    }
}

fn bench_stage_hybrid_kem_key_a_vs_key_b_success(runner: &mut CtRunner, rng: &mut BenchRng) {
    let cit = Citadel::new();
    let (pk_a, sk_a) = cit.generate_keypair();
    let (pk_b, sk_b) = cit.generate_keypair();
    let sk_a_bytes = sk_a.to_bytes();
    let sk_b_bytes = sk_b.to_bytes();
    let aad = Aad::raw(b"dudect-aad");
    let ctx = Context::raw(b"dudect-ctx");
    let plaintext = vec![0x42u8; 256];

    let mut a_pairs = Vec::new();
    let mut b_pairs = Vec::new();
    for _ in 0..4096 {
        let sk = SecretKey::from_bytes(&sk_a_bytes).unwrap();
        let ct = cit.seal(&pk_a, &plaintext, &aad, &ctx).unwrap();
        let parts = wire::decode_wire(&ct).unwrap();
        a_pairs.push((sk, parts.kem_ciphertext.to_vec()));

        let sk = SecretKey::from_bytes(&sk_b_bytes).unwrap();
        let ct = cit.seal(&pk_b, &plaintext, &aad, &ctx).unwrap();
        let parts = wire::decode_wire(&ct).unwrap();
        b_pairs.push((sk, parts.kem_ciphertext.to_vec()));
    }

    let mut a_idx = 0usize;
    let mut b_idx = 0usize;
    for _ in 0..100_000 {
        if rng.gen::<bool>() {
            let pair = &a_pairs[a_idx % a_pairs.len()];
            a_idx += 1;
            runner.run_one(Class::Left, || {
                let _ = black_box(timing_diagnostics::hybrid_decapsulate(
                    &pair.0,
                    black_box(&pair.1),
                ));
            });
        } else {
            let pair = &b_pairs[b_idx % b_pairs.len()];
            b_idx += 1;
            runner.run_one(Class::Right, || {
                let _ = black_box(timing_diagnostics::hybrid_decapsulate(
                    &pair.0,
                    black_box(&pair.1),
                ));
            });
        }
    }
}

fn bench_stage_kdf_fixed_vs_random_secret(runner: &mut CtRunner, rng: &mut BenchRng) {
    let aad = Aad::raw(b"dudect-aad");
    let ctx = Context::raw(b"dudect-ctx");
    let plaintext = vec![0x42u8; 256];
    let (_, _, fixed_pairs, random_pairs, _, _) = build_stage_pairs(2048, &plaintext, &aad, &ctx);

    let mut fixed_idx = 0usize;
    let mut random_idx = 0usize;
    for _ in 0..100_000 {
        if rng.gen::<bool>() {
            let pair = &fixed_pairs[fixed_idx % fixed_pairs.len()];
            fixed_idx += 1;
            runner.run_one(Class::Left, || {
                let _ = black_box(timing_diagnostics::derive_key(
                    black_box(&pair.0),
                    &pair.1,
                    &pair.2,
                ));
            });
        } else {
            let pair = &random_pairs[random_idx % random_pairs.len()];
            random_idx += 1;
            runner.run_one(Class::Right, || {
                let _ = black_box(timing_diagnostics::derive_key(
                    black_box(&pair.0),
                    &pair.1,
                    &pair.2,
                ));
            });
        }
    }
}

fn bench_stage_aead_fixed_vs_random_key_success(runner: &mut CtRunner, rng: &mut BenchRng) {
    let aad = Aad::raw(b"dudect-aad");
    let ctx = Context::raw(b"dudect-ctx");
    let plaintext = vec![0x42u8; 256];
    let (_, _, _, _, fixed_pairs, random_pairs) = build_stage_pairs(2048, &plaintext, &aad, &ctx);

    let mut fixed_idx = 0usize;
    let mut random_idx = 0usize;
    for _ in 0..100_000 {
        if rng.gen::<bool>() {
            let pair = &fixed_pairs[fixed_idx % fixed_pairs.len()];
            fixed_idx += 1;
            runner.run_one(Class::Left, || {
                let _ = black_box(timing_diagnostics::aead_open(
                    black_box(&pair.0),
                    &pair.1,
                    black_box(&pair.2),
                    aad.as_bytes(),
                ));
            });
        } else {
            let pair = &random_pairs[random_idx % random_pairs.len()];
            random_idx += 1;
            runner.run_one(Class::Right, || {
                let _ = black_box(timing_diagnostics::aead_open(
                    black_box(&pair.0),
                    &pair.1,
                    black_box(&pair.2),
                    aad.as_bytes(),
                ));
            });
        }
    }
}

fn bench_info_wrong_key_a_vs_b_failure(runner: &mut CtRunner, rng: &mut BenchRng) {
    let cit = Citadel::new();
    let (pk, _sk) = cit.generate_keypair();
    let (_pk_a, sk_a) = cit.generate_keypair();
    let (_pk_b, sk_b) = cit.generate_keypair();
    let aad = Aad::raw(b"dudect-aad");
    let ctx = Context::raw(b"dudect-ctx");

    let plaintext = vec![0x42u8; 256];
    let ct = cit.seal(&pk, &plaintext, &aad, &ctx).unwrap();

    let mut classes = Vec::new();
    let mut use_a = Vec::new();

    for _ in 0..100_000 {
        if rng.gen::<bool>() {
            use_a.push(true);
            classes.push(Class::Left);
        } else {
            use_a.push(false);
            classes.push(Class::Right);
        }
    }

    for (class, a) in classes.into_iter().zip(use_a) {
        let sk = if a { &sk_a } else { &sk_b };
        runner.run_one(class, || {
            let _ = black_box(cit.open(sk, black_box(&ct), &aad, &ctx));
        });
    }
}

fn bench_info_valid_vs_short_public_format(runner: &mut CtRunner, rng: &mut BenchRng) {
    let cit = Citadel::new();
    let (pk, sk) = cit.generate_keypair();
    let aad = Aad::raw(b"dudect-aad");
    let ctx = Context::raw(b"dudect-ctx");

    let plaintext = vec![0x42u8; 256];
    let ct_valid = cit.seal(&pk, &plaintext, &aad, &ctx).unwrap();
    let ct_short: Vec<u8> = vec![0x01; 64];

    let mut inputs = Vec::new();
    let mut classes = Vec::new();

    for _ in 0..100_000 {
        if rng.gen::<bool>() {
            inputs.push(ct_valid.clone());
            classes.push(Class::Left);
        } else {
            inputs.push(ct_short.clone());
            classes.push(Class::Right);
        }
    }

    for (class, input) in classes.into_iter().zip(inputs) {
        runner.run_one(class, || {
            let _ = black_box(cit.open(&sk, black_box(&input), &aad, &ctx));
        });
    }
}

fn main() {
    let mut opts = BenchOpts::default();
    let mut args = std::env::args().skip(1).peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            // Cargo appends this flag when invoking bench targets. The
            // dudect-bencher macro-generated CLI rejects it, so this local
            // runner accepts and ignores it.
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
                    "Usage: timing_sidechannel [--filter BENCH] [--continuous BENCH] [--out FILE]"
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
            name: BenchName("bench_tag_first_byte_vs_last_byte_failure"),
            seed: None,
            benchfn: bench_tag_first_byte_vs_last_byte_failure,
        },
        BenchMetadata {
            name: BenchName("bench_wrong_aad_vs_wrong_tag_failure"),
            seed: None,
            benchfn: bench_wrong_aad_vs_wrong_tag_failure,
        },
        BenchMetadata {
            name: BenchName("bench_kem_corruption_a_vs_b_failure"),
            seed: None,
            benchfn: bench_kem_corruption_a_vs_b_failure,
        },
        BenchMetadata {
            name: BenchName("bench_key_material_fixed_vs_random_success"),
            seed: None,
            benchfn: bench_key_material_fixed_vs_random_success,
        },
        BenchMetadata {
            name: BenchName("bench_null_fixed_vs_random_harness_control"),
            seed: None,
            benchfn: bench_null_fixed_vs_random_harness_control,
        },
        BenchMetadata {
            name: BenchName("bench_stage_hybrid_kem_fixed_vs_random_success"),
            seed: None,
            benchfn: bench_stage_hybrid_kem_fixed_vs_random_success,
        },
        BenchMetadata {
            name: BenchName("bench_stage_x25519_fixed_vs_random_success"),
            seed: None,
            benchfn: bench_stage_x25519_fixed_vs_random_success,
        },
        BenchMetadata {
            name: BenchName("bench_stage_mlkem_fixed_vs_random_success"),
            seed: None,
            benchfn: bench_stage_mlkem_fixed_vs_random_success,
        },
        BenchMetadata {
            name: BenchName("bench_stage_mlkem_key_a_vs_key_b_success"),
            seed: None,
            benchfn: bench_stage_mlkem_key_a_vs_key_b_success,
        },
        BenchMetadata {
            name: BenchName("bench_stage_mlkem_same_key_pool_a_vs_pool_b_success"),
            seed: None,
            benchfn: bench_stage_mlkem_same_key_pool_a_vs_pool_b_success,
        },
        BenchMetadata {
            name: BenchName("bench_stage_mlkem_same_key_shared_buffer_control"),
            seed: None,
            benchfn: bench_stage_mlkem_same_key_shared_buffer_control,
        },
        BenchMetadata {
            name: BenchName("bench_stage_mlkem_same_key_pool_a_vs_pool_b_shared_buffer_success"),
            seed: None,
            benchfn: bench_stage_mlkem_same_key_pool_a_vs_pool_b_shared_buffer_success,
        },
        BenchMetadata {
            name: BenchName("bench_stage_mlkem_key_a_vs_key_b_shared_buffer_success"),
            seed: None,
            benchfn: bench_stage_mlkem_key_a_vs_key_b_shared_buffer_success,
        },
        BenchMetadata {
            name: BenchName("bench_pqclean_mlkem_same_key_shared_buffer_control"),
            seed: None,
            benchfn: bench_pqclean_mlkem_same_key_shared_buffer_control,
        },
        BenchMetadata {
            name: BenchName("bench_pqclean_mlkem_same_key_pool_a_vs_pool_b_shared_buffer_success"),
            seed: None,
            benchfn: bench_pqclean_mlkem_same_key_pool_a_vs_pool_b_shared_buffer_success,
        },
        BenchMetadata {
            name: BenchName("bench_pqclean_mlkem_key_a_vs_key_b_shared_buffer_success"),
            seed: None,
            benchfn: bench_pqclean_mlkem_key_a_vs_key_b_shared_buffer_success,
        },
        BenchMetadata {
            name: BenchName("bench_stage_hybrid_kem_key_a_vs_key_b_success"),
            seed: None,
            benchfn: bench_stage_hybrid_kem_key_a_vs_key_b_success,
        },
        BenchMetadata {
            name: BenchName("bench_stage_kdf_fixed_vs_random_secret"),
            seed: None,
            benchfn: bench_stage_kdf_fixed_vs_random_secret,
        },
        BenchMetadata {
            name: BenchName("bench_stage_aead_fixed_vs_random_key_success"),
            seed: None,
            benchfn: bench_stage_aead_fixed_vs_random_key_success,
        },
        BenchMetadata {
            name: BenchName("bench_info_wrong_key_a_vs_b_failure"),
            seed: None,
            benchfn: bench_info_wrong_key_a_vs_b_failure,
        },
        BenchMetadata {
            name: BenchName("bench_info_valid_vs_short_public_format"),
            seed: None,
            benchfn: bench_info_valid_vs_short_public_format,
        },
    ];

    run_benches_console(opts, benches).expect("dudect timing benchmark failed");
}
