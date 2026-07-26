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
// This is a leakage screen, not a proof of constant-time behavior. It prints
// dudect's maximum t-statistic; |t| < 4.5 after 100K samples means this run did
// not detect a difference. Positive findings require controls, repetition, and
// an attacker-model analysis before they are attributed to secret control flow.

use dudect_bencher::{
    ctbench::{run_benches_console, BenchMetadata, BenchName, BenchOpts},
    BenchRng, Class, CtRunner,
};
use rand::Rng;
use std::hint::black_box;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::Instant;

use citadel_envelope::{
    timing_diagnostics, wire, Aad, Citadel, CitadelP384, Context, P384MlKem1024PublicKey,
    P384MlKem1024SecretKey, PublicKey, SecretKey,
};
use libcrux_ml_kem::mlkem768 as libcrux_mlkem768;
use ml_kem::{
    kem::{Decapsulate, Encapsulate, Kem},
    ml_kem_768::{
        Ciphertext as RustCryptoCiphertext, DecapsulationKey as RustCryptoDecapsulationKey,
    },
    MlKem768,
};
#[allow(deprecated)]
use ml_kem::{ml_kem_768::ExpandedDecapsulationKey, ExpandedKeyEncoding};

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

fn fixture_nonce(class_domain: u32, index: usize) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&class_domain.to_be_bytes());
    nonce[4..].copy_from_slice(&(index as u64).to_be_bytes());
    nonce
}

fn fixture_kem_ciphertext(pk: &PublicKey, label: &str, index: usize) -> Vec<u8> {
    let (_, kem_ct) = timing_diagnostics::hybrid_encapsulate(pk)
        .unwrap_or_else(|_| panic!("{label} KEM encapsulation failed at fixture index {index}"));
    assert_eq!(
        kem_ct.len(),
        wire::KEM_CIPHERTEXT_BYTES,
        "{label} KEM ciphertext length mismatch at fixture index {index}"
    );
    kem_ct
}

fn fixture_kem_array(
    pk: &PublicKey,
    label: &str,
    index: usize,
) -> [u8; wire::KEM_CIPHERTEXT_BYTES] {
    fixture_kem_ciphertext(pk, label, index)
        .try_into()
        .unwrap_or_else(|_| panic!("{label} KEM array conversion failed at fixture index {index}"))
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
    let kem_range = timing_diagnostics::current_envelope_kem_range(&ct)
        .expect("current CTD2 fixture must decode before KEM mutation");
    // Both classes mutate bytes inside the CTD2 KEM field while preserving the
    // public header and wire shape. The previous offsets (6 and 7) altered suite
    // identifiers in the CTD2 header and never exercised KEM rejection.
    kem_a[kem_range.start] ^= 0x01;
    kem_b[kem_range.end - 1] ^= 0x01;

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

    // A null control requires class labels to be independent of the selected
    // input. The old control coupled Left=fixed-key and Right=random-key, so it
    // measured cache/key-reuse effects instead of harness noise.
    let mut pairs = fixed_pairs;
    pairs.extend(random_pairs);
    for _ in 0..100_000 {
        let class = if rng.gen::<bool>() {
            Class::Left
        } else {
            Class::Right
        };
        let pair = &pairs[rng.gen_range(0..pairs.len())];
        runner.run_one(class, || {
            let _ = dummy_touch(black_box(&pair.0), black_box(&pair.1));
        });
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
        let fixed_sk = SecretKey::from_bytes(&fixed_sk_bytes)
            .unwrap_or_else(|_| panic!("fixed timing key rejected at fixture index {i}"));
        let (fixed_ss, fixed_kem_ct) = timing_diagnostics::hybrid_encapsulate(&pk_fixed)
            .unwrap_or_else(|_| panic!("fixed KEM encapsulation failed at fixture index {i}"));
        let fixed_decapsulated = timing_diagnostics::hybrid_decapsulate(&fixed_sk, &fixed_kem_ct)
            .unwrap_or_else(|_| panic!("fixed KEM decapsulation failed at fixture index {i}"));
        assert_eq!(
            fixed_ss.as_slice(),
            fixed_decapsulated.as_slice(),
            "fixed KEM shared-secret mismatch at fixture index {i}"
        );
        let fixed_hash = timing_diagnostics::ct_hash(&fixed_kem_ct);
        let fixed_aes_key = timing_diagnostics::derive_key(&fixed_ss, &fixed_hash, ctx.as_bytes())
            .unwrap_or_else(|_| panic!("fixed KDF failed at fixture index {i}"));
        fixed_kem_pairs.push((fixed_sk, fixed_kem_ct));
        fixed_kdf_pairs.push((fixed_ss.to_vec(), fixed_hash, ctx.as_bytes().to_vec()));

        let fixed_nonce = fixture_nonce(1, i);
        let fixed_aead_ct =
            timing_diagnostics::aead_seal(&fixed_aes_key, &fixed_nonce, plaintext, aad.as_bytes())
                .unwrap_or_else(|_| panic!("fixed AEAD seal failed at fixture index {i}"));
        let fixed_roundtrip = timing_diagnostics::aead_open(
            &fixed_aes_key,
            &fixed_nonce,
            &fixed_aead_ct,
            aad.as_bytes(),
        )
        .unwrap_or_else(|_| panic!("fixed AEAD open failed at fixture index {i}"));
        assert_eq!(
            fixed_roundtrip, plaintext,
            "fixed AEAD mismatch at fixture index {i}"
        );
        fixed_aead_pairs.push((fixed_aes_key, fixed_nonce, fixed_aead_ct));

        let (pk, sk) = cit.generate_keypair();
        let (random_ss, random_kem_ct) = timing_diagnostics::hybrid_encapsulate(&pk)
            .unwrap_or_else(|_| panic!("random KEM encapsulation failed at fixture index {i}"));
        let random_decapsulated = timing_diagnostics::hybrid_decapsulate(&sk, &random_kem_ct)
            .unwrap_or_else(|_| panic!("random KEM decapsulation failed at fixture index {i}"));
        assert_eq!(
            random_ss.as_slice(),
            random_decapsulated.as_slice(),
            "random KEM shared-secret mismatch at fixture index {i}"
        );
        let random_hash = timing_diagnostics::ct_hash(&random_kem_ct);
        let random_aes_key =
            timing_diagnostics::derive_key(&random_ss, &random_hash, ctx.as_bytes())
                .unwrap_or_else(|_| panic!("random KDF failed at fixture index {i}"));
        random_kem_pairs.push((sk, random_kem_ct));
        random_kdf_pairs.push((random_ss.to_vec(), random_hash, ctx.as_bytes().to_vec()));

        let random_nonce = fixture_nonce(2, i);
        let random_aead_ct = timing_diagnostics::aead_seal(
            &random_aes_key,
            &random_nonce,
            plaintext,
            aad.as_bytes(),
        )
        .unwrap_or_else(|_| panic!("random AEAD seal failed at fixture index {i}"));
        let random_roundtrip = timing_diagnostics::aead_open(
            &random_aes_key,
            &random_nonce,
            &random_aead_ct,
            aad.as_bytes(),
        )
        .unwrap_or_else(|_| panic!("random AEAD open failed at fixture index {i}"));
        assert_eq!(
            random_roundtrip, plaintext,
            "random AEAD mismatch at fixture index {i}"
        );
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
    let mut samples = Vec::new();
    for i in 0..4096 {
        let sk = SecretKey::from_bytes(&sk_a_bytes).unwrap();
        let kem_ct = fixture_kem_ciphertext(&pk_a, "stage-key-a", i);
        samples.push((Class::Left, sk, kem_ct));

        let sk = SecretKey::from_bytes(&sk_b_bytes).unwrap();
        let kem_ct = fixture_kem_ciphertext(&pk_b, "stage-key-b", i);
        samples.push((Class::Right, sk, kem_ct));
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

fn bench_stage_mlkem_secret_bit_balanced_success(
    runner: &mut CtRunner,
    rng: &mut BenchRng,
    mlkem_secret_offset: usize,
    mask: u8,
    fixture_label: &str,
) {
    const PER_CLASS: usize = 2048;
    const MLKEM_DKPKE_BYTES: usize = 1152;
    assert!(mlkem_secret_offset < MLKEM_DKPKE_BYTES);
    assert!(mask.is_power_of_two());
    let cit = Citadel::new();
    let (fixed_pk, fixed_sk) = cit.generate_keypair();
    let fixed_sk_bytes = fixed_sk.to_bytes();
    let private_start = wire::X25519_KEY_BYTES;
    let private_end = private_start + MLKEM_DKPKE_BYTES;
    let validation_ct = fixture_kem_ciphertext(&fixed_pk, fixture_label, 0);
    let mut samples = Vec::with_capacity(PER_CLASS * 2);
    let mut left_indices = Vec::with_capacity(PER_CLASS);
    let mut right_indices = Vec::with_capacity(PER_CLASS);

    while left_indices.len() < PER_CLASS || right_indices.len() < PER_CLASS {
        let (_, random_sk) = cit.generate_keypair();
        let random_sk_bytes = random_sk.to_bytes();
        let mut isolated_sk_bytes = fixed_sk_bytes;
        isolated_sk_bytes[private_start..private_end]
            .copy_from_slice(&random_sk_bytes[private_start..private_end]);
        let is_left = isolated_sk_bytes[private_start + mlkem_secret_offset] & mask == 0;
        if (is_left && left_indices.len() == PER_CLASS)
            || (!is_left && right_indices.len() == PER_CLASS)
        {
            continue;
        }

        let index = samples.len();
        let sk = SecretKey::from_bytes(&isolated_sk_bytes)
            .unwrap_or_else(|_| panic!("isolated secret fixture key failed at index {index}"));
        let recovered = timing_diagnostics::mlkem_decapsulate_only(&sk, &validation_ct)
            .unwrap_or_else(|_| panic!("secret-bit fixture failed at index {index}"));
        black_box(recovered);
        samples.push(sk);
        if is_left {
            left_indices.push(index);
        } else {
            right_indices.push(index);
        }
    }

    for _ in 0..100_000 {
        let (class, indices) = if rng.gen::<bool>() {
            (Class::Left, &left_indices)
        } else {
            (Class::Right, &right_indices)
        };
        let sk = &samples[indices[rng.gen_range(0..indices.len())]];
        runner.run_one(class, || {
            let _ = black_box(timing_diagnostics::mlkem_decapsulate_only(
                sk,
                black_box(&validation_ct),
            ));
        });
    }
}

fn bench_stage_mlkem_secret_start_bit0_balanced_success(runner: &mut CtRunner, rng: &mut BenchRng) {
    bench_stage_mlkem_secret_bit_balanced_success(runner, rng, 0, 0x01, "secret-start-bit0");
}

fn bench_stage_mlkem_secret_middle_bit3_balanced_success(
    runner: &mut CtRunner,
    rng: &mut BenchRng,
) {
    bench_stage_mlkem_secret_bit_balanced_success(runner, rng, 576, 0x08, "secret-middle-bit3");
}

fn bench_stage_mlkem_secret_end_bit7_balanced_success(runner: &mut CtRunner, rng: &mut BenchRng) {
    // ML-KEM-768's private K-PKE component occupies the first 1,152 bytes.
    bench_stage_mlkem_secret_bit_balanced_success(runner, rng, 1151, 0x80, "secret-end-bit7");
}

fn bench_stage_mlkem_multikey_random_label_control(runner: &mut CtRunner, rng: &mut BenchRng) {
    const PER_CLASS: usize = 2048;
    const MLKEM_DKPKE_BYTES: usize = 1152;
    let cit = Citadel::new();
    let (fixed_pk, fixed_sk) = cit.generate_keypair();
    let fixed_sk_bytes = fixed_sk.to_bytes();
    let private_start = wire::X25519_KEY_BYTES;
    let private_end = private_start + MLKEM_DKPKE_BYTES;
    let validation_ct = fixture_kem_ciphertext(&fixed_pk, "isolated-control-validation", 0);
    let mut samples = Vec::with_capacity(PER_CLASS * 2);

    for index in 0..(PER_CLASS * 2) {
        let (_, random_sk) = cit.generate_keypair();
        let random_sk_bytes = random_sk.to_bytes();
        let mut isolated_sk_bytes = fixed_sk_bytes;
        isolated_sk_bytes[private_start..private_end]
            .copy_from_slice(&random_sk_bytes[private_start..private_end]);
        let sk = SecretKey::from_bytes(&isolated_sk_bytes)
            .unwrap_or_else(|_| panic!("isolated control key failed at index {index}"));
        let recovered = timing_diagnostics::mlkem_decapsulate_only(&sk, &validation_ct)
            .unwrap_or_else(|_| panic!("isolated control fixture failed at index {index}"));
        black_box(recovered);
        samples.push(sk);
    }

    for _ in 0..100_000 {
        let sk = &samples[rng.gen_range(0..samples.len())];
        let class = if rng.gen::<bool>() {
            Class::Left
        } else {
            Class::Right
        };
        runner.run_one(class, || {
            let _ = black_box(timing_diagnostics::mlkem_decapsulate_only(
                sk,
                black_box(&validation_ct),
            ));
        });
    }
}

fn build_libcrux_isolated_end_bit_samples() -> (
    Vec<libcrux_mlkem768::MlKem768PrivateKey>,
    Vec<usize>,
    Vec<usize>,
    libcrux_mlkem768::MlKem768Ciphertext,
) {
    const PER_CLASS: usize = 2048;
    const MLKEM_DKPKE_BYTES: usize = 1152;
    let mut fixed_seed = [0u8; 64];
    getrandom::getrandom(&mut fixed_seed).expect("libcrux fixed seed generation failed");
    let fixed_pair = libcrux_mlkem768::generate_key_pair(fixed_seed);
    let (fixed_sk, fixed_pk) = fixed_pair.into_parts();
    let fixed_sk_bytes: [u8; wire::MLKEM_SECRET_KEY_BYTES] = *fixed_sk.as_slice();
    let mut encaps_seed = [0u8; 32];
    getrandom::getrandom(&mut encaps_seed).expect("libcrux encapsulation seed generation failed");
    let (fixed_ct, _) = libcrux_mlkem768::encapsulate(&fixed_pk, encaps_seed);

    let mut samples = Vec::with_capacity(PER_CLASS * 2);
    let mut left_indices = Vec::with_capacity(PER_CLASS);
    let mut right_indices = Vec::with_capacity(PER_CLASS);
    while left_indices.len() < PER_CLASS || right_indices.len() < PER_CLASS {
        let mut random_seed = [0u8; 64];
        getrandom::getrandom(&mut random_seed).expect("libcrux sample seed generation failed");
        let random_pair = libcrux_mlkem768::generate_key_pair(random_seed);
        let (random_sk, _) = random_pair.into_parts();
        let random_sk_bytes: [u8; wire::MLKEM_SECRET_KEY_BYTES] = *random_sk.as_slice();
        let mut isolated_sk_bytes = fixed_sk_bytes;
        isolated_sk_bytes[..MLKEM_DKPKE_BYTES]
            .copy_from_slice(&random_sk_bytes[..MLKEM_DKPKE_BYTES]);
        let is_left = isolated_sk_bytes[MLKEM_DKPKE_BYTES - 1] & 0x80 == 0;
        if (is_left && left_indices.len() == PER_CLASS)
            || (!is_left && right_indices.len() == PER_CLASS)
        {
            continue;
        }
        let index = samples.len();
        let isolated_sk = libcrux_mlkem768::MlKem768PrivateKey::from(isolated_sk_bytes);
        black_box(libcrux_mlkem768::decapsulate(&isolated_sk, &fixed_ct));
        samples.push(isolated_sk);
        if is_left {
            left_indices.push(index);
        } else {
            right_indices.push(index);
        }
    }
    (samples, left_indices, right_indices, fixed_ct)
}

fn bench_libcrux_mlkem_secret_end_bit7_balanced_success(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (samples, left_indices, right_indices, fixed_ct) = build_libcrux_isolated_end_bit_samples();
    for _ in 0..100_000 {
        let (class, indices) = if rng.gen::<bool>() {
            (Class::Left, &left_indices)
        } else {
            (Class::Right, &right_indices)
        };
        let sk = &samples[indices[rng.gen_range(0..indices.len())]];
        runner.run_one(class, || {
            let _ = black_box(libcrux_mlkem768::decapsulate(sk, black_box(&fixed_ct)));
        });
    }
}

fn bench_libcrux_mlkem_isolated_random_label_control(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (samples, _, _, fixed_ct) = build_libcrux_isolated_end_bit_samples();
    for _ in 0..100_000 {
        let sk = &samples[rng.gen_range(0..samples.len())];
        let class = if rng.gen::<bool>() {
            Class::Left
        } else {
            Class::Right
        };
        runner.run_one(class, || {
            let _ = black_box(libcrux_mlkem768::decapsulate(sk, black_box(&fixed_ct)));
        });
    }
}

fn bench_stage_mlkem_same_key_pool_a_vs_pool_b_success(runner: &mut CtRunner, rng: &mut BenchRng) {
    let cit = Citadel::new();
    let (pk, sk_original) = cit.generate_keypair();
    let sk_bytes = sk_original.to_bytes();
    let mut samples = Vec::new();
    for i in 0..4096 {
        let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
        let kem_ct = fixture_kem_ciphertext(&pk, "same-key-pool-a", i);
        samples.push((sk, kem_ct));

        let sk = SecretKey::from_bytes(&sk_bytes).unwrap();
        let kem_ct = fixture_kem_ciphertext(&pk, "same-key-pool-b", i);
        samples.push((sk, kem_ct));
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
    let mut samples = Vec::new();
    for i in 0..8192 {
        samples.push((
            sk_bytes,
            fixture_kem_array(&pk, "same-key-shared-control", i),
        ));
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
    let mut samples = Vec::new();
    for i in 0..4096 {
        samples.push((
            Class::Left,
            sk_bytes,
            fixture_kem_array(&pk, "same-key-shared-pool-a", i),
        ));

        samples.push((
            Class::Right,
            sk_bytes,
            fixture_kem_array(&pk, "same-key-shared-pool-b", i),
        ));
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
    let mut samples = Vec::new();
    for i in 0..4096 {
        samples.push((
            Class::Left,
            sk_a_bytes,
            fixture_kem_array(&pk_a, "key-a-shared", i),
        ));

        samples.push((
            Class::Right,
            sk_b_bytes,
            fixture_kem_array(&pk_b, "key-b-shared", i),
        ));
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

#[allow(deprecated)]
fn rustcrypto_mlkem768_decapsulate_from_buffers(
    sk_bytes: &[u8; wire::MLKEM_SECRET_KEY_BYTES],
    ct_bytes: &[u8; wire::MLKEM_CIPHERTEXT_BYTES],
) -> [u8; 32] {
    let encoded: ExpandedDecapsulationKey = (*sk_bytes).into();
    let sk = RustCryptoDecapsulationKey::from_expanded_bytes(&encoded).unwrap();
    let ct: RustCryptoCiphertext = (*ct_bytes).into();
    let ss = sk.decapsulate(&ct);
    let mut out = [0u8; 32];
    out.copy_from_slice(ss.as_ref());
    out
}

#[allow(deprecated)]
fn bench_rustcrypto_mlkem_same_key_shared_buffer_control(
    runner: &mut CtRunner,
    rng: &mut BenchRng,
) {
    let (sk, pk) = MlKem768::generate_keypair();
    let sk_bytes: [u8; wire::MLKEM_SECRET_KEY_BYTES] = sk.to_expanded_bytes().into();

    let mut samples = Vec::new();
    for _ in 0..8192 {
        let (ct, _) = pk.encapsulate();
        let ct_bytes: [u8; wire::MLKEM_CIPHERTEXT_BYTES] = ct.into();
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
            let _ = black_box(rustcrypto_mlkem768_decapsulate_from_buffers(
                black_box(&shared_key),
                black_box(&shared_ct),
            ));
        });
    }
}

#[allow(deprecated)]
fn bench_rustcrypto_mlkem_same_key_pool_a_vs_pool_b_shared_buffer_success(
    runner: &mut CtRunner,
    rng: &mut BenchRng,
) {
    let (sk, pk) = MlKem768::generate_keypair();
    let sk_bytes: [u8; wire::MLKEM_SECRET_KEY_BYTES] = sk.to_expanded_bytes().into();

    let mut samples = Vec::new();
    for _ in 0..4096 {
        let (ct_a, _) = pk.encapsulate();
        let ct_a_bytes: [u8; wire::MLKEM_CIPHERTEXT_BYTES] = ct_a.into();
        samples.push((Class::Left, sk_bytes, ct_a_bytes));

        let (ct_b, _) = pk.encapsulate();
        let ct_b_bytes: [u8; wire::MLKEM_CIPHERTEXT_BYTES] = ct_b.into();
        samples.push((Class::Right, sk_bytes, ct_b_bytes));
    }

    let mut shared_key = [0u8; wire::MLKEM_SECRET_KEY_BYTES];
    let mut shared_ct = [0u8; wire::MLKEM_CIPHERTEXT_BYTES];

    for _ in 0..100_000 {
        let sample = &samples[rng.gen_range(0..samples.len())];

        shared_key.copy_from_slice(&sample.1);
        shared_ct.copy_from_slice(&sample.2);

        runner.run_one(sample.0, || {
            let _ = black_box(rustcrypto_mlkem768_decapsulate_from_buffers(
                black_box(&shared_key),
                black_box(&shared_ct),
            ));
        });
    }
}

#[allow(deprecated)]
fn bench_rustcrypto_mlkem_key_a_vs_key_b_shared_buffer_success(
    runner: &mut CtRunner,
    rng: &mut BenchRng,
) {
    let (sk_a, pk_a) = MlKem768::generate_keypair();
    let (sk_b, pk_b) = MlKem768::generate_keypair();
    let sk_a_bytes: [u8; wire::MLKEM_SECRET_KEY_BYTES] = sk_a.to_expanded_bytes().into();
    let sk_b_bytes: [u8; wire::MLKEM_SECRET_KEY_BYTES] = sk_b.to_expanded_bytes().into();

    let mut samples = Vec::new();
    for _ in 0..4096 {
        let (ct_a, _) = pk_a.encapsulate();
        let ct_a_bytes: [u8; wire::MLKEM_CIPHERTEXT_BYTES] = ct_a.into();
        samples.push((Class::Left, sk_a_bytes, ct_a_bytes));

        let (ct_b, _) = pk_b.encapsulate();
        let ct_b_bytes: [u8; wire::MLKEM_CIPHERTEXT_BYTES] = ct_b.into();
        samples.push((Class::Right, sk_b_bytes, ct_b_bytes));
    }

    let mut shared_key = [0u8; wire::MLKEM_SECRET_KEY_BYTES];
    let mut shared_ct = [0u8; wire::MLKEM_CIPHERTEXT_BYTES];

    for _ in 0..100_000 {
        let sample = &samples[rng.gen_range(0..samples.len())];

        shared_key.copy_from_slice(&sample.1);
        shared_ct.copy_from_slice(&sample.2);

        runner.run_one(sample.0, || {
            let _ = black_box(rustcrypto_mlkem768_decapsulate_from_buffers(
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
    let mut a_pairs = Vec::new();
    let mut b_pairs = Vec::new();
    for i in 0..4096 {
        let sk = SecretKey::from_bytes(&sk_a_bytes).unwrap();
        let kem_ct = fixture_kem_ciphertext(&pk_a, "hybrid-key-a", i);
        a_pairs.push((sk, kem_ct));

        let sk = SecretKey::from_bytes(&sk_b_bytes).unwrap();
        let kem_ct = fixture_kem_ciphertext(&pk_b, "hybrid-key-b", i);
        b_pairs.push((sk, kem_ct));
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

fn run_fixture_preflight() {
    let aad = Aad::raw(b"dudect-aad");
    let ctx = Context::raw(b"dudect-ctx");
    let plaintext = vec![0x42u8; 256];
    let (fixed_kem, random_kem, fixed_kdf, random_kdf, fixed_aead, random_aead) =
        build_stage_pairs(2048, &plaintext, &aad, &ctx);
    assert_eq!(fixed_kem.len(), 2048);
    assert_eq!(random_kem.len(), 2048);
    assert_eq!(fixed_kdf.len(), 2048);
    assert_eq!(random_kdf.len(), 2048);
    assert_eq!(fixed_aead.len(), 2048);
    assert_eq!(random_aead.len(), 2048);
    println!("timing fixture preflight: 2048 fixed + 2048 random pairs valid");
}

fn run_independent_isolated_sample(mode: &str, count: usize, output: &PathBuf) {
    const PER_CLASS: usize = 2048;
    const MLKEM_DKPKE_BYTES: usize = 1152;
    let cit = Citadel::new();
    let (fixed_pk, fixed_sk) = cit.generate_keypair();
    let fixed_sk_bytes = fixed_sk.to_bytes();
    let private_start = wire::X25519_KEY_BYTES;
    let private_end = private_start + MLKEM_DKPKE_BYTES;
    let validation_ct = fixture_kem_ciphertext(&fixed_pk, "independent-isolated", 0);
    let mut samples = Vec::with_capacity(PER_CLASS * 2);
    let mut left_indices = Vec::with_capacity(PER_CLASS);
    let mut right_indices = Vec::with_capacity(PER_CLASS);

    while left_indices.len() < PER_CLASS || right_indices.len() < PER_CLASS {
        let (_, random_sk) = cit.generate_keypair();
        let random_sk_bytes = random_sk.to_bytes();
        let mut isolated_sk_bytes = fixed_sk_bytes;
        isolated_sk_bytes[private_start..private_end]
            .copy_from_slice(&random_sk_bytes[private_start..private_end]);
        let is_left = isolated_sk_bytes[private_start + MLKEM_DKPKE_BYTES - 1] & 0x80 == 0;
        if (is_left && left_indices.len() == PER_CLASS)
            || (!is_left && right_indices.len() == PER_CLASS)
        {
            continue;
        }
        let index = samples.len();
        let sk = SecretKey::from_bytes(&isolated_sk_bytes)
            .unwrap_or_else(|_| panic!("independent sample key failed at index {index}"));
        let recovered = timing_diagnostics::mlkem_decapsulate_only(&sk, &validation_ct)
            .unwrap_or_else(|_| panic!("independent sample preflight failed at index {index}"));
        black_box(recovered);
        samples.push(sk);
        if is_left {
            left_indices.push(index);
        } else {
            right_indices.push(index);
        }
    }

    let secret_class = match mode {
        "secret-end-bit7" => true,
        "random-label-control" => false,
        _ => panic!("unknown independent sample mode: {mode}"),
    };
    let mut rng = rand::thread_rng();
    let mut rows = Vec::with_capacity(count);
    for _ in 0..count {
        let class_left = rng.gen::<bool>();
        let sample_index = if secret_class {
            let indices = if class_left {
                &left_indices
            } else {
                &right_indices
            };
            indices[rng.gen_range(0..indices.len())]
        } else {
            rng.gen_range(0..samples.len())
        };
        let start = Instant::now();
        let result = timing_diagnostics::mlkem_decapsulate_only(
            black_box(&samples[sample_index]),
            black_box(&validation_ct),
        );
        black_box(result.expect("preflighted independent sample must decapsulate"));
        rows.push((if class_left { 0 } else { 1 }, start.elapsed().as_nanos()));
    }

    let file = std::fs::File::create(output).expect("create independent timing CSV");
    let mut writer = BufWriter::new(file);
    writeln!(writer, "benchname,class,runtime").unwrap();
    for (class, runtime) in rows {
        writeln!(writer, "independent_{mode},{class},{runtime}").unwrap();
    }
    writer.flush().unwrap();
    println!(
        "independent timing sample complete: mode={mode} n={count} out={}",
        output.display()
    );
}

// ---------------------------------------------------------------------------
// P-384 arm (suite 0xA4) — dudect screens for the NEW classical primitive.
// The ML-KEM-1024 arm is the same family as 768 (already characterized in TIMING.md);
// what 0xA4 adds is pure-Rust p384 ECDH, isolated here via `p384_ecdh_only`.
// ---------------------------------------------------------------------------

fn p384_fixture_kem_ct(pk: &P384MlKem1024PublicKey, label: &str, index: usize) -> Vec<u8> {
    let (_, kem_ct) = timing_diagnostics::p384_encapsulate(pk)
        .unwrap_or_else(|_| panic!("{label} p384 encapsulation failed at fixture index {index}"));
    assert_eq!(
        kem_ct.len(),
        1665,
        "{label} p384 kem ct length mismatch at index {index}"
    );
    kem_ct
}

/// Static-key-material screen on the P-384 ECDH: two keys A/B, does decapsulation timing
/// distinguish the key? This is the class the ML-KEM finding flagged (Hertzbleed-class); it
/// is NOT attacker-varyable per query. Interpret only with the same-key pool control below.
fn bench_stage_p384_ecdh_key_a_vs_key_b_success(runner: &mut CtRunner, rng: &mut BenchRng) {
    let cit = CitadelP384::new();
    let (pk_a, sk_a) = cit.generate_keypair();
    let (pk_b, sk_b) = cit.generate_keypair();
    let sk_a_bytes = sk_a.to_bytes();
    let sk_b_bytes = sk_b.to_bytes();
    let mut samples = Vec::new();
    for i in 0..4096 {
        let sk = P384MlKem1024SecretKey::from_bytes(&sk_a_bytes).unwrap();
        samples.push((Class::Left, sk, p384_fixture_kem_ct(&pk_a, "p384-key-a", i)));
        let sk = P384MlKem1024SecretKey::from_bytes(&sk_b_bytes).unwrap();
        samples.push((
            Class::Right,
            sk,
            p384_fixture_kem_ct(&pk_b, "p384-key-b", i),
        ));
    }
    for _ in 0..100_000 {
        let sample = &samples[rng.gen_range(0..samples.len())];
        runner.run_one(sample.0, || {
            let _ = black_box(timing_diagnostics::p384_ecdh_only(
                &sample.1,
                black_box(&sample.2),
            ));
        });
    }
}

/// Null control for the screen above: ONE key, two independent ciphertext pools assigned to
/// Left/Right. If this exceeds |t| ≥ 4.5, the key-A-vs-key-B result is confounded by
/// pool/layout effects and must be marked REVIEW, not treated as a key-material leak.
fn bench_stage_p384_ecdh_same_key_pool_a_vs_pool_b_control(
    runner: &mut CtRunner,
    rng: &mut BenchRng,
) {
    let cit = CitadelP384::new();
    let (pk, sk) = cit.generate_keypair();
    let sk_bytes = sk.to_bytes();
    let mut samples = Vec::new();
    for i in 0..4096 {
        let sk_l = P384MlKem1024SecretKey::from_bytes(&sk_bytes).unwrap();
        samples.push((
            Class::Left,
            sk_l,
            p384_fixture_kem_ct(&pk, "p384-pool-a", i),
        ));
        let sk_r = P384MlKem1024SecretKey::from_bytes(&sk_bytes).unwrap();
        samples.push((
            Class::Right,
            sk_r,
            p384_fixture_kem_ct(&pk, "p384-pool-b", i),
        ));
    }
    for _ in 0..100_000 {
        let sample = &samples[rng.gen_range(0..samples.len())];
        runner.run_one(sample.0, || {
            let _ = black_box(timing_diagnostics::p384_ecdh_only(
                &sample.1,
                black_box(&sample.2),
            ));
        });
    }
}

fn main() {
    let mut opts = BenchOpts::default();
    let mut args = std::env::args().skip(1).peekable();
    let mut independent_mode = None;
    let mut independent_samples = 100_000usize;
    let mut independent_out = None;

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
            "--preflight" => {
                run_fixture_preflight();
                return;
            }
            "--independent-sample" => independent_mode = args.next(),
            "--samples" => {
                independent_samples = args
                    .next()
                    .expect("--samples requires a positive integer")
                    .parse()
                    .expect("--samples requires a positive integer");
                assert!(independent_samples > 0, "--samples must be positive");
            }
            "--independent-out" => independent_out = args.next().map(PathBuf::from),
            "-h" | "--help" => {
                println!(
                    "Usage: timing_sidechannel [--preflight] [--filter BENCH] [--continuous BENCH] [--out FILE] [--independent-sample MODE --samples N --independent-out FILE]"
                );
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }

    if let Some(mode) = independent_mode {
        let output = independent_out.expect("--independent-sample requires --independent-out");
        run_independent_isolated_sample(&mode, independent_samples, &output);
        return;
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
            name: BenchName("bench_stage_mlkem_secret_start_bit0_balanced_success"),
            seed: None,
            benchfn: bench_stage_mlkem_secret_start_bit0_balanced_success,
        },
        BenchMetadata {
            name: BenchName("bench_stage_mlkem_secret_middle_bit3_balanced_success"),
            seed: None,
            benchfn: bench_stage_mlkem_secret_middle_bit3_balanced_success,
        },
        BenchMetadata {
            name: BenchName("bench_stage_mlkem_secret_end_bit7_balanced_success"),
            seed: None,
            benchfn: bench_stage_mlkem_secret_end_bit7_balanced_success,
        },
        BenchMetadata {
            name: BenchName("bench_stage_mlkem_multikey_random_label_control"),
            seed: None,
            benchfn: bench_stage_mlkem_multikey_random_label_control,
        },
        BenchMetadata {
            name: BenchName("bench_libcrux_mlkem_secret_end_bit7_balanced_success"),
            seed: None,
            benchfn: bench_libcrux_mlkem_secret_end_bit7_balanced_success,
        },
        BenchMetadata {
            name: BenchName("bench_libcrux_mlkem_isolated_random_label_control"),
            seed: None,
            benchfn: bench_libcrux_mlkem_isolated_random_label_control,
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
            name: BenchName("bench_rustcrypto_mlkem_same_key_shared_buffer_control"),
            seed: None,
            benchfn: bench_rustcrypto_mlkem_same_key_shared_buffer_control,
        },
        BenchMetadata {
            name: BenchName(
                "bench_rustcrypto_mlkem_same_key_pool_a_vs_pool_b_shared_buffer_success",
            ),
            seed: None,
            benchfn: bench_rustcrypto_mlkem_same_key_pool_a_vs_pool_b_shared_buffer_success,
        },
        BenchMetadata {
            name: BenchName("bench_rustcrypto_mlkem_key_a_vs_key_b_shared_buffer_success"),
            seed: None,
            benchfn: bench_rustcrypto_mlkem_key_a_vs_key_b_shared_buffer_success,
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
        BenchMetadata {
            name: BenchName("bench_stage_p384_ecdh_key_a_vs_key_b_success"),
            seed: None,
            benchfn: bench_stage_p384_ecdh_key_a_vs_key_b_success,
        },
        BenchMetadata {
            name: BenchName("bench_stage_p384_ecdh_same_key_pool_a_vs_pool_b_control"),
            seed: None,
            benchfn: bench_stage_p384_ecdh_same_key_pool_a_vs_pool_b_control,
        },
    ];

    run_benches_console(opts, benches).expect("dudect timing benchmark failed");
}
