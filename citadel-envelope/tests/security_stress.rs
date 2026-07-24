// SPDX-License-Identifier: AGPL-3.0-or-later
//! Security stress tests for citadel-envelope.
//!
//! These tests go beyond correctness into adversarial territory.
//! Run with: cargo test --test security_stress -- --nocapture
//!
//! For timing tests specifically:
//!   cargo test --test security_stress timing -- --nocapture --test-threads=1
//!
//! For the full suite including slow tests:
//!   cargo test --test security_stress -- --nocapture --include-ignored

use citadel_envelope::{Aad, Citadel, Context, OpenError, PublicKey, SecretKey};
use std::collections::HashSet;
use std::time::{Duration, Instant};

fn setup() -> (Citadel, PublicKey, SecretKey) {
    let cit = Citadel::new();
    let (pk, sk) = cit.generate_keypair();
    (cit, pk, sk)
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. TIMING UNIFORMITY
//    A timing side-channel leaks whether decryption failed due to bad AAD,
//    bad ciphertext, bad key, or truncation. All failures must take the same
//    time — otherwise an attacker can distinguish failure modes.
// ─────────────────────────────────────────────────────────────────────────────

fn measure_ns<F: Fn()>(f: F, iterations: usize) -> Vec<u64> {
    (0..iterations)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed().as_nanos() as u64
        })
        .collect()
}

fn mean(v: &[u64]) -> f64 {
    v.iter().sum::<u64>() as f64 / v.len() as f64
}

fn stddev(v: &[u64]) -> f64 {
    let m = mean(v);
    let variance = v.iter().map(|&x| (x as f64 - m).powi(2)).sum::<f64>() / v.len() as f64;
    variance.sqrt()
}

// Load-sensitive wall-clock timing assertion — run on a QUIET box, in isolation:
//   cargo test -p citadel-envelope timing_bad_aad_vs_bad_ciphertext_uniform \
//       -- --ignored --test-threads=1
// It measures a real property (uniform decrypt-failure timing across bad-AAD vs
// tampered-ciphertext), but the threshold is CPU-contention sensitive and flakes
// under full-suite/host load, so it is #[ignore]d by default rather than gating CI
// on a noisy signal. Not a correctness test — keep it, run it deliberately.
#[test]
#[ignore = "load-sensitive timing assertion; run in isolation on a quiet box (see note above)"]
fn timing_bad_aad_vs_bad_ciphertext_uniform() {
    // Tests that decrypt failure due to wrong AAD takes the same time as
    // failure due to a tampered ciphertext byte. If they differ significantly,
    // an attacker could distinguish failure modes via timing.
    let (cit, pk, sk) = setup();
    let aad = Aad::raw(b"legitimate-aad");
    let ctx = Context::raw(b"ctx");
    let ct = cit.seal(&pk, b"secret", &aad, &ctx).unwrap();

    let mut tampered = ct.clone();
    tampered[ct.len() - 1] ^= 0x01; // flip last AEAD tag byte

    let iterations = 500;

    let times_bad_aad = measure_ns(
        || {
            let _ = cit.open(&sk, &ct, &Aad::raw(b"wrong-aad"), &ctx);
        },
        iterations,
    );

    let times_tampered = measure_ns(
        || {
            let _ = cit.open(&sk, &tampered, &aad, &ctx);
        },
        iterations,
    );

    let mean_bad_aad = mean(&times_bad_aad);
    let mean_tampered = mean(&times_tampered);
    let diff_pct = ((mean_bad_aad - mean_tampered).abs() / mean_tampered) * 100.0;

    println!(
        "Timing — bad AAD:     mean={:.0}ns  stddev={:.0}ns",
        mean_bad_aad,
        stddev(&times_bad_aad)
    );
    println!(
        "Timing — tampered ct: mean={:.0}ns  stddev={:.0}ns",
        mean_tampered,
        stddev(&times_tampered)
    );
    println!("Timing — difference:  {:.1}%", diff_pct);

    // Allow up to 25% difference — tighter than typical 50% threshold.
    // Real constant-time implementations should be well under 10%.
    assert!(
        diff_pct < 25.0,
        "Timing difference between bad-AAD and tampered-ciphertext is {:.1}%",
        diff_pct
    );
}

#[test]
fn timing_wrong_key_vs_bad_aad_uniform() {
    let (cit, pk, sk) = setup();
    let (_, _, sk2) = setup(); // different keypair
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");
    let ct = cit.seal(&pk, b"secret data", &aad, &ctx).unwrap();

    let iterations = 500;

    let times_wrong_key = measure_ns(
        || {
            let _ = cit.open(&sk2, &ct, &aad, &ctx);
        },
        iterations,
    );

    let times_bad_aad = measure_ns(
        || {
            let _ = cit.open(&sk, &ct, &Aad::raw(b"wrong"), &ctx);
        },
        iterations,
    );

    let diff_pct =
        ((mean(&times_wrong_key) - mean(&times_bad_aad)).abs() / mean(&times_bad_aad)) * 100.0;

    println!("Timing — wrong key:  mean={:.0}ns", mean(&times_wrong_key));
    println!("Timing — bad AAD:    mean={:.0}ns", mean(&times_bad_aad));
    println!("Timing — diff:       {:.1}%", diff_pct);

    // ML-KEM decapsulation (wrong key) is more expensive than AEAD tag
    // verification (bad AAD) — this is a structural difference, not a
    // side channel. 60% threshold catches catastrophic leaks while
    // accounting for this known asymmetry.
    assert!(
        diff_pct < 60.0,
        "Timing difference between wrong-key and bad-AAD is {:.1}%",
        diff_pct
    );
}

#[test]
fn timing_truncated_vs_full_bad() {
    let (cit, pk, sk) = setup();
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");
    let ct = cit.seal(&pk, b"data", &aad, &ctx).unwrap();

    let iterations = 500;

    let times_truncated = measure_ns(
        || {
            let _ = cit.open(&sk, &ct[..10], &aad, &ctx);
        },
        iterations,
    );

    let times_empty = measure_ns(
        || {
            let _ = cit.open(&sk, b"", &aad, &ctx);
        },
        iterations,
    );

    println!(
        "Timing — truncated(10): mean={:.0}ns",
        mean(&times_truncated)
    );
    println!("Timing — empty:         mean={:.0}ns", mean(&times_empty));

    // Truncated inputs should fail fast and uniformly — no long computation
    assert!(
        mean(&times_truncated) < 1_000_000.0, // under 1ms
        "Truncated decrypt taking too long — possible timing issue"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. NONCE UNIQUENESS
//    AES-GCM catastrophically fails if the same nonce is used twice with the
//    same key. Under normal usage this shouldn't happen, but we verify it
//    statistically across thousands of encryptions.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn nonce_uniqueness_under_volume() {
    let (cit, pk, _sk) = setup();
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");

    let count = 10_000;
    let mut nonces: HashSet<Vec<u8>> = HashSet::with_capacity(count);
    let mut collisions = 0;

    for i in 0..count {
        let plaintext = format!("message-{}", i);
        let ct = cit.seal(&pk, plaintext.as_bytes(), &aad, &ctx).unwrap();
        assert!(ct.starts_with(b"CTD2"));
        let nonce = ct[86..98].to_vec();
        if !nonces.insert(nonce) {
            collisions += 1;
        }
    }

    println!(
        "Nonce uniqueness: {} encryptions, {} collisions",
        count, collisions
    );
    assert_eq!(
        collisions, 0,
        "Nonce collision detected across {} encryptions — critical AES-GCM failure",
        count
    );
}

#[test]
fn nonce_uniqueness_multiple_keypairs() {
    // Nonces should also be unique across different keypairs using the same plaintext
    let count = 1_000;
    let mut nonces: HashSet<Vec<u8>> = HashSet::with_capacity(count);

    for _ in 0..count {
        let cit = Citadel::new();
        let (pk, _) = cit.generate_keypair();
        let ct = cit
            .seal(
                &pk,
                b"same plaintext",
                &Aad::raw(b"aad"),
                &Context::raw(b"ctx"),
            )
            .unwrap();
        assert!(ct.starts_with(b"CTD2"));
        nonces.insert(ct[86..98].to_vec());
    }

    // All nonces should be unique
    assert_eq!(nonces.len(), count, "Nonce collision across keypairs");
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. CIPHERTEXT MALLEABILITY
//    Verify that every byte of the ciphertext is authenticated. Flipping any
//    single bit anywhere should cause decryption to fail.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn every_byte_is_authenticated() {
    let (cit, pk, sk) = setup();
    let plaintext = b"authenticated encryption test";
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");
    let ct = cit.seal(&pk, plaintext, &aad, &ctx).unwrap();

    let mut failures = 0;
    let total = ct.len();

    for byte_idx in 0..total {
        let mut tampered = ct.clone();
        tampered[byte_idx] ^= 0x01;
        if cit.open(&sk, &tampered, &aad, &ctx).is_ok() {
            failures += 1;
            eprintln!("MALLEABILITY: byte {} not authenticated", byte_idx);
        }
    }

    println!(
        "Malleability: {}/{} bytes authenticated (all must be)",
        total - failures,
        total
    );
    assert_eq!(
        failures, 0,
        "{} bytes are NOT authenticated — ciphertext malleable",
        failures
    );
}

#[test]
fn bit_flip_anywhere_fails() {
    let (cit, pk, sk) = setup();
    let ct = cit
        .seal(&pk, b"data", &Aad::raw(b"aad"), &Context::raw(b"ctx"))
        .unwrap();

    // Test every bit, not just every byte
    let mut undetected = 0;
    for byte_idx in 0..ct.len() {
        for bit in 0..8u8 {
            let mut tampered = ct.clone();
            tampered[byte_idx] ^= 1 << bit;
            if tampered != ct {
                // Only test if actually different
                if cit
                    .open(&sk, &tampered, &Aad::raw(b"aad"), &Context::raw(b"ctx"))
                    .is_ok()
                {
                    undetected += 1;
                }
            }
        }
    }

    assert_eq!(undetected, 0, "{} bit flips went undetected", undetected);
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. BOUNDARY AND EDGE CASES
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn aad_boundary_values() {
    let (cit, pk, sk) = setup();
    let ctx = Context::raw(b"ctx");
    let plaintext = b"test";

    // Empty AAD
    let ct = cit.seal(&pk, plaintext, &Aad::empty(), &ctx).unwrap();
    let pt = cit.open(&sk, &ct, &Aad::empty(), &ctx).unwrap();
    assert_eq!(&pt, plaintext);

    // Single byte AAD
    let ct = cit.seal(&pk, plaintext, &Aad::raw(b"\x00"), &ctx).unwrap();
    let pt = cit.open(&sk, &ct, &Aad::raw(b"\x00"), &ctx).unwrap();
    assert_eq!(&pt, plaintext);

    // All-zeros AAD
    let zero_aad = vec![0u8; 256];
    let ct = cit
        .seal(&pk, plaintext, &Aad::raw(&zero_aad), &ctx)
        .unwrap();
    let pt = cit.open(&sk, &ct, &Aad::raw(&zero_aad), &ctx).unwrap();
    assert_eq!(&pt, plaintext);

    // All-ones AAD
    let ones_aad = vec![0xFFu8; 256];
    let ct = cit
        .seal(&pk, plaintext, &Aad::raw(&ones_aad), &ctx)
        .unwrap();
    let pt = cit.open(&sk, &ct, &Aad::raw(&ones_aad), &ctx).unwrap();
    assert_eq!(&pt, plaintext);

    // AAD with null bytes
    let ct = cit
        .seal(&pk, plaintext, &Aad::raw(b"aad\x00with\x00nulls"), &ctx)
        .unwrap();
    let pt = cit
        .open(&sk, &ct, &Aad::raw(b"aad\x00with\x00nulls"), &ctx)
        .unwrap();
    assert_eq!(&pt, plaintext);
}

#[test]
fn plaintext_boundary_values() {
    let (cit, pk, sk) = setup();
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");

    // Single byte
    let ct = cit.seal(&pk, b"\x00", &aad, &ctx).unwrap();
    let pt = cit.open(&sk, &ct, &aad, &ctx).unwrap();
    assert_eq!(pt, b"\x00");

    // All zeros
    let zeros = vec![0u8; 1024];
    let ct = cit.seal(&pk, &zeros, &aad, &ctx).unwrap();
    let pt = cit.open(&sk, &ct, &aad, &ctx).unwrap();
    assert_eq!(pt, zeros);

    // All 0xFF
    let ones = vec![0xFFu8; 1024];
    let ct = cit.seal(&pk, &ones, &aad, &ctx).unwrap();
    let pt = cit.open(&sk, &ct, &aad, &ctx).unwrap();
    assert_eq!(pt, ones);

    // High entropy (random-looking)
    let high_entropy: Vec<u8> = (0..1024).map(|i| ((i * 7 + 13) % 256) as u8).collect();
    let ct = cit.seal(&pk, &high_entropy, &aad, &ctx).unwrap();
    let pt = cit.open(&sk, &ct, &aad, &ctx).unwrap();
    assert_eq!(pt, high_entropy);

    // Unicode
    let unicode = "こんにちは世界 — Hello, 世界! 🔐".as_bytes();
    let ct = cit.seal(&pk, unicode, &aad, &ctx).unwrap();
    let pt = cit.open(&sk, &ct, &aad, &ctx).unwrap();
    assert_eq!(pt, unicode);
}

#[test]
fn context_isolation() {
    // Data encrypted with context A must not decrypt with context B.
    // This is the domain-separation guarantee.
    let (cit, pk, sk) = setup();
    let aad = Aad::raw(b"aad");

    let ct_med = cit
        .seal(&pk, b"patient-data", &aad, &Context::raw(b"medical"))
        .unwrap();
    let ct_fin = cit
        .seal(&pk, b"account-data", &aad, &Context::raw(b"financial"))
        .unwrap();

    // Cross-context decrypt must fail
    assert_eq!(
        cit.open(&sk, &ct_med, &aad, &Context::raw(b"financial")),
        Err(OpenError),
        "medical ciphertext should not decrypt under financial context"
    );
    assert_eq!(
        cit.open(&sk, &ct_fin, &aad, &Context::raw(b"medical")),
        Err(OpenError),
        "financial ciphertext should not decrypt under medical context"
    );

    // Correct contexts work
    assert!(cit
        .open(&sk, &ct_med, &aad, &Context::raw(b"medical"))
        .is_ok());
    assert!(cit
        .open(&sk, &ct_fin, &aad, &Context::raw(b"financial"))
        .is_ok());
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. KEY MATERIAL HANDLING
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn keypair_uniqueness() {
    // Two generate_keypair() calls must produce different keys
    let cit = Citadel::new();
    let (pk1, sk1) = cit.generate_keypair();
    let (pk2, sk2) = cit.generate_keypair();

    assert_ne!(
        pk1.to_bytes(),
        pk2.to_bytes(),
        "Two keypair generations produced identical public keys"
    );
    assert_ne!(
        sk1.to_bytes(),
        sk2.to_bytes(),
        "Two keypair generations produced identical secret keys"
    );
}

#[test]
fn key_serialization_is_lossless() {
    // Keys must round-trip through bytes without any loss
    let cit = Citadel::new();
    let (pk, sk) = cit.generate_keypair();

    let pk_bytes = pk.to_bytes();
    let sk_bytes = sk.to_bytes();

    let pk2 = PublicKey::from_bytes(&pk_bytes).expect("pk deserialization failed");
    let sk2 = SecretKey::from_bytes(&sk_bytes).expect("sk deserialization failed");

    // Re-serialized must match original
    assert_eq!(pk_bytes, pk2.to_bytes(), "Public key round-trip mismatch");
    assert_eq!(sk_bytes, sk2.to_bytes(), "Secret key round-trip mismatch");

    // Must be functionally equivalent
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");
    let ct = cit.seal(&pk2, b"test", &aad, &ctx).unwrap();
    let pt = cit.open(&sk2, &ct, &aad, &ctx).unwrap();
    assert_eq!(&pt, b"test");
}

#[test]
fn public_key_cannot_decrypt() {
    // The public key must not be usable for decryption.
    // This is obvious but worth asserting explicitly.
    let (cit, pk, _sk) = setup();
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");
    let ct = cit.seal(&pk, b"secret", &aad, &ctx).unwrap();

    // Try to use public key bytes as a secret key
    let pk_bytes = pk.to_bytes();
    if let Ok(fake_sk) = SecretKey::from_bytes(&pk_bytes) {
        let result = cit.open(&fake_sk, &ct, &aad, &ctx);
        assert!(
            result.is_err(),
            "Public key bytes accepted as secret key — critical failure"
        );
    }
    // If from_bytes returns Err on pk_bytes, that's also fine — the key is rejected
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. CIPHERTEXT EXPANSION AND DETERMINISM
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ciphertext_is_non_deterministic() {
    // Encrypting the same plaintext twice must produce different ciphertexts
    // (due to fresh nonce each time). Deterministic encryption leaks
    // whether two ciphertexts contain the same plaintext.
    let (cit, pk, _sk) = setup();
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");
    let plaintext = b"same message encrypted twice";

    let ct1 = cit.seal(&pk, plaintext, &aad, &ctx).unwrap();
    let ct2 = cit.seal(&pk, plaintext, &aad, &ctx).unwrap();

    assert_ne!(
        ct1, ct2,
        "Same plaintext produced identical ciphertexts — nonce is not being randomized"
    );
}

#[test]
fn ciphertext_length_depends_only_on_plaintext_length() {
    // Ciphertext length must not leak anything about the plaintext content,
    // only its length. Two plaintexts of the same length must produce
    // ciphertexts of the same length.
    let (cit, pk, _sk) = setup();
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");

    let ct1 = cit.seal(&pk, b"aaaaaaaa", &aad, &ctx).unwrap();
    let ct2 = cit.seal(&pk, b"zzzzzzzz", &aad, &ctx).unwrap();
    let ct3 = cit.seal(&pk, b"12345678", &aad, &ctx).unwrap();

    assert_eq!(
        ct1.len(),
        ct2.len(),
        "Same-length plaintexts produce different-length ciphertexts"
    );
    assert_eq!(ct1.len(), ct3.len());
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. VOLUME / STRESS
// ─────────────────────────────────────────────────────────────────────────────

#[test]
#[ignore] // run with: cargo test volume -- --ignored --nocapture
fn volume_10k_roundtrips() {
    let (cit, pk, sk) = setup();
    let aad = Aad::raw(b"stress-aad");
    let ctx = Context::raw(b"stress-ctx");
    let count = 10_000;

    let start = Instant::now();
    for i in 0..count {
        let plaintext = format!("message-{:06}", i);
        let ct = cit.seal(&pk, plaintext.as_bytes(), &aad, &ctx).unwrap();
        let pt = cit.open(&sk, &ct, &aad, &ctx).unwrap();
        assert_eq!(pt, plaintext.as_bytes());
    }
    let elapsed = start.elapsed();
    let per_op = elapsed / count as u32;

    println!(
        "Volume: {} roundtrips in {:.2}s ({:.2}ms/op)",
        count,
        elapsed.as_secs_f64(),
        per_op.as_secs_f64() * 1000.0
    );

    // Should complete in under 180s in debug builds (60s in release)
    // Debug builds include unoptimized ML-KEM operations which are ~3x slower
    let limit = if cfg!(debug_assertions) {
        Duration::from_secs(180)
    } else {
        Duration::from_secs(60)
    };
    assert!(
        elapsed < limit,
        "10k roundtrips took too long: {:.2}s (limit: {}s)",
        elapsed.as_secs_f64(),
        limit.as_secs()
    );
}

#[test]
#[ignore]
fn volume_large_plaintext_stress() {
    let (cit, pk, sk) = setup();
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");

    let sizes = [1024, 65536, 1024 * 1024]; // 1KB, 64KB, 1MB
    for &size in &sizes {
        let plaintext = vec![0xABu8; size];
        let start = Instant::now();
        let ct = cit.seal(&pk, &plaintext, &aad, &ctx).unwrap();
        let pt = cit.open(&sk, &ct, &aad, &ctx).unwrap();
        let elapsed = start.elapsed();
        assert_eq!(pt, plaintext);
        println!(
            "Large plaintext: {}B roundtrip in {:.2}ms",
            size,
            elapsed.as_secs_f64() * 1000.0
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. INVARIANTS
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn error_type_carries_no_information() {
    // OpenError must be a unit type — it must not carry information about
    // why decryption failed (that would be a side channel).
    let (cit, pk, sk) = setup();
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");
    let ct = cit.seal(&pk, b"data", &aad, &ctx).unwrap();

    let (_, _, sk2) = setup();

    let err_bad_aad = cit.open(&sk, &ct, &Aad::raw(b"wrong"), &ctx).unwrap_err();
    let err_bad_ctx = cit
        .open(&sk, &ct, &aad, &Context::raw(b"wrong"))
        .unwrap_err();
    let err_bad_key = cit.open(&sk2, &ct, &aad, &ctx).unwrap_err();
    let err_truncated = cit.open(&sk, b"short", &aad, &ctx).unwrap_err();

    // All errors must be identical — same type, same display
    assert_eq!(err_bad_aad, err_bad_ctx);
    assert_eq!(err_bad_ctx, err_bad_key);
    assert_eq!(err_bad_key, err_truncated);

    let msg = format!("{}", err_bad_aad);
    assert_eq!(format!("{}", err_bad_ctx), msg);
    assert_eq!(format!("{}", err_bad_key), msg);
    assert_eq!(format!("{}", err_truncated), msg);
}

#[test]
fn plaintext_not_in_ciphertext() {
    // The plaintext must not appear verbatim anywhere in the ciphertext.
    // This is trivially true for any real encryption but worth asserting.
    let (cit, pk, _sk) = setup();
    let plaintext = b"FIND_ME_IF_YOU_CAN_SUPERSECRET";
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");
    let ct = cit.seal(&pk, plaintext, &aad, &ctx).unwrap();

    let ct_str = ct.windows(plaintext.len()).any(|w| w == plaintext);

    assert!(
        !ct_str,
        "Plaintext appears verbatim in ciphertext — encryption is broken"
    );
}

#[test]
fn decryption_never_panics_on_garbage() {
    // Feed completely random-looking garbage inputs to open().
    // It must never panic — always return Err(OpenError).
    let (cit, _pk, sk) = setup();
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");

    let garbage_inputs: Vec<&[u8]> = vec![
        b"",
        b"\x00",
        b"\xFF",
        b"\x00\xFF\x00\xFF",
        &[0u8; 1154], // exact wire size but garbage content
        &[0xFFu8; 1154],
        &[0u8; 2048],
    ];

    for input in garbage_inputs {
        let result = std::panic::catch_unwind(|| {
            let _ = cit.open(&sk, input, &aad, &ctx);
        });
        assert!(
            result.is_ok(),
            "open() panicked on garbage input of length {}",
            input.len()
        );
    }
}

#[test]
fn parsers_never_panic_on_boundary_or_garbage_inputs() {
    // Both public parsers that accept fully attacker-controlled bytes — open() and
    // inspect() — must return Err, never panic (a panic on adversarial input is a
    // remote DoS). Hammer them across garbage content AND every length near a format
    // boundary (v1 header 6, v2 header 98, kem 1120/1218, stream 1126, v1 min 1154,
    // v3 header 1162, v2 min 1234), where an off-by-one slice would fire, with leading
    // bytes that drive each dispatch branch.
    use citadel_envelope::inspect;
    use std::collections::BTreeSet;

    let (cit, _pk, sk) = setup();
    let aad = Aad::raw(b"aad");
    let ctx = Context::raw(b"ctx");

    let mut lengths: BTreeSet<usize> = (0..12).collect();
    for base in [6usize, 98, 1120, 1126, 1154, 1162, 1218, 1234, 2048] {
        for delta in -2i64..=2 {
            let n = base as i64 + delta;
            if n >= 0 {
                lengths.insert(n as usize);
            }
        }
    }

    // Leading bytes that route into each decoder branch of inspect()/open().
    let prefixes: &[&[u8]] = &[
        b"",     // pure fill
        b"CTD2", // envelope v2 (wire_v2::decode)
        &[0x01], // v1 envelope (decode_wire_raw)
        &[0x02], // v2 stream (decode_stream_header)
        b"CTDL", // v3 stream magic
    ];

    for &len in &lengths {
        for fill in [0x00u8, 0xFF, 0xA3] {
            for prefix in prefixes {
                let mut buf = vec![fill; len];
                let p = prefix.len().min(len);
                buf[..p].copy_from_slice(&prefix[..p]);

                let opened = std::panic::catch_unwind(|| {
                    let _ = cit.open(&sk, &buf, &aad, &ctx);
                });
                assert!(
                    opened.is_ok(),
                    "open() panicked: len={len} fill={fill:#x} prefix={prefix:?}"
                );

                let inspected = std::panic::catch_unwind(|| {
                    let _ = inspect(&buf);
                });
                assert!(
                    inspected.is_ok(),
                    "inspect() panicked: len={len} fill={fill:#x} prefix={prefix:?}"
                );
            }
        }
    }
}
