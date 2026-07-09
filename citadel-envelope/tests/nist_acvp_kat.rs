// SPDX-License-Identifier: AGPL-3.0-or-later
//! NIST ACVP KAT-adjacent tests for ML-KEM-768 and the hybrid envelope.
//!
//! ## Coverage tier: Partial (Tier 2)
//!
//! The underlying library (ml-kem 0.2.3) does not expose deterministic
//! seed-based keygen or deterministic encapsulate APIs. Therefore:
//!
//! - **Full ACVP KAT** (Tier 1): NOT achievable without upstream API changes.
//!   We cannot feed ACVP seed/dk/ek vectors and compare encapsulate output.
//!
//! - **Partial KAT** (Tier 2, this file): We verify:
//!   1. Round-trip correctness: encapsulate → decapsulate recovers the shared
//!      secret (functionally equivalent to ACVP decapVal).
//!   2. Key sizes match FIPS 203 Section 7: ek=1184, dk=2400, ct=1088, ss=32.
//!   3. Hybrid composition: X25519 ephemeral[32] || ML-KEM-768 ct[1088] = 1120.
//!   4. Decapsulation of corrupted ciphertext fails (invalid ciphertext check).
//!   5. Underlying primitives (HKDF, AES-GCM, SHA3, X25519) are verified
//!      against official NIST/RFC test vectors in primitive_kat.rs.
//!
//! - **Round-trip only** (Tier 3): Would be the fallback if even decapsulation
//!   were non-deterministic (it is deterministic — no randomness in decap).
//!
//! ## Gap record
//!
//! "Library API (ml-kem 0.2.3) does not expose deterministic KAT hooks for
//! keygen or encapsulate. Full ACVP vector compliance requires upstream API
//! changes (seed-based keygen, deterministic encapsulate). Round-trip and
//! structural correctness verified; all underlying primitives have independent
//! NIST/RFC KAT coverage (see primitive_kat.rs)."

use citadel_envelope::wire;
use citadel_envelope::{Aad, Citadel, Context};

// ─────────────────────────────────────────────────────────────────────────────
// ML-KEM-768 structural validation (FIPS 203 Section 7)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn mlkem768_key_sizes_match_fips203() {
    let cit = Citadel::new();
    let (pk, sk) = cit.generate_keypair();

    // FIPS 203 Table 3: ML-KEM-768
    //   ek (encapsulation key): 1184 bytes
    //   dk (decapsulation key): 2400 bytes
    //   ct (ciphertext):        1088 bytes
    //   ss (shared secret):     32 bytes
    //
    // Citadel's PublicKey = X25519 pk[32] + ML-KEM ek[1184] = 1216
    // Citadel's SecretKey = X25519 sk[32] + ML-KEM dk[2400] = 2432
    let pk_bytes = pk.to_bytes();
    let sk_bytes = sk.to_bytes();

    assert_eq!(
        pk_bytes.len(),
        32 + 1184,
        "Hybrid PublicKey must be X25519[32] + ML-KEM-768 ek[1184] = 1216, got {}",
        pk_bytes.len()
    );
    assert_eq!(
        sk_bytes.len(),
        32 + 2400,
        "Hybrid SecretKey must be X25519[32] + ML-KEM-768 dk[2400] = 2432, got {}",
        sk_bytes.len()
    );
}

#[test]
fn mlkem768_ciphertext_size_matches_fips203() {
    let cit = Citadel::new();
    let (pk, _sk) = cit.generate_keypair();

    let ct = cit
        .seal(&pk, b"test", &Aad::empty(), &Context::empty())
        .unwrap();

    // Wire format: header[6] + kem_ct[1120] + nonce[12] + aead_ct[4+16] = 1158
    // KEM ciphertext = X25519 ephemeral[32] + ML-KEM ct[1088] = 1120
    let parts = wire::decode_wire(&ct).unwrap();
    assert_eq!(
        parts.kem_ciphertext.len(),
        1120,
        "Hybrid KEM ciphertext must be X25519[32] + ML-KEM-768[1088] = 1120, got {}",
        parts.kem_ciphertext.len()
    );

    // Verify ML-KEM-768 ct portion is exactly 1088 bytes
    let mlkem_ct = &parts.kem_ciphertext[32..];
    assert_eq!(
        mlkem_ct.len(),
        1088,
        "ML-KEM-768 ciphertext portion must be 1088 bytes (FIPS 203), got {}",
        mlkem_ct.len()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Round-trip correctness (equivalent to ACVP decapVal)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn roundtrip_100_independent_keypairs() {
    let cit = Citadel::new();

    for i in 0..100 {
        let (pk, sk) = cit.generate_keypair();
        let plaintext = format!("ACVP round-trip test payload #{}", i).into_bytes();
        let aad = Aad::raw(format!("aad-{}", i).as_bytes());
        let ctx = Context::raw(format!("ctx-{}", i).as_bytes());

        let ct = cit
            .seal(&pk, &plaintext, &aad, &ctx)
            .unwrap_or_else(|e| panic!("seal failed at i={}: {:?}", i, e));
        let pt = cit
            .open(&sk, &ct, &aad, &ctx)
            .unwrap_or_else(|e| panic!("open failed at i={}: {:?}", i, e));

        assert_eq!(pt, plaintext, "round-trip mismatch at i={}", i);
    }
}

#[test]
fn roundtrip_empty_plaintext() {
    let cit = Citadel::new();
    let (pk, sk) = cit.generate_keypair();

    let ct = cit
        .seal(&pk, b"", &Aad::empty(), &Context::empty())
        .unwrap();
    let pt = cit
        .open(&sk, &ct, &Aad::empty(), &Context::empty())
        .unwrap();
    assert!(
        pt.is_empty(),
        "empty plaintext round-trip must produce empty output"
    );
}

#[test]
fn roundtrip_large_plaintext() {
    let cit = Citadel::new();
    let (pk, sk) = cit.generate_keypair();

    let plaintext = vec![0xAB_u8; 1_000_000]; // 1MB
    let ct = cit
        .seal(
            &pk,
            &plaintext,
            &Aad::raw(b"large"),
            &Context::raw(b"large"),
        )
        .unwrap();
    let pt = cit
        .open(&sk, &ct, &Aad::raw(b"large"), &Context::raw(b"large"))
        .unwrap();
    assert_eq!(pt, plaintext, "1MB round-trip mismatch");
}

// ─────────────────────────────────────────────────────────────────────────────
// Invalid ciphertext rejection (equivalent to ACVP decapVal negative)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn corrupted_kem_ciphertext_rejected() {
    let cit = Citadel::new();
    let (pk, sk) = cit.generate_keypair();

    let ct = cit
        .seal(&pk, b"test", &Aad::empty(), &Context::empty())
        .unwrap();

    // Corrupt the ML-KEM ciphertext portion (bytes 38..38+1088)
    let mut ct_bad = ct.clone();
    ct_bad[40] ^= 0xFF; // inside KEM ciphertext
    assert!(
        cit.open(&sk, &ct_bad, &Aad::empty(), &Context::empty())
            .is_err(),
        "corrupted KEM ciphertext must be rejected"
    );
}

#[test]
fn corrupted_x25519_ephemeral_rejected() {
    let cit = Citadel::new();
    let (pk, sk) = cit.generate_keypair();

    let ct = cit
        .seal(&pk, b"test", &Aad::empty(), &Context::empty())
        .unwrap();

    // Corrupt the X25519 ephemeral public key (bytes 6..38)
    let mut ct_bad = ct.clone();
    ct_bad[6] ^= 0xFF;
    assert!(
        cit.open(&sk, &ct_bad, &Aad::empty(), &Context::empty())
            .is_err(),
        "corrupted X25519 ephemeral must be rejected"
    );
}

#[test]
fn corrupted_aead_tag_rejected() {
    let cit = Citadel::new();
    let (pk, sk) = cit.generate_keypair();

    let ct = cit
        .seal(&pk, b"test", &Aad::empty(), &Context::empty())
        .unwrap();

    // Corrupt the last byte (inside AEAD tag)
    let mut ct_bad = ct.clone();
    let len = ct_bad.len();
    ct_bad[len - 1] ^= 0x01;
    assert!(
        cit.open(&sk, &ct_bad, &Aad::empty(), &Context::empty())
            .is_err(),
        "corrupted AEAD tag must be rejected"
    );
}

#[test]
fn wrong_key_rejected() {
    let cit = Citadel::new();
    let (pk1, _sk1) = cit.generate_keypair();
    let (_pk2, sk2) = cit.generate_keypair();

    let ct = cit
        .seal(&pk1, b"test", &Aad::empty(), &Context::empty())
        .unwrap();
    assert!(
        cit.open(&sk2, &ct, &Aad::empty(), &Context::empty())
            .is_err(),
        "wrong secret key must be rejected"
    );
}

#[test]
fn truncated_ciphertext_rejected() {
    let cit = Citadel::new();
    let (_pk, sk) = cit.generate_keypair();

    // Various truncation points
    let truncations: &[usize] = &[0, 1, 5, 6, 37, 100, 500, 1000, 1153];
    for &len in truncations {
        let ct = vec![0x01; len]; // version byte + garbage
        assert!(
            cit.open(&sk, &ct, &Aad::empty(), &Context::empty())
                .is_err(),
            "truncated ciphertext (len={}) must be rejected",
            len
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AAD and context binding verification
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn aad_binding_enforced() {
    let cit = Citadel::new();
    let (pk, sk) = cit.generate_keypair();

    let ct = cit
        .seal(
            &pk,
            b"secret",
            &Aad::raw(b"correct-aad"),
            &Context::raw(b"ctx"),
        )
        .unwrap();

    // Correct AAD works
    assert!(cit
        .open(&sk, &ct, &Aad::raw(b"correct-aad"), &Context::raw(b"ctx"))
        .is_ok());

    // Wrong AAD fails
    assert!(
        cit.open(&sk, &ct, &Aad::raw(b"wrong-aad"), &Context::raw(b"ctx"))
            .is_err(),
        "wrong AAD must be rejected"
    );

    // Empty AAD fails
    assert!(
        cit.open(&sk, &ct, &Aad::empty(), &Context::raw(b"ctx"))
            .is_err(),
        "empty AAD must be rejected when AAD was provided"
    );
}

#[test]
fn context_binding_enforced() {
    let cit = Citadel::new();
    let (pk, sk) = cit.generate_keypair();

    let ct = cit
        .seal(
            &pk,
            b"secret",
            &Aad::raw(b"aad"),
            &Context::raw(b"correct-ctx"),
        )
        .unwrap();

    assert!(cit
        .open(&sk, &ct, &Aad::raw(b"aad"), &Context::raw(b"correct-ctx"))
        .is_ok());
    assert!(
        cit.open(&sk, &ct, &Aad::raw(b"aad"), &Context::raw(b"wrong-ctx"))
            .is_err(),
        "wrong context must be rejected"
    );
    assert!(
        cit.open(&sk, &ct, &Aad::raw(b"aad"), &Context::empty())
            .is_err(),
        "empty context must be rejected when context was provided"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire format constants verification (protocol self-description)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn wire_protocol_version_is_v1() {
    assert_eq!(
        wire::PROTOCOL_VERSION,
        0x01,
        "standard envelope must use protocol version 0x01"
    );
}

#[test]
fn wire_suite_identifiers_correct() {
    assert_eq!(
        wire::SUITE_KEM_HYBRID_X25519_MLKEM768,
        0xA3,
        "hybrid X25519+ML-KEM-768 suite must be 0xA3"
    );
    assert_eq!(
        wire::SUITE_AEAD_AES256GCM,
        0xB1,
        "AES-256-GCM suite must be 0xB1"
    );
}
